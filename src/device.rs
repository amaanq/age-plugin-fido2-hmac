//! FIDO2 device abstraction backed by [`ctap_fido2`].

use std::{
   cell::RefCell,
   env,
   fmt,
   io,
   str::FromStr,
   thread,
   time::{
      Duration,
      Instant,
   },
};

use ctap_fido2::{
   cmd::{
      self as fido_cmd,
      Authenticator,
      AuthenticatorInfo,
      MakeCredentialOptions,
      get_assertion::HmacSecretRequest,
   },
   cose::CredentialPublicKey,
   device::{
      self as fido_device,
      DeviceInfo,
   },
   error as fido_error,
};
use rand::Rng as _;
use secrecy::SecretBox;
use zeroize::Zeroize as _;

use crate::{
   error::{
      Error,
      Result,
   },
   format::RELYING_PARTY,
   yubikey_serial,
};

/// Random FIDO2 client-data hash for CTAP commands.
fn random_cdh() -> [u8; 32] {
   let mut cdh = [0_u8; 32];
   rand::rng().fill_bytes(&mut cdh);
   cdh
}

/// FIDO2 COSE algorithm choice for credential creation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Algorithm {
   /// ECDSA P-256, default.
   Es256,
   /// `EdDSA` over Ed25519.
   EdDsa,
   /// RSA-PSS / PKCS#1, depending on authenticator.
   Rs256,
}

impl Algorithm {
   /// COSE algorithm identifier per IANA.
   #[must_use]
   pub const fn cose_id(self) -> i32 {
      match self {
         Self::Es256 => -7,
         Self::EdDsa => -8,
         Self::Rs256 => -257,
      }
   }
}

impl FromStr for Algorithm {
   type Err = Error;
   fn from_str(s: &str) -> Result<Self> {
      match s.trim().to_ascii_lowercase().as_str() {
         "es256" => Ok(Self::Es256),
         "eddsa" | "ed25519" => Ok(Self::EdDsa),
         "rs256" => Ok(Self::Rs256),
         other => Err(Error::InvalidFormat(format!("unknown algorithm {other}"))),
      }
   }
}

impl fmt::Display for Algorithm {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str(match *self {
         Self::Es256 => "es256",
         Self::EdDsa => "eddsa",
         Self::Rs256 => "rs256",
      })
   }
}

impl TryFrom<Algorithm> for fido_cmd::Algorithm {
   type Error = Error;
   fn try_from(alg: Algorithm) -> Result<Self> {
      match alg {
         Algorithm::Es256 => Ok(Self::Es256),
         Algorithm::EdDsa => Ok(Self::EdDsa),
         Algorithm::Rs256 => {
            Err(Error::Fido2(
               "RS256 is not supported by this build; use es256 or eddsa".into(),
            ))
         },
      }
   }
}

impl From<fido_error::Error> for Error {
   fn from(err: fido_error::Error) -> Self {
      match err {
         fido_error::Error::Ctap(status) => Self::Ctap(status),
         other => Self::Fido2(other.to_string()),
      }
   }
}

/// Credential id paired with its public key, as returned by registration.
#[derive(Clone, Debug)]
pub struct GeneratedCredential {
   pub id:         Vec<u8>,
   pub public_key: CredentialPublicKey,
}

/// FIDO2 device operations needed by this plugin.
pub trait Fido2Device {
   /// Has the device been provisioned with a client PIN?
   fn has_pin_set(&self) -> Result<bool>;

   /// Create a non-discoverable credential with the hmac-secret extension.
   fn generate_credential(&self, pin: Option<&str>, alg: Algorithm) -> Result<GeneratedCredential>;

   /// Get the 32-byte hmac-secret output for `(cred_id, salt)`. When
   /// `public_key` is [`Some`], the assertion signature is verified.
   fn get_hmac_secret(
      &self,
      cred_id: &[u8],
      salt: &[u8; 32],
      pin: Option<&str>,
      public_key: Option<&CredentialPublicKey>,
   ) -> Result<SecretBox<[u8; 32]>>;

   /// Silent (`up=false`) allow-list probe. Returns the matching
   /// credential id without a touch, or [`None`] when none of the
   /// candidates are on this device or the firmware rejects the silent
   /// assertion — callers fall back to sequential per-credential probing.
   fn probe_credential(&self, allow_list: &[&[u8]]) -> Result<Option<Vec<u8>>>;

   /// Device serial if the bus reports one.
   fn serial(&self) -> Option<&str>;
}

/// Hardware-backed [`Fido2Device`] over [`ctap_fido2::Authenticator`].
pub struct CtapHidDevice {
   inner:  RefCell<Authenticator>,
   serial: Option<String>,
}

impl CtapHidDevice {
   /// Wrap an opened [`Authenticator`].
   #[must_use]
   pub const fn new(inner: Authenticator, serial: Option<String>) -> Self {
      Self {
         inner: RefCell::new(inner),
         serial,
      }
   }
}

impl Fido2Device for CtapHidDevice {
   fn has_pin_set(&self) -> Result<bool> {
      let mut auth = self.inner.borrow_mut();
      auth
         .info()
         .map(AuthenticatorInfo::client_pin_set)
         .map_err(Error::from)
   }

   fn generate_credential(&self, pin: Option<&str>, alg: Algorithm) -> Result<GeneratedCredential> {
      let cdh = random_cdh();
      let opts = MakeCredentialOptions {
         algorithm: fido_cmd::Algorithm::try_from(alg)?,
         pin,
         resident_key: false,
         cred_protect: None,
         cred_blob: None,
         large_blob_key: false,
         min_pin_length: false,
      };
      let credential = self
         .inner
         .borrow_mut()
         .make_credential(RELYING_PARTY, &cdh, &opts)
         .map_err(Error::from)?;
      Ok(GeneratedCredential {
         id:         credential.id,
         public_key: credential.public_key,
      })
   }

   fn get_hmac_secret(
      &self,
      cred_id: &[u8],
      salt: &[u8; 32],
      pin: Option<&str>,
      public_key: Option<&CredentialPublicKey>,
   ) -> Result<SecretBox<[u8; 32]>> {
      let cdh = random_cdh();
      let response = self
         .inner
         .borrow_mut()
         .get_hmac_secret(&HmacSecretRequest {
            rp_id: RELYING_PARTY,
            client_data_hash: &cdh,
            cred_id,
            salt,
            salt2: None,
            pin,
            public_key,
            request_cred_blob: false,
         })
         .map_err(Error::from)?;
      let mut bytes = response.secret.0;
      let boxed = Box::new(bytes);
      bytes.zeroize();
      Ok(SecretBox::new(boxed))
   }

   fn probe_credential(&self, allow_list: &[&[u8]]) -> Result<Option<Vec<u8>>> {
      let cdh = random_cdh();
      self
         .inner
         .borrow_mut()
         .probe_credential(RELYING_PARTY, &cdh, allow_list)
         .map_err(Error::from)
   }

   fn serial(&self) -> Option<&str> {
      self.serial.as_deref()
   }
}

/// Callbacks the device-find loop uses to surface state to the user.
pub trait DiscoveryUi {
   /// Display a one-line message (e.g. "please insert your security key...").
   fn message(&mut self, msg: &str);

   /// Called once per poll while waiting for a device.
   fn waiting_tick(&mut self, _started: Instant) {}

   /// Ask the user to pick a label among multiple devices. Return the
   /// chosen index into `labels`.
   fn pick_device(&mut self, labels: &[String]) -> Result<usize>;
}

/// Best-effort device serial: HID, Linux parent USB device, then `YubiKey` query.
#[must_use]
pub fn device_serial(info: &DeviceInfo) -> Option<String> {
   if let Some(serial) = info.serial_number.as_deref()
      && !serial.is_empty()
   {
      return Some(serial.to_owned());
   }
   if let Some(serial) = linux_usb_serial_from_hidraw(&info.path) {
      return Some(serial);
   }
   if let Some(yk) = yubikey_serial::read(info) {
      return Some(yk.serial.to_string());
   }
   None
}

#[cfg(target_os = "linux")]
fn linux_usb_serial_from_hidraw(path: &str) -> Option<String> {
   use std::fs;

   let name = path.strip_prefix("/dev/")?;
   let class_link = format!("/sys/class/hidraw/{name}/device");
   let mut dir = fs::canonicalize(class_link).ok()?;
   // Anchor on the USB device directory; parent `serial` files can be bus IDs.
   for _ in 0_u8..8 {
      if dir.join("idVendor").is_file() && dir.join("idProduct").is_file() {
         let serial = fs::read_to_string(dir.join("serial")).ok()?;
         let trimmed = serial.trim();
         if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
         }
         return None;
      }
      dir = dir.parent()?.to_path_buf();
   }
   None
}

#[cfg(not(target_os = "linux"))]
const fn linux_usb_serial_from_hidraw(_path: &str) -> Option<String> {
   None
}

/// Render a discovered [`DeviceInfo`] for the device picker.
fn render_device(info: &DeviceInfo) -> String {
   let location = &info.path;
   if let Some(yk) = yubikey_serial::read(info) {
      return format!("{yk} ({location})");
   }
   let name = info
      .product_string
      .as_deref()
      .filter(|name| !name.is_empty());
   let serial = device_serial(info);
   match (name, serial.as_deref()) {
      (Some(name), Some(serial)) => format!("{name} Serial: {serial} ({location})"),
      (Some(name), None) => format!("{name} ({location})"),
      (None, Some(serial)) => format!("Serial: {serial} ({location})"),
      (None, None) => location.clone(),
   }
}

/// Print every eligible authenticator with all selector forms a user can
/// hand back through `FIDO2_SERIAL`. Used by the `--list-devices` flag.
///
/// # Errors
///
/// Resurfaces [`fido_device::list_devices`] errors.
pub fn list_devices_to(out: &mut dyn io::Write) -> Result<()> {
   let devices = fido_device::list_devices().map_err(Error::from)?;
   if devices.is_empty() {
      let _ = writeln!(out, "no FIDO2 hmac-secret authenticators found");
      return Ok(());
   }
   for (idx, info) in devices.iter().enumerate() {
      let name = info
         .product_string
         .as_deref()
         .filter(|n| !n.is_empty())
         .unwrap_or("<unknown>");
      let _ = writeln!(out, "[{idx}] {name}");
      let _ = writeln!(
         out,
         "    vid:pid = {:04x}:{:04x}",
         info.vendor_id, info.product_id
      );
      if let Some(serial) = device_serial(info) {
         let _ = writeln!(out, "    serial  = {serial}");
         let _ = writeln!(out, "    set FIDO2_SERIAL={serial}");
      }
      let _ = writeln!(out, "    path    = {}", info.path);
   }
   Ok(())
}

/// Read `FIDO2_SERIAL`.
fn get_serial_from_env() -> Option<String> {
   let value = env::var("FIDO2_SERIAL").ok()?;
   (!value.is_empty()).then_some(value)
}

/// Find a FIDO2 authenticator suitable for this plugin.
///
/// This honors `FIDO2_SERIAL`, otherwise polls up to `timeout` and either
/// auto-picks the only device or asks the user to disambiguate.
pub fn find(timeout: Duration, ui: &mut dyn DiscoveryUi) -> Result<Box<dyn Fido2Device>> {
   let wanted_serial = get_serial_from_env();

   let started = Instant::now();
   let deadline = started + timeout;
   let poll = Duration::from_millis(200);
   let mut prompted = false;

   loop {
      ui.waiting_tick(started);
      let eligible = fido_device::list_devices().map_err(Error::from)?;

      if let Some(ref serial) = wanted_serial {
         let matched = eligible
            .iter()
            .filter(|info| device_serial(info).as_deref() == Some(serial.as_str()))
            .cloned()
            .collect::<Vec<DeviceInfo>>();
         match matched.len() {
            1 => {
               let info = matched.into_iter().next().expect("len == 1");
               let serial = device_serial(&info);
               let auth = Authenticator::open(&info).map_err(Error::from)?;
               return Ok(Box::new(CtapHidDevice::new(auth, serial)));
            },
            0 => {
               if !prompted && !eligible.is_empty() {
                  ui.message(&format!(
                     "FIDO2_SERIAL={serial} matched nothing; eligible devices: {}",
                     eligible
                        .iter()
                        .map(render_device)
                        .collect::<Vec<_>>()
                        .join(", ")
                  ));
                  prompted = true;
               }
            },
            _ => {
               ui.message(&format!(
                  "FIDO2_SERIAL={serial} matched {} devices; pick one: {}",
                  matched.len(),
                  matched
                     .iter()
                     .map(render_device)
                     .collect::<Vec<_>>()
                     .join(", ")
               ));
               return Err(Error::Fido2(
                  "FIDO2_SERIAL matched more than one device".into(),
               ));
            },
         }
      } else {
         match eligible.len() {
            1 => {
               // Avoid a YubiKey management query when auto-picking the only device.
               let info = eligible.into_iter().next().expect("len == 1");
               let auth = Authenticator::open(&info).map_err(Error::from)?;
               return Ok(Box::new(CtapHidDevice::new(auth, None)));
            },
            n if n > 1 => {
               let labels = eligible.iter().map(render_device).collect::<Vec<String>>();
               let idx = ui.pick_device(&labels)?;
               let info = eligible.into_iter().nth(idx).ok_or_else(|| {
                  Error::Fido2(format!("pick_device returned out-of-range index {idx}"))
               })?;
               let serial = device_serial(&info);
               let auth = Authenticator::open(&info).map_err(Error::from)?;
               return Ok(Box::new(CtapHidDevice::new(auth, serial)));
            },
            _ => {
               if !prompted {
                  ui.message("Please insert your security key...");
               }
               prompted = true;
            },
         }
      }

      if Instant::now() >= deadline {
         return Err(Error::Timeout);
      }
      thread::sleep(poll);
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn algorithm_from_str() {
      assert_eq!("ES256".parse::<Algorithm>().unwrap(), Algorithm::Es256);
      assert_eq!("eddsa".parse::<Algorithm>().unwrap(), Algorithm::EdDsa);
      assert_eq!("rs256".parse::<Algorithm>().unwrap(), Algorithm::Rs256);
      "bogus".parse::<Algorithm>().unwrap_err();
   }

   #[test]
   fn rs256_rejected() {
      match fido_cmd::Algorithm::try_from(Algorithm::Rs256) {
         Err(Error::Fido2(msg)) => assert!(msg.contains("RS256")),
         other => panic!("expected RS256 rejection, got {other:?}"),
      }
   }
}
