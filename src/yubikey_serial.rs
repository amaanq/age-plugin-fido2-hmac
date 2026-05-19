//! Read a `YubiKey`'s model name, firmware version, USB-mode label, and
//! serial via its FIDO HID interface.
//!
//! Approach mirrors `yubikey-manager`'s `_ManagementCtapBackend.read_config`:
//! open the device, send CTAPHID vendor command wire byte `0xC2`
//! (logical id `0x42`, `CTAP_READ_CONFIG`) via
//! [`Transport::vendor_command`](ctap_fido2::Transport::vendor_command)
//! with payload `[page=0]`, parse the returned TLV blob, and pick out
//! tags for serial / form factor / usb-enabled / nfc-supported.

use std::fmt;

use ctap_fido2::{
   cmd::Authenticator,
   device::DeviceInfo,
};

const YUBICO_VID: u16 = 0x1050;

/// Wire byte for `CTAP_READ_CONFIG`. Logical id `0x42` OR'd with the
/// CTAPHID init-frame bit (`0x80`).
const CTAP_READ_CONFIG: u8 = 0xC2;

const TAG_USB_SUPPORTED: u8 = 0x01;
const TAG_SERIAL: u8 = 0x02;
const TAG_USB_ENABLED: u8 = 0x03;
const TAG_FORM_FACTOR: u8 = 0x04;
const TAG_NFC_SUPPORTED: u8 = 0x0D;
const TAG_NFC_ENABLED: u8 = 0x0E;

const CAP_OTP: u16 = 0x01;
const CAP_U2F: u16 = 0x02;
const CAP_FIDO2: u16 = 0x200;
const CAP_CCID_GENERAL: u16 = 0x04;
const CAP_OPENPGP: u16 = 0x08;
const CAP_PIV: u16 = 0x10;
const CAP_OATH: u16 = 0x20;
const CAP_HSMAUTH: u16 = 0x100;
const CAP_MGMT_CCID: u16 = 0x400;

const CCID_MASK: u16 =
   CAP_CCID_GENERAL | CAP_OPENPGP | CAP_PIV | CAP_OATH | CAP_HSMAUTH | CAP_MGMT_CCID;
const FIDO_MASK: u16 = CAP_U2F | CAP_FIDO2;

/// `FORM_FACTOR` codes from the management TLV (tag `0x04`, 1 byte).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum FormFactor {
   UsbAKeychain,
   UsbANano,
   UsbCKeychain,
   UsbCNano,
   UsbCLightning,
   UsbABio,
   UsbCBio,
   Unknown,
}

impl From<u8> for FormFactor {
   fn from(code: u8) -> Self {
      match code & 0x0F {
         1 => Self::UsbAKeychain,
         2 => Self::UsbANano,
         3 => Self::UsbCKeychain,
         4 => Self::UsbCNano,
         5 => Self::UsbCLightning,
         6 => Self::UsbABio,
         7 => Self::UsbCBio,
         _ => Self::Unknown,
      }
   }
}

impl FormFactor {
   const fn is_c(self) -> bool {
      matches!(self, Self::UsbCKeychain | Self::UsbCNano | Self::UsbCBio)
   }

   const fn is_nano(self) -> bool {
      matches!(self, Self::UsbANano | Self::UsbCNano)
   }

   const fn is_bio(self) -> bool {
      matches!(self, Self::UsbABio | Self::UsbCBio)
   }
}

/// Everything we surface in the picker for a `YubiKey`.
#[derive(Clone, Debug)]
pub struct YubiKeyInfo {
   pub serial:      u32,
   pub version:     (u8, u8, u8),
   pub mode_label:  String,
   pub device_name: String,
}

impl fmt::Display for YubiKeyInfo {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      let (major, minor, patch) = self.version;
      write!(
         f,
         "{} ({major}.{minor}.{patch}) [{}] Serial: {}",
         self.device_name, self.mode_label, self.serial
      )
   }
}

/// Probe the device at `info` for `YubiKey` metadata. Returns [`None`]
/// if the device isn't a `YubiKey`, the vendor command isn't supported,
/// or the protocol exchange fails.
#[must_use]
pub fn read(info: &DeviceInfo) -> Option<YubiKeyInfo> {
   if info.vendor_id != YUBICO_VID {
      return None;
   }
   let mut auth = Authenticator::open(info).ok()?;
   let version = auth.firmware_version();
   let body = auth
      .transport_mut()
      .vendor_command(CTAP_READ_CONFIG, &[0x00])
      .ok()?;
   parse(&body, version).ok()
}

fn parse(blob: &[u8], version: (u8, u8, u8)) -> Result<YubiKeyInfo, &'static str> {
   let total = *blob.first().ok_or("empty CTAP_READ_CONFIG body")? as usize;
   if blob
      .len()
      .checked_sub(1)
      .ok_or("config body length underflow")?
      != total
   {
      return Err("CTAP_READ_CONFIG length prefix mismatch");
   }
   let entries = blob.get(1..).ok_or("config body slice")?;
   let mut serial = Option::<u32>::None;
   let mut form_factor = FormFactor::Unknown;
   let mut usb_enabled = 0_u16;
   let mut nfc_seen = false;
   let mut cursor = 0_usize;
   while cursor + 2 <= entries.len() {
      let tag = entries[cursor];
      let len = entries[cursor + 1] as usize;
      cursor += 2;
      let end = cursor.checked_add(len).ok_or("TLV length overflow")?;
      if end > entries.len() {
         return Err("TLV runs past end of body");
      }
      let value = &entries[cursor..end];
      match tag {
         TAG_SERIAL if len == 4 => {
            serial = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
         },
         TAG_FORM_FACTOR if len >= 1 => {
            form_factor = FormFactor::from(value[0]);
         },
         TAG_USB_ENABLED if len == 2 => {
            usb_enabled = u16::from_be_bytes([value[0], value[1]]);
         },
         TAG_USB_SUPPORTED if len == 2 && usb_enabled == 0 => {
            usb_enabled = u16::from_be_bytes([value[0], value[1]]);
         },
         TAG_NFC_SUPPORTED | TAG_NFC_ENABLED
            if len == 2 && u16::from_be_bytes([value[0], value[1]]) != 0 =>
         {
            nfc_seen = true;
         },
         _ => {},
      }
      cursor = end;
   }
   Ok(YubiKeyInfo {
      serial: serial.ok_or("no TAG_SERIAL in CTAP_READ_CONFIG response")?,
      version,
      mode_label: format_mode(usb_enabled),
      device_name: build_device_name(version, form_factor, nfc_seen),
   })
}

fn format_mode(usb_enabled: u16) -> String {
   let mut parts = Vec::<&str>::new();
   if usb_enabled & CAP_OTP != 0 {
      parts.push("OTP");
   }
   if usb_enabled & FIDO_MASK != 0 {
      parts.push("FIDO");
   }
   if usb_enabled & CCID_MASK != 0 {
      parts.push("CCID");
   }
   if parts.is_empty() {
      "unknown".into()
   } else {
      parts.join("+")
   }
}

/// Replicates `yubikit/support.py::get_name` for the `YubiKey 5+` branch.
fn build_device_name(version: (u8, u8, u8), form_factor: FormFactor, has_nfc: bool) -> String {
   if version.0 < 5 || (version.0 == 5 && version.1 == 0) {
      return "YubiKey".into();
   }
   let mut parts = vec!["YubiKey", "5"];
   if form_factor.is_c() {
      parts.push("C");
   } else if form_factor == FormFactor::UsbCLightning {
      parts.push("Ci");
   }
   if form_factor.is_nano() {
      parts.push("Nano");
   } else if has_nfc {
      parts.push("NFC");
   } else if form_factor == FormFactor::UsbAKeychain {
      parts.push("A");
   } else if form_factor.is_bio() {
      parts.push("Bio");
   }
   parts.join(" ").replace("5 C", "5C").replace("5 A", "5A")
}
