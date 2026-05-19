//! [`Identity`] parsing, encoding, wrapping, and unwrapping.

use std::{
   collections::HashMap,
   fmt,
   str::FromStr,
};

use age_core::{
   format::{
      FILE_KEY_BYTES,
      FileKey,
      Stanza,
   },
   primitives::{
      aead_decrypt,
      hkdf,
   },
};
use base64::{
   Engine as _,
   engine::general_purpose::STANDARD_NO_PAD,
};
use ctap_fido2::{
   cose::CredentialPublicKey,
   error::CtapStatus,
};
use secrecy::{
   ExposeSecret as _,
   SecretBox,
};
use subtle::ConstantTimeEq as _;
use x25519_dalek::{
   PublicKey,
   StaticSecret,
};
use zeroize::Zeroize as _;

use crate::{
   device::Fido2Device,
   error::{
      Error,
      Result,
   },
   format::{
      IDENTITY_HRP,
      IDENTITY_VERSION,
      PLUGIN_NAME,
      bech32_decode,
      bech32_encode,
   },
   mlock,
   recipient::Recipient,
   stanza::{
      Fido2HmacStanza,
      Fido2HmacStanzaRef,
   },
};

/// Per-batch derived secrets, keyed by `(cred_id, salt)`.
pub type HmacCache = HashMap<(Box<[u8]>, [u8; 32]), SecretBox<[u8; 32]>>;

/// Connection-scoped state for [`Identity::unwrap_parsed`].
pub struct UnwrapCtx<'a> {
   /// The connected FIDO2 device.
   pub device:           &'a dyn Fido2Device,
   /// PIN, when a credential requires it.
   pub pin:              Option<&'a str>,
   /// Credential id the device holds, narrowing the stanza set without a touch.
   pub preselected_cred: Option<&'a [u8]>,
   /// Shared derive cache.
   pub hmac_cache:       &'a mut HmacCache,
   /// Called immediately before a device call that needs user presence.
   pub notify_touch:     &'a mut dyn FnMut(),
}

/// HKDF label used by age's X25519 stanza format. Must match `recipient.rs`.
const X25519_HKDF_LABEL: &[u8] = b"age-encryption.org/v1/X25519";

/// A fido2-hmac identity: either an on-disk record or a dataless placeholder.
///
/// On-wire layout (Record):
/// `version(2) | require_pin(1) | salt(32) | cred_id_len(2 BE) | cred_id |
/// cose_pubkey`.
pub struct Identity {
   kind:                     IdentityKind,
   /// Cached HMAC secret. Never serialized.
   pub(crate) secret:        Option<SecretBox<[u8; 32]>>,
   /// Last `mlock(2)` warning.
   pub(crate) mlock_warning: Option<String>,
}

/// The two operational shapes an [`Identity`] can take.
#[derive(Clone, Debug)]
pub enum IdentityKind {
   /// A fully-populated identity with all credential metadata.
   Record {
      /// True if a PIN is required when unwrapping.
      require_pin: bool,
      /// 32-byte salt used for the hmac-secret assertion.
      salt:        [u8; 32],
      /// FIDO2 credential ID.
      cred_id:     Vec<u8>,
      /// Credential public key, used to verify assertion signatures.
      public_key:  CredentialPublicKey,
   },
   /// Placeholder used by the `age -d -j fido2-hmac` dataless flow.
   /// All fields are adopted from each plugin stanza at decrypt time.
   Dataless,
}

impl Identity {
   /// Build a Record-shaped identity from fully-known credential
   /// metadata.
   ///
   /// # Errors
   ///
   /// [`Error::InvalidFormat`] if `cred_id` is empty or exceeds `u16`
   /// length.
   pub fn record(
      require_pin: bool,
      salt: [u8; 32],
      cred_id: Vec<u8>,
      public_key: CredentialPublicKey,
   ) -> Result<Self> {
      if cred_id.is_empty() {
         return Err(Error::InvalidFormat("identity: cred_id is empty".into()));
      }
      if u16::try_from(cred_id.len()).is_err() {
         return Err(Error::InvalidFormat(
            "identity: cred_id exceeds u16 length".into(),
         ));
      }
      Ok(Self {
         kind:          IdentityKind::Record {
            require_pin,
            salt,
            cred_id,
            public_key,
         },
         secret:        None,
         mlock_warning: None,
      })
   }

   /// Build a dataless placeholder used by `age -d -j fido2-hmac`.
   #[must_use]
   pub const fn dataless() -> Self {
      Self {
         kind:          IdentityKind::Dataless,
         secret:        None,
         mlock_warning: None,
      }
   }

   /// True for the dataless placeholder; false for a [`IdentityKind::Record`].
   #[must_use]
   pub const fn is_dataless(&self) -> bool {
      matches!(self.kind, IdentityKind::Dataless)
   }

   /// `require_pin` flag. Always `false` for the dataless placeholder
   /// (the real value is adopted from each stanza at decrypt time).
   #[must_use]
   pub const fn require_pin(&self) -> bool {
      match self.kind {
         IdentityKind::Record { require_pin, .. } => require_pin,
         IdentityKind::Dataless => false,
      }
   }

   /// 32-byte hmac-secret salt. All zeros for the dataless placeholder.
   #[must_use]
   pub const fn salt(&self) -> &[u8; 32] {
      match self.kind {
         IdentityKind::Record { ref salt, .. } => salt,
         IdentityKind::Dataless => &[0_u8; 32],
      }
   }

   /// FIDO2 credential id. Empty slice for the dataless placeholder.
   #[must_use]
   pub fn cred_id(&self) -> &[u8] {
      match self.kind {
         IdentityKind::Record { ref cred_id, .. } => cred_id,
         IdentityKind::Dataless => &[],
      }
   }

   /// Credential public key. [`None`] for the dataless placeholder.
   #[must_use]
   pub const fn public_key(&self) -> Option<&CredentialPublicKey> {
      match self.kind {
         IdentityKind::Record { ref public_key, .. } => Some(public_key),
         IdentityKind::Dataless => None,
      }
   }

   /// Inner [`IdentityKind`] for callers that want to pattern-match.
   #[must_use]
   pub const fn kind(&self) -> &IdentityKind {
      &self.kind
   }

   /// Parse raw identity payload bytes.
   pub fn from_bytes(data: &[u8]) -> Result<Self> {
      if data.len() < 2 {
         return Err(Error::InvalidFormat("identity: too short".into()));
      }
      let version = u16::from_be_bytes([data[0], data[1]]);
      if version != IDENTITY_VERSION {
         return Err(Error::UnsupportedVersion(version));
      }
      if data.len() < 2 + 1 + 32 + 2 {
         return Err(Error::InvalidFormat("identity: truncated".into()));
      }

      let require_pin = match data[2] {
         0 => false,
         1 => true,
         other => {
            return Err(Error::InvalidFormat(format!(
               "identity: bad pin flag {other}"
            )));
         },
      };
      let mut salt = [0_u8; 32];
      salt.copy_from_slice(&data[3..35]);

      let cred_id_len = u16::from_be_bytes([data[35], data[36]]) as usize;
      let id_end = 37_usize
         .checked_add(cred_id_len)
         .ok_or_else(|| Error::InvalidFormat("identity: cred_id length overflow".into()))?;
      if id_end > data.len() {
         return Err(Error::InvalidFormat(
            "identity: cred_id exceeds payload".into(),
         ));
      }
      let cred_id = data[37..id_end].to_vec();
      let public_key = CredentialPublicKey::from_cose_bytes(data[id_end..].to_vec())
         .map_err(|err| Error::InvalidFormat(format!("identity: bad public key: {err}")))?;

      Self::record(require_pin, salt, cred_id, public_key)
   }

   /// Encode as the uppercase bech32 string used in identity files.
   ///
   /// # Errors
   ///
   /// [`Error::InvalidFormat`] if called on a dataless placeholder.
   pub fn encode(&self) -> Result<String> {
      let IdentityKind::Record {
         require_pin,
         ref salt,
         ref cred_id,
         ref public_key,
      } = self.kind
      else {
         return Err(Error::InvalidFormat(
            "identity: dataless placeholder cannot be encoded".into(),
         ));
      };
      // cred_id length is validated at construction; the cast is safe.
      #[expect(
         clippy::cast_possible_truncation,
         reason = "Self::record rejects cred_id longer than u16::MAX"
      )]
      let cred_id_len = cred_id.len() as u16;

      let cose = public_key.as_cose_bytes();
      let mut data = Vec::with_capacity(2 + 1 + 32 + 2 + cred_id.len() + cose.len());
      data.extend_from_slice(&IDENTITY_VERSION.to_be_bytes());
      data.push(u8::from(require_pin));
      data.extend_from_slice(salt);
      data.extend_from_slice(&cred_id_len.to_be_bytes());
      data.extend_from_slice(cred_id);
      data.extend_from_slice(cose);

      let lower = bech32_encode(IDENTITY_HRP, &data)?;
      Ok(lower.to_uppercase())
   }
}

impl FromStr for Identity {
   type Err = Error;
   /// Parse a bech32-encoded identity string (case-insensitive).
   fn from_str(input: &str) -> Result<Self> {
      let (hrp, data) = bech32_decode(input)?;
      if hrp != IDENTITY_HRP {
         return Err(Error::InvalidFormat(format!(
            "identity: wrong hrp {hrp}, expected {IDENTITY_HRP}"
         )));
      }
      Self::from_bytes(&data)
   }
}

impl Identity {
   /// Acquire the HMAC secret and return a [`LoadedIdentity`] handle.
   ///
   /// The secret is cleared automatically when the returned handle is
   /// dropped; explicit `clear_secret` calls are not needed.
   pub fn load_secret(
      &mut self,
      device: &dyn Fido2Device,
      pin: Option<&str>,
   ) -> Result<LoadedIdentity<'_>> {
      if self.secret.is_none() {
         let IdentityKind::Record {
            require_pin,
            ref salt,
            ref cred_id,
            ref public_key,
         } = self.kind
         else {
            return Err(Error::InvalidFormat(
               "identity: dataless placeholder has no secret to load".into(),
            ));
         };
         if require_pin && pin.is_none() {
            return Err(Error::PinRequired);
         }
         let pin = if require_pin { pin } else { None };
         let secret = device.get_hmac_secret(cred_id, salt, pin, Some(public_key))?;
         if let Err(err) = mlock::mlock(secret.expose_secret()) {
            self.mlock_warning = Some(format!("Warning: failed to call mlock: {err}"));
         }
         self.secret = Some(secret);
      }
      Ok(LoadedIdentity { id: self })
   }

   /// Drain any pending `mlock(2)` failure warning.
   pub const fn take_mlock_warning(&mut self) -> Option<String> {
      self.mlock_warning.take()
   }

   /// Wrap a file key. The HMAC secret is loaded for the call and
   /// cleared automatically before returning.
   pub fn wrap(
      &mut self,
      device: &dyn Fido2Device,
      pin: Option<&str>,
      file_key: &FileKey,
   ) -> Result<Fido2HmacStanza> {
      let loaded = self.load_secret(device, pin)?;
      let recipient = loaded.to_recipient()?;
      recipient.wrap(file_key)
   }

   /// Clear the cached HMAC secret. Internal — [`LoadedIdentity`]'s
   /// [`Drop`] is the documented public path.
   fn clear_secret(&mut self) {
      self.secret = None;
   }

   /// Try to unwrap stanzas and recover the file key.
   pub fn unwrap(
      &mut self,
      device: &dyn Fido2Device,
      pin: Option<&str>,
      stanzas: &[Stanza],
   ) -> Result<Option<FileKey>> {
      let mut plugin = Vec::<Fido2HmacStanzaRef<'_>>::new();
      let mut native_x25519 = Vec::<&Stanza>::new();

      for stz in stanzas {
         if stz.tag == PLUGIN_NAME {
            plugin.push(Fido2HmacStanzaRef::try_from(stz)?);
         } else if stz.tag == "X25519" {
            native_x25519.push(stz);
         }
      }

      let mut ctx = UnwrapCtx {
         device,
         pin,
         preselected_cred: None,
         hmac_cache: &mut HmacCache::new(),
         notify_touch: &mut || {},
      };
      self.unwrap_parsed(&mut ctx, &plugin, &native_x25519)
   }

   /// Unwrap from pre-parsed plugin and X25519 stanzas. Connection-scoped state
   /// travels in `ctx` (see [`UnwrapCtx`]).
   pub fn unwrap_parsed(
      &mut self,
      ctx: &mut UnwrapCtx<'_>,
      plugin: &[Fido2HmacStanzaRef<'_>],
      native_x25519: &[&Stanza],
   ) -> Result<Option<FileKey>> {
      if plugin.is_empty() && native_x25519.is_empty() {
         return Ok(None);
      }

      let device = ctx.device;
      let pin = ctx.pin;
      let preselected_cred = ctx.preselected_cred;

      let mut sorted_plugin = plugin.iter().collect::<Vec<&Fido2HmacStanzaRef<'_>>>();
      sorted_plugin.sort_by_key(|stz| stz.require_pin());

      // Restrict to the credential the device holds so a derive runs only when it can
      // succeed. Preselect is the fast path, else probe this file's creds.
      // Additionally, "holds none" skips it touch-free, a probe error falls back to
      // the sequential path.
      if !sorted_plugin.is_empty() {
         let preselect_hit =
            preselected_cred.filter(|cred| sorted_plugin.iter().any(|fs| fs.cred_id() == *cred));
         match preselect_hit {
            Some(cred) => sorted_plugin.retain(|fs| fs.cred_id() == cred),
            None => {
               let cred_ids = sorted_plugin
                  .iter()
                  .map(|fs| fs.cred_id())
                  .filter(|cid| !cid.is_empty())
                  .collect::<Vec<&[u8]>>();
               match device.probe_credential(&cred_ids) {
                  Ok(Some(found)) => sorted_plugin.retain(|fs| fs.cred_id() == found.as_slice()),
                  Ok(None) => sorted_plugin.clear(),
                  Err(_) => {},
               }
            },
         }
      }

      // X25519 stanzas, if any; a non-match falls through to the plugin stanzas.
      if !self.is_dataless() && !native_x25519.is_empty() {
         (ctx.notify_touch)();
         match self.load_secret(device, pin) {
            Ok(loaded) => {
               let secret = loaded.to_x25519_secret()?;
               let mut result = Result::Ok(Option::<FileKey>::None);
               for stz in native_x25519 {
                  if stz.tag != "X25519" || stz.args.len() != 1 {
                     continue;
                  }
                  match unwrap_x25519_parts(&secret, &stz.args[0], &stz.body) {
                     Some(Ok(fk)) => {
                        result = Ok(Some(fk));
                        break;
                     },
                     Some(Err(err)) => {
                        result = Err(err);
                        break;
                     },
                     None => {},
                  }
               }
               drop(loaded);
               match result {
                  Ok(Some(fk)) => return Ok(Some(fk)),
                  Err(err) => return Err(err),
                  Ok(None) => {},
               }
            },
            Err(Error::Ctap(CtapStatus::NoCredentials)) => {},
            Err(err) => return Err(err),
         }
      }

      // Each plugin stanza: a Record identity skips non-matching cred_ids; a
      // Dataless placeholder adopts every stanza's fields.
      'stanza: for fs in sorted_plugin {
         let (cred_id, require_pin, public_key) = match self.kind {
            IdentityKind::Record {
               ref cred_id,
               require_pin,
               ref public_key,
               ..
            } => {
               let cred_id = cred_id.as_slice();
               if cred_id != fs.cred_id() {
                  continue;
               }
               (cred_id, require_pin || fs.require_pin(), Some(public_key))
            },
            IdentityKind::Dataless => (fs.cred_id(), fs.require_pin(), None),
         };
         let salt = *fs.salt();
         let dyn_pin = if require_pin { pin } else { None };
         if require_pin && dyn_pin.is_none() {
            return Err(Error::PinRequired);
         }
         // Cache hit: no second touch.
         let cache_key = (Box::<[u8]>::from(cred_id), salt);
         let cached = ctx
            .hmac_cache
            .get(&cache_key)
            .map(|secret| SecretBox::new(Box::new(*secret.expose_secret())));
         let secret = match cached {
            Some(secret) => secret,
            None => {
               (ctx.notify_touch)();
               let derived = match device.get_hmac_secret(cred_id, &salt, dyn_pin, public_key) {
                  Ok(secret) => secret,
                  // Non-selected miss; YubiKey may report 0x27 instead of 0x2E.
                  Err(Error::Ctap(CtapStatus::NoCredentials | CtapStatus::OperationDenied))
                     if preselected_cred != Some(cred_id) =>
                  {
                     continue 'stanza;
                  },
                  // Selected credential: 0x27/0x2E means lapsed touch; reopen.
                  Err(Error::Ctap(CtapStatus::NoCredentials | CtapStatus::OperationDenied)) => {
                     return Err(Error::Ctap(CtapStatus::UserActionTimeout));
                  },
                  Err(err) => return Err(err),
               };
               ctx.hmac_cache.insert(
                  cache_key,
                  SecretBox::new(Box::new(*derived.expose_secret())),
               );
               derived
            },
         };
         if let Err(err) = mlock::mlock(secret.expose_secret()) {
            self.mlock_warning = Some(format!("Warning: failed to call mlock: {err}"));
         }
         let static_secret = StaticSecret::from(*secret.expose_secret());
         drop(secret);
         let result = unwrap_x25519_parts(&static_secret, fs.native_share(), fs.body());
         match result {
            Some(Ok(fk)) => return Ok(Some(fk)),
            Some(Err(err)) => return Err(err),
            None => {},
         }
      }

      Ok(None)
   }
}

/// Unwrap an X25519 stanza from its parts.
fn unwrap_x25519_parts(
   secret: &StaticSecret,
   native_share: &str,
   body: &[u8],
) -> Option<Result<FileKey>> {
   let mut epk_bytes = [0_u8; 32];
   let decoded = STANDARD_NO_PAD.decode(native_share.as_bytes()).ok()?;
   if decoded.len() != 32 {
      return None;
   }
   epk_bytes.copy_from_slice(&decoded);

   if body.len() != FILE_KEY_BYTES + 16 {
      return None;
   }

   let epk = PublicKey::from(epk_bytes);
   let shared = secret.diffie_hellman(&epk);
   if bool::from(shared.as_bytes().ct_eq(&[0_u8; 32])) {
      return Some(Err(Error::AgeDecrypt(
         "x25519: low-order shared secret".into(),
      )));
   }

   let mut salt = [0_u8; 64];
   salt[..32].copy_from_slice(&epk_bytes);
   salt[32..].copy_from_slice(PublicKey::from(secret).as_bytes());
   let key = hkdf(&salt, X25519_HKDF_LABEL, shared.as_bytes());

   let mut plaintext = aead_decrypt(&key, FILE_KEY_BYTES, body).ok()?;
   let fk = FileKey::init_with_mut(|dest| dest.copy_from_slice(&plaintext));
   plaintext.zeroize();
   Some(Ok(fk))
}

/// Borrowed handle returned by [`Identity::load_secret`].
///
/// While alive it grants access to the cached HMAC secret, and on drop the
/// secret is cleared from the underlying [`Identity`].
#[derive(Debug)]
pub struct LoadedIdentity<'a> {
   id: &'a mut Identity,
}

impl LoadedIdentity<'_> {
   /// Derive an X25519 [`StaticSecret`] from the cached HMAC secret.
   pub fn to_x25519_secret(&self) -> Result<StaticSecret> {
      let secret = self
         .id
         .secret
         .as_ref()
         .ok_or_else(|| Error::InvalidFormat("secret not loaded".into()))?;
      Ok(StaticSecret::from(*secret.expose_secret()))
   }

   /// Public recipient derived from the cached secret. Errors on a
   /// dataless placeholder.
   pub fn to_recipient(&self) -> Result<Recipient> {
      let IdentityKind::Record {
         require_pin,
         salt,
         ref cred_id,
         ..
      } = self.id.kind
      else {
         return Err(Error::InvalidFormat(
            "identity: dataless placeholder has no recipient".into(),
         ));
      };
      let secret = self.to_x25519_secret()?;
      let native_pubkey = *PublicKey::from(&secret).as_bytes();
      Recipient::new(native_pubkey, require_pin, salt, cred_id.clone())
   }

   /// Drain any pending `mlock(2)` failure warning from the underlying
   /// identity. Mirror of [`Identity::take_mlock_warning`] so callers
   /// can stay on the `LoadedIdentity` handle for the duration of
   /// secret work.
   pub const fn take_mlock_warning(&mut self) -> Option<String> {
      self.id.mlock_warning.take()
   }
}

impl Drop for LoadedIdentity<'_> {
   fn drop(&mut self) {
      self.id.clear_secret();
   }
}

impl fmt::Debug for Identity {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.debug_struct("Identity")
         .field("require_pin", &self.require_pin())
         .field("salt", &"<32 bytes>")
         .field("cred_id_len", &self.cred_id().len())
         .field(
            "public_key",
            &self.public_key().map_or("<none>", |_| "<cose>"),
         )
         .field("secret", &self.secret.as_ref().map(|_| "<loaded>"))
         .field(
            "mlock_warning",
            &self.mlock_warning.as_deref().unwrap_or("<none>"),
         )
         .finish_non_exhaustive()
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn rejects_v1() {
      let mut data = vec![0, 1, 0];
      data.extend_from_slice(b"old-cred");
      let encoded = bech32_encode(IDENTITY_HRP, &data).unwrap();
      match encoded.to_uppercase().parse::<Identity>() {
         Err(Error::UnsupportedVersion(1)) => {},
         other => panic!("expected UnsupportedVersion(1), got {other:?}"),
      }
   }
}
