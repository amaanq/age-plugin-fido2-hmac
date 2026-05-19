//! v2 plugin stanza parse and encode.

use age_core::format::Stanza;
use base64::{
   Engine as _,
   engine::general_purpose::STANDARD_NO_PAD,
};

use crate::{
   error::{
      Error,
      Result,
   },
   format::{
      PLUGIN_NAME,
      STANZA_VERSION,
   },
};

/// Domain-level v2 fido2-hmac stanza. The on-wire version is the
/// constant [`STANZA_VERSION`] and isn't carried in the struct.
///
/// Fields are private so the type's invariants (non-empty `cred_id`,
/// non-empty `native_share`) are enforced at construction time. Use
/// [`Self::new`] or [`Self::parse`] / [`TryFrom`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fido2HmacStanza {
   require_pin:  bool,
   salt:         [u8; 32],
   cred_id:      Vec<u8>,
   native_share: String,
   body:         Vec<u8>,
}

impl Fido2HmacStanza {
   /// Build a stanza, validating that `cred_id` is non-empty and
   /// `native_share` (the base64 X25519 ephemeral share) is non-empty.
   ///
   /// # Errors
   ///
   /// [`Error::InvalidFormat`] when either invariant fails.
   pub fn new(
      require_pin: bool,
      salt: [u8; 32],
      cred_id: Vec<u8>,
      native_share: String,
      body: Vec<u8>,
   ) -> Result<Self> {
      if cred_id.is_empty() {
         return Err(Error::InvalidFormat("stanza: cred_id is empty".into()));
      }
      if native_share.is_empty() {
         return Err(Error::InvalidFormat("stanza: native share is empty".into()));
      }
      Ok(Self {
         require_pin,
         salt,
         cred_id,
         native_share,
         body,
      })
   }

   /// PIN-required flag.
   #[must_use]
   pub const fn require_pin(&self) -> bool {
      self.require_pin
   }

   /// 32-byte hmac-secret salt.
   #[must_use]
   pub const fn salt(&self) -> &[u8; 32] {
      &self.salt
   }

   /// FIDO2 credential id.
   #[must_use]
   pub fn cred_id(&self) -> &[u8] {
      &self.cred_id
   }

   /// Base64 X25519 ephemeral share.
   #[must_use]
   pub fn native_share(&self) -> &str {
      &self.native_share
   }

   /// Native stanza body (X25519-wrapped file-key bytes).
   #[must_use]
   pub fn body(&self) -> &[u8] {
      &self.body
   }

   /// Parse raw stanza args and body.
   pub fn parse(args: &[String], body: Vec<u8>) -> Result<Self> {
      let parsed = parse_stanza_args(args)?;
      Self::new(
         parsed.require_pin,
         parsed.salt,
         parsed.cred_id,
         parsed.native_share.to_owned(),
         body,
      )
   }

   /// Encode to protocol args and body. Cannot fail — the type
   /// invariants (set by [`Self::parse`] or by callers that construct
   /// this directly) are all the encoder needs.
   #[must_use]
   pub fn encode(&self) -> (Vec<String>, Vec<u8>) {
      let args = vec![
         STANDARD_NO_PAD.encode(STANZA_VERSION.to_be_bytes()),
         self.native_share.clone(),
         STANDARD_NO_PAD.encode([u8::from(self.require_pin)]),
         STANDARD_NO_PAD.encode(self.salt),
         STANDARD_NO_PAD.encode(&self.cred_id),
      ];
      (args, self.body.clone())
   }

   /// Stanza tag (always `fido2-hmac`).
   #[must_use]
   pub const fn tag() -> &'static str {
      PLUGIN_NAME
   }
}

/// Decoded stanza args shared by the owned and borrowed parsers; non-empty
/// checks are left to each constructor.
struct StanzaArgs<'a> {
   require_pin:  bool,
   salt:         [u8; 32],
   cred_id:      Vec<u8>,
   native_share: &'a str,
}

/// Decode and length-validate a stanza's five args.
fn parse_stanza_args(args: &[String]) -> Result<StanzaArgs<'_>> {
   if args.len() != 5 {
      return Err(Error::InvalidFormat(format!(
         "stanza: expected 5 args, got {}",
         args.len()
      )));
   }

   let version_bytes = STANDARD_NO_PAD
      .decode(&args[0])
      .map_err(|err| Error::InvalidFormat(format!("stanza version b64: {err}")))?;
   if version_bytes.len() != 2 {
      return Err(Error::InvalidFormat("stanza: version not 2 bytes".into()));
   }
   let version = u16::from_be_bytes([version_bytes[0], version_bytes[1]]);
   if version != STANZA_VERSION {
      return Err(Error::UnsupportedVersion(version));
   }

   let native_share = args[1].as_str();

   let pin_bytes = STANDARD_NO_PAD
      .decode(&args[2])
      .map_err(|err| Error::InvalidFormat(format!("stanza pin flag b64: {err}")))?;
   if pin_bytes.len() != 1 {
      return Err(Error::InvalidFormat("stanza: pin flag not 1 byte".into()));
   }
   let require_pin = match pin_bytes[0] {
      0 => false,
      1 => true,
      other => {
         return Err(Error::InvalidFormat(format!(
            "stanza: bad pin flag {other}"
         )));
      },
   };

   let salt_bytes = STANDARD_NO_PAD
      .decode(&args[3])
      .map_err(|err| Error::InvalidFormat(format!("stanza salt b64: {err}")))?;
   if salt_bytes.len() != 32 {
      return Err(Error::InvalidFormat("stanza: salt not 32 bytes".into()));
   }
   let mut salt = [0_u8; 32];
   salt.copy_from_slice(&salt_bytes);

   let cred_id = STANDARD_NO_PAD
      .decode(&args[4])
      .map_err(|err| Error::InvalidFormat(format!("stanza cred id b64: {err}")))?;

   Ok(StanzaArgs {
      require_pin,
      salt,
      cred_id,
      native_share,
   })
}

impl TryFrom<Stanza> for Fido2HmacStanza {
   type Error = Error;
   fn try_from(stanza: Stanza) -> Result<Self> {
      if stanza.tag != PLUGIN_NAME {
         return Err(Error::InvalidFormat(format!(
            "stanza: wrong tag {:?}, expected {PLUGIN_NAME}",
            stanza.tag
         )));
      }
      Self::parse(&stanza.args, stanza.body)
   }
}

/// Borrowed read-only view over a parsed [`Stanza`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fido2HmacStanzaRef<'a> {
   require_pin:  bool,
   salt:         [u8; 32],
   cred_id:      Vec<u8>,
   native_share: &'a str,
   body:         &'a [u8],
}

impl<'a> Fido2HmacStanzaRef<'a> {
   /// PIN-required flag.
   #[must_use]
   pub const fn require_pin(&self) -> bool {
      self.require_pin
   }

   /// 32-byte hmac-secret salt.
   #[must_use]
   pub const fn salt(&self) -> &[u8; 32] {
      &self.salt
   }

   /// FIDO2 credential id.
   #[must_use]
   pub fn cred_id(&self) -> &[u8] {
      &self.cred_id
   }

   /// Base64 X25519 ephemeral share, borrowed from the source stanza.
   #[must_use]
   pub const fn native_share(&self) -> &'a str {
      self.native_share
   }

   /// Stanza body (X25519-wrapped file key), borrowed from the source.
   #[must_use]
   pub const fn body(&self) -> &'a [u8] {
      self.body
   }
}

impl<'a> TryFrom<&'a Stanza> for Fido2HmacStanzaRef<'a> {
   type Error = Error;
   fn try_from(stanza: &'a Stanza) -> Result<Self> {
      if stanza.tag != PLUGIN_NAME {
         return Err(Error::InvalidFormat(format!(
            "stanza: wrong tag {:?}, expected {PLUGIN_NAME}",
            stanza.tag
         )));
      }
      let parsed = parse_stanza_args(&stanza.args)?;
      if parsed.native_share.is_empty() {
         return Err(Error::InvalidFormat("stanza: native share is empty".into()));
      }
      if parsed.cred_id.is_empty() {
         return Err(Error::InvalidFormat("stanza: cred_id is empty".into()));
      }

      Ok(Self {
         require_pin:  parsed.require_pin,
         salt:         parsed.salt,
         cred_id:      parsed.cred_id,
         native_share: parsed.native_share,
         body:         &stanza.body,
      })
   }
}

impl From<Fido2HmacStanza> for Stanza {
   fn from(stz: Fido2HmacStanza) -> Self {
      let Fido2HmacStanza {
         require_pin,
         salt,
         cred_id,
         native_share,
         body,
      } = stz;
      let args = vec![
         STANDARD_NO_PAD.encode(STANZA_VERSION.to_be_bytes()),
         native_share,
         STANDARD_NO_PAD.encode([u8::from(require_pin)]),
         STANDARD_NO_PAD.encode(salt),
         STANDARD_NO_PAD.encode(&cred_id),
      ];
      Self {
         tag: PLUGIN_NAME.into(),
         args,
         body,
      }
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   fn sample() -> Fido2HmacStanza {
      Fido2HmacStanza {
         require_pin:  true,
         salt:         [0x55; 32],
         cred_id:      vec![0xCA, 0xFE, 0xBA, 0xBE],
         native_share: "abcDEF123".into(),
         body:         vec![1, 2, 3, 4, 5],
      }
   }

   #[test]
   fn roundtrip() {
      let stz = sample();
      let (args, body) = stz.encode();
      let parsed = Fido2HmacStanza::parse(&args, body).unwrap();
      assert_eq!(parsed, stz);
   }

   #[test]
   fn roundtrip_via_age_stanza() {
      let stz = sample();
      let raw = Stanza::from(stz.clone());
      let parsed = Fido2HmacStanza::try_from(raw).unwrap();
      assert_eq!(parsed, stz);
   }

   #[test]
   fn rejects_wrong_arg_count() {
      let result = Fido2HmacStanza::parse(&["a".into(), "b".into()], vec![]);
      result.unwrap_err();
   }

   #[test]
   fn rejects_v1_version_byte() {
      let args = vec![
         STANDARD_NO_PAD.encode(1_u16.to_be_bytes()),
         "share".into(),
         STANDARD_NO_PAD.encode([0_u8]),
         STANDARD_NO_PAD.encode([0_u8; 32]),
         STANDARD_NO_PAD.encode([0_u8]),
      ];
      match Fido2HmacStanza::parse(&args, vec![]) {
         Err(Error::UnsupportedVersion(1)) => {},
         other => panic!("expected UnsupportedVersion(1), got {other:?}"),
      }
   }
}
