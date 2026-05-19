//! v2 [`Recipient`] parsing and encoding.

use std::{
   fmt,
   str::FromStr,
};

use age_core::{
   format::{
      FILE_KEY_BYTES,
      FileKey,
   },
   primitives::{
      aead_encrypt,
      hkdf,
   },
};
use base64::{
   Engine as _,
   engine::general_purpose::STANDARD_NO_PAD,
};
use rand::Rng as _;
use secrecy::ExposeSecret as _;
use subtle::ConstantTimeEq as _;
use x25519_dalek::{
   PublicKey,
   StaticSecret,
};
use zeroize::Zeroize as _;

use crate::{
   error::{
      Error,
      Result,
   },
   format::{
      RECIPIENT_HRP,
      RECIPIENT_VERSION,
      bech32_decode,
      bech32_encode,
   },
   stanza::Fido2HmacStanza,
};

/// HKDF label used by age's X25519 stanza format.
const X25519_HKDF_LABEL: &[u8] = b"age-encryption.org/v1/X25519";

/// A v2 fido2-hmac recipient. The on-wire version is the constant
/// [`RECIPIENT_VERSION`] and isn't carried in the struct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
   native_pubkey: [u8; 32],
   require_pin:   bool,
   salt:          [u8; 32],
   cred_id:       Vec<u8>,
}

impl Recipient {
   /// Construct a recipient, validating field invariants:
   /// - `native_pubkey` must not be all-zero (low-order point).
   /// - `cred_id` must be non-empty and fit in `u16` length.
   ///
   /// # Errors
   ///
   /// [`Error::InvalidFormat`] when any invariant fails.
   pub fn new(
      native_pubkey: [u8; 32],
      require_pin: bool,
      salt: [u8; 32],
      cred_id: Vec<u8>,
   ) -> Result<Self> {
      if native_pubkey == [0_u8; 32] {
         return Err(Error::InvalidFormat(
            "recipient: all-zero X25519 pubkey".into(),
         ));
      }
      if cred_id.is_empty() {
         return Err(Error::InvalidFormat("recipient: cred_id is empty".into()));
      }
      if u16::try_from(cred_id.len()).is_err() {
         return Err(Error::InvalidFormat(
            "recipient: cred_id exceeds u16 length".into(),
         ));
      }
      Ok(Self {
         native_pubkey,
         require_pin,
         salt,
         cred_id,
      })
   }

   /// 32-byte X25519 public key derived from the HMAC secret.
   #[must_use]
   pub const fn native_pubkey(&self) -> &[u8; 32] {
      &self.native_pubkey
   }

   /// True if a PIN is required when unwrapping.
   #[must_use]
   pub const fn require_pin(&self) -> bool {
      self.require_pin
   }

   /// 32-byte salt used for the hmac-secret assertion.
   #[must_use]
   pub const fn salt(&self) -> &[u8; 32] {
      &self.salt
   }

   /// FIDO2 credential id.
   #[must_use]
   pub fn cred_id(&self) -> &[u8] {
      &self.cred_id
   }

   /// Parse raw recipient payload bytes.
   pub fn from_bytes(data: &[u8]) -> Result<Self> {
      if data.len() < 2 {
         return Err(Error::InvalidFormat("recipient: too short".into()));
      }

      let version = u16::from_be_bytes([data[0], data[1]]);
      if version != RECIPIENT_VERSION {
         return Err(Error::UnsupportedVersion(version));
      }

      if data.len() < 2 + 32 + 1 + 32 {
         return Err(Error::InvalidFormat("recipient: v2 truncated".into()));
      }

      let mut native_pubkey = [0_u8; 32];
      native_pubkey.copy_from_slice(&data[2..34]);

      let require_pin = match data[34] {
         0 => false,
         1 => true,
         other => {
            return Err(Error::InvalidFormat(format!(
               "recipient: bad pin flag {other}"
            )));
         },
      };

      let mut salt = [0_u8; 32];
      salt.copy_from_slice(&data[35..67]);

      let cred_id = data[67..].to_vec();
      Self::new(native_pubkey, require_pin, salt, cred_id)
   }
}

impl FromStr for Recipient {
   type Err = Error;
   fn from_str(input: &str) -> Result<Self> {
      let (hrp, data) = bech32_decode(input)?;
      if hrp != RECIPIENT_HRP {
         return Err(Error::InvalidFormat(format!(
            "recipient: wrong hrp {hrp}, expected {RECIPIENT_HRP}"
         )));
      }
      Self::from_bytes(&data)
   }
}

impl fmt::Display for Recipient {
   /// Bech32-encode this recipient.
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      let mut data = Vec::with_capacity(2 + 32 + 1 + 32 + self.cred_id.len());
      data.extend_from_slice(&RECIPIENT_VERSION.to_be_bytes());
      data.extend_from_slice(&self.native_pubkey);
      data.push(u8::from(self.require_pin));
      data.extend_from_slice(&self.salt);
      data.extend_from_slice(&self.cred_id);
      let encoded = bech32_encode(RECIPIENT_HRP, &data).map_err(|_| fmt::Error)?;
      f.write_str(&encoded)
   }
}

impl Recipient {
   /// Wrap a file key into a single [`Fido2HmacStanza`].
   pub fn wrap(&self, file_key: &FileKey) -> Result<Fido2HmacStanza> {
      let recipient_pk = PublicKey::from(self.native_pubkey);

      let mut esk_bytes = [0_u8; 32];
      rand::rng().fill_bytes(&mut esk_bytes);
      let esk = StaticSecret::from(esk_bytes);
      esk_bytes.zeroize();
      let epk = PublicKey::from(&esk);

      let shared = esk.diffie_hellman(&recipient_pk);
      // Low-order peer public key.
      if bool::from(shared.as_bytes().ct_eq(&[0_u8; 32])) {
         return Err(Error::AgeEncrypt("x25519: low-order shared secret".into()));
      }

      let mut salt = [0_u8; 64];
      salt[..32].copy_from_slice(epk.as_bytes());
      salt[32..].copy_from_slice(recipient_pk.as_bytes());
      let key = hkdf(&salt, X25519_HKDF_LABEL, shared.as_bytes());

      let body = aead_encrypt(&key, file_key.expose_secret());
      let native_share = STANDARD_NO_PAD.encode(epk.as_bytes());

      Fido2HmacStanza::new(
         self.require_pin,
         self.salt,
         self.cred_id.clone(),
         native_share,
         body,
      )
   }
}

const _: () = assert!(FILE_KEY_BYTES == 16);

#[cfg(test)]
mod tests {
   use super::*;

   fn sample() -> Recipient {
      Recipient {
         native_pubkey: [0x42; 32],
         require_pin:   true,
         salt:          [0x37; 32],
         cred_id:       vec![0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03],
      }
   }

   #[test]
   fn roundtrip() {
      let rcpt = sample();
      let encoded = rcpt.to_string();
      let parsed = encoded.parse::<Recipient>().unwrap();
      assert_eq!(parsed, rcpt);
   }

   #[test]
   fn rejects_v1() {
      let mut data = vec![0, 1, 0];
      data.extend_from_slice(b"cred-id-bytes");
      let encoded = bech32_encode(RECIPIENT_HRP, &data).unwrap();
      match encoded.parse::<Recipient>() {
         Err(Error::UnsupportedVersion(1)) => {},
         other => panic!("expected UnsupportedVersion(1), got {other:?}"),
      }
   }

   #[test]
   fn rejects_truncated_v2() {
      let encoded = bech32_encode(RECIPIENT_HRP, &[0, 2, 0, 0, 0]).unwrap();
      encoded.parse::<Recipient>().unwrap_err();
   }

   #[test]
   fn rejects_wrong_hrp() {
      let encoded = bech32_encode("age1other", &[0, 2]).unwrap();
      encoded.parse::<Recipient>().unwrap_err();
   }

   #[test]
   fn rejects_bad_pin_flag() {
      let mut data = vec![0, 2];
      data.extend_from_slice(&[0; 32]);
      data.push(7);
      data.extend_from_slice(&[0; 32]);
      data.extend_from_slice(b"cred");
      let encoded = bech32_encode(RECIPIENT_HRP, &data).unwrap();
      encoded.parse::<Recipient>().unwrap_err();
   }

   #[test]
   fn rejects_all_zero_pubkey() {
      let mut data = vec![0, 2];
      data.extend_from_slice(&[0_u8; 32]);
      data.push(0);
      data.extend_from_slice(&[0_u8; 32]);
      data.extend_from_slice(b"cred");
      let encoded = bech32_encode(RECIPIENT_HRP, &data).unwrap();
      match encoded.parse::<Recipient>() {
         Err(Error::InvalidFormat(msg)) => assert!(msg.contains("all-zero")),
         other => panic!("expected InvalidFormat all-zero error, got {other:?}"),
      }
   }
}
