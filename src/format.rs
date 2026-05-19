//! On-wire constants and bech32 helpers.

use bech32::{
   Bech32,
   Hrp,
};

use crate::error::Error;

/// The age plugin name used in stanza tags and HRP suffixes.
pub const PLUGIN_NAME: &str = "fido2-hmac";

/// Bech32 HRP for [`Recipient::encode`](crate::recipient::Recipient::encode).
pub const RECIPIENT_HRP: &str = "age1fido2-hmac";

/// Bech32 HRP for [`Identity::encode`](crate::identity::Identity::encode).
pub const IDENTITY_HRP: &str = "age-plugin-fido2-hmac-";

/// The Relying Party ID we register credentials under. Fixed forever
/// because changing it would invalidate every existing recipient.
pub const RELYING_PARTY: &str = "age-encryption.org";

/// On-wire format version for [`Identity`](crate::identity::Identity)
/// blobs. Bumped to 3 when the credential public key joined identities.
pub const IDENTITY_VERSION: u16 = 3;

/// On-wire format version for [`Recipient`](crate::recipient::Recipient)
/// blobs.
pub const RECIPIENT_VERSION: u16 = 2;

/// On-wire format version for
/// [`Fido2HmacStanza`](crate::stanza::Fido2HmacStanza) blobs.
pub const STANZA_VERSION: u16 = 2;

/// Encode bytes as bech32 with the given HRP using the bech32 v1 variant.
pub fn bech32_encode(hrp: &str, data: &[u8]) -> Result<String, Error> {
   let hrp_parsed =
      Hrp::parse(hrp).map_err(|err| Error::InvalidFormat(format!("bad hrp {hrp}: {err}")))?;
   bech32::encode::<Bech32>(hrp_parsed, data)
      .map_err(|err| Error::InvalidFormat(format!("bech32 encode: {err}")))
}

/// Decode a bech32 string, returning `(hrp, data_bytes)`. Case-insensitive on
/// input.
pub fn bech32_decode(input: &str) -> Result<(String, Vec<u8>), Error> {
   let (hrp, data) = bech32::decode(&input.to_lowercase())
      .map_err(|err| Error::InvalidFormat(format!("bech32 decode: {err}")))?;
   Ok((hrp.to_string(), data))
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn roundtrip_arbitrary_bytes() {
      let data = b"hello world, this is some payload";
      let encoded = bech32_encode(RECIPIENT_HRP, data).unwrap();
      let (hrp, decoded) = bech32_decode(&encoded).unwrap();
      assert_eq!(hrp, RECIPIENT_HRP);
      assert_eq!(decoded, data);
   }

   #[test]
   fn identity_hrp_uppercase_input_decodes() {
      let encoded = bech32_encode(IDENTITY_HRP, b"\x00\x02test").unwrap();
      let upper = encoded.to_uppercase();
      let (hrp, _) = bech32_decode(&upper).unwrap();
      assert_eq!(hrp, IDENTITY_HRP);
   }

   #[test]
   fn bad_input_errors_cleanly() {
      bech32_decode("not a bech32 string").unwrap_err();
   }
}
