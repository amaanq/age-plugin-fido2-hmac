//! Dataless ("magic") identity strings.
//!
//! These placeholders tell unwrap to adopt credential ID, salt, and PIN flag
//! from each stanza instead of from an identity file.

use std::sync::LazyLock;

use crate::format::bech32_decode;

/// Identity string the legacy `-m` flag once emitted.
pub const LEGACY_MAGIC_IDENTITY: &str = "AGE-PLUGIN-FIDO2-HMAC-1VE5KGMEJ945X6CTRM2TF76";

/// Identity string `age -j fido2-hmac` injects.
pub const AGE_J_MAGIC_IDENTITY: &str = "AGE-PLUGIN-FIDO2-HMAC-188VDVA";

/// Bech32-decoded payload of [`LEGACY_MAGIC_IDENTITY`].
static LEGACY_MAGIC_BYTES: LazyLock<Vec<u8>> = LazyLock::new(|| {
   bech32_decode(LEGACY_MAGIC_IDENTITY)
      .expect("LEGACY_MAGIC_IDENTITY is a valid bech32 constant")
      .1
});

/// Bech32-decoded payload of [`AGE_J_MAGIC_IDENTITY`].
static AGE_J_MAGIC_BYTES: LazyLock<Vec<u8>> = LazyLock::new(|| {
   bech32_decode(AGE_J_MAGIC_IDENTITY)
      .expect("AGE_J_MAGIC_IDENTITY is a valid bech32 constant")
      .1
});

/// True if `s` is one of the recognized dataless identity strings.
///
/// Case-exact: the input must match the canonical uppercase form.
#[must_use]
pub fn is_dataless(input: &str) -> bool {
   input == LEGACY_MAGIC_IDENTITY || input == AGE_J_MAGIC_IDENTITY
}

/// True if `bytes` is the payload of one of the recognized dataless
/// identity strings (i.e., what the age plugin protocol hands us after
/// stripping bech32).
pub fn is_dataless_bytes(bytes: &[u8]) -> bool {
   bytes == LEGACY_MAGIC_BYTES.as_slice() || bytes == AGE_J_MAGIC_BYTES.as_slice()
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn recognizes_both() {
      assert!(is_dataless(LEGACY_MAGIC_IDENTITY));
      assert!(is_dataless(AGE_J_MAGIC_IDENTITY));
   }

   #[test]
   fn rejects_other_strings() {
      assert!(!is_dataless(""));
      assert!(!is_dataless("AGE-PLUGIN-FIDO2-HMAC-2OTHER"));
      assert!(!is_dataless("AGE-SECRET-KEY-1ABCDEF"));
   }

   #[test]
   fn byte_form_matches_decoded_strings() {
      let legacy_bytes = bech32_decode(LEGACY_MAGIC_IDENTITY).unwrap().1;
      let age_j_bytes = bech32_decode(AGE_J_MAGIC_IDENTITY).unwrap().1;
      assert!(is_dataless_bytes(&legacy_bytes));
      assert!(is_dataless_bytes(&age_j_bytes));
   }

   #[test]
   fn byte_form_rejects_others() {
      // Non-empty arbitrary bytes are not dataless.
      assert!(!is_dataless_bytes(&[0, 2, 0]));
      assert!(!is_dataless_bytes(b"AGE-SECRET-KEY-1ABCDEF"));
      // A valid v2 identity payload (version + pin flag + zero salt +
      // dummy cred) is NOT dataless.
      let mut v2_payload = vec![0, 2, 0];
      v2_payload.extend_from_slice(&[0_u8; 32]);
      v2_payload.extend_from_slice(b"cred");
      assert!(!is_dataless_bytes(&v2_payload));
   }

   #[test]
   fn age_j_magic_decodes_to_empty_payload() {
      // age -d -j fido2-hmac hands the plugin an empty decoded payload.
      assert!(AGE_J_MAGIC_BYTES.is_empty());
      assert!(is_dataless_bytes(&[]));
   }
}
