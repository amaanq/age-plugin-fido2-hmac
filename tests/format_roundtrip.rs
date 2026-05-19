//! End-to-end format round-trip tests.

use age_plugin_fido2_hmac::{
   identity::Identity,
   recipient::Recipient,
   stanza::Fido2HmacStanza,
};
use ctap_fido2::cose::CredentialPublicKey;

/// Minimal ES256 `COSE_Key` blob with zero coordinates. Only used for
/// `identity_roundtrip_full` below; structurally valid for `from_cose_bytes`
/// but useless for actual verification (which this test doesn't need).
const FAKE_ES256_COSE: &[u8] = &[
   0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x22, 0x58, 0x20, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn sample_es256_pubkey() -> CredentialPublicKey {
   CredentialPublicKey::from_cose_bytes(FAKE_ES256_COSE.to_vec()).expect("test COSE parse")
}

#[test]
fn recipient_roundtrip_full() {
   let rcpt = Recipient::new(
      [
         0x73, 0xF5, 0xF3, 0x88, 0x91, 0x4D, 0x4F, 0x32, 0x99, 0x9C, 0xC0, 0xC7, 0x5C, 0x52, 0x6F,
         0x36, 0x4C, 0xF6, 0xD4, 0x67, 0x95, 0xFE, 0xE9, 0xD8, 0x9B, 0xBE, 0xF0, 0x44, 0xFF, 0x9B,
         0x7E, 0xAA,
      ],
      true,
      [0xA5; 32],
      vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x42, 0x42, 0x42],
   )
   .unwrap();
   let encoded = rcpt.to_string();
   assert!(encoded.starts_with("age1fido2-hmac"));
   let rcpt2 = encoded.parse::<Recipient>().unwrap();
   assert_eq!(rcpt, rcpt2);
   assert_eq!(encoded, rcpt2.to_string());
}

#[test]
fn identity_roundtrip_full() {
   let idt = Identity::record(
      false,
      [0x10; 32],
      vec![0xFE, 0xED, 0xC0, 0xDE],
      sample_es256_pubkey(),
   )
   .unwrap();
   let encoded = idt.encode().unwrap();
   assert!(encoded.starts_with("AGE-PLUGIN-FIDO2-HMAC-"));
   let idt2 = encoded.parse::<Identity>().unwrap();
   assert_eq!(idt.require_pin(), idt2.require_pin());
   assert_eq!(idt.salt(), idt2.salt());
   assert_eq!(idt.cred_id(), idt2.cred_id());
   assert_eq!(idt.public_key(), idt2.public_key());
}

#[test]
fn stanza_args_count_and_lengths() {
   let stanza = Fido2HmacStanza::new(
      true,
      [0x21; 32],
      vec![0x01, 0x02, 0x03, 0x04],
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq".into(),
      b"sixteen-byte-bod".to_vec(),
   )
   .unwrap();
   let (args, body) = stanza.encode();
   assert_eq!(args.len(), 5);
   assert_eq!(body, stanza.body());
   let parsed = Fido2HmacStanza::parse(&args, body).unwrap();
   assert_eq!(parsed, stanza);
}
