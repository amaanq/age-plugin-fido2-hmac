//! Integration tests that need a [`MockDevice`]: `Identity` wrap/unwrap,
//! `Recipient` wrap, and the age-plugin protocol layer. Everything that
//! uses the mock lives in one file so the helpers below have a user in
//! the same crate and don't trigger dead-code warnings.

use core::result::Result as StdResult;
use std::{
   cell::Cell,
   io,
   rc::Rc,
};

use age_core::{
   format::{
      FileKey,
      Stanza,
   },
   plugin,
};
use age_plugin::{
   Callbacks,
   identity::{
      self as plugin_identity,
      IdentityPluginV1,
   },
   recipient::{
      self as plugin_recipient,
      RecipientPluginV1,
   },
};
use age_plugin_fido2_hmac::{
   device::{
      Algorithm,
      Fido2Device,
      GeneratedCredential,
   },
   error::{
      Error,
      Result,
   },
   format::PLUGIN_NAME,
   identity::Identity,
   plugin::{
      IdentityImpl,
      RecipientImpl,
   },
};
use bech32::{
   Bech32,
   primitives::decode::CheckedHrpstring,
};
use ctap_fido2::{
   cose::CredentialPublicKey,
   error::CtapStatus,
};
use secrecy::{
   ExposeSecret as _,
   SecretBox,
   SecretString,
};

// --- shared helpers -------------------------------------------------------

const FAKE_ES256_COSE: &[u8] = &[
   0xA5, // map(5)
   0x01, 0x02, // kty(1) = EC2(2)
   0x03, 0x26, // alg(3) = ES256(-7)
   0x20, 0x01, // crv(-1) = P-256(1)
   0x21, 0x58, 0x20, // x(-2) = bytes(32)
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0x22, 0x58, 0x20, // y(-3) = bytes(32)
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn sample_es256_pubkey() -> CredentialPublicKey {
   CredentialPublicKey::from_cose_bytes(FAKE_ES256_COSE.to_vec()).expect("test COSE parse")
}

struct MockDevice {
   cred_id:     Vec<u8>,
   hmac_secret: [u8; 32],
   /// Bump to make the next N `get_hmac_secret` calls fail with
   /// [`CtapStatus::PinInvalid`]. Used to exercise the PIN-retry path.
   fail_count:  Cell<u32>,
   /// Count of `get_hmac_secret` calls (the device "touch"). Shared so a
   /// test can read it after the device is moved into the plugin.
   calls:       Rc<Cell<u32>>,
}

impl MockDevice {
   fn new(cred_id: &[u8], hmac_secret: [u8; 32]) -> Self {
      Self {
         cred_id: cred_id.to_vec(),
         hmac_secret,
         fail_count: Cell::new(0),
         calls: Rc::new(Cell::new(0)),
      }
   }
}

impl Fido2Device for MockDevice {
   fn has_pin_set(&self) -> Result<bool> {
      Ok(false)
   }

   fn generate_credential(&self, _: Option<&str>, _: Algorithm) -> Result<GeneratedCredential> {
      Ok(GeneratedCredential {
         id:         self.cred_id.clone(),
         public_key: sample_es256_pubkey(),
      })
   }

   fn get_hmac_secret(
      &self,
      _: &[u8],
      salt: &[u8; 32],
      _: Option<&str>,
      _: Option<&CredentialPublicKey>,
   ) -> Result<SecretBox<[u8; 32]>> {
      self.calls.set(self.calls.get() + 1);
      let remaining = self.fail_count.get();
      if remaining > 0 {
         self.fail_count.set(remaining - 1);
         return Err(Error::Ctap(CtapStatus::PinInvalid));
      }
      let mut out = self.hmac_secret;
      for i in 0..32 {
         out[i] ^= salt[i];
      }
      Ok(SecretBox::new(Box::new(out)))
   }

   fn probe_credential(&self, allow_list: &[&[u8]]) -> Result<Option<Vec<u8>>> {
      Ok(allow_list
         .iter()
         .find(|cred| *cred == &self.cred_id.as_slice())
         .map(|cred| cred.to_vec()))
   }

   fn serial(&self) -> Option<&str> {
      None
   }
}

fn mock_box(cred_id: &[u8], secret: [u8; 32]) -> Box<dyn Fido2Device> {
   Box::new(MockDevice::new(cred_id, secret))
}

fn sample() -> Identity {
   Identity::record(
      false,
      [0x11; 32],
      vec![0xAA, 0xBB, 0xCC],
      sample_es256_pubkey(),
   )
   .unwrap()
}

type AgeCoreErr = plugin::Error;

#[derive(Default)]
struct RecordingCallbacks {
   confirm_answers: Vec<bool>,
   secret_answers:  Vec<String>,
   messages:        Vec<String>,
}

impl RecordingCallbacks {
   fn confirm(mut self, yes: bool) -> Self {
      self.confirm_answers.push(yes);
      self
   }
   fn secret<S>(mut self, value: S) -> Self
   where
      S: Into<String>,
   {
      self.secret_answers.push(value.into());
      self
   }
}

impl<E: Send> Callbacks<E> for RecordingCallbacks {
   fn message(&mut self, message: &str) -> io::Result<StdResult<(), AgeCoreErr>> {
      self.messages.push(message.to_owned());
      Ok(Ok(()))
   }

   fn confirm(
      &mut self,
      _: &str,
      _: &str,
      _: Option<&str>,
   ) -> io::Result<StdResult<bool, AgeCoreErr>> {
      let answer = if self.confirm_answers.is_empty() {
         false
      } else {
         self.confirm_answers.remove(0)
      };
      Ok(Ok(answer))
   }

   fn request_public(&mut self, _: &str) -> io::Result<StdResult<String, AgeCoreErr>> {
      Ok(Ok(String::new()))
   }

   fn request_secret(&mut self, _: &str) -> io::Result<StdResult<SecretString, AgeCoreErr>> {
      let answer = if self.secret_answers.is_empty() {
         String::new()
      } else {
         self.secret_answers.remove(0)
      };
      Ok(Ok(SecretString::from(answer)))
   }

   fn error(&mut self, _: E) -> io::Result<StdResult<(), AgeCoreErr>> {
      Ok(Ok(()))
   }
}

fn wrap_one_for_recipient(secret: [u8; 32], salt: [u8; 32], cred_id: &[u8]) -> (Vec<u8>, Stanza) {
   let mut wrapper =
      Identity::record(false, salt, cred_id.to_vec(), sample_es256_pubkey()).unwrap();
   let mock = MockDevice::new(cred_id, secret);
   let file_key = FileKey::new(Box::new([0xAB_u8; 16]));
   let fs = wrapper.wrap(&mock, None, &file_key).unwrap();
   let (args, body) = fs.encode();
   let stanza = Stanza {
      tag: PLUGIN_NAME.into(),
      args,
      body,
   };
   (file_key.expose_secret().to_vec(), stanza)
}

fn bech32_payload_of(encoded: &str) -> Vec<u8> {
   let lower = encoded.to_lowercase();
   let stripped = CheckedHrpstring::new::<Bech32>(&lower).expect("valid bech32");
   stripped.byte_iter().collect()
}

// --- Identity wrap/unwrap --------------------------------------------------

#[test]
fn identity_encode_parse_roundtrip() {
   let idt = sample();
   let encoded = idt.encode().unwrap();
   assert!(encoded.starts_with("AGE-PLUGIN-FIDO2-HMAC-"));
   let parsed = &encoded.parse::<Identity>().unwrap();
   assert_eq!(parsed.require_pin(), idt.require_pin());
   assert_eq!(parsed.salt(), idt.salt());
   assert_eq!(parsed.cred_id(), idt.cred_id());
   assert_eq!(parsed.public_key(), idt.public_key());
}

#[test]
fn identity_debug_does_not_leak_secret() {
   let idt = sample();
   let dbg = format!("{idt:?}");
   assert!(!dbg.contains("0x11"));
}

#[test]
fn identity_load_secret_and_derive_recipient() {
   let mut id = sample();
   let mock = MockDevice::new(id.cred_id(), [0x7B; 32]);
   let salt_snapshot = *id.salt();
   let cred_id_snapshot = id.cred_id().to_vec();
   let loaded = id.load_secret(&mock, None).unwrap();
   let rcpt = loaded.to_recipient().unwrap();
   // version field removed, RECIPIENT_VERSION is implicit
   assert_eq!(rcpt.salt(), &salt_snapshot);
   assert_eq!(rcpt.cred_id(), cred_id_snapshot.as_slice());
   let rcpt2 = loaded.to_recipient().unwrap();
   assert_eq!(rcpt.native_pubkey(), rcpt2.native_pubkey());
}

#[test]
fn identity_load_secret_pin_required() {
   let mut id = Identity::record(
      true,
      [0x11; 32],
      vec![0xAA, 0xBB, 0xCC],
      sample_es256_pubkey(),
   )
   .unwrap();
   let mock = MockDevice::new(id.cred_id(), [0x7B; 32]);
   match id.load_secret(&mock, None) {
      Err(Error::PinRequired) => {},
      Ok(_) => panic!("expected PinRequired, got Ok"),
      Err(other) => panic!("expected PinRequired, got {other:?}"),
   }
   id.load_secret(&mock, Some("1234")).unwrap();
}

#[test]
fn identity_wrap_then_unwrap_plugin_stanza() {
   let mut id = sample();
   let mock = MockDevice::new(id.cred_id(), [0x99; 32]);
   let file_key = FileKey::new(Box::new([0x11_u8; 16]));

   let fs = id.wrap(&mock, None, &file_key).unwrap();
   let (args, body) = fs.encode();
   let stanza = Stanza {
      tag: PLUGIN_NAME.into(),
      args,
      body,
   };

   let mut fresh = sample();
   let result = fresh.unwrap(&mock, None, &[stanza]).unwrap();
   let fk = result.expect("unwrap recovered file key");
   assert_eq!(fk.expose_secret(), file_key.expose_secret());
}

#[test]
fn identity_unwrap_no_matching_stanzas_returns_none() {
   let mut id = sample();
   let mock = MockDevice::new(id.cred_id(), [0xAA; 32]);
   let result = id.unwrap(&mock, None, &[]).unwrap();
   assert!(result.is_none());
}

#[test]
fn identity_unwrap_uses_stanza_salt_not_identity_salt() {
   let cred_id = vec![0xC0, 0xDE, 0xCA, 0xFE];
   let wrap_salt = [0xAA_u8; 32];
   let unwrap_identity_salt = [0xBB_u8; 32];

   let mock = MockDevice::new(&cred_id, [0x5C_u8; 32]);

   let mut wrapper =
      Identity::record(false, wrap_salt, cred_id.clone(), sample_es256_pubkey()).unwrap();
   let file_key = FileKey::new(Box::new([0x7E_u8; 16]));
   let fs = wrapper.wrap(&mock, None, &file_key).unwrap();
   let (args, body) = fs.encode();
   let stanza = Stanza {
      tag: PLUGIN_NAME.into(),
      args,
      body,
   };

   let mut unwrapper =
      Identity::record(false, unwrap_identity_salt, cred_id, sample_es256_pubkey()).unwrap();
   let result = unwrapper
      .unwrap(&mock, None, &[stanza])
      .unwrap()
      .expect("unwrap should adopt stanza salt and recover file key");
   assert_eq!(result.expose_secret(), file_key.expose_secret());
}

#[test]
fn identity_unwrap_dataless_adopts_stanza_fields() {
   let cred_id = vec![0xFE, 0xED];
   let salt = [0x42_u8; 32];
   let mock = MockDevice::new(&cred_id, [0x91_u8; 32]);

   let mut wrapper = Identity::record(false, salt, cred_id, sample_es256_pubkey()).unwrap();
   let file_key = FileKey::new(Box::new([0x3E_u8; 16]));
   let fs = wrapper.wrap(&mock, None, &file_key).unwrap();
   let (args, body) = fs.encode();
   let stanza = Stanza {
      tag: PLUGIN_NAME.into(),
      args,
      body,
   };

   let mut dataless = Identity::dataless();
   let result = dataless
      .unwrap(&mock, None, &[stanza])
      .unwrap()
      .expect("dataless must adopt cred_id and salt from stanza");
   assert_eq!(result.expose_secret(), file_key.expose_secret());
}

// --- Recipient wrap --------------------------------------------------------

#[test]
fn recipient_wrap_produces_a_stanza() {
   let mut id = Identity::record(
      false,
      [0x22; 32],
      vec![0xFE, 0xED, 0xFA, 0xCE],
      sample_es256_pubkey(),
   )
   .unwrap();
   let mock = MockDevice::new(id.cred_id(), [0x33; 32]);
   let salt_snapshot = *id.salt();
   let cred_id_snapshot = id.cred_id().to_vec();
   let loaded = id.load_secret(&mock, None).unwrap();
   let recipient = loaded.to_recipient().unwrap();
   drop(loaded);

   let file_key = FileKey::new(Box::new([0_u8; 16]));
   let stanza = recipient.wrap(&file_key).unwrap();
   // version field removed, STANZA_VERSION is implicit
   assert_eq!(stanza.salt(), &salt_snapshot);
   assert_eq!(stanza.cred_id(), cred_id_snapshot.as_slice());
   assert!(!stanza.native_share().is_empty());
   assert!(!stanza.body().is_empty());
}

// --- age-plugin protocol layer --------------------------------------------

#[test]
fn protocol_recipient_wraps_to_static_recipient_then_round_trips() {
   let secret = [0x42_u8; 32];
   let salt = [0x55_u8; 32];
   let cred_id = vec![0x01, 0x02, 0x03, 0x04];
   let mut id = Identity::record(false, salt, cred_id, sample_es256_pubkey()).unwrap();
   let mock = MockDevice::new(id.cred_id(), secret);
   let recipient_bytes = {
      let loaded = id.load_secret(&mock, None).unwrap();
      bech32_payload_of(&loaded.to_recipient().unwrap().to_string())
   };

   let mut imp = RecipientImpl::with_device(mock_box(id.cred_id(), secret));
   assert!(
      <RecipientImpl as RecipientPluginV1>::add_recipient(
         &mut imp,
         0,
         "fido2-hmac",
         &recipient_bytes,
      )
      .is_ok()
   );

   let fk = FileKey::new(Box::new([0x11_u8; 16]));
   let outer = imp
      .wrap_file_keys(vec![fk], RecordingCallbacks::default())
      .expect("wrap_file_keys io ok");
   let stanzas_per_file =
      outer.unwrap_or_else(|errs| panic!("wrap_file_keys produced errors: {} entries", errs.len()));
   assert_eq!(stanzas_per_file.len(), 1);
   assert_eq!(stanzas_per_file[0].len(), 1);
   assert_eq!(stanzas_per_file[0][0].tag, PLUGIN_NAME);
}

#[test]
fn protocol_recipient_dataless_identity_generates_fresh_credential() {
   let secret = [0x77_u8; 32];
   let cred_id = vec![0xDE, 0xAD];
   let mut imp = RecipientImpl::with_device(mock_box(&cred_id, secret));

   assert!(
      <RecipientImpl as RecipientPluginV1>::add_identity(&mut imp, 0, "fido2-hmac", &[]).is_ok()
   );

   let cb = RecordingCallbacks::default().confirm(false);

   let fk = FileKey::new(Box::new([0x22_u8; 16]));
   let stanzas_per_file = imp
      .wrap_file_keys(vec![fk], cb)
      .expect("wrap_file_keys io ok")
      .unwrap_or_else(|_| panic!("wrap_file_keys produced errors"));
   assert_eq!(stanzas_per_file.len(), 1);
   assert_eq!(stanzas_per_file[0].len(), 1);
   assert_eq!(stanzas_per_file[0][0].tag, PLUGIN_NAME);
}

#[test]
fn protocol_recipient_rejects_malformed_payload() {
   let mut imp = RecipientImpl::default();
   let err =
      <RecipientImpl as RecipientPluginV1>::add_recipient(&mut imp, 7, "fido2-hmac", &[0, 99])
         .expect_err("add_recipient must reject");
   if let plugin_recipient::Error::Recipient { index, .. } = err {
      assert_eq!(index, 7);
   } else {
      panic!("expected Error::Recipient");
   }
}

#[test]
fn protocol_identity_unwraps_plugin_stanza() {
   let secret = [0x99_u8; 32];
   let salt = [0x66_u8; 32];
   let cred_id = vec![0xCA, 0xFE];

   let (file_key_bytes, stanza) = wrap_one_for_recipient(secret, salt, &cred_id);

   let mut imp = IdentityImpl::with_device(mock_box(&cred_id, secret));
   let id_bytes = bech32_payload_of(
      &Identity::record(false, salt, cred_id, sample_es256_pubkey())
         .unwrap()
         .encode()
         .unwrap(),
   );
   assert!(
      <IdentityImpl as IdentityPluginV1>::add_identity(&mut imp, 0, "fido2-hmac", &id_bytes)
         .is_ok()
   );

   let map = imp
      .unwrap_file_keys(vec![vec![stanza]], RecordingCallbacks::default())
      .expect("unwrap_file_keys io ok");
   let entry = map.get(&0).expect("file index 0 in map");
   let fk_bytes = entry.as_ref().map_or_else(
      |errs| panic!("expected recovered file key, got {} error(s)", errs.len()),
      |fk| fk.expose_secret().to_vec(),
   );
   assert_eq!(fk_bytes, file_key_bytes);
}

#[test]
fn protocol_identity_dataless_adopts_stanza_fields() {
   let secret = [0xA5_u8; 32];
   let salt = [0x33_u8; 32];
   let cred_id = vec![0xBE, 0xEF];

   let (file_key_bytes, stanza) = wrap_one_for_recipient(secret, salt, &cred_id);

   let mut imp = IdentityImpl::with_device(mock_box(&cred_id, secret));
   assert!(
      <IdentityImpl as IdentityPluginV1>::add_identity(&mut imp, 0, "fido2-hmac", &[]).is_ok()
   );

   let map = imp
      .unwrap_file_keys(vec![vec![stanza]], RecordingCallbacks::default())
      .expect("unwrap_file_keys io ok");
   let entry = map.get(&0).expect("file index 0");
   let fk_bytes = entry.as_ref().map_or_else(
      |errs| panic!("expected recovered file key, got {} error(s)", errs.len()),
      |fk| fk.expose_secret().to_vec(),
   );
   assert_eq!(fk_bytes, file_key_bytes);
}

#[test]
fn protocol_identity_batch_derives_hmac_once() {
   // Many files encrypted to the SAME credential (fixed salt) must cost a
   // single device derive across the whole batch — that's the one-touch
   // reseal property.
   let secret = [0x5A_u8; 32];
   let salt = [0x42_u8; 32];
   let cred_id = vec![0xDE, 0xAD];

   let mut expected = Vec::<Vec<u8>>::new();
   let mut files = Vec::<Vec<Stanza>>::new();
   for _ in 0..4 {
      let (fk_bytes, stanza) = wrap_one_for_recipient(secret, salt, &cred_id);
      expected.push(fk_bytes);
      files.push(vec![stanza]);
   }

   let device = MockDevice::new(&cred_id, secret);
   let calls = Rc::clone(&device.calls);
   let mut imp = IdentityImpl::with_device(Box::new(device));
   assert!(
      <IdentityImpl as IdentityPluginV1>::add_identity(&mut imp, 0, "fido2-hmac", &[]).is_ok()
   );

   let map = imp
      .unwrap_file_keys(files, RecordingCallbacks::default())
      .expect("unwrap_file_keys io ok");

   for (index, fk_expected) in expected.iter().enumerate() {
      let entry = map.get(&index).expect("file present in map");
      let fk = entry.as_ref().map_or_else(
         |errs| panic!("file {index}: expected key, got {} error(s)", errs.len()),
         |fk| fk.expose_secret().to_vec(),
      );
      assert_eq!(&fk, fk_expected, "file {index} key mismatch");
   }
   assert_eq!(
      calls.get(),
      1,
      "device should derive the hmac secret exactly once"
   );
}

#[test]
fn protocol_identity_skips_undecryptable_file_without_touch() {
   // A batch mixing a file the connected key can unwrap with one keyed to a
   // cred it doesn't hold: the latter is skipped touch-free, not tried
   // stanza-by-stanza.
   let secret = [0x5A_u8; 32];
   let salt = [0x42_u8; 32];
   let cred_present = vec![0xDE, 0xAD];
   let cred_absent = vec![0xBE, 0xEF];

   let (fk_present, stanza_present) = wrap_one_for_recipient(secret, salt, &cred_present);
   let (_fk_absent, stanza_absent) = wrap_one_for_recipient(secret, salt, &cred_absent);
   let files = vec![vec![stanza_present], vec![stanza_absent]];

   let device = MockDevice::new(&cred_present, secret);
   let calls = Rc::clone(&device.calls);
   let mut imp = IdentityImpl::with_device(Box::new(device));
   assert!(
      <IdentityImpl as IdentityPluginV1>::add_identity(&mut imp, 0, "fido2-hmac", &[]).is_ok()
   );

   let map = imp
      .unwrap_file_keys(files, RecordingCallbacks::default())
      .expect("unwrap_file_keys io ok");

   let fk0 = map.get(&0).expect("file 0 present").as_ref().map_or_else(
      |_| panic!("file keyed to the connected credential should recover"),
      |fk| fk.expose_secret().to_vec(),
   );
   assert_eq!(fk0, fk_present);
   assert!(
      !map.contains_key(&1),
      "file keyed to an absent credential should be skipped"
   );
   assert_eq!(
      calls.get(),
      1,
      "the undecryptable file must not cost a device derive (touch)"
   );
}

#[test]
fn protocol_identity_omits_file_when_no_match() {
   let mut imp = IdentityImpl::with_device(mock_box(&[0x01], [0x02_u8; 32]));
   let unrelated = Stanza {
      tag:  "some-other-plugin".into(),
      args: vec![],
      body: vec![],
   };
   let map = imp
      .unwrap_file_keys(vec![vec![unrelated]], RecordingCallbacks::default())
      .expect("unwrap_file_keys io ok");
   assert!(map.is_empty());
}

#[test]
fn protocol_recipient_wrap_retries_after_wrong_pin() {
   let secret = [0xD0_u8; 32];
   let salt = [0x77_u8; 32];
   let cred_id = vec![0xAB, 0xCD];

   let failing_mock = MockDevice::new(&cred_id, secret);
   let id_bytes = bech32_payload_of(
      &Identity::record(true, salt, cred_id, sample_es256_pubkey())
         .unwrap()
         .encode()
         .unwrap(),
   );

   failing_mock.fail_count.set(1);
   let mut imp = RecipientImpl::with_device(Box::new(failing_mock));
   assert!(
      <RecipientImpl as RecipientPluginV1>::add_identity(&mut imp, 0, "fido2-hmac", &id_bytes)
         .is_ok()
   );

   let cb = RecordingCallbacks::default().secret("1234").secret("1234");

   let fk = FileKey::new(Box::new([0x44_u8; 16]));
   let outer = imp
      .wrap_file_keys(vec![fk], cb)
      .expect("wrap_file_keys io ok");
   let stanzas_per_file = outer.unwrap_or_else(|errs| {
      panic!(
         "retry path should have produced a stanza, got {} error(s)",
         errs.len()
      )
   });
   assert_eq!(stanzas_per_file.len(), 1);
   assert_eq!(stanzas_per_file[0].len(), 1);
   assert_eq!(stanzas_per_file[0][0].tag, PLUGIN_NAME);
}

#[test]
fn protocol_identity_surfaces_malformed_plugin_stanza_as_error_stanza() {
   let mut imp = IdentityImpl::with_device(mock_box(&[0xCA, 0xFE], [0xAA_u8; 32]));
   let id_bytes = bech32_payload_of(
      &Identity::record(
         false,
         [0x00_u8; 32],
         vec![0xCA, 0xFE],
         sample_es256_pubkey(),
      )
      .unwrap()
      .encode()
      .unwrap(),
   );
   assert!(
      <IdentityImpl as IdentityPluginV1>::add_identity(&mut imp, 0, "fido2-hmac", &id_bytes)
         .is_ok()
   );

   let bad = Stanza {
      tag:  PLUGIN_NAME.into(),
      args: vec!["AQ".into()],
      body: vec![],
   };
   let map = imp
      .unwrap_file_keys(vec![vec![bad]], RecordingCallbacks::default())
      .expect("unwrap_file_keys io ok");
   let entry = map.get(&0).expect("file index 0");
   match *entry {
      Err(ref errs) => {
         let stanza_err = errs
            .iter()
            .find(|err| matches!(err, plugin_identity::Error::Stanza { .. }));
         assert!(stanza_err.is_some(), "expected at least one Error::Stanza");
      },
      Ok(_) => panic!("expected stanza parse error, got recovered file key"),
   }
}
