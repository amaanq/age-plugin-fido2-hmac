//! CTAP hmac-secret sanity check.
//!
//! Set `FIDO2_PIN=<your-pin>` for PIN-protected authenticators.

use std::{
   env,
   error::Error,
};

use ctap_fido2::{
   cmd::{
      Algorithm,
      Authenticator,
      MakeCredentialOptions,
      get_assertion::HmacSecretRequest,
   },
   device::list_devices,
};

const RP_ID: &str = "age-plugin-fido2-hmac.spike";

const SALT: [u8; 32] = [
   0x53, 0x50, 0x49, 0x4B, 0x45, 0x2D, 0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65,
   0x74, 0x2D, 0x73, 0x70, 0x69, 0x6B, 0x65, 0x2D, 0x73, 0x61, 0x6C, 0x74, 0x2D, 0x30, 0x32, 0x21,
];

const SALT2: [u8; 32] = [
   0x53, 0x50, 0x49, 0x4B, 0x45, 0x2D, 0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65,
   0x74, 0x2D, 0x73, 0x70, 0x69, 0x6B, 0x65, 0x2D, 0x73, 0x61, 0x6C, 0x74, 0x2D, 0x32, 0x32, 0x21,
];

fn main() -> Result<(), Box<dyn Error>> {
   env_logger::init();
   let devices = list_devices()?;
   if devices.is_empty() {
      eprintln!("no FIDO2 hmac-secret authenticators found; plug a key in and re-run");
      return Ok(());
   }
   eprintln!("found {} eligible device(s):", devices.len());
   for (idx, info) in devices.iter().enumerate() {
      eprintln!(
         "  [{idx}] vid={:#06x} pid={:#06x} product={:?} serial={:?}",
         info.vendor_id, info.product_id, info.product_string, info.serial_number,
      );
   }
   let info = devices.into_iter().next().expect("checked non-empty above");
   let mut auth = Authenticator::open(&info)?;

   let pin = env::var("FIDO2_PIN").ok();
   let challenge = [0xAB_u8; 32];

   let verbose = env::var_os("SPIKE_VERBOSE").is_some();

   eprintln!("> registering a fresh credential (touch your key when it blinks)…");
   let credential = auth.make_credential(RP_ID, &challenge, &MakeCredentialOptions {
      algorithm: Algorithm::Es256,
      pin: pin.as_deref(),
      ..MakeCredentialOptions::default()
   })?;
   eprintln!("  registered ({} byte id)", credential.id.len());
   if verbose {
      eprintln!("    id     = {}", hex::encode(&credential.id));
      eprintln!(
         "    pubkey = {}",
         hex::encode(credential.public_key.as_cose_bytes())
      );
   }

   let challenge2 = [0xCD_u8; 32];
   eprintln!("> deriving one secret (touch your key when it blinks)…");
   let response = auth.get_hmac_secret(&HmacSecretRequest {
      rp_id:             RP_ID,
      client_data_hash:  &challenge2,
      cred_id:           &credential.id,
      salt:              &SALT,
      salt2:             None,
      pin:               pin.as_deref(),
      public_key:        Some(&credential.public_key),
      request_cred_blob: false,
   })?;
   eprintln!("  got 32 bytes back, assertion signature verified");
   if verbose {
      eprintln!("    secret = {}", hex::encode(response.secret.0));
   }

   let challenge3 = [0xEF_u8; 32];
   eprintln!("> deriving two secrets in one tap (touch your key when it blinks)…");
   let pair = auth.get_hmac_secret(&HmacSecretRequest {
      rp_id:             RP_ID,
      client_data_hash:  &challenge3,
      cred_id:           &credential.id,
      salt:              &SALT,
      salt2:             Some(&SALT2),
      pin:               pin.as_deref(),
      public_key:        Some(&credential.public_key),
      request_cred_blob: false,
   })?;
   let secret2 = pair
      .secret2
      .expect("device returned only one output despite salt2 request");
   eprintln!("  got 64 bytes back, assertion signature verified");
   if verbose {
      eprintln!("    secret1 = {}", hex::encode(pair.secret.0));
      eprintln!("    secret2 = {}", hex::encode(secret2.0));
   }
   if pair.secret.0 != response.secret.0 {
      eprintln!(
         "  WARN: first secret differs from the single-salt run, but the same salt was used"
      );
   }
   if pair.secret.0 == secret2.0 {
      eprintln!("  WARN: both secrets match, but the salts differed so they should not");
   }

   eprintln!("spike OK");
   if !verbose {
      eprintln!("(set SPIKE_VERBOSE=1 to dump credential id, pubkey, and the derived secrets)");
   }
   Ok(())
}
