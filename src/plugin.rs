//! age-plugin state machine glue.

use std::{
   collections::{
      HashMap,
      HashSet,
   },
   io,
   marker::PhantomData,
   thread,
   time::{
      Duration,
      Instant,
   },
};

use age_core::format::{
   FileKey,
   Stanza,
};
use age_plugin::{
   Callbacks,
   PluginHandler,
   identity::{
      self as plugin_identity,
      IdentityPluginV1,
   },
   recipient::{
      self as plugin_recipient,
      RecipientPluginV1,
   },
   run_state_machine,
};
use ctap_fido2::error::CtapStatus;
use rand::Rng as _;
use secrecy::ExposeSecret as _;
use zeroize::Zeroizing;

use crate::{
   device::{
      Algorithm,
      DiscoveryUi,
      Fido2Device,
      find,
   },
   error::Error,
   format::PLUGIN_NAME,
   identity::{
      HmacCache,
      Identity,
      UnwrapCtx,
   },
   magic,
   recipient::Recipient,
   stanza::Fido2HmacStanzaRef,
};

/// Silent-probe attempts to wake an autosuspended device that fails its first
/// transaction.
const PROBE_WAKE_ATTEMPTS: u32 = 4;

/// Device re-opens (each a fresh touch window) before giving up on a source.
const REOPEN_LIMIT: u32 = 60;

/// Dispatch `--age-plugin=<state>`.
pub fn run(state: &str) -> io::Result<()> {
   run_state_machine(state, Fido2HmacHandler)
}

struct Fido2HmacHandler;

impl PluginHandler for Fido2HmacHandler {
   type IdentityV1 = IdentityImpl;
   type RecipientV1 = RecipientImpl;

   fn recipient_v1(self) -> io::Result<Self::RecipientV1> {
      Ok(RecipientImpl::default())
   }

   fn identity_v1(self) -> io::Result<Self::IdentityV1> {
      Ok(IdentityImpl::default())
   }
}

enum IdentityAsRecipient {
   Parsed(Identity),
   Dataless,
}

/// [`RecipientPluginV1`] implementation.
#[derive(Default)]
pub struct RecipientImpl {
   recipients: Vec<(usize, Recipient)>,
   identities: Vec<(usize, IdentityAsRecipient)>,
   device:     Option<Box<dyn Fido2Device>>,
   pin_cache:  Option<Zeroizing<String>>,
}

impl RecipientImpl {
   /// Construct with a pre-supplied device.
   #[must_use]
   pub fn with_device(device: Box<dyn Fido2Device>) -> Self {
      Self {
         recipients: Vec::new(),
         identities: Vec::new(),
         device:     Some(device),
         pin_cache:  None,
      }
   }

   /// Pre-seed the PIN cache.
   #[must_use]
   pub fn with_pin<S>(mut self, pin: S) -> Self
   where
      S: Into<String>,
   {
      self.pin_cache = Some(Zeroizing::new(pin.into()));
      self
   }
}

impl RecipientPluginV1 for RecipientImpl {
   fn add_recipient(
      &mut self,
      index: usize,
      _plugin_name: &str,
      bytes: &[u8],
   ) -> Result<(), plugin_recipient::Error> {
      let rcpt = Recipient::from_bytes(bytes).map_err(|err| {
         plugin_recipient::Error::Recipient {
            index,
            message: format!("parse recipient: {err}"),
         }
      })?;
      self.recipients.push((index, rcpt));
      Ok(())
   }

   fn add_identity(
      &mut self,
      index: usize,
      _plugin_name: &str,
      bytes: &[u8],
   ) -> Result<(), plugin_recipient::Error> {
      let entry = if magic::is_dataless_bytes(bytes) {
         IdentityAsRecipient::Dataless
      } else {
         let id = Identity::from_bytes(bytes).map_err(|err| {
            plugin_recipient::Error::Identity {
               index,
               message: format!("parse identity: {err}"),
            }
         })?;
         IdentityAsRecipient::Parsed(id)
      };
      self.identities.push((index, entry));
      Ok(())
   }

   fn labels(&mut self) -> HashSet<String> {
      HashSet::new()
   }

   fn wrap_file_keys(
      &mut self,
      file_keys: Vec<FileKey>,
      mut callbacks: impl Callbacks<plugin_recipient::Error>,
   ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<plugin_recipient::Error>>> {
      let &mut Self {
         ref recipients,
         ref mut identities,
         ref mut device,
         ref mut pin_cache,
      } = self;

      let mut errors = Vec::<plugin_recipient::Error>::new();
      let mut materialized = Vec::<(usize, Recipient)>::new();

      for &mut (idx, ref mut entry) in identities.iter_mut() {
         match *entry {
            IdentityAsRecipient::Dataless => {
               match generate_fresh_recipient(device, pin_cache, &mut callbacks) {
                  Ok(rcpt) => materialized.push((idx, rcpt)),
                  Err(err) => {
                     errors.push(plugin_recipient::Error::Identity {
                        index:   idx,
                        message: err.to_string(),
                     });
                  },
               }
            },
            IdentityAsRecipient::Parsed(ref mut id) => {
               let dev = match ensure_device(device, &mut callbacks) {
                  Ok(dev) => dev,
                  Err(err) => {
                     errors.push(plugin_recipient::Error::Identity {
                        index:   idx,
                        message: err.to_string(),
                     });
                     continue;
                  },
               };
               let mut pin = if id.require_pin() {
                  match ensure_pin(pin_cache, &mut callbacks) {
                     Ok(pin_val) => Some(pin_val),
                     Err(err) => {
                        errors.push(plugin_recipient::Error::Identity {
                           index:   idx,
                           message: err.to_string(),
                        });
                        continue;
                     },
                  }
               } else {
                  None
               };
               let mut tried_retry = false;
               let load_result = loop {
                  let _ = callbacks.message("Please touch your security key...");
                  match id.load_secret(dev.as_ref(), pin.as_deref().map(String::as_str)) {
                     Ok(loaded) => break Ok(loaded),
                     Err(ref err) if !tried_retry && is_retryable_pin_failure(err) => {
                        tried_retry = true;
                        *pin_cache = None;
                        match ensure_pin(pin_cache, &mut callbacks) {
                           Ok(pin_val) => {
                              pin = Some(pin_val);
                           },
                           Err(err) => break Err(err),
                        }
                     },
                     Err(err) => break Err(err),
                  }
               };
               let mut loaded = match load_result {
                  Ok(loaded) => loaded,
                  Err(err) => {
                     errors.push(plugin_recipient::Error::Identity {
                        index:   idx,
                        message: err.to_string(),
                     });
                     continue;
                  },
               };
               if let Some(warning) = loaded.take_mlock_warning() {
                  let _ = callbacks.message(&warning);
               }
               match loaded.to_recipient() {
                  Ok(rcpt) => materialized.push((idx, rcpt)),
                  Err(err) => {
                     errors.push(plugin_recipient::Error::Identity {
                        index:   idx,
                        message: err.to_string(),
                     });
                  },
               }
            },
         }
      }

      if !errors.is_empty() {
         return Ok(Err(errors));
      }

      let all_recipients = recipients
         .iter()
         .map(|&(_, ref rcpt)| rcpt)
         .chain(materialized.iter().map(|&(_, ref rcpt)| rcpt))
         .collect::<Vec<&Recipient>>();

      let mut out = Vec::<Vec<Stanza>>::with_capacity(file_keys.len());
      for fk in &file_keys {
         let mut stanzas = Vec::with_capacity(all_recipients.len());
         for rcpt in &all_recipients {
            let fs = match rcpt.wrap(fk) {
               Ok(fs) => fs,
               Err(err) => {
                  return Ok(Err(vec![plugin_recipient::Error::Internal {
                     message: format!("wrap: {err}"),
                  }]));
               },
            };
            stanzas.push(Stanza::from(fs));
         }
         out.push(stanzas);
      }
      Ok(Ok(out))
   }
}

/// [`IdentityPluginV1`] implementation.
#[derive(Default)]
pub struct IdentityImpl {
   identities: Vec<(usize, Identity)>,
   device:     Option<Box<dyn Fido2Device>>,
   pin_cache:  Option<Zeroizing<String>>,
}

impl IdentityImpl {
   /// Construct with a pre-supplied device.
   #[must_use]
   pub fn with_device(device: Box<dyn Fido2Device>) -> Self {
      Self {
         identities: Vec::new(),
         device:     Some(device),
         pin_cache:  None,
      }
   }

   /// Pre-seed the PIN cache.
   #[must_use]
   pub fn with_pin<S>(mut self, pin: S) -> Self
   where
      S: Into<String>,
   {
      self.pin_cache = Some(Zeroizing::new(pin.into()));
      self
   }
}

impl IdentityPluginV1 for IdentityImpl {
   fn add_identity(
      &mut self,
      index: usize,
      _plugin_name: &str,
      bytes: &[u8],
   ) -> Result<(), plugin_identity::Error> {
      let id = if magic::is_dataless_bytes(bytes) {
         Identity::dataless()
      } else {
         Identity::from_bytes(bytes).map_err(|err| {
            plugin_identity::Error::Identity {
               index,
               message: format!("parse identity: {err}"),
            }
         })?
      };
      self.identities.push((index, id));
      Ok(())
   }

   fn unwrap_file_keys(
      &mut self,
      files: Vec<Vec<Stanza>>,
      mut callbacks: impl Callbacks<plugin_identity::Error>,
   ) -> io::Result<HashMap<usize, Result<FileKey, Vec<plugin_identity::Error>>>> {
      let &mut Self {
         ref mut identities,
         ref mut device,
         ref mut pin_cache,
      } = self;

      let mut out = HashMap::<usize, Result<FileKey, Vec<plugin_identity::Error>>>::new();

      // Cache derives across the batch.
      let mut hmac_cache = HmacCache::new();

      // PIN policy is per-file; these are the identity-level inputs.
      let has_dataless = identities.iter().any(|&(_, ref id)| id.is_dataless());
      let any_id_requires_pin = identities.iter().any(|&(_, ref id)| id.require_pin());

      // Probe once; `None` after `cred_probed` means no matching credential.
      let mut connected_cred = Option::<Vec<u8>>::None;
      let mut cred_probed = false;

      for (file_index, stanzas) in files.iter().enumerate() {
         let parsed = match ParsedFileStanzas::classify(file_index, stanzas) {
            Ok(parsed) => parsed,
            Err(errs) => {
               out.insert(file_index, Err(errs));
               continue;
            },
         };

         let has_ours = !parsed.plugin.is_empty();
         let has_x25519_we_can_try = !parsed.native_x25519.is_empty()
            && identities.iter().any(|&(_, ref id)| !id.is_dataless());
         if !has_ours && !has_x25519_we_can_try {
            continue;
         }

         // Touch-free preselection avoids one touch per non-matching stanza.
         if !cred_probed {
            let cred_ids = parsed
               .plugin
               .iter()
               .map(Fido2HmacStanzaRef::cred_id)
               .filter(|cid| !cid.is_empty())
               .collect::<Vec<&[u8]>>();
            if !cred_ids.is_empty()
               && let Ok(dev) = ensure_device(device, &mut callbacks)
            {
               connected_cred = probe_connected_credential(dev.as_ref(), &cred_ids);
               cred_probed = true;
               let _ = callbacks.message(if connected_cred.is_some() {
                  "Identified the connected security key; one touch unlocks the batch."
               } else {
                  "Could not silently identify the connected key; expect a touch per credential."
               });
            }
         }

         let cx = FileUnwrapCtx {
            identities:        &mut *identities,
            device:            &mut *device,
            pin_cache:         &mut *pin_cache,
            callbacks:         &mut callbacks,
            hmac_cache:        &mut hmac_cache,
            connected_cred:    connected_cred.as_deref(),
            file_requires_pin: any_id_requires_pin
               || (has_dataless && parsed.any_plugin_requires_pin()),
         };
         if let Some(result) = recover_file_key(cx, &parsed) {
            out.insert(file_index, result);
         }
      }

      Ok(out)
   }
}

/// Session state for one-file unwrap.
struct FileUnwrapCtx<'a, C: Callbacks<plugin_identity::Error>> {
   identities:        &'a mut Vec<(usize, Identity)>,
   device:            &'a mut Option<Box<dyn Fido2Device>>,
   pin_cache:         &'a mut Option<Zeroizing<String>>,
   callbacks:         &'a mut C,
   hmac_cache:        &'a mut HmacCache,
   /// Touch-free preselection result.
   connected_cred:    Option<&'a [u8]>,
   file_requires_pin: bool,
}

/// Touch-free probe, with brief wake retries.
fn probe_connected_credential(dev: &dyn Fido2Device, cred_ids: &[&[u8]]) -> Option<Vec<u8>> {
   for attempt in 0..PROBE_WAKE_ATTEMPTS {
      if attempt > 0 {
         thread::sleep(Duration::from_millis(120));
      }
      if let Some(cred) = dev.probe_credential(cred_ids).ok().flatten() {
         return Some(cred);
      }
   }
   None
}

/// Try each identity; reopen on touch timeout so the next prompt has a fresh
/// channel.
fn recover_file_key<C>(
   cx: FileUnwrapCtx<'_, C>,
   parsed: &ParsedFileStanzas<'_>,
) -> Option<Result<FileKey, Vec<plugin_identity::Error>>>
where
   C: Callbacks<plugin_identity::Error>,
{
   let FileUnwrapCtx {
      identities,
      device,
      pin_cache,
      callbacks,
      hmac_cache,
      connected_cred,
      file_requires_pin,
   } = cx;

   let mut pin = if file_requires_pin {
      match ensure_pin(pin_cache, callbacks) {
         Ok(pin_val) => Some(pin_val),
         Err(err) => {
            return Some(Err(vec![plugin_identity::Error::Internal {
               message: format!("pin: {err}"),
            }]));
         },
      }
   } else {
      None
   };

   let mut file_errors = Vec::<plugin_identity::Error>::new();
   for &mut (idx, ref mut id) in identities.iter_mut() {
      let mut tried_retry = false;
      let mut reopens = 0_u32;
      loop {
         let dev = match ensure_device(device, callbacks) {
            Ok(dev) => dev,
            Err(err) => {
               file_errors.push(plugin_identity::Error::Internal {
                  message: format!("device: {err}"),
               });
               break;
            },
         };
         // `unwrap_parsed` prompts only before device work.
         let result = {
            let mut notify = || {
               let _ = callbacks.message("Please touch your security key...");
            };
            let mut ctx = UnwrapCtx {
               device:           dev.as_ref(),
               pin:              pin.as_deref().map(String::as_str),
               preselected_cred: connected_cred,
               hmac_cache:       &mut *hmac_cache,
               notify_touch:     &mut notify,
            };
            id.unwrap_parsed(&mut ctx, &parsed.plugin, &parsed.native_x25519)
         };
         match result {
            Ok(Some(fk)) => {
               if let Some(warning) = id.take_mlock_warning() {
                  let _ = callbacks.message(&warning);
               }
               return Some(Ok(fk));
            },
            Ok(None) => {
               if let Some(warning) = id.take_mlock_warning() {
                  let _ = callbacks.message(&warning);
               }
               break;
            },
            // Fresh channel required after a lapsed touch window.
            Err(Error::Ctap(CtapStatus::UserActionTimeout)) if reopens < REOPEN_LIMIT => {
               reopens += 1;
               let _ = callbacks.message(
                  "No touch yet — re-arming your security key; tap whenever you're ready.",
               );
               *device = None;
               thread::sleep(Duration::from_millis(500));
            },
            Err(Error::Ctap(CtapStatus::UserActionTimeout)) => {
               file_errors.push(plugin_identity::Error::Identity {
                  index:   idx,
                  message: "no touch after repeated re-prompts".into(),
               });
               break;
            },
            Err(ref err) if !tried_retry && is_retryable_pin_failure(err) => {
               tried_retry = true;
               *pin_cache = None;
               match ensure_pin(pin_cache, callbacks) {
                  Ok(pin_val) => pin = Some(pin_val),
                  Err(err) => {
                     file_errors.push(plugin_identity::Error::Identity {
                        index:   idx,
                        message: err.to_string(),
                     });
                     break;
                  },
               }
            },
            Err(err) => {
               file_errors.push(plugin_identity::Error::Identity {
                  index:   idx,
                  message: err.to_string(),
               });
               break;
            },
         }
      }
      // A miss/error here doesn't rule out another identity.
   }
   (!file_errors.is_empty()).then_some(Err(file_errors))
}

fn generate_fresh_recipient<C>(
   device: &mut Option<Box<dyn Fido2Device>>,
   pin_cache: &mut Option<Zeroizing<String>>,
   callbacks: &mut C,
) -> Result<Recipient, Error>
where
   C: Callbacks<plugin_recipient::Error>,
{
   let dev = ensure_device(device, callbacks)?;
   let has_pin = dev.has_pin_set()?;
   let pin = if has_pin {
      Some(ensure_pin(pin_cache, callbacks)?)
   } else {
      None
   };
   // Ask instead of inheriting the token's PIN state.
   let require_pin = if has_pin {
      match callbacks.confirm("Require a PIN for decryption?", "y", Some("n")) {
         Ok(Ok(yes)) => yes,
         Ok(Err(_)) | Err(_) => {
            return Err(Error::InvalidFormat(
               "could not confirm PIN policy from the age host".into(),
            ));
         },
      }
   } else {
      false
   };
   let _ = callbacks.message("Please touch your security key to generate a credential...");
   let credential =
      dev.generate_credential(pin.as_deref().map(String::as_str), Algorithm::Es256)?;
   let mut salt = [0_u8; 32];
   rand::rng().fill_bytes(&mut salt);
   let mut id = Identity::record(require_pin, salt, credential.id, credential.public_key)
      .map_err(|err| Error::Fido2(format!("identity: {err}")))?;
   let _ = callbacks.message("Please touch your security key to derive the recipient...");
   let load_pin = if require_pin {
      pin.as_deref().map(String::as_str)
   } else {
      None
   };
   let mut loaded = id.load_secret(dev.as_ref(), load_pin)?;
   if let Some(warning) = loaded.take_mlock_warning() {
      let _ = callbacks.message(&warning);
   }
   loaded.to_recipient()
}

fn ensure_device<'a, C, E>(
   device: &'a mut Option<Box<dyn Fido2Device>>,
   callbacks: &mut C,
) -> Result<&'a mut Box<dyn Fido2Device>, Error>
where
   C: Callbacks<E>,
{
   if device.is_none() {
      let mut ui = CallbackUi::<C, E>::new(callbacks);
      *device = Some(find(Duration::from_secs(50), &mut ui)?);
   }
   Ok(device.as_mut().expect("device just initialized"))
}

/// True if `err` is a recoverable PIN failure.
const fn is_retryable_pin_failure(err: &Error) -> bool {
   match *err {
      Error::PinRequired => true,
      Error::Ctap(status) => {
         matches!(
            status,
            CtapStatus::PinInvalid | CtapStatus::PinAuthInvalid | CtapStatus::PinRequired
         )
      },
      _ => false,
   }
}

/// Per-file plugin+native stanza classification. Decrypt-only —
/// borrows stanza bodies via [`Fido2HmacStanzaRef`] so the hot path
/// avoids cloning.
struct ParsedFileStanzas<'a> {
   plugin:        Vec<Fido2HmacStanzaRef<'a>>,
   native_x25519: Vec<&'a Stanza>,
}

impl<'a> ParsedFileStanzas<'a> {
   /// Classify a single file's stanzas, surfacing per-stanza parse
   /// errors with positional context. Returns `Err` if any plugin
   /// stanza failed to parse so the caller can short-circuit the file.
   fn classify(
      file_index: usize,
      stanzas: &'a [Stanza],
   ) -> Result<Self, Vec<plugin_identity::Error>> {
      let mut plugin = Vec::<Fido2HmacStanzaRef<'a>>::new();
      let mut native_x25519 = Vec::<&'a Stanza>::new();
      let mut parse_errors = Vec::<plugin_identity::Error>::new();
      for (stanza_index, stz) in stanzas.iter().enumerate() {
         if stz.tag == PLUGIN_NAME {
            match Fido2HmacStanzaRef::try_from(stz) {
               Ok(parsed) => plugin.push(parsed),
               Err(err) => {
                  parse_errors.push(plugin_identity::Error::Stanza {
                     file_index,
                     stanza_index,
                     message: format!("parse plugin stanza: {err}"),
                  });
               },
            }
         } else if stz.tag == "X25519" {
            native_x25519.push(stz);
         }
      }
      if parse_errors.is_empty() {
         Ok(Self {
            plugin,
            native_x25519,
         })
      } else {
         Err(parse_errors)
      }
   }

   /// True if any classified plugin stanza in this file declares
   /// `require_pin`. Used by the lazy PIN policy.
   fn any_plugin_requires_pin(&self) -> bool {
      self.plugin.iter().any(Fido2HmacStanzaRef::require_pin)
   }
}

fn ensure_pin<C, E>(
   pin_cache: &mut Option<Zeroizing<String>>,
   callbacks: &mut C,
) -> Result<Zeroizing<String>, Error>
where
   C: Callbacks<E>,
{
   if let &mut Some(ref cached) = pin_cache {
      return Ok(cached.clone());
   }
   match callbacks.request_secret("Please enter your FIDO2 PIN") {
      Ok(Ok(secret)) => {
         let pin_val = Zeroizing::new(secret.expose_secret().to_owned());
         *pin_cache = Some(pin_val.clone());
         Ok(pin_val)
      },
      Ok(Err(_)) | Err(_) => Err(Error::PinRequired),
   }
}

struct CallbackUi<'a, C: Callbacks<E>, E> {
   callbacks:      &'a mut C,
   last_tick_secs: u64,
   _marker:        PhantomData<E>,
}

impl<'a, C: Callbacks<E>, E> CallbackUi<'a, C, E> {
   const fn new(callbacks: &'a mut C) -> Self {
      Self {
         callbacks,
         last_tick_secs: 0,
         _marker: PhantomData,
      }
   }
}

impl<C: Callbacks<E>, E> DiscoveryUi for CallbackUi<'_, C, E> {
   fn message(&mut self, msg: &str) {
      let _ = self.callbacks.message(msg);
   }

   fn waiting_tick(&mut self, started: Instant) {
      let elapsed = started.elapsed().as_secs();
      if elapsed >= 3 && elapsed.is_multiple_of(5) && elapsed != self.last_tick_secs {
         self.last_tick_secs = elapsed;
         let _ = self
            .callbacks
            .message(&format!("Still waiting for security key... ({elapsed}s)"));
      }
   }

   fn pick_device(&mut self, paths: &[String]) -> Result<usize, Error> {
      let _ = self.callbacks.message(&format!(
         "Multiple security keys detected: {}. Re-run with FIDO2_SERIAL=<serial> to pick one.",
         paths.join(", ")
      ));
      Err(Error::InvalidFormat(
         "multiple FIDO2 devices; set FIDO2_SERIAL to disambiguate".into(),
      ))
   }
}
