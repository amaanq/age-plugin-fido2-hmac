//! `age-plugin-fido2-hmac`.

pub mod device;
pub mod error;
pub mod format;
pub mod identity;
pub mod magic;
pub(crate) mod mlock;
pub mod plugin;
pub mod recipient;
pub mod stanza;
mod yubikey_serial;
