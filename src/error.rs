//! Crate-wide error type.

use core::result::Result as StdResult;
use std::io;

use ctap_fido2::error::CtapStatus;
use thiserror::Error;

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum Error {
   /// Wire-format problem (bad bech32, unexpected length, wrong HRP, etc.).
   #[error("invalid format: {0}")]
   InvalidFormat(String),

   /// On-wire format version we don't support.
   #[error("unsupported format version {0}")]
   UnsupportedVersion(u16),

   /// FIDO2 device error from the underlying CTAP library.
   #[error("fido2 device: {0}")]
   Fido2(String),

   /// Typed CTAP status byte from the authenticator.
   #[error("ctap: {0}")]
   Ctap(CtapStatus),

   /// No FIDO2 device with hmac-secret support found before timeout.
   #[error("no compatible FIDO2 device found")]
   NoDevice,

   /// Operation timed out (device wait, PIN entry, etc.).
   #[error("operation timed out")]
   Timeout,

   /// A PIN was required but not supplied.
   #[error("PIN required for this identity")]
   PinRequired,

   /// IO error.
   #[error("io: {0}")]
   Io(#[from] io::Error),

   /// Error coming from the underlying age crate (encrypt path).
   #[error("age encrypt: {0}")]
   AgeEncrypt(String),

   /// Error coming from the underlying age crate (decrypt path).
   #[error("age decrypt: {0}")]
   AgeDecrypt(String),
}

pub type Result<T> = StdResult<T, Error>;

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn display_is_one_line() {
      let err = Error::UnsupportedVersion(7);
      assert_eq!(format!("{err}"), "unsupported format version 7");
   }

   #[test]
   fn invalid_format_carries_context() {
      let err = Error::InvalidFormat("missing salt".into());
      assert!(format!("{err}").contains("missing salt"));
   }
}
