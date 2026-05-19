//! Best-effort `mlock(2)` wrapper.
//!
//! On non-Unix platforms this is a no-op that always succeeds.

#[cfg(unix)] use std::io::Error;

#[cfg(unix)]
mod ffi {
   use core::ffi::{
      c_int,
      c_void,
   };
   unsafe extern "C" {
      pub fn mlock(addr: *const c_void, len: usize) -> c_int;
   }
}

/// Attempt to [`mlock`] the given byte slice. Returns the OS error on failure.
#[cfg(unix)]
pub fn mlock(bytes: &[u8]) -> Result<(), Error> {
   // SAFETY: we pass a valid pointer + length
   let rc = unsafe { ffi::mlock(bytes.as_ptr().cast(), bytes.len()) };
   if rc == 0 {
      Ok(())
   } else {
      Err(Error::last_os_error())
   }
}

/// No-op on non-Unix.
#[cfg(not(unix))]
pub fn mlock(_bytes: &[u8]) -> Result<(), Error> {
   Ok(())
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn small_buffer_locks_or_fails_cleanly() {
      // Low memlock limits can make this fail; it must still return normally.
      let buf = [0_u8; 64];
      let _ = mlock(&buf);
   }
}
