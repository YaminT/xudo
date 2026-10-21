//! Where a nonce's randomness comes from.
//!
//! The kernel's `getrandom`, with no flags: it blocks until the pool is
//! initialised and never returns early from a request this small, so a nonce
//! is never drawn from an empty pool. Behind a trait so a test can script the
//! bytes — including the same bytes twice, which is the only way to watch the
//! broker refuse a nonce that collides.

use std::cell::RefCell;
use std::collections::VecDeque;

use crate::error::SysError;

/// A source of random bytes.
pub trait Entropy {
    /// Fills `buf` completely.
    ///
    /// # Errors
    ///
    /// [`SysError::Os`] if the kernel refuses or returns fewer bytes than
    /// asked for, and [`SysError::Unsupported`] off Linux.
    fn fill(&self, buf: &mut [u8]) -> Result<(), SysError>;
}

/// The kernel's random source.
#[derive(Clone, Copy, Debug)]
pub struct HostEntropy;

#[cfg(target_os = "linux")]
impl Entropy for HostEntropy {
    fn fill(&self, buf: &mut [u8]) -> Result<(), SysError> {
        let wanted = buf.len();
        filled(
            rustix::rand::getrandom(buf, rustix::rand::GetRandomFlags::empty()),
            wanted,
        )
    }
}

#[cfg(not(target_os = "linux"))]
impl Entropy for HostEntropy {
    fn fill(&self, _buf: &mut [u8]) -> Result<(), SysError> {
        Err(SysError::unsupported("getrandom on a non-Linux platform"))
    }
}

/// Reads a `getrandom` result as "the buffer is full", or a refusal.
///
/// A short read is a refusal rather than a retry: for a request of this size
/// the kernel never returns one once the pool is ready, so one means something
/// is wrong, and a nonce built from a partly filled buffer would be partly
/// zeros. Split out so both failure arms are reachable from a test.
#[cfg(target_os = "linux")]
fn filled(result: rustix::io::Result<usize>, wanted: usize) -> Result<(), SysError> {
    match result {
        Ok(got) if got == wanted => Ok(()),
        Ok(got) => Err(SysError::Os {
            operation: "getrandom".to_owned(),
            code: None,
            reason: format!("returned {got} of {wanted} bytes"),
        }),
        Err(errno) => Err(SysError::os("getrandom", &errno.into())),
    }
}

/// Scripted randomness, for tests.
///
/// Each [`Entropy::fill`] takes the next scripted answer. An answer of the
/// wrong length is refused, as is a call with nothing scripted, so a test
/// cannot be handed bytes it did not choose.
#[derive(Debug, Default)]
pub struct FakeEntropy {
    answers: RefCell<VecDeque<Result<Vec<u8>, SysError>>>,
}

impl FakeEntropy {
    /// A fake with nothing scripted.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues the next answer.
    #[must_use]
    pub fn with(self, answer: Result<Vec<u8>, SysError>) -> Self {
        self.answers.borrow_mut().push_back(answer);
        self
    }
}

impl Entropy for FakeEntropy {
    fn fill(&self, buf: &mut [u8]) -> Result<(), SysError> {
        let answer = self
            .answers
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Err(SysError::unsupported("fake: no randomness scripted")))?;
        if answer.len() != buf.len() {
            return Err(SysError::unsupported(format!(
                "fake: {} bytes scripted for a {}-byte request",
                answer.len(),
                buf.len()
            )));
        }
        buf.copy_from_slice(&answer);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn a_short_or_failed_read_is_a_refusal_never_a_partial_nonce() {
        use rustix::io::Errno;

        assert_eq!(filled(Ok(32), 32), Ok(()));
        let short = filled(Ok(5), 32).unwrap_err();
        assert!(short.to_string().contains("5 of 32"), "{short}");
        let failed = filled(Err(Errno::INTR), 32).unwrap_err();
        assert_eq!(failed.os_code(), Some(Errno::INTR.raw_os_error()));
    }

    #[test]
    fn a_fake_hands_out_exactly_what_was_scripted() {
        let fake = FakeEntropy::new()
            .with(Ok(vec![7; 4]))
            .with(Ok(vec![1; 3]))
            .with(Err(SysError::unsupported("scripted")));
        let mut buf = [0u8; 4];
        fake.fill(&mut buf).unwrap();
        assert_eq!(buf, [7; 4]);
        assert!(
            fake.fill(&mut buf)
                .unwrap_err()
                .to_string()
                .contains("3 bytes")
        );
        assert!(
            fake.fill(&mut buf)
                .unwrap_err()
                .to_string()
                .contains("scripted")
        );
        assert!(
            fake.fill(&mut buf)
                .unwrap_err()
                .to_string()
                .contains("no randomness")
        );
        assert!(format!("{fake:?}").contains("FakeEntropy"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_host_fills_a_nonce_sized_buffer() {
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        HostEntropy.fill(&mut first).unwrap();
        HostEntropy.fill(&mut second).unwrap();
        // Two draws of 256 bits do not collide.
        assert_ne!(first, second);
        assert!(format!("{HostEntropy:?}").contains("HostEntropy"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn the_host_refuses_off_linux() {
        let mut buf = [0u8; 32];
        let err = HostEntropy.fill(&mut buf).unwrap_err();
        assert!(err.to_string().contains("not supported"), "{err}");
        assert!(format!("{HostEntropy:?}").contains("HostEntropy"));
    }
}
