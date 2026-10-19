//! The only `unsafe` code in the workspace.
//!
//! Four system calls, each because rustix 1.1 cannot make it safely:
//!
//! | Call | Why it is here |
//! |---|---|
//! | `close_range(first, ~0, CLOSE_RANGE_CLOEXEC)` | not wrapped by rustix |
//! | `getsockopt(SO_PEERPIDFD)` | not wrapped by rustix |
//! | `ioctl(PIDFD_GET_INFO)` | not wrapped by rustix |
//! | `execveat(fd, "", AT_EMPTY_PATH)` | rustix wraps it, but as `unsafe` |
//!
//! Everything else the broker and the gate need (`openat2`, `pidfd_open`,
//! `fstatfs`, `PR_SET_NO_NEW_PRIVS`) is safe in rustix and stays there.
//!
//! **Budget: 5 `unsafe` blocks.** One per call, plus one to take ownership of
//! the descriptor `SO_PEERPIDFD` returns. Each block holds exactly one unsafe
//! operation (`clippy::multiple_unsafe_ops_per_block`) and a `SAFETY` comment
//! (`clippy::undocumented_unsafe_blocks`). There is no `unsafe fn` and no
//! `unsafe impl`. `tests/unsafe_budget.rs` reads the number from this paragraph
//! and counts, so raising it means editing this sentence in a reviewed change.
//!
//! Nothing here interprets a result. Each function returns the kernel's answer
//! or its errno as a [`SysError`], and every decision about what an answer
//! means lives in safe code behind [`crate::syscall::Syscalls`], where a fake
//! can drive it.

#![allow(unsafe_code)]

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use libc::{c_char, c_int, c_long, c_uint};

use crate::error::SysError;
use crate::syscall::PidfdInfo;

// The ioctl number encodes the size of the struct it writes. A `PidfdInfo` of
// any other size would be a request for a different struct.
const _: () = assert!(size_of::<PidfdInfo>() == size_of::<libc::pidfd_info>());
const _: () = assert!(size_of::<PidfdInfo>() == 64);

// The SO_PEERPIDFD option is an `int`; its length is passed as a literal.
const C_INT_LEN: libc::socklen_t = 4;
const _: () = assert!(size_of::<c_int>() == 4);

/// Turns a raw return value into a result, reading `errno` immediately.
fn check(operation: &'static str, rc: c_long) -> Result<(), SysError> {
    if rc == -1 {
        Err(SysError::os(operation, &io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

/// `close_range(first, ~0, CLOSE_RANGE_CLOEXEC)`.
pub(crate) fn mark_cloexec_from(first: u32) -> Result<(), SysError> {
    // SAFETY: three integer arguments, no pointers. CLOSE_RANGE_CLOEXEC closes
    // nothing: it sets a flag the kernel acts on at the next exec, so no
    // descriptor an `OwnedFd` in this process holds changes meaning.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            c_long::from(first),
            c_long::from(c_uint::MAX),
            c_long::from(libc::CLOSE_RANGE_CLOEXEC),
        )
    };
    check("close_range", rc)
}

/// `getsockopt(socket, SOL_SOCKET, SO_PEERPIDFD)`.
pub(crate) fn peer_pidfd(socket: BorrowedFd<'_>) -> Result<OwnedFd, SysError> {
    let mut pidfd: c_int = -1;
    let mut len = C_INT_LEN;
    // SAFETY: `pidfd` and `len` are live locals for the whole call, `len`
    // states the size of `pidfd` exactly, and `socket` is a borrowed, open
    // descriptor. The kernel writes at most `len` bytes.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&raw mut pidfd).cast(),
            &raw mut len,
        )
    };
    check("getsockopt(SO_PEERPIDFD)", c_long::from(rc))?;
    // SAFETY: on success the kernel installed a new descriptor in this
    // process's table and returned its number. Nothing else owns it, so taking
    // ownership here is the only ownership there is.
    Ok(unsafe { OwnedFd::from_raw_fd(pidfd) })
}

/// `ioctl(pidfd, PIDFD_GET_INFO)`.
///
/// Branch-free after the call on purpose: the success path needs Linux 6.13,
/// and the coverage gate must not depend on which kernel the CI runner has.
pub(crate) fn pidfd_info(pidfd: BorrowedFd<'_>, mask: u64) -> Result<PidfdInfo, SysError> {
    let mut info = PidfdInfo::new(mask);
    // SAFETY: `info` is a live `#[repr(C)]` struct of exactly the size the
    // request number encodes (asserted at compile time above), so the kernel's
    // write stays inside it. Every bit pattern is a valid `PidfdInfo`: the
    // fields are plain integers.
    let rc = unsafe { libc::ioctl(pidfd.as_raw_fd(), libc::PIDFD_GET_INFO, &raw mut info) };
    check("ioctl(PIDFD_GET_INFO)", c_long::from(rc)).and(Ok(info))
}

/// `execveat(program, "", argv, envp, AT_EMPTY_PATH)`. Returns only on failure.
pub(crate) fn exec_fd(program: BorrowedFd<'_>, argv: &[&CStr], envp: &[&CStr]) -> SysError {
    let argv = null_terminated(argv);
    let envp = null_terminated(envp);
    // SAFETY: the path is a NUL-terminated literal, and `argv` and `envp` are
    // NULL-terminated arrays of pointers into `&CStr`s the caller keeps alive
    // for this whole call. On success the process image is replaced and none
    // of this memory is read again; on failure the call returns and nothing was
    // written.
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            c_long::from(program.as_raw_fd()),
            c"".as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            c_long::from(libc::AT_EMPTY_PATH),
        )
    };
    SysError::os("execveat", &io::Error::last_os_error())
}

fn null_terminated(strings: &[&CStr]) -> Vec<*const c_char> {
    strings
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::syscall::{PIDFD_INFO_CGROUPID, PIDFD_INFO_CREDS, PIDFD_INFO_PID};

    #[test]
    fn the_mask_bits_are_the_kernels() {
        // Defined in safe code so the fake can use them on any platform, and
        // checked here against the headers on the platform that has them.
        assert_eq!(PIDFD_INFO_PID, u64::from(libc::PIDFD_INFO_PID));
        assert_eq!(PIDFD_INFO_CREDS, u64::from(libc::PIDFD_INFO_CREDS));
        assert_eq!(PIDFD_INFO_CGROUPID, u64::from(libc::PIDFD_INFO_CGROUPID));
    }
}
