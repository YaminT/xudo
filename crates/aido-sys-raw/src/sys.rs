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
//! These are the four the broker and the gate are known to need. Two more are
//! foreseeable and deliberately not here yet: `fork`, if the gate is built to
//! outlive the command it runs rather than to exec in place, and a per-
//! descriptor `fcntl` fallback for kernels before 5.11, if the gate is to run
//! there. Both are decided with the gate (M2b step 4); either one is a change to
//! the budget below, reviewed as such.
//!
//! **Budget: 5 `unsafe` blocks.** One per call, plus one to take ownership of
//! the descriptor `SO_PEERPIDFD` returns. Each block holds exactly one unsafe
//! operation (`clippy::multiple_unsafe_ops_per_block`) and a `SAFETY` comment
//! (`clippy::undocumented_unsafe_blocks`). There is no `unsafe fn` and no
//! `unsafe impl`. `tests/unsafe_budget.rs` reads the number from this paragraph
//! and counts the blocks as tokens, so raising it means editing this sentence in
//! a reviewed change.
//!
//! Nothing here interprets a result. Each function returns the kernel's answer
//! or an [`OsError`], and every decision about what an answer means lives in
//! `aido-sys`, behind a trait with a fake.

#![allow(unsafe_code)]

use std::ffi::CStr;
use std::io;
use std::mem::offset_of;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use libc::{c_char, c_int, c_long, c_uint};

use crate::{OsError, PidfdInfo};

// The ioctl number encodes the size of the struct it writes, and the kernel
// writes each field at its own offset. A `PidfdInfo` that differed from the
// kernel's struct in either would hand the broker one credential in another's
// place, so both are asserted against the headers.
const _: () = assert!(size_of::<PidfdInfo>() == size_of::<libc::pidfd_info>());
const _: () = assert!(size_of::<PidfdInfo>() == 64);
const _: () = {
    assert!(offset_of!(PidfdInfo, mask) == offset_of!(libc::pidfd_info, mask));
    assert!(offset_of!(PidfdInfo, cgroupid) == offset_of!(libc::pidfd_info, cgroupid));
    assert!(offset_of!(PidfdInfo, pid) == offset_of!(libc::pidfd_info, pid));
    assert!(offset_of!(PidfdInfo, tgid) == offset_of!(libc::pidfd_info, tgid));
    assert!(offset_of!(PidfdInfo, ppid) == offset_of!(libc::pidfd_info, ppid));
    assert!(offset_of!(PidfdInfo, ruid) == offset_of!(libc::pidfd_info, ruid));
    assert!(offset_of!(PidfdInfo, rgid) == offset_of!(libc::pidfd_info, rgid));
    assert!(offset_of!(PidfdInfo, euid) == offset_of!(libc::pidfd_info, euid));
    assert!(offset_of!(PidfdInfo, egid) == offset_of!(libc::pidfd_info, egid));
    assert!(offset_of!(PidfdInfo, suid) == offset_of!(libc::pidfd_info, suid));
    assert!(offset_of!(PidfdInfo, sgid) == offset_of!(libc::pidfd_info, sgid));
    assert!(offset_of!(PidfdInfo, fsuid) == offset_of!(libc::pidfd_info, fsuid));
    assert!(offset_of!(PidfdInfo, fsgid) == offset_of!(libc::pidfd_info, fsgid));
    assert!(offset_of!(PidfdInfo, _exit_code) == offset_of!(libc::pidfd_info, exit_code));
};

// The SO_PEERPIDFD option is an `int`; its length is passed as a literal.
const C_INT_LEN: libc::socklen_t = 4;
const _: () = assert!(size_of::<c_int>() == 4);

/// Turns a raw return value into a result, reading `errno` immediately.
fn check(operation: &'static str, rc: c_long) -> Result<(), OsError> {
    if rc == -1 {
        Err(OsError {
            operation,
            error: io::Error::last_os_error(),
        })
    } else {
        Ok(())
    }
}

/// `close_range(first, ~0, CLOSE_RANGE_CLOEXEC)`.
///
/// # Errors
///
/// The kernel's errno: `EINVAL` before Linux 5.11, `ENOSYS` before 5.9.
pub fn mark_cloexec_from(first: u32) -> Result<(), OsError> {
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
///
/// # Errors
///
/// The kernel's errno, or an error with no errno if the kernel reported
/// success without writing a descriptor.
pub fn peer_pidfd(socket: BorrowedFd<'_>) -> Result<OwnedFd, OsError> {
    let operation = "getsockopt(SO_PEERPIDFD)";
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
    check(operation, c_long::from(rc))?;
    // A success that wrote nothing — a syscall filter returning 0 without
    // running the call — would leave `-1` behind, and adopting `-1` panics.
    // Checked without an early return, because no real kernel takes it, and a
    // return no test can reach is a region no test can cover.
    let written = pidfd >= 0 && len == C_INT_LEN;
    let unwritten = OsError {
        operation,
        error: io::Error::new(
            io::ErrorKind::InvalidData,
            "the kernel reported success without writing a descriptor",
        ),
    };
    written.then_some(pidfd).ok_or(unwritten).map(|fd| {
        // SAFETY: the kernel installed a new descriptor in this process's
        // table and returned its number, which was just checked to be one.
        // Nothing else owns it, so taking ownership here is the only ownership
        // there is.
        unsafe { OwnedFd::from_raw_fd(fd) }
    })
}

/// `ioctl(pidfd, PIDFD_GET_INFO)`.
///
/// Branch-free after the call on purpose: the success path needs Linux 6.13,
/// and the coverage gate must not depend on which kernel the CI runner has.
/// Whether the record is an answer at all is the caller's to check, with
/// [`PidfdInfo::is_answer`].
///
/// # Errors
///
/// The kernel's errno.
pub fn pidfd_info(pidfd: BorrowedFd<'_>, mask: u64) -> Result<PidfdInfo, OsError> {
    let mut info = PidfdInfo::with_mask(mask);
    // SAFETY: `info` is a live `#[repr(C)]` struct of exactly the size and
    // layout the request number encodes (asserted at compile time above), so
    // the kernel's write stays inside it. Every bit pattern is a valid
    // `PidfdInfo`: the fields are plain integers.
    let rc = unsafe { libc::ioctl(pidfd.as_raw_fd(), libc::PIDFD_GET_INFO, &raw mut info) };
    check("ioctl(PIDFD_GET_INFO)", c_long::from(rc)).and(Ok(info))
}

/// `execveat(program, "", argv, envp, AT_EMPTY_PATH)`. Returns only on failure.
pub fn exec_fd(program: BorrowedFd<'_>, argv: &[&CStr], envp: &[&CStr]) -> OsError {
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
    OsError {
        operation: "execveat",
        error: io::Error::last_os_error(),
    }
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
    use crate::{PIDFD_INFO_CGROUPID, PIDFD_INFO_CREDS, PIDFD_INFO_PID};

    #[test]
    fn the_mask_bits_are_the_kernels() {
        // Defined in safe code so a fake can use them on any platform, and
        // checked here against the headers on the platform that has them.
        assert_eq!(PIDFD_INFO_PID, u64::from(libc::PIDFD_INFO_PID));
        assert_eq!(PIDFD_INFO_CREDS, u64::from(libc::PIDFD_INFO_CREDS));
        assert_eq!(PIDFD_INFO_CGROUPID, u64::from(libc::PIDFD_INFO_CGROUPID));
    }
}
