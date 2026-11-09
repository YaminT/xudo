//! `xudod`, the root broker: the only thing that mints the requests the gate
//! acts on.
//!
//! The gate refuses with `NoPendingRequest` unless a root-minted entry exists
//! under `/run/xudo/req`, so without this broker nothing `xudo` decides can be
//! executed — the human path included. M2b's broker does exactly one job:
//!
//! 1. take one connection from systemd, as descriptor 0;
//! 2. identify the peer from the kernel, by the attestation ladder;
//! 3. classify it `Unattested` — there is no cgroup classification until M4,
//!    so every caller takes the human path, with a password;
//! 4. evaluate the request against root's ruleset, with the same function
//!    `xudo explain` uses;
//! 5. on a permitted decision, mint the spool entry the gate reads;
//! 6. answer with the decision and, if one was minted, the nonce, the deadline,
//!    and the gate to run.
//!
//! No confirmation channel, no `freeze`, no cgroups: those are M3 and M4.
//!
//! # Trust
//!
//! The broker runs as root and trusts nothing it is sent. The request carries
//! only the question; who asked comes from `SO_PEERCRED` and a pidfd, and what
//! is allowed comes from root's ruleset, read through verified descriptors.
//! Every syscall is behind a seam in `xudo-sys`, so every refusal below is
//! reached by a test on a laptop, without root.
//!
//! | Module | Answers |
//! |---|---|
//! | [`identify`] | Who is on the other end of the socket? |
//! | [`policy`] | What does root's policy decide about this command? |
//! | [`mint`] | What does the gate's entry say, and what may stay in the spool? |
//! | [`record`] | What does the audit trail say about this answer? |
//! | [`refusal`] | What is the client told when the answer is no answer? |
//! | [`serve`] | In what order, and what happens when a step fails? |

#![forbid(unsafe_code)]

pub mod confirm;
pub mod identify;
pub mod mint;
pub mod policy;
pub mod record;
pub mod refusal;
pub mod serve;

use std::os::fd::BorrowedFd;
use std::path::Path;
use std::time::Duration;

use xudo_sys::{
    AuditSink, HostClock, HostEntropy, HostHygiene, HostPeer, HostSyscalls, Hygiene, SpoolDir,
    UnixConnection,
};
use xudo_wire::RefusalCode;

pub use identify::{Fault, IdentifyError, PeerIdentity, identify};
pub use policy::{HostPolicy, LoadedPolicy, PolicyError, PolicySource};
pub use refusal::Refusal;
pub use serve::{Platform, Served, UNUSABLE, serve};

/// Where the broker is installed.
pub const INSTALLED_PATH: &str = "/usr/libexec/xudo/xudod";

/// How long the broker waits on one read or one write of its connection.
///
/// The front-end writes its whole request the moment it connects, so five
/// seconds is generous for a client that means to talk; a client that does
/// not is cut off, and the unit's `RuntimeMaxSec=` cuts off anything this
/// does not.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Serves the connection on `socket` — descriptor 0, from systemd — against
/// this host, and returns the exit status.
///
/// A descriptor that is not a connected `AF_UNIX` stream socket is refused
/// with [`UNUSABLE`]: there is nobody to answer. Nothing is minted unless its
/// record lands on `audit` first.
pub fn run(socket: BorrowedFd<'_>, audit: &mut dyn AuditSink) -> u8 {
    run_with_hygiene(socket, audit, &HostHygiene)
}

fn run_with_hygiene(
    socket: BorrowedFd<'_>,
    audit: &mut dyn AuditSink,
    hygiene: &dyn Hygiene,
) -> u8 {
    match UnixConnection::adopt(socket, IO_TIMEOUT) {
        Ok(conn) => {
            let spool = SpoolDir::open(Path::new(xudo_gate::SPOOL_DIR));
            let confirmations = SpoolDir::open(Path::new("/run/xudo/confirm"));
            let policy = HostPolicy::system();
            let mut platform = Platform {
                hygiene,
                syscalls: &HostSyscalls,
                peers: &HostPeer,
                clock: &HostClock,
                entropy: &HostEntropy,
                policy: &policy,
                audit,
                confirmations: xudo_sys::as_seam(&confirmations).ok(),
            };
            serve(&conn, &mut platform, xudo_sys::as_seam(&spool)).exit_status()
        }
        Err(error) => {
            let refusal = Refusal::broker(RefusalCode::BrokerUnusable, error.to_string());
            let _ = audit.append(&|previous| record::refused(previous, &refusal, None, None));
            UNUSABLE
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use std::io::{Read as _, Write as _};
    use std::net::Shutdown;
    use std::os::fd::AsFd as _;
    use std::os::unix::net::UnixStream;

    use xudo_sys::{FakeAuditSink, FakeHygiene, HygieneCall, SysError};
    use xudo_wire::{Answer, BrokerRequest, BrokerResponse};

    use super::*;

    /// What a socketpair client is refused with on this host, as a test user:
    /// Linux reaches the untrusted spool; other platforms cannot set broker hygiene.
    #[cfg(target_os = "linux")]
    const EXPECTED: RefusalCode = RefusalCode::SpoolUnusable;
    #[cfg(not(target_os = "linux"))]
    const EXPECTED: RefusalCode = RefusalCode::BrokerUnusable;
    #[cfg(target_os = "linux")]
    const AFTER_HYGIENE: RefusalCode = RefusalCode::SpoolUnusable;
    #[cfg(not(target_os = "linux"))]
    const AFTER_HYGIENE: RefusalCode = RefusalCode::PeerUnidentified;

    fn code_of(answer: &Answer) -> Option<RefusalCode> {
        match answer {
            Answer::Refused { code, .. } => Some(*code),
            Answer::Decided { .. }
            | Answer::Pending { .. }
            | Answer::Watching { .. }
            | Answer::Done => None,
        }
    }

    #[test]
    fn descriptor_zero_that_is_not_a_socket_is_refused_with_a_record() {
        let file = std::fs::File::open(env!("CARGO_MANIFEST_DIR")).unwrap();
        let mut audit = FakeAuditSink::new();
        assert_eq!(run(file.as_fd(), &mut audit), UNUSABLE);
        let record = &audit.records()[0];
        assert_eq!(record.denial.as_deref(), Some("broker_unusable"));
        assert!(record.evidence.join(" ").contains("not a socket"));
    }

    #[test]
    fn a_broker_that_cannot_set_no_new_privs_serves_nothing() {
        let (broker, mut client) = UnixStream::pair().unwrap();

        let hygiene =
            FakeHygiene::new(1).with_privileges_error(SysError::unsupported("PR_SET_NO_NEW_PRIVS"));
        let mut audit = FakeAuditSink::new();
        assert_eq!(
            run_with_hygiene(broker.as_fd(), &mut audit, &hygiene),
            UNUSABLE
        );
        drop(broker);

        let mut answer = Vec::new();
        client.read_to_end(&mut answer).unwrap();
        let response = BrokerResponse::parse(&answer).unwrap();
        assert_eq!(code_of(&response.answer), Some(RefusalCode::BrokerUnusable));
        assert_eq!(hygiene.calls(), [HygieneCall::ForbidNewPrivileges]);
        assert_eq!(audit.records().len(), 1);
        assert_eq!(
            audit.records()[0].denial.as_deref(),
            Some("broker_unusable")
        );
        assert!(
            audit.records()[0]
                .evidence
                .join(" ")
                .contains("PR_SET_NO_NEW_PRIVS")
        );
    }

    #[test]
    fn a_broker_that_sets_no_new_privs_reaches_request_serving() {
        let (broker, mut client) = UnixStream::pair().unwrap();
        let request = BrokerRequest::new("/usr/bin/id", vec!["-u".to_owned()], "unattested");
        client.write_all(request.to_json().as_bytes()).unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let hygiene = FakeHygiene::new(1);
        let mut audit = FakeAuditSink::new();
        assert_eq!(
            run_with_hygiene(broker.as_fd(), &mut audit, &hygiene),
            UNUSABLE
        );
        drop(broker);

        let mut answer = Vec::new();
        client.read_to_end(&mut answer).unwrap();
        let response = BrokerResponse::parse(&answer).unwrap();
        assert_eq!(code_of(&response.answer), Some(AFTER_HYGIENE));
        assert_eq!(hygiene.calls(), [HygieneCall::ForbidNewPrivileges]);
        assert_eq!(audit.records().len(), 1);
        assert_eq!(
            audit.records()[0].denial.as_deref(),
            Some(AFTER_HYGIENE.as_str())
        );
    }

    #[test]
    fn a_real_connection_is_served_end_to_end_and_refused_as_this_host_must() {
        let (broker, mut client) = UnixStream::pair().unwrap();
        let request = BrokerRequest::new(
            "/usr/bin/systemctl",
            vec!["restart".to_owned(), "nginx.service".to_owned()],
            "unattested",
        );
        client.write_all(request.to_json().as_bytes()).unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let mut audit = FakeAuditSink::new();
        assert_eq!(run(broker.as_fd(), &mut audit), UNUSABLE);
        drop(broker);

        let mut answer = Vec::new();
        client.read_to_end(&mut answer).unwrap();
        let response = BrokerResponse::parse(&answer).unwrap();
        assert_eq!(code_of(&response.answer), Some(EXPECTED));
        assert_eq!(
            code_of(
                &BrokerResponse::decided(
                    xudo_policy::Decision::deny(
                        xudo_policy::DenialCode::UnknownAction,
                        Vec::new(),
                        Vec::new()
                    ),
                    None
                )
                .answer
            ),
            None
        );
        assert_eq!(
            audit.records()[0].denial.as_deref(),
            Some(EXPECTED.as_str())
        );
    }

    #[test]
    fn the_installed_path_and_timeout_are_the_documented_ones() {
        assert_eq!(INSTALLED_PATH, "/usr/libexec/xudo/xudod");
        assert_eq!(IO_TIMEOUT, Duration::from_secs(5));
        assert_eq!(
            i32::from(UNUSABLE),
            xudo_policy::ExitCode::Unusable.as_i32()
        );
    }
}
