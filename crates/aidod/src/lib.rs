//! `aidod`, the root broker: the only thing that mints the requests the gate
//! acts on.
//!
//! The gate refuses with `NoPendingRequest` unless a root-minted entry exists
//! under `/run/aido/req`, so without this broker nothing `aido` decides can be
//! executed — the human path included. M2b's broker does exactly one job:
//!
//! 1. take one connection from systemd, as descriptor 0;
//! 2. identify the peer from the kernel, by the attestation ladder;
//! 3. classify it `Unattested` — there is no cgroup classification until M4,
//!    so every caller takes the human path, with a password;
//! 4. evaluate the request against root's ruleset, with the same function
//!    `aido explain` uses;
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
//! Every syscall is behind a seam in `aido-sys`, so every refusal below is
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

pub mod identify;
pub mod mint;
pub mod policy;
pub mod record;
pub mod refusal;
pub mod serve;

use std::io::Write;
use std::os::fd::BorrowedFd;
use std::path::Path;
use std::time::Duration;

use aido_sys::{HostClock, HostEntropy, HostPeer, HostSyscalls, SpoolDir, UnixConnection};
use aido_wire::RefusalCode;

pub use identify::{Fault, IdentifyError, PeerIdentity, identify};
pub use policy::{HostPolicy, LoadedPolicy, PolicyError, PolicySource};
pub use refusal::Refusal;
pub use serve::{Platform, Served, UNUSABLE, serve};

/// Where the broker is installed.
pub const INSTALLED_PATH: &str = "/usr/libexec/aido/aidod";

/// How long the broker waits on one read or one write of its connection.
///
/// The front-end writes its whole request the moment it connects, so five
/// seconds is generous for a client that means to talk; a client that does
/// not is cut off, and the unit's `RuntimeMaxSec=` cuts off anything this
/// does not.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether the audit trail is attested: `Ok` when `stderr` is a connected
/// `AF_UNIX` stream socket, which is what systemd makes of a connection to
/// the journal, and the reason when it is anything else.
///
/// What this does and does not show: a socket, not that the journal is on the
/// other end of it. But when systemd cannot connect a service to the journal it
/// logs "Failed to connect stderr to the journal socket, ignoring" and
/// points standard error at `/dev/null`, and a closed descriptor is reopened on
/// `/dev/null` by the Rust runtime; neither is a socket.
///
/// # Errors
///
/// The first property that does not hold, in words for the audit record.
pub fn trail_of(stderr: BorrowedFd<'_>) -> Result<(), String> {
    aido_sys::connected_unix_stream(stderr).map_err(|error| error.to_string())
}

/// Serves the connection on `socket` — descriptor 0, from systemd — against
/// this host, and returns the exit status.
///
/// A descriptor that is not a connected `AF_UNIX` stream socket is refused
/// with [`UNUSABLE`] and an audit record: there is nobody to answer.
///
/// `trail` is [`trail_of`] standard error: nothing is minted unless it is `Ok`.
pub fn run(socket: BorrowedFd<'_>, trail: Result<(), String>, log: &mut dyn Write) -> u8 {
    match UnixConnection::adopt(socket, IO_TIMEOUT) {
        Ok(conn) => {
            let spool = SpoolDir::open(Path::new(aido_gate::SPOOL_DIR));
            let policy = HostPolicy::system();
            let platform = Platform {
                syscalls: &HostSyscalls,
                peers: &HostPeer,
                clock: &HostClock,
                entropy: &HostEntropy,
                policy: &policy,
                trail,
            };
            serve(&conn, &platform, spool.as_ref(), log).exit_status()
        }
        Err(error) => {
            let refusal = Refusal::broker(RefusalCode::BrokerUnusable, error.to_string());
            let _ = record::emit(&record::refused(&refusal, None, None), log);
            UNUSABLE
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use std::io::Read as _;
    use std::net::Shutdown;
    use std::os::fd::AsFd as _;
    use std::os::unix::net::UnixStream;

    use aido_wire::{Answer, BrokerRequest, BrokerResponse};

    use super::*;

    /// What a socketpair client is refused with on this host, as a test user:
    /// on Linux the peer is identified and the spool is not root's; anywhere
    /// else, no peer can be identified at all.
    #[cfg(target_os = "linux")]
    const EXPECTED: RefusalCode = RefusalCode::SpoolUnusable;
    #[cfg(not(target_os = "linux"))]
    const EXPECTED: RefusalCode = RefusalCode::PeerUnidentified;

    fn code_of(answer: &Answer) -> Option<RefusalCode> {
        match answer {
            Answer::Refused { code, .. } => Some(*code),
            Answer::Decided { .. } => None,
        }
    }

    #[test]
    fn descriptor_zero_that_is_not_a_socket_is_refused_with_a_record() {
        let file = std::fs::File::open(env!("CARGO_MANIFEST_DIR")).unwrap();
        let mut log = Vec::new();
        assert_eq!(run(file.as_fd(), Ok(()), &mut log), UNUSABLE);
        let text = String::from_utf8(log).unwrap();
        assert!(text.contains("broker_unusable"), "{text}");
        assert!(text.contains("not a socket"), "{text}");
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

        let mut log = Vec::new();
        assert_eq!(run(broker.as_fd(), Ok(()), &mut log), UNUSABLE);
        drop(broker);

        let mut answer = Vec::new();
        client.read_to_end(&mut answer).unwrap();
        let response = BrokerResponse::parse(&answer).unwrap();
        assert_eq!(code_of(&response.answer), Some(EXPECTED));
        assert_eq!(
            code_of(
                &BrokerResponse::decided(
                    aido_policy::Decision::deny(
                        aido_policy::DenialCode::UnknownAction,
                        Vec::new(),
                        Vec::new()
                    ),
                    None
                )
                .answer
            ),
            None
        );
        let text = String::from_utf8(log).unwrap();
        assert!(text.contains(EXPECTED.as_str()), "{text}");
    }

    #[test]
    fn standard_error_counts_as_a_trail_only_when_it_is_a_connected_stream() {
        let (journal, _other) = UnixStream::pair().unwrap();
        assert_eq!(trail_of(journal.as_fd()), Ok(()));
        let null = std::fs::File::open("/dev/null").unwrap();
        let why = trail_of(null.as_fd()).unwrap_err();
        assert!(why.contains("not a socket"), "{why}");
    }

    #[test]
    fn the_installed_path_and_timeout_are_the_documented_ones() {
        assert_eq!(INSTALLED_PATH, "/usr/libexec/aido/aidod");
        assert_eq!(IO_TIMEOUT, Duration::from_secs(5));
        assert_eq!(
            i32::from(UNUSABLE),
            aido_policy::ExitCode::Unusable.as_i32()
        );
    }
}
