//! A refusal: the code the client is sent, and what only the audit record
//! carries.
//!
//! The client gets a [`RefusalCode`] and its fixed remediation, nothing else —
//! no path, no errno, no description of the broker's state. The detail goes to
//! the audit record, which only root reads. [`Fault`] decides the exit status:
//! systemd marks the instance failed when the broker or its host is broken,
//! not when a client misbehaved.

use aido_sys::{ReadFailure, SpoolError};
use aido_wire::{RefusalCode, RequestError};

use crate::identify::{Fault, IdentifyError};
use crate::mint::MintError;
use crate::policy::PolicyError;

/// Why the broker answered without, or instead of, a decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// What the client is told.
    pub code: RefusalCode,
    /// What the audit record says, in full.
    pub detail: String,
    /// Whose failure it is.
    pub fault: Fault,
}

impl Refusal {
    /// A refusal caused by the client.
    pub fn client(code: RefusalCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            fault: Fault::Client,
        }
    }

    /// A refusal caused by the broker or its host.
    pub fn broker(code: RefusalCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            fault: Fault::Broker,
        }
    }
}

impl From<&IdentifyError> for Refusal {
    fn from(error: &IdentifyError) -> Self {
        Self {
            code: RefusalCode::PeerUnidentified,
            detail: error.to_string(),
            fault: error.fault(),
        }
    }
}

impl From<&ReadFailure> for Refusal {
    fn from(error: &ReadFailure) -> Self {
        let code = match error {
            ReadFailure::TooLarge { .. } => RefusalCode::RequestTooLarge,
            ReadFailure::TimedOut => RefusalCode::RequestTimedOut,
            ReadFailure::Os(_) => RefusalCode::RequestUnreadable,
        };
        Self::client(code, error.to_string())
    }
}

impl From<&RequestError> for Refusal {
    fn from(error: &RequestError) -> Self {
        Self::client(error.code(), error.to_string())
    }
}

impl From<&SpoolError> for Refusal {
    fn from(error: &SpoolError) -> Self {
        Self::broker(RefusalCode::SpoolUnusable, error.to_string())
    }
}

impl From<&PolicyError> for Refusal {
    fn from(error: &PolicyError) -> Self {
        Self::broker(RefusalCode::PolicyUnloadable, error.to_string())
    }
}

impl From<&MintError> for Refusal {
    /// A full spool is the clients' doing — the pending requests of whoever
    /// asked before — and the broker refusing to grow it is the broker
    /// working. Classed as the broker's, any group member could make it
    /// report itself broken by asking often enough.
    fn from(error: &MintError) -> Self {
        match error {
            MintError::NoAction => Self::broker(RefusalCode::BrokerUnusable, error.to_string()),
            MintError::Spool(_) => Self::broker(RefusalCode::SpoolUnusable, error.to_string()),
            MintError::Full { .. } | MintError::UidFull { .. } => {
                Self::client(RefusalCode::SpoolFull, error.to_string())
            }
            MintError::Collision { .. } => {
                Self::broker(RefusalCode::NonceCollision, error.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use aido_sys::SysError;

    use super::*;

    #[test]
    fn a_read_failure_is_the_clients_and_keeps_its_kind() {
        for (failure, code) in [
            (
                ReadFailure::TooLarge { limit: 1 },
                RefusalCode::RequestTooLarge,
            ),
            (ReadFailure::TimedOut, RefusalCode::RequestTimedOut),
            (
                ReadFailure::Os(SysError::unsupported("x")),
                RefusalCode::RequestUnreadable,
            ),
        ] {
            let refusal = Refusal::from(&failure);
            assert_eq!(refusal.code, code);
            assert_eq!(refusal.fault, Fault::Client);
            assert_eq!(refusal.detail, failure.to_string());
        }
    }

    #[test]
    fn a_spool_or_policy_failure_is_the_brokers() {
        let spool = Refusal::from(&SpoolError::Exists {
            name: "x".to_owned(),
        });
        assert_eq!(spool.code, RefusalCode::SpoolUnusable);
        assert_eq!(spool.fault, Fault::Broker);
        let policy = Refusal::from(&PolicyError::ConfigNotUtf8 {
            file: "f".to_owned(),
        });
        assert_eq!(policy.code, RefusalCode::PolicyUnloadable);
        assert_eq!(policy.fault, Fault::Broker);
    }

    #[test]
    fn each_mint_failure_has_its_own_code_and_a_full_spool_is_not_the_brokers_fault() {
        for (failure, code, fault) in [
            (
                MintError::NoAction,
                RefusalCode::BrokerUnusable,
                Fault::Broker,
            ),
            (
                MintError::Spool(SpoolError::Exists {
                    name: "x".to_owned(),
                }),
                RefusalCode::SpoolUnusable,
                Fault::Broker,
            ),
            (
                MintError::Full {
                    entries: 1,
                    bytes: 1,
                },
                RefusalCode::SpoolFull,
                Fault::Client,
            ),
            (
                MintError::UidFull {
                    uid: 1000,
                    entries: 8,
                },
                RefusalCode::SpoolFull,
                Fault::Client,
            ),
            (
                MintError::Collision {
                    nonce: "n".to_owned(),
                },
                RefusalCode::NonceCollision,
                Fault::Broker,
            ),
        ] {
            let refusal = Refusal::from(&failure);
            assert_eq!(refusal.code, code);
            assert_eq!(refusal.fault, fault, "{failure:?}");
            assert_eq!(refusal.detail, failure.to_string());
        }
    }

    #[test]
    fn an_identification_failure_keeps_its_fault() {
        let gone = Refusal::from(&IdentifyError::Exited);
        assert_eq!(gone.code, RefusalCode::PeerUnidentified);
        assert_eq!(gone.fault, Fault::Client);
        let host = Refusal::from(&IdentifyError::PeerNotVisible);
        assert_eq!(host.fault, Fault::Broker);
        let request = Refusal::from(&RequestError::NotUtf8 { offset: 3 });
        assert_eq!(request.code, RefusalCode::RequestNotUtf8);
        assert_eq!(request.fault, Fault::Client);
    }
}
