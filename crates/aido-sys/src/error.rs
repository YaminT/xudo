//! Typed failures. Every variant is a reason to fail closed.

/// Something the platform could not tell us.
///
/// There is deliberately no variant meaning "probably fine": a caller that
/// cannot read what it needs must treat the request as unattested, not as
/// permitted.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SysError {
    /// A file under the source root could not be read.
    #[error("cannot read {path}: {reason}")]
    Read {
        /// The path, relative to the source root.
        path: String,
        /// The operating system's account of why.
        reason: String,
    },
    /// A file was read but did not have the shape its format requires.
    #[error("malformed {path}: {reason}")]
    Malformed {
        /// The path, relative to the source root.
        path: String,
        /// What was wrong with it.
        reason: String,
    },
    /// The operation is not available on this platform.
    ///
    /// Returned by [`crate::MacOsStub`] for every privileged operation, so a
    /// macOS developer always exercises the fail-closed branch.
    #[error("{operation} is not supported on this platform")]
    Unsupported {
        /// What was attempted.
        operation: String,
    },
    /// The ancestry chain was longer than the configured bound.
    ///
    /// A bound rather than a loop guard: a hostile process tree can be made
    /// arbitrarily deep, and walking it is work an unprivileged caller should
    /// not be able to demand.
    #[error("process ancestry exceeded the depth limit of {limit}")]
    AncestryTooDeep {
        /// The limit that was hit.
        limit: usize,
    },
    /// A system call failed.
    ///
    /// Carries the errno as well as the text, because some callers must tell
    /// "this kernel lacks the call" from "the call refused", and the number is
    /// the only stable way to do that.
    #[error("{operation} failed: {reason}")]
    Os {
        /// The system call, named as the kernel documents it.
        operation: String,
        /// The errno, when the failure carried one.
        code: Option<i32>,
        /// The operating system's account of why.
        reason: String,
    },
}

impl SysError {
    /// Builds a read failure.
    pub fn read(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Read {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Builds a malformed-content failure.
    pub fn malformed(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Malformed {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Builds an unsupported-operation failure.
    pub fn unsupported(operation: impl Into<String>) -> Self {
        Self::Unsupported {
            operation: operation.into(),
        }
    }

    /// Builds a system-call failure from the error the call returned.
    pub fn os(operation: impl Into<String>, error: &std::io::Error) -> Self {
        Self::Os {
            operation: operation.into(),
            code: error.raw_os_error(),
            reason: error.to_string(),
        }
    }

    /// The errno of a failed system call, and `None` for every other failure,
    /// including a system call that failed without one.
    pub fn os_code(&self) -> Option<i32> {
        match self {
            Self::Os { code, .. } => *code,
            _ => None,
        }
    }
}

/// Lifts the errno a rustix call returned into the crate's error, naming the
/// call, so the number survives for the callers that must tell one refusal
/// from another.
pub(crate) fn lift<T>(
    operation: &str,
    result: Result<T, rustix::io::Errno>,
) -> Result<T, SysError> {
    match result {
        Ok(value) => Ok(value),
        Err(errno) => Err(SysError::Os {
            operation: operation.to_owned(),
            code: Some(errno.raw_os_error()),
            reason: errno.to_string(),
        }),
    }
}

impl From<aido_sys_raw::OsError> for SysError {
    fn from(failed: aido_sys_raw::OsError) -> Self {
        Self::os(failed.operation, &failed.error)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    #[test]
    fn every_variant_renders_something_an_operator_can_act_on() {
        let cases = [
            SysError::read("1/stat", "No such file or directory"),
            SysError::malformed("1/stat", "no closing parenthesis in comm"),
            SysError::unsupported("resolve_exe"),
            SysError::AncestryTooDeep { limit: 64 },
            SysError::os("execveat", &std::io::Error::from_raw_os_error(13)),
        ];
        for err in &cases {
            let rendered = err.to_string();
            assert!(rendered.len() > 15, "{rendered}");
            assert!(format!("{err:?}").len() > 5);
        }
        assert!(cases[0].to_string().contains("No such file or directory"));
        assert!(cases[1].to_string().contains("malformed"));
        assert!(cases[2].to_string().contains("not supported"));
        assert!(cases[3].to_string().contains("depth limit of 64"));
        assert!(cases[4].to_string().starts_with("execveat failed: "));
    }

    #[test]
    fn only_a_system_call_failure_carries_an_errno() {
        // Callers branch on the number to tell a missing syscall from a refusal,
        // so no other variant may be mistaken for one.
        let os = SysError::os("close_range", &std::io::Error::from_raw_os_error(38));
        assert_eq!(os.os_code(), Some(38));
        let synthetic = SysError::os("x", &std::io::Error::other("no errno"));
        assert_eq!(synthetic.os_code(), None);
        assert_eq!(SysError::unsupported("x").os_code(), None);
    }

    #[test]
    fn a_raw_failure_keeps_its_call_and_its_errno() {
        let raw = aido_sys_raw::OsError {
            operation: "getsockopt(SO_PEERPIDFD)",
            error: std::io::Error::from_raw_os_error(92),
        };
        let err = SysError::from(raw);
        assert_eq!(err.os_code(), Some(92));
        assert!(
            err.to_string()
                .starts_with("getsockopt(SO_PEERPIDFD) failed: ")
        );
    }

    #[test]
    fn a_rustix_failure_is_lifted_with_its_errno_and_a_success_passes_through() {
        let err = lift("dup2", Err::<(), _>(rustix::io::Errno::BADF)).unwrap_err();
        assert_eq!(err.os_code(), Some(rustix::io::Errno::BADF.raw_os_error()));
        assert!(err.to_string().starts_with("dup2 failed: "), "{err}");
        assert_eq!(lift("dup2", Ok::<_, rustix::io::Errno>(7)), Ok(7));
    }

    #[test]
    fn errors_compare_by_value_so_tests_can_assert_on_them() {
        assert_eq!(
            SysError::read("a", "b"),
            SysError::Read {
                path: "a".into(),
                reason: "b".into()
            }
        );
        assert_ne!(SysError::read("a", "b"), SysError::malformed("a", "b"));
    }
}
