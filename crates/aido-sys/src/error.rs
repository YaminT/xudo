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
