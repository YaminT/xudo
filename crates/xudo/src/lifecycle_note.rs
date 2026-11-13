//! The note printed when a loaded ruleset has no service-lifecycle action.
//!
//! The shipped rules deliberately omit `xudo.svc.lifecycle`. The operator
//! copies the packaged example and lists units. Check and doctor say so.
//! The note is not a lint error and does not change the exit status.

use xudo_policy::RuleSet;

/// The action id the example file defines and the shipped rules omit.
pub(crate) const ACTION_ID: &str = "xudo.svc.lifecycle";

/// Printed on stdout, exactly, when [`missing`] is true.
pub(crate) const TEXT: &str = concat!(
    "no service lifecycle rule: copy ",
    "/usr/share/doc/xudo/examples/20-services-lifecycle.toml ",
    "to /etc/xudo/rules.d/ and list your units"
);

/// Whether `rules` has no action whose id is [`ACTION_ID`].
pub(crate) fn missing(rules: &RuleSet) -> bool {
    !rules
        .actions()
        .iter()
        .any(|action| action.id.as_str() == ACTION_ID)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::{ACTION_ID, TEXT, missing};
    use xudo_policy::RuleSet;

    fn rules(id: &str) -> RuleSet {
        let source = format!(
            "[[action]]\nid = \"{id}\"\ntier = \"svc-control\"\nexe = \"/usr/bin/true\"\nargs = []\n"
        );
        RuleSet::from_toml("note.toml", &source).unwrap()
    }

    #[test]
    fn missing_is_the_absence_of_the_lifecycle_action() {
        assert!(missing(&rules("xudo.svc.reset-failed")));
        assert!(!missing(&rules(ACTION_ID)));
        assert!(TEXT.starts_with("no service lifecycle rule: "));
        assert!(TEXT.contains("/usr/share/doc/xudo/examples/20-services-lifecycle.toml"));
    }
}
