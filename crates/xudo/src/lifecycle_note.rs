//! The note printed when a loaded ruleset has no service-lifecycle action.
//!
//! The shipped rules deliberately omit a `systemctl` lifecycle verb. The
//! operator copies the packaged example and lists units. Check and doctor
//! say so. The note is not a lint error and does not change the exit status.
//! An action id is not enough: a lifecycle verb under any id is the rule.

use xudo_policy::RuleSet;

/// Printed on stdout, exactly, when [`missing`] is true.
pub(crate) const TEXT: &str = concat!(
    "no service lifecycle rule: copy ",
    "/usr/share/xudo/examples/20-services-lifecycle.toml ",
    "to /etc/xudo/rules.d/ and list your units"
);

/// Whether `rules` has no `systemctl` action with a lifecycle or power verb.
///
/// The action id is not consulted. An operator who wrote that verb under
/// another id already has a lifecycle rule, and this note would nag them
/// to copy the example.
pub(crate) fn missing(rules: &RuleSet) -> bool {
    !rules.has_systemctl_lifecycle_or_power()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::{TEXT, missing};
    use xudo_policy::RuleSet;

    fn rules(id: &str) -> RuleSet {
        let source = format!(
            "[[action]]\nid = \"{id}\"\ntier = \"svc-control\"\nexe = \"/usr/bin/true\"\nargs = []\n"
        );
        RuleSet::from_toml("note.toml", &source).unwrap()
    }

    fn systemctl(id: &str, verb: &str, unit: &str) -> RuleSet {
        let unit_line = if unit.is_empty() {
            String::new()
        } else {
            format!("  {{ name = \"unit\", matcher = {unit} }},\n")
        };
        let source = format!(
            "[[action]]\nid = \"{id}\"\ntier = \"svc-control\"\n\
             exe = \"/usr/bin/systemctl\"\nargs = [\n  \
             {{ name = \"verb\", matcher = {{ literal = \"{verb}\" }} }},\n\
             {unit_line}]\n"
        );
        RuleSet::from_toml("note.toml", &source).unwrap()
    }

    #[test]
    fn missing_is_the_absence_of_a_lifecycle_verb() {
        // The id is not the signal, including the example's own id.
        assert!(missing(&rules("xudo.svc.lifecycle")));
        assert!(missing(&rules("xudo.svc.reset-failed")));
        // A lifecycle verb under another id is a lifecycle rule, open or closed.
        assert!(!missing(&systemctl(
            "xudo.svc.restart-web",
            "restart",
            "{ name = \"unit-name\" }",
        )));
        assert!(!missing(&systemctl(
            "other.lifecycle",
            "start",
            "{ one-of = [\"nginx.service\"] }",
        )));
        // daemon-reload does not start or stop a unit.
        assert!(missing(&systemctl("xudo.svc.reload", "daemon-reload", "")));
        assert!(TEXT.starts_with("no service lifecycle rule: "));
        assert!(TEXT.contains("/usr/share/xudo/examples/20-services-lifecycle.toml"));
    }
}
