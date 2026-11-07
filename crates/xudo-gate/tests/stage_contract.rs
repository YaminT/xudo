//! Pins the audit codes emitted when a gate stage fails.

use std::fmt::Write as _;

use xudo_gate::Stage;

fn lists_every_stage(stage: Stage) {
    match stage {
        Stage::Descriptors
        | Stage::Streams
        | Stage::Privileges
        | Stage::Invocation
        | Stage::Procfs
        | Stage::Lineage
        | Stage::Rules
        | Stage::Clock
        | Stage::Spool
        | Stage::Program
        | Stage::Audit
        | Stage::Exec
        | Stage::Config => {}
    }
}

#[test]
fn every_gate_stage_audit_code_is_pinned() {
    let stages = [
        Stage::Descriptors,
        Stage::Streams,
        Stage::Privileges,
        Stage::Invocation,
        Stage::Procfs,
        Stage::Lineage,
        Stage::Rules,
        Stage::Clock,
        Stage::Spool,
        Stage::Program,
        Stage::Audit,
        Stage::Exec,
        Stage::Config,
    ];
    let mut snapshot = String::new();
    for stage in stages {
        lists_every_stage(stage);
        let _ = writeln!(snapshot, "{stage:?} {}", stage.code());
    }
    insta::assert_snapshot!("gate_stage_audit_codes", snapshot);
}
