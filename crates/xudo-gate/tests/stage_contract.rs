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

fn position(stage: Stage) -> usize {
    match stage {
        Stage::Descriptors => 0,
        Stage::Streams => 1,
        Stage::Privileges => 2,
        Stage::Invocation => 3,
        Stage::Procfs => 4,
        Stage::Lineage => 5,
        Stage::Rules => 6,
        Stage::Clock => 7,
        Stage::Spool => 8,
        Stage::Program => 9,
        Stage::Audit => 10,
        Stage::Exec => 11,
        Stage::Config => 12,
    }
}

const ALL_STAGES: [Stage; 13] = [
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

#[test]
fn every_gate_stage_audit_code_is_pinned() {
    let mut snapshot = String::new();
    for stage in ALL_STAGES {
        lists_every_stage(stage);
        let _ = writeln!(snapshot, "{stage:?} {}", stage.code());
    }
    assert_eq!(ALL_STAGES.len(), 13);
    let mut positions = [false; 13];
    for stage in ALL_STAGES {
        let index = position(stage);
        assert_eq!(ALL_STAGES.get(index).copied(), Some(stage));
        assert_eq!(positions.get(index).copied(), Some(false));
        assert!(
            positions
                .get_mut(index)
                .map(|position| *position = true)
                .is_some()
        );
    }
    assert!(positions.into_iter().all(|present| present));
    insta::assert_snapshot!("gate_stage_audit_codes", snapshot);
}
