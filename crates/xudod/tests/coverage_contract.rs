//! Exercise the dependency copies of shared policy, wire and spool contracts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use xudo_sys::{FakeSpool, Spool, SpoolDir, SpoolError};
use xudo_wire::{Answer, BrokerRequest, BrokerResponse, Question, ResponseError};

fn seeded_fake() -> FakeSpool {
    FakeSpool::new().with_file(b"item".to_vec(), b"bytes".to_vec())
}

fn io_error() -> SpoolError {
    SpoolError::Io {
        operation: "test".to_owned(),
        at: "queue".to_owned(),
        code: None,
        reason: "scripted".to_owned(),
    }
}

#[test]
fn dependency_policy_wire_and_spool_paths_are_exercised() {
    let record = br#"{"reason":"maintenance","uid":0,"time":1}"#;
    assert!(xudo_gate::policy::user_frozen(1000, &|_, _| Ok(Some(
        record.to_vec()
    ))));
    assert!(xudo_gate::policy::parse_freeze_record(record).is_ok());
    let _ = xudo_gate::policy::PolicyError::from(xudo_gate::policy::SettingsError::NotUtf8 {
        file: "config.toml".to_owned(),
    });

    let owned = BrokerRequest::new(
        String::from("/usr/bin/true"),
        Vec::new(),
        String::from("unattested"),
    );
    assert!(matches!(owned.question, Question::Run { .. }));
    let _ = BrokerRequest::new(String::from("/usr/bin/true"), Vec::new(), "unattested");
    let _ = BrokerRequest::new("/usr/bin/true", Vec::new(), String::from("unattested"));
    assert!(matches!(
        BrokerRequest {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            question: Question::QueueList,
        }
        .with_cwd_bytes(b"/unused".to_vec())
        .question,
        Question::QueueList
    ));
    assert!(BrokerResponse::parse(br#"{"schema_version":2,"answer":"done"}"#).is_ok());
    assert!(matches!(
        BrokerResponse::parse(
            br#"{"schema_version":2,"answer":{"pending":{"id":"bad","expires_in_ms":1}}}"#
        ),
        Err(ResponseError::Malformed { .. })
    ));
    assert!(matches!(
        BrokerResponse::parse(br#"{"schema_version":2,"answer":{"decided":{}}}"#),
        Err(ResponseError::Malformed { .. })
    ));
    let invalid_minted = BrokerResponse::decided(
        xudo_policy::Decision::deny(
            xudo_policy::DenialCode::ArgvRejected,
            Vec::new(),
            Vec::new(),
        ),
        Some(xudo_wire::Minted {
            nonce: "invalid".to_owned(),
            expires_in_ms: 1,
            gate: "/usr/libexec/xudo/xudo-gate-auth".to_owned(),
        }),
    );
    assert!(BrokerResponse::parse(invalid_minted.to_json().as_bytes()).is_err());
    let invalid_queue = BrokerResponse {
        schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
        answer: Answer::QueueListed {
            next: None,
            entries: vec![xudo_wire::QueueListEntry {
                id: "bad".to_owned(),
                argv: vec!["/usr/bin/true".to_owned()],
                cwd: "/srv".to_owned(),
                harness: "codex".to_owned(),
                uid: 1000,
                rule_id: "xudo.test".to_owned(),
                generation: 1,
                queued_at: 1,
                expires_at: 2,
                reason: None,
                state: "pending".to_owned(),
            }],
        },
    };
    assert!(matches!(
        BrokerResponse::parse(invalid_queue.to_json().as_bytes()),
        Err(ResponseError::Malformed { .. })
    ));
}

#[test]
fn dependency_spool_paths_are_exercised() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-tmp")
        .join(format!("q1b-contract-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(SpoolDir::open_test_directory(&path.join("missing")).is_err());
    let spool = SpoolDir::open_test_directory(&path).unwrap();
    spool.lock().unwrap();
    spool.publish("pending", b"before").unwrap();
    assert!(spool.publish("pending", b"collision").is_err());
    assert_eq!(spool.names().unwrap(), vec![b"pending".to_vec()]);
    assert_eq!(spool.names_up_to(1).unwrap(), vec![b"pending".to_vec()]);
    assert_eq!(spool.read(b"pending", 16).unwrap(), b"before");
    spool.replace(b"pending", b"before", b"after").unwrap();
    assert_eq!(spool.read(b"pending", 16).unwrap(), b"after");
    spool.consume(b"pending").unwrap();
    spool.remove(b"absent").unwrap();
    assert!(spool.consume(b"absent").is_err());
    std::fs::create_dir(path.join("not-a-file")).unwrap();
    assert!(spool.consume(b"not-a-file").is_err());
    spool.unlock();
    assert!(SpoolDir::open_beneath(&path.join("missing")).is_err());
    let _ = std::fs::remove_dir_all(&path);

    let fake = FakeSpool::new().with_file(b"item".to_vec(), b"bytes".to_vec());
    let _ = FakeSpool::new().with_file("item", b"bytes".as_slice());
    let _ = FakeSpool::new().failing_read("item");
    assert_eq!(fake.files().get(b"item".as_slice()).unwrap(), b"bytes");
    fake.lock().unwrap();
    assert_eq!(fake.names().unwrap(), vec![b"item".to_vec()]);
    assert_eq!(fake.names_up_to(1).unwrap(), vec![b"item".to_vec()]);
    fake.read(b"item", 8).unwrap();
    fake.publish("second", b"bytes").unwrap();
    fake.replace(b"second", b"bytes", b"changed").unwrap();
    fake.consume(b"second").unwrap();
    fake.remove(b"item").unwrap();
    fake.unlock();
    assert!(!fake.calls().is_empty());

    assert!(seeded_fake().failing_lock(io_error()).lock().is_err());
    assert!(seeded_fake().failing_names(io_error()).names().is_err());
    assert!(
        seeded_fake()
            .failing_names_on_call(1, io_error())
            .names_up_to(1)
            .is_err()
    );
    assert!(
        seeded_fake()
            .failing_read(b"item".to_vec())
            .read(b"item", 8)
            .is_err()
    );
    assert!(
        seeded_fake()
            .failing_remove(io_error())
            .remove(b"item")
            .is_err()
    );
    assert!(
        seeded_fake()
            .failing_consume(io_error())
            .consume(b"item")
            .is_err()
    );
    assert!(
        seeded_fake()
            .failing_publish(io_error())
            .publish("new", b"x")
            .is_err()
    );
    assert!(
        seeded_fake()
            .failing_replace(io_error())
            .replace(b"item", b"bytes", b"x")
            .is_err()
    );
    assert!(
        seeded_fake()
            .failing_replace_after_exchange(io_error())
            .replace(b"item", b"bytes", b"x")
            .is_err()
    );
    let after_replace = seeded_fake().failing_read_after_replace();
    after_replace
        .replace(b"item", b"bytes", b"changed")
        .unwrap();
    assert!(after_replace.read(b"item", 16).is_err());
}
