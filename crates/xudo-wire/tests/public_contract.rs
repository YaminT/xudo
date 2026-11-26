//! Exercise wire validation through the public dependency API.

use xudo_wire::{
    Answer, BrokerRequest, BrokerResponse, Question, QueueListEntry, RequestError, ResponseError,
    WIRE_SCHEMA_VERSION,
};

#[test]
fn public_requests_and_responses_keep_their_bounds() {
    let request = BrokerRequest::new(
        String::from("/usr/bin/true"),
        Vec::new(),
        String::from("unattested"),
    )
    .with_cwd_bytes(b"/srv".to_vec());
    assert!(BrokerRequest::parse(request.to_json().as_bytes()).is_ok());
    let queue_list = BrokerRequest {
        schema_version: WIRE_SCHEMA_VERSION,
        question: Question::QueueList,
    }
    .with_cwd_bytes(b"/ignored".to_vec());
    assert!(matches!(queue_list.question, Question::QueueList));

    let bad_cwd = BrokerRequest {
        schema_version: WIRE_SCHEMA_VERSION,
        question: Question::Run {
            program: "/usr/bin/true".to_owned(),
            argv: vec!["/usr/bin/true".to_owned()],
            cwd: b"relative".to_vec(),
            claimed_classification: "unattested".to_owned(),
        },
    };
    assert!(matches!(
        BrokerRequest::parse(bad_cwd.to_json().as_bytes()),
        Err(RequestError::Malformed { .. })
    ));
}

fn entry(id: String, reason: Option<String>) -> QueueListEntry {
    QueueListEntry {
        id,
        argv: vec!["/usr/bin/true".to_owned()],
        cwd: "/srv".to_owned(),
        harness: "codex".to_owned(),
        uid: 1000,
        rule_id: "xudo.test".to_owned(),
        generation: 1,
        queued_at: 10,
        expires_at: 20,
        reason,
        state: "pending".to_owned(),
    }
}

#[test]
fn public_queue_list_responses_keep_their_bounds() {
    let response = BrokerResponse {
        schema_version: WIRE_SCHEMA_VERSION,
        answer: Answer::QueueListed {
            entries: vec![entry("ab".repeat(32), None)],
            next: None,
        },
    };
    assert!(BrokerResponse::parse(response.to_json().as_bytes()).is_ok());
    let with_reason = BrokerResponse {
        schema_version: WIRE_SCHEMA_VERSION,
        answer: Answer::QueueListed {
            entries: vec![entry("cd".repeat(32), Some("please review".to_owned()))],
            next: None,
        },
    };
    assert!(BrokerResponse::parse(with_reason.to_json().as_bytes()).is_ok());
    let too_many = BrokerResponse {
        schema_version: WIRE_SCHEMA_VERSION,
        answer: Answer::QueueListed {
            entries: (0..=xudo_wire::MAX_QUEUE_LIST)
                .map(|index| entry(format!("{:064x}", index + 1), None))
                .collect(),
            next: None,
        },
    };
    assert!(matches!(
        BrokerResponse::parse(too_many.to_json().as_bytes()),
        Err(ResponseError::Malformed { .. })
    ));
    assert!(matches!(
        BrokerResponse::parse(br#"{"schema_version":2,"answer":{"decided":{}}}"#),
        Err(ResponseError::Malformed { .. })
    ));
    assert!(matches!(
        BrokerResponse::parse(&[0xff]),
        Err(ResponseError::NotUtf8 { .. })
    ));
    assert!(matches!(
        BrokerResponse::parse(
            br#"{"schema_version":2,"answer":{"pending":{"id":"bad","expires_in_ms":1}}}"#
        ),
        Err(ResponseError::Malformed { .. })
    ));
}

/// Which gate runs is the broker's to decide: a request that tries to name a
/// gate, a `via`, or a grant, anywhere, does not parse.
#[test]
fn a_request_naming_a_gate_or_a_via_is_rejected() {
    for json in [
        r#"{"schema_version":2,"question":"watch","via":"harness"}"#,
        r#"{"schema_version":2,"question":"watch","gate":"/usr/libexec/xudo/xudo-gate-nopass"}"#,
        r#"{"schema_version":2,"question":{"run":{"program":"/usr/bin/systemctl","argv":[],"claimed_classification":"x","via":"harness"}}}"#,
        r#"{"schema_version":2,"question":{"run":{"program":"/usr/bin/systemctl","argv":[],"claimed_classification":"x","harness_grant":"a.b"}}}"#,
    ] {
        assert!(
            xudo_wire::BrokerRequest::parse(json.as_bytes()).is_err(),
            "{json}"
        );
    }
}
