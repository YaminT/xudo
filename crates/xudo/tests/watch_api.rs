//! Exercise the public watcher API through the library build used by clients.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods
)]

use std::collections::VecDeque;
use std::io::{self, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::thread;

use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{self, LocalModes};
use xudo::watch::{
    Answer, BrokerRequest, BrokerResponse, ExitCode, Question, RefusalCode, RuleSet, StdTerminal,
    Terminal, WIRE_SCHEMA_VERSION, WatchPrompt, ask_live, pending, watch_live, watch_with,
};

fn rules() -> RuleSet {
    RuleSet::from_toml(
        "20-packages.toml",
        r#"[[action]]
id = "xudo.pkg.remove"
tier = "pkg-remove"
confirm = "always"
exe = "/usr/bin/apt-get"
args = [{ name = "verb", matcher = { literal = "remove" } }]
"#,
    )
    .unwrap()
}

fn prompt() -> WatchPrompt {
    WatchPrompt {
        id: "ab".repeat(32),
        action: "xudo.pkg.remove".to_owned(),
        program: "/usr/bin/apt-get".to_owned(),
        argv: vec!["remove".to_owned(), "nginx".to_owned()],
        classification: "unattested".to_owned(),
        evidence: "watch approval is pending; the password remains required".to_owned(),
        expires_in_ms: 87_000,
    }
}

struct FakeTerminal(VecDeque<Option<String>>);

impl Terminal for FakeTerminal {
    fn is_terminal(&self) -> bool {
        true
    }

    fn begin(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn flush_typeahead(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn read_line_tick(&mut self) -> io::Result<Option<String>> {
        Ok(self.0.pop_front().flatten())
    }
}

#[test]
fn public_watch_renders_and_answers_the_prompt() {
    let mut terminal = FakeTerminal(VecDeque::from([Some("n\n".to_owned())]));
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut watch_count = 0;
    let code = watch_with(
        Path::new("socket"),
        &rules(),
        &mut terminal,
        &mut out,
        &mut err,
        &mut |_, request| match &request.question {
            Question::Watch => {
                watch_count += 1;
                if watch_count == 1 {
                    Ok(BrokerResponse {
                        schema_version: WIRE_SCHEMA_VERSION,
                        answer: Answer::Watching {
                            prompts: vec![prompt()],
                            omitted: 0,
                        },
                    })
                } else {
                    Ok(BrokerResponse {
                        schema_version: WIRE_SCHEMA_VERSION,
                        answer: Answer::Refused {
                            code: RefusalCode::ChannelUntrusted,
                            remediation: "stop".to_owned(),
                            detail: Some("test finished".to_owned()),
                        },
                    })
                }
            }
            Question::Answer { approve, token, .. } => {
                assert!(!approve);
                assert_eq!(token, "n");
                Ok(BrokerResponse {
                    schema_version: WIRE_SCHEMA_VERSION,
                    answer: Answer::Done,
                })
            }
            _ => panic!("unexpected request"),
        },
    );
    assert_eq!(code, ExitCode::Unusable);
    insta::assert_snapshot!(String::from_utf8(out).unwrap(), @r###"
    PENDING abababababababababababababababababababababababababababababababab
      command         /usr/bin/apt-get remove nginx
      action          xudo.pkg.remove at 20-packages.toml:2
      classification  claimed (unverified): unattested
      broker evidence  watch approval is pending; the password remains required
      time left       87000 ms
      answer          type 'remove' to approve, n to deny
    xudo: answer recorded
    "###);
    insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
    xudo: broker refused the request (ChannelUntrusted)
    xudo: test finished
    "###);
}

#[test]
fn public_pending_lists_and_fails_closed() {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = pending(
        Path::new("socket"),
        &rules(),
        &mut out,
        &mut err,
        &mut |_, request| {
            assert!(matches!(&request.question, Question::Pending));
            Ok(BrokerResponse {
                schema_version: WIRE_SCHEMA_VERSION,
                answer: Answer::Watching {
                    prompts: vec![prompt()],
                    omitted: 0,
                },
            })
        },
    );
    assert_eq!(code, ExitCode::Delegated);
    assert!(err.is_empty());
    insta::assert_snapshot!(String::from_utf8(out).unwrap(), @r###"
    PENDING abababababababababababababababababababababababababababababababab
      command         /usr/bin/apt-get remove nginx
      action          xudo.pkg.remove at 20-packages.toml:2
      classification  claimed (unverified): unattested
      broker evidence  watch approval is pending; the password remains required
      time left       87000 ms
      answer          approve in xudo watch by typing 'remove'
    "###);

    let mut out = Vec::new();
    let mut err = Vec::new();
    assert_eq!(
        pending(
            Path::new("socket"),
            &rules(),
            &mut out,
            &mut err,
            &mut |_, _| Err("public pending broker failure".to_owned()),
        ),
        ExitCode::Unusable
    );
    insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
    xudo: broker unavailable: public pending broker failure
    "###);

    let mut out = Vec::new();
    let mut err = Vec::new();
    assert_eq!(
        pending(
            Path::new("socket"),
            &rules(),
            &mut out,
            &mut err,
            &mut |_, _| Ok(BrokerResponse {
                schema_version: WIRE_SCHEMA_VERSION,
                answer: Answer::Refused {
                    code: RefusalCode::RequestUnknown,
                    remediation: "retry".to_owned(),
                    detail: None,
                },
            }),
        ),
        ExitCode::Unusable
    );
    insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
    xudo: broker refused the request (RequestUnknown)
    "###);
}

#[test]
fn live_entry_points_and_terminal_methods_fail_closed_without_a_tty() {
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert_eq!(
        watch_live(
            Path::new("unused"),
            &rules(),
            &mut out,
            &mut err,
            &mut ask_live
        ),
        ExitCode::Unusable
    );
    assert!(out.is_empty());
    assert!(
        String::from_utf8(err)
            .unwrap()
            .contains("requires a terminal")
    );

    let mut terminal = StdTerminal::default();
    assert!(!terminal.is_terminal());
    terminal.begin().unwrap();
    assert!(terminal.flush_typeahead().is_err());
    let _ = terminal.read_line_tick();
}

#[test]
fn public_std_terminal_watches_on_an_injected_real_pty() {
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    grantpt(&master).unwrap();
    unlockpt(&master).unwrap();
    let name = ptsname(&master, Vec::new()).unwrap();
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(name.to_str().unwrap())
        .unwrap();
    let settings_fd = slave.try_clone().unwrap();
    let mut terminal = StdTerminal::from_fd(slave.into());
    assert!(!terminal.is_terminal());
    let keep_master = master.try_clone().unwrap();
    let writer = thread::spawn(move || {
        thread::sleep(std::time::Duration::from_millis(100));
        rustix::io::write(&master, b"n\n").unwrap();
    });
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut watch_count = 0;
    let result = watch_with(
        Path::new("socket"),
        &rules(),
        &mut terminal,
        &mut out,
        &mut err,
        &mut |_, request| match &request.question {
            Question::Watch => {
                watch_count += 1;
                if watch_count == 1 {
                    Ok(BrokerResponse {
                        schema_version: WIRE_SCHEMA_VERSION,
                        answer: Answer::Watching {
                            prompts: vec![prompt()],
                            omitted: 0,
                        },
                    })
                } else {
                    Ok(BrokerResponse {
                        schema_version: WIRE_SCHEMA_VERSION,
                        answer: Answer::Refused {
                            code: RefusalCode::ChannelUntrusted,
                            remediation: "stop".to_owned(),
                            detail: Some("pty test finished".to_owned()),
                        },
                    })
                }
            }
            Question::Answer { approve, token, .. } => {
                assert!(!approve);
                assert_eq!(token, "n");
                Ok(BrokerResponse {
                    schema_version: WIRE_SCHEMA_VERSION,
                    answer: Answer::Done,
                })
            }
            _ => panic!("unexpected request"),
        },
    );
    assert_eq!(result, ExitCode::Unusable);
    writer.join().unwrap();
    drop(terminal);
    assert!(
        termios::tcgetattr(&settings_fd)
            .unwrap()
            .local_modes
            .contains(LocalModes::ISIG)
    );
    drop(keep_master);
    assert!(out.is_empty());
    insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
    xudo: watch requires a terminal on stdin
    "###);
}

#[test]
fn live_broker_request_uses_the_public_socket_exchange() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("broker.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut stream, &mut bytes).unwrap();
        let request = BrokerRequest::parse(&bytes).unwrap();
        assert!(matches!(&request.question, Question::Pending));
        stream
            .write_all(
                BrokerResponse {
                    schema_version: WIRE_SCHEMA_VERSION,
                    answer: Answer::Watching {
                        prompts: Vec::new(),
                        omitted: 0,
                    },
                }
                .to_json()
                .as_bytes(),
            )
            .unwrap();
    });
    let response = ask_live(
        &socket,
        &BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: Question::Pending,
        },
    )
    .unwrap();
    assert!(matches!(response.answer, Answer::Watching { prompts, .. } if prompts.is_empty()));
    server.join().unwrap();

    let missing = dir.path().join("missing.sock");
    assert!(
        ask_live(
            &missing,
            &BrokerRequest {
                schema_version: WIRE_SCHEMA_VERSION,
                question: Question::Pending,
            }
        )
        .is_err()
    );

    let bad_socket = dir.path().join("bad.sock");
    let bad_listener = UnixListener::bind(&bad_socket).unwrap();
    let bad_server = thread::spawn(move || {
        let (mut stream, _) = bad_listener.accept().unwrap();
        let mut request = Vec::new();
        std::io::Read::read_to_end(&mut stream, &mut request).unwrap();
        stream.write_all(b"not json").unwrap();
    });
    assert!(
        ask_live(
            &bad_socket,
            &BrokerRequest {
                schema_version: WIRE_SCHEMA_VERSION,
                question: Question::Pending,
            }
        )
        .is_err()
    );
    bad_server.join().unwrap();
}
