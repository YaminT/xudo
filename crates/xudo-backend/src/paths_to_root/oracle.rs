//! What `sudo -l -U <user>` says, read as the last word on passwords.
//!
//! The hand reader in `config` is a hint: it has been wrong about sudoers
//! lexing four times. sudo's own listing is already normalized, so the one
//! thing looked for here is the tags it prints.

/// What the backend itself said about one user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// It lists something without a password; these are the lines that say so.
    Passwordless(String),
    /// It lists nothing without a password.
    Nothing,
    /// It could not be asked, or its reply was not understood. Never "nothing".
    Unavailable(String),
}

/// Why a non-root run cannot ask.
pub const ROOT_NEEDED: &str = "run `sudo xudo doctor` to ask sudo itself";

/// Reads sudo's reply, both streams joined. The exit status is not used: the
/// refusal exits non-zero.
pub fn read_listing(reply: &str) -> Answer {
    if reply.contains("may run the following commands") {
        let lines: Vec<&str> = reply
            .lines()
            .filter(|line| {
                line.split_whitespace().any(|word| {
                    word == "NOPASSWD:" || word.trim_end_matches(',') == "!authenticate"
                })
            })
            .map(str::trim)
            .collect();
        if lines.is_empty() {
            Answer::Nothing
        } else {
            Answer::Passwordless(lines.join("\n"))
        }
    } else if reply.contains("is not allowed to run sudo") {
        Answer::Nothing
    } else {
        Answer::Unavailable("its reply was neither a listing nor a refusal".to_owned())
    }
}
