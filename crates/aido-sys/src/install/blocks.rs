//! Sentinel-delimited blocks in a file aido shares with the operator.
//!
//! `/etc/doas.conf` is the operator's file. aido owns exactly the lines between
//! its two sentinels and nothing else, so everything here works on whole lines,
//! byte for byte, and refuses any file it cannot read unambiguously rather than
//! guessing which lines are its own. A guess that deletes an operator's `permit`
//! line is a privilege change nobody asked for.
//!
//! Pure: bytes in, bytes out. The lock, the temporary copy, the validator, and
//! the rename around it are in [`super::host`].

/// Why a block could not be inserted or removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BlockError {
    /// The block aido was asked to write is not `begin`, its lines, `end`.
    #[error(
        "the block to write must open with the begin sentinel and close with the end sentinel, \
         each exactly once, on lines of their own"
    )]
    BadBlock,
    /// The file's own sentinels do not pair up: aido cannot tell which lines are its own.
    #[error(
        "the file carries aido's sentinels in a shape aido did not write (an unpaired, repeated, \
         or reversed marker); refusing to guess which lines are its own"
    )]
    Ambiguous,
}

/// Where aido's block sits in a file, as byte offsets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Span {
    /// The first byte of the begin line.
    start: usize,
    /// One past the last byte of the end line, terminator included.
    end: usize,
}

/// Every line of `text`, with its terminator, and where it starts.
fn lines(text: &[u8]) -> impl Iterator<Item = (usize, &[u8])> {
    let mut offset = 0usize;
    text.split_inclusive(|byte| *byte == b'\n')
        .map(move |line| {
            let at = offset;
            offset = offset.saturating_add(line.len());
            (at, line)
        })
}

/// A line without its terminator.
fn bare(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\n").unwrap_or(line)
}

/// Finds the one block `begin`..`end` in `text`: `None` when there is no
/// sentinel at all, an error for anything that is not exactly one well-ordered
/// pair.
fn locate(text: &[u8], begin: &[u8], end: &[u8]) -> Result<Option<Span>, BlockError> {
    let mut opened: Option<usize> = None;
    let mut span: Option<Span> = None;
    for (at, line) in lines(text) {
        let content = bare(line);
        if content == begin {
            if opened.is_some() || span.is_some() {
                return Err(BlockError::Ambiguous);
            }
            opened = Some(at);
        } else if content == end {
            let Some(start) = opened.take() else {
                return Err(BlockError::Ambiguous);
            };
            span = Some(Span {
                start,
                end: at.saturating_add(line.len()),
            });
        }
    }
    if opened.is_some() {
        return Err(BlockError::Ambiguous);
    }
    Ok(span)
}

/// Whether `block` is `begin`, any lines that are not sentinels, then `end`.
fn is_well_formed(block: &[u8], begin: &[u8], end: &[u8]) -> bool {
    let all: Vec<&[u8]> = lines(block).map(|(_, line)| bare(line)).collect();
    let sentinels = all
        .iter()
        .filter(|line| **line == begin || **line == end)
        .count();
    all.first() == Some(&begin) && all.last() == Some(&end) && all.len() >= 2 && sentinels == 2
}

/// `text` with aido's block set to `block`: appended when there is none,
/// replacing the previous one when there is.
///
/// # Errors
///
/// [`BlockError::BadBlock`] for a block that does not carry the sentinels
/// properly; [`BlockError::Ambiguous`] for a file whose sentinels do not pair.
pub(super) fn insert(
    text: &[u8],
    block: &[u8],
    begin: &[u8],
    end: &[u8],
) -> Result<Vec<u8>, BlockError> {
    if !is_well_formed(block, begin, end) {
        return Err(BlockError::BadBlock);
    }
    let mut owned = block.to_vec();
    if !owned.ends_with(b"\n") {
        owned.push(b'\n');
    }
    let mut out = Vec::with_capacity(text.len().saturating_add(owned.len()).saturating_add(1));
    if let Some(span) = locate(text, begin, end)? {
        out.extend_from_slice(text.get(..span.start).unwrap_or_default());
        out.extend_from_slice(&owned);
        out.extend_from_slice(text.get(span.end..).unwrap_or_default());
    } else {
        out.extend_from_slice(text);
        if !text.is_empty() && !text.ends_with(b"\n") {
            out.push(b'\n');
        }
        out.extend_from_slice(&owned);
    }
    Ok(out)
}

/// `text` without aido's block, or `None` when it carries none.
///
/// Exactly the lines from the begin sentinel to the end sentinel are removed;
/// every other byte, the operator's included, is returned as it was.
///
/// # Errors
///
/// [`BlockError::Ambiguous`] for a file whose sentinels do not pair.
pub(super) fn remove(text: &[u8], begin: &[u8], end: &[u8]) -> Result<Option<Vec<u8>>, BlockError> {
    Ok(locate(text, begin, end)?.map(|span| {
        let mut out = Vec::with_capacity(text.len());
        out.extend_from_slice(text.get(..span.start).unwrap_or_default());
        out.extend_from_slice(text.get(span.end..).unwrap_or_default());
        out
    }))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use proptest::prelude::*;

    use super::*;

    const B: &[u8] = b"### aido:begin";
    const E: &[u8] = b"### aido:end";
    const BLOCK: &[u8] = b"### aido:begin\npermit :aido as root cmd /x args\n### aido:end\n";

    /// Whether no line of `text` is one of aido's sentinels.
    fn carries_no_sentinel(text: &[u8]) -> bool {
        text.split(|b| *b == b'\n').all(|l| l != B && l != E)
    }

    #[test]
    fn a_block_is_appended_after_the_operators_lines() {
        let out = insert(b"permit :wheel\n", BLOCK, B, E).unwrap();
        assert_eq!(out, [b"permit :wheel\n".as_slice(), BLOCK].concat());
    }

    #[test]
    fn a_block_goes_into_an_empty_file_with_nothing_before_it() {
        assert_eq!(insert(b"", BLOCK, B, E).unwrap(), BLOCK);
    }

    #[test]
    fn a_file_with_no_final_newline_is_given_one_rather_than_gluing_a_line() {
        // `permit :wheel### aido:begin` would be a different rule, and the
        // sentinel would no longer be on a line of its own.
        let out = insert(b"permit :wheel", BLOCK, B, E).unwrap();
        assert_eq!(out, [b"permit :wheel\n".as_slice(), BLOCK].concat());
    }

    #[test]
    fn a_block_missing_its_final_newline_is_terminated() {
        let out = insert(b"", b"### aido:begin\nx\n### aido:end", B, E).unwrap();
        assert!(out.ends_with(b"### aido:end\n"));
    }

    #[test]
    fn reinstalling_replaces_the_previous_block_and_only_it() {
        let old = b"# mine\n### aido:begin\nold rule\n### aido:end\n# also mine\n";
        let out = insert(old, BLOCK, B, E).unwrap();
        assert_eq!(
            out,
            [b"# mine\n".as_slice(), BLOCK, b"# also mine\n".as_slice()].concat()
        );
    }

    #[test]
    fn removal_deletes_exactly_the_block() {
        let text = b"# mine\n### aido:begin\npermit :aido\n### aido:end\n# also mine\n";
        let out = remove(text, B, E).unwrap().unwrap();
        assert_eq!(out, b"# mine\n# also mine\n");
    }

    #[test]
    fn removal_from_a_file_without_a_block_changes_nothing() {
        assert_eq!(remove(b"permit :wheel\n", B, E).unwrap(), None);
        assert_eq!(remove(b"", B, E).unwrap(), None);
    }

    #[test]
    fn removal_keeps_a_neighbouring_line_that_merely_contains_a_sentinel() {
        // Whole-line equality, not substring: an operator's comment quoting the
        // marker is not aido's block.
        let text = b"# see ### aido:begin above\nx ### aido:end\n";
        assert_eq!(remove(text, B, E).unwrap(), None);
    }

    #[test]
    fn a_crlf_line_is_not_a_sentinel() {
        // Byte-exact. A marker with a stray carriage return is not the marker
        // aido wrote, so it is not aido's to delete.
        let text = b"### aido:begin\r\nx\r\n### aido:end\r\n";
        assert_eq!(remove(text, B, E).unwrap(), None);
    }

    #[test]
    fn an_unpaired_reversed_or_repeated_sentinel_is_refused_not_guessed_at() {
        for text in [
            b"### aido:begin\nx\n".as_slice(),
            b"x\n### aido:end\n",
            b"### aido:end\n### aido:begin\n",
            b"### aido:begin\n### aido:begin\n### aido:end\n",
            b"### aido:begin\n### aido:end\n### aido:begin\n### aido:end\n",
            b"### aido:begin\n### aido:end\n### aido:end\n",
            b"### aido:begin\n### aido:end\n### aido:begin\n",
        ] {
            assert_eq!(remove(text, B, E), Err(BlockError::Ambiguous), "{text:?}");
            assert_eq!(
                insert(text, BLOCK, B, E),
                Err(BlockError::Ambiguous),
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_block_that_is_not_a_block_is_refused() {
        for block in [
            b"".as_slice(),
            b"### aido:begin\n",
            b"### aido:begin\n### aido:end\n### aido:end\n",
            b"x\n### aido:begin\ny\n### aido:end\n",
            b"### aido:begin\ny\n### aido:end\nz\n",
            b"### aido:end\ny\n### aido:begin\n",
            b"### aido:begin\n### aido:begin\n### aido:end\n",
        ] {
            assert_eq!(
                insert(b"", block, B, E),
                Err(BlockError::BadBlock),
                "{block:?}"
            );
        }
        // An empty body is a block: two sentinels and nothing between.
        assert!(insert(b"", b"### aido:begin\n### aido:end\n", B, E).is_ok());
    }

    #[test]
    fn the_refusals_say_what_was_wrong() {
        assert!(BlockError::BadBlock.to_string().contains("sentinel"));
        assert!(BlockError::Ambiguous.to_string().contains("refusing"));
    }

    proptest! {
        /// Removal deletes exactly aido's block: whatever the operator's file
        /// holds, installing and then removing returns it byte for byte.
        #[test]
        fn removal_undoes_insertion_exactly(
            mine in proptest::collection::vec(any::<u8>(), 0..200)
        ) {
            let mut text = mine;
            prop_assume!(carries_no_sentinel(&text));
            if !text.is_empty() && !text.ends_with(b"\n") {
                text.push(b'\n');
            }
            let with = insert(&text, BLOCK, B, E).unwrap();
            prop_assert_eq!(remove(&with, B, E).unwrap().unwrap(), text);
        }

        /// Inserting twice is inserting once.
        #[test]
        fn insertion_is_idempotent(mine in proptest::collection::vec(any::<u8>(), 0..200)) {
            prop_assume!(carries_no_sentinel(&mine));
            let once = insert(&mine, BLOCK, B, E).unwrap();
            prop_assert_eq!(insert(&once, BLOCK, B, E).unwrap(), once);
        }

        /// No operator byte is ever lost to insertion.
        #[test]
        fn the_operators_bytes_survive_insertion(
            mine in proptest::collection::vec(any::<u8>(), 0..200)
        ) {
            prop_assume!(carries_no_sentinel(&mine));
            let out = insert(&mine, BLOCK, B, E).unwrap();
            prop_assert!(out.starts_with(&mine));
        }
    }
}
