//! The mountinfo parser, held to the kernel's own escaping for any bytes.
//!
//! The kernel writes the root, the mount point, the filesystem type, and the
//! source with space, tab, newline, and backslash as a backslash and three
//! octal digits, and a superblock option's value with its commas escaped too.
//! Several of those fields are chosen by whoever made the mount: the mount
//! point, and a FUSE mount's subtype and source. So these properties render
//! arbitrary bytes exactly as the kernel would and require the parse to hand
//! back exactly those bytes, and require that no input whatever can make the
//! parser panic.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use aido_sys::{MountEntry, parse_mountinfo};
use proptest::prelude::*;

/// Escaped in every field a user can name.
const PATH_SPECIAL: &[u8] = b" \t\n\\";
/// Escaped in an option, where a comma would otherwise end it.
const OPTION_SPECIAL: &[u8] = b", \t\n\\";

/// The kernel's octal escaping, as `string_escape_mem(ESCAPE_OCTAL)` does it.
fn escape(bytes: &[u8], special: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for &byte in bytes {
        if special.contains(&byte) {
            out.extend_from_slice(format!("\\{byte:03o}").as_bytes());
        } else {
            out.push(byte);
        }
    }
    out
}

/// A line as `show_mountinfo` writes it.
fn render(entry: &MountEntry) -> Vec<u8> {
    let options = |list: &[Vec<u8>]| -> Vec<u8> {
        list.iter()
            .map(|option| escape(option, OPTION_SPECIAL))
            .collect::<Vec<_>>()
            .join(&b","[..])
    };
    let mut line = format!(
        "{} {} {}:{} ",
        entry.mount_id, entry.parent_id, entry.major, entry.minor
    )
    .into_bytes();
    line.extend(escape(&entry.root, PATH_SPECIAL));
    line.push(b' ');
    line.extend(escape(&entry.mount_point, PATH_SPECIAL));
    line.push(b' ');
    line.extend(options(&entry.mount_options));
    for field in &entry.optional_fields {
        line.push(b' ');
        line.extend(field);
    }
    line.extend_from_slice(b" - ");
    line.extend(escape(&entry.fs_type, PATH_SPECIAL));
    line.push(b' ');
    line.extend(escape(&entry.source, PATH_SPECIAL));
    line.push(b' ');
    line.extend(options(&entry.super_options));
    line.push(b'\n');
    line
}

/// Any bytes at all, which is what a user may put in a name.
fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max)
}

/// A path: the kernel shows every reachable mount as one, from `/`.
fn path() -> impl Strategy<Value = Vec<u8>> {
    bytes(24).prop_map(|tail| [b"/".as_slice(), &tail].concat())
}

/// An option list: `rw` or `ro` first, as the kernel always writes it.
fn option_list() -> impl Strategy<Value = Vec<Vec<u8>>> {
    (
        prop_oneof![Just(b"rw".to_vec()), Just(b"ro".to_vec())],
        prop::collection::vec(bytes(12), 0..4),
    )
        .prop_map(|(access, rest)| [vec![access], rest].concat())
}

fn entry() -> impl Strategy<Value = MountEntry> {
    (
        (any::<u32>(), any::<u32>(), any::<u32>(), any::<u32>()),
        (path(), path(), option_list()),
        prop::collection::vec("[a-z_]{1,12}(:[0-9]{1,5})?", 0..3),
        (bytes(16), bytes(24), option_list()),
    )
        .prop_map(
            |(
                (mount_id, parent_id, major, minor),
                (root, mount_point, mount_options),
                optional,
                (fs_type, source, super_options),
            )| MountEntry {
                mount_id,
                parent_id,
                major,
                minor,
                root,
                mount_point,
                mount_options,
                optional_fields: optional.into_iter().map(String::into_bytes).collect(),
                fs_type,
                source,
                super_options,
            },
        )
}

proptest! {
    #[test]
    fn every_field_survives_the_kernels_escaping_byte_for_byte(
        entries in prop::collection::vec(entry(), 1..4),
    ) {
        let text: Vec<u8> = entries.iter().flat_map(render).collect();
        let parsed = parse_mountinfo("self/mountinfo", &text).unwrap();
        prop_assert_eq!(parsed, entries);
    }

    #[test]
    fn no_input_can_make_the_parser_panic(text in bytes(512)) {
        // A refusal or a table; never a crash in the middle of a trust check.
        let _ = parse_mountinfo("self/mountinfo", &text);
    }

    #[test]
    fn a_lone_line_without_its_newline_is_never_accepted(entry in entry()) {
        let mut line = render(&entry);
        line.pop();
        prop_assert!(parse_mountinfo("self/mountinfo", &line).is_err());
    }
}
