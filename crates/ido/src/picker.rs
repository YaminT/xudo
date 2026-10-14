//! The full-screen picker, as a pure state machine.
//!
//! [`Picker`] takes keys and returns [`Action`]s; [`Picker::frame`] renders the
//! current state to text. Neither touches a terminal: the binary owns raw mode
//! and the alternate screen behind the [`Terminal`] trait, and [`pick`] drives
//! one against the other. So every rule below is a unit test, not a hope.
//!
//! The rules that matter:
//!
//! * **Nothing runs on one accidental keystroke.** Enter runs the *selected*
//!   set and does nothing when nothing is selected. Running more than one
//!   entry, or any high-consequence entry, takes the word `run` typed out.
//! * A blocked or halted entry cannot be selected, and saying why is the
//!   response to trying.
//! * Every string an agent wrote is rendered through the sanitizer.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use crate::entry::Entry;
use crate::keys::{Key, decode};
use crate::render::{self, Row};
use crate::status::{Status, run_order, status_of};

/// The word a typed confirmation must match exactly.
pub const CONFIRM_WORD: &str = "run";

/// What the binary's terminal does for the picker.
pub trait Terminal {
    /// Columns and rows.
    fn size(&self) -> (usize, usize);
    /// Blocks for input and returns what one read delivered. Empty means the
    /// input closed.
    ///
    /// # Errors
    ///
    /// Whatever the read failed with.
    fn read_input(&mut self) -> std::io::Result<Vec<u8>>;
    /// Replaces the screen with `frame`, lines separated by `\n`.
    ///
    /// # Errors
    ///
    /// Whatever the write failed with.
    fn draw(&mut self, frame: &str) -> std::io::Result<()>;
    /// Leaves raw mode and the alternate screen.
    ///
    /// # Errors
    ///
    /// Whatever restoring the terminal failed with.
    fn restore(&mut self) -> std::io::Result<()>;
}

/// What the picker wants done.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Keep going.
    Continue,
    /// Leave without doing anything.
    Quit,
    /// Run these ids, in this order.
    Run(Vec<u64>),
    /// Drop these ids.
    Drop(Vec<u64>),
}

/// What the keyboard is currently doing.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Mode {
    /// Moving and selecting.
    Browse,
    /// Typing the confirmation word for a run.
    ConfirmRun {
        /// What will run.
        ids: Vec<u64>,
        /// What has been typed so far.
        typed: String,
    },
    /// Answering y/n to a drop.
    ConfirmDrop {
        /// What will be dropped.
        ids: Vec<u64>,
    },
}

/// The picker's state.
#[derive(Clone, Debug)]
pub struct Picker {
    queue: Vec<Entry>,
    order: Vec<u64>,
    cursor: usize,
    selected: BTreeSet<u64>,
    preview: bool,
    mode: Mode,
    message: Option<String>,
    now: u64,
    color: bool,
}

impl Picker {
    /// A picker over `queue`, as of `now_unix`.
    #[must_use]
    pub fn new(queue: Vec<Entry>, now_unix: u64, color: bool) -> Self {
        let order = run_order(&queue);
        Self {
            queue,
            order,
            cursor: 0,
            selected: BTreeSet::new(),
            preview: false,
            mode: Mode::Browse,
            message: None,
            now: now_unix,
            color,
        }
    }

    /// Starts with a message on the status line.
    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// The selected ids, in run order.
    #[must_use]
    pub fn selected(&self) -> Vec<u64> {
        self.order
            .iter()
            .copied()
            .filter(|id| self.selected.contains(id))
            .collect()
    }

    fn entry(&self, id: u64) -> Option<&Entry> {
        self.queue.iter().find(|e| e.id == id)
    }

    fn current(&self) -> Option<&Entry> {
        self.order.get(self.cursor).and_then(|id| self.entry(*id))
    }

    fn status(&self, entry: &Entry) -> Status {
        status_of(entry, &self.queue, self.now)
    }

    /// Applies one key.
    pub fn handle(&mut self, key: Key) -> Action {
        match std::mem::replace(&mut self.mode, Mode::Browse) {
            Mode::Browse => self.browse(key),
            Mode::ConfirmRun { ids, typed } => self.confirm_run(key, ids, typed),
            Mode::ConfirmDrop { ids } => {
                if key == Key::Char('y') {
                    Action::Drop(ids)
                } else {
                    self.message = Some("kept; nothing was dropped".to_owned());
                    Action::Continue
                }
            }
        }
    }

    fn browse(&mut self, key: Key) -> Action {
        match key {
            Key::Up | Key::Char('k') => {
                self.cursor = self.cursor.saturating_sub(1);
                self.message = None;
            }
            Key::Down | Key::Char('j') => {
                if self.cursor.saturating_add(1) < self.order.len() {
                    self.cursor = self.cursor.saturating_add(1);
                }
                self.message = None;
            }
            Key::Space => self.toggle(),
            Key::Char('g') => self.select_group(),
            Key::Char('p') => self.preview = !self.preview,
            Key::Char('d') => self.start_drop(),
            Key::Enter => return self.start_run(),
            Key::Char('q') | Key::Esc | Key::CtrlC => return Action::Quit,
            _ => {}
        }
        Action::Continue
    }

    fn confirm_run(&mut self, key: Key, ids: Vec<u64>, mut typed: String) -> Action {
        match key {
            Key::Esc | Key::CtrlC => {
                self.message = Some("cancelled; nothing ran".to_owned());
                return Action::Continue;
            }
            Key::Enter if typed == CONFIRM_WORD => return Action::Run(ids),
            Key::Enter => {
                typed.clear();
                self.message = Some(format!(
                    "type {CONFIRM_WORD} exactly and press enter, or esc to cancel"
                ));
            }
            Key::Backspace => {
                typed.pop();
            }
            Key::Char(c) if typed.chars().count() < 16 => typed.push(c),
            Key::Space if typed.chars().count() < 16 => typed.push(' '),
            _ => {}
        }
        self.mode = Mode::ConfirmRun { ids, typed };
        Action::Continue
    }

    fn toggle(&mut self) {
        let Some(entry) = self.current() else {
            return;
        };
        let id = entry.id;
        let status = self.status(entry);
        if self.selected.remove(&id) {
            self.message = None;
        } else if status.selectable() {
            self.selected.insert(id);
            self.message = None;
        } else {
            self.message = Some(format!(
                "#{id} is {}: {}",
                status.label(),
                status.detail().unwrap_or_default()
            ));
        }
    }

    fn select_group(&mut self) {
        let Some(entry) = self.current() else {
            return;
        };
        let Some(group) = entry.group.clone() else {
            self.message = Some(format!("#{} is not in a group", entry.id));
            return;
        };
        let members: Vec<u64> = self
            .order
            .iter()
            .copied()
            .filter(|id| {
                self.entry(*id)
                    .is_some_and(|e| e.group.as_deref() == Some(group.as_str()))
            })
            .collect();
        self.message = Some(format!(
            "group {}: {} step(s) selected; they run in order, stopping at the first failure",
            render::group_name(&group),
            members.len()
        ));
        self.selected.extend(members);
    }

    fn start_drop(&mut self) {
        let ids = if self.selected.is_empty() {
            self.current().map(|e| vec![e.id]).unwrap_or_default()
        } else {
            self.selected()
        };
        if !ids.is_empty() {
            self.mode = Mode::ConfirmDrop { ids };
        }
    }

    fn start_run(&mut self) -> Action {
        let ids = self.selected();
        if ids.is_empty() {
            self.message =
                Some("nothing selected: press space to select, then enter to run".to_owned());
            return Action::Continue;
        }
        let high = ids
            .iter()
            .filter_map(|id| self.entry(*id))
            .any(|e| crate::consequence::assess(&e.argv).is_high());
        if ids.len() > 1 || high {
            self.mode = Mode::ConfirmRun {
                ids,
                typed: String::new(),
            };
            return Action::Continue;
        }
        Action::Run(ids)
    }

    /// Renders the screen as `rows` lines of at most `cols` characters.
    #[must_use]
    pub fn frame(&self, cols: usize, rows: usize) -> String {
        let cols = cols.max(20);
        let rows = rows.max(8);

        let mut header = format!("ido \u{2014} {} queued", self.queue.len());
        if !self.selected.is_empty() {
            let _ = write!(header, " \u{b7} {} selected", self.selected.len());
        }

        let footer = self.footer();
        let preview = if self.preview {
            self.preview_lines()
        } else {
            Vec::new()
        };
        let reserved = 2_usize
            .saturating_add(footer.len())
            .saturating_add(preview.len());
        let budget = rows.saturating_sub(reserved).max(1);

        let blocks = self.blocks();
        let start = window_start(&blocks, self.cursor, budget);
        let mut body: Vec<Line> = Vec::new();
        for block in blocks.into_iter().skip(start) {
            if body.len().saturating_add(block.len()) > budget && !body.is_empty() {
                break;
            }
            body.extend(block);
        }
        body.truncate(budget);

        let mut lines: Vec<Line> = vec![Line::plain(header), Line::plain(String::new())];
        lines.extend(body);
        while lines
            .len()
            .saturating_add(preview.len())
            .saturating_add(footer.len())
            < rows
        {
            lines.push(Line::plain(String::new()));
        }
        lines.extend(preview);
        lines.extend(footer);

        lines
            .iter()
            .map(|line| line.render(cols, self.color))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// One block of lines per entry, in run order.
    fn blocks(&self) -> Vec<Vec<Line>> {
        let mut blocks = Vec::new();
        let mut current_group: Option<String> = None;
        let ordered = self.order.iter().filter_map(|id| self.entry(*id));
        for (index, entry) in ordered.enumerate() {
            let mut block = Vec::new();
            if entry.group != current_group {
                if let Some(group) = &entry.group {
                    block.push(Line::plain(format!(
                        "  group {} \u{2014} g selects every step",
                        render::group_name(group)
                    )));
                }
                current_group.clone_from(&entry.group);
            }
            let row = render::row(entry, &self.queue, self.now);
            block.extend(self.entry_lines(entry, &row, index == self.cursor));
            blocks.push(block);
        }
        blocks
    }

    fn entry_lines(&self, entry: &Entry, row: &Row, at_cursor: bool) -> Vec<Line> {
        let pointer = if at_cursor { '\u{25B8}' } else { ' ' };
        let mark = if self.selected.contains(&entry.id) {
            "[x]"
        } else if row.status.selectable() {
            "[ ]"
        } else {
            " - "
        };
        let indent = if entry.group.is_some() { "  " } else { "" };
        let step = entry.step.map(|s| format!("{s}. ")).unwrap_or_default();
        let dim = !row.status.selectable() || row.status == Status::Stale;
        let mut lines = vec![Line {
            text: format!(
                "{pointer} {mark} {indent}{step}#{} {:<7} {}",
                entry.id,
                row.status.label(),
                row.head
            ),
            style: if at_cursor {
                Style::Cursor
            } else if dim {
                Style::Dim
            } else {
                Style::Plain
            },
        }];
        let pad = format!("      {indent}");
        if let Some(detail) = row.status.detail() {
            lines.push(Line::dim(format!("{pad}{}: {detail}", row.status.label())));
        }
        lines.push(Line::dim(format!("{pad}{}", row.meta)));
        for warning in &row.warnings {
            lines.push(Line::warn(format!("{pad}{warning}")));
        }
        lines
    }

    fn preview_lines(&self) -> Vec<Line> {
        let Some(entry) = self.current() else {
            return Vec::new();
        };
        let mut lines = vec![Line::plain(format!(
            "\u{2500}\u{2500} #{} exactly as it will run \u{2500}\u{2500}",
            entry.id
        ))];
        for (i, token) in entry.argv.iter().enumerate() {
            let shown = render::argv_line(std::slice::from_ref(token), render::FIELD_COLS);
            lines.push(Line::plain(format!("  argv[{i}] {}", shown.text)));
        }
        let cwd = entry.cwd.as_deref().map_or_else(
            || "where you run ido".to_owned(),
            |c| render::field(c, 120).text,
        );
        lines.push(Line::plain(format!("  directory {cwd}")));
        lines.push(Line::plain(
            "  environment your own, unchanged; no shell is involved".to_owned(),
        ));
        if !entry.dry_run_of.is_empty() {
            lines.push(Line::plain(format!(
                "  preview command (not run automatically; it is a command too): {}",
                render::argv_line(&entry.dry_run_of, render::FIELD_COLS).text
            )));
        }
        lines
    }

    fn footer(&self) -> Vec<Line> {
        let prompt = match &self.mode {
            Mode::Browse => Line::dim(
                "\u{2191}\u{2193} move \u{b7} space select \u{b7} g group \u{b7} enter run \
                 \u{b7} d drop \u{b7} p preview \u{b7} q quit"
                    .to_owned(),
            ),
            Mode::ConfirmRun { ids, typed } => {
                let list: Vec<String> = ids.iter().map(|id| format!("#{id}")).collect();
                Line::warn(format!(
                    "run {} in order, stopping at the first failure? type {CONFIRM_WORD} \
                     and press enter (esc cancels): {typed}",
                    list.join(" ")
                ))
            }
            Mode::ConfirmDrop { ids } => {
                let list: Vec<String> = ids.iter().map(|id| format!("#{id}")).collect();
                Line::warn(format!(
                    "drop {}? y drops, any other key keeps",
                    list.join(" ")
                ))
            }
        };
        let message = Line::plain(self.message.clone().unwrap_or_default());
        vec![message, prompt]
    }
}

/// The first block to draw so the cursor's block is visible.
fn window_start(blocks: &[Vec<Line>], cursor: usize, budget: usize) -> usize {
    let mut start = cursor.min(blocks.len().saturating_sub(1));
    let mut used = blocks.get(start).map_or(0, Vec::len);
    while start > 0 {
        let above = blocks.get(start.saturating_sub(1)).map_or(0, Vec::len);
        if used.saturating_add(above) > budget {
            break;
        }
        used = used.saturating_add(above);
        start = start.saturating_sub(1);
    }
    start
}

/// How a line is drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Style {
    Plain,
    Dim,
    Warn,
    Cursor,
}

/// One screen line, before width clamping and styling.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Line {
    text: String,
    style: Style,
}

impl Line {
    fn plain(text: String) -> Self {
        Self {
            text,
            style: Style::Plain,
        }
    }

    fn dim(text: String) -> Self {
        Self {
            text,
            style: Style::Dim,
        }
    }

    fn warn(text: String) -> Self {
        Self {
            text,
            style: Style::Warn,
        }
    }

    /// Clamps to `cols` characters, then styles. Styling is applied after the
    /// clamp so an escape sequence is never cut in half.
    fn render(&self, cols: usize, color: bool) -> String {
        let fitted: String = if self.text.chars().count() > cols {
            let mut cut: String = self.text.chars().take(cols.saturating_sub(1)).collect();
            cut.push('\u{2026}');
            cut
        } else {
            self.text.clone()
        };
        if !color || self.style == Style::Plain {
            return fitted;
        }
        let code = match self.style {
            Style::Dim => "2",
            Style::Warn => "33",
            Style::Cursor | Style::Plain => "7",
        };
        format!("\u{1B}[{code}m{fitted}\u{1B}[0m")
    }
}

/// Drives `picker` on `terminal` until it wants something other than more
/// keys.
///
/// # Errors
///
/// Whatever the terminal failed with.
pub fn pick(terminal: &mut dyn Terminal, picker: &mut Picker) -> std::io::Result<Action> {
    loop {
        let (cols, rows) = terminal.size();
        terminal.draw(&picker.frame(cols, rows))?;
        let input = terminal.read_input()?;
        if input.is_empty() {
            return Ok(Action::Quit);
        }
        for key in decode(&input) {
            match picker.handle(key) {
                Action::Continue => {}
                other => return Ok(other),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use super::*;
    use crate::entry::QUEUE_SCHEMA_VERSION;

    fn entry(id: u64, argv: &[&str]) -> Entry {
        Entry {
            schema_version: QUEUE_SCHEMA_VERSION,
            id,
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            reason: None,
            group: None,
            step: None,
            needs: Vec::new(),
            cwd: None,
            dry_run_of: Vec::new(),
            queued_at: 1000,
            queued_by: None,
            attempts: 0,
            last_exit: None,
        }
    }

    fn grouped(id: u64, step: u32, argv: &[&str]) -> Entry {
        let mut e = entry(id, argv);
        e.group = Some("deploy".into());
        e.step = Some(step);
        e
    }

    fn keys(picker: &mut Picker, keys: &[Key]) -> Action {
        let mut last = Action::Continue;
        for key in keys {
            last = picker.handle(*key);
        }
        last
    }

    fn typed(word: &str) -> Vec<Key> {
        word.chars().map(Key::Char).collect()
    }

    #[test]
    fn enter_with_nothing_selected_runs_nothing() {
        let mut p = Picker::new(vec![entry(1, &["true"])], 1000, false);
        assert_eq!(p.handle(Key::Enter), Action::Continue);
        assert!(p.frame(80, 24).contains("nothing selected"));
    }

    #[test]
    fn one_low_consequence_entry_runs_on_space_then_enter() {
        let mut p = Picker::new(vec![entry(1, &["willyoumarryme"])], 1000, false);
        assert_eq!(
            keys(&mut p, &[Key::Space, Key::Enter]),
            Action::Run(vec![1])
        );
    }

    #[test]
    fn a_high_consequence_entry_needs_the_word_typed() {
        let mut p = Picker::new(vec![entry(1, &["sudo", "true"])], 1000, false);
        assert_eq!(keys(&mut p, &[Key::Space, Key::Enter]), Action::Continue);
        let frame = p.frame(120, 24);
        assert!(frame.contains("type run"), "{frame}");
        // A wrong word clears and explains; it never runs.
        assert_eq!(keys(&mut p, &typed("yes")), Action::Continue);
        assert_eq!(p.handle(Key::Enter), Action::Continue);
        assert!(p.frame(120, 24).contains("type run exactly"));
        // Typing, fixing a typo, and confirming.
        let mut sequence = typed("rux");
        sequence.extend([Key::Backspace, Key::Char('n'), Key::Unknown]);
        keys(&mut p, &sequence);
        assert_eq!(p.handle(Key::Enter), Action::Run(vec![1]));
    }

    #[test]
    fn several_entries_need_the_word_typed_and_run_in_queue_order() {
        let mut p = Picker::new(vec![entry(1, &["true"]), entry(2, &["true"])], 1000, false);
        keys(
            &mut p,
            &[Key::Down, Key::Space, Key::Up, Key::Space, Key::Enter],
        );
        assert!(p.frame(120, 24).contains("run #1 #2 in order"));
        let mut sequence = typed("run");
        sequence.push(Key::Enter);
        assert_eq!(keys(&mut p, &sequence), Action::Run(vec![1, 2]));
    }

    #[test]
    fn the_confirmation_is_bounded_and_escapable() {
        let mut p = Picker::new(vec![entry(1, &["sudo", "x"])], 1000, false);
        keys(&mut p, &[Key::Space, Key::Enter]);
        // A flood of keys cannot grow the buffer without bound.
        keys(&mut p, &[Key::Char('a'); 40]);
        keys(&mut p, &[Key::Space; 40]);
        assert!(p.frame(400, 24).contains(&"a".repeat(16)));
        assert!(!p.frame(400, 24).contains(&"a".repeat(17)));
        assert_eq!(p.handle(Key::Esc), Action::Continue);
        assert!(p.frame(80, 24).contains("cancelled; nothing ran"));
        // Back in browse mode: Ctrl-C now quits.
        keys(&mut p, &[Key::Enter]);
        assert_eq!(
            p.handle(Key::CtrlC),
            Action::Continue,
            "ctrl-c cancels a prompt"
        );
        assert_eq!(p.handle(Key::CtrlC), Action::Quit, "and quits from browse");
    }

    #[test]
    fn a_blocked_step_cannot_be_selected_and_says_why() {
        let mut p = Picker::new(
            vec![
                grouped(1, 1, &["terraform", "plan"]),
                grouped(2, 2, &["terraform", "apply"]),
            ],
            1000,
            false,
        );
        keys(&mut p, &[Key::Down, Key::Space]);
        assert!(p.selected().is_empty());
        let frame = p.frame(120, 30);
        assert!(
            frame.contains("#2 is blocked: step 1 has not run"),
            "{frame}"
        );
        assert!(frame.contains(" - "), "{frame}");
    }

    #[test]
    fn g_selects_the_whole_group_in_step_order() {
        let mut p = Picker::new(
            vec![
                grouped(5, 2, &["terraform", "apply"]),
                grouped(4, 1, &["terraform", "plan"]),
                entry(9, &["true"]),
            ],
            1000,
            false,
        );
        keys(&mut p, &[Key::Char('g')]);
        assert_eq!(p.selected(), vec![4, 5]);
        assert!(p.frame(160, 30).contains("2 step(s) selected"));
        // Off the group, `g` explains instead.
        keys(&mut p, &[Key::Down, Key::Down, Key::Char('g')]);
        assert!(p.frame(120, 30).contains("#9 is not in a group"));
    }

    #[test]
    fn space_toggles_a_selection_off() {
        let mut p = Picker::new(vec![entry(1, &["true"])], 1000, false);
        keys(&mut p, &[Key::Space, Key::Space]);
        assert!(p.selected().is_empty());
    }

    #[test]
    fn dropping_takes_a_y() {
        let mut p = Picker::new(vec![entry(1, &["true"]), entry(2, &["true"])], 1000, false);
        keys(&mut p, &[Key::Char('d')]);
        assert!(p.frame(80, 24).contains("drop #1?"));
        assert_eq!(p.handle(Key::Char('n')), Action::Continue);
        assert!(p.frame(80, 24).contains("kept"));
        // With a selection, the selection is what is dropped.
        keys(&mut p, &[Key::Space, Key::Down, Key::Space, Key::Char('d')]);
        assert_eq!(p.handle(Key::Char('y')), Action::Drop(vec![1, 2]));
    }

    #[test]
    fn movement_stays_in_bounds_and_q_quits() {
        let mut p = Picker::new(vec![entry(1, &["true"]), entry(2, &["true"])], 1000, false);
        keys(
            &mut p,
            &[
                Key::Up,
                Key::Char('k'),
                Key::Down,
                Key::Char('j'),
                Key::Down,
            ],
        );
        assert!(p.frame(80, 24).contains("\u{25B8} [ ] #2"));
        assert_eq!(p.handle(Key::Char('q')), Action::Quit);
        assert_eq!(p.handle(Key::Esc), Action::Quit);
    }

    #[test]
    fn the_preview_shows_every_token_and_runs_nothing() {
        let mut e = entry(1, &["aws", "s3", "sync", "a b"]);
        e.cwd = Some("/srv/app".into());
        e.dry_run_of = vec!["aws".into(), "s3".into(), "sync".into(), "--dryrun".into()];
        let mut p = Picker::new(vec![e, entry(2, &["true"])], 1000, false).with_message("hello");
        keys(&mut p, &[Key::Char('p')]);
        let frame = p.frame(160, 40);
        assert!(frame.contains("hello"));
        assert!(frame.contains("argv[3] \"a b\""), "{frame}");
        assert!(frame.contains("directory /srv/app"), "{frame}");
        assert!(frame.contains("not run automatically"), "{frame}");
        keys(&mut p, &[Key::Down]);
        assert!(p.frame(160, 40).contains("directory where you run ido"));
        keys(&mut p, &[Key::Char('p')]);
        assert!(!p.frame(160, 40).contains("argv[0]"));
    }

    #[test]
    fn untrusted_text_never_reaches_the_frame_raw() {
        let mut e = entry(1, &["echo", "\u{1B}]0;pwned\u{7}hi"]);
        e.reason = Some("\u{202E}evil".into());
        let p = Picker::new(vec![e], 1000, false);
        let frame = p.frame(120, 24);
        assert!(!frame.contains('\u{1B}'), "{frame:?}");
        assert!(!frame.contains('\u{202E}'), "{frame:?}");
        assert!(frame.contains('\u{26A0}'), "warnings are shown: {frame}");
    }

    #[test]
    fn color_styles_lines_without_cutting_escapes() {
        let mut stale = entry(2, &["true"]);
        stale.queued_at = 0;
        let mut p = Picker::new(vec![entry(1, &["sudo", "x"]), stale], 10_000_000, true);
        keys(&mut p, &[Key::Space, Key::Enter]);
        let frame = p.frame(30, 24);
        assert!(frame.contains("\u{1B}[7m"), "cursor in reverse video");
        assert!(frame.contains("\u{1B}[2m"), "dim");
        assert!(frame.contains("\u{1B}[33m"), "warning colour");
        for line in frame.lines() {
            let visible = line
                .replace("\u{1B}[7m", "")
                .replace("\u{1B}[2m", "")
                .replace("\u{1B}[33m", "")
                .replace("\u{1B}[0m", "");
            assert!(visible.chars().count() <= 30, "{visible:?}");
        }
    }

    #[test]
    fn a_long_queue_scrolls_to_keep_the_cursor_visible() {
        let queue: Vec<Entry> = (1..=30).map(|id| entry(id, &["true"])).collect();
        let mut p = Picker::new(queue, 1000, false);
        keys(&mut p, &[Key::Down; 25]);
        let frame = p.frame(80, 12);
        assert_eq!(frame.lines().count(), 12);
        assert!(frame.contains("\u{25B8} [ ] #26"), "{frame}");
        assert!(!frame.contains("#1 "), "{frame}");
    }

    #[test]
    fn a_tiny_terminal_still_renders_something_sane() {
        let p = Picker::new(vec![entry(1, &["true"])], 1000, false);
        let frame = p.frame(1, 1);
        assert_eq!(frame.lines().count(), 8);
    }

    #[test]
    fn the_empty_picker_ignores_selection_keys() {
        let mut p = Picker::new(Vec::new(), 1000, false);
        keys(
            &mut p,
            &[Key::Space, Key::Char('g'), Key::Char('d'), Key::Char('p')],
        );
        assert!(p.selected().is_empty());
        assert!(p.frame(80, 24).contains("0 queued"));
    }

    #[test]
    fn a_window_start_backs_up_while_blocks_fit() {
        let block = vec![Line::plain(String::new()); 3];
        let blocks = vec![block.clone(), block.clone(), block];
        assert_eq!(window_start(&blocks, 2, 9), 0);
        assert_eq!(window_start(&blocks, 2, 6), 1);
        assert_eq!(window_start(&[], 0, 6), 0);
    }

    struct Scripted {
        inputs: Vec<Vec<u8>>,
        frames: Vec<String>,
        draw_fails: bool,
    }

    impl Terminal for Scripted {
        fn size(&self) -> (usize, usize) {
            (80, 24)
        }
        fn read_input(&mut self) -> std::io::Result<Vec<u8>> {
            if self.inputs.is_empty() {
                return Err(std::io::Error::other("no more input scripted"));
            }
            Ok(self.inputs.remove(0))
        }
        fn draw(&mut self, frame: &str) -> std::io::Result<()> {
            if self.draw_fails {
                return Err(std::io::Error::other("cannot draw"));
            }
            self.frames.push(frame.to_owned());
            Ok(())
        }
        fn restore(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn pick_drives_keys_until_an_action() {
        let mut terminal = Scripted {
            inputs: vec![b"\x1b[B".to_vec(), b" \r".to_vec()],
            frames: Vec::new(),
            draw_fails: false,
        };
        let mut p = Picker::new(vec![entry(1, &["true"]), entry(2, &["true"])], 1000, false);
        assert_eq!(pick(&mut terminal, &mut p).unwrap(), Action::Run(vec![2]));
        assert_eq!(terminal.frames.len(), 2);
        terminal.restore().unwrap();
    }

    #[test]
    fn a_draw_error_surfaces_before_any_key_is_read() {
        let mut broken = Scripted {
            inputs: vec![b" \r".to_vec()],
            frames: Vec::new(),
            draw_fails: true,
        };
        let mut p = Picker::new(vec![entry(1, &["true"])], 1000, false);
        assert!(pick(&mut broken, &mut p).is_err());
        assert_eq!(broken.inputs.len(), 1, "nothing was read");
    }

    #[test]
    fn spaces_can_be_typed_into_the_confirmation() {
        let mut p = Picker::new(vec![entry(1, &["sudo", "x"])], 1000, false);
        keys(
            &mut p,
            &[Key::Space, Key::Enter, Key::Space, Key::Char('r')],
        );
        assert!(p.frame(200, 24).contains("(esc cancels):  r"));
        assert_eq!(p.handle(Key::Enter), Action::Continue, "\" r\" is not run");
    }

    #[test]
    fn an_unknown_key_while_browsing_does_nothing() {
        let mut p = Picker::new(vec![entry(1, &["true"])], 1000, false);
        assert_eq!(p.handle(Key::Unknown), Action::Continue);
        assert_eq!(p.handle(Key::Char('z')), Action::Continue);
    }

    #[test]
    fn closed_input_quits_and_a_read_error_surfaces() {
        let mut closed = Scripted {
            inputs: vec![Vec::new()],
            frames: Vec::new(),
            draw_fails: false,
        };
        let mut p = Picker::new(vec![entry(1, &["true"])], 1000, false);
        assert_eq!(pick(&mut closed, &mut p).unwrap(), Action::Quit);
        assert!(pick(&mut closed, &mut p).is_err());
    }
}
