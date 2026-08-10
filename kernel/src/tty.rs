//! Console line discipline.
//!
//! VibeOS components print whenever they like, from tasks the shell knows
//! nothing about. Without arbitration that output lands in the middle of
//! whatever you are typing. The tty owns the bottom line of the screen: any
//! asynchronous write erases the prompt, prints, and redraws the prompt with
//! your partial input intact.
//!
//! `quiet` is a console setting, not an authority question — muting chatter is
//! about what gets rendered, not about who is allowed to speak. Taking a
//! component's voice away is what `revoke` is for.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use core::fmt::{self, Write};

use crate::sync::SpinLock;
use crate::{heap, uart};

struct Tty {
    prompt: &'static str,
    input: String,
    cursor: usize,
    history: VecDeque<String>,
    history_bytes: usize,
    history_index: Option<usize>,
    draft: String,
    /// True while the shell is waiting at a prompt, i.e. the last line on
    /// screen is ours to redraw.
    at_prompt: bool,
    /// Suppress background chatter from the demo components.
    quiet: bool,
}

static TTY: SpinLock<Tty> = SpinLock::new(Tty {
    prompt: "",
    input: String::new(),
    cursor: 0,
    history: VecDeque::new(),
    history_bytes: 0,
    history_index: None,
    draft: String::new(),
    at_prompt: false,
    quiet: false,
});

fn raw(s: &str) {
    let _ = uart::Console.write_str(s);
}

/// Erase the current line, leaving the cursor at column 0.
fn erase_line() {
    raw("\r\x1b[2K");
}

const MAX_INPUT_BYTES: usize = 4 * 1024;
const MAX_HISTORY_ENTRIES: usize = 64;
const MAX_HISTORY_BYTES: usize = 64 * 1024;

fn redraw(t: &Tty) {
    erase_line();
    raw(t.prompt);
    raw(&t.input);
    let tail = t.input[t.cursor..].chars().count();
    if tail != 0 {
        let _ = write!(uart::Console, "\x1b[{}D", tail);
    }
}

/// Print. `background` marks output that `quiet` may drop.
pub fn emit(args: fmt::Arguments, background: bool) {
    let t = TTY.lock();
    if background && t.quiet {
        return;
    }
    if t.at_prompt {
        erase_line();
    }
    let _ = uart::Console.write_fmt(args);
    if t.at_prompt {
        raw(t.prompt);
        raw(&t.input);
        let tail = t.input[t.cursor..].chars().count();
        if tail != 0 {
            let _ = write!(uart::Console, "\x1b[{}D", tail);
        }
    }
}

/// Start a fresh prompt and take ownership of the bottom line.
pub fn prompt(p: &'static str) {
    let mut t = TTY.lock();
    t.prompt = p;
    t.input.clear();
    t.cursor = 0;
    t.history_index = None;
    t.draft.clear();
    t.at_prompt = true;
    erase_line();
    raw(p);
}

pub fn type_char(c: char) {
    let mut t = TTY.lock();
    if t.input.len().saturating_add(c.len_utf8()) > MAX_INPUT_BYTES {
        raw("\x07");
        return;
    }
    // The line buffer is shared TTY state and grows while its lock is held.
    // Charge that growth to kernel infrastructure so a shell quota fault
    // cannot longjmp past the guard and permanently wedge input.
    let mut system = heap::enter_owner(heap::OwnerId::SYSTEM);
    let cursor = t.cursor;
    let appended = cursor == t.input.len();
    t.input.insert(cursor, c);
    t.cursor += c.len_utf8();
    t.history_index = None;
    t.draft.clear();
    system.restore();
    if appended {
        let mut encoded = [0; 4];
        raw(c.encode_utf8(&mut encoded));
    } else {
        redraw(&t);
    }
}

pub fn backspace() {
    let mut t = TTY.lock();
    if t.cursor == 0 { return; }
    let removed_from_end = t.cursor == t.input.len();
    let previous = t.input[..t.cursor]
        .char_indices()
        .last()
        .map(|(index, _)| index)
        .unwrap_or(0);
    t.input.remove(previous);
    t.cursor = previous;
    t.history_index = None;
    t.draft.clear();
    if removed_from_end {
        raw("\x08 \x08");
    } else {
        redraw(&t);
    }
}

pub fn move_left() {
    let mut t = TTY.lock();
    if t.cursor == 0 { return; }
    t.cursor = t.input[..t.cursor]
        .char_indices()
        .last()
        .map(|(index, _)| index)
        .unwrap_or(0);
    raw("\x1b[D");
}

pub fn move_right() {
    let mut t = TTY.lock();
    if t.cursor == t.input.len() { return; }
    let width = t.input[t.cursor..].chars().next().map(char::len_utf8).unwrap_or(0);
    t.cursor += width;
    raw("\x1b[C");
}

pub fn history_previous() {
    let mut t = TTY.lock();
    if t.history.is_empty() { return; }
    let mut system = heap::enter_owner(heap::OwnerId::SYSTEM);
    let index = match t.history_index {
        Some(0) => 0,
        Some(index) => index - 1,
        None => {
            t.draft = t.input.clone();
            t.history.len() - 1
        }
    };
    t.history_index = Some(index);
    t.input = t.history[index].clone();
    t.cursor = t.input.len();
    system.restore();
    redraw(&t);
}

pub fn history_next() {
    let mut t = TTY.lock();
    let Some(index) = t.history_index else { return; };
    let mut system = heap::enter_owner(heap::OwnerId::SYSTEM);
    if index + 1 < t.history.len() {
        let next = index + 1;
        t.history_index = Some(next);
        t.input = t.history[next].clone();
    } else {
        t.history_index = None;
        t.input = core::mem::take(&mut t.draft);
    }
    t.cursor = t.input.len();
    system.restore();
    redraw(&t);
}

/// Hand the line back: returns what was typed and releases the bottom line so
/// ordinary output scrolls normally again.
pub fn submit() -> String {
    let mut t = TTY.lock();
    t.at_prompt = false;
    raw("\n");
    let line = core::mem::take(&mut t.input);
    t.cursor = 0;
    t.history_index = None;
    t.draft.clear();
    if !line.is_empty() && t.history.back().is_none_or(|last| last != &line) {
        let mut system = heap::enter_owner(heap::OwnerId::SYSTEM);
        while t.history.len() >= MAX_HISTORY_ENTRIES
            || t.history_bytes.saturating_add(line.len()) > MAX_HISTORY_BYTES
        {
            let Some(oldest) = t.history.pop_front() else { break; };
            t.history_bytes -= oldest.len();
        }
        t.history_bytes += line.len();
        t.history.push_back(line.clone());
        system.restore();
    }
    line
}

/// Abandon the current input (Ctrl-C).
pub fn cancel() {
    let mut t = TTY.lock();
    t.at_prompt = false;
    t.input.clear();
    t.cursor = 0;
    t.history_index = None;
    t.draft.clear();
    raw("^C\n");
}

pub fn set_quiet(q: bool) {
    TTY.lock().quiet = q;
}

pub fn is_quiet() -> bool {
    TTY.lock().quiet
}
