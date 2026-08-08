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

use alloc::string::String;
use core::fmt::{self, Write};

use crate::sync::SpinLock;
use crate::{heap, uart};

struct Tty {
    prompt: &'static str,
    input: String,
    /// True while the shell is waiting at a prompt, i.e. the last line on
    /// screen is ours to redraw.
    at_prompt: bool,
    /// Suppress background chatter from the demo components.
    quiet: bool,
}

static TTY: SpinLock<Tty> = SpinLock::new(Tty {
    prompt: "",
    input: String::new(),
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
    }
}

/// Start a fresh prompt and take ownership of the bottom line.
pub fn prompt(p: &'static str) {
    let mut t = TTY.lock();
    t.prompt = p;
    t.input.clear();
    t.at_prompt = true;
    erase_line();
    raw(p);
}

pub fn type_char(c: char) {
    let mut t = TTY.lock();
    // The line buffer is shared TTY state and grows while its lock is held.
    // Charge that growth to kernel infrastructure so a shell quota fault
    // cannot longjmp past the guard and permanently wedge input.
    let mut system = heap::enter_owner(heap::OwnerId::SYSTEM);
    t.input.push(c);
    system.restore();
    let mut buf = [0u8; 4];
    raw(c.encode_utf8(&mut buf));
}

pub fn backspace() {
    let mut t = TTY.lock();
    if t.input.pop().is_some() {
        raw("\x08 \x08");
    }
}

/// Hand the line back: returns what was typed and releases the bottom line so
/// ordinary output scrolls normally again.
pub fn submit() -> String {
    let mut t = TTY.lock();
    t.at_prompt = false;
    raw("\n");
    core::mem::take(&mut t.input)
}

/// Abandon the current input (Ctrl-C).
pub fn cancel() {
    let mut t = TTY.lock();
    t.at_prompt = false;
    t.input.clear();
    raw("^C\n");
}

pub fn set_quiet(q: bool) {
    TTY.lock().quiet = q;
}

pub fn is_quiet() -> bool {
    TTY.lock().quiet
}
