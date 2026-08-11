//! UART adapter for the transport-independent per-session line discipline.
//!
//! The physical console retains one global renderer because it has one UART
//! transport. SSH sessions will own separate `LineDiscipline` instances and
//! must never enter this adapter or mutate its prompt, history, or quiet state.

use core::fmt::{self, Write};

use crate::heap;
use crate::sync::SpinLock;
use crate::terminal::{InputAction, LineDiscipline, TerminalEvent};
use crate::uart;

struct ConsoleTty {
    prompt: &'static str,
    line: LineDiscipline,
    /// Suppress background chatter from demo components. This is a physical
    /// UART rendering preference, not authority and not shell-session state.
    quiet: bool,
    /// True while the console owns the bottom line and may redraw it around
    /// asynchronous output.
    at_prompt: bool,
}

static TTY: SpinLock<ConsoleTty> = SpinLock::new(ConsoleTty {
    prompt: "",
    line: LineDiscipline::new(),
    quiet: false,
    at_prompt: false,
});

fn raw(text: &str) {
    let _ = uart::Console.write_str(text);
}

fn erase_line() {
    raw("\r\x1b[2K");
}

fn redraw_contents(tty: &ConsoleTty) {
    raw(tty.prompt);
    raw(tty.line.input());
    let tail = tty.line.cursor_tail_chars();
    if tail != 0 {
        let _ = write!(uart::Console, "\x1b[{tail}D");
    }
}

fn redraw(tty: &ConsoleTty) {
    erase_line();
    redraw_contents(tty);
}

fn apply_input(tty: &mut ConsoleTty, action: InputAction) -> Option<TerminalEvent> {
    match action {
        InputAction::None => None,
        InputAction::Echo(character) => {
            let _ = uart::Console.write_char(character);
            None
        }
        InputAction::Bell => {
            raw("\x07");
            None
        }
        InputAction::BackspaceTail => {
            raw("\x08 \x08");
            None
        }
        InputAction::MoveLeft => {
            raw("\x1b[D");
            None
        }
        InputAction::MoveRight => {
            raw("\x1b[C");
            None
        }
        InputAction::Redraw => {
            redraw(tty);
            None
        }
        InputAction::Event(event) => {
            tty.at_prompt = false;
            match event {
                TerminalEvent::Line(_) => raw("\n"),
                TerminalEvent::Interrupt => raw("^C\n"),
                TerminalEvent::Eof => {}
            }
            Some(event)
        }
    }
}

/// Print to UART, redrawing an active console prompt around the output.
/// `background` marks output that the console's `quiet` setting may drop.
pub fn emit(args: fmt::Arguments<'_>, background: bool) {
    let tty = TTY.lock();
    if background && tty.quiet {
        return;
    }
    if tty.at_prompt {
        erase_line();
    }
    let _ = uart::Console.write_fmt(args);
    if tty.at_prompt {
        redraw_contents(&tty);
    }
}

/// Start a fresh prompt on the physical UART console.
pub fn prompt(prompt: &'static str) {
    let mut tty = TTY.lock();
    tty.prompt = prompt;
    tty.line.reset_line();
    tty.at_prompt = true;
    erase_line();
    raw(prompt);
}

pub fn set_completion_candidates(candidates: &[alloc::string::String]) {
    let mut tty = TTY.lock();
    let mut system = heap::enter_owner(heap::OwnerId::SYSTEM);
    tty.line.set_completion_candidates(candidates);
    system.restore();
}

/// Feed one UART byte into the physical console's line discipline.
pub fn input_byte(byte: u8) -> Option<TerminalEvent> {
    let mut tty = TTY.lock();
    // Input and history buffers may grow while the console lock is held. Charge
    // that growth to kernel infrastructure so a shell quota fault cannot
    // abandon the guard and wedge the physical console. A future SSH adapter
    // instead runs in, and is charged to, its connection component.
    let mut system = heap::enter_owner(heap::OwnerId::SYSTEM);
    let action = tty.line.feed_byte(byte);
    let event = apply_input(&mut tty, action);
    system.restore();
    event
}

/// Abandon an active physical-console prompt.
pub fn cancel() {
    let mut tty = TTY.lock();
    let action = tty.line.interrupt();
    let _ = apply_input(&mut tty, action);
}

pub fn set_quiet(quiet: bool) {
    TTY.lock().quiet = quiet;
}

pub fn is_quiet() -> bool {
    TTY.lock().quiet
}
