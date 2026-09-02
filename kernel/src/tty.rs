//! UART adapter for the transport-independent per-session line discipline.
//!
//! The physical console retains one global renderer because it has one UART
//! transport. SSH sessions will own separate `LineDiscipline` instances and
//! must never enter this adapter or mutate its prompt, history, or quiet state.

use core::fmt::{self, Write};
use core::mem::ManuallyDrop;

use crate::heap;
use crate::sync::{SpinGuard, SpinLock};
use crate::terminal::{InputAction, LineDiscipline, TerminalEvent};
use crate::uart;

pub(crate) use crate::uart::RawTxRecordError as RawUartRecordError;

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

/// Unforgeable outside this module: borrowing one proves the caller is in the
/// lexical scope of a live TTY guard before it attempts to acquire TX.
pub(crate) struct RawTxOrderPermit<'guard> {
    _tty: &'guard SpinGuard<'static, ConsoleTty>,
}

static TTY: SpinLock<ConsoleTty> = SpinLock::new(ConsoleTty {
    prompt: "",
    line: LineDiscipline::new(),
    quiet: false,
    at_prompt: false,
});

/// One temporary raw UART record with the global renderer and transmitter
/// excluded for its entire lifetime.
///
/// Field order is intentional: ordinary destruction releases the nested TX
/// guard before the outer TTY guard. Once a future formal publisher performs
/// its first sink call it must wrap this value in `ManuallyDrop`; any returned
/// error or panic then leaves both guards held as a fail-stop quarantine
/// instead of running a destructor after a partial record. Successful commit
/// is the sole method path that releases the pair.
pub(crate) struct RawUartRecord {
    tx: Option<uart::RawTxRecord>,
    tty: Option<SpinGuard<'static, ConsoleTty>>,
}

impl RawUartRecord {
    fn release_after_commit(&mut self) {
        // Preserve the reverse of the sole legal acquisition order. Dropping
        // TX first restores the interrupt-disabled state captured underneath
        // TTY; dropping TTY then restores the caller's original IRQ state.
        drop(self.tx.take());
        drop(self.tty.take());
    }

    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> Result<(), RawUartRecordError> {
        match self.tx.as_mut() {
            Some(tx) => tx.write_all(bytes),
            None => Err(RawUartRecordError::Released),
        }
    }

    pub(crate) fn commit_record(&mut self) -> Result<(), RawUartRecordError> {
        let result = match self.tx.as_mut() {
            Some(tx) => tx.commit_record(),
            None => Err(RawUartRecordError::Released),
        };
        if result.is_ok() {
            // The inner commit has waited for LSR_TX_EMPTY and released TX.
            // Only now may panic/OOM output stop failing silently. Dispose of
            // the inert TX wrapper, then release the outer TTY guard.
            uart::finish_raw_record_activity();
            self.release_after_commit();
        }
        result
    }
}

impl Drop for RawUartRecord {
    fn drop(&mut self) {
        if uart::raw_record_active() {
            // A caller must not recover ordinary console output by dropping a
            // started record. Keep the same permanent quarantine even if a
            // future call site forgets to wrap the value in ManuallyDrop.
            if let Some(tx) = self.tx.take() {
                core::mem::forget(tx);
            }
            if let Some(tty) = self.tty.take() {
                core::mem::forget(tty);
            }
        }
    }
}

/// Acquire one raw record in the only permitted order: TTY, then TX.
///
/// Holding TTY prevents the per-byte ordinary console writer from being
/// paused midway through a formatted emission. `RawTxRecord::begin` then
/// checks that the prior complete emission actually left the byte stream at
/// column zero; it never inserts a repair newline on failure.
pub(crate) fn begin_raw_uart_record() -> Result<RawUartRecord, RawUartRecordError> {
    // ManuallyDrop is installed before arming the lock-free panic gate. From
    // that point onward no explicit error or unwind may restore ordinary TTY
    // output unless a complete record has drained successfully.
    let tty = ManuallyDrop::new(TTY.lock());
    uart::begin_raw_record_activity();
    let tx = {
        let permit = RawTxOrderPermit { _tty: &tty };
        uart::RawTxRecord::begin(&permit)?
    };
    Ok(RawUartRecord {
        tx: Some(tx),
        tty: Some(ManuallyDrop::into_inner(tty)),
    })
}

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
