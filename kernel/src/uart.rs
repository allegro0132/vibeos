//! Console buffering and scheduling over the firmware-owned UART.
//!
//! TX is synchronous (polled) because it is on the panic path. RX is
//! interrupt-driven: the trap handler fills a ring and wakes whichever task is
//! parked on `Uart::read_byte()`.

use core::fmt::{self, Write};
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::exec::WaitQueue;
use crate::interrupt::SpscByteRing;
use crate::sync::{SpinGuard, SpinLock};
pub fn base() -> usize {
    hardware().description.registers.start
}
pub fn irq() -> u32 {
    hardware().description.irq
}

fn hardware() -> &'static vibeos_hal::devices::ConsoleOps {
    &vibeos_hal::devices::early_devices().console
}

/// Byte-level state protected by the one UART transmitter lock.
///
/// `at_line_start` describes the raw byte stream, not terminal cursor state:
/// only LF establishes a record boundary. In particular, the CR inserted by
/// [`Console`] immediately before an ordinary LF does not make a formal record
/// eligible to start.
struct TxState {
    at_line_start: bool,
}

impl TxState {
    const NEW: Self = Self {
        at_line_start: true,
    };

    fn observe(&mut self, byte: u8) {
        self.at_line_start = byte == b'\n';
    }
}

// TX remains locked because foreground output, background diagnostics, and the
// panic path can otherwise interleave bytes. It is a polled task/panic path,
// not part of RX IRQ buffering. Ordinary console output retains its existing
// per-byte acquisition behavior; a raw record temporarily owns one guard for
// all of its fragments.
static TX: SpinLock<TxState> = SpinLock::new(TxState::NEW);
// Set only while a physical formal record owns the TTY/TX exclusion pair.
// Panic and OOM paths read this without taking either lock so they can halt
// silently instead of using the SBI console in the middle of a record.
static RAW_RECORD_ACTIVE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
// The PLIC UART top half is the sole producer and the shell is the sole
// consumer. Release/Acquire indices replace the former IRQ-side SpinLock;
// overflow drops the newest byte and increments `rx_dropped()`.
static RX: SpscByteRing<256> = SpscByteRing::new();
// The XHCI service is the sole producer and the shell remains the sole
// consumer. A second SPSC ring preserves the UART IRQ ring's one-producer
// contract while exposing one merged physical-console input stream.
static USB_RX: SpscByteRing<256> = SpscByteRing::new();
pub static RX_WAIT: WaitQueue = WaitQueue::new();
static DW_BUSY_IRQS: AtomicU64 = AtomicU64::new(0);
static DW_PHANTOM_TIMEOUTS: AtomicU64 = AtomicU64::new(0);

pub fn init() {
    // Safety: boot initializes UART before enabling the PLIC source or
    // starting the sole shell consumer.
    unsafe { RX.reset_quiescent() };
    if hardware().capabilities.usb_keyboard_input {
        unsafe { USB_RX.reset_quiescent() };
    }
    (hardware().init)();
}

/// Emit a boot marker before the normal console and MMU diagnostics exist.
///
/// U-Boot leaves UART0 enabled. This deliberately bypasses every lock and
/// queue so a failure while constructing or enabling the first page tables can
/// still be localized from the serial log. It is used only on the boot hart
/// before secondary harts or the executor can introduce another console
/// writer; one final marker may be emitted immediately after enabling IRQs.
pub fn early_write(text: &str) {
    if !hardware().capabilities.early_uart {
        return;
    }
    for byte in text.bytes() {
        (hardware().write_byte)(byte);
    }
    (hardware().drain)();
}

pub fn put(b: u8) {
    let mut tx = TX.lock();
    put_locked(&mut tx, b);
}

/// Arms the lock-free panic/allocator fail-stop before TX acquisition.
///
/// The caller already owns the TTY guard in `ManuallyDrop`, so every path
/// after this store either completes one drained record or remains silent.
pub(crate) fn begin_raw_record_activity() {
    let was_active = RAW_RECORD_ACTIVE.swap(true, Ordering::AcqRel);
    debug_assert!(!was_active, "raw UART record activity cannot nest");
}

/// True while SBI console output would be able to split a formal record.
pub(crate) fn raw_record_active() -> bool {
    RAW_RECORD_ACTIVE.load(Ordering::Acquire)
}

/// Disarms the lock-free fail-stop after TX has drained and been released.
pub(crate) fn finish_raw_record_activity() {
    debug_assert!(
        RAW_RECORD_ACTIVE.load(Ordering::Acquire),
        "raw UART record activity must be armed until commit"
    );
    RAW_RECORD_ACTIVE.store(false, Ordering::Release);
}

/// Write one byte while the caller owns [`TX`].
///
/// The line-state update follows the hardware write, so a successfully
/// observed LF means the raw stream itself ended at a complete LF boundary.
fn put_locked(tx: &mut TxState, byte: u8) {
    (hardware().write_byte)(byte);
    tx.observe(byte);
}

fn wait_tx_fully_empty() {
    (hardware().drain)();
}

/// Explicit framing failures for one raw UART record.
///
/// A failure returned after [`RawTxRecord::begin`] succeeds deliberately keeps
/// the TX guard owned. The publisher has already wrapped the record in
/// `ManuallyDrop`, so a failed or panicking record remains permanently
/// quarantined. Only a successful commit may release TX.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RawTxRecordError {
    NotAtLineStart,
    Released,
    EmptyRecord,
    MultipleLineFeeds,
    LineFeedNotFinal,
    BytesAfterLineFeed,
    MissingLineFeed,
}

/// Pure framing state for one raw record.
///
/// A prospective fragment is validated in full before a byte reaches the
/// hardware. Therefore an explicit framing error never writes part of the
/// rejected fragment or mutates this state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawRecordFraming {
    wrote_any: bool,
    line_feed_seen: bool,
}

impl RawRecordFraming {
    const NEW: Self = Self {
        wrote_any: false,
        line_feed_seen: false,
    };

    fn append(self, bytes: &[u8]) -> Result<Self, RawTxRecordError> {
        if bytes.is_empty() {
            return Ok(self);
        }
        if self.line_feed_seen {
            return Err(RawTxRecordError::BytesAfterLineFeed);
        }

        let line_feeds = bytes.iter().filter(|byte| **byte == b'\n').count();
        if line_feeds > 1 {
            return Err(RawTxRecordError::MultipleLineFeeds);
        }
        if line_feeds == 1 && bytes.last() != Some(&b'\n') {
            return Err(RawTxRecordError::LineFeedNotFinal);
        }

        Ok(Self {
            wrote_any: true,
            line_feed_seen: line_feeds == 1,
        })
    }

    fn validate_commit(self) -> Result<(), RawTxRecordError> {
        if !self.wrote_any {
            Err(RawTxRecordError::EmptyRecord)
        } else if !self.line_feed_seen {
            Err(RawTxRecordError::MissingLineFeed)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod raw_record_framing_tests {
    use super::{RawRecordFraming, RawTxRecordError};

    #[test]
    fn accepts_one_final_line_feed_across_fragments() {
        let framing = RawRecordFraming::NEW
            .append(b"VIBE_WASM_AOT_SAMPLE ")
            .unwrap()
            .append(b"{\"sample\":0}")
            .unwrap()
            .append(b"\n")
            .unwrap();

        assert_eq!(framing.validate_commit(), Ok(()));
    }

    #[test]
    fn rejects_more_than_one_line_feed() {
        assert_eq!(
            RawRecordFraming::NEW.append(b"first\nsecond\n"),
            Err(RawTxRecordError::MultipleLineFeeds)
        );
    }

    #[test]
    fn rejects_nonfinal_or_following_bytes() {
        let prefix = RawRecordFraming::NEW.append(b"record").unwrap();
        assert_eq!(
            prefix.append(b"\ntrailer"),
            Err(RawTxRecordError::LineFeedNotFinal)
        );
        // The rejected prospective fragment is transactional: the retained
        // record still describes exactly the previously accepted prefix.
        assert_eq!(
            prefix.validate_commit(),
            Err(RawTxRecordError::MissingLineFeed)
        );

        let framing = RawRecordFraming::NEW.append(b"record\n").unwrap();
        assert_eq!(
            framing.append(b"trailer"),
            Err(RawTxRecordError::BytesAfterLineFeed)
        );
    }

    #[test]
    fn commit_requires_a_nonempty_lf_terminated_record() {
        assert_eq!(
            RawRecordFraming::NEW.validate_commit(),
            Err(RawTxRecordError::EmptyRecord)
        );
        assert_eq!(
            RawRecordFraming::NEW
                .append(b"unterminated")
                .unwrap()
                .validate_commit(),
            Err(RawTxRecordError::MissingLineFeed)
        );
    }
}

/// Temporary ownership of the raw UART transmitter for one complete record.
///
/// This value contains a hart-affine [`SpinGuard`] and is consequently neither
/// `Send` nor suitable for static storage. The persistent collector must store
/// only a guard-free factory and create this value synchronously per record.
/// Callers must obtain it only while holding the outer TTY guard; the public
/// crate-level entry point enforcing that order lives in `tty`. After begin,
/// the surrounding publisher must put the record in `ManuallyDrop` before its
/// first call: every error retains the guard, while successful commit is the
/// sole method path that drains and releases it.
pub(crate) struct RawTxRecord {
    guard: Option<SpinGuard<'static, TxState>>,
    framing: RawRecordFraming,
}

impl RawTxRecord {
    pub(crate) fn begin(
        _permit: &crate::tty::RawTxOrderPermit<'_>,
    ) -> Result<Self, RawTxRecordError> {
        // Activity was armed while the outer TTY guard was already held. Put
        // TX in ManuallyDrop before inspecting framing so NotAtLineStart is a
        // permanent fail-stop just like every later framing error.
        let guard = ManuallyDrop::new(TX.lock());
        if !guard.at_line_start {
            return Err(RawTxRecordError::NotAtLineStart);
        }
        Ok(Self {
            guard: Some(ManuallyDrop::into_inner(guard)),
            framing: RawRecordFraming::NEW,
        })
    }

    fn release_after_commit(&mut self) {
        // Taking the guard restores exactly the interrupt state captured by
        // the nested TX acquisition. The TTY wrapper releases its outer guard
        // only after this method returns.
        drop(self.guard.take());
    }

    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> Result<(), RawTxRecordError> {
        if self.guard.is_none() {
            return Err(RawTxRecordError::Released);
        }
        // Do not release or mutate the record on error. The caller must
        // quarantine this still-guarded value instead of retrying it.
        let next = self.framing.append(bytes)?;
        let tx = self.guard.as_mut().expect("raw TX guard was checked above");
        for byte in bytes.iter().copied() {
            put_locked(tx, byte);
        }
        self.framing = next;
        Ok(())
    }

    pub(crate) fn commit_record(&mut self) -> Result<(), RawTxRecordError> {
        if self.guard.is_none() {
            return Err(RawTxRecordError::Released);
        }
        // A malformed record retains TX. This is a transcript failure, not a
        // recoverable opportunity to append or repair bytes.
        self.framing.validate_commit()?;

        wait_tx_fully_empty();
        debug_assert!(
            self.guard.as_ref().is_some_and(|guard| guard.at_line_start),
            "a committed raw UART record must end immediately after LF"
        );
        self.release_after_commit();
        Ok(())
    }
}

/// Called by the console IRQ handler registered during boot.
pub fn handle_irq() {
    use vibeos_hal::devices::ConsoleInterrupt;
    match (hardware().interrupt)() {
        ConsoleInterrupt::None => return,
        ConsoleInterrupt::BusyCleared => {
            DW_BUSY_IRQS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        ConsoleInterrupt::PhantomTimeoutCleared => {
            DW_PHANTOM_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        ConsoleInterrupt::Receive => {}
    }
    let mut received = false;
    while let Some(byte) = (hardware().read_byte)() {
        // SAFETY: the boot-hart top half remains the sole producer.
        unsafe { let _ = RX.push_from_producer(byte); }
        received = true;
    }
    if received { RX_WAIT.wake_all(); }
}

pub fn dw_irq_recoveries() -> (u64, u64) {
    (
        DW_BUSY_IRQS.load(Ordering::Relaxed),
        DW_PHANTOM_TIMEOUTS.load(Ordering::Relaxed),
    )
}

pub fn try_read() -> Option<u8> {
    // Safety: console input is owned by the one shell task.
    unsafe {
        RX.pop_from_consumer().or_else(|| {
            hardware().capabilities
                .usb_keyboard_input
                .then(|| USB_RX.pop_from_consumer())
                .flatten()
        })
    }
}

/// Inject one byte from the sole USB keyboard service. Overflow drops the
/// newest byte, matching the physical UART receive policy.
pub fn inject_usb_input(byte: u8) {
    if !hardware().capabilities.usb_keyboard_input {
        return;
    }
    let _ = unsafe { USB_RX.push_from_producer(byte) };
    RX_WAIT.wake_all();
}

pub fn variant_name() -> &'static str {
    hardware().description.variant.name()
}

#[allow(dead_code)]
pub fn rx_dropped() -> u64 {
    RX.dropped()
}

/// Await one byte from the console.
pub async fn read_byte() -> u8 {
    loop {
        // Prepare before inspecting RX so an IRQ between the check and the
        // first poll is observed through the wait queue's epoch.
        let ready = RX_WAIT.wait();
        if let Some(b) = try_read() {
            return b;
        }
        ready.await;
    }
}

pub struct Console;

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                put(b'\r');
            }
            put(b);
        }
        Ok(())
    }
}

/// Foreground output: erases and redraws an active prompt around itself.
pub fn _print(args: fmt::Arguments) {
    crate::tty::emit(args, false);
}

/// Background chatter from demo components; dropped while `quiet` is set.
pub fn _print_bg(args: fmt::Arguments) {
    crate::tty::emit(args, true);
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::uart::_print(format_args!($($arg)*)));
}

/// Like `println!`, but suppressible with the shell's `quiet` command.
#[macro_export]
macro_rules! bgprintln {
    ($($arg:tt)*) => ($crate::uart::_print_bg(format_args!("{}\n", format_args!($($arg)*))));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
