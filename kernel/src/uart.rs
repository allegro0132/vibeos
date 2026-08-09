//! 16550-compatible UART driver for the selected board.
//!
//! TX is synchronous (polled) because it is on the panic path. RX is
//! interrupt-driven: the trap handler fills a ring and wakes whichever task is
//! parked on `Uart::read_byte()`.

use core::fmt::{self, Write};
#[cfg(feature = "milkv-duo")]
use core::sync::atomic::{AtomicU64, Ordering};

use crate::exec::WaitQueue;
use crate::interrupt::SpscByteRing;
use crate::sync::SpinLock;

pub const UART_BASE: usize = crate::platform::UART_BASE;
pub const UART_IRQ: u32 = crate::platform::UART_IRQ;

const RBR: usize = 0; // read: receive buffer
const THR: usize = 0; // write: transmit holding
const IER: usize = 1; // interrupt enable
const IIR: usize = 2; // read: interrupt identification
const FCR: usize = 2; // FIFO control
const LCR: usize = 3; // line control
const LSR: usize = 5; // line status
#[cfg(feature = "milkv-duo")]
const DW_USR: usize = 0x1f; // DesignWare UART status register

const LSR_RX_READY: u8 = 1 << 0;
#[cfg(feature = "milkv-duo")]
const LSR_BREAK: u8 = 1 << 4;
const LSR_TX_IDLE: u8 = 1 << 5;
const LSR_TX_EMPTY: u8 = 1 << 6;
const IIR_NO_INTERRUPT: u8 = 1 << 0;
#[cfg(feature = "milkv-duo")]
const IIR_BUSY: u8 = 0x07;
#[cfg(feature = "milkv-duo")]
const IIR_RX_TIMEOUT: u8 = 0x0c;
#[cfg(feature = "milkv-duo")]
const DW_USR_BUSY: u8 = 1 << 0;

#[inline]
fn reg_address(off: usize) -> usize {
    UART_BASE + (off << crate::platform::UART_REG_SHIFT)
}

#[inline]
unsafe fn read_reg(off: usize) -> u8 {
    match crate::platform::UART_REG_WIDTH {
        1 => unsafe { (reg_address(off) as *const u8).read_volatile() },
        4 => unsafe { (reg_address(off) as *const u32).read_volatile() as u8 },
        _ => unreachable!("unsupported UART register width"),
    }
}

#[inline]
unsafe fn write_reg(off: usize, value: u8) {
    match crate::platform::UART_REG_WIDTH {
        1 => unsafe { (reg_address(off) as *mut u8).write_volatile(value) },
        4 => unsafe { (reg_address(off) as *mut u32).write_volatile(u32::from(value)) },
        _ => unreachable!("unsupported UART register width"),
    }
}

// TX remains locked because foreground output, background diagnostics, and the
// panic path can otherwise interleave bytes. It is a polled task/panic path,
// not part of RX IRQ buffering.
static TX: SpinLock<()> = SpinLock::new(());
// The PLIC UART top half is the sole producer and the shell is the sole
// consumer. Release/Acquire indices replace the former IRQ-side SpinLock;
// overflow drops the newest byte and increments `rx_dropped()`.
static RX: SpscByteRing<256> = SpscByteRing::new();
pub static RX_WAIT: WaitQueue = WaitQueue::new();
#[cfg(feature = "milkv-duo")]
static DW_BUSY_IRQS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "milkv-duo")]
static DW_PHANTOM_TIMEOUTS: AtomicU64 = AtomicU64::new(0);

pub fn init() {
    // Safety: boot initializes UART before enabling the PLIC source or
    // starting the sole shell consumer.
    unsafe { RX.reset_quiescent() };
    let baud_divisor = (u64::from(crate::platform::UART_CLOCK_HZ)
        + u64::from(crate::platform::UART_BAUD) * 8)
        / (u64::from(crate::platform::UART_BAUD) * 16);
    assert!(
        (1..=u16::MAX as u64).contains(&baud_divisor),
        "UART baud divisor is out of range"
    );
    unsafe {
        // U-Boot can leave its final byte in flight. DesignWare raises a
        // sticky busy-detect interrupt if LCR is changed before that transfer
        // completes, so quiesce it before touching the divisor.
        write_reg(IER, 0x00);
        while read_reg(LSR) & LSR_TX_EMPTY == 0 {
            core::hint::spin_loop();
        }
        #[cfg(feature = "milkv-duo")]
        while read_reg(DW_USR) & DW_USR_BUSY != 0 {
            core::hint::spin_loop();
        }
        write_reg(LCR, 0x80); // DLAB on
        write_reg(0, baud_divisor as u8);
        write_reg(1, (baud_divisor >> 8) as u8);
        write_reg(LCR, 0x03); // 8N1, DLAB off
        write_reg(FCR, 0x07); // enable + clear FIFOs
        #[cfg(feature = "milkv-duo")]
        {
            // Reading USR clears any busy-detect condition inherited from the
            // firmware or raised during the line-control transition above.
            let _ = read_reg(DW_USR);
        }
        write_reg(IER, 0x01); // receive-data-available interrupt
    }
}

/// Emit a boot marker before the normal console and MMU diagnostics exist.
///
/// U-Boot leaves UART0 enabled. This deliberately bypasses every lock and
/// queue so a failure while constructing or enabling the first page tables can
/// still be localized from the serial log. It is used only on the boot hart
/// before secondary harts or the executor can introduce another console
/// writer; one final marker may be emitted immediately after enabling IRQs.
#[cfg(feature = "milkv-duo")]
pub fn early_write(text: &str) {
    for byte in text.bytes() {
        unsafe {
            while read_reg(LSR) & LSR_TX_IDLE == 0 {
                core::hint::spin_loop();
            }
            write_reg(THR, byte);
        }
    }
    // Unlike ordinary console writes, the next early-boot operation may
    // reprogram LCR. Wait for both the FIFO and shift register to drain.
    unsafe {
        while read_reg(LSR) & LSR_TX_EMPTY == 0 {
            core::hint::spin_loop();
        }
    }
}

pub fn put(b: u8) {
    let _g = TX.lock();
    unsafe {
        while read_reg(LSR) & LSR_TX_IDLE == 0 {
            core::hint::spin_loop();
        }
        write_reg(THR, b);
    }
}

/// Called from the trap handler when the PLIC reports UART_IRQ.
pub fn handle_irq() {
    let mut received = false;
    unsafe {
        let iir = read_reg(IIR);
        #[cfg(feature = "milkv-duo")]
        if iir & 0x3f == IIR_BUSY {
            // DW APB busy detect is cleared only by reading USR. Merely
            // completing the level-triggered PLIC claim would immediately
            // reclaim IRQ 44 forever and starve the executor.
            let _ = read_reg(DW_USR);
            DW_BUSY_IRQS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if iir & IIR_NO_INTERRUPT != 0 {
            return;
        }
        #[cfg(feature = "milkv-duo")]
        if iir & 0x3f == IIR_RX_TIMEOUT {
            let status = read_reg(LSR);
            if status & (LSR_RX_READY | LSR_BREAK) == 0 {
                // DesignWare can assert RX timeout with an empty FIFO. Its
                // documented workaround is one harmless dummy RBR read.
                let _ = read_reg(RBR);
                DW_PHANTOM_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        while read_reg(LSR) & LSR_RX_READY != 0 {
            let b = read_reg(RBR);
            // Safety: the boot-hart UART top half is the ring's sole producer.
            // Failure is a counted newest-byte drop; draining the hardware
            // FIFO still prevents a level interrupt storm.
            let _ = RX.push_from_producer(b);
            received = true;
        }
    }
    if received {
        RX_WAIT.wake_all();
    }
}

#[cfg(feature = "milkv-duo")]
pub fn dw_irq_recoveries() -> (u64, u64) {
    (
        DW_BUSY_IRQS.load(Ordering::Relaxed),
        DW_PHANTOM_TIMEOUTS.load(Ordering::Relaxed),
    )
}

pub fn try_read() -> Option<u8> {
    // Safety: console input is owned by the one shell task.
    unsafe { RX.pop_from_consumer() }
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
