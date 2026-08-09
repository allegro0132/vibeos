//! NS16550A driver for the QEMU `virt` machine.
//!
//! TX is synchronous (polled) because it is on the panic path. RX is
//! interrupt-driven: the trap handler fills a ring and wakes whichever task is
//! parked on `Uart::read_byte()`.

use core::fmt::{self, Write};

use crate::exec::WaitQueue;
use crate::interrupt::SpscByteRing;
use crate::sync::SpinLock;

pub const UART_BASE: usize = 0x1000_0000;
pub const UART_IRQ: u32 = 10;

const RBR: usize = 0; // read: receive buffer
const THR: usize = 0; // write: transmit holding
const IER: usize = 1; // interrupt enable
const FCR: usize = 2; // FIFO control
const LCR: usize = 3; // line control
const LSR: usize = 5; // line status

const LSR_RX_READY: u8 = 1 << 0;
const LSR_TX_IDLE: u8 = 1 << 5;

#[inline]
unsafe fn reg(off: usize) -> *mut u8 {
    (UART_BASE + off) as *mut u8
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

pub fn init() {
    // Safety: boot initializes UART before enabling the PLIC source or
    // starting the sole shell consumer.
    unsafe { RX.reset_quiescent() };
    unsafe {
        reg(LCR).write_volatile(0x80); // DLAB on
        reg(0).write_volatile(0x03); // divisor low  -> 38400 baud @ 1.8432 MHz
        reg(1).write_volatile(0x00); // divisor high
        reg(LCR).write_volatile(0x03); // 8N1, DLAB off
        reg(FCR).write_volatile(0x07); // enable + clear FIFOs
        reg(IER).write_volatile(0x01); // receive-data-available interrupt
    }
}

pub fn put(b: u8) {
    let _g = TX.lock();
    unsafe {
        while reg(LSR).read_volatile() & LSR_TX_IDLE == 0 {
            core::hint::spin_loop();
        }
        reg(THR).write_volatile(b);
    }
}

/// Called from the trap handler when the PLIC reports UART_IRQ.
pub fn handle_irq() {
    let mut received = false;
    unsafe {
        while reg(LSR).read_volatile() & LSR_RX_READY != 0 {
            let b = reg(RBR).read_volatile();
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
