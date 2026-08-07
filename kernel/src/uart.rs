//! NS16550A driver for the QEMU `virt` machine.
//!
//! TX is synchronous (polled) because it is on the panic path. RX is
//! interrupt-driven: the trap handler fills a ring and wakes whichever task is
//! parked on `Uart::read_byte()`.

use core::fmt::{self, Write};

use crate::exec::WaitQueue;
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

struct RxRing {
    buf: [u8; 256],
    head: usize,
    tail: usize,
}

impl RxRing {
    const fn new() -> Self {
        Self { buf: [0; 256], head: 0, tail: 0 }
    }
    fn push(&mut self, b: u8) {
        let next = (self.head + 1) % self.buf.len();
        if next != self.tail {
            self.buf[self.head] = b;
            self.head = next;
        }
    }
    fn pop(&mut self) -> Option<u8> {
        if self.head == self.tail {
            return None;
        }
        let b = self.buf[self.tail];
        self.tail = (self.tail + 1) % self.buf.len();
        Some(b)
    }
}

static TX: SpinLock<()> = SpinLock::new(());
static RX: SpinLock<RxRing> = SpinLock::new(RxRing::new());
pub static RX_WAIT: WaitQueue = WaitQueue::new();

pub fn init() {
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
    let mut woke = false;
    unsafe {
        while reg(LSR).read_volatile() & LSR_RX_READY != 0 {
            let b = reg(RBR).read_volatile();
            RX.lock().push(b);
            woke = true;
        }
    }
    if woke {
        RX_WAIT.wake_all();
    }
}

pub fn try_read() -> Option<u8> {
    RX.lock().pop()
}

/// Await one byte from the console.
pub async fn read_byte() -> u8 {
    loop {
        if let Some(b) = try_read() {
            return b;
        }
        RX_WAIT.wait().await;
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

pub fn _print(args: fmt::Arguments) {
    let _ = Console.write_fmt(args);
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::uart::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
