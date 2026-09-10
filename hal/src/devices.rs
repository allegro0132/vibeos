//! Statically linked firmware/device contracts. This is a Rust link contract,
//! not a dynamically loadable or stable binary ABI. The firmware owns every
//! instance; the kernel owns serialization, IRQ publication and scheduling.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleInterrupt {
    None,
    Receive,
    BusyCleared,
    PhantomTimeoutCleared,
}

/// All callbacks refer to the same firmware-owned console. TX calls are
/// serialized by the kernel; RX is consumed only by the boot-hart top half.
pub struct ConsoleOps {
    pub description: crate::UartDescription,
    pub capabilities: crate::ConsoleCapabilities,
    pub init: fn(),
    pub write_byte: fn(u8),
    pub drain: fn(),
    pub interrupt: fn() -> ConsoleInterrupt,
    pub read_byte: fn() -> Option<u8>,
}

/// Controller operations are separate from the kernel's handler registry.
/// The kernel serializes enable-word updates and assigns physical contexts.
pub struct InterruptControllerOps {
    pub description: crate::PlicDescription,
    pub supervisor_context: fn(usize) -> Option<usize>,
    pub init_context: fn(usize),
    pub set_enabled: fn(usize, u32, bool),
    pub claim: fn(usize) -> Option<u32>,
    pub complete: fn(usize, u32),
}

/// Present in read-only storage before the heap, MMU or secondary harts exist.
pub struct EarlyDevices {
    pub console: ConsoleOps,
    pub interrupts: InterruptControllerOps,
}

extern "Rust" {
    static VIBEOS_EARLY_DEVICES: EarlyDevices;
}

/// Firmware must define the immutable table and retain its instances for the
/// entire boot. Linking without a firmware composition fails, rather than
/// silently selecting a hardware backend inside the kernel.
pub fn early_devices() -> &'static EarlyDevices {
    // SAFETY: a single final firmware provides the immutable Rust static.
    unsafe { &VIBEOS_EARLY_DEVICES }
}
