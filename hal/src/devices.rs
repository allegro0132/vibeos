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

/// Retire metadata for an owner that cannot resume, without running a driver
/// destructor that could race recovery or a replacement device incarnation.
/// This does not release DMA ownership or prove that hardware is quiescent.
///
/// # Safety
/// All prior users of this instance must be permanently unable to execute.
/// The caller must perform explicit hardware recovery, retaining DMA storage
/// and quarantine until reset is confirmed. Resources owned by T are leaked
/// deliberately: this function cannot be used for ordinary shutdown.
pub unsafe fn abandon_faulted_instance<T>(instance: &mut Option<T>) {
    if let Some(old) = instance.take() { core::mem::forget(old); }
}
#[cfg(test)]
mod instance_tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize,Ordering};
    #[test]
    fn fault_retirement_never_runs_old_destructor_during_replacement() {
        static DROPS:AtomicUsize=AtomicUsize::new(0);
        struct Instance;
        impl Drop for Instance {fn drop(&mut self){DROPS.fetch_add(1,Ordering::SeqCst);}}
        let mut slot=Some(Instance);
        unsafe{abandon_faulted_instance(&mut slot);}
        assert!(slot.is_none());assert_eq!(DROPS.load(Ordering::SeqCst),0);
        slot=Some(Instance);drop(slot);
        assert_eq!(DROPS.load(Ordering::SeqCst),1);
    }
}
