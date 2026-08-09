//! SiFive PLIC as wired up by the QEMU `virt` machine, hart 0 / S-mode context.
//!
//! IRQ handlers live in a small, fixed-capacity atomic registry. Registration
//! never allocates. Dispatch takes one bounded sequence snapshot per slot and
//! never acquires a kernel lock before invoking component-independent top-half
//! code.

use crate::interrupt::{AtomicIrqHandlerSlot, IrqHandlerPublication};
use crate::sync::SpinLock;

pub const PLIC_BASE: usize = 0x0c00_0000;

const PRIORITY: usize = PLIC_BASE;
const ENABLE_S: usize = PLIC_BASE + 0x2080; // hart 0, S-mode
const THRESHOLD_S: usize = PLIC_BASE + 0x20_1000;
const CLAIM_S: usize = PLIC_BASE + 0x20_1004;

// A PLIC context owns 0x80 bytes of enable words on QEMU `virt`: 32 words,
// covering source IDs 0..=1023. Source zero is reserved as "no interrupt".
const ENABLE_WORDS: usize = crate::interrupt::PLIC_ENABLE_WORDS;
pub const MAX_HANDLERS: usize = 16;

/// Allocation-free top-half callback. `context` is the value supplied during
/// registration; `irq_entry` is the cycle timestamp captured by trap entry.
pub type IrqHandler = fn(context: usize, irq_entry: u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisterError {
    InvalidIrq,
    AlreadyRegistered,
    RegistryFull,
}

const _: () = assert!(core::mem::size_of::<IrqHandler>() == core::mem::size_of::<usize>());

static HANDLERS: [AtomicIrqHandlerSlot; MAX_HANDLERS] =
    [const { AtomicIrqHandlerSlot::new() }; MAX_HANDLERS];
// Only task-side publishers take this lock. IRQ dispatch never waits on it.
// Besides serializing slot writers, masking local interrupts means the boot
// hart cannot observe its own odd in-progress sequence.
static HANDLER_WRITER: SpinLock<()> = SpinLock::new(());
// Serializes enable-word read/modify/write operations. The lock also masks
// local interrupts, so two task-side source updates cannot lose a bit. It is
// deliberately absent from claim, dispatch, and completion.
static ENABLE_LOCK: SpinLock<()> = SpinLock::new(());

/// Reset this S-mode PLIC context to a known, fully masked state.
pub fn init() {
    let _writer = HANDLER_WRITER.lock();
    for slot in &HANDLERS {
        // Safety: HANDLER_WRITER is the sole registry writer and interrupts
        // have not been enabled while PLIC initialization runs.
        unsafe { slot.publish_exclusive(None) };
    }
    let _enable = ENABLE_LOCK.lock();
    unsafe {
        (THRESHOLD_S as *mut u32).write_volatile(0);
        for word in 0..ENABLE_WORDS {
            enable_reg(word).write_volatile(0);
        }
    }
}

/// Register a handler without enabling its interrupt source.
///
/// Keeping registration and enabling separate lets callers finish device
/// initialization before the first top half can run.
pub fn register(irq: u32, handler: IrqHandler, context: usize) -> Result<(), RegisterError> {
    crate::interrupt::plic_enable_location(irq).ok_or(RegisterError::InvalidIrq)?;

    let _writer = HANDLER_WRITER.lock();
    if HANDLERS.iter().any(|slot| {
        slot.try_snapshot()
            .expect("serialized handler slot cannot be updating")
            .is_some_and(|entry| entry.irq == irq)
    }) {
        return Err(RegisterError::AlreadyRegistered);
    }
    let Some(slot) = HANDLERS.iter().find(|slot| {
        slot.try_snapshot()
            .expect("serialized handler slot cannot be updating")
            .is_none()
    }) else {
        return Err(RegisterError::RegistryFull);
    };
    // Safety: HANDLER_WRITER serializes every slot mutation. The Release
    // publication makes the callback and context visible as one record.
    unsafe {
        slot.publish_exclusive(Some(IrqHandlerPublication {
            irq,
            callback: handler as usize,
            context,
        }))
    };
    Ok(())
}

/// Mask an IRQ and remove its handler. Returns whether a handler was present.
pub fn unregister(irq: u32) -> bool {
    // Mask first. If an interrupt was already claimed, trap dispatch can still
    // observe either the old handler or no handler; both paths complete it.
    let _ = disable(irq);
    let _writer = HANDLER_WRITER.lock();
    if let Some(slot) = HANDLERS.iter().find(|slot| {
        slot.try_snapshot()
            .expect("serialized handler slot cannot be updating")
            .is_some_and(|entry| entry.irq == irq)
    }) {
        // Safety: HANDLER_WRITER serializes every slot mutation. A dispatch
        // which already copied the old record may still finish, matching the
        // pre-existing mask-before-remove contract.
        unsafe { slot.publish_exclusive(None) };
        true
    } else {
        false
    }
}

/// Invoke a registered top half without acquiring or spinning on a lock.
pub fn dispatch(irq: u32, irq_entry: u64) -> bool {
    let mut writer_observed = false;
    for slot in &HANDLERS {
        match slot.try_snapshot() {
            Ok(Some(entry)) if entry.irq == irq => {
                // Safety: register stored this address from `IrqHandler`, and
                // the compile-time assertion above proves the representations
                // have equal size on this kernel target.
                let handler = unsafe { core::mem::transmute::<usize, IrqHandler>(entry.callback) };
                handler(entry.context, irq_entry);
                return true;
            }
            Ok(_) => {}
            Err(_) => writer_observed = true,
        }
    }

    // Do not permanently mask a source merely because a remote publisher was
    // between its odd/even sequence samples. Completing this claim lets a
    // level source retrigger after the bounded publication finishes.
    writer_observed
}

pub fn enable(irq: u32) -> Result<(), RegisterError> {
    set_enabled(irq, true)
}

pub fn disable(irq: u32) -> Result<(), RegisterError> {
    set_enabled(irq, false)
}

fn set_enabled(irq: u32, enabled: bool) -> Result<(), RegisterError> {
    let (word, bit) =
        crate::interrupt::plic_enable_location(irq).ok_or(RegisterError::InvalidIrq)?;
    let _enable = ENABLE_LOCK.lock();
    unsafe {
        let reg = enable_reg(word);
        let current = reg.read_volatile();
        let mask = 1u32 << bit;
        reg.write_volatile(if enabled {
            current | mask
        } else {
            current & !mask
        });
        // A source only needs a non-zero priority to pass threshold zero.
        if enabled {
            ((PRIORITY + irq as usize * 4) as *mut u32).write_volatile(1);
        }
    }
    Ok(())
}

#[inline]
unsafe fn enable_reg(word: usize) -> *mut u32 {
    (ENABLE_S + word * core::mem::size_of::<u32>()) as *mut u32
}

pub fn claim() -> Option<u32> {
    let irq = unsafe { (CLAIM_S as *mut u32).read_volatile() };
    (irq != 0).then_some(irq)
}

pub fn complete(irq: u32) {
    unsafe { (CLAIM_S as *mut u32).write_volatile(irq) };
}
