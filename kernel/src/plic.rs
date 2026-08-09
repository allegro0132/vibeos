//! SiFive PLIC as wired up by the QEMU `virt` machine, using the firmware-
//! selected boot hart's S-mode context.
//!
//! IRQ handlers live in a small, fixed-capacity atomic registry. Registration
//! never allocates. Dispatch takes one bounded sequence snapshot per slot and
//! never acquires a kernel lock before invoking component-independent top-half
//! code.

use crate::interrupt::{AtomicIrqHandlerSlot, IrqHandlerPublication};
use crate::sync::SpinLock;
use core::sync::atomic::{AtomicUsize, Ordering};

pub const PLIC_BASE: usize = 0x0c00_0000;

const PRIORITY: usize = PLIC_BASE;
const ENABLE_CONTEXTS: usize = PLIC_BASE + 0x2000;
const ENABLE_CONTEXT_STRIDE: usize = 0x80;
const CONTEXTS: usize = PLIC_BASE + 0x20_0000;
const CONTEXT_STRIDE: usize = 0x1000;
const CLAIM_OFFSET: usize = 4;
const UNINITIALIZED_CONTEXT: usize = usize::MAX;

// QEMU virt exposes M/S context pairs for each physical hart; VibeOS routes
// every external interrupt through the dynamically selected boot hart.
static BOOT_S_CONTEXT: AtomicUsize = AtomicUsize::new(UNINITIALIZED_CONTEXT);

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

/// Reset the boot physical hart's S-mode PLIC context to a fully masked state.
pub fn init(physical_hart: usize) {
    let context = physical_hart
        .checked_mul(2)
        .and_then(|context| context.checked_add(1))
        .expect("PLIC S-mode context index overflowed");
    BOOT_S_CONTEXT.store(context, Ordering::Release);
    let _writer = HANDLER_WRITER.lock();
    for slot in &HANDLERS {
        // Safety: HANDLER_WRITER is the sole registry writer and interrupts
        // have not been enabled while PLIC initialization runs.
        unsafe { slot.publish_exclusive(None) };
    }
    let _enable = ENABLE_LOCK.lock();
    unsafe {
        threshold_reg().write_volatile(0);
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
    (ENABLE_CONTEXTS + boot_context() * ENABLE_CONTEXT_STRIDE + word * core::mem::size_of::<u32>())
        as *mut u32
}

#[inline]
fn boot_context() -> usize {
    let context = BOOT_S_CONTEXT.load(Ordering::Acquire);
    assert_ne!(
        context, UNINITIALIZED_CONTEXT,
        "PLIC context used before boot initialization"
    );
    context
}

#[inline]
unsafe fn threshold_reg() -> *mut u32 {
    (CONTEXTS + boot_context() * CONTEXT_STRIDE) as *mut u32
}

#[inline]
unsafe fn claim_reg() -> *mut u32 {
    (CONTEXTS + boot_context() * CONTEXT_STRIDE + CLAIM_OFFSET) as *mut u32
}

pub fn claim() -> Option<u32> {
    let irq = unsafe { claim_reg().read_volatile() };
    (irq != 0).then_some(irq)
}

pub fn complete(irq: u32) {
    unsafe { claim_reg().write_volatile(irq) };
}
