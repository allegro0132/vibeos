//! SiFive PLIC as wired up by the QEMU `virt` machine, hart 0 / S-mode context.
//!
//! IRQ handlers live in a small, fixed-capacity registry. Registration never
//! allocates, and dispatch copies the handler plus its context out of the
//! registry before invoking it. A handler can therefore register/unregister
//! IRQs without recursively acquiring the registry lock.

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

#[derive(Clone, Copy)]
struct HandlerSlot {
    irq: u32,
    handler: IrqHandler,
    context: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisterError {
    InvalidIrq,
    AlreadyRegistered,
    RegistryFull,
}

static HANDLERS: SpinLock<[Option<HandlerSlot>; MAX_HANDLERS]> =
    SpinLock::new([None; MAX_HANDLERS]);
// Serializes enable-word read/modify/write operations. The lock also masks
// local interrupts, so task-side registration cannot lose an IRQ-side mask.
static ENABLE_LOCK: SpinLock<()> = SpinLock::new(());

/// Reset this S-mode PLIC context to a known, fully masked state.
pub fn init() {
    *HANDLERS.lock() = [None; MAX_HANDLERS];
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
pub fn register(
    irq: u32,
    handler: IrqHandler,
    context: usize,
) -> Result<(), RegisterError> {
    crate::interrupt::plic_enable_location(irq).ok_or(RegisterError::InvalidIrq)?;

    let mut handlers = HANDLERS.lock();
    if handlers.iter().flatten().any(|slot| slot.irq == irq) {
        return Err(RegisterError::AlreadyRegistered);
    }
    let Some(slot) = handlers.iter_mut().find(|slot| slot.is_none()) else {
        return Err(RegisterError::RegistryFull);
    };
    *slot = Some(HandlerSlot { irq, handler, context });
    Ok(())
}

/// Mask an IRQ and remove its handler. Returns whether a handler was present.
pub fn unregister(irq: u32) -> bool {
    // Mask first. If an interrupt was already claimed, trap dispatch can still
    // observe either the old handler or no handler; both paths complete it.
    let _ = disable(irq);
    let mut handlers = HANDLERS.lock();
    if let Some(slot) = handlers
        .iter_mut()
        .find(|slot| slot.is_some_and(|entry| entry.irq == irq))
    {
        *slot = None;
        true
    } else {
        false
    }
}

/// Invoke a registered top half. The registry lock is dropped before calling
/// component code, so handlers never execute while a kernel lock is held.
pub fn dispatch(irq: u32, irq_entry: u64) -> bool {
    let target = {
        let handlers = HANDLERS.lock();
        handlers
            .iter()
            .flatten()
            .find(|slot| slot.irq == irq)
            .map(|slot| (slot.handler, slot.context))
    };

    if let Some((handler, context)) = target {
        handler(context, irq_entry);
        true
    } else {
        false
    }
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
