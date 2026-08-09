//! Lock-free runnable-reason mailboxes and SBI IPI doorbells.
//!
//! A ready queue is the source of truth. After publishing work there, the
//! executor sets the target hart's reason bit with `Release`. Reason bits and
//! the kick-armed bit share one atomic word, so the receiver's `Acquire` swap
//! releases a doorbell and consumes its reasons at one linearization point.
//! The receiver clears SSIP and executes an I/O fence before that swap; this
//! prevents a late CSR clear from erasing a concurrent publisher's new kick.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::arch;
use crate::runqueue::{HartId, MAX_HARTS};

/// At least one runnable task was published for this hart.
pub const REASON_RUNNABLE: usize = 1 << 0;
const REASON_MASK: usize = REASON_RUNNABLE;
const KICK_ARMED: usize = 1usize << (usize::BITS as usize - 1);
const UNMAPPED_HART: usize = usize::MAX;

static MAILBOXES: [AtomicUsize; MAX_HARTS] = [const { AtomicUsize::new(0) }; MAX_HARTS];
static ONLINE_HARTS: AtomicUsize = AtomicUsize::new(0);
static PHYSICAL_HART_IDS: [AtomicUsize; MAX_HARTS] =
    [const { AtomicUsize::new(UNMAPPED_HART) }; MAX_HARTS];
// Mapping uniqueness spans the complete logical-hart table and cannot be
// committed with one atomic RMW. This cold boot-only gate serializes the scan
// plus reservation; callers mask local IRQs before taking it, so an interrupt
// cannot re-enter registration while its hart owns the gate.
static REGISTRATION_GATE: AtomicBool = AtomicBool::new(false);
static NOTIFICATIONS: [AtomicU64; MAX_HARTS] = [const { AtomicU64::new(0) }; MAX_HARTS];
static DOORBELLS: [AtomicU64; MAX_HARTS] = [const { AtomicU64::new(0) }; MAX_HARTS];
static SEND_FAILURES: [AtomicU64; MAX_HARTS] = [const { AtomicU64::new(0) }; MAX_HARTS];
static ACKNOWLEDGED: [AtomicU64; MAX_HARTS] = [const { AtomicU64::new(0) }; MAX_HARTS];
static IDLE_CONSUMED: [AtomicU64; MAX_HARTS] = [const { AtomicU64::new(0) }; MAX_HARTS];
static STALE: [AtomicU64; MAX_HARTS] = [const { AtomicU64::new(0) }; MAX_HARTS];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HartIpiStats {
    pub pending_reasons: usize,
    pub notifications: u64,
    pub doorbells: u64,
    pub send_failures: u64,
    pub acknowledged: u64,
    pub idle_consumed: u64,
    pub stale: u64,
    pub online: bool,
    pub physical_hart_id: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DoorbellDisposition {
    Sent,
    /// The target is the currently executing hart, which is already awake.
    Local,
    Coalesced,
    Offline,
    Failed(arch::IpiError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnlineDisposition {
    AlreadyOnline,
    OnlineIdle,
    Pending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnlineError {
    InvalidPhysicalHart,
    NotCurrentPhysicalHart,
    LogicalHartRemapped,
    PhysicalHartAlreadyMapped,
}

struct RegistrationGuard;

impl Drop for RegistrationGuard {
    fn drop(&mut self) {
        REGISTRATION_GATE.store(false, Ordering::Release);
    }
}

fn lock_registration() -> RegistrationGuard {
    while REGISTRATION_GATE
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    RegistrationGuard
}

const fn hart_bit(hart: HartId) -> usize {
    1usize << hart.index()
}

fn physical_hart_id(hart: HartId) -> Option<usize> {
    match PHYSICAL_HART_IDS[hart.index()].load(Ordering::Acquire) {
        UNMAPPED_HART => None,
        physical => Some(physical),
    }
}

/// Reserve one unique logical-to-physical mapping before issuing HSM start.
///
/// Reservation does not publish the hart as online and therefore cannot cause
/// an IPI to target a hart whose SBI start is merely pending. Repeating the
/// same reservation is idempotent, which lets callers retry an asynchronous
/// startup sequence without weakening a previously validated mapping.
pub fn prepare_start(hart: HartId, physical_hart: usize) -> Result<(), OnlineError> {
    if physical_hart == UNMAPPED_HART {
        return Err(OnlineError::InvalidPhysicalHart);
    }
    let irq = arch::irq_save();
    let result = (|| {
        let _registration = lock_registration();
        bind_physical_hart(hart, physical_hart)
    })();
    arch::irq_restore(irq);
    result
}

/// Bind `hart` while the global registration gate is held.
fn bind_physical_hart(hart: HartId, physical_hart: usize) -> Result<(), OnlineError> {
    for index in 0..MAX_HARTS {
        if index != hart.index()
            && PHYSICAL_HART_IDS[index].load(Ordering::Acquire) == physical_hart
        {
            return Err(OnlineError::PhysicalHartAlreadyMapped);
        }
    }

    let mapping = &PHYSICAL_HART_IDS[hart.index()];
    if let Err(previous) = mapping.compare_exchange(
        UNMAPPED_HART,
        physical_hart,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        if previous != physical_hart {
            return Err(OnlineError::LogicalHartRemapped);
        }
    }
    Ok(())
}

/// Logical scheduler identity bound to the currently executing physical hart.
#[inline(always)]
pub fn current_logical_hart() -> Option<HartId> {
    if let Some(index) = arch::cached_logical_hart_index() {
        return HartId::new(index);
    }

    // On target, a zero per-hart token means this CPU has not completed its
    // own registration. Never borrow a controller-published mapping for a
    // secondary that has not initialized its local stack/trap/runtime state.
    #[cfg(target_arch = "riscv64")]
    return None;

    #[cfg(not(target_arch = "riscv64"))]
    {
        let physical = arch::current_hart_id();
        (0..MAX_HARTS).find_map(|index| {
            let logical = HartId::new(index).expect("mailbox index is a logical hart");
            (is_online(logical) && physical_hart_id(logical) == Some(physical)).then_some(logical)
        })
    }
}

/// Send one already-armed doorbell. Failure releases the armed bit while
/// retaining every reason, so a later publication or explicit retry may kick
/// the exact same work again.
fn ring_armed(hart: HartId) -> DoorbellDisposition {
    let Some(physical) = physical_hart_id(hart) else {
        MAILBOXES[hart.index()].fetch_and(!KICK_ARMED, Ordering::Release);
        return DoorbellDisposition::Offline;
    };
    DOORBELLS[hart.index()].fetch_add(1, Ordering::Relaxed);
    // RVWMO does not make an ecall a memory barrier. Order the ready-queue
    // publication and Release reason before firmware makes SSIP visible.
    arch::fence_ipi();
    match arch::send_ipi(physical) {
        Ok(()) => DoorbellDisposition::Sent,
        Err(error) => {
            SEND_FAILURES[hart.index()].fetch_add(1, Ordering::Relaxed);
            MAILBOXES[hart.index()].fetch_and(!KICK_ARMED, Ordering::Release);
            DoorbellDisposition::Failed(error)
        }
    }
}

fn arm_and_ring(hart: HartId, force_local: bool) -> DoorbellDisposition {
    if !is_online(hart) || physical_hart_id(hart).is_none() {
        return DoorbellDisposition::Offline;
    }
    if !force_local && current_logical_hart() == Some(hart) {
        return DoorbellDisposition::Local;
    }

    let mailbox = &MAILBOXES[hart.index()];
    loop {
        let state = mailbox.load(Ordering::Acquire);
        if state & REASON_MASK == 0 || state & KICK_ARMED != 0 {
            return DoorbellDisposition::Coalesced;
        }
        if mailbox
            .compare_exchange_weak(
                state,
                state | KICK_ARMED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            return ring_armed(hart);
        }
    }
}

/// Publish a runnable reason after work is visible in the target ready queue.
///
/// This function is allocation-free and lock-free. Offline harts retain their
/// reason without issuing an invalid SBI request. Repeated publications
/// coalesce behind an armed kick; if a send fails, clearing only `KICK_ARMED`
/// lets the next publication retry without losing the reason.
pub fn publish_runnable(hart: HartId) -> DoorbellDisposition {
    NOTIFICATIONS[hart.index()].fetch_add(1, Ordering::Relaxed);
    MAILBOXES[hart.index()].fetch_or(REASON_RUNNABLE, Ordering::Release);
    arm_and_ring(hart, false)
}

/// Executor ready-notification hook.
pub fn notify_ready(hart: HartId) {
    if let DoorbellDisposition::Failed(error) = publish_runnable(hart) {
        // An online physical hart with a valid mapping must be reachable. A
        // firmware failure here is kernel infrastructure state, not a
        // component fault; fail-stop without entering the task panic guard.
        #[cfg(target_arch = "riscv64")]
        {
            let _ = error;
            arch::shutdown(true);
        }
        #[cfg(not(target_arch = "riscv64"))]
        panic!("host IPI notification failed: {error:?}");
    }
}

/// Bind one logical scheduler hart to the current physical hart supplied by SBI.
///
/// HSM start is asynchronous, so the boot hart must not publish a secondary as
/// online merely because `hart_start` returned success. The secondary calls
/// this after installing its own stack and trap state; requiring physical
/// self-registration makes that call the completion side of the startup
/// handshake. A pending offline publication is then consumed by the newly
/// awake hart before its first WFI. Not ringing during this transition avoids
/// a duplicate kick if a publisher races online state.
pub fn mark_online(hart: HartId, physical_hart: usize) -> Result<OnlineDisposition, OnlineError> {
    // `usize::MAX` is both our unmapped sentinel and SBI's special all-harts
    // base. Neither can identify one schedulable physical hart.
    if physical_hart == UNMAPPED_HART {
        return Err(OnlineError::InvalidPhysicalHart);
    }
    // Mapping publication and this hart's CSR token form one local
    // registration transaction. A pending IRQ cannot observe the target
    // halfway through its first identity install.
    let irq = arch::irq_save();
    let result = (|| {
        if arch::current_hart_id() != physical_hart {
            return Err(OnlineError::NotCurrentPhysicalHart);
        }
        let _registration = lock_registration();
        bind_physical_hart(hart, physical_hart)?;

        let bit = hart_bit(hart);
        let already_online = ONLINE_HARTS.fetch_or(bit, Ordering::AcqRel) & bit != 0;
        // This per-hart CSR cache turns allocation and poll hot paths into one
        // register read. Safety: the current-physical-hart check plus mapping
        // conflict checks prove that this CPU owns exactly this logical slot.
        unsafe { arch::cache_logical_hart_index(hart.index()) };
        if already_online {
            return Ok(OnlineDisposition::AlreadyOnline);
        }
        if pending_reasons(hart) == 0 {
            Ok(OnlineDisposition::OnlineIdle)
        } else {
            Ok(OnlineDisposition::Pending)
        }
    })();
    arch::irq_restore(irq);
    result
}

pub fn is_online(hart: HartId) -> bool {
    ONLINE_HARTS.load(Ordering::Acquire) & hart_bit(hart) != 0
}

/// Snapshot reason bits for diagnostics. The internal armed bit is hidden.
pub fn pending_reasons(hart: HartId) -> usize {
    MAILBOXES[hart.index()].load(Ordering::Acquire) & REASON_MASK
}

pub fn has_pending(hart: HartId) -> bool {
    pending_reasons(hart) != 0
}

pub fn stats(hart: HartId) -> HartIpiStats {
    HartIpiStats {
        pending_reasons: pending_reasons(hart),
        notifications: NOTIFICATIONS[hart.index()].load(Ordering::Acquire),
        doorbells: DOORBELLS[hart.index()].load(Ordering::Acquire),
        send_failures: SEND_FAILURES[hart.index()].load(Ordering::Acquire),
        acknowledged: ACKNOWLEDGED[hart.index()].load(Ordering::Acquire),
        idle_consumed: IDLE_CONSUMED[hart.index()].load(Ordering::Acquire),
        stale: STALE[hart.index()].load(Ordering::Acquire),
        online: is_online(hart),
        physical_hart_id: physical_hart_id(hart),
    }
}

/// Consume a reason while interrupts are masked at the executor idle gate.
///
/// Work stolen or cancelled after publication must not leave a permanently
/// nonzero mailbox that turns the idle loop into a busy loop. Consuming a
/// nonzero reason forces this iteration to return without WFI; the ready queue
/// remains the source of truth. A delivered SSIP arriving later is stale.
pub fn take_idle_reasons(hart: HartId) -> usize {
    let reasons = MAILBOXES[hart.index()].swap(0, Ordering::Acquire) & REASON_MASK;
    if reasons != 0 {
        IDLE_CONSUMED[hart.index()].fetch_add(1, Ordering::Relaxed);
    }
    reasons
}

/// Acknowledge one supervisor-software interrupt on the current physical hart.
///
/// The CSR clear deliberately precedes the fence and mailbox swap. This path
/// performs no allocation, polling, or locking; returning to the executor is
/// the only scheduling action.
pub fn acknowledge_current() -> usize {
    arch::clear_software_interrupt();
    arch::fence_ipi();
    let Some(hart) = current_logical_hart() else {
        return 0;
    };
    let reasons = MAILBOXES[hart.index()].swap(0, Ordering::Acquire) & REASON_MASK;
    if reasons == 0 {
        STALE[hart.index()].fetch_add(1, Ordering::Relaxed);
    } else {
        ACKNOWLEDGED[hart.index()].fetch_add(1, Ordering::Relaxed);
    }
    reasons
}

/// Force a kick for pending work, including a deliberate self-IPI acceptance
/// probe or recovery after an observed transport failure.
pub fn retry_pending(hart: HartId) -> DoorbellDisposition {
    if !has_pending(hart) {
        return DoorbellDisposition::Coalesced;
    }
    arm_and_ring(hart, true)
}

/// Reset global state for deterministic host integration tests.
#[cfg(not(target_arch = "riscv64"))]
pub fn reset_test_state() {
    REGISTRATION_GATE.store(false, Ordering::Release);
    ONLINE_HARTS.store(0, Ordering::Release);
    for index in 0..MAX_HARTS {
        MAILBOXES[index].store(0, Ordering::Release);
        PHYSICAL_HART_IDS[index].store(UNMAPPED_HART, Ordering::Release);
        NOTIFICATIONS[index].store(0, Ordering::Release);
        DOORBELLS[index].store(0, Ordering::Release);
        SEND_FAILURES[index].store(0, Ordering::Release);
        ACKNOWLEDGED[index].store(0, Ordering::Release);
        IDLE_CONSUMED[index].store(0, Ordering::Release);
        STALE[index].store(0, Ordering::Release);
    }
    arch::reset_ipi_test_state();
}
