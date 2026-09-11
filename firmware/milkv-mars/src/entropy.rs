//! Static HAL assembly for the native PIO owner. Discovery never approves this
//! source. The boot diagnostic invokes the table directly before kernel claims.
use core::{cell::UnsafeCell, sync::atomic::{AtomicU8, Ordering}};
use vibeos_hal::{device_transport::Descriptor, entropy::{Backing, CompletionMode,
    DiscoveredSource, EntropyDevice, Error, Events, SourceApproval}};
use super::NativeEntropyInstance;

struct Storage(UnsafeCell<Option<NativeEntropyInstance>>);
// Only the unique claim holder invokes engine callbacks. IRQ/quiesce callbacks
// never borrow this storage; boot installation finishes before secondary harts.
unsafe impl Sync for Storage {}
static STORAGE: Storage = Storage(UnsafeCell::new(None));
static INSTALLED: AtomicU8 = AtomicU8::new(0);
pub const POLL_BUDGET: usize = 100_000;

/// # Safety
/// Boot hart only, before any table invocation. The instance owns the complete
/// SEC domain and must remain exclusively accessible through this table. Caller
/// must not install a second owner; failed hardware ownership stays here forever.
pub unsafe fn install(instance: NativeEntropyInstance) {
    assert_eq!(INSTALLED.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire), Ok(0));
    *STORAGE.0.get() = Some(instance);
    INSTALLED.store(2, Ordering::Release);
}
unsafe fn read() -> Result<&'static NativeEntropyInstance, Error> {
    if INSTALLED.load(Ordering::Acquire) != 2 { return Err(Error::Unsupported); }
    (&*STORAGE.0.get()).as_ref().ok_or(Error::Unsupported)
}
unsafe fn write() -> Result<&'static mut NativeEntropyInstance, Error> {
    if INSTALLED.load(Ordering::Acquire) != 2 { return Err(Error::Unsupported); }
    (&mut *STORAGE.0.get()).as_mut().ok_or(Error::Unsupported)
}
fn identity(slot: usize, base: usize) -> bool {
    super::entropy_description().is_some_and(|d| d.slot == slot && d.base == base)
}
fn budget(value: usize) -> Result<(), Error> {
    // Native waits have fixed timer/poll bounds. Reject smaller caller budgets
    // instead of silently exceeding them; larger values do not extend waits.
    if value < POLL_BUDGET { Err(Error::Unsupported) } else { Ok(()) }
}
pub const DEVICE: EntropyDevice = EntropyDevice {
    discover: || Some(DiscoveredSource {
        endpoint: super::entropy_description()?,
        approval: SourceApproval::DiagnosticOnly,
    }),
    resource_kind: "starfive-trng",
    transport_name: "JH7110 TRNG PIO",
    // Shared SEC reset requires a known exclusive CPU owner. With inconsistent
    // ownership we cannot safely reset this domain, or borrow/drop its state.
    quiesce: |_: Descriptor, _| false,
    completion_mode: CompletionMode::Polling,
    queue_size: 1,
    backing: Backing::DriverOwned,
    prepare: |slot, base, epoch, limit| unsafe {
        if !identity(slot, base) { return Err(Error::Unsupported); }
        budget(limit)?;
        write()?.prepare(epoch)
    },
    start: || unsafe { if read()?.operational() { Ok(()) } else { Err(Error::DriverRestarted) } },
    epoch: || unsafe { read().map_or(0, |i| i.epoch()) },
    accepted_features: || 0,
    operational: || unsafe { read().is_ok_and(|i| i.operational()) },
    submit: |bytes| unsafe { write()?.submit(bytes) },
    completion: |token| unsafe { read().is_ok_and(|i| i.completion(token)) },
    finish: |token, out| unsafe { write()?.finish(token, out) },
    require_reset: || unsafe { if let Ok(i) = write() { i.require_reset(); } },
    reset_and_prepare: |epoch, limit| unsafe { budget(limit)?; write()?.reset_and_prepare(epoch) },
    shutdown: |limit| unsafe { budget(limit)?; write()?.shutdown() },
    confirmed_reset: |slot, base, limit| unsafe {
        if !identity(slot, base) || budget(limit).is_err() { return false; }
        // Retire hardware using the same owner, retaining serial/history state.
        // HAL requires the caller to exclude every old engine before this call.
        write().is_ok_and(|i| i.shutdown().is_ok())
    },
    // Polling owns ISTAT. An unrelated/spurious IRQ must not consume its events.
    acknowledge: |_| Events::default(),
};
