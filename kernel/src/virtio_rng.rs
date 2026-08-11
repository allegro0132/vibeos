//! Capability-gated modern virtio-rng backend for the QEMU `virt` machine.
//!
//! Entropy crosses the component boundary only as a bounded value. Client
//! pointers never enter a descriptor: the device can write solely into the
//! fixed SYSTEM-owned DMA slab below. Every invocation is fallible, retains its
//! non-cloneable capability lease until completion, and either returns exactly
//! the requested byte count or no bytes at all.
//!
//! This whole module is QEMU-only. In particular, the Milk-V Duo build gets no
//! synthetic provider from this file; SSH must remain disabled there until a
//! separately validated hardware source exists.

#![cfg(feature = "qemu-virt")]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::cell::UnsafeCell;
use core::future::{poll_fn, Future};
use core::pin::pin;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::task::Poll;

use crate::cap::{Cap, InvocationLease, Resource, Revocable, Rights};
use crate::exec::{self, WaitQueue};
use crate::heap::{AllocationDomain, ArenaId};
use crate::plic;
use crate::sync::SpinLock;
use crate::virtio::{
    self, AvailableRing, Descriptor, ModernInit, UsedElement, UsedRing, DESC_F_WRITE,
    SPLIT_QUEUE_SIZE,
};
use crate::virtio_mmio::MmioTransport;
use crate::world::Space;

const ENTROPY_QUEUE: u16 = 0;
const ENTROPY_DESCRIPTOR: u16 = 0;
const RESET_POLL_BUDGET: usize = 100_000;
const REQUEST_TIMEOUT_MS: u64 = 2_000;
const INTERRUPT_STATUS_OFFSET: usize = 0x060;
const INTERRUPT_ACK_OFFSET: usize = 0x064;

/// One invocation can request at most this many bytes.
///
/// The bound limits DMA exposure, queue work, per-client kernel state, and the
/// amount of entropy copied through a capability invocation.
pub const MAX_RANDOM_BYTES: usize = 64;
const DMA_BYTES: usize = core::mem::size_of::<DmaSlab>();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomError {
    Offline,
    InvalidLength,
    Busy,
    TimedOut,
    DriverCancelled,
    DriverFault,
    DriverRestarted,
    Protocol,
    Unsupported,
    Quarantined,
    AuthorityRevoked,
    PermissionDenied,
    IdentityExhausted,
}

impl core::fmt::Display for RandomError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Offline => "random source is offline",
            Self::InvalidLength => "random request length is outside the bounded range",
            Self::Busy => "random source already has an active request",
            Self::TimedOut => "random source timed out",
            Self::DriverCancelled => "random driver was cancelled",
            Self::DriverFault => "random driver faulted",
            Self::DriverRestarted => "random driver session restarted",
            Self::Protocol => "random device returned a malformed completion",
            Self::Unsupported => "random device lacks the required modern profile",
            Self::Quarantined => "random DMA is quarantined after an unconfirmed reset",
            Self::AuthorityRevoked => "random capability is absent or revoked",
            Self::PermissionDenied => "random capability lacks READ authority",
            Self::IdentityExhausted => "random session identity space is exhausted",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomInfo {
    pub online: bool,
    pub quarantined: bool,
    pub max_request_bytes: u16,
    pub queue_size: u16,
    pub session_epoch: u64,
    pub irq: u32,
    pub used_interrupts: u64,
    pub bytes_returned: u64,
    pub resets: u64,
    pub timeouts: u64,
}

/// A bounded entropy result. Only `as_slice()` exposes initialized bytes.
///
/// The backing array is cleared on ordinary Drop. Fault-domain raw reclamation
/// still relies on the kernel arena's isolation/zero-before-reuse contract.
pub struct RandomBytes {
    bytes: [u8; MAX_RANDOM_BYTES],
    len: u8,
}

impl RandomBytes {
    fn zeroed(length: usize) -> Self {
        Self {
            bytes: [0; MAX_RANDOM_BYTES],
            len: length as u8,
        }
    }

    pub const fn len(&self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }

    pub fn copy_to(&self, output: &mut [u8]) -> Result<(), RandomError> {
        if output.len() != self.len() {
            return Err(RandomError::InvalidLength);
        }
        output.copy_from_slice(self.as_slice());
        Ok(())
    }
}

impl Drop for RandomBytes {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            // Prevent an optimizing build from eliding ordinary secret cleanup.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        self.len = 0;
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}

/// Capability naming exactly one discovered modern virtio-rng MMIO window.
pub struct MmioWindow {
    transport: MmioTransport,
}

impl MmioWindow {
    fn new(transport: MmioTransport) -> Arc<Self> {
        Arc::new(Self { transport })
    }
}

impl Resource for MmioWindow {
    fn kind(&self) -> &'static str {
        "virtio-mmio"
    }

    fn describe(&self) -> String {
        format!(
            "modern entropy transport slot {} @ {:#x}, IRQ {}, vendor {:#x}",
            self.transport.slot(),
            self.transport.base(),
            self.transport.irq(),
            self.transport.vendor_id()
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Capability naming the sole fixed SYSTEM-owned entropy DMA slab.
pub struct DmaRegion;

impl Resource for DmaRegion {
    fn kind(&self) -> &'static str {
        "dma-region"
    }

    fn describe(&self) -> String {
        format!(
            "SYSTEM stable entropy slab @ {:#x}, {} bytes",
            dma_base(),
            DMA_BYTES
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Bounded, fallible entropy service. Possessing the Rust object is not enough:
/// every public operation accepts an invocation lease and checks READ rights.
pub struct RandomSource;

impl RandomSource {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }

    fn info(&self) -> RandomInfo {
        let control = CONTROL.lock();
        RandomInfo {
            online: control.online,
            quarantined: control.quarantined,
            max_request_bytes: MAX_RANDOM_BYTES as u16,
            queue_size: SPLIT_QUEUE_SIZE,
            session_epoch: control.epoch,
            irq: control.transport.map_or(0, MmioTransport::irq),
            used_interrupts: USED_INTERRUPT_COUNT.load(Ordering::Acquire),
            bytes_returned: BYTE_COUNT.load(Ordering::Acquire),
            resets: RESET_COUNT.load(Ordering::Acquire),
            timeouts: TIMEOUT_COUNT.load(Ordering::Acquire),
        }
    }
}

impl Resource for RandomSource {
    fn kind(&self) -> &'static str {
        "random-source"
    }

    fn describe(&self) -> String {
        let info = self.info();
        if info.quarantined {
            return String::from("virtio-rng quarantined");
        }
        if !info.online {
            return String::from("virtio-rng offline");
        }
        format!(
            "virtio-rng [max {} bytes, queue {}, epoch {}]",
            info.max_request_bytes, info.queue_size, info.session_epoch
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn info_with(lease: &InvocationLease<RandomSource>) -> Result<RandomInfo, RandomError> {
    if !lease.authorizes(Rights::READ) {
        return Err(RandomError::PermissionDenied);
    }
    Ok(lease.with(RandomSource::info))
}

/// Return exactly `length` trusted bytes or an error containing no bytes.
pub async fn bytes_with(
    lease: InvocationLease<RandomSource>,
    length: usize,
) -> Result<RandomBytes, RandomError> {
    if !lease.authorizes(Rights::READ) {
        return Err(RandomError::PermissionDenied);
    }
    lease.with(|_| ());
    let result = request(length).await;
    drop(lease);
    result
}

/// Convenience wrapper for callers which already own a fixed destination.
/// The destination pointer never crosses the service or DMA boundary.
pub async fn fill_with(
    lease: InvocationLease<RandomSource>,
    output: &mut [u8],
) -> Result<(), RandomError> {
    let bytes = bytes_with(lease, output.len()).await?;
    bytes.copy_to(output)
}

pub struct RandomResources {
    pub mmio: Arc<MmioWindow>,
    pub dma: Arc<DmaRegion>,
    pub source: Arc<RandomSource>,
}

/// Discover only a real QEMU modern transport with device id 4.
///
/// There is intentionally no clock/counter/deterministic fallback. Since this
/// module is removed wholesale outside `qemu-virt`, a Milk-V build cannot
/// accidentally publish a fake `RandomSource`.
pub fn discover() -> Option<RandomResources> {
    // Safety: the selected BSP maps this trusted VirtIO MMIO aperture into
    // the kernel's identity address space before device discovery begins.
    let transport = unsafe { MmioTransport::scan_entropy(crate::platform::VIRTIO_MMIO) }?;
    {
        // The transport is a boot-discovered, immutable part of the DMA claim.
        // Publish it before any component can claim the slab so raw-fault
        // recovery never has to rely on a half-completed driver attach.
        let mut control = CONTROL.lock();
        if control
            .transport
            .is_some_and(|published| published != transport)
        {
            control.online = false;
            control.quarantined = true;
            return None;
        }
        control.transport = Some(transport);
    }
    Some(RandomResources {
        mmio: MmioWindow::new(transport),
        dma: Arc::new(DmaRegion),
        source: RandomSource::new(),
    })
}

#[repr(C, align(4096))]
struct DmaSlab {
    descriptors: [Descriptor; SPLIT_QUEUE_SIZE as usize],
    available: AvailableRing,
    used: UsedRing,
    data: [u8; MAX_RANDOM_BYTES],
}

impl DmaSlab {
    const ZERO: Self = Self {
        descriptors: [Descriptor::new(0, 0, 0, 0); SPLIT_QUEUE_SIZE as usize],
        available: AvailableRing {
            flags: 0,
            index: 0,
            ring: [0; SPLIT_QUEUE_SIZE as usize],
        },
        used: UsedRing {
            flags: 0,
            index: 0,
            ring: [UsedElement::new(0, 0); SPLIT_QUEUE_SIZE as usize],
        },
        data: [0; MAX_RANDOM_BYTES],
    };
}

struct StableDma(UnsafeCell<DmaSlab>);

// Safety: DMA_CLAIM_ARENA serializes task-side CPU access. Its non-zero value
// is the exact tracked arena which owns the current device incarnation, so
// fault recovery can identify a claim even if attach has not yet published any
// other driver state. A confirmed status-zero reset is the only path which
// releases the slab for another incarnation.
unsafe impl Sync for StableDma {}

#[link_section = ".dma"]
static DMA: StableDma = StableDma(UnsafeCell::new(DmaSlab::ZERO));
static DMA_CLAIM_ARENA: AtomicU64 = AtomicU64::new(ArenaId::UNTRACKED.get());

#[derive(Clone, Copy)]
struct PendingRequest {
    id: u64,
    length: u8,
    expected_epoch: u64,
    deadline: u64,
    abandoned: bool,
    requester: AllocationDomain,
}

enum RequestSlot {
    Empty,
    Queued(PendingRequest),
    InFlight(PendingRequest),
    Completed {
        id: u64,
        result: Result<RandomBytes, RandomError>,
        requester: AllocationDomain,
    },
}

struct DriverControl {
    transport: Option<MmioTransport>,
    accepted_features: u64,
    epoch: u64,
    online: bool,
    quarantined: bool,
}

struct DriverAuthority {
    mmio: Revocable<MmioWindow>,
    dma: Revocable<DmaRegion>,
    source: Revocable<RandomSource>,
}

static CONTROL: SpinLock<DriverControl> = SpinLock::new_recoverable(DriverControl {
    transport: None,
    accepted_features: 0,
    epoch: 0,
    online: false,
    quarantined: false,
});
static AUTHORITY: SpinLock<Option<DriverAuthority>> = SpinLock::new_recoverable(None);
static REQUEST: SpinLock<RequestSlot> = SpinLock::new_recoverable(RequestSlot::Empty);
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);
static REQUEST_WAIT: WaitQueue = WaitQueue::new();
static COMPLETION_WAIT: WaitQueue = WaitQueue::new();
static IRQ_WAIT: WaitQueue = WaitQueue::new();
static IRQ_CAUSES: AtomicU32 = AtomicU32::new(0);
static USED_INTERRUPT_COUNT: AtomicU64 = AtomicU64::new(0);
static BYTE_COUNT: AtomicU64 = AtomicU64::new(0);
static RESET_COUNT: AtomicU64 = AtomicU64::new(0);
static TIMEOUT_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RandomSubmission {
    epoch: u64,
    requested: u16,
    available_slot: u16,
    expected_used_index: u16,
}

struct RandomQueueModel {
    epoch: u64,
    available_index: u16,
    used_index: u16,
    active: Option<RandomSubmission>,
    reset_required: bool,
}

impl RandomQueueModel {
    fn new(epoch: u64) -> Result<Self, RandomError> {
        if epoch == 0 {
            return Err(RandomError::IdentityExhausted);
        }
        Ok(Self {
            epoch,
            available_index: 0,
            used_index: 0,
            active: None,
            reset_required: false,
        })
    }

    fn submit(&mut self, requested: usize) -> Result<RandomSubmission, RandomError> {
        if self.reset_required {
            return Err(RandomError::DriverRestarted);
        }
        if self.active.is_some() {
            return Err(RandomError::Busy);
        }
        if !(1..=MAX_RANDOM_BYTES).contains(&requested) {
            return Err(RandomError::InvalidLength);
        }
        let previous_available = self.available_index;
        self.available_index = self.available_index.wrapping_add(1);
        let submission = RandomSubmission {
            epoch: self.epoch,
            requested: requested as u16,
            available_slot: virtio::ring_slot(previous_available),
            expected_used_index: self.used_index.wrapping_add(1),
        };
        self.active = Some(submission);
        Ok(submission)
    }

    fn complete(
        &mut self,
        submission: RandomSubmission,
        observed_used_index: u16,
        used: UsedElement,
    ) -> Result<usize, RandomError> {
        let result = self.validate_completion(submission, observed_used_index, used);
        match result {
            Ok(length) => {
                self.used_index = observed_used_index;
                self.active = None;
                Ok(length)
            }
            Err(error) => {
                self.reset_required = true;
                Err(error)
            }
        }
    }

    fn validate_completion(
        &self,
        submission: RandomSubmission,
        observed_used_index: u16,
        used: UsedElement,
    ) -> Result<usize, RandomError> {
        if submission.epoch != self.epoch || self.active != Some(submission) {
            return Err(RandomError::Protocol);
        }
        if observed_used_index != submission.expected_used_index {
            return Err(RandomError::Protocol);
        }
        if used.id() != u32::from(ENTROPY_DESCRIPTOR) {
            return Err(RandomError::Protocol);
        }
        let length = used.length() as usize;
        // The virtio-rng device may return fewer bytes than offered. Zero makes
        // no progress and a length above the descriptor would expose stale or
        // out-of-bounds DMA, so both are protocol failures.
        if length == 0 || length > submission.requested as usize {
            return Err(RandomError::Protocol);
        }
        Ok(length)
    }

    fn require_reset(&mut self) {
        self.reset_required = true;
    }
}

async fn request(length: usize) -> Result<RandomBytes, RandomError> {
    if !(1..=MAX_RANDOM_BYTES).contains(&length) {
        return Err(RandomError::InvalidLength);
    }
    let deadline = request_deadline();
    let expected_epoch = {
        let control = CONTROL.lock();
        if control.quarantined {
            return Err(RandomError::Quarantined);
        }
        if !control.online {
            return Err(RandomError::Offline);
        }
        control.epoch
    };

    let id = NEXT_REQUEST_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .map_err(|_| RandomError::IdentityExhausted)?;
    {
        let mut slot = REQUEST.lock();
        if !matches!(*slot, RequestSlot::Empty) {
            return Err(RandomError::Busy);
        }
        *slot = RequestSlot::Queued(PendingRequest {
            id,
            length: length as u8,
            expected_epoch,
            deadline,
            abandoned: false,
            requester: crate::heap::current_domain(),
        });
    }
    let mut guard = ClientRequestGuard { id, armed: true };
    if let Some(error) = queued_session_error(expected_epoch) {
        guard.abandon();
        return Err(error);
    }
    if crate::sbi::time() >= deadline {
        guard.abandon();
        return Err(RandomError::TimedOut);
    }
    REQUEST_WAIT.wake_all();

    loop {
        let listener = COMPLETION_WAIT.wait();
        if let Some(result) = take_completed(id) {
            guard.armed = false;
            return result;
        }
        let now = crate::sbi::time();
        if now >= deadline {
            // Completion wins when both became visible in the same turn: the
            // exact-slot check above ran before the deadline check. Otherwise
            // cancellation never reuses an in-flight DMA buffer; it only marks
            // the request abandoned while the driver finishes or resets it.
            guard.abandon();
            return Err(RandomError::TimedOut);
        }
        let remaining_ms = (deadline - now)
            .saturating_mul(1_000)
            .div_ceil(exec::timebase_hz())
            .max(1);
        let timeout = exec::sleep_ms(remaining_ms);
        let mut listener = pin!(listener);
        let mut timeout = pin!(timeout);
        poll_fn(|cx| {
            if request_completed(id) {
                return Poll::Ready(());
            }
            if timeout.as_mut().poll(cx).is_ready() {
                return Poll::Ready(());
            }
            if listener.as_mut().poll(cx).is_ready() {
                return Poll::Ready(());
            }
            Poll::Pending
        })
        .await;
    }
}

fn request_deadline() -> u64 {
    let timeout_ticks = REQUEST_TIMEOUT_MS
        .saturating_mul(exec::timebase_hz())
        .div_ceil(1_000)
        .max(1);
    crate::sbi::time().saturating_add(timeout_ticks)
}

fn queued_session_error(expected_epoch: u64) -> Option<RandomError> {
    let control = CONTROL.lock();
    if control.quarantined {
        Some(RandomError::Quarantined)
    } else if !control.online {
        Some(RandomError::Offline)
    } else if control.epoch != expected_epoch {
        Some(RandomError::DriverRestarted)
    } else {
        None
    }
}

fn request_completed(id: u64) -> bool {
    matches!(&*REQUEST.lock(), RequestSlot::Completed { id: current, .. } if *current == id)
}

fn take_completed(id: u64) -> Option<Result<RandomBytes, RandomError>> {
    let mut slot = REQUEST.lock();
    let current = core::mem::replace(&mut *slot, RequestSlot::Empty);
    match current {
        RequestSlot::Completed {
            id: completed_id,
            result,
            ..
        } if completed_id == id => Some(result),
        other => {
            *slot = other;
            None
        }
    }
}

struct ClientRequestGuard {
    id: u64,
    armed: bool,
}

impl ClientRequestGuard {
    fn abandon(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        let mut wake_driver = false;
        let mut slot = REQUEST.lock();
        match &mut *slot {
            RequestSlot::Queued(request) if request.id == self.id => {
                *slot = RequestSlot::Empty;
                wake_driver = true;
            }
            RequestSlot::InFlight(request) if request.id == self.id => {
                request.abandoned = true;
            }
            RequestSlot::Completed { id, .. } if *id == self.id => {
                *slot = RequestSlot::Empty;
            }
            _ => {}
        }
        drop(slot);
        if wake_driver {
            REQUEST_WAIT.wake_all();
        }
    }
}

impl Drop for ClientRequestGuard {
    fn drop(&mut self) {
        self.abandon();
    }
}

/// Run one supervised hardware incarnation after resolving its three grants.
pub async fn driver_task(space: &'static Space, mmio_cap: Cap, dma_cap: Cap, source_cap: Cap) {
    let authority = {
        let cspace = space.0.lock();
        match (
            cspace.lookup_revocable::<MmioWindow>(mmio_cap, Rights::READ.union(Rights::WRITE)),
            cspace.lookup_revocable::<DmaRegion>(dma_cap, Rights::READ.union(Rights::WRITE)),
            cspace.lookup_revocable::<RandomSource>(source_cap, Rights::READ),
        ) {
            (Ok(mmio), Ok(dma), Ok(source)) => Some(DriverAuthority { mmio, dma, source }),
            _ => None,
        }
    };
    let Some(authority) = authority else {
        complete_active(Err(RandomError::AuthorityRevoked));
        return;
    };
    let Ok(transport) = authority.mmio.try_with(|window| window.transport) else {
        complete_active(Err(RandomError::AuthorityRevoked));
        return;
    };
    let Some(mut session) = DriverSession::attach(transport, authority) else {
        return;
    };

    loop {
        let listener = REQUEST_WAIT.wait();
        if let Err(error) = session.service_device_events() {
            complete_active(Err(error));
            return;
        }
        if let Some(request) = take_queued() {
            let result = session.perform(request).await;
            let terminal = matches!(
                &result,
                Err(RandomError::Quarantined
                    | RandomError::AuthorityRevoked
                    | RandomError::Offline
                    | RandomError::IdentityExhausted)
            );
            finish_request(request, result);
            if terminal {
                return;
            }
        } else {
            listener.await;
        }
    }
}

fn take_queued() -> Option<PendingRequest> {
    let mut slot = REQUEST.lock();
    let queued = match &*slot {
        RequestSlot::Queued(request) => Some(*request),
        _ => None,
    };
    match queued {
        Some(request) if request.abandoned => {
            *slot = RequestSlot::Empty;
            None
        }
        Some(request) => {
            *slot = RequestSlot::InFlight(request);
            Some(request)
        }
        _ => None,
    }
}

fn finish_request(request: PendingRequest, result: Result<RandomBytes, RandomError>) {
    let mut notify = false;
    let mut slot = REQUEST.lock();
    let current = match &*slot {
        RequestSlot::InFlight(current) if current.id == request.id => Some(*current),
        _ => None,
    };
    if let Some(current) = current {
        if current.abandoned {
            *slot = RequestSlot::Empty;
        } else {
            *slot = RequestSlot::Completed {
                id: request.id,
                result,
                requester: request.requester,
            };
            notify = true;
        }
    }
    drop(slot);
    if notify {
        COMPLETION_WAIT.wake_all();
    }
}

fn complete_active(result: Result<RandomBytes, RandomError>) {
    let mut notify = false;
    let mut result = Some(result);
    let mut slot = REQUEST.lock();
    let request = match &*slot {
        RequestSlot::Queued(request) | RequestSlot::InFlight(request) => Some(*request),
        _ => None,
    };
    if let Some(request) = request {
        if request.abandoned {
            *slot = RequestSlot::Empty;
        } else {
            *slot = RequestSlot::Completed {
                id: request.id,
                result: result.take().expect("one active random result"),
                requester: request.requester,
            };
            notify = true;
        }
    }
    drop(slot);
    if notify {
        COMPLETION_WAIT.wake_all();
    }
}

struct DriverSession {
    transport: MmioTransport,
    model: RandomQueueModel,
    claim_arena: ArenaId,
    armed: bool,
}

#[derive(Clone, Copy)]
struct InitializedTransport {
    accepted_features: u64,
    ready_status: u32,
}

impl DriverSession {
    fn attach(transport: MmioTransport, authority: DriverAuthority) -> Option<Self> {
        if CONTROL.lock().quarantined {
            complete_active(Err(RandomError::Quarantined));
            return None;
        }
        if CONTROL.lock().transport != Some(transport) {
            complete_active(Err(RandomError::Unsupported));
            return None;
        }
        let domain = crate::heap::current_domain();
        if !domain.arena.is_tracked() {
            complete_active(Err(RandomError::DriverCancelled));
            return None;
        }
        let claim_arena = domain.arena;
        if DMA_CLAIM_ARENA
            .compare_exchange(
                ArenaId::UNTRACKED.get(),
                claim_arena.get(),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            complete_active(Err(RandomError::DriverRestarted));
            return None;
        }
        {
            let mut installed = AUTHORITY.lock();
            if installed.is_some() {
                drop(installed);
                // A stale authority with an atomically free slab violates the
                // publication invariant: an unknown old CPU session may still
                // touch DMA even if the device reset succeeds. Revoke what we
                // can, quarantine permanently, and deliberately retain this
                // new exact claim so no later incarnation can reuse the slab.
                quarantine_inconsistent_attach(transport);
                return None;
            }
            *installed = Some(authority);
        }

        clear_dma();

        let initialized = match initialize_transport(transport) {
            Ok(initialized) => initialized,
            Err(error) => {
                attach_failed(transport, claim_arena, error);
                return None;
            }
        };
        let epoch = match advance_epoch() {
            Ok(epoch) => epoch,
            Err(error) => {
                attach_failed(transport, claim_arena, error);
                return None;
            }
        };

        let _ = plic::unregister(transport.irq());
        if plic::register(transport.irq(), irq_top_half, transport.base()).is_err()
            || plic::enable(transport.irq()).is_err()
        {
            shutdown(transport, claim_arena, RandomError::DriverCancelled);
            return None;
        }
        transport.set_status(initialized.ready_status);
        if !operational_status(transport.status()) {
            shutdown(transport, claim_arena, RandomError::DriverRestarted);
            return None;
        }
        {
            let mut control = CONTROL.lock();
            control.transport = Some(transport);
            control.accepted_features = initialized.accepted_features;
            control.online = true;
        }

        Some(Self {
            transport,
            model: RandomQueueModel::new(epoch).expect("a published entropy epoch is non-zero"),
            claim_arena,
            armed: true,
        })
    }

    async fn perform(&mut self, request: PendingRequest) -> Result<RandomBytes, RandomError> {
        self.service_device_events()?;
        if request.expected_epoch != self.model.epoch {
            return Err(RandomError::DriverRestarted);
        }
        if crate::sbi::time() >= request.deadline {
            TIMEOUT_COUNT.fetch_add(1, Ordering::Relaxed);
            return Err(RandomError::TimedOut);
        }
        if !authority_live(self.transport) {
            return Err(RandomError::AuthorityRevoked);
        }

        let requested = request.length as usize;
        let mut result = RandomBytes::zeroed(requested);
        let mut offset = 0usize;
        let deadline = request.deadline;

        // A conforming device may use less than the offered buffer. Each turn
        // must make positive progress, and the client-wide deadline plus the
        // 64-byte API bound limits the complete loop.
        while offset < requested {
            self.service_device_events()?;
            if crate::sbi::time() >= deadline {
                TIMEOUT_COUNT.fetch_add(1, Ordering::Relaxed);
                return Err(RandomError::TimedOut);
            }
            if !authority_live(self.transport) {
                return Err(RandomError::AuthorityRevoked);
            }
            let submission = self.model.submit(requested - offset)?;
            publish_request(submission)?;
            self.transport.notify_queue(ENTROPY_QUEUE);

            let outcome =
                wait_for_completion(self.transport, self.model.used_index, deadline).await;
            let (observed_used, used) = match outcome {
                WaitOutcome::Completed { used_index, used } => (used_index, used),
                WaitOutcome::TimedOut => {
                    TIMEOUT_COUNT.fetch_add(1, Ordering::Relaxed);
                    self.model.require_reset();
                    self.reset_required_transport()?;
                    return Err(RandomError::TimedOut);
                }
                WaitOutcome::DeviceNeedsReset => {
                    self.model.require_reset();
                    self.reset_required_transport()?;
                    return Err(RandomError::DriverRestarted);
                }
            };

            if !operational_status(self.transport.status()) {
                self.model.require_reset();
                self.reset_required_transport()?;
                return Err(RandomError::DriverRestarted);
            }
            let length = match self.model.complete(submission, observed_used, used) {
                Ok(length) => length,
                Err(_) => {
                    self.reset_required_transport()?;
                    return Err(RandomError::Protocol);
                }
            };
            read_dma_data(&mut result.bytes[offset..offset + length]);
            zero_dma_data();
            offset += length;
        }

        BYTE_COUNT.fetch_add(requested as u64, Ordering::Relaxed);
        Ok(result)
    }

    fn service_device_events(&mut self) -> Result<(), RandomError> {
        if !authority_live(self.transport) {
            return Err(RandomError::AuthorityRevoked);
        }
        let _ = virtio::InterruptCauses::from_status(IRQ_CAUSES.swap(0, Ordering::AcqRel));
        if !operational_status(self.transport.status()) {
            self.model.require_reset();
            self.reset_required_transport()?;
        }
        Ok(())
    }

    fn reset_required_transport(&mut self) -> Result<(), RandomError> {
        let _ = plic::disable(self.transport.irq());
        CONTROL.lock().online = false;
        if !self.transport.reset(RESET_POLL_BUDGET) {
            self.quarantine();
            return Err(RandomError::Quarantined);
        }
        let _ = self.transport.acknowledge_interrupt();
        IRQ_CAUSES.store(0, Ordering::Release);
        RESET_COUNT.fetch_add(1, Ordering::Relaxed);
        self.reinitialize_after_reset()
    }

    fn reinitialize_after_reset(&mut self) -> Result<(), RandomError> {
        clear_dma();
        let mut identity_exhausted = false;
        let initialized = initialize_transport(self.transport);
        if let Ok(initialized) = initialized {
            if let Ok(epoch) = advance_epoch() {
                if plic::enable(self.transport.irq()).is_ok() {
                    self.transport.set_status(initialized.ready_status);
                    if operational_status(self.transport.status()) {
                        self.model = RandomQueueModel::new(epoch)
                            .expect("a reinitialized entropy epoch is non-zero");
                        let mut control = CONTROL.lock();
                        control.accepted_features = initialized.accepted_features;
                        control.online = true;
                        return Ok(());
                    }
                }
            } else {
                identity_exhausted = true;
                CONTROL.lock().quarantined = true;
            }
        }

        let _ = plic::disable(self.transport.irq());
        let reset = self.transport.reset(RESET_POLL_BUDGET);
        let _ = self.transport.acknowledge_interrupt();
        let _ = plic::unregister(self.transport.irq());
        IRQ_CAUSES.store(0, Ordering::Release);
        {
            let mut control = CONTROL.lock();
            control.online = false;
            if !reset {
                control.quarantined = true;
            }
        }
        *AUTHORITY.lock() = None;
        if reset {
            clear_dma();
            // Retain the exact claim until `perform` returns, the in-flight
            // request is completed, and DriverSession::drop enters shutdown's
            // CONTROL barrier. Releasing here would let a replacement attach
            // while the retiring driver can still mutate shared state.
            if identity_exhausted {
                Err(RandomError::IdentityExhausted)
            } else if CONTROL.lock().quarantined {
                Err(RandomError::Quarantined)
            } else {
                Err(RandomError::Offline)
            }
        } else {
            // One unconfirmed reset permanently quarantines the slab. Prevent
            // Drop from retrying and releasing a claim which must stay fenced.
            self.armed = false;
            Err(RandomError::Quarantined)
        }
    }

    fn quarantine(&mut self) {
        let _ = plic::disable(self.transport.irq());
        let _ = plic::unregister(self.transport.irq());
        let _ = self.transport.acknowledge_interrupt();
        IRQ_CAUSES.store(0, Ordering::Release);
        {
            let mut control = CONTROL.lock();
            control.online = false;
            control.quarantined = true;
        }
        *AUTHORITY.lock() = None;
        self.armed = false;
        // Reset was not confirmed, so the device may still own every DMA byte.
        // DMA_CLAIM_ARENA intentionally retains this exact incarnation forever.
    }
}

impl Drop for DriverSession {
    fn drop(&mut self) {
        if self.armed {
            shutdown(
                self.transport,
                self.claim_arena,
                RandomError::DriverCancelled,
            );
            self.armed = false;
        }
    }
}

fn initialize_transport(transport: MmioTransport) -> Result<InitializedTransport, RandomError> {
    if transport.device_id() != virtio::DEVICE_ID_ENTROPY {
        return Err(RandomError::Unsupported);
    }
    if !transport.reset(RESET_POLL_BUDGET) {
        return Err(RandomError::Quarantined);
    }

    let mut init = ModernInit::new();
    transport.set_status(init.acknowledge().map_err(|_| RandomError::Protocol)?);
    transport.set_status(init.declare_driver().map_err(|_| RandomError::Protocol)?);
    let features = init
        .select_entropy_features(transport.device_features())
        .map_err(|_| RandomError::Unsupported)?;
    transport.set_driver_features(features.accepted());
    transport.set_status(init.set_features_ok().map_err(|_| RandomError::Protocol)?);
    init.confirm_features(transport.status())
        .map_err(|_| RandomError::Unsupported)?;

    transport.select_queue(ENTROPY_QUEUE);
    if transport.queue_ready() || transport.queue_num_max() < SPLIT_QUEUE_SIZE {
        return Err(RandomError::Unsupported);
    }
    let (descriptors, available, used) = dma_addresses();
    transport.configure_queue(SPLIT_QUEUE_SIZE, descriptors, available, used);
    let ready_status = init.set_driver_ok().map_err(|_| RandomError::Protocol)?;
    Ok(InitializedTransport {
        accepted_features: features.accepted(),
        ready_status,
    })
}

fn operational_status(status: u32) -> bool {
    let expected = virtio::STATUS_ACKNOWLEDGE
        | virtio::STATUS_DRIVER
        | virtio::STATUS_FEATURES_OK
        | virtio::STATUS_DRIVER_OK;
    status & (virtio::STATUS_FAILED | virtio::STATUS_DEVICE_NEEDS_RESET) == 0
        && status & expected == expected
}

fn advance_epoch() -> Result<u64, RandomError> {
    let mut control = CONTROL.lock();
    let Some(epoch) = control.epoch.checked_add(1) else {
        control.online = false;
        control.quarantined = true;
        return Err(RandomError::IdentityExhausted);
    };
    control.epoch = epoch;
    Ok(epoch)
}

fn attach_failed(transport: MmioTransport, claim_arena: ArenaId, error: RandomError) {
    let reset = transport.reset(RESET_POLL_BUDGET);
    let _ = transport.acknowledge_interrupt();
    IRQ_CAUSES.store(0, Ordering::Release);
    *AUTHORITY.lock() = None;
    if reset {
        clear_dma();
    }
    finish_claimed_teardown(claim_arena, reset, error);
}

fn quarantine_inconsistent_attach(transport: MmioTransport) {
    let _ = plic::disable(transport.irq());
    let _ = plic::unregister(transport.irq());
    let _ = transport.reset(RESET_POLL_BUDGET);
    let _ = transport.acknowledge_interrupt();
    IRQ_CAUSES.store(0, Ordering::Release);
    *AUTHORITY.lock() = None;
    {
        let mut control = CONTROL.lock();
        control.online = false;
        control.quarantined = true;
    }
    complete_active(Err(RandomError::Quarantined));
    // DMA_CLAIM_ARENA intentionally remains non-zero forever.
}

fn shutdown(transport: MmioTransport, claim_arena: ArenaId, reason: RandomError) {
    let _ = plic::disable(transport.irq());
    let _ = plic::unregister(transport.irq());
    CONTROL.lock().online = false;
    let reset = transport.reset(RESET_POLL_BUDGET);
    let _ = transport.acknowledge_interrupt();
    IRQ_CAUSES.store(0, Ordering::Release);
    *AUTHORITY.lock() = None;
    if reset {
        clear_dma();
    }
    finish_claimed_teardown(claim_arena, reset, reason);
}

/// Finish all shared-state mutation behind CONTROL before publishing the DMA
/// claim as reusable. A replacement attach must take CONTROL before it can
/// inspect policy and claim the slab, so it cannot cross this teardown barrier.
fn finish_claimed_teardown(claim_arena: ArenaId, reset: bool, reason: RandomError) {
    let mut control = CONTROL.lock();
    control.online = false;
    let owns_claim =
        claim_arena.is_tracked() && DMA_CLAIM_ARENA.load(Ordering::Acquire) == claim_arena.get();
    if !reset || !owns_claim || matches!(reason, RandomError::IdentityExhausted) {
        control.quarantined = true;
    }

    complete_active(Err(if reset && owns_claim {
        reason
    } else {
        RandomError::Quarantined
    }));

    if reset && owns_claim && !release_dma_claim(claim_arena) {
        // A failed CAS did not publish the slab as free, so mutating CONTROL is
        // still safe and the only correct response is permanent quarantine.
        control.quarantined = true;
    }
}

fn release_dma_claim(claim_arena: ArenaId) -> bool {
    claim_arena.is_tracked()
        && DMA_CLAIM_ARENA
            .compare_exchange(
                claim_arena.get(),
                ArenaId::UNTRACKED.get(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
}

fn authority_live(transport: MmioTransport) -> bool {
    let authority = AUTHORITY.lock();
    let Some(authority) = authority.as_ref() else {
        return false;
    };
    authority
        .mmio
        .try_with(|window| window.transport == transport)
        .is_ok_and(|same| same)
        && authority.dma.try_with(|_| ()).is_ok()
        && authority.source.try_with(|_| ()).is_ok()
}

enum WaitOutcome {
    Completed { used_index: u16, used: UsedElement },
    DeviceNeedsReset,
    TimedOut,
}

enum WaitSignal {
    Completed { used_index: u16, used: UsedElement },
    DeviceNeedsReset,
    Irq,
    TimedOut,
}

async fn wait_for_completion(
    transport: MmioTransport,
    previous_used: u16,
    deadline: u64,
) -> WaitOutcome {
    loop {
        let irq = IRQ_WAIT.wait();
        if !operational_status(transport.status()) {
            return WaitOutcome::DeviceNeedsReset;
        }
        let used_index = read_used_index();
        if used_index != previous_used {
            let slot = virtio::ring_slot(previous_used) as usize;
            return WaitOutcome::Completed {
                used_index,
                used: read_used_element(slot),
            };
        }
        let now = crate::sbi::time();
        if now >= deadline {
            return WaitOutcome::TimedOut;
        }
        let remaining_ms = (deadline - now)
            .saturating_mul(1_000)
            .div_ceil(exec::timebase_hz())
            .max(1);
        let timeout = exec::sleep_ms(remaining_ms);
        let mut irq = pin!(irq);
        let mut timeout = pin!(timeout);
        let signal = poll_fn(|cx| {
            if !operational_status(transport.status()) {
                return Poll::Ready(WaitSignal::DeviceNeedsReset);
            }
            let used_index = read_used_index();
            if used_index != previous_used {
                let slot = virtio::ring_slot(previous_used) as usize;
                return Poll::Ready(WaitSignal::Completed {
                    used_index,
                    used: read_used_element(slot),
                });
            }
            if timeout.as_mut().poll(cx).is_ready() {
                return Poll::Ready(WaitSignal::TimedOut);
            }
            if irq.as_mut().poll(cx).is_ready() {
                return Poll::Ready(WaitSignal::Irq);
            }
            Poll::Pending
        })
        .await;
        match signal {
            WaitSignal::Completed { used_index, used } => {
                return WaitOutcome::Completed { used_index, used }
            }
            WaitSignal::DeviceNeedsReset => return WaitOutcome::DeviceNeedsReset,
            WaitSignal::TimedOut => return WaitOutcome::TimedOut,
            WaitSignal::Irq => {}
        }
    }
}

fn irq_top_half(transport_base: usize, _irq_entry: u64) {
    let causes = acknowledge_irq_transport(transport_base);
    if causes != 0 {
        if virtio::InterruptCauses::from_status(causes).used_buffer() {
            USED_INTERRUPT_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        IRQ_CAUSES.fetch_or(causes, Ordering::Release);
        IRQ_WAIT.wake_all();
        REQUEST_WAIT.wake_all();
    }
}

fn acknowledge_irq_transport(transport_base: usize) -> u32 {
    let raw = unsafe { ((transport_base + INTERRUPT_STATUS_OFFSET) as *const u32).read_volatile() };
    dma_fence();
    let causes = virtio::InterruptCauses::from_status(raw).ack_bits();
    if causes != 0 {
        dma_fence();
        unsafe { ((transport_base + INTERRUPT_ACK_OFFSET) as *mut u32).write_volatile(causes) };
        dma_fence();
    }
    causes
}

fn publish_request(submission: RandomSubmission) -> Result<(), RandomError> {
    if submission.requested == 0 || submission.requested as usize > MAX_RANDOM_BYTES {
        return Err(RandomError::InvalidLength);
    }
    zero_dma_data();
    let data_address = unsafe { core::ptr::addr_of!((*DMA.0.get()).data) as u64 };
    let descriptor = Descriptor::new(
        data_address,
        u32::from(submission.requested),
        DESC_F_WRITE,
        0,
    );
    unsafe {
        let slab = DMA.0.get();
        core::ptr::addr_of_mut!((*slab).descriptors[ENTROPY_DESCRIPTOR as usize])
            .write_volatile(descriptor);
        let ring = core::ptr::addr_of_mut!((*slab).available.ring) as *mut u16;
        ring.add(submission.available_slot as usize)
            .write_volatile(ENTROPY_DESCRIPTOR.to_le());
        dma_fence();
        core::ptr::addr_of_mut!((*slab).available.index)
            .write_volatile(submission.expected_used_index.to_le());
        dma_fence();
    }
    Ok(())
}

fn dma_addresses() -> (u64, u64, u64) {
    unsafe {
        let slab = DMA.0.get();
        (
            core::ptr::addr_of!((*slab).descriptors) as u64,
            core::ptr::addr_of!((*slab).available) as u64,
            core::ptr::addr_of!((*slab).used) as u64,
        )
    }
}

fn dma_base() -> usize {
    DMA.0.get() as usize
}

fn clear_dma() {
    unsafe {
        core::ptr::write_bytes(DMA.0.get().cast::<u8>(), 0, DMA_BYTES);
        dma_fence();
    }
}

fn zero_dma_data() {
    unsafe {
        let data = core::ptr::addr_of_mut!((*DMA.0.get()).data) as *mut u8;
        for index in 0..MAX_RANDOM_BYTES {
            data.add(index).write_volatile(0);
        }
        dma_fence();
    }
}

fn read_used_index() -> u16 {
    dma_fence();
    unsafe { u16::from_le(core::ptr::addr_of!((*DMA.0.get()).used.index).read_volatile()) }
}

fn read_used_element(slot: usize) -> UsedElement {
    dma_fence();
    unsafe { core::ptr::addr_of!((*DMA.0.get()).used.ring[slot]).read_volatile() }
}

fn read_dma_data(output: &mut [u8]) {
    unsafe {
        let source = core::ptr::addr_of!((*DMA.0.get()).data) as *const u8;
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = source.add(index).read_volatile();
        }
    }
}

#[inline]
fn dma_fence() {
    unsafe { core::arch::asm!("fence iorw, iorw", options(nostack, preserves_flags)) };
}

pub fn is_online() -> bool {
    let control = CONTROL.lock();
    control.online && !control.quarantined
}

/// Device-specific raw-fault recovery. The executor must call this before the
/// generic arena is reclaimed and before `Faulted` becomes supervisor-visible.
///
/// # Safety
/// Every task in `domain` must already be permanently detached.
pub unsafe fn recover_faulted_domain(domain: AllocationDomain) {
    let _ = unsafe { REQUEST.recover_after_fault(domain) };
    abandon_requests_for_domain(domain);
    // Random clients call info/request through CONTROL too. Repair an exact
    // abandoned client-held guard even when that domain never owned the DMA
    // claim; otherwise one client fault could deadlock the whole service.
    let _ = unsafe { CONTROL.recover_after_fault(domain) };

    // The claim itself carries the exact non-wrapping arena incarnation. This
    // remains valid from the first successful claim instruction, including the
    // attach window before DriverSession exists or CONTROL has been touched by
    // that component.
    if !domain.arena.is_tracked() || DMA_CLAIM_ARENA.load(Ordering::Acquire) != domain.arena.get() {
        return;
    }

    let _ = unsafe { AUTHORITY.recover_after_fault(domain) };
    let transport = CONTROL.lock().transport;
    if let Some(transport) = transport {
        shutdown(transport, domain.arena, RandomError::DriverFault);
    } else {
        // A claimed slab without its boot-published transport cannot be proven
        // device-idle. Keep the exact claim forever and fail closed.
        {
            let mut control = CONTROL.lock();
            control.online = false;
            control.quarantined = true;
        }
        *AUTHORITY.lock() = None;
        complete_active(Err(RandomError::Quarantined));
    }
}

fn abandon_requests_for_domain(domain: AllocationDomain) {
    let mut wake_driver = false;
    let mut wake_client = false;
    let mut slot = REQUEST.lock();
    match &mut *slot {
        RequestSlot::Queued(request) if request.requester == domain => {
            *slot = RequestSlot::Empty;
            wake_driver = true;
        }
        RequestSlot::InFlight(request) if request.requester == domain => {
            request.abandoned = true;
        }
        RequestSlot::Completed { requester, .. } if *requester == domain => {
            *slot = RequestSlot::Empty;
            wake_client = true;
        }
        _ => {}
    }
    drop(slot);
    if wake_driver {
        REQUEST_WAIT.wake_all();
    }
    if wake_client {
        COMPLETION_WAIT.wake_all();
    }
}

#[allow(dead_code)]
pub fn debug_waiter_counts() -> (usize, usize, usize) {
    (
        REQUEST_WAIT.waiter_count(),
        COMPLETION_WAIT.waiter_count(),
        IRQ_WAIT.waiter_count(),
    )
}

/// Deterministic bytes exist only for unit-test fixtures. No production or
/// board feature can name this module, and it is never wired to `RandomSource`.
#[cfg(test)]
pub(crate) mod fixture {
    pub(crate) struct DeterministicBytes(u64);

    impl DeterministicBytes {
        pub(crate) const fn new(seed: u64) -> Self {
            Self(seed)
        }

        pub(crate) fn fill(&mut self, output: &mut [u8]) {
            for byte in output {
                // xorshift64* is a fixture, explicitly not a source of entropy.
                self.0 ^= self.0 >> 12;
                self.0 ^= self.0 << 25;
                self.0 ^= self.0 >> 27;
                self.0 = self.0.wrapping_mul(0x2545_f491_4f6c_dd1d);
                *byte = self.0 as u8;
            }
        }
    }
}
