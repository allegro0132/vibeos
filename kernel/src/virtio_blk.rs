//! Supervised modern virtio-blk service.
//!
//! The component future owns protocol progress, never DMA storage. The latter
//! is a fixed SYSTEM slab because cancellation can drop a future and a fault
//! can skip every destructor while the device still holds published addresses.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::cell::UnsafeCell;
use core::future::{poll_fn, Future};
use core::pin::pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::Poll;

use crate::cap::{Cap, InvocationLease, Resource, Revocable, Rights};
use crate::exec::{self, WaitQueue};
use crate::heap::{AllocationDomain, ArenaId, OwnerId};
use crate::plic;
use crate::sync::SpinLock;
use crate::virtio::{
    self, AvailableRing, BlockDmaAddresses, BlockOperation, BlockRequestHeader, BlockStatus,
    Descriptor, ModernInit, NegotiatedFeatures, ResetReason, SplitQueueModel, UsedElement,
    UsedRing, BLOCK_SECTOR_SIZE, SPLIT_QUEUE_SIZE,
};
use crate::world::Space;

use crate::virtio_mmio::MmioTransport;

const RESET_POLL_BUDGET: usize = 100_000;
const REQUEST_TIMEOUT_MS: u64 = 2_000;
const DMA_BYTES: usize = core::mem::size_of::<DmaSlab>();
const INTERRUPT_STATUS_OFFSET: usize = 0x060;
const INTERRUPT_ACK_OFFSET: usize = 0x064;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    Offline,
    QueueFull,
    OutOfRange,
    ReadOnly,
    FlushUnsupported,
    TimedOut,
    DriverCancelled,
    DriverFault,
    DriverRestarted,
    DeviceIo,
    Unsupported,
    Protocol,
    Quarantined,
    AuthorityRevoked,
    PermissionDenied,
}

impl core::fmt::Display for BlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Offline => "block device is offline",
            Self::QueueFull => "block request queue is full",
            Self::OutOfRange => "sector is outside the device capacity",
            Self::ReadOnly => "block device is read-only",
            Self::FlushUnsupported => "block device does not support flush",
            Self::TimedOut => "block request timed out",
            Self::DriverCancelled => "block driver was cancelled",
            Self::DriverFault => "block driver faulted",
            Self::DriverRestarted => "block driver session restarted",
            Self::DeviceIo => "block device reported an I/O error",
            Self::Unsupported => "block device rejected the operation",
            Self::Protocol => "block device returned a malformed completion",
            Self::Quarantined => "block DMA is quarantined after an unconfirmed reset",
            Self::AuthorityRevoked => "block capability is absent or revoked",
            Self::PermissionDenied => "block capability lacks the required right",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockInfo {
    pub online: bool,
    pub quarantined: bool,
    pub capacity_sectors: u64,
    pub queue_size: u16,
    pub read_only: bool,
    pub supports_flush: bool,
    pub session_epoch: u64,
    pub irq: u32,
    pub used_interrupts: u64,
}

/// Capability naming exactly one discovered 4 KiB transport window.
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
            "modern block transport slot {} @ {:#x}, IRQ {}, vendor {:#x}",
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

/// Capability naming the sole stable DMA slab. Client addresses are never
/// accepted by the descriptor builder.
pub struct DmaRegion;

impl Resource for DmaRegion {
    fn kind(&self) -> &'static str {
        "dma-region"
    }

    fn describe(&self) -> String {
        format!(
            "SYSTEM stable slab @ {:#x}, {} bytes",
            dma_base(),
            DMA_BYTES
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Client-facing capability. Its methods enqueue bounded, pointer-free sector
/// requests; only the driver component can expose the stable DMA slab.
pub struct BlockDevice;

impl BlockDevice {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }

    pub fn info(&self) -> BlockInfo {
        let control = CONTROL.lock();
        BlockInfo {
            online: control.online,
            quarantined: control.quarantined,
            capacity_sectors: control.capacity,
            queue_size: SPLIT_QUEUE_SIZE,
            read_only: control
                .features
                .is_some_and(|features| features.read_only()),
            supports_flush: control
                .features
                .is_some_and(|features| features.supports_flush()),
            session_epoch: control.epoch,
            irq: control.transport.map_or(0, MmioTransport::irq),
            used_interrupts: USED_INTERRUPT_COUNT.load(Ordering::Acquire),
        }
    }
}

impl Resource for BlockDevice {
    fn kind(&self) -> &'static str {
        "block-device"
    }

    fn describe(&self) -> String {
        let info = self.info();
        if info.quarantined {
            return String::from("virtio-blk quarantined");
        }
        if !info.online {
            return String::from("virtio-blk offline");
        }
        format!(
            "virtio-blk [{} sectors, queue {}, epoch {}]",
            info.capacity_sectors, info.queue_size, info.session_epoch
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn info_with(lease: &InvocationLease<BlockDevice>) -> Result<BlockInfo, BlockError> {
    if !lease.authorizes(Rights::READ) {
        return Err(BlockError::PermissionDenied);
    }
    Ok(lease.with(BlockDevice::info))
}

pub async fn read_with(
    lease: InvocationLease<BlockDevice>,
    sector: u64,
) -> Result<[u8; 512], BlockError> {
    if !lease.authorizes(Rights::READ) {
        return Err(BlockError::PermissionDenied);
    }
    // Retain the non-cloneable invocation authority until the hardware request
    // has completed or reset. Revocation blocks the next acquisition.
    lease.with(|_| ());
    let result = request(BlockOperation::Read { sector }, [0; 512]).await;
    drop(lease);
    result
}

pub async fn write_with(
    lease: InvocationLease<BlockDevice>,
    sector: u64,
    data: [u8; 512],
) -> Result<(), BlockError> {
    if !lease.authorizes(Rights::WRITE) {
        return Err(BlockError::PermissionDenied);
    }
    lease.with(|_| ());
    let result = request(BlockOperation::Write { sector }, data)
        .await
        .map(|_| ());
    drop(lease);
    result
}

pub async fn flush_with(lease: InvocationLease<BlockDevice>) -> Result<(), BlockError> {
    if !lease.authorizes(Rights::WRITE) {
        return Err(BlockError::PermissionDenied);
    }
    lease.with(|_| ());
    let result = request(BlockOperation::Flush, [0; 512]).await.map(|_| ());
    drop(lease);
    result
}

pub struct BlockResources {
    pub mmio: Arc<MmioWindow>,
    pub dma: Arc<DmaRegion>,
    pub device: Arc<BlockDevice>,
}

/// Discover a real device. Empty QEMU transport slots are not an error and no
/// block component is spawned when no device is present.
pub fn discover() -> Option<BlockResources> {
    let transport = MmioTransport::scan_block()?;
    Some(BlockResources {
        mmio: MmioWindow::new(transport),
        dma: Arc::new(DmaRegion),
        device: BlockDevice::new(),
    })
}

#[repr(C, align(4096))]
struct DmaSlab {
    descriptors: [Descriptor; SPLIT_QUEUE_SIZE as usize],
    available: AvailableRing,
    used: UsedRing,
    header: BlockRequestHeader,
    data: [u8; BLOCK_SECTOR_SIZE as usize],
    status: u8,
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
        header: BlockRequestHeader {
            request_type: 0,
            reserved: 0,
            sector: 0,
        },
        data: [0; BLOCK_SECTOR_SIZE as usize],
        status: 0,
    };
}

struct StableDma(UnsafeCell<DmaSlab>);

// Safety: CPU access is serialized by DMA_CLAIMED and the single-in-flight
// driver. The device sees only addresses inside this slab. Fault recovery owns
// it only after the executor has made the old incarnation unable to resume.
unsafe impl Sync for StableDma {}

#[link_section = ".dma"]
static DMA: StableDma = StableDma(UnsafeCell::new(DmaSlab::ZERO));
static DMA_CLAIMED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
struct PendingRequest {
    id: u64,
    operation: BlockOperation,
    data: [u8; 512],
    abandoned: bool,
    requester: AllocationDomain,
}

#[derive(Clone, Copy)]
enum RequestSlot {
    Empty,
    Queued(PendingRequest),
    InFlight(PendingRequest),
    Completed {
        id: u64,
        result: Result<[u8; 512], BlockError>,
        requester: AllocationDomain,
    },
}

struct DriverControl {
    transport: Option<MmioTransport>,
    features: Option<NegotiatedFeatures>,
    capacity: u64,
    epoch: u64,
    online: bool,
    quarantined: bool,
}

struct DriverAuthority {
    mmio: Revocable<MmioWindow>,
    dma: Revocable<DmaRegion>,
    service: Revocable<BlockDevice>,
}

static CONTROL: SpinLock<DriverControl> = SpinLock::new_recoverable(DriverControl {
    transport: None,
    features: None,
    capacity: 0,
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
static DRIVER_OWNER: AtomicU64 = AtomicU64::new(OwnerId::SYSTEM.get());
static DRIVER_ARENA: AtomicU64 = AtomicU64::new(ArenaId::UNTRACKED.get());
static FAULT_AFTER_PUBLISH: AtomicBool = AtomicBool::new(false);
static SUPPRESS_NEXT_NOTIFY: AtomicBool = AtomicBool::new(false);

async fn request(operation: BlockOperation, data: [u8; 512]) -> Result<[u8; 512], BlockError> {
    validate_operation(operation)?;

    let id = NEXT_REQUEST_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .expect("block request id space exhausted");
    {
        let mut slot = REQUEST.lock();
        if !matches!(*slot, RequestSlot::Empty) {
            return Err(BlockError::QueueFull);
        }
        *slot = RequestSlot::Queued(PendingRequest {
            id,
            operation,
            data,
            abandoned: false,
            requester: crate::heap::current_domain(),
        });
    }
    REQUEST_WAIT.wake_all();
    let mut guard = ClientRequestGuard { id, armed: true };

    loop {
        let listener = COMPLETION_WAIT.wait();
        let completed = {
            let mut slot = REQUEST.lock();
            match *slot {
                RequestSlot::Completed {
                    id: completed_id,
                    result,
                    ..
                } if completed_id == id => {
                    *slot = RequestSlot::Empty;
                    Some(result)
                }
                _ => None,
            }
        };
        if let Some(result) = completed {
            guard.armed = false;
            return result;
        }
        listener.await;
    }
}

fn validate_operation(operation: BlockOperation) -> Result<(), BlockError> {
    let info = BlockDevice.info();
    if info.quarantined {
        return Err(BlockError::Quarantined);
    }
    if !info.online {
        return Err(BlockError::Offline);
    }
    match operation {
        BlockOperation::Read { sector } | BlockOperation::Write { sector }
            if sector >= info.capacity_sectors =>
        {
            return Err(BlockError::OutOfRange)
        }
        BlockOperation::Write { .. } if info.read_only => return Err(BlockError::ReadOnly),
        BlockOperation::Flush if !info.supports_flush => return Err(BlockError::FlushUnsupported),
        _ => {}
    }
    Ok(())
}

struct ClientRequestGuard {
    id: u64,
    armed: bool,
}

impl Drop for ClientRequestGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut wake_driver = false;
        let mut slot = REQUEST.lock();
        match *slot {
            RequestSlot::Queued(request) if request.id == self.id => {
                *slot = RequestSlot::Empty;
                wake_driver = true;
            }
            RequestSlot::InFlight(mut request) if request.id == self.id => {
                request.abandoned = true;
                *slot = RequestSlot::InFlight(request);
            }
            RequestSlot::Completed { id, .. } if id == self.id => {
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

/// Run the hardware session after resolving the component's three explicit
/// grants. Revocable tokens move into supervisor-stable storage and are
/// revalidated before every new hardware request. Revocation does not pretend
/// to interrupt DMA which was already published.
pub async fn driver_task(space: &'static Space, mmio_cap: Cap, dma_cap: Cap, service_cap: Cap) {
    let authority = {
        let cspace = space.0.lock();
        match (
            cspace.lookup_revocable::<MmioWindow>(mmio_cap, Rights::READ.union(Rights::WRITE)),
            cspace.lookup_revocable::<DmaRegion>(dma_cap, Rights::READ.union(Rights::WRITE)),
            cspace.lookup_revocable::<BlockDevice>(service_cap, Rights::READ.union(Rights::WRITE)),
        ) {
            (Ok(mmio), Ok(dma), Ok(service)) => Some(DriverAuthority { mmio, dma, service }),
            _ => None,
        }
    };
    let Some(authority) = authority else {
        complete_active(Err(BlockError::AuthorityRevoked));
        return;
    };
    let Ok(transport) = authority.mmio.try_with(|window| window.transport) else {
        complete_active(Err(BlockError::AuthorityRevoked));
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
        let request = take_queued();
        if let Some(request) = request {
            let result = session.perform(request).await;
            let terminal = matches!(
                result,
                Err(BlockError::Quarantined | BlockError::AuthorityRevoked | BlockError::Offline)
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
    match *slot {
        RequestSlot::Queued(request) if request.abandoned => {
            *slot = RequestSlot::Empty;
            None
        }
        RequestSlot::Queued(request) => {
            *slot = RequestSlot::InFlight(request);
            Some(request)
        }
        _ => None,
    }
}

fn finish_request(request: PendingRequest, result: Result<[u8; 512], BlockError>) {
    let mut notify = false;
    let mut slot = REQUEST.lock();
    if let RequestSlot::InFlight(current) = *slot {
        if current.id == request.id {
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
    }
    drop(slot);
    if notify {
        COMPLETION_WAIT.wake_all();
    }
}

fn complete_active(result: Result<[u8; 512], BlockError>) {
    let mut notify = false;
    let mut slot = REQUEST.lock();
    match *slot {
        RequestSlot::InFlight(request) | RequestSlot::Queued(request) => {
            if request.abandoned {
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
        _ => {}
    }
    drop(slot);
    if notify {
        COMPLETION_WAIT.wake_all();
    }
}

struct DriverSession {
    transport: MmioTransport,
    model: SplitQueueModel,
    armed: bool,
}

impl DriverSession {
    fn attach(transport: MmioTransport, authority: DriverAuthority) -> Option<Self> {
        if CONTROL.lock().quarantined {
            complete_active(Err(BlockError::Quarantined));
            return None;
        }
        if DMA_CLAIMED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            complete_active(Err(BlockError::DriverRestarted));
            return None;
        }
        {
            let mut installed = AUTHORITY.lock();
            if installed.is_some() {
                DMA_CLAIMED.store(false, Ordering::Release);
                complete_active(Err(BlockError::DriverRestarted));
                return None;
            }
            *installed = Some(authority);
        }

        let domain = crate::heap::current_domain();
        DRIVER_OWNER.store(domain.owner.get(), Ordering::Release);
        DRIVER_ARENA.store(domain.arena.get(), Ordering::Release);
        clear_dma();

        let (features, capacity) = match initialize(transport) {
            Ok(initialized) => initialized,
            Err(error) => {
                let reset = transport.reset(RESET_POLL_BUDGET);
                if reset {
                    DMA_CLAIMED.store(false, Ordering::Release);
                } else {
                    CONTROL.lock().quarantined = true;
                }
                *AUTHORITY.lock() = None;
                complete_active(Err(error));
                return None;
            }
        };

        let epoch = {
            let mut control = CONTROL.lock();
            control.epoch = control.epoch.checked_add(1).expect("block epoch exhausted");
            control.transport = Some(transport);
            control.features = Some(features);
            control.capacity = capacity;
            control.online = true;
            control.epoch
        };
        let _ = plic::unregister(transport.irq());
        // The PLIC's atomic callback record publishes this validated transport
        // base together with the handler, so the top half needs no second lock
        // or revocable snapshot.
        if plic::register(transport.irq(), irq_top_half, transport.base()).is_err()
            || plic::enable(transport.irq()).is_err()
        {
            shutdown(transport, BlockError::DriverCancelled);
            return None;
        }
        transport.add_status(virtio::STATUS_DRIVER_OK);

        Some(Self {
            transport,
            model: SplitQueueModel::at_epoch(features, epoch).expect("driver epochs are non-zero"),
            armed: true,
        })
    }

    async fn perform(&mut self, request: PendingRequest) -> Result<[u8; 512], BlockError> {
        // Process status/configuration interrupts again after claiming the
        // request. This closes the race between the idle check and descriptor
        // publication without trusting an IRQ as proof of completion.
        self.service_device_events()?;
        // Capacity and negotiated feature state may have changed while this
        // request waited in the client slot. Revalidate after draining device
        // events and before exposing another descriptor.
        validate_operation(request.operation)?;
        if !authority_live(self.transport) {
            return Err(BlockError::AuthorityRevoked);
        }
        let submission = self.model.submit(request.operation).map_err(queue_error)?;
        publish_request(request, submission.available_slot)?;
        if !SUPPRESS_NEXT_NOTIFY.swap(false, Ordering::AcqRel) {
            self.transport.notify_queue(0);
        }

        if FAULT_AFTER_PUBLISH.swap(false, Ordering::AcqRel) {
            panic!("injected virtio-blk fault after DMA publication");
        }

        let outcome = wait_for_completion(self.transport, self.model.used_index()).await;
        let (observed_used, used) = match outcome {
            WaitOutcome::Completed { used_index, used } => (used_index, used),
            WaitOutcome::TimedOut => {
                self.model
                    .timeout(submission)
                    .expect("the active block submission must time out");
                self.reset_required_transport()?;
                return Err(BlockError::TimedOut);
            }
            WaitOutcome::DeviceNeedsReset => {
                self.model.require_reset(ResetReason::DeviceNeedsReset);
                self.reset_required_transport()?;
                return Err(BlockError::DriverRestarted);
            }
        };

        // If completion and DEVICE_NEEDS_RESET become visible together, reset
        // wins. Do not interpret device-writable DMA after observing that the
        // device has declared this session unreliable.
        if self.transport.status() & virtio::STATUS_DEVICE_NEEDS_RESET != 0 {
            self.model.require_reset(ResetReason::DeviceNeedsReset);
            self.reset_required_transport()?;
            return Err(BlockError::DriverRestarted);
        }

        let status = unsafe { core::ptr::addr_of!((*DMA.0.get()).status).read_volatile() };
        let completion = match self.model.complete(submission, observed_used, used, status) {
            Ok(completion) => completion,
            Err(_) => {
                self.reset_required_transport()?;
                return Err(BlockError::Protocol);
            }
        };
        match completion.block_status {
            BlockStatus::Ok => {
                if matches!(request.operation, BlockOperation::Read { .. }) {
                    Ok(read_dma_data())
                } else {
                    Ok([0; 512])
                }
            }
            BlockStatus::IoError => Err(BlockError::DeviceIo),
            BlockStatus::Unsupported => Err(BlockError::Unsupported),
        }
    }

    /// Drain causes recorded by the IRQ top half while the request queue is
    /// idle. A device reset request is handled before another descriptor can
    /// be published; a configuration change refreshes capacity through the
    /// bounded generation protocol.
    fn service_device_events(&mut self) -> Result<(), BlockError> {
        // Revocation must be observed before even an idle status/config read.
        // The only raw transport operations allowed after this fails are the
        // Drop/shutdown reset and IRQ quiescence required for DMA safety.
        if !authority_live(self.transport) {
            return Err(BlockError::AuthorityRevoked);
        }
        let causes = virtio::InterruptCauses::from_status(IRQ_CAUSES.swap(0, Ordering::AcqRel));
        if self.transport.status() & virtio::STATUS_DEVICE_NEEDS_RESET != 0 {
            self.model.require_reset(ResetReason::DeviceNeedsReset);
            return self.reset_required_transport();
        }
        if causes.configuration_change() {
            if let Some(capacity) = self.transport.block_capacity() {
                CONTROL.lock().capacity = capacity;
            } else {
                // A permanently moving generation is a faulty transport, not
                // permission to monopolize the non-preemptive kernel hart.
                self.model.require_reset(ResetReason::DeviceNeedsReset);
                self.reset_required_transport()?;
            }
        }
        Ok(())
    }

    /// Reset a queue model which is already in ResetRequired, then negotiate a
    /// fresh session before allowing its stable DMA slab to be reused.
    fn reset_required_transport(&mut self) -> Result<(), BlockError> {
        let _ = plic::disable(self.transport.irq());
        if !self.transport.reset(RESET_POLL_BUDGET) {
            self.quarantine();
            return Err(BlockError::Quarantined);
        }
        let _ = self.transport.acknowledge_interrupt();
        IRQ_CAUSES.store(0, Ordering::Release);
        self.model
            .confirm_reset(0)
            .expect("confirmed transport reset releases descriptors");
        self.reinitialize_after_reset()
    }

    fn reinitialize_after_reset(&mut self) -> Result<(), BlockError> {
        let _ = plic::disable(self.transport.irq());
        let _ = self.transport.acknowledge_interrupt();
        IRQ_CAUSES.store(0, Ordering::Release);
        clear_dma();

        if let Ok((features, capacity)) = initialize(self.transport) {
            if plic::enable(self.transport.irq()).is_ok() {
                self.transport.add_status(virtio::STATUS_DRIVER_OK);
                self.model = SplitQueueModel::at_epoch(features, self.model.epoch())
                    .expect("a live driver epoch is non-zero");
                let mut control = CONTROL.lock();
                control.features = Some(features);
                control.capacity = capacity;
                control.epoch = self.model.epoch();
                control.online = true;
                return Ok(());
            }
        }

        // A second initialization can fail after status zero was already
        // confirmed. Fail closed: quiesce once more and terminate this
        // incarnation instead of leaving a stale `online` session.
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
        self.armed = false;
        if reset {
            clear_dma();
            DMA_CLAIMED.store(false, Ordering::Release);
            DRIVER_OWNER.store(OwnerId::SYSTEM.get(), Ordering::Release);
            DRIVER_ARENA.store(ArenaId::UNTRACKED.get(), Ordering::Release);
            Err(BlockError::Offline)
        } else {
            Err(BlockError::Quarantined)
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
        // DMA_CLAIMED intentionally remains set: reset was not confirmed.
    }
}

impl Drop for DriverSession {
    fn drop(&mut self) {
        if self.armed {
            shutdown(self.transport, BlockError::DriverCancelled);
            self.armed = false;
        }
    }
}

fn initialize(transport: MmioTransport) -> Result<(NegotiatedFeatures, u64), BlockError> {
    if !transport.reset(RESET_POLL_BUDGET) {
        return Err(BlockError::Quarantined);
    }
    let mut init = ModernInit::new();
    transport.set_status(init.acknowledge().map_err(|_| BlockError::Protocol)?);
    transport.set_status(init.declare_driver().map_err(|_| BlockError::Protocol)?);
    let features = init
        .select_features(transport.device_features())
        .map_err(|_| BlockError::Unsupported)?;
    transport.set_driver_features(features.accepted());
    transport.set_status(init.set_features_ok().map_err(|_| BlockError::Protocol)?);
    init.confirm_features(transport.status())
        .map_err(|_| BlockError::Unsupported)?;

    transport.select_queue(0);
    if transport.queue_ready() || transport.queue_num_max() < SPLIT_QUEUE_SIZE {
        return Err(BlockError::Unsupported);
    }
    let (descriptors, available, used) = dma_addresses();
    transport.configure_queue(SPLIT_QUEUE_SIZE, descriptors, available, used);
    let capacity = transport.block_capacity().ok_or(BlockError::Protocol)?;
    Ok((features, capacity))
}

fn shutdown(transport: MmioTransport, reason: BlockError) {
    let _ = plic::disable(transport.irq());
    let _ = plic::unregister(transport.irq());
    let reset = transport.reset(RESET_POLL_BUDGET);
    let _ = transport.acknowledge_interrupt();
    IRQ_CAUSES.store(0, Ordering::Release);
    {
        let mut control = CONTROL.lock();
        control.online = false;
        if !reset {
            control.quarantined = true;
        }
    }
    complete_active(Err(if reset {
        reason
    } else {
        BlockError::Quarantined
    }));
    *AUTHORITY.lock() = None;
    if reset {
        clear_dma();
        DMA_CLAIMED.store(false, Ordering::Release);
        DRIVER_OWNER.store(OwnerId::SYSTEM.get(), Ordering::Release);
        DRIVER_ARENA.store(ArenaId::UNTRACKED.get(), Ordering::Release);
    }
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
        && authority.service.try_with(|_| ()).is_ok()
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

async fn wait_for_completion(transport: MmioTransport, previous_used: u16) -> WaitOutcome {
    let deadline = crate::sbi::time()
        .saturating_add(REQUEST_TIMEOUT_MS.saturating_mul(exec::timebase_hz() / 1_000));
    loop {
        // Listener-before-check closes completion between the ring load and
        // waiter registration. A configuration-only IRQ consumes this listener
        // and the outer loop immediately installs a fresh one.
        let irq = IRQ_WAIT.wait();
        if transport.status() & virtio::STATUS_DEVICE_NEEDS_RESET != 0 {
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
        let remaining_ticks = deadline - now;
        let remaining_ms = remaining_ticks
            .saturating_mul(1_000)
            .div_ceil(exec::timebase_hz())
            .max(1);
        let timeout = exec::sleep_ms(remaining_ms);
        let mut irq = pin!(irq);
        let mut timeout = pin!(timeout);
        let signal = poll_fn(|cx| {
            if transport.status() & virtio::STATUS_DEVICE_NEEDS_RESET != 0 {
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

/// Acknowledge the two architected virtio-mmio interrupt bits from a transport
/// base captured in the PLIC's atomic handler publication. The base can only
/// originate from a successfully probed `MmioTransport`; no task-owned pointer
/// or revocable object is dereferenced in the top half.
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

fn publish_request(request: PendingRequest, available_slot: u16) -> Result<(), BlockError> {
    let addresses = unsafe {
        let slab = DMA.0.get();
        BlockDmaAddresses {
            header: core::ptr::addr_of!((*slab).header) as u64,
            data: core::ptr::addr_of!((*slab).data) as u64,
            status: core::ptr::addr_of!((*slab).status) as u64,
        }
    };
    let chain = virtio::build_block_chain(request.operation, addresses)
        .map_err(|_| BlockError::Protocol)?;
    unsafe {
        let slab = DMA.0.get();
        core::ptr::addr_of_mut!((*slab).header)
            .write_volatile(BlockRequestHeader::new(request.operation));
        core::ptr::addr_of_mut!((*slab).status).write_volatile(0xff);
        if matches!(request.operation, BlockOperation::Write { .. }) {
            let data = core::ptr::addr_of_mut!((*slab).data) as *mut u8;
            for (index, byte) in request.data.iter().copied().enumerate() {
                data.add(index).write_volatile(byte);
            }
        }
        for (index, descriptor) in chain.descriptors.iter().copied().enumerate() {
            core::ptr::addr_of_mut!((*slab).descriptors[index]).write_volatile(descriptor);
        }
        let ring = core::ptr::addr_of_mut!((*slab).available.ring) as *mut u16;
        ring.add(available_slot as usize)
            .write_volatile(virtio::BLOCK_HEADER_DESCRIPTOR.to_le());
        dma_fence();
        let index = core::ptr::addr_of_mut!((*slab).available.index);
        let next = u16::from_le(index.read_volatile()).wrapping_add(1);
        index.write_volatile(next.to_le());
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
        // Safety: attach owns DMA_CLAIMED, or fault recovery has made the old
        // incarnation terminal and confirmed device reset before this call.
        core::ptr::write_bytes(DMA.0.get().cast::<u8>(), 0, DMA_BYTES);
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

fn read_dma_data() -> [u8; 512] {
    let mut data = [0u8; 512];
    unsafe {
        let source = core::ptr::addr_of!((*DMA.0.get()).data) as *const u8;
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = source.add(index).read_volatile();
        }
    }
    data
}

#[inline]
fn dma_fence() {
    unsafe { core::arch::asm!("fence iorw, iorw", options(nostack, preserves_flags)) };
}

fn queue_error(error: virtio::QueueError) -> BlockError {
    match error {
        virtio::QueueError::Busy => BlockError::QueueFull,
        virtio::QueueError::ReadOnly => BlockError::ReadOnly,
        virtio::QueueError::FlushUnsupported => BlockError::FlushUnsupported,
        _ => BlockError::Protocol,
    }
}

/// Deterministic acceptance hook: the next request faults after QueueNotify,
/// proving fault teardown resets the live device before DMA reuse.
pub fn inject_fault_after_publish() {
    FAULT_AFTER_PUBLISH.store(true, Ordering::Release);
}

/// Suppress one QueueNotify so the real timer path deterministically proves a
/// timeout performs full reset before the next request reuses descriptors.
pub fn inject_timeout() {
    SUPPRESS_NEXT_NOTIFY.store(true, Ordering::Release);
}

pub fn is_online() -> bool {
    let control = CONTROL.lock();
    control.online && !control.quarantined
}

/// Device-specific half of raw fault recovery. It runs before the generic
/// component arena is reclaimed and before Faulted becomes observable.
///
/// # Safety
/// The executor guarantees that every task in `domain` is detached forever.
pub unsafe fn recover_faulted_domain(domain: AllocationDomain) {
    // A client may have faulted after enqueueing or while awaiting completion.
    // Recover its abandoned request guard even when this is not the driver
    // domain; in-flight DMA remains owned by the live driver until completion.
    let _ = unsafe { REQUEST.recover_after_fault(domain) };
    abandon_requests_for_domain(domain);

    if DRIVER_OWNER.load(Ordering::Acquire) != domain.owner.get()
        || DRIVER_ARENA.load(Ordering::Acquire) != domain.arena.get()
    {
        return;
    }

    // Safety: the executor contract above means an abandoned guard from this
    // exact domain can never later run Drop and manufacture a second borrow.
    let _ = unsafe { CONTROL.recover_after_fault(domain) };
    let _ = unsafe { AUTHORITY.recover_after_fault(domain) };

    let transport = CONTROL.lock().transport;
    if let Some(transport) = transport {
        shutdown(transport, BlockError::DriverFault);
    } else {
        complete_active(Err(BlockError::DriverFault));
    }
}

fn abandon_requests_for_domain(domain: AllocationDomain) {
    let mut wake_driver = false;
    let mut wake_client = false;
    let mut slot = REQUEST.lock();
    match *slot {
        RequestSlot::Queued(request) if request.requester == domain => {
            *slot = RequestSlot::Empty;
            wake_driver = true;
        }
        RequestSlot::InFlight(mut request) if request.requester == domain => {
            request.abandoned = true;
            *slot = RequestSlot::InFlight(request);
        }
        RequestSlot::Completed { requester, .. } if requester == domain => {
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
