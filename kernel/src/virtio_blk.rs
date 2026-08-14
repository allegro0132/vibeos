//! Supervised modern virtio-blk service.
//!
//! The component future owns scheduling and supervision, while the driver
//! crate owns protocol progress and its fixed DMA slab. Cancellation may drop
//! a future and a fault may skip every destructor, so recovery still confirms
//! device reset before permitting the driver crate to reuse those addresses.

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

use crate::cap::{Cap, Resource, Revocable, Rights};
use crate::exec::{self, WaitQueue};
use crate::heap::{AllocationDomain, ArenaId, OwnerId};
use crate::plic;
use crate::sync::SpinLock;
use crate::virtio::{self, BlockOperation, UsedElement, BLOCK_MAX_TRANSFER_SIZE, SPLIT_QUEUE_SIZE};
use crate::world::Space;

use crate::virtio_mmio::MmioTransport;
use vibeos_driver_virtio_blk::{self as block_driver, BlockEngine, HardwareError};
use vibeos_storage_device::{MutationFailure, MutationResult};

const REQUEST_TIMEOUT_MS: u64 = 2_000;

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct BlockTelemetry {
    pub requests: u64,
    pub read_requests: u64,
    pub write_requests: u64,
    pub flush_requests: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub used_interrupts: u64,
}

impl BlockTelemetry {
    pub(crate) fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            requests: self.requests.saturating_sub(earlier.requests),
            read_requests: self.read_requests.saturating_sub(earlier.read_requests),
            write_requests: self.write_requests.saturating_sub(earlier.write_requests),
            flush_requests: self.flush_requests.saturating_sub(earlier.flush_requests),
            read_bytes: self.read_bytes.saturating_sub(earlier.read_bytes),
            write_bytes: self.write_bytes.saturating_sub(earlier.write_bytes),
            used_interrupts: self.used_interrupts.saturating_sub(earlier.used_interrupts),
        }
    }
}

pub(crate) fn telemetry() -> BlockTelemetry {
    BlockTelemetry {
        requests: REQUEST_COUNT.load(Ordering::Acquire),
        read_requests: READ_REQUEST_COUNT.load(Ordering::Acquire),
        write_requests: WRITE_REQUEST_COUNT.load(Ordering::Acquire),
        flush_requests: FLUSH_REQUEST_COUNT.load(Ordering::Acquire),
        read_bytes: READ_BYTE_COUNT.load(Ordering::Acquire),
        write_bytes: WRITE_BYTE_COUNT.load(Ordering::Acquire),
        used_interrupts: USED_INTERRUPT_COUNT.load(Ordering::Acquire),
    }
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
            block_driver::dma_base(),
            block_driver::DMA_BYTES
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
            read_only: control.read_only,
            supports_flush: control.supports_flush,
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

/// Raw backend entry points used only by the capability-scoped facade. The
/// facade validates a `BlockRange` invocation before calling these functions;
/// no client module receives the raw `BlockDevice` capability.
pub(crate) fn raw_info() -> BlockInfo {
    BlockDevice.info()
}

pub(crate) async fn raw_read_at(expected_epoch: u64, sector: u64) -> Result<[u8; 512], BlockError> {
    let mut output = [0; 512];
    raw_read_blocks_at(expected_epoch, sector, 1, &mut output).await?;
    Ok(output)
}

pub(crate) async fn raw_read_blocks_at(
    expected_epoch: u64,
    sector: u64,
    block_count: u32,
    output: &mut [u8],
) -> Result<(), BlockError> {
    let operation = if block_count == 1 {
        BlockOperation::Read { sector }
    } else {
        BlockOperation::ReadBlocks {
            sector,
            block_count,
        }
    };
    request_at(expected_epoch, operation, &[], output)
        .await
        .map_err(|failure| failure.error)
}

pub(crate) async fn raw_write_at(
    expected_epoch: u64,
    sector: u64,
    data: [u8; 512],
) -> MutationResult<(), BlockError> {
    raw_write_blocks_at(expected_epoch, sector, 1, &data).await
}

pub(crate) async fn raw_write_blocks_at(
    expected_epoch: u64,
    sector: u64,
    block_count: u32,
    data: &[u8],
) -> MutationResult<(), BlockError> {
    let operation = if block_count == 1 {
        BlockOperation::Write { sector }
    } else {
        BlockOperation::WriteBlocks {
            sector,
            block_count,
        }
    };
    request_at(expected_epoch, operation, data, &mut [])
        .await
        .map_err(RequestFailure::into_mutation)
}

pub(crate) async fn raw_flush_at(expected_epoch: u64) -> MutationResult<(), BlockError> {
    request_at(expected_epoch, BlockOperation::Flush, &[], &mut [])
        .await
        .map_err(RequestFailure::into_mutation)
}

pub struct BlockResources {
    pub mmio: Arc<MmioWindow>,
    pub dma: Arc<DmaRegion>,
    pub device: Arc<BlockDevice>,
}

/// Discover a real device. Empty QEMU transport slots are not an error and no
/// block component is spawned when no device is present.
pub fn discover() -> Option<BlockResources> {
    // Safety: the selected BSP maps this trusted VirtIO MMIO aperture into
    // the kernel's identity address space before device discovery begins.
    let transport = unsafe { MmioTransport::scan_block(crate::platform::VIRTIO_MMIO) }?;
    Some(BlockResources {
        mmio: MmioWindow::new(transport),
        dma: Arc::new(DmaRegion),
        device: BlockDevice::new(),
    })
}

#[derive(Clone, Copy)]
struct PendingRequest {
    id: u64,
    expected_epoch: u64,
    operation: BlockOperation,
    data_len: u32,
    abandoned: bool,
    submitted: bool,
    requester: AllocationDomain,
}

#[derive(Clone, Copy)]
struct RequestFailure {
    error: BlockError,
    submitted: bool,
}

impl RequestFailure {
    const fn not_submitted(error: BlockError) -> Self {
        Self {
            error,
            submitted: false,
        }
    }

    const fn ambiguous(error: BlockError) -> Self {
        Self {
            error,
            submitted: true,
        }
    }

    const fn for_phase(error: BlockError, submitted: bool) -> Self {
        if submitted {
            Self::ambiguous(error)
        } else {
            Self::not_submitted(error)
        }
    }

    fn into_mutation(self) -> MutationFailure<BlockError> {
        if self.submitted {
            MutationFailure::ambiguous(self.error)
        } else {
            MutationFailure::not_submitted(self.error)
        }
    }
}

type RequestResult = Result<(), RequestFailure>;

struct StableRequestData(UnsafeCell<[u8; BLOCK_MAX_TRANSFER_SIZE as usize]>);

// Safety: REQUEST is the ownership state machine for this buffer. The client
// writes it only while changing Empty -> Queued; the driver owns it while the
// slot is Queued/InFlight, and a successful reader copies it before changing
// Completed -> Empty. IRQ code never dereferences it.
unsafe impl Sync for StableRequestData {}

#[derive(Clone, Copy)]
enum RequestSlot {
    Empty,
    Queued(PendingRequest),
    InFlight(PendingRequest),
    Completed {
        id: u64,
        result: RequestResult,
        requester: AllocationDomain,
    },
}

struct DriverControl {
    transport: Option<MmioTransport>,
    read_only: bool,
    supports_flush: bool,
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
    read_only: false,
    supports_flush: false,
    capacity: 0,
    epoch: 0,
    online: false,
    quarantined: false,
});
static AUTHORITY: SpinLock<Option<DriverAuthority>> = SpinLock::new_recoverable(None);
static REQUEST: SpinLock<RequestSlot> = SpinLock::new_recoverable(RequestSlot::Empty);
static REQUEST_DATA: StableRequestData =
    StableRequestData(UnsafeCell::new([0; BLOCK_MAX_TRANSFER_SIZE as usize]));
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);
static REQUEST_WAIT: WaitQueue = WaitQueue::new();
static COMPLETION_WAIT: WaitQueue = WaitQueue::new();
static IRQ_WAIT: WaitQueue = WaitQueue::new();
static IRQ_CAUSES: AtomicU32 = AtomicU32::new(0);
static USED_INTERRUPT_COUNT: AtomicU64 = AtomicU64::new(0);
static REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);
static READ_REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);
static WRITE_REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);
static FLUSH_REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);
static READ_BYTE_COUNT: AtomicU64 = AtomicU64::new(0);
static WRITE_BYTE_COUNT: AtomicU64 = AtomicU64::new(0);
static DRIVER_OWNER: AtomicU64 = AtomicU64::new(OwnerId::SYSTEM.get());
static DRIVER_ARENA: AtomicU64 = AtomicU64::new(ArenaId::UNTRACKED.get());
static FAULT_AFTER_PUBLISH: AtomicBool = AtomicBool::new(false);
static SUPPRESS_NEXT_NOTIFY: AtomicBool = AtomicBool::new(false);

fn request_input(request: PendingRequest) -> &'static [u8] {
    if !request.operation.is_write() {
        return &[];
    }
    // Safety: only the driver can call this while REQUEST is InFlight. The
    // client cannot regain access until a terminal completion is published.
    unsafe { &(&*REQUEST_DATA.0.get())[..request.data_len as usize] }
}

fn request_output(request: PendingRequest) -> &'static mut [u8] {
    if !request.operation.is_read() {
        return &mut [];
    }
    // Safety: only the driver can call this while REQUEST is InFlight. It
    // finishes the DMA-to-stable copy before publishing Completed.
    unsafe { &mut (&mut *REQUEST_DATA.0.get())[..request.data_len as usize] }
}

async fn request_at(
    expected_epoch: u64,
    operation: BlockOperation,
    input: &[u8],
    output: &mut [u8],
) -> RequestResult {
    validate_operation(expected_epoch, operation).map_err(RequestFailure::not_submitted)?;
    let data_len = operation.data_len() as usize;
    let buffers_valid = match operation {
        BlockOperation::Read { .. } | BlockOperation::ReadBlocks { .. } => {
            input.is_empty() && output.len() == data_len
        }
        BlockOperation::Write { .. } | BlockOperation::WriteBlocks { .. } => {
            input.len() == data_len && output.is_empty()
        }
        BlockOperation::Flush => input.is_empty() && output.is_empty(),
    };
    if !buffers_valid || data_len > BLOCK_MAX_TRANSFER_SIZE as usize {
        return Err(RequestFailure::not_submitted(BlockError::Protocol));
    }

    let id = NEXT_REQUEST_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .expect("block request id space exhausted");
    {
        let mut slot = REQUEST.lock();
        if !matches!(*slot, RequestSlot::Empty) {
            return Err(RequestFailure::not_submitted(BlockError::QueueFull));
        }
        if operation.is_write() {
            // Safety: the Empty slot gives this client exclusive ownership,
            // and publication to Queued occurs only after the copy completes.
            unsafe { (&mut *REQUEST_DATA.0.get())[..data_len].copy_from_slice(input) };
        }
        *slot = RequestSlot::Queued(PendingRequest {
            id,
            expected_epoch,
            operation,
            data_len: data_len as u32,
            abandoned: false,
            submitted: false,
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
                    if result.is_ok() && operation.is_read() {
                        // Safety: Completed retains driver publication of the
                        // read bytes until this exact client empties the slot.
                        unsafe {
                            output.copy_from_slice(&(&*REQUEST_DATA.0.get())[..data_len]);
                        }
                    }
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

fn validate_operation(expected_epoch: u64, operation: BlockOperation) -> Result<(), BlockError> {
    let info = BlockDevice.info();
    if info.quarantined {
        return Err(BlockError::Quarantined);
    }
    if !info.online {
        return Err(BlockError::Offline);
    }
    if info.session_epoch != expected_epoch {
        return Err(BlockError::DriverRestarted);
    }
    match operation {
        BlockOperation::Read { sector }
        | BlockOperation::Write { sector }
        | BlockOperation::ReadBlocks { sector, .. }
        | BlockOperation::WriteBlocks { sector, .. }
            if sector
                .checked_add(u64::from(operation.block_count()))
                .is_none_or(|end| end > info.capacity_sectors) =>
        {
            return Err(BlockError::OutOfRange);
        }
        _ if operation.is_write() && info.read_only => return Err(BlockError::ReadOnly),
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
        complete_active(BlockError::AuthorityRevoked);
        return;
    };
    let Ok(transport) = authority.mmio.try_with(|window| window.transport) else {
        complete_active(BlockError::AuthorityRevoked);
        return;
    };

    let Some(mut session) = DriverSession::attach(transport, authority) else {
        return;
    };

    loop {
        let listener = REQUEST_WAIT.wait();
        if let Err(error) = session.service_device_events() {
            complete_active(error);
            return;
        }
        let request = take_queued();
        if let Some(request) = request {
            let result = session.perform(request).await;
            let terminal = matches!(
                result,
                Err(RequestFailure {
                    error: BlockError::Quarantined
                        | BlockError::AuthorityRevoked
                        | BlockError::Offline,
                    ..
                })
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

fn mark_submitted(id: u64) {
    let mut slot = REQUEST.lock();
    match *slot {
        RequestSlot::InFlight(mut request) if request.id == id => {
            request.submitted = true;
            *slot = RequestSlot::InFlight(request);
        }
        _ => panic!("published block request lost its in-flight slot"),
    }
}

fn finish_request(request: PendingRequest, result: RequestResult) {
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

fn complete_active(error: BlockError) {
    let mut notify = false;
    let mut slot = REQUEST.lock();
    match *slot {
        RequestSlot::InFlight(request) | RequestSlot::Queued(request) => {
            if request.abandoned {
                *slot = RequestSlot::Empty;
            } else {
                *slot = RequestSlot::Completed {
                    id: request.id,
                    result: Err(RequestFailure::for_phase(error, request.submitted)),
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
    engine: Option<BlockEngine>,
    armed: bool,
}

impl DriverSession {
    fn attach(transport: MmioTransport, authority: DriverAuthority) -> Option<Self> {
        if CONTROL.lock().quarantined {
            complete_active(BlockError::Quarantined);
            return None;
        }
        {
            let mut installed = AUTHORITY.lock();
            if installed.is_some() {
                complete_active(BlockError::DriverRestarted);
                return None;
            }
            *installed = Some(authority);
        }

        let domain = crate::heap::current_domain();
        DRIVER_OWNER.store(domain.owner.get(), Ordering::Release);
        DRIVER_ARENA.store(domain.arena.get(), Ordering::Release);

        let epoch = CONTROL
            .lock()
            .epoch
            .checked_add(1)
            .expect("block epoch exhausted");
        let engine = match BlockEngine::attach(transport, epoch) {
            Ok(engine) => engine,
            Err(error) => {
                if matches!(error, HardwareError::Quarantined) {
                    CONTROL.lock().quarantined = true;
                }
                *AUTHORITY.lock() = None;
                complete_active(map_hardware_error(error));
                return None;
            }
        };

        {
            let info = engine.info();
            let mut control = CONTROL.lock();
            control.epoch = info.epoch;
            control.transport = Some(transport);
            control.read_only = info.read_only;
            control.supports_flush = info.supports_flush;
            control.capacity = info.capacity_sectors;
            control.online = true;
        }
        let _ = plic::unregister(transport.irq());
        // The PLIC's atomic callback record publishes this validated transport
        // base together with the handler, so the top half needs no second lock
        // or revocable snapshot.
        if plic::register(transport.irq(), irq_top_half, transport.base()).is_err()
            || plic::enable(transport.irq()).is_err()
        {
            let _ = plic::disable(transport.irq());
            let _ = plic::unregister(transport.irq());
            let reset = engine.shutdown().is_ok();
            IRQ_CAUSES.store(0, Ordering::Release);
            {
                let mut control = CONTROL.lock();
                control.online = false;
                if !reset {
                    control.quarantined = true;
                }
            }
            complete_active(if reset {
                BlockError::DriverCancelled
            } else {
                BlockError::Quarantined
            });
            *AUTHORITY.lock() = None;
            if reset {
                DRIVER_OWNER.store(OwnerId::SYSTEM.get(), Ordering::Release);
                DRIVER_ARENA.store(ArenaId::UNTRACKED.get(), Ordering::Release);
            }
            return None;
        }
        engine.mark_ready();

        Some(Self {
            engine: Some(engine),
            armed: true,
        })
    }

    fn engine(&self) -> &BlockEngine {
        self.engine
            .as_ref()
            .expect("armed block session has engine")
    }

    fn engine_mut(&mut self) -> &mut BlockEngine {
        self.engine
            .as_mut()
            .expect("armed block session has engine")
    }

    async fn perform(&mut self, request: PendingRequest) -> RequestResult {
        // Process status/configuration interrupts again after claiming the
        // request. This closes the race between the idle check and descriptor
        // publication without trusting an IRQ as proof of completion.
        self.service_device_events()
            .map_err(RequestFailure::not_submitted)?;
        // Capacity and negotiated feature state may have changed while this
        // request waited in the client slot. Revalidate after draining device
        // events and before exposing another descriptor.
        validate_operation(request.expected_epoch, request.operation)
            .map_err(RequestFailure::not_submitted)?;
        let transport = self.engine().transport();
        if !authority_live(transport) {
            return Err(RequestFailure::not_submitted(BlockError::AuthorityRevoked));
        }
        let submission = self
            .engine_mut()
            .submit_tracked(request.operation, request_input(request), || {
                mark_submitted(request.id)
            })
            .map_err(map_hardware_error)
            .map_err(RequestFailure::not_submitted)?;
        REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
        if request.operation.is_read() {
            READ_REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
            READ_BYTE_COUNT.fetch_add(u64::from(request.data_len), Ordering::Relaxed);
        } else if request.operation.is_write() {
            WRITE_REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
            WRITE_BYTE_COUNT.fetch_add(u64::from(request.data_len), Ordering::Relaxed);
        } else {
            FLUSH_REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        if !SUPPRESS_NEXT_NOTIFY.swap(false, Ordering::AcqRel) {
            self.engine().notify();
        }

        if FAULT_AFTER_PUBLISH.swap(false, Ordering::AcqRel) {
            panic!("injected virtio-blk fault after DMA publication");
        }

        let outcome = wait_for_completion(self.engine(), submission.previous_used_index()).await;
        let (observed_used, used) = match outcome {
            WaitOutcome::Completed { used_index, used } => (used_index, used),
            WaitOutcome::TimedOut => {
                self.engine_mut()
                    .timeout(submission)
                    .expect("the active block submission must time out");
                self.reset_required_transport()
                    .map_err(RequestFailure::ambiguous)?;
                return Err(RequestFailure::ambiguous(BlockError::TimedOut));
            }
            WaitOutcome::DeviceNeedsReset => {
                self.engine_mut().require_device_reset();
                self.reset_required_transport()
                    .map_err(RequestFailure::ambiguous)?;
                return Err(RequestFailure::ambiguous(BlockError::DriverRestarted));
            }
        };

        // If completion and DEVICE_NEEDS_RESET become visible together, reset
        // wins. Do not interpret device-writable DMA after observing that the
        // device has declared this session unreliable.
        if self.engine().device_needs_reset() {
            self.engine_mut().require_device_reset();
            self.reset_required_transport()
                .map_err(RequestFailure::ambiguous)?;
            return Err(RequestFailure::ambiguous(BlockError::DriverRestarted));
        }

        match self
            .engine_mut()
            .complete(submission, observed_used, used, request_output(request))
        {
            Ok(()) => Ok(()),
            Err(HardwareError::Protocol) => {
                self.reset_required_transport()
                    .map_err(RequestFailure::ambiguous)?;
                Err(RequestFailure::ambiguous(BlockError::Protocol))
            }
            Err(error) => Err(RequestFailure::ambiguous(map_hardware_error(error))),
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
        if !authority_live(self.engine().transport()) {
            return Err(BlockError::AuthorityRevoked);
        }
        let causes = virtio::InterruptCauses::from_status(IRQ_CAUSES.swap(0, Ordering::AcqRel));
        if self.engine().device_needs_reset() {
            self.engine_mut().require_device_reset();
            return self.reset_required_transport();
        }
        if causes.configuration_change() {
            if let Ok(capacity) = self.engine_mut().refresh_capacity() {
                CONTROL.lock().capacity = capacity;
            } else {
                // A permanently moving generation is a faulty transport, not
                // permission to monopolize the non-preemptive kernel hart.
                self.reset_required_transport()?;
            }
        }
        Ok(())
    }

    /// Reset a queue model which is already in ResetRequired, then negotiate a
    /// fresh session before allowing its stable DMA slab to be reused.
    fn reset_required_transport(&mut self) -> Result<(), BlockError> {
        let transport = self.engine().transport();
        let _ = plic::disable(transport.irq());
        IRQ_CAUSES.store(0, Ordering::Release);
        match self.engine_mut().reset_and_reinitialize() {
            Ok(()) => self.reinitialize_after_reset(),
            Err(HardwareError::Quarantined) => {
                self.quarantine();
                Err(BlockError::Quarantined)
            }
            Err(error) => Err(map_hardware_error(error)),
        }
    }

    fn reinitialize_after_reset(&mut self) -> Result<(), BlockError> {
        let transport = self.engine().transport();
        let _ = plic::disable(transport.irq());
        let _ = transport.acknowledge_interrupt();
        IRQ_CAUSES.store(0, Ordering::Release);

        if plic::enable(transport.irq()).is_ok() {
            self.engine().mark_ready();
            let info = self.engine().info();
            let mut control = CONTROL.lock();
            control.read_only = info.read_only;
            control.supports_flush = info.supports_flush;
            control.capacity = info.capacity_sectors;
            control.epoch = info.epoch;
            control.online = true;
            return Ok(());
        }

        // A second initialization can fail after status zero was already
        // confirmed. Fail closed: quiesce once more and terminate this
        // incarnation instead of leaving a stale `online` session.
        let _ = plic::disable(transport.irq());
        let reset = self
            .engine
            .take()
            .expect("terminating block session has engine")
            .shutdown()
            .is_ok();
        let _ = plic::unregister(transport.irq());
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
            DRIVER_OWNER.store(OwnerId::SYSTEM.get(), Ordering::Release);
            DRIVER_ARENA.store(ArenaId::UNTRACKED.get(), Ordering::Release);
            Err(BlockError::Offline)
        } else {
            Err(BlockError::Quarantined)
        }
    }

    fn quarantine(&mut self) {
        let transport = self.engine().transport();
        let _ = plic::disable(transport.irq());
        let _ = plic::unregister(transport.irq());
        let _ = transport.acknowledge_interrupt();
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
            let transport = self.engine().transport();
            let _ = plic::disable(transport.irq());
            let _ = plic::unregister(transport.irq());
            let reset = self
                .engine
                .take()
                .expect("armed block session has engine")
                .shutdown()
                .is_ok();
            IRQ_CAUSES.store(0, Ordering::Release);
            {
                let mut control = CONTROL.lock();
                control.online = false;
                if !reset {
                    control.quarantined = true;
                }
            }
            complete_active(if reset {
                BlockError::DriverCancelled
            } else {
                BlockError::Quarantined
            });
            *AUTHORITY.lock() = None;
            if reset {
                DRIVER_OWNER.store(OwnerId::SYSTEM.get(), Ordering::Release);
                DRIVER_ARENA.store(ArenaId::UNTRACKED.get(), Ordering::Release);
            }
            self.armed = false;
        }
    }
}

fn shutdown_transport(transport: MmioTransport, reason: BlockError) {
    let _ = plic::disable(transport.irq());
    let _ = plic::unregister(transport.irq());
    // Safety: the executor has made the faulted owner permanently unable to
    // resume, so no live BlockEngine can touch the slab after this point.
    let reset = unsafe { block_driver::recover_after_fault(transport) }.is_ok();
    IRQ_CAUSES.store(0, Ordering::Release);
    {
        let mut control = CONTROL.lock();
        control.online = false;
        if !reset {
            control.quarantined = true;
        }
    }
    complete_active(if reset {
        reason
    } else {
        BlockError::Quarantined
    });
    *AUTHORITY.lock() = None;
    if reset {
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

async fn wait_for_completion(engine: &BlockEngine, previous_used: u16) -> WaitOutcome {
    let transport = engine.transport();
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
        let used_index = engine.used_index();
        if used_index != previous_used {
            return WaitOutcome::Completed {
                used_index,
                used: engine.used_element(previous_used),
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
            let used_index = engine.used_index();
            if used_index != previous_used {
                return Poll::Ready(WaitSignal::Completed {
                    used_index,
                    used: engine.used_element(previous_used),
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
                return WaitOutcome::Completed { used_index, used };
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
    unsafe { block_driver::acknowledge_interrupt_at(transport_base) }
}

fn map_hardware_error(error: HardwareError) -> BlockError {
    match error {
        HardwareError::AlreadyClaimed => BlockError::DriverRestarted,
        HardwareError::QueueFull => BlockError::QueueFull,
        HardwareError::ReadOnly => BlockError::ReadOnly,
        HardwareError::FlushUnsupported => BlockError::FlushUnsupported,
        HardwareError::DeviceIo => BlockError::DeviceIo,
        HardwareError::Unsupported => BlockError::Unsupported,
        HardwareError::Protocol => BlockError::Protocol,
        HardwareError::Quarantined => BlockError::Quarantined,
        HardwareError::RestartRequired => BlockError::DriverRestarted,
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
        shutdown_transport(transport, BlockError::DriverFault);
    } else {
        complete_active(BlockError::DriverFault);
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
