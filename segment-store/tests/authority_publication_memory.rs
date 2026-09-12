//! Host requested-allocation probe; run alone with --ignored --nocapture --test-threads=1.
//! The backing device is preallocated, so media writes do not add heap nodes.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::future::Future;
use std::task::{Context, Poll, Waker};
use vibeos_durable_format::{RecordBody, RecordChain, StoreId};
use vibeos_segment_format::{admitted_pages, Page, StoreUuid};
use vibeos_segment_store::{FormatOptions, PageDevice, PageDeviceInfo,
    PersistentAuthorityImport, SegmentStore, StoreLimits, StoreRuntimeContext};
use vibeos_storage_device::MutationFailure;

struct Meter;
static REQUESTED_BYTES: AtomicUsize = AtomicUsize::new(0);
static ALLOCATION_CALLS: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
fn added(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
        REQUESTED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        let pointer = System.alloc(layout);
        if !pointer.is_null() {
            added(layout.size());
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(pointer, layout);
    }
    unsafe fn realloc(&self, pointer: *mut u8, old: Layout, size: usize) -> *mut u8 {
        ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
        REQUESTED_BYTES.fetch_add(size, Ordering::Relaxed);
        let result = System.realloc(pointer, old, size);
        if !result.is_null() {
            if size >= old.size() {
                added(size - old.size());
            } else {
                LIVE.fetch_sub(old.size() - size, Ordering::Relaxed);
            }
        }
        result
    }
}
#[global_allocator]
static ALLOCATOR: Meter = Meter;


static IO_PEAK: AtomicUsize = AtomicUsize::new(0);
fn note_io_memory() { IO_PEAK.fetch_max(LIVE.load(Ordering::Relaxed), Ordering::Relaxed); }

#[derive(Clone)]
struct Device {
    pages: Arc<Mutex<Vec<Page>>>,
    reads: Arc<AtomicUsize>, writes: Arc<AtomicUsize>, flushes: Arc<AtomicUsize>,
    write_requests: Arc<AtomicUsize>,
}
impl Device {
    fn new() -> Self {
        Self { pages: Arc::new(Mutex::new(vec![[0; 4096]; admitted_pages(16).unwrap() as usize])),
            reads: Arc::new(AtomicUsize::new(0)), writes: Arc::new(AtomicUsize::new(0)),
            flushes: Arc::new(AtomicUsize::new(0)), write_requests: Arc::new(AtomicUsize::new(0)) }
    }
    fn reset(&self) {
        for counter in [&self.reads, &self.writes, &self.flushes, &self.write_requests] { counter.store(0, Ordering::Relaxed); }
    }
}
impl PageDevice for Device {
    type Error = ();
    fn info(&self) -> PageDeviceInfo {
        let page_count = admitted_pages(16).unwrap();
        PageDeviceInfo { device_id: [7;16], range_first_logical_block: 0,
            logical_block_count: page_count * 8, logical_block_size: 512, page_count }
    }
    async fn read_page(&self, index: u64, output: &mut Page) -> Result<(), ()> {
        note_io_memory();
        let pages = self.pages.lock().unwrap();
        *output = *pages.get(index as usize).ok_or(())?;
        self.reads.fetch_add(1, Ordering::Relaxed); Ok(())
    }
    async fn write_page(&self, index: u64, input: &Page) -> Result<(), MutationFailure<()>> {
        note_io_memory();
        let mut pages = self.pages.lock().unwrap();
        *pages.get_mut(index as usize).ok_or(MutationFailure::not_submitted(()))? = *input;
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.write_requests.fetch_add(1, Ordering::Relaxed); Ok(())
    }
    async fn write_pages(&self, first: u64, input: &[Page]) -> Result<(), MutationFailure<()>> {
        note_io_memory();
        let mut pages = self.pages.lock().unwrap();
        let end = (first as usize).checked_add(input.len()).ok_or(MutationFailure::not_submitted(()))?;
        pages.get_mut(first as usize..end).ok_or(MutationFailure::not_submitted(()))?.copy_from_slice(input);
        self.writes.fetch_add(input.len(), Ordering::Relaxed);
        self.write_requests.fetch_add(1, Ordering::Relaxed); Ok(())
    }
    async fn flush(&self) -> Result<(), MutationFailure<()>> {
        note_io_memory();
        self.flushes.fetch_add(1, Ordering::Relaxed); Ok(())
    }
}
fn run<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut Context::from_waker(Waker::noop())) { return output; }
    }
}
#[test]
#[ignore = "isolated host allocation measurement"]
fn authority_publication_requested_allocation() {
    for count in [32usize, 2048, 4096] {
        let device = Device::new();
        let limits = StoreLimits { recovery_memory_bytes: 64 * 1024 * 1024, ..StoreLimits::default() };
        let (runtime, _, provisioner) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
        let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits, runtime);
        run(store.format(FormatOptions { store_uuid: StoreUuid::new([7;16]).unwrap(),
            cleaner_reserve_segments: 4, limits })).unwrap();
        let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
        let id = StoreId::new(7).unwrap();
        let mut chain = RecordChain::new(id);
        let mut records = vec![chain.append(None, RecordBody::Format).unwrap()];
        for index in 1..count {
            records.push(chain.append(None, RecordBody::IdHighWater { exclusive_end: index as u128 + 1 }).unwrap());
        }
        let import = PersistentAuthorityImport::from_m4(&records, id, &[], b"allocation probe", vec![]).unwrap();
        device.reset();
        let baseline = LIVE.load(Ordering::Relaxed);
        PEAK.store(baseline, Ordering::Relaxed);
        IO_PEAK.store(baseline, Ordering::Relaxed);
        let calls = ALLOCATION_CALLS.load(Ordering::Relaxed);
        let requested = REQUESTED_BYTES.load(Ordering::Relaxed);
        let view = run(store.import_persistent_authority(&maintenance, import)).unwrap();
        let requested = REQUESTED_BYTES.load(Ordering::Relaxed) - requested;
        let peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
        let live_delta = LIVE.load(Ordering::Relaxed) as i128 - baseline as i128;
        let calls = ALLOCATION_CALLS.load(Ordering::Relaxed) - calls;
        let io_peak = IO_PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
        let generation = view.checkpoint_generation();
        let snapshot_sha256 = view.snapshot_sha256();
        let reads = device.reads.load(Ordering::Relaxed);
        let writes = device.writes.load(Ordering::Relaxed);
        let flushes = device.flushes.load(Ordering::Relaxed);
        let write_requests = device.write_requests.load(Ordering::Relaxed);
        println!("PUBLICATION_MEMORY records={count} peak_extra={peak} live_delta={live_delta} io_peak_extra={io_peak} calls={calls} requested_bytes={requested} reads={reads} writes={writes} write_requests={write_requests} flushes={flushes}");
        drop(view); drop(store);
        let (runtime, _, _) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
        let mut cold = SegmentStore::new_with_runtime_context(device, limits, runtime);
        let mounted = run(cold.mount()).unwrap();
        assert_eq!(mounted.generation, generation);
        let recovered = run(cold.recover_persistent_authority(
            vibeos_segment_store::root_policy_commitment(b"allocation probe"))).unwrap();
        assert_eq!(recovered.snapshot_sha256(), snapshot_sha256);
        assert_eq!(recovered.record_stream().len(), records.len() * 512);
        for (actual, expected) in recovered.record_stream().chunks_exact(512).zip(&records) {
            assert_eq!(actual, expected);
        }
    }
}

#[test]
#[ignore = "isolated host allocation measurement"]
fn persistent_object_read_requested_allocation() {
    use vibeos_durable_format::{encode_object_transaction, preview_grant_transaction,
        TransactionId, ObjectId, ObjectKind, GrantRecord, DerivationId, SlotIdentity,
        SpaceId, DurableRights, ResourceKind, GrantFlags, RootPolicy};
    for (history_records, size) in [0usize, 256].into_iter().flat_map(|history_records| {
        [4096usize, 65536, 131072, 368640].into_iter().map(move |size| (history_records, size))
    }) {
        let device = Device::new();
        let limits = StoreLimits { recovery_memory_bytes: 64 * 1024 * 1024, ..StoreLimits::default() };
        let (runtime, _, provisioner) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
        let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits, runtime);
        run(store.format(FormatOptions { store_uuid: StoreUuid::new([7;16]).unwrap(), cleaner_reserve_segments: 4, limits })).unwrap();
        let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
        let content = vec![0x5a; size];
        let id = StoreId::new(7).unwrap();
        let mut chain = RecordChain::new(id);
        let mut records = vec![chain.append(None, RecordBody::Format).unwrap(),
            chain.append(None, RecordBody::IdHighWater { exclusive_end: 8 }).unwrap()];
        let mut append_seed = None;
        if history_records != 0 {
            for index in 0..history_records {
                records.push(chain.append(None, RecordBody::IdHighWater { exclusive_end: 9 + index as u128 }).unwrap());
            }
            let seed = PersistentAuthorityImport::from_m4(&records, id, &[], b"read allocation probe", vec![]).unwrap();
            let seed_view = run(store.import_persistent_authority(&maintenance, seed)).unwrap();
            append_seed = Some((seed_view.checkpoint_generation(), seed_view.principals()[0].clone(),
                store.derive_persistent_authority_writer(&maintenance).unwrap()));
        }
        records.extend(encode_object_transaction(&mut chain, TransactionId::new(1).unwrap(),
            ObjectId::new(2).unwrap(), ObjectKind::new(7).unwrap(), &content).unwrap().records);
        let grant = GrantRecord { derivation_id: DerivationId::new(5).unwrap(), parent_id: None,
            object_id: ObjectId::new(2).unwrap(), target: SlotIdentity { space: SpaceId::new(6).unwrap(), slot: 0, generation: 0 },
            rights: DurableRights::READ, resource_kind: ResourceKind::new(7).unwrap(), flags: GrantFlags::ROOT };
        records.extend(preview_grant_transaction(&chain, TransactionId::new(4).unwrap(), grant.clone()).unwrap().0.records);
        let import = PersistentAuthorityImport::from_m4(&records, id, &[RootPolicy { grant }], b"read allocation probe", vec![]).unwrap();
        device.reset();
        let import_baseline = LIVE.load(Ordering::Relaxed);
        PEAK.store(import_baseline, Ordering::Relaxed);
        let import_calls = ALLOCATION_CALLS.load(Ordering::Relaxed);
        let import_requested = REQUESTED_BYTES.load(Ordering::Relaxed);
        let view = match append_seed {
            Some((generation, principal, writer)) => run(store.append_persistent_authority(
                &writer, generation, import, &principal)).unwrap().into_view(),
            None => run(store.import_persistent_authority(&maintenance, import)).unwrap(),
        };
        let import_peak = PEAK.load(Ordering::Relaxed).saturating_sub(import_baseline);
        let import_calls = ALLOCATION_CALLS.load(Ordering::Relaxed) - import_calls;
        let import_requested = REQUESTED_BYTES.load(Ordering::Relaxed) - import_requested;
        println!("OBJECT_IMPORT_MEMORY history_records={history_records} size={size} peak_extra={import_peak} calls={import_calls} requested_bytes={import_requested} read_pages={} write_pages={} write_requests={} flushes={}",
            device.reads.load(Ordering::Relaxed), device.writes.load(Ordering::Relaxed),
            device.write_requests.load(Ordering::Relaxed), device.flushes.load(Ordering::Relaxed));
        assert_eq!(view.objects().len(), 1);
        device.reset();
        let baseline = LIVE.load(Ordering::Relaxed);
        PEAK.store(baseline, Ordering::Relaxed);
        let before = ALLOCATION_CALLS.load(Ordering::Relaxed);
        let bytes = run(store.read_persistent_object(&view.objects()[0])).unwrap();
        let peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
        let calls = ALLOCATION_CALLS.load(Ordering::Relaxed) - before;
        assert_eq!(bytes, content);
        assert_eq!(device.writes.load(Ordering::Relaxed), 0);
        assert_eq!(device.flushes.load(Ordering::Relaxed), 0);
        println!("OBJECT_READ_MEMORY history_records={history_records} size={size} peak_extra={peak} calls={calls} read_pages={}", device.reads.load(Ordering::Relaxed));
    }
}
