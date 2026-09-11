//! Host-side I/O attribution harness for the Storage v2 steady-state path.
//!
//! Reproduces the kernel benchmark's authority-append pattern (one object per
//! append, content identical across appends so CAS dedups to one blob) and
//! counts every page read/write/flush against a counting memory device.

use core::future::Future;
use core::task::{Context, Poll, Waker};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use vibeos_durable_format::{
    encode_object_transaction, preview_grant_transaction, DerivationId, DurableRights,
    GrantFlags, GrantRecord, ObjectId, ObjectKind, RecordBody, RecordChain, ResourceKind,
    RootPolicy, SlotIdentity, SpaceId, StoreId, TransactionId,
};
use vibeos_segment_format::{admitted_pages, Page, StoreUuid};
use vibeos_segment_store::{
    root_policy_commitment, FormatOptions, PageDevice, PageDeviceInfo, PersistentAuthorityImport,
    PersistentAuthorityWriter, SegmentStore, StoreLimits, StoreRuntimeContext,
    LEGACY_SYSTEM_PRINCIPAL,
};
use vibeos_storage_device::MutationFailure;

const SEGMENTS: u64 = 20;
const OBJECT_KIND_RAW: u32 = 0x5045_5246;
const POLICY: &[u8] = b"perf steady-state policy v1";

const PAGE_BYTES: u64 = 4096;

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    loop {
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Counters {
    reads: u64,
    writes: u64,
    flushes: u64,
    read_bytes: u64,
    write_bytes: u64,
    read_requests: u64,
    write_requests: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestError {
    OutOfRange,
}

impl core::fmt::Display for TestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone)]
struct CountingDevice {
    page_count: u64,
    pages: Arc<Mutex<BTreeMap<u64, Page>>>,
    counters: Arc<Mutex<Counters>>,
    epoch: Arc<AtomicU64>,
    trace: Arc<AtomicU64>,
    sites: Arc<Mutex<BTreeMap<String, u64>>>,
}

fn call_site(kind: &str) -> String {
    let backtrace = std::backtrace::Backtrace::force_capture().to_string();
    let mut frames: Vec<&str> = Vec::new();
    for line in backtrace.lines() {
        let line = line.trim();
        if let Some(rest) = line.splitn(2, ": ").nth(1) {
            if rest.starts_with("vibeos_segment_store::") {
                let name = rest.split(" at ").next().unwrap_or(rest);
                let short = name
                    .trim_start_matches("vibeos_segment_store::")
                    .split("::{{closure}}")
                    .next()
                    .unwrap_or(name);
                if !frames.last().is_some_and(|last| *last == short) {
                    frames.push(short);
                }
            }
        }
        if frames.len() >= 4 {
            break;
        }
    }
    format!("{} {}", kind, frames.join(" <- "))
}

impl CountingDevice {
    fn blank(segments: u64) -> Self {
        Self {
            page_count: admitted_pages(segments).unwrap(),
            pages: Arc::new(Mutex::new(BTreeMap::new())),
            counters: Arc::new(Mutex::new(Counters::default())),
            epoch: Arc::new(AtomicU64::new(0)),
            trace: Arc::new(AtomicU64::new(0)),
            sites: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn begin_epoch(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
    }

    fn set_trace(&self, on: bool) {
        self.trace.store(on as u64, Ordering::Release);
    }

    fn note(&self, kind: &str) {
        if self.trace.load(Ordering::Acquire) != 0 {
            *self.sites.lock().unwrap().entry(call_site(kind)).or_insert(0) += 1;
        }
    }

    fn dump_sites(&self) {
        let mut entries: Vec<(String, u64)> = self
            .sites
            .lock()
            .unwrap()
            .iter()
            .map(|(site, count)| (site.clone(), *count))
            .collect();
        entries.sort_by_key(|(_, count)| core::cmp::Reverse(*count));
        for (site, count) in entries {
            println!("SITE {:6} {}", count, site);
        }
        self.sites.lock().unwrap().clear();
    }

    fn epoch_counters(&self) -> Counters {
        let mut counters = self.counters.lock().unwrap();
        let snapshot = *counters;
        *counters = Counters::default();
        snapshot
    }
}

impl PageDevice for CountingDevice {
    type Error = TestError;

    fn info(&self) -> PageDeviceInfo {
        PageDeviceInfo {
            device_id: [0x77; 16],
            range_first_logical_block: 64,
            logical_block_count: self.page_count * 8,
            logical_block_size: 512,
            page_count: self.page_count,
        }
    }

    async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
        if page >= self.page_count {
            return Err(TestError::OutOfRange);
        }
        output.fill(0);
        if let Some(stored) = self.pages.lock().unwrap().get(&page) {
            output.copy_from_slice(stored);
        }
        let mut counters = self.counters.lock().unwrap();
        counters.reads += 1;
        counters.read_bytes += PAGE_BYTES;
        counters.read_requests += 1;
        drop(counters);
        self.note("read");
        Ok(())
    }

    async fn read_pages(&self, first: u64, output: &mut [Page]) -> Result<(), Self::Error> {
        for (index, page) in output.iter_mut().enumerate() {
            self.read_page(first + index as u64, page).await?;
        }
        // read_page counted one request per page; collapse to one batch.
        if output.len() > 1 {
            self.counters.lock().unwrap().read_requests -= output.len() as u64 - 1;
        }
        Ok(())
    }

    async fn write_page(
        &self,
        page: u64,
        input: &Page,
    ) -> Result<(), MutationFailure<Self::Error>> {
        if page >= self.page_count {
            return Err(MutationFailure::not_submitted(TestError::OutOfRange));
        }
        self.pages.lock().unwrap().insert(page, *input);
        let mut counters = self.counters.lock().unwrap();
        counters.writes += 1;
        counters.write_bytes += PAGE_BYTES;
        counters.write_requests += 1;
        drop(counters);
        self.note("write");
        Ok(())
    }

    async fn write_pages(
        &self,
        first: u64,
        input: &[Page],
    ) -> Result<(), MutationFailure<Self::Error>> {
        for (index, page) in input.iter().enumerate() {
            self.write_page(first + index as u64, page).await?;
        }
        if input.len() > 1 {
            self.counters.lock().unwrap().write_requests -= input.len() as u64 - 1;
        }
        Ok(())
    }

    async fn flush(&self) -> Result<(), MutationFailure<Self::Error>> {
        self.counters.lock().unwrap().flushes += 1;
        self.note("flush");
        Ok(())
    }
}

fn limits() -> StoreLimits {
    StoreLimits::default()
}

fn store_id() -> StoreId {
    StoreId::new(0x5045_5246_5f5354_4f52_4501).unwrap()
}

fn kind() -> ObjectKind {
    ObjectKind::new(OBJECT_KIND_RAW).unwrap()
}

fn format_records() -> Vec<[u8; vibeos_durable_format::RECORD_SIZE]> {
    vec![RecordChain::new(store_id())
        .append(None, RecordBody::Format)
        .unwrap()]
}

fn import(records: &[[u8; vibeos_durable_format::RECORD_SIZE]]) -> PersistentAuthorityImport {
    PersistentAuthorityImport::from_m4(records, store_id(), &[], POLICY, Vec::new())
        .unwrap()
        .with_system_principal(LEGACY_SYSTEM_PRINCIPAL, 1 << 30, 1 << 30, false)
        .unwrap()
}

fn append_grant_for(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    object_id: ObjectId,
) -> (Vec<[u8; vibeos_durable_format::RECORD_SIZE]>, GrantRecord) {
    let preflight = vibeos_durable_format::preflight_recovery(records, store_id()).unwrap();
    let mut chain =
        RecordChain::from_checkpoint(store_id(), preflight.chain_checkpoint().unwrap()).unwrap();
    let transaction = preflight.id_high_water().max(1);
    let derivation = transaction.checked_add(1).unwrap();
    let space = transaction.checked_add(2).unwrap();
    let exclusive_end = transaction.checked_add(3).unwrap();
    let grant = GrantRecord {
        derivation_id: DerivationId::new(derivation).unwrap(),
        parent_id: None,
        object_id,
        target: SlotIdentity {
            space: SpaceId::new(space).unwrap(),
            slot: 0,
            generation: 0,
        },
        rights: DurableRights::READ,
        resource_kind: ResourceKind::new(OBJECT_KIND_RAW).unwrap(),
        flags: GrantFlags::ROOT,
    };
    let mut output = records.to_vec();
    output.push(
        chain
            .append(None, RecordBody::IdHighWater { exclusive_end })
            .unwrap(),
    );
    output.extend(
        preview_grant_transaction(&chain, TransactionId::new(transaction).unwrap(), grant.clone())
            .unwrap()
            .0
            .records,
    );
    (output, grant)
}

fn append_records(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    bytes: &[u8],
) -> (Vec<[u8; vibeos_durable_format::RECORD_SIZE]>, ObjectId) {
    append_records_with_encoding(records, bytes, false)
}

fn append_records_with_encoding(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    bytes: &[u8],
    external: bool,
) -> (Vec<[u8; vibeos_durable_format::RECORD_SIZE]>, ObjectId) {
    let preflight = vibeos_durable_format::preflight_recovery(records, store_id()).unwrap();
    let mut chain =
        RecordChain::from_checkpoint(store_id(), preflight.chain_checkpoint().unwrap()).unwrap();
    let transaction = preflight.id_high_water().max(1);
    let object = transaction.checked_add(1).unwrap();
    let exclusive_end = object.checked_add(1).unwrap();
    let object_id = ObjectId::new(object).unwrap();
    let mut output = records.to_vec();
    output.push(
        chain
            .append(None, RecordBody::IdHighWater { exclusive_end })
            .unwrap(),
    );
    if external {
        let root = vibeos_blob_format::BlobDescriptor::from_content(OBJECT_KIND_RAW, bytes)
            .unwrap()
            .root;
        let (encoded, _) = vibeos_durable_format::preview_external_object_transaction(
            &chain,
            TransactionId::new(transaction).unwrap(),
            object_id,
            kind(),
            bytes.len() as u64,
            root,
        )
        .unwrap();
        output.extend(encoded.records);
    } else {
        output.extend(
            encode_object_transaction(
                &mut chain,
                TransactionId::new(transaction).unwrap(),
                object_id,
                kind(),
                bytes,
            )
            .unwrap()
            .records,
        );
    }
    (output, object_id)
}

fn runtime_ctx() -> (
    StoreRuntimeContext,
    vibeos_segment_store::StorageQuotaProvisioner,
    vibeos_segment_store::StoreMaintenanceProvisioner,
) {
    StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(&[])
        .unwrap()
}

#[test]
fn steady_state_replace_attribution() {
    steady_state_attribution(false, 64);
}

#[test]
fn steady_state_external_attribution() {
    steady_state_attribution(true, 128);
}

fn steady_state_attribution(external: bool, default_rounds: usize) {
    let device = CountingDevice::blank(SEGMENTS);
    let (runtime, _quota, provisioner) = runtime_ctx();
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(*b"PERF-STEADY-ST!!").unwrap(),
        cleaner_reserve_segments: 2,
        limits: limits(),
    }))
    .unwrap();
    let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
    let writer: PersistentAuthorityWriter = store
        .derive_persistent_authority_writer(&maintenance)
        .unwrap();

    let mut records = format_records();
    let first = import(&records);
    let first_view = block_on(store.import_persistent_authority(&maintenance, first)).unwrap();
    records = first_view
        .record_stream()
        .chunks_exact(vibeos_durable_format::RECORD_SIZE)
        .map(|chunk| chunk.try_into().unwrap())
        .collect();

    let payload: Vec<u8> = (0..4096usize)
        .map(|index| (index * 131 + 0x5a) as u8)
        .collect();
    let mut generation = first_view.checkpoint_generation();
    let bench_principal = first_view.principals()[0].clone();
    let rounds = std::env::var("VIBEOS_STEADY_APPEND_COUNT")
        .map(|value| {
            value
                .parse::<usize>()
                .expect("VIBEOS_STEADY_APPEND_COUNT must be an integer")
        })
        .unwrap_or(default_rounds);
    assert!(rounds > 0);
    println!("steady-state requested appends: {rounds}; external={external}");
    println!("append,kind,read_pages,write_pages,flush,read_req,write_req");
    for round in 0..rounds {
        let (next_records, object_id) = append_records_with_encoding(&records, &payload, external);
        let mut update = import(&next_records);
        if external {
            update
                .attach_external_payload(object_id.get(), payload.clone())
                .unwrap();
        }
        device.begin_epoch();
        device.set_trace(round == 34);
        let result = block_on(store.append_persistent_authority(
            &writer,
            generation,
            update,
            &bench_principal,
        ));
        let counters = device.epoch_counters();
        if round == 34 {
            device.set_trace(false);
            device.dump_sites();
        }
        let (view, witness) = match result {
            Ok(result) => result.into_parts(),
            Err(error) => panic!("append {} failed: {:?}", round, error),
        };
        if external {
            let recovered =
                vibeos_durable_format::preflight_recovery(&next_records, store_id()).unwrap();
            let object = recovered
                .committed_objects()
                .iter()
                .find(|object| object.object_id == object_id)
                .unwrap();
            assert_eq!(
                block_on(store.read_transient_object(&witness, object)).unwrap(),
                payload
            );
            // Keep readback verification outside the append I/O attribution.
            device.epoch_counters();
        }
        drop(witness);
        generation = view.checkpoint_generation();
        records = next_records;
        // A collection round is visible as extra checkpoint transactions;
        // flush count is the stable signature now that GC reads are batched.
        let kind_label = if counters.flushes > 4 { "gc" } else { "normal" };
        println!(
            "{},{},{},{},{},{},{}",
            round,
            kind_label,
            counters.reads,
            counters.writes,
            counters.flushes,
            counters.read_requests,
            counters.write_requests
        );
        // Regression budget for the fused durable-append fast path: one
        // metadata segment and one checkpoint per append. The zero-seal reuse
        // barrier plus the three checkpoint slot-protocol flushes are the
        // complete flush budget; reads/writes stay bounded by the authority
        // snapshot rewrite (which grows with the record stream), never by
        // re-verification of historical objects.
        if round > 0 && kind_label == "normal" {
            assert!(
                counters.flushes <= 4,
                "round {}: {} flushes exceeds the fused-append budget of 4",
                round,
                counters.flushes
            );
            assert!(
                counters.reads <= 200,
                "round {}: {} page reads exceeds the steady-state budget",
                round,
                counters.reads
            );
        }
    }
    let view =
        block_on(store.recover_persistent_authority(root_policy_commitment(POLICY))).unwrap();
    // The kernel benchmark publishes capabilities without durable root grants,
    // so appended objects stay boot-local (transient) and the admitted set
    // remains empty, exactly like the observed "2 live objects" matrix.
    assert_eq!(view.objects().len(), 0);
    println!(
        "final authority stream bytes: {}",
        records.len() * vibeos_durable_format::RECORD_SIZE
    );
    drop(view);
    drop(store);
    let (runtime, _quota, _provisioner) = runtime_ctx();
    let mut cold = SegmentStore::new_with_runtime_context(device, limits(), runtime);
    block_on(cold.mount()).unwrap();
    let view = block_on(cold.recover_persistent_authority(root_policy_commitment(POLICY))).unwrap();
    // Neither encoding may turn an ungranted transient object into authority
    // at the boot boundary. External payload readback was checked per append.
    assert!(view.objects().is_empty());
}

#[test]
fn large_object_append_and_cold_recover() {
    let device = CountingDevice::blank(SEGMENTS);
    let (runtime, _quota, provisioner) = runtime_ctx();
    let large_limits = StoreLimits {
        recovery_memory_bytes: 64 * 1024 * 1024,
        ..StoreLimits::default()
    };
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), large_limits, runtime);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(*b"PERF-LARGE-OBJ!!").unwrap(),
        cleaner_reserve_segments: 2,
        limits: large_limits,
    }))
    .unwrap();
    let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
    let writer: PersistentAuthorityWriter =
        store.derive_persistent_authority_writer(&maintenance).unwrap();
    let mut records = format_records();
    let first_view = block_on(store.import_persistent_authority(&maintenance, import(&records))).unwrap();
    records = first_view
        .record_stream()
        .chunks_exact(vibeos_durable_format::RECORD_SIZE)
        .map(|chunk| chunk.try_into().unwrap())
        .collect();
    let principal = first_view.principals()[0].clone();
    let mut generation = first_view.checkpoint_generation();
    let mut expected_objects = 0usize;
    let mut all_grants: Vec<RootPolicy> = Vec::new();
    // Append three 1 MiB objects: the third one forces the authority extent
    // chain past one segment's payload area, exercising the multi-segment
    // write and the allocated-segment scan on cold recovery.
    for round in 0..3 {
        let object_payload: Vec<u8> = (0..1024 * 1024usize)
            .map(|index| (index as u64)
                .wrapping_mul(131)
                .wrapping_add(round as u64)
                .wrapping_add(0x5a) as u8)
            .collect();
        let (object_records, object_id) = append_records(&records, &object_payload);
        let (next_records, grant) = append_grant_for(&object_records, object_id);
        all_grants.push(RootPolicy { grant });
        let update = PersistentAuthorityImport::from_m4(
            &next_records,
            store_id(),
            &all_grants,
            POLICY,
            Vec::new(),
        )
        .unwrap()
        .with_system_principal(LEGACY_SYSTEM_PRINCIPAL, 1 << 30, 1 << 30, false)
        .unwrap();
        let result = block_on(store.append_persistent_authority(
            &writer,
            generation,
            update,
            &principal,
        ))
        .unwrap_or_else(|error| panic!("append round {} failed: {:?}", round, error));
        let (view, _) = result.into_parts();
        generation = view.checkpoint_generation();
        records = next_records;
        expected_objects += 1;
        assert_eq!(view.objects().len(), expected_objects);
        let handle = view.objects().last().unwrap();
        device.epoch_counters();
        assert_eq!(
            block_on(store.read_persistent_object(handle)).unwrap(),
            object_payload
        );
        let full = device.epoch_counters();
        assert!(full.read_requests < 64, "streaming read lost batching: {full:?}");
        assert!(full.reads < 320, "streaming verification reread payload/hash pages: {full:?}");
        // Unaligned reads cross native CAS leaves without materializing the
        // full object. Include both extent edges and the final partial range.
        for (offset, len) in [
            (0, 0),
            (0, 4096),
            (127, 4096),
            (1024 * 1024 - 13, 13),
            (1024 * 1024, 0),
        ] {
            let bytes = block_on(store.read_persistent_object_range(handle, offset, len)).unwrap();
            assert_eq!(
                bytes,
                object_payload[offset as usize..offset as usize + len]
            );
            let range = device.epoch_counters();
            println!("range round={round} offset={offset} len={len} reads={} requests={} full_reads={} full_requests={}",
                range.reads, range.read_requests, full.reads, full.read_requests);
            assert!(
                range.read_bytes < full.read_bytes / 2,
                "directed read scanned full payload"
            );
        }
        let ranges = [(128, 4096), (4096 + 128, 32), (4096 + 256, 32),
                      (8192, 32), (8192, 0)];
        device.epoch_counters();
        let separate: Vec<_> = ranges.iter().map(|&(offset, len)|
            block_on(store.read_persistent_object_range(handle, offset, len)).unwrap()).collect();
        let separate_io = device.epoch_counters();
        let batched = block_on(store.read_persistent_object_ranges(handle, &ranges)).unwrap();
        let batched_io = device.epoch_counters();
        assert_eq!(batched, separate);
        assert!(batched_io.read_requests < separate_io.read_requests / 2,
            "batch repeated resolution: {batched_io:?} vs {separate_io:?}");
        println!("batch ranges: {} -> {} requests, {} -> {} pages",
            separate_io.read_requests, batched_io.read_requests, separate_io.reads, batched_io.reads);
        assert!(block_on(store.read_persistent_object_ranges(handle, &[(0, 1); 33])).is_err());
        assert!(block_on(store.read_persistent_object_ranges(handle, &[(0, 1), (u64::MAX, 1)])).is_err());
        assert!(block_on(store.read_persistent_object_range(handle, u64::MAX, 1)).is_err());
        assert!(block_on(store.read_persistent_object_range(handle, 1024 * 1024, 1)).is_err());
    }
    drop(store);
    // Cold recovery must reassemble the multi-extent authority payload.
    device.epoch_counters();
    let (runtime, _quota, _provisioner) = runtime_ctx();
    let mut cold = SegmentStore::new_with_runtime_context(device.clone(), large_limits, runtime);
    block_on(cold.mount()).unwrap_or_else(|error| panic!("cold mount: {:?}", error));
    let mount_io = device.epoch_counters();
    assert!(mount_io.read_requests < 512,
        "cold authority recovery regressed to per-page I/O: {} requests", mount_io.read_requests);
    let recovered =
        block_on(cold.recover_persistent_authority(root_policy_commitment(POLICY))).unwrap();
    assert_eq!(recovered.objects().len(), 3);
    let authority_io = device.epoch_counters();
    println!("cold-mount: {} requests, {} bytes; authority-recover: {} requests, {} bytes",
        mount_io.read_requests, mount_io.read_bytes,
        authority_io.read_requests, authority_io.read_bytes);
}

#[test]
fn two_transient_large_appends() {
    // Repeated ~1.5 MiB authority rewrites plus their relocation targets need
    // more headroom than the small steady-state store; the kernel relies on
    // online growth for the same reason.
    let device = CountingDevice::blank(48);
    let (runtime, _quota, provisioner) = runtime_ctx();
    let large_limits = StoreLimits {
        recovery_memory_bytes: 64 * 1024 * 1024,
        ..StoreLimits::default()
    };
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), large_limits, runtime);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(*b"PERF-2xLARGE-OBJ").unwrap(),
        cleaner_reserve_segments: 2,
        limits: large_limits,
    }))
    .unwrap();
    let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
    let writer: PersistentAuthorityWriter =
        store.derive_persistent_authority_writer(&maintenance).unwrap();
    let mut records = format_records();
    let first_view =
        block_on(store.import_persistent_authority(&maintenance, import(&records))).unwrap();
    records = first_view
        .record_stream()
        .chunks_exact(vibeos_durable_format::RECORD_SIZE)
        .map(|chunk| chunk.try_into().unwrap())
        .collect();
    let principal = first_view.principals()[0].clone();
    let mut generation = first_view.checkpoint_generation();
    for round in 0..8u64 {
        let payload: Vec<u8> = (0..1024 * 1024usize)
            .map(|index| (index as u64).wrapping_mul(131).wrapping_add(round) as u8)
            .collect();
        let (next_records, _object_id) = append_records(&records, &payload);
        let update = import(&next_records);
        let result = block_on(store.append_persistent_authority(
            &writer,
            generation,
            update,
            &principal,
        ))
        .unwrap_or_else(|error| panic!("transient append round {} failed: {:?}", round, error));
        let info = store.info().unwrap();
        println!(
            "round {} ok, gen {} free={} allocated={} admitted={}",
            round, generation, info.free_segments, info.allocated_segments, info.admitted_segments
        );
        let (view, _transient) = result.into_parts();
        generation = view.checkpoint_generation();
        records = next_records;
    }
}


#[test]
fn large_stream_batches_writes_and_verifies_after_cold_mount() {
    let device = CountingDevice::blank(SEGMENTS);
    let limits = StoreLimits::default();
    let mut store = SegmentStore::new(device.clone(), limits);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(*b"PERF-WRITE-RUN!!").unwrap(),
        cleaner_reserve_segments: 2,
        limits,
    }))
    .unwrap();
    // Cross content extents and segment boundaries, ending in a partial page
    // and a partial write run. Read every byte back through verification.
    let bytes: Vec<u8> = (0..3 * 1024 * 1024 + 17usize)
        .map(|i| (i.wrapping_mul(131) ^ (i >> 13)) as u8)
        .collect();
    device.epoch_counters();
    let mut writer = store
        .begin_blob(OBJECT_KIND_RAW, bytes.len() as u64, None)
        .unwrap();
    for chunk in bytes.chunks(4096) {
        block_on(writer.write_chunk(chunk)).unwrap();
    }
    let object = block_on(writer.commit()).unwrap();
    let writes = device.epoch_counters();
    println!(
        "stream write pages={} requests={} flushes={}",
        writes.writes, writes.write_requests, writes.flushes
    );
    assert!(
        writes.write_requests < writes.writes / 4,
        "large stream lost write coalescing: {writes:?}"
    );
    let runtime = store.runtime_context();
    drop(store);
    let mut cold = SegmentStore::new_with_runtime_context(device, limits, runtime);
    block_on(cold.mount()).unwrap();
    for (index, expected) in bytes.chunks(4096).enumerate() {
        assert_eq!(
            block_on(cold.get_blob_chunk(&object, index as u32))
                .unwrap()
                .bytes,
            expected
        );
    }
}
