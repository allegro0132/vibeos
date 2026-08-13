use core::future::{pending, Future};
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use vibeos_segment_format::{
    admitted_pages, decode_checkpoint, decode_segment_header, descriptor_chain_initial,
    descriptor_chain_next, encode_checkpoint_body, encode_extent_body, encode_record_seal,
    encode_segment_header_body, encode_segment_seal_body, encode_segment_summary_body,
    payload_chain_initial, payload_chain_next, payload_sha256, segment_base_page, Checkpoint,
    DecodeStatus, ExtentKind, ExtentRecord, Page, PhysicalPointer, PointerValue, RecordBinding,
    SegmentHeader, SegmentSeal, SegmentSummary, StoreUuid, ANCHOR_PAGES, ANCHOR_SEGMENT_NO,
    DATA_FIRST_PAGE, PAGE_SIZE, SEGMENT_PAGES, SEGMENT_SEAL_BODY_PAGE, SEGMENT_SEAL_PAGE,
    SUMMARY_BODY_PAGE, SUMMARY_SEAL_PAGE,
};
use vibeos_segment_store::{
    decode_allocation_v2, decode_blob_manifest, decode_cas_snapshot, encode_allocation,
    AllocationState, AuthorizedObject, CapacityClass, CasCodecContext, CasObjectHandle,
    CasSnapshot, CasStoreError, FormatOptions, GcError, GcStoreError, GcTelemetry, GcTimeSource,
    PageDevice, PageDeviceInfo, RuntimeObjectPinClass, RuntimePinOwnerError, SegmentAllocation,
    SegmentStore, StoppedRuntimePinOwner, StoreError, StoreLimits, StoreRuntimeContext,
    ROOT_POLICY_HEADROOM_SEGMENTS,
};
use vibeos_storage_device::MutationFailure;

const OBJECT_KIND: u32 = 0x4743_5632;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestError {
    Injected,
    DriverRestarted,
    OutsideRange,
}

impl fmt::Display for TestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[derive(Clone)]
struct MemoryDevice {
    page_count: u64,
    pages: Arc<Mutex<BTreeMap<u64, Page>>>,
}

impl MemoryDevice {
    fn blank(segments: u64) -> Self {
        Self {
            page_count: admitted_pages(segments).unwrap(),
            pages: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn durable_image(&self) -> BTreeMap<u64, Page> {
        self.pages.lock().unwrap().clone()
    }
}

impl PageDevice for MemoryDevice {
    type Error = TestError;

    fn info(&self) -> PageDeviceInfo {
        PageDeviceInfo {
            device_id: [0x75; 16],
            range_first_logical_block: 64,
            logical_block_count: self.page_count * 8,
            logical_block_size: 512,
            page_count: self.page_count,
        }
    }

    async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
        if page >= self.page_count {
            return Err(TestError::OutsideRange);
        }
        output.fill(0);
        if let Some(stored) = self.pages.lock().unwrap().get(&page) {
            output.copy_from_slice(stored);
        }
        Ok(())
    }

    async fn write_page(
        &self,
        page: u64,
        input: &Page,
    ) -> Result<(), MutationFailure<Self::Error>> {
        if page >= self.page_count {
            return Err(MutationFailure::not_submitted(TestError::OutsideRange));
        }
        self.pages.lock().unwrap().insert(page, *input);
        Ok(())
    }

    async fn flush(&self) -> Result<(), MutationFailure<Self::Error>> {
        Ok(())
    }
}

fn limits() -> StoreLimits {
    StoreLimits {
        max_catalog_entries: 64,
        max_replay_records: 4,
        recovery_memory_bytes: 2 * 1024 * 1024,
        max_compat_object_bytes: 64 * 1024,
    }
}

fn format(device: MemoryDevice) -> SegmentStore<MemoryDevice> {
    format_with(device, limits(), 4)
}

fn format_with(
    device: MemoryDevice,
    store_limits: StoreLimits,
    cleaner_reserve_segments: u32,
) -> SegmentStore<MemoryDevice> {
    let mut store = SegmentStore::new(device, store_limits);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(*b"M7.5-GC-TEST!!!!").unwrap(),
        cleaner_reserve_segments,
        limits: store_limits,
    }))
    .unwrap();
    store
}

fn put<D>(store: &mut SegmentStore<D>, bytes: &[u8]) -> AuthorizedObject<CasObjectHandle>
where
    D: PageDevice<Error = TestError>,
{
    let mut writer = store
        .begin_blob(OBJECT_KIND, bytes.len() as u64, None)
        .unwrap();
    for chunk in bytes.chunks(PAGE_SIZE) {
        block_on(writer.write_chunk(chunk)).unwrap();
    }
    block_on(writer.commit()).unwrap()
}

struct StepClock(AtomicU64);

impl GcTimeSource for StepClock {
    fn monotonic_ns(&self) -> u64 {
        self.0.fetch_add(100, Ordering::Relaxed)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultAction {
    Normal,
    FailNotSubmitted,
    FailAmbiguous(Effect),
    Pending(Effect),
    AcknowledgeCorrupt { byte_index: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Effect {
    None,
    Visible,
    Durable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FaultPlan {
    mutation_index: usize,
    action: FaultAction,
}

#[derive(Clone)]
struct FaultMedia {
    page_count: u64,
    durable: BTreeMap<u64, Page>,
    visible: BTreeMap<u64, Page>,
    mutation_count: usize,
    mutation_pages: Vec<Option<u64>>,
    fault: Option<FaultPlan>,
}

#[derive(Clone)]
struct FaultDevice {
    media: Arc<Mutex<FaultMedia>>,
}

impl FaultDevice {
    fn from_image(segments: u64, image: BTreeMap<u64, Page>) -> Self {
        Self {
            media: Arc::new(Mutex::new(FaultMedia {
                page_count: admitted_pages(segments).unwrap(),
                visible: image.clone(),
                durable: image,
                mutation_count: 0,
                mutation_pages: Vec::new(),
                fault: None,
            })),
        }
    }

    fn arm(&self, boundary: usize, action: FaultAction) {
        let mut media = self.media.lock().unwrap();
        media.mutation_count = 0;
        media.mutation_pages.clear();
        media.fault = Some(FaultPlan {
            mutation_index: boundary,
            action,
        });
    }

    fn reset_mutation_count(&self) {
        let mut media = self.media.lock().unwrap();
        media.mutation_count = 0;
        media.mutation_pages.clear();
    }

    fn mutation_count(&self) -> usize {
        self.media.lock().unwrap().mutation_count
    }

    fn mutation_pages(&self) -> Vec<Option<u64>> {
        self.media.lock().unwrap().mutation_pages.clone()
    }

    fn power_cycle(&self) {
        let mut media = self.media.lock().unwrap();
        media.visible = media.durable.clone();
        media.mutation_count = 0;
        media.mutation_pages.clear();
        media.fault = None;
    }

    fn next_action(&self, page: Option<u64>) -> FaultAction {
        let mut media = self.media.lock().unwrap();
        let index = media.mutation_count;
        media.mutation_count += 1;
        media.mutation_pages.push(page);
        media
            .fault
            .filter(|plan| plan.mutation_index == index)
            .map_or(FaultAction::Normal, |plan| plan.action)
    }

    fn durable_image(&self) -> BTreeMap<u64, Page> {
        self.media.lock().unwrap().durable.clone()
    }

    fn write_effect(&self, page: u64, bytes: Page, effect: Effect) {
        let mut media = self.media.lock().unwrap();
        if !matches!(effect, Effect::None) {
            media.visible.insert(page, bytes);
        }
        if matches!(effect, Effect::Durable) {
            media.durable.insert(page, bytes);
        }
    }

    fn flush_effect(&self, effect: Effect) {
        if matches!(effect, Effect::Durable) {
            let mut media = self.media.lock().unwrap();
            media.durable = media.visible.clone();
        }
    }
}

impl PageDevice for FaultDevice {
    type Error = TestError;

    fn info(&self) -> PageDeviceInfo {
        let page_count = self.media.lock().unwrap().page_count;
        PageDeviceInfo {
            device_id: [0x75; 16],
            range_first_logical_block: 64,
            logical_block_count: page_count * 8,
            logical_block_size: 512,
            page_count,
        }
    }

    async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
        let media = self.media.lock().unwrap();
        if page >= media.page_count {
            return Err(TestError::OutsideRange);
        }
        output.fill(0);
        if let Some(stored) = media.visible.get(&page) {
            output.copy_from_slice(stored);
        }
        Ok(())
    }

    async fn write_page(
        &self,
        page: u64,
        input: &Page,
    ) -> Result<(), MutationFailure<Self::Error>> {
        if page >= self.media.lock().unwrap().page_count {
            return Err(MutationFailure::not_submitted(TestError::OutsideRange));
        }
        let bytes = *input;
        match self.next_action(Some(page)) {
            FaultAction::Normal => {
                self.write_effect(page, bytes, Effect::Visible);
                Ok(())
            }
            FaultAction::FailNotSubmitted => {
                Err(MutationFailure::not_submitted(TestError::Injected))
            }
            FaultAction::FailAmbiguous(effect) => {
                self.write_effect(page, bytes, effect);
                Err(MutationFailure::ambiguous(TestError::DriverRestarted))
            }
            FaultAction::Pending(effect) => {
                self.write_effect(page, bytes, effect);
                pending::<Result<(), MutationFailure<TestError>>>().await
            }
            FaultAction::AcknowledgeCorrupt { byte_index } => {
                let mut corrupted = bytes;
                corrupted[byte_index] ^= 0x80;
                self.write_effect(page, corrupted, Effect::Visible);
                Ok(())
            }
        }
    }

    async fn flush(&self) -> Result<(), MutationFailure<Self::Error>> {
        match self.next_action(None) {
            FaultAction::Normal => {
                self.flush_effect(Effect::Durable);
                Ok(())
            }
            FaultAction::FailNotSubmitted => {
                Err(MutationFailure::not_submitted(TestError::Injected))
            }
            FaultAction::FailAmbiguous(effect) => {
                self.flush_effect(effect);
                Err(MutationFailure::ambiguous(TestError::DriverRestarted))
            }
            FaultAction::Pending(effect) => {
                self.flush_effect(effect);
                pending::<Result<(), MutationFailure<TestError>>>().await
            }
            FaultAction::AcknowledgeCorrupt { .. } => {
                self.flush_effect(Effect::Durable);
                Ok(())
            }
        }
    }
}

fn mount_fault(device: FaultDevice, runtime: StoreRuntimeContext) -> SegmentStore<FaultDevice> {
    let mut store = SegmentStore::new_with_runtime_context(device, limits(), runtime);
    block_on(store.mount()).unwrap();
    store
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn image_page(image: &BTreeMap<u64, Page>, page_no: u64) -> Page {
    image.get(&page_no).copied().unwrap_or([0; PAGE_SIZE])
}

fn selected_checkpoint(image: &BTreeMap<u64, Page>) -> Checkpoint {
    [4_u64, 6]
        .into_iter()
        .filter_map(|body_page| {
            let body = image_page(image, body_page);
            let seal = image_page(image, body_page + 1);
            match decode_checkpoint(&body, &seal).expect("checkpoint pair must decode strictly") {
                DecodeStatus::Sealed(checkpoint) => Some(checkpoint),
                DecodeStatus::Empty | DecodeStatus::Unsealed => None,
            }
        })
        .max_by_key(|checkpoint| checkpoint.binding.generation)
        .expect("a mounted image must contain a sealed checkpoint")
}

fn pointer_payload(image: &BTreeMap<u64, Page>, pointer: PhysicalPointer) -> Vec<u8> {
    let PhysicalPointer::Value(pointer) = pointer else {
        panic!("expected a non-null physical pointer");
    };
    let segment_base = ANCHOR_PAGES + pointer.segment_no * SEGMENT_PAGES;
    let payload_first = segment_base + u64::from(pointer.payload_relative_page);
    let mut output = Vec::new();
    output.reserve_exact(pointer.payload_pages as usize * PAGE_SIZE);
    for relative in 0..u64::from(pointer.payload_pages) {
        output.extend_from_slice(&image_page(image, payload_first + relative));
    }
    output.truncate(pointer.exact_byte_len as usize);
    output
}

fn raw_image_path(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "vibeos-gc-{label}-{}-{unique}.img",
        std::process::id()
    ))
}

fn write_raw_image(image: &BTreeMap<u64, Page>, page_count: u64, path: &Path) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)
        .expect("raw image must be created");
    file.set_len(page_count * PAGE_SIZE as u64)
        .expect("raw image length must be set");
    for (page_no, page) in image {
        file.seek(SeekFrom::Start(*page_no * PAGE_SIZE as u64))
            .expect("raw image seek must succeed");
        file.write_all(page)
            .expect("raw image page write must succeed");
    }
    file.flush().expect("raw image flush must succeed");
}

fn run_raw_gc_verifier(path: &Path) -> std::process::Output {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    Command::new("python3")
        .arg("-B")
        .arg(repository.join("scripts/verify-storage-v2-gc.py"))
        .arg("--raw-image")
        .arg(path)
        .output()
        .expect("independent GC raw-image verifier must run")
}

fn allocation_at_selected_checkpoint(
    image: &BTreeMap<u64, Page>,
) -> (Checkpoint, vibeos_segment_store::AllocationV2) {
    let checkpoint = selected_checkpoint(image);
    let allocation = decode_allocation_v2(&pointer_payload(image, checkpoint.allocation_root))
        .expect("selected allocation-v2 payload must decode");
    assert_eq!(
        allocation.checkpoint_generation,
        checkpoint.binding.generation
    );
    (checkpoint, allocation)
}

fn cas_at_selected_checkpoint(image: &BTreeMap<u64, Page>) -> (Checkpoint, CasSnapshot) {
    let checkpoint = selected_checkpoint(image);
    let context = CasCodecContext::new(
        checkpoint.binding.store_uuid,
        checkpoint.admitted_segments,
        checkpoint.next_segment_generation,
    )
    .unwrap();
    let snapshot = decode_cas_snapshot(&pointer_payload(image, checkpoint.catalog_root), context)
        .expect("selected CAS snapshot must decode");
    (checkpoint, snapshot)
}

fn assert_source_epoch_state(
    image: &BTreeMap<u64, Page>,
    epoch_generation: u64,
    sources: &[u64],
    case: &str,
) -> u64 {
    let (checkpoint, allocation) = allocation_at_selected_checkpoint(image);
    let generation = checkpoint.binding.generation;
    assert!(
        (epoch_generation..=epoch_generation + 2).contains(&generation),
        "{case}: selected generation {generation}, expected G/G+1/G+2 from {epoch_generation}"
    );
    for &source in sources {
        match generation - epoch_generation {
            0 => {
                assert_eq!(
                    allocation.segment_state(source),
                    Some(SegmentAllocation::Allocated),
                    "{case}: source {source} was not Allocated at G"
                );
                assert_eq!(allocation.retire_generation(source), None);
            }
            1 => {
                assert_eq!(
                    allocation.segment_state(source),
                    Some(SegmentAllocation::Retired),
                    "{case}: source {source} bypassed Retired at G+1"
                );
                assert_eq!(
                    allocation.retire_generation(source),
                    Some(epoch_generation + 1),
                    "{case}: source {source} has the wrong retirement generation"
                );
            }
            2 => {
                assert_eq!(
                    allocation.segment_state(source),
                    Some(SegmentAllocation::Free),
                    "{case}: source {source} was not Free at G+2"
                );
                assert_eq!(allocation.retire_generation(source), None);
            }
            _ => unreachable!(),
        }
    }
    generation
}

fn segment_generation(image: &BTreeMap<u64, Page>, segment_no: u64) -> u64 {
    let base = ANCHOR_PAGES + segment_no * SEGMENT_PAGES;
    let body = image_page(image, base);
    let seal = image_page(image, base + 1);
    match decode_segment_header(&body, &seal).expect("segment header must decode") {
        DecodeStatus::Sealed(header) => header.binding.generation,
        DecodeStatus::Empty | DecodeStatus::Unsealed => panic!("allocated segment is unsealed"),
    }
}

fn insert_page(image: &mut BTreeMap<u64, Page>, page_no: u64, page: Page) {
    if page.iter().any(|byte| *byte != 0) {
        image.insert(page_no, page);
    } else {
        image.remove(&page_no);
    }
}

/// Convert a production CAS checkpoint to the exact M7.4 allocation-v1 media
/// form. The Blob and CAS payloads are left byte-for-byte unchanged; only a
/// fresh legacy allocation extent and checkpoint replace the M7.5 allocation
/// pointer. This models an image produced before VIBERST2 existed, including a
/// Null authority root and a prefix whose free suffix equals the reserve.
fn as_legacy_full_prefix_image(
    image: &BTreeMap<u64, Page>,
    cleaner_reserve_segments: u32,
) -> BTreeMap<u64, Page> {
    const LEGACY_ALLOCATION_KIND: u32 = 0xffff_0002;
    let mut legacy = image.clone();
    let selected = selected_checkpoint(image);
    assert_eq!(selected.authority_root, PhysicalPointer::Null);
    let original_reserve = selected.cleaner_reserve_segments;
    let segment_no = selected.admitted_segments - u64::from(cleaner_reserve_segments) - 1;
    let segment_generation = selected.next_segment_generation;
    let checkpoint_generation = selected.binding.generation + 1;
    let next_segment_generation = segment_generation + 1;
    let base = segment_base_page(segment_no).unwrap();
    let allocation_bytes = encode_allocation(AllocationState {
        checkpoint_generation,
        admitted_segments: selected.admitted_segments,
        allocated_prefix_segments: segment_no + 1,
        next_segment_generation,
        cleaner_reserve_segments,
    })
    .unwrap();
    let payload_pages = u32::try_from(allocation_bytes.len().div_ceil(PAGE_SIZE)).unwrap();
    let record_span_pages = payload_pages + 2;
    let header = SegmentHeader {
        binding: RecordBinding {
            store_uuid: selected.binding.store_uuid,
            generation: segment_generation,
            segment_no,
            ordinal: 0,
            self_page: base,
            target_checkpoint_generation: checkpoint_generation,
        },
        base_page: base,
        previous_segment_no: ANCHOR_SEGMENT_NO,
        previous_segment_generation: 0,
        previous_segment_seal_body_sha256: [0; 32],
    };
    let mut header_body = [0; PAGE_SIZE];
    let mut header_seal = [0; PAGE_SIZE];
    let header_digest = encode_segment_header_body(&header, &mut header_body).unwrap();
    encode_record_seal(header_digest, &mut header_seal).unwrap();

    let payload_hash = payload_sha256(&allocation_bytes);
    let extent = ExtentRecord {
        binding: RecordBinding {
            store_uuid: selected.binding.store_uuid,
            generation: segment_generation,
            segment_no,
            ordinal: 1,
            self_page: base + u64::from(DATA_FIRST_PAGE),
            target_checkpoint_generation: checkpoint_generation,
        },
        extent_kind: ExtentKind::Allocation,
        object_kind: LEGACY_ALLOCATION_KIND,
        extent_index: 0,
        extent_count: 1,
        payload_pages,
        content_byte_len: allocation_bytes.len() as u64,
        encoded_blob_len: allocation_bytes.len() as u64,
        encoded_offset: 0,
        payload_byte_len: allocation_bytes.len() as u64,
        payload_first_relative_page: DATA_FIRST_PAGE + 2,
        record_span_pages,
        merkle_root: payload_hash,
        payload_sha256: payload_hash,
    };
    let mut extent_body = [0; PAGE_SIZE];
    let mut extent_seal = [0; PAGE_SIZE];
    let extent_digest = encode_extent_body(&extent, &mut extent_body).unwrap();
    encode_record_seal(extent_digest, &mut extent_seal).unwrap();
    let next_free_page = DATA_FIRST_PAGE + record_span_pages;
    let descriptor_chain = descriptor_chain_next(
        selected.binding.store_uuid,
        segment_no,
        segment_generation,
        descriptor_chain_initial(selected.binding.store_uuid, segment_no, segment_generation),
        1,
        extent_digest.body_sha256(),
        payload_hash,
    );
    let payload_chain = payload_chain_next(
        selected.binding.store_uuid,
        segment_no,
        segment_generation,
        payload_chain_initial(selected.binding.store_uuid, segment_no, segment_generation),
        1,
        allocation_bytes.len() as u64,
        payload_hash,
    );
    let summary = SegmentSummary {
        binding: RecordBinding {
            store_uuid: selected.binding.store_uuid,
            generation: segment_generation,
            segment_no,
            ordinal: 2,
            self_page: base + u64::from(SUMMARY_BODY_PAGE),
            target_checkpoint_generation: checkpoint_generation,
        },
        record_count: 1,
        next_free_page,
        payload_page_count: payload_pages,
        total_payload_bytes: allocation_bytes.len() as u64,
        first_target_checkpoint_generation: checkpoint_generation,
        last_target_checkpoint_generation: checkpoint_generation,
        header_body_sha256: header_digest.body_sha256(),
        descriptor_chain_sha256: descriptor_chain,
        payload_chain_sha256: payload_chain,
        kind_counts: [0, 0, 0, 1, 0],
        kind_bytes: [0, 0, 0, allocation_bytes.len() as u64, 0],
    };
    let mut summary_body = [0; PAGE_SIZE];
    let mut summary_seal = [0; PAGE_SIZE];
    let summary_digest = encode_segment_summary_body(&summary, &mut summary_body).unwrap();
    encode_record_seal(summary_digest, &mut summary_seal).unwrap();
    let segment_seal = SegmentSeal {
        binding: RecordBinding {
            store_uuid: selected.binding.store_uuid,
            generation: segment_generation,
            segment_no,
            ordinal: 3,
            self_page: base + u64::from(SEGMENT_SEAL_BODY_PAGE),
            target_checkpoint_generation: checkpoint_generation,
        },
        header_body_sha256: header_digest.body_sha256(),
        summary_body_sha256: summary_digest.body_sha256(),
        final_descriptor_chain_sha256: descriptor_chain,
        final_payload_chain_sha256: payload_chain,
        record_count: 1,
        next_free_page,
        payload_page_count: payload_pages,
        total_payload_bytes: allocation_bytes.len() as u64,
        target_checkpoint_generation: checkpoint_generation,
    };
    let mut segment_seal_body = [0; PAGE_SIZE];
    let mut final_segment_seal = [0; PAGE_SIZE];
    let segment_seal_digest =
        encode_segment_seal_body(&segment_seal, &mut segment_seal_body).unwrap();
    encode_record_seal(segment_seal_digest, &mut final_segment_seal).unwrap();

    insert_page(&mut legacy, base, header_body);
    insert_page(&mut legacy, base + 1, header_seal);
    insert_page(&mut legacy, base + u64::from(DATA_FIRST_PAGE), extent_body);
    insert_page(
        &mut legacy,
        base + u64::from(DATA_FIRST_PAGE + 1),
        extent_seal,
    );
    let payload_first = base + u64::from(DATA_FIRST_PAGE + 2);
    for (index, chunk) in allocation_bytes.chunks(PAGE_SIZE).enumerate() {
        let mut page = [0; PAGE_SIZE];
        page[..chunk.len()].copy_from_slice(chunk);
        insert_page(&mut legacy, payload_first + index as u64, page);
    }
    insert_page(
        &mut legacy,
        base + u64::from(SUMMARY_BODY_PAGE),
        summary_body,
    );
    insert_page(
        &mut legacy,
        base + u64::from(SUMMARY_SEAL_PAGE),
        summary_seal,
    );
    insert_page(
        &mut legacy,
        base + u64::from(SEGMENT_SEAL_BODY_PAGE),
        segment_seal_body,
    );
    insert_page(
        &mut legacy,
        base + u64::from(SEGMENT_SEAL_PAGE),
        final_segment_seal,
    );

    let allocation_root = PhysicalPointer::Value(PointerValue {
        store_uuid: selected.binding.store_uuid,
        segment_no,
        segment_generation,
        descriptor_relative_page: DATA_FIRST_PAGE,
        payload_relative_page: DATA_FIRST_PAGE + 2,
        payload_pages,
        ordinal: 1,
        exact_byte_len: allocation_bytes.len() as u64,
        extent_kind: ExtentKind::Allocation,
        payload_sha256: payload_hash,
    });
    let slot = ((checkpoint_generation - 1) & 1) as u8;
    let checkpoint = Checkpoint {
        binding: RecordBinding {
            store_uuid: selected.binding.store_uuid,
            generation: checkpoint_generation,
            segment_no: ANCHOR_SEGMENT_NO,
            ordinal: u32::from(slot),
            self_page: 4 + u64::from(slot) * 2,
            target_checkpoint_generation: checkpoint_generation,
        },
        slot,
        previous_generation: selected.binding.generation,
        admitted_range_pages: selected.admitted_range_pages,
        admitted_segments: selected.admitted_segments,
        next_segment_generation,
        replay_count: 0,
        max_replay_records: selected.max_replay_records,
        cleaner_reserve_segments,
        catalog_root: selected.catalog_root,
        authority_root: PhysicalPointer::Null,
        allocation_root,
        replay_tail: PhysicalPointer::Null,
    };
    let mut checkpoint_body = [0; PAGE_SIZE];
    let mut checkpoint_seal = [0; PAGE_SIZE];
    let checkpoint_digest = encode_checkpoint_body(&checkpoint, &mut checkpoint_body).unwrap();
    encode_record_seal(checkpoint_digest, &mut checkpoint_seal).unwrap();
    insert_page(&mut legacy, checkpoint.binding.self_page, checkpoint_body);
    insert_page(
        &mut legacy,
        checkpoint.binding.self_page + 1,
        checkpoint_seal,
    );
    if cleaner_reserve_segments != original_reserve {
        // The other anchor slot is an older checkpoint whose immutable reserve
        // binding cannot match this historical policy. A powered-off image may
        // legally retain only the selected slot, so clear its publication pair
        // rather than fabricating a cross-generation reserve transition.
        let older_body = if checkpoint.binding.self_page == 4 {
            6
        } else {
            4
        };
        legacy.remove(&older_body);
        legacy.remove(&(older_body + 1));
        for (body_page, copy) in [(0_u64, 0_u8), (2, 1)] {
            let body = image_page(&legacy, body_page);
            let seal = image_page(&legacy, body_page + 1);
            let DecodeStatus::Sealed(mut superblock) =
                vibeos_segment_format::decode_superblock(&body, &seal).unwrap()
            else {
                panic!("seed superblock must be sealed");
            };
            assert_eq!(superblock.copy, copy);
            superblock.cleaner_reserve_segments = cleaner_reserve_segments;
            let mut patched_body = [0; PAGE_SIZE];
            let mut patched_seal = [0; PAGE_SIZE];
            let digest =
                vibeos_segment_format::encode_superblock_body(&superblock, &mut patched_body)
                    .unwrap();
            encode_record_seal(digest, &mut patched_seal).unwrap();
            insert_page(&mut legacy, body_page, patched_body);
            insert_page(&mut legacy, body_page + 1, patched_seal);
        }
        // The preceding checkpoint still carries the seed reserve and cannot
        // remain a compatible fallback after modeling this format-time legacy
        // value. Historical media could already have cleared that old seal.
        let old_slot = (checkpoint.previous_generation - 1) & 1;
        insert_page(&mut legacy, 5 + old_slot * 2, [0; PAGE_SIZE]);
    }
    legacy
}

fn legacy_bootstrap_fixture(
    segments: u64,
    cleaner_reserve_segments: u32,
) -> (
    BTreeMap<u64, Page>,
    StoreRuntimeContext,
    AuthorizedObject<CasObjectHandle>,
) {
    let device = MemoryDevice::blank(segments);
    let seed_reserve = cleaner_reserve_segments.max(2);
    let mut store = format_with(device.clone(), limits(), seed_reserve);
    let retained = put(&mut store, &[0x7a; PAGE_SIZE + 29]);
    let _garbage = put(&mut store, &[0x39; PAGE_SIZE + 11]);
    let runtime = store.runtime_context();
    let image = as_legacy_full_prefix_image(&device.durable_image(), cleaner_reserve_segments);
    assert_eq!(
        selected_checkpoint(&image).authority_root,
        PhysicalPointer::Null
    );
    (image, runtime, retained)
}

#[test]
fn legacy_v1_full_prefix_bootstraps_initial_policy_inside_gc_relocation() {
    const SEGMENTS: u64 = 10;
    const RESERVE: u32 = 4;
    let (image, runtime, retained) = legacy_bootstrap_fixture(SEGMENTS, RESERVE);
    let device = FaultDevice::from_image(SEGMENTS, image);
    let mut store = mount_fault(device.clone(), runtime);
    let before = store.info().unwrap();
    assert_eq!(before.free_segments, u64::from(RESERVE));
    assert!(matches!(
        block_on(store.collect_garbage()),
        Err(GcStoreError::Gc(GcError::MissingPersistentRootPolicy))
    ));

    let telemetry = block_on(store.collect_garbage_with_initial_roots(&[&retained])).unwrap();
    assert_eq!(telemetry.root_count, 1);
    assert_eq!(telemetry.live_object_count, 1);
    assert_eq!(telemetry.live_blob_count, 1);
    assert!(telemetry.reclaimed_segments > telemetry.target_segments);
    let checkpoint = selected_checkpoint(&device.durable_image());
    assert_ne!(checkpoint.authority_root, PhysicalPointer::Null);
    assert_eq!(checkpoint.binding.generation, telemetry.reuse_generation);
    assert_eq!(
        block_on(store.get_blob_chunk(&retained, 0)).unwrap().bytes,
        vec![0x7a; PAGE_SIZE]
    );
    assert!(matches!(
        block_on(store.collect_garbage_with_initial_roots(&[&retained])),
        Err(GcStoreError::Gc(GcError::InvalidPhase))
    ));
}

#[test]
fn legacy_bootstrap_rejects_cross_store_witness_before_media_mutation() {
    const SEGMENTS: u64 = 10;
    const RESERVE: u32 = 4;
    let (image, runtime, _retained) = legacy_bootstrap_fixture(SEGMENTS, RESERVE);
    let foreign_device = MemoryDevice::blank(SEGMENTS);
    let mut foreign_store = format_with(foreign_device, limits(), RESERVE);
    let foreign = put(&mut foreign_store, &[0x51; PAGE_SIZE]);

    let device = FaultDevice::from_image(SEGMENTS, image);
    let before = device.durable_image();
    let mut store = mount_fault(device.clone(), runtime);
    assert!(matches!(
        block_on(store.collect_garbage_with_initial_roots(&[&foreign])),
        Err(GcStoreError::Gc(GcError::RootDoesNotResolve)) | Err(GcStoreError::Gc(GcError::Pins))
    ));
    assert_eq!(device.durable_image(), before);
}

#[test]
fn legacy_reserve_one_mounts_and_reads_but_gc_fails_capacity_without_writing() {
    const SEGMENTS: u64 = 8;
    let (image, runtime, retained) = legacy_bootstrap_fixture(SEGMENTS, 1);
    let device = FaultDevice::from_image(SEGMENTS, image);
    let before = device.durable_image();
    let mut store = mount_fault(device.clone(), runtime);
    assert_eq!(store.info().unwrap().free_segments, 1);
    assert_eq!(
        block_on(store.get_blob_chunk(&retained, 0)).unwrap().bytes,
        vec![0x7a; PAGE_SIZE]
    );
    assert!(matches!(
        block_on(store.collect_garbage_with_initial_roots(&[&retained])),
        Err(GcStoreError::Gc(GcError::Capacity))
    ));
    assert_eq!(device.durable_image(), before);
}

#[test]
fn every_legacy_bootstrap_mutation_boundary_selects_old_or_complete_gc_state() {
    const SEGMENTS: u64 = 10;
    const RESERVE: u32 = 4;
    let (image, _runtime, _retained) = legacy_bootstrap_fixture(SEGMENTS, RESERVE);
    let old = selected_checkpoint(&image);
    assert_eq!(old.authority_root, PhysicalPointer::Null);

    let (probe_image, probe_runtime, probe_retained) = legacy_bootstrap_fixture(SEGMENTS, RESERVE);
    let probe_device = FaultDevice::from_image(SEGMENTS, probe_image);
    let mut probe = mount_fault(probe_device.clone(), probe_runtime);
    probe_device.reset_mutation_count();
    let complete = block_on(probe.collect_garbage_with_initial_roots(&[&probe_retained])).unwrap();
    let boundary_count = probe_device.mutation_count();
    assert!(
        boundary_count > 30,
        "bootstrap did not exercise real GC media stages"
    );
    assert_eq!(complete.epoch_generation, old.binding.generation);

    let actions = [
        FaultAction::FailNotSubmitted,
        FaultAction::FailAmbiguous(Effect::None),
        FaultAction::FailAmbiguous(Effect::Visible),
        FaultAction::FailAmbiguous(Effect::Durable),
        FaultAction::Pending(Effect::None),
        FaultAction::Pending(Effect::Visible),
        FaultAction::Pending(Effect::Durable),
    ];
    for boundary in 0..boundary_count {
        for action in actions {
            // Runtime generations and opaque handles deliberately cannot be
            // rolled back. Build an independent but byte-identical legacy
            // fixture for each power-cut case rather than weakening that rule.
            let (case_image, runtime, retained) = legacy_bootstrap_fixture(SEGMENTS, RESERVE);
            assert_eq!(selected_checkpoint(&case_image), old);
            let device = FaultDevice::from_image(SEGMENTS, case_image);
            let mut store = mount_fault(device.clone(), runtime.clone());
            device.arm(boundary, action);
            match action {
                FaultAction::Pending(_) => {
                    let witnesses = [&retained];
                    let mut operation =
                        Box::pin(store.collect_garbage_with_initial_roots(&witnesses));
                    assert!(matches!(poll_once(operation.as_mut()), Poll::Pending));
                    drop(operation);
                }
                FaultAction::FailNotSubmitted | FaultAction::FailAmbiguous(_) => assert!(
                    block_on(store.collect_garbage_with_initial_roots(&[&retained])).is_err(),
                    "bootstrap fault at mutation {boundary} was not reached ({action:?})"
                ),
                FaultAction::Normal | FaultAction::AcknowledgeCorrupt { .. } => unreachable!(),
            }
            assert_eq!(store.info(), Err(StoreError::RecoveryRequired));

            device.power_cycle();
            let mut recovered =
                SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime.clone());
            let selected = block_on(recovered.mount()).unwrap_or_else(|error| {
                panic!(
                    "bootstrap mutation {boundary}, action {action:?}: cold mount failed: {error:?}"
                )
            });
            assert!(
                (old.binding.generation..=old.binding.generation + 2)
                    .contains(&selected.generation),
                "bootstrap mutation {boundary}, action {action:?}: selected unexpected generation"
            );
            let recovered_checkpoint = selected_checkpoint(&device.durable_image());
            if selected.generation == old.binding.generation {
                assert_eq!(recovered_checkpoint.authority_root, PhysicalPointer::Null);
                // A failed pre-G+1 copy may leave a sealed orphan that legacy
                // recovery quarantines into the allocated prefix. It grants
                // no authority and the bootstrap cleaner may select it as a
                // garbage source; physical free count need not remain exact.
                assert!(selected.free_segments >= 2);
                block_on(recovered.collect_garbage_with_initial_roots(&[&retained]))
                    .unwrap_or_else(|error| {
                        panic!(
                            "bootstrap mutation {boundary}, action {action:?}: retry failed: {error:?}"
                        )
                    });
            } else {
                assert_ne!(recovered_checkpoint.authority_root, PhysicalPointer::Null);
                if selected.generation != old.binding.generation + 2 {
                    block_on(recovered.collect_garbage()).unwrap_or_else(|error| {
                        panic!(
                            "bootstrap mutation {boundary}, action {action:?}: resume failed: {error:?}"
                        )
                    });
                }
            }

            device.power_cycle();
            let mut final_cold =
                SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime.clone());
            let final_info = block_on(final_cold.mount()).unwrap();
            assert_eq!(final_info.generation, old.binding.generation + 2);
            assert_eq!(final_info.object_count, 1);
            assert_ne!(
                selected_checkpoint(&device.durable_image()).authority_root,
                PhysicalPointer::Null
            );
            assert_eq!(
                block_on(final_cold.get_blob_chunk(&retained, 0))
                    .unwrap()
                    .bytes,
                vec![0x7a; PAGE_SIZE]
            );
        }
    }
}

#[test]
fn full_gc_keeps_shared_blob_until_last_authority_is_gone_and_cold_mounts() {
    let device = MemoryDevice::blank(16);
    let mut store = format(device.clone());
    let bytes = vec![0xa5; PAGE_SIZE];
    let first = put(&mut store, &bytes);
    let duplicate = put(&mut store, &bytes);
    let runtime = store.runtime_context();
    block_on(store.synchronize_gc_roots(&[&first])).unwrap();
    drop(duplicate);

    let telemetry = block_on(store.collect_garbage()).unwrap();
    assert_eq!(telemetry.live_object_count, 1);
    assert_eq!(telemetry.live_blob_count, 1);
    assert!(telemetry.reclaimed_segments > 0);
    assert_eq!(
        block_on(store.get_blob_chunk(&first, 0)).unwrap().bytes,
        bytes
    );

    let mut cold = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    let info = block_on(cold.mount()).unwrap();
    assert_eq!(info.generation, telemetry.reuse_generation);
    assert_eq!(
        block_on(cold.get_blob_chunk(&first, 0)).unwrap().bytes,
        vec![0xa5; PAGE_SIZE]
    );

    block_on(cold.synchronize_gc_roots(&[])).unwrap();
    drop(first);
    let empty = block_on(cold.collect_garbage()).unwrap();
    assert_eq!(empty.live_object_count, 0);
    assert_eq!(empty.live_blob_count, 0);
    let mut final_cold = SegmentStore::new(device, limits());
    let info = block_on(final_cold.mount()).unwrap();
    assert_eq!(info.object_count, 0);
    assert_eq!(info.generation, empty.reuse_generation);
}

#[test]
fn every_gc_mutation_boundary_recovers_g_or_g_plus_one_and_resumes_to_g_plus_two() {
    const SEGMENTS: u64 = 16;
    let seed_device = MemoryDevice::blank(SEGMENTS);
    let mut seed = format(seed_device.clone());
    let bytes = vec![0x5a; PAGE_SIZE];
    let object = put(&mut seed, &bytes);
    block_on(seed.synchronize_gc_roots(&[&object])).unwrap();
    let old = seed.info().unwrap();
    let image = seed_device.durable_image();
    let (seed_checkpoint, seed_allocation) = allocation_at_selected_checkpoint(&image);
    assert_eq!(seed_checkpoint.binding.generation, old.generation);
    let sources: Vec<_> = (0..seed_allocation.admitted_segments)
        .filter(|&segment_no| {
            seed_allocation.segment_state(segment_no) == Some(SegmentAllocation::Allocated)
        })
        .collect();
    assert!(
        !sources.is_empty(),
        "GC fault seed must have source segments"
    );

    let probe_device = FaultDevice::from_image(SEGMENTS, image.clone());
    let mut probe = mount_fault(probe_device.clone(), StoreRuntimeContext::new());
    probe_device.reset_mutation_count();
    block_on(probe.collect_garbage()).unwrap();
    let boundary_count = probe_device.mutation_count();
    assert!(boundary_count > 30, "GC did not exercise real media stages");

    let actions = [
        FaultAction::FailNotSubmitted,
        FaultAction::FailAmbiguous(Effect::None),
        FaultAction::FailAmbiguous(Effect::Visible),
        FaultAction::FailAmbiguous(Effect::Durable),
        FaultAction::Pending(Effect::None),
        FaultAction::Pending(Effect::Visible),
        FaultAction::Pending(Effect::Durable),
    ];
    for boundary in 0..boundary_count {
        for action in actions {
            let device = FaultDevice::from_image(SEGMENTS, image.clone());
            let mut store = mount_fault(device.clone(), StoreRuntimeContext::new());
            device.arm(boundary, action);
            match action {
                FaultAction::Pending(_) => {
                    let mut operation = Box::pin(store.collect_garbage());
                    assert!(matches!(poll_once(operation.as_mut()), Poll::Pending));
                    drop(operation);
                }
                FaultAction::FailNotSubmitted | FaultAction::FailAmbiguous(_) => assert!(
                    block_on(store.collect_garbage()).is_err(),
                    "fault at mutation {boundary} was not reached ({action:?})"
                ),
                FaultAction::Normal | FaultAction::AcknowledgeCorrupt { .. } => unreachable!(),
            }
            assert_eq!(store.info(), Err(StoreError::RecoveryRequired));

            device.power_cycle();
            let mut recovered = SegmentStore::new(device.clone(), limits());
            let selected = block_on(recovered.mount()).unwrap_or_else(|error| {
                panic!("mutation {boundary}, action {action:?}: cold mount failed: {error:?}")
            });
            let case = format!("mutation {boundary}, action {action:?}");
            let durable_generation =
                assert_source_epoch_state(&device.durable_image(), old.generation, &sources, &case);
            assert_eq!(selected.generation, durable_generation, "{case}");
            assert_eq!(selected.object_count, 1, "{case}");

            if selected.generation != old.generation + 2 {
                let resumed = block_on(recovered.collect_garbage())
                    .unwrap_or_else(|error| panic!("{case}: GC resume failed: {error:?}"));
                assert_eq!(resumed.epoch_generation, old.generation, "{case}");
                assert_eq!(resumed.reuse_generation, old.generation + 2, "{case}");
            }

            device.power_cycle();
            let mut final_cold = SegmentStore::new(device.clone(), limits());
            let final_info = block_on(final_cold.mount())
                .unwrap_or_else(|error| panic!("{case}: final cold mount failed: {error:?}"));
            assert_eq!(final_info.generation, old.generation + 2, "{case}");
            assert_eq!(final_info.object_count, 1, "{case}");
            assert_eq!(
                assert_source_epoch_state(&device.durable_image(), old.generation, &sources, &case,),
                old.generation + 2,
                "{case}"
            );
        }
    }
}

#[test]
fn acknowledged_copied_payload_or_padding_corruption_fails_before_checkpoint_seal() {
    const SEGMENTS: u64 = 16;
    let seed_device = MemoryDevice::blank(SEGMENTS);
    let mut seed = format(seed_device.clone());
    let bytes = vec![0x63; PAGE_SIZE + 17];
    let object = put(&mut seed, &bytes);
    block_on(seed.synchronize_gc_roots(&[&object])).unwrap();
    let old = seed.info().unwrap();
    let seed_image = seed_device.durable_image();
    let old_checkpoint = selected_checkpoint(&seed_image);

    // First run without a fault to bind one deterministic mutation index to
    // the final physical page of a copied, non-page-aligned Blob extent.
    let probe_device = FaultDevice::from_image(SEGMENTS, seed_image.clone());
    let mut probe = mount_fault(probe_device.clone(), StoreRuntimeContext::new());
    probe_device.reset_mutation_count();
    block_on(probe.collect_garbage()).unwrap();
    let mutation_pages = probe_device.mutation_pages();
    let probe_image = probe_device.durable_image();
    let (probe_checkpoint, probe_cas) = cas_at_selected_checkpoint(&probe_image);
    let context = CasCodecContext::new(
        probe_checkpoint.binding.store_uuid,
        probe_checkpoint.admitted_segments,
        probe_checkpoint.next_segment_generation,
    )
    .unwrap();
    let mapping = probe_cas
        .blobs
        .iter()
        .find(|mapping| mapping.blob_key.exact_len() == bytes.len() as u64)
        .expect("the retained Blob must remain in the relocated snapshot");
    let manifest =
        decode_blob_manifest(&pointer_payload(&probe_image, mapping.manifest), context).unwrap();
    let copied_pointer = manifest
        .extents
        .iter()
        .find_map(|extent| {
            let PhysicalPointer::Value(pointer) = extent.pointer else {
                return None;
            };
            (pointer.segment_generation >= old_checkpoint.next_segment_generation
                && !pointer.exact_byte_len.is_multiple_of(PAGE_SIZE as u64))
            .then_some(pointer)
        })
        .expect("fixture must relocate a Blob extent with physical page padding");
    let exact_tail = usize::try_from(copied_pointer.exact_byte_len % PAGE_SIZE as u64).unwrap();
    assert_ne!(exact_tail, 0);
    let copied_last_page = ANCHOR_PAGES
        + copied_pointer.segment_no * SEGMENT_PAGES
        + u64::from(copied_pointer.payload_relative_page)
        + u64::from(copied_pointer.payload_pages - 1);
    let copied_write = mutation_pages
        .iter()
        .position(|page| *page == Some(copied_last_page))
        .expect("probe trace must contain the copied target payload write");

    for (case, byte_index, expected_stage) in [
        (
            "payload",
            exact_tail - 1,
            "relocate-copied-payload-readback",
        ),
        ("padding", exact_tail, "relocate-copied-padding-readback"),
    ] {
        let device = FaultDevice::from_image(SEGMENTS, seed_image.clone());
        let mut store = mount_fault(device.clone(), StoreRuntimeContext::new());
        device.arm(copied_write, FaultAction::AcknowledgeCorrupt { byte_index });
        let result = block_on(store.collect_garbage());
        assert!(
            matches!(
                result,
                Err(GcStoreError::Gc(GcError::CorruptAt(stage))) if stage == expected_stage
            ),
            "{case} corruption returned {result:?}"
        );
        assert_eq!(store.info(), Err(StoreError::RecoveryRequired), "{case}");
        assert!(
            !device
                .mutation_pages()
                .into_iter()
                .flatten()
                .any(|page| (4..=7).contains(&page)),
            "{case} corruption reached a checkpoint body or seal write"
        );
        assert_eq!(
            selected_checkpoint(&device.durable_image())
                .binding
                .generation,
            old.generation,
            "{case} corruption published a newer checkpoint"
        );

        device.power_cycle();
        let mut cold = SegmentStore::new(device, limits());
        let recovered = block_on(cold.mount()).unwrap();
        assert_eq!(recovered.generation, old.generation, "{case}");
        assert_eq!(recovered.object_count, 1, "{case}");
    }
}

#[test]
fn marker_bearing_torn_old_checkpoint_seal_fails_closed_after_gc() {
    let device = MemoryDevice::blank(16);
    let mut store = format(device.clone());
    let object = put(&mut store, &[0x91; PAGE_SIZE]);
    block_on(store.synchronize_gc_roots(&[&object])).unwrap();
    let telemetry = block_on(store.collect_garbage()).unwrap();
    let mut image = device.durable_image();

    let old_generation = telemetry.relocation_generation;
    let old_slot = (old_generation - 1) & 1;
    let old_body_page = 4 + old_slot * 2;
    assert!(matches!(
        decode_checkpoint(
            &image_page(&image, old_body_page),
            &image_page(&image, old_body_page + 1),
        )
        .unwrap(),
        DecodeStatus::Sealed(checkpoint)
            if checkpoint.binding.generation == old_generation
    ));

    let old_seal = image
        .get_mut(&(old_body_page + 1))
        .expect("the old checkpoint seal must be present");
    assert_eq!(&old_seal[0xff0..], b"VIBESG2-SEALED!!");
    old_seal[0x050] ^= 0x80;
    assert_eq!(
        &old_seal[0xff0..],
        b"VIBESG2-SEALED!!",
        "the synthetic tear must retain its publication marker"
    );

    let torn = FaultDevice::from_image(16, image);
    torn.power_cycle();
    let mut cold = SegmentStore::new(torn, limits());
    assert!(
        matches!(
            block_on(cold.mount()),
            Err(StoreError::Format(_)) | Err(StoreError::Corrupt)
        ),
        "a marker-bearing torn older seal must not be ignored in favor of G+2"
    );
}

#[test]
fn reclaimed_source_is_reused_with_a_fresh_segment_generation_and_cold_reads() {
    const SEGMENTS: u64 = 16;
    let seed_device = MemoryDevice::blank(SEGMENTS);
    let mut seed = format(seed_device.clone());
    let retained = put(&mut seed, &[0x37; PAGE_SIZE]);
    block_on(seed.synchronize_gc_roots(&[&retained])).unwrap();
    let epoch = seed.info().unwrap().generation;
    let seed_image = seed_device.durable_image();
    let (_, seed_allocation) = allocation_at_selected_checkpoint(&seed_image);
    let sources: Vec<_> = (0..seed_allocation.admitted_segments)
        .filter(|&segment_no| {
            seed_allocation.segment_state(segment_no) == Some(SegmentAllocation::Allocated)
        })
        .collect();
    let source_generations: BTreeMap<_, _> = sources
        .iter()
        .map(|&segment_no| (segment_no, segment_generation(&seed_image, segment_no)))
        .collect();

    let device = FaultDevice::from_image(SEGMENTS, seed_image);
    let mut store = mount_fault(device.clone(), StoreRuntimeContext::new());
    let telemetry = block_on(store.collect_garbage()).unwrap();
    assert_eq!(telemetry.epoch_generation, epoch);
    assert_eq!(telemetry.reuse_generation, epoch + 2);
    let after_gc = device.durable_image();
    assert_eq!(
        assert_source_epoch_state(&after_gc, epoch, &sources, "successful GC"),
        epoch + 2
    );
    let (reuse_checkpoint, _) = allocation_at_selected_checkpoint(&after_gc);

    let bytes = vec![0xc4; PAGE_SIZE + 37];
    let reused_object = put(&mut store, &bytes);
    let runtime = store.runtime_context();
    let after_reuse = device.durable_image();
    let (_, allocation) = allocation_at_selected_checkpoint(&after_reuse);
    let (reused_source, old_segment_generation, fresh_segment_generation) = sources
        .iter()
        .find_map(|&segment_no| {
            let old = source_generations[&segment_no];
            let current = segment_generation(&after_reuse, segment_no);
            (current != old).then_some((segment_no, old, current))
        })
        .expect("the first post-G+2 allocation must reuse a reclaimed source");
    assert_eq!(
        allocation.segment_state(reused_source),
        Some(SegmentAllocation::Allocated)
    );
    assert!(
        fresh_segment_generation > old_segment_generation,
        "reused source {reused_source} kept stale generation {old_segment_generation}"
    );
    assert!(
        fresh_segment_generation >= reuse_checkpoint.next_segment_generation,
        "reused source {reused_source} did not receive a generation from the post-G+2 cursor"
    );

    device.power_cycle();
    let mut cold =
        SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime.clone());
    let cold_info = block_on(cold.mount()).unwrap();
    assert!(cold_info.generation > telemetry.reuse_generation);
    assert_eq!(
        block_on(cold.get_blob_chunk(&reused_object, 0))
            .unwrap()
            .bytes,
        bytes[..PAGE_SIZE]
    );
    assert_eq!(
        block_on(cold.get_blob_chunk(&reused_object, 1))
            .unwrap()
            .bytes,
        bytes[PAGE_SIZE..]
    );
}

#[test]
fn deterministic_workload_exceeds_initial_ordinary_capacity_across_stable_gc_cycles() {
    const SEGMENTS: u64 = 12;
    const CLEANER_RESERVE: u32 = 5;
    const CYCLES: u64 = 6;
    const PAYLOAD_BYTES: usize = 5 * 1024 * 1024;

    let workload_limits = StoreLimits {
        max_catalog_entries: 16,
        recovery_memory_bytes: 4 * 1024 * 1024,
        ..limits()
    };
    let device = MemoryDevice::blank(SEGMENTS);
    let mut store = format_with(device.clone(), workload_limits, CLEANER_RESERVE);
    let initial_ordinary_capacity =
        (SEGMENTS - u64::from(CLEANER_RESERVE)) * SEGMENT_PAGES * PAGE_SIZE as u64;
    let mut logical_bytes_written = 0_u64;
    let mut retained: Option<AuthorizedObject<CasObjectHandle>> = None;
    let mut stable_allocated_segments = None;

    for cycle in 0..CYCLES {
        let fill = u8::try_from(cycle + 1).unwrap();
        let bytes = vec![fill; PAYLOAD_BYTES];
        let next = put(&mut store, &bytes);
        block_on(store.synchronize_gc_roots(&[&next])).unwrap();
        drop(retained.take());
        logical_bytes_written += bytes.len() as u64;

        let before = store.info().unwrap();
        assert!(
            before.free_segments >= u64::from(CLEANER_RESERVE),
            "cycle {cycle} consumed the cleaner reserve before GC: {before:?}"
        );
        let telemetry = block_on(store.collect_garbage())
            .unwrap_or_else(|error| panic!("cycle {cycle} GC failed: {error:?}"));
        assert_eq!(telemetry.root_count, 1, "cycle {cycle}");
        assert_eq!(telemetry.live_object_count, 1, "cycle {cycle}");
        assert_eq!(telemetry.live_blob_count, 1, "cycle {cycle}");
        assert!(
            u64::from(telemetry.retired_segments) < before.allocated_segments,
            "cycle {cycle} did not use partial source selection"
        );
        assert_eq!(
            telemetry.reclaimed_segments, telemetry.retired_segments,
            "cycle {cycle} did not reclaim the exact retired set"
        );
        assert_eq!(
            telemetry.reclaimed_bytes,
            u64::from(telemetry.reclaimed_segments) * SEGMENT_PAGES * PAGE_SIZE as u64,
            "cycle {cycle} reported inconsistent reclaimed bytes"
        );
        assert!(
            telemetry.target_segments <= CLEANER_RESERVE,
            "cycle {cycle} exceeded cleaner-target capacity"
        );
        assert!(
            telemetry.reclaimed_segments > telemetry.target_segments,
            "cycle {cycle} did not produce net segment reclamation"
        );
        assert_eq!(
            telemetry.reserve_pressure_ppm,
            u32::try_from(
                u64::from(telemetry.target_segments) * 1_000_000 / u64::from(CLEANER_RESERVE)
            )
            .unwrap(),
            "cycle {cycle}"
        );
        assert!(telemetry.reserve_pressure_ppm <= 1_000_000, "cycle {cycle}");
        assert!(
            telemetry.memory_high_water_bytes <= workload_limits.recovery_memory_bytes,
            "cycle {cycle} exceeded its accounted memory ceiling"
        );
        assert!(telemetry.write_amplification_ppm() > 0, "cycle {cycle}");

        let after = store.info().unwrap();
        assert_eq!(
            after.allocated_segments,
            before.allocated_segments - u64::from(telemetry.reclaimed_segments)
                + u64::from(telemetry.target_segments),
            "cycle {cycle} allocation accounting did not preserve unselected sources"
        );
        assert!(
            after.free_segments >= u64::from(CLEANER_RESERVE),
            "cycle {cycle} violated the cleaner reserve after GC: {after:?}"
        );
        if let Some(expected) = stable_allocated_segments {
            assert_eq!(
                after.allocated_segments, expected,
                "cycle {cycle} did not converge to the stable post-GC footprint"
            );
        } else {
            stable_allocated_segments = Some(after.allocated_segments);
        }
        assert_eq!(
            block_on(store.get_blob_chunk(&next, 0)).unwrap().bytes,
            vec![fill; PAGE_SIZE],
            "cycle {cycle} lost the first live chunk"
        );
        assert_eq!(
            block_on(store.get_blob_chunk(&next, (PAYLOAD_BYTES / PAGE_SIZE - 1) as u32))
                .unwrap()
                .bytes,
            vec![fill; PAGE_SIZE],
            "cycle {cycle} lost the last live chunk"
        );
        retained = Some(next);
    }

    assert!(
        logical_bytes_written > initial_ordinary_capacity,
        "workload wrote {logical_bytes_written} bytes but initial ordinary capacity was \
         {initial_ordinary_capacity}"
    );
    let latest = retained.as_ref().unwrap();
    let runtime = store.runtime_context();
    let mut cold = SegmentStore::new_with_runtime_context(device, workload_limits, runtime);
    let cold_info = block_on(cold.mount()).unwrap();
    assert_eq!(
        cold_info.allocated_segments,
        stable_allocated_segments.unwrap()
    );
    assert_eq!(
        block_on(cold.get_blob_chunk(latest, 0)).unwrap().bytes,
        vec![CYCLES as u8; PAGE_SIZE]
    );
}

#[test]
fn foreground_admission_uses_root_headroom_then_cleans_before_capacity_failure() {
    const SEGMENTS: u64 = 14;
    const CLEANER_RESERVE: u32 = 4;
    let device = MemoryDevice::blank(SEGMENTS);
    let mut store = format_with(device, limits(), CLEANER_RESERVE);
    let mut garbage = Vec::new();
    let mut sequence = 1_u8;

    loop {
        let payload = vec![sequence; PAGE_SIZE + 17];
        let mut writer = match store.begin_blob(OBJECT_KIND, payload.len() as u64, None) {
            Ok(writer) => writer,
            Err(CasStoreError::Store(StoreError::Capacity(CapacityClass::CleanerReserve))) => break,
            Err(error) => panic!("unexpected foreground-fill admission error: {error:?}"),
        };
        for chunk in payload.chunks(PAGE_SIZE) {
            block_on(writer.write_chunk(chunk)).unwrap();
        }
        garbage.push(block_on(writer.commit()).unwrap());
        sequence = sequence.wrapping_add(1).max(1);
    }

    let before_policy = store.info().unwrap();
    assert!(
        before_policy.free_segments >= u64::from(CLEANER_RESERVE + ROOT_POLICY_HEADROOM_SEGMENTS)
    );
    drop(garbage);
    while store.info().unwrap().free_segments > u64::from(CLEANER_RESERVE) {
        block_on(store.synchronize_gc_roots(&[])).unwrap();
    }
    let after_policy = store.info().unwrap();
    assert_eq!(after_policy.free_segments, u64::from(CLEANER_RESERVE));

    let next_payload = vec![0xf1; PAGE_SIZE + 17];
    let clock = StepClock(AtomicU64::new(1_000));
    let (mut writer, telemetry) = block_on(store.begin_blob_with_foreground_gc(
        OBJECT_KIND,
        next_payload.len() as u64,
        None,
        &clock,
    ))
    .unwrap();
    let telemetry = telemetry.expect("admission at the reserve boundary must run foreground GC");
    assert!(telemetry.foreground_cycles >= 1);
    assert!(telemetry.pause_time_measured);
    assert_eq!(telemetry.foreground_pause_ns, 100);
    assert!(telemetry.reclaimed_segments > telemetry.target_segments);
    for chunk in next_payload.chunks(PAGE_SIZE) {
        block_on(writer.write_chunk(chunk)).unwrap();
    }
    let retained = block_on(writer.commit()).unwrap();
    assert_eq!(
        block_on(store.get_blob_chunk(&retained, 0)).unwrap().bytes,
        next_payload[..PAGE_SIZE]
    );
    assert!(
        store.info().unwrap().free_segments
            >= u64::from(CLEANER_RESERVE + ROOT_POLICY_HEADROOM_SEGMENTS)
    );
}

#[test]
fn foreground_admission_collects_unreachable_catalog_entries_before_metadata_failure() {
    const SEGMENTS: u64 = 16;
    let metadata_limits = StoreLimits {
        max_catalog_entries: 2,
        ..limits()
    };
    let device = MemoryDevice::blank(SEGMENTS);
    let mut store = format_with(device, metadata_limits, 5);
    let first = put(&mut store, &[0x31; PAGE_SIZE]);
    let second = put(&mut store, &[0x42; PAGE_SIZE]);
    drop((first, second));
    block_on(store.synchronize_gc_roots(&[])).unwrap();

    let clock = StepClock(AtomicU64::new(2_000));
    let (mut writer, telemetry) =
        block_on(store.begin_blob_with_foreground_gc(OBJECT_KIND, PAGE_SIZE as u64, None, &clock))
            .unwrap();
    let telemetry = telemetry.expect("metadata admission must run foreground GC");
    assert!(telemetry.foreground_cycles >= 1);
    assert_eq!(telemetry.live_object_count, 0);
    block_on(writer.write_chunk(&[0x53; PAGE_SIZE])).unwrap();
    let replacement = block_on(writer.commit()).unwrap();
    assert_eq!(
        block_on(store.get_blob_chunk(&replacement, 0))
            .unwrap()
            .bytes,
        vec![0x53; PAGE_SIZE]
    );
}

#[test]
fn immutable_foreground_request_error_precedes_any_cleaner_mutation() {
    const SEGMENTS: u64 = 16;
    let metadata_limits = StoreLimits {
        max_catalog_entries: 1,
        ..limits()
    };
    let seed_device = MemoryDevice::blank(SEGMENTS);
    let mut seed = format_with(seed_device.clone(), metadata_limits, 5);
    let garbage = put(&mut seed, &[0x64; PAGE_SIZE]);
    drop(garbage);
    block_on(seed.synchronize_gc_roots(&[])).unwrap();

    let device = FaultDevice::from_image(SEGMENTS, seed_device.durable_image());
    let mut store = SegmentStore::new(device.clone(), metadata_limits);
    block_on(store.mount()).unwrap();
    device.reset_mutation_count();
    let before = device.durable_image();
    let clock = StepClock(AtomicU64::new(3_000));
    assert!(matches!(
        block_on(store.begin_blob_with_foreground_gc(0, PAGE_SIZE as u64, None, &clock)),
        Err(vibeos_segment_store::ForegroundBlobError::Cas(
            CasStoreError::Blob(vibeos_blob_format::BlobError::EmptyObjectKind)
        ))
    ));
    assert_eq!(device.mutation_count(), 0);
    assert_eq!(device.durable_image(), before);
}

#[test]
fn public_runtime_operation_pin_keeps_an_authorized_object_in_the_root_union() {
    let device = MemoryDevice::blank(12);
    let mut store = format(device);
    let object = put(&mut store, &[0x91; PAGE_SIZE + 23]);
    let snapshot = store
        .pin_runtime_object(&object, RuntimeObjectPinClass::ExplicitSnapshot)
        .unwrap();
    block_on(store.synchronize_gc_roots(&[])).unwrap();
    drop(object);

    let retained = block_on(store.collect_garbage()).unwrap();
    assert_eq!(retained.root_count, 1);
    assert_eq!(retained.live_object_count, 1);
    assert_eq!(retained.live_blob_count, 1);

    drop(snapshot);
}

#[test]
fn synchronously_stopped_fault_domain_releases_only_its_grouped_runtime_pins() {
    let device = MemoryDevice::blank(12);
    let mut store = format(device);
    let object = put(&mut store, &[0xa7; PAGE_SIZE + 9]);
    let stopped_owner = store.allocate_runtime_pin_owner().unwrap();
    let live_owner = store.allocate_runtime_pin_owner().unwrap();
    let leaked = store
        .pin_runtime_object_owned(
            &object,
            RuntimeObjectPinClass::InvocationLease,
            &stopped_owner,
        )
        .unwrap();
    let live = store
        .pin_runtime_object_owned(
            &object,
            RuntimeObjectPinClass::AuthorityTransaction,
            &live_owner,
        )
        .unwrap();
    core::mem::forget(leaked);
    block_on(store.synchronize_gc_roots(&[])).unwrap();
    drop(object);

    // SAFETY: this test has synchronously stopped the modeled fault domain;
    // its leaked guard will never execute again.
    let stopped = unsafe { StoppedRuntimePinOwner::after_synchronous_join(stopped_owner) };
    let released = store.release_stopped_runtime_pins(stopped).unwrap();
    assert_eq!(released.roots, 1);
    assert_eq!(released.readers, 0);
    let retained = block_on(store.collect_garbage()).unwrap();
    assert_eq!(retained.root_count, 1);
    assert_eq!(retained.live_object_count, 1);

    drop(live);
}

#[test]
fn runtime_pin_owner_is_bound_to_exact_store_registry() {
    let first = format(MemoryDevice::blank(12));
    let mut second = format(MemoryDevice::blank(12));
    let object = put(&mut second, &[0xb8; PAGE_SIZE + 5]);
    let foreign_pin_owner = first.allocate_runtime_pin_owner().unwrap();
    assert!(matches!(
        second.pin_runtime_object_owned(
            &object,
            RuntimeObjectPinClass::InvocationLease,
            &foreign_pin_owner,
        ),
        Err(vibeos_segment_store::CasStoreError::Store(
            StoreError::ObjectUnavailable
        ))
    ));

    let live_owner = second.allocate_runtime_pin_owner().unwrap();
    let live = second
        .pin_runtime_object_owned(
            &object,
            RuntimeObjectPinClass::MigrationTransaction,
            &live_owner,
        )
        .unwrap();
    let foreign_stop_owner = first.allocate_runtime_pin_owner().unwrap();
    // SAFETY: the modeled first-store domain never started any operation.
    let foreign_stopped =
        unsafe { StoppedRuntimePinOwner::after_synchronous_join(foreign_stop_owner) };
    assert_eq!(
        second.release_stopped_runtime_pins(foreign_stopped),
        Err(RuntimePinOwnerError::WrongStore)
    );

    block_on(second.synchronize_gc_roots(&[])).unwrap();
    drop(object);
    let retained = block_on(second.collect_garbage()).unwrap();
    assert_eq!(retained.live_object_count, 1);
    drop(live);
}

#[test]
fn gc_memory_high_water_is_an_exact_admission_boundary() {
    const SEGMENTS: u64 = 16;
    let seed_device = MemoryDevice::blank(SEGMENTS);
    let mut seed = format(seed_device.clone());
    let retained = put(&mut seed, &[0x6d; PAGE_SIZE * 2 + 17]);
    block_on(seed.synchronize_gc_roots(&[&retained])).unwrap();
    let image = seed_device.durable_image();

    let probe_device = FaultDevice::from_image(SEGMENTS, image.clone());
    let mut probe = SegmentStore::new(probe_device, limits());
    let probe_mount = block_on(probe.mount()).unwrap();
    let probe_telemetry = block_on(probe.collect_garbage()).unwrap();
    let exact_peak = probe_telemetry.memory_high_water_bytes;
    assert!(exact_peak > probe_mount.recovery_peak_bytes);
    assert!(exact_peak <= limits().recovery_memory_bytes);

    let exact_limits = StoreLimits {
        recovery_memory_bytes: exact_peak,
        ..limits()
    };
    let exact_device = FaultDevice::from_image(SEGMENTS, image.clone());
    let mut exact = SegmentStore::new(exact_device.clone(), exact_limits);
    block_on(exact.mount()).unwrap();
    let exact_telemetry = block_on(exact.collect_garbage()).unwrap();
    assert_eq!(exact_telemetry.memory_high_water_bytes, exact_peak);
    assert!(exact.info().unwrap().recovery_peak_bytes <= exact_peak);
    exact_device.power_cycle();
    let mut exact_cold = SegmentStore::new(exact_device, exact_limits);
    block_on(exact_cold.mount()).unwrap();

    let below_limits = StoreLimits {
        recovery_memory_bytes: exact_peak - 1,
        ..limits()
    };
    let below_device = FaultDevice::from_image(SEGMENTS, image);
    let before_image = below_device.durable_image();
    let mut below = SegmentStore::new(below_device.clone(), below_limits);
    let before = block_on(below.mount()).unwrap();
    assert!(before.recovery_peak_bytes < exact_peak);
    assert!(matches!(
        block_on(below.collect_garbage()),
        Err(GcStoreError::Gc(GcError::MemoryLimit))
            | Err(GcStoreError::Store(StoreError::MemoryLimit))
    ));
    assert_eq!(below.info().unwrap(), before);
    assert_eq!(below_device.durable_image(), before_image);
}

#[test]
fn root_policy_sync_memory_limit_fails_before_any_media_mutation() {
    const SEGMENTS: u64 = 16;
    let seed_device = MemoryDevice::blank(SEGMENTS);
    let mut seed = format(seed_device.clone());
    let mut objects = Vec::new();
    for fill in 1_u8..=4 {
        objects.push(put(&mut seed, &[fill; PAGE_SIZE]));
    }
    drop(objects);
    let image = seed_device.durable_image();

    let succeeds = |limit: usize| {
        let candidate_limits = StoreLimits {
            recovery_memory_bytes: limit,
            ..limits()
        };
        let device = FaultDevice::from_image(SEGMENTS, image.clone());
        let mut store = SegmentStore::new(device, candidate_limits);
        if block_on(store.mount()).is_err() {
            return false;
        }
        block_on(store.synchronize_gc_roots(&[])).is_ok()
    };
    let mut low = 1_usize;
    let mut high = limits().recovery_memory_bytes;
    assert!(succeeds(high));
    while low < high {
        let midpoint = low + (high - low) / 2;
        if succeeds(midpoint) {
            high = midpoint;
        } else {
            low = midpoint + 1;
        }
    }
    let exact = low;
    assert!(exact > 1);

    let below_limits = StoreLimits {
        recovery_memory_bytes: exact - 1,
        ..limits()
    };
    let below_device = FaultDevice::from_image(SEGMENTS, image);
    let before = below_device.durable_image();
    let mut below = SegmentStore::new(below_device.clone(), below_limits);
    block_on(below.mount()).expect("fixture must isolate sync rather than mount admission");
    below_device.reset_mutation_count();
    assert!(matches!(
        block_on(below.synchronize_gc_roots(&[])),
        Err(GcStoreError::Gc(GcError::MemoryLimit))
            | Err(GcStoreError::Store(StoreError::MemoryLimit))
    ));
    assert_eq!(below_device.mutation_count(), 0);
    assert_eq!(below_device.durable_image(), before);
}

#[test]
fn gc_telemetry_arithmetic_saturates_and_zero_denominator_is_defined() {
    assert_eq!(GcTelemetry::default().write_amplification_ppm(), 0);
    let no_reclaimed_bytes = GcTelemetry {
        copied_bytes: 7,
        metadata_bytes: 11,
        reclaimed_bytes: 0,
        ..GcTelemetry::default()
    };
    assert_eq!(no_reclaimed_bytes.write_amplification_ppm(), 0);

    let saturated = GcTelemetry {
        copied_bytes: u64::MAX,
        metadata_bytes: u64::MAX,
        reclaimed_bytes: 1,
        ..GcTelemetry::default()
    };
    assert_eq!(saturated.write_amplification_ppm(), u64::MAX);

    let divided = GcTelemetry {
        copied_bytes: u64::MAX,
        metadata_bytes: u64::MAX,
        reclaimed_bytes: 2,
        ..GcTelemetry::default()
    };
    assert_eq!(divided.write_amplification_ppm(), u64::MAX / 2);
}

#[test]
fn shared_runtime_generation_makes_a_stale_reader_retry_after_gc_publication() {
    let device = MemoryDevice::blank(16);
    let mut cleaner = format(device.clone());
    let bytes = vec![0x33; PAGE_SIZE];
    let object = put(&mut cleaner, &bytes);
    block_on(cleaner.synchronize_gc_roots(&[&object])).unwrap();
    let runtime = cleaner.runtime_context();

    let mut stale_reader =
        SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime.clone());
    block_on(stale_reader.mount()).unwrap();
    block_on(cleaner.collect_garbage()).unwrap();

    let durable_after_gc = device.durable_image();
    assert!(matches!(
        stale_reader.begin_blob(OBJECT_KIND, 1, None),
        Err(vibeos_segment_store::CasStoreError::Store(
            StoreError::RecoveryRequired
        ))
    ));
    assert!(matches!(
        block_on(stale_reader.synchronize_gc_roots(&[])),
        Err(vibeos_segment_store::GcStoreError::Store(
            StoreError::RecoveryRequired
        ))
    ));
    assert!(matches!(
        block_on(stale_reader.collect_garbage()),
        Err(vibeos_segment_store::GcStoreError::Store(
            StoreError::RecoveryRequired
        ))
    ));
    assert_eq!(device.durable_image(), durable_after_gc);

    let stale_result = block_on(stale_reader.get_blob_chunk(&object, 0));
    assert!(
        matches!(
            stale_result,
            Err(vibeos_segment_store::CasStoreError::Store(
                StoreError::RecoveryRequired
            ))
        ),
        "unexpected stale-reader result: {stale_result:?}"
    );
    block_on(stale_reader.mount()).unwrap();
    assert_eq!(
        block_on(stale_reader.get_blob_chunk(&object, 0))
            .unwrap()
            .bytes,
        bytes
    );
}

#[test]
fn partial_gc_preserves_unselected_live_extent_pointers() {
    const SEGMENTS: u64 = 16;
    const LARGE_BYTES: usize = 5 * 1024 * 1024;

    let device = MemoryDevice::blank(SEGMENTS);
    let mut store = format_with(device.clone(), limits(), 5);
    let garbage = put(&mut store, &[0x17; PAGE_SIZE]);
    let small_bytes = vec![0x29; PAGE_SIZE];
    let small = put(&mut store, &small_bytes);
    let large_bytes = vec![0x3b; LARGE_BYTES];
    let large = put(&mut store, &large_bytes);
    block_on(store.synchronize_gc_roots(&[&small, &large])).unwrap();
    drop(garbage);

    let before_image = device.durable_image();
    let (before_checkpoint, before_cas) = cas_at_selected_checkpoint(&before_image);
    let before_context = CasCodecContext::new(
        before_checkpoint.binding.store_uuid,
        before_checkpoint.admitted_segments,
        before_checkpoint.next_segment_generation,
    )
    .unwrap();
    let before_large_mapping = before_cas
        .blobs
        .iter()
        .find(|mapping| mapping.blob_key.exact_len() == LARGE_BYTES as u64)
        .unwrap();
    let before_large_manifest = decode_blob_manifest(
        &pointer_payload(&before_image, before_large_mapping.manifest),
        before_context,
    )
    .unwrap();
    let before_large_pointers: Vec<_> = before_large_manifest
        .extents
        .iter()
        .map(|extent| extent.pointer)
        .collect();
    let before_allocated = store.info().unwrap().allocated_segments;

    let telemetry = block_on(store.collect_garbage()).unwrap();
    assert!(u64::from(telemetry.reclaimed_segments) < before_allocated);
    assert!(telemetry.reclaimed_segments > telemetry.target_segments);

    let after_image = device.durable_image();
    let (after_checkpoint, after_cas) = cas_at_selected_checkpoint(&after_image);
    let after_context = CasCodecContext::new(
        after_checkpoint.binding.store_uuid,
        after_checkpoint.admitted_segments,
        after_checkpoint.next_segment_generation,
    )
    .unwrap();
    let after_large_mapping = after_cas
        .blobs
        .iter()
        .find(|mapping| mapping.blob_key.exact_len() == LARGE_BYTES as u64)
        .unwrap();
    let after_large_manifest = decode_blob_manifest(
        &pointer_payload(&after_image, after_large_mapping.manifest),
        after_context,
    )
    .unwrap();
    let after_large_pointers: Vec<_> = after_large_manifest
        .extents
        .iter()
        .map(|extent| extent.pointer)
        .collect();
    assert!(
        after_large_pointers
            .iter()
            .zip(&before_large_pointers)
            .any(|(after, before)| after == before),
        "at least one high-live unselected extent must keep its authenticated pointer"
    );
    assert!(
        after_large_pointers
            .iter()
            .zip(&before_large_pointers)
            .any(|(after, before)| after != before),
        "fixture must also cover a selected low-live tail segment"
    );
    let (_, after_allocation) = allocation_at_selected_checkpoint(&after_image);
    for pointer in after_large_pointers
        .iter()
        .zip(&before_large_pointers)
        .filter_map(|(after, before)| (after == before).then_some(*after))
    {
        let PhysicalPointer::Value(pointer) = pointer else {
            panic!("Blob extent pointer must not be null");
        };
        assert_eq!(
            after_allocation.segment_state(pointer.segment_no),
            Some(SegmentAllocation::Allocated),
            "unchanged pointer must still name an Allocated segment"
        );
    }
    assert_eq!(
        block_on(store.get_blob_chunk(&small, 0)).unwrap().bytes,
        small_bytes
    );
    assert_eq!(
        block_on(store.get_blob_chunk(&large, 0)).unwrap().bytes,
        vec![0x3b; PAGE_SIZE]
    );

    let raw_path = raw_image_path("partial-ok");
    write_raw_image(&after_image, device.page_count, &raw_path);
    let accepted = run_raw_gc_verifier(&raw_path);
    let _ = std::fs::remove_file(&raw_path);
    let accepted_stdout = String::from_utf8(accepted.stdout).unwrap();
    assert!(
        accepted.status.success(),
        "Python GC verifier rejected a powered-off production image: {accepted_stdout}"
    );
    assert!(accepted_stdout.contains("\"status\":\"ok\""));

    let small_mapping = after_cas
        .blobs
        .iter()
        .find(|mapping| mapping.blob_key.exact_len() == PAGE_SIZE as u64)
        .unwrap();
    let small_manifest = decode_blob_manifest(
        &pointer_payload(&after_image, small_mapping.manifest),
        after_context,
    )
    .unwrap();
    let PhysicalPointer::Value(corrupt_extent) = small_manifest.extents[0].pointer else {
        panic!("Blob extent pointer must not be null");
    };
    let corrupt_page = ANCHOR_PAGES
        + corrupt_extent.segment_no * SEGMENT_PAGES
        + u64::from(corrupt_extent.payload_relative_page);
    let mut corrupt_image = after_image.clone();
    corrupt_image
        .get_mut(&corrupt_page)
        .expect("live Blob payload page must be materialized")[0] ^= 0x80;
    let corrupt_path = raw_image_path("partial-corrupt");
    write_raw_image(&corrupt_image, device.page_count, &corrupt_path);
    let rejected = run_raw_gc_verifier(&corrupt_path);
    let _ = std::fs::remove_file(&corrupt_path);
    let rejected_stdout = String::from_utf8(rejected.stdout).unwrap();
    assert!(!rejected.status.success(), "{rejected_stdout}");
    assert!(rejected_stdout.contains("\"status\":\"corrupt\""));
}

#[test]
fn cold_mount_does_not_reuse_highest_object_id_collected_by_gc() {
    let device = MemoryDevice::blank(16);
    let mut store = format(device.clone());
    let retained = put(&mut store, &[0x51; PAGE_SIZE]);
    let collected = put(&mut store, &[0x62; PAGE_SIZE]);
    let (_, before) = cas_at_selected_checkpoint(&device.durable_image());
    let before_ids: Vec<_> = before
        .objects
        .iter()
        .map(|object| object.object_id)
        .collect();
    assert_eq!(before_ids, vec![1, 2]);

    block_on(store.synchronize_gc_roots(&[&retained])).unwrap();
    drop(collected);
    let telemetry = block_on(store.collect_garbage()).unwrap();
    let (_, after_gc) = cas_at_selected_checkpoint(&device.durable_image());
    assert_eq!(
        after_gc
            .objects
            .iter()
            .map(|object| object.object_id)
            .collect::<Vec<_>>(),
        vec![1],
        "fixture must collect the highest issued ObjectId"
    );

    drop(retained);
    drop(store);
    let mut cold = SegmentStore::new(device.clone(), limits());
    let cold_info = block_on(cold.mount()).unwrap();
    assert_eq!(cold_info.generation, telemetry.reuse_generation);
    let replacement = put(&mut cold, &[0x73; PAGE_SIZE]);
    let (_, after_put) = cas_at_selected_checkpoint(&device.durable_image());
    let after_ids: Vec<_> = after_put
        .objects
        .iter()
        .map(|object| object.object_id)
        .collect();
    assert_eq!(after_ids[0], 1);
    assert_eq!(after_ids[1], u128::from(telemetry.reuse_generation));
    assert!(after_ids[1] > 2, "collected ObjectId 2 was reused");
    drop(replacement);
}
