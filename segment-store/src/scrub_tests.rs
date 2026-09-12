use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;
use core::future::Future;
use core::task::{Context, Poll, Waker};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::pins::{PinAdmission, PinRegistry};
use crate::{
    decode_blob_manifest, decode_cas_snapshot, encode_typed_manifest_refs_v1, AuthorizedObject,
    CasCodecContext, CasObjectHandle, FormatOptions, MaintenanceOperation, PageDevice,
    PageDeviceInfo, ScrubCorruptionDomain, ScrubError, ScrubStatus, SegmentAllocation,
    SegmentStore, StoreLimits, StoreRuntimeContext, TypedManifestRefsV1, TypedObjectReference,
    REFERENCE_CODEC_TYPED_V1,
};
use vibeos_segment_format::{
    admitted_pages, decode_checkpoint, decode_extent, decode_segment_header,
    decode_segment_summary, segment_base_page, Checkpoint, DecodeStatus, ExtentKind, Page,
    PhysicalPointer, StoreUuid, DATA_FIRST_PAGE, PAGE_SIZE, SUMMARY_BODY_PAGE, SUMMARY_SEAL_PAGE,
};
use vibeos_storage_device::MutationFailure;

const SEGMENTS: u64 = 16;
const OBJECT_KIND: u32 = 0x5343_5255;
const TYPED_KIND: u32 = 0x5459_5045;

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
    OutsideRange,
    SensitiveLocation(u64),
}

impl fmt::Display for TestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[derive(Clone)]
struct Media {
    page_count: u64,
    pages: BTreeMap<u64, Page>,
    reads: usize,
    writes: usize,
    next_read_error: Option<TestError>,
}

#[derive(Clone)]
struct MemoryDevice(Arc<Mutex<Media>>);

impl MemoryDevice {
    fn blank() -> Self {
        Self(Arc::new(Mutex::new(Media {
            page_count: admitted_pages(SEGMENTS).unwrap(),
            pages: BTreeMap::new(),
            reads: 0,
            writes: 0,
            next_read_error: None,
        })))
    }

    fn from_image(image: BTreeMap<u64, Page>) -> Self {
        Self(Arc::new(Mutex::new(Media {
            page_count: admitted_pages(SEGMENTS).unwrap(),
            pages: image,
            reads: 0,
            writes: 0,
            next_read_error: None,
        })))
    }

    fn image(&self) -> BTreeMap<u64, Page> {
        self.0.lock().unwrap().pages.clone()
    }

    fn reset_io(&self) {
        let mut media = self.0.lock().unwrap();
        media.reads = 0;
        media.writes = 0;
    }

    fn io_counts(&self) -> (usize, usize) {
        let media = self.0.lock().unwrap();
        (media.reads, media.writes)
    }

    fn corrupt(&self, page_no: u64, offset: usize) {
        let mut media = self.0.lock().unwrap();
        let page = media.pages.entry(page_no).or_insert([0; PAGE_SIZE]);
        page[offset] ^= 0x80;
    }

    fn fail_next_read(&self, error: TestError) {
        self.0.lock().unwrap().next_read_error = Some(error);
    }
}

impl PageDevice for MemoryDevice {
    type Error = TestError;

    fn info(&self) -> PageDeviceInfo {
        let page_count = self.0.lock().unwrap().page_count;
        PageDeviceInfo {
            device_id: [0x63; 16],
            range_first_logical_block: 128,
            logical_block_count: page_count * 8,
            logical_block_size: 512,
            page_count,
        }
    }

    async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
        let mut media = self.0.lock().unwrap();
        if page >= media.page_count {
            return Err(TestError::OutsideRange);
        }
        media.reads += 1;
        if let Some(error) = media.next_read_error.take() {
            return Err(error);
        }
        output.fill(0);
        if let Some(stored) = media.pages.get(&page) {
            output.copy_from_slice(stored);
        }
        Ok(())
    }

    async fn write_page(
        &self,
        page: u64,
        input: &Page,
    ) -> Result<(), MutationFailure<Self::Error>> {
        let mut media = self.0.lock().unwrap();
        if page >= media.page_count {
            return Err(MutationFailure::not_submitted(TestError::OutsideRange));
        }
        media.writes += 1;
        media.pages.insert(page, *input);
        Ok(())
    }

    async fn flush(&self) -> Result<(), MutationFailure<Self::Error>> {
        self.0.lock().unwrap().writes += 1;
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

fn uuid() -> StoreUuid {
    StoreUuid::new(*b"M7.6-SCRUB-TEST!").unwrap()
}

fn format(device: MemoryDevice) -> SegmentStore<MemoryDevice> {
    let mut store = SegmentStore::new(device, limits());
    block_on(store.format(FormatOptions {
        store_uuid: uuid(),
        cleaner_reserve_segments: 4,
        limits: limits(),
    }))
    .unwrap();
    store
}

fn mount(device: MemoryDevice) -> SegmentStore<MemoryDevice> {
    let mut store = SegmentStore::new(device, limits());
    block_on(store.mount()).unwrap();
    store
}

fn put(store: &mut SegmentStore<MemoryDevice>, bytes: &[u8]) -> AuthorizedObject<CasObjectHandle> {
    let mut writer = store
        .begin_blob(OBJECT_KIND, bytes.len() as u64, None)
        .unwrap();
    for chunk in bytes.chunks(PAGE_SIZE) {
        block_on(writer.write_chunk(chunk)).unwrap();
    }
    block_on(writer.commit()).unwrap()
}

fn fixture() -> (BTreeMap<u64, Page>, Vec<u8>) {
    let device = MemoryDevice::blank();
    let mut store = format(device.clone());
    let bytes: Vec<u8> = (0..PAGE_SIZE * 2)
        .map(|index| (index.wrapping_mul(37) ^ (index >> 3) ^ 0x5a) as u8)
        .collect();
    let first = put(&mut store, &bytes);
    let _deduplicated = put(&mut store, &bytes);
    block_on(store.synchronize_gc_roots(&[&first])).unwrap();
    (device.image(), bytes)
}

fn image_page(image: &BTreeMap<u64, Page>, page_no: u64) -> Page {
    image.get(&page_no).copied().unwrap_or([0; PAGE_SIZE])
}

fn selected_checkpoint(image: &BTreeMap<u64, Page>) -> Checkpoint {
    [4_u64, 6]
        .into_iter()
        .filter_map(|body_page| {
            match decode_checkpoint(
                &image_page(image, body_page),
                &image_page(image, body_page + 1),
            )
            .unwrap()
            {
                DecodeStatus::Sealed(value) => Some(value),
                DecodeStatus::Empty | DecodeStatus::Unsealed => None,
            }
        })
        .max_by_key(|checkpoint| checkpoint.binding.generation)
        .unwrap()
}

fn pointer_payload(image: &BTreeMap<u64, Page>, pointer: PhysicalPointer) -> Vec<u8> {
    let PhysicalPointer::Value(pointer) = pointer else {
        panic!("expected non-null pointer");
    };
    let first =
        segment_base_page(pointer.segment_no).unwrap() + u64::from(pointer.payload_relative_page);
    let mut output = Vec::new();
    for index in 0..u64::from(pointer.payload_pages) {
        output.extend_from_slice(&image_page(image, first + index));
    }
    output.truncate(pointer.exact_byte_len as usize);
    output
}

fn live_pointers(
    image: &BTreeMap<u64, Page>,
) -> (
    PhysicalPointer,
    PhysicalPointer,
    PhysicalPointer,
    PhysicalPointer,
    PhysicalPointer,
) {
    let checkpoint = selected_checkpoint(image);
    let snapshot = decode_cas_snapshot(
        &pointer_payload(image, checkpoint.catalog_root),
        CasCodecContext::new(
            uuid(),
            checkpoint.admitted_segments,
            checkpoint.next_segment_generation,
        )
        .unwrap(),
    )
    .unwrap();
    let manifest_pointer = snapshot.blobs[0].manifest;
    let manifest = decode_blob_manifest(
        &pointer_payload(image, manifest_pointer),
        CasCodecContext::new(
            uuid(),
            checkpoint.admitted_segments,
            checkpoint.next_segment_generation,
        )
        .unwrap(),
    )
    .unwrap();
    // Canonical split (header / content / tree) or the compact single
    // extent: the content is in the first payload page either way and the
    // tree ends the last payload page either way.
    let (data, tree) = match manifest.extents.len() {
        3 => (manifest.extents[1].pointer, manifest.extents[2].pointer),
        1 => (manifest.extents[0].pointer, manifest.extents[0].pointer),
        other => panic!("unexpected manifest layout with {other} extents"),
    };
    (
        checkpoint.catalog_root,
        data,
        tree,
        checkpoint.authority_root,
        checkpoint.allocation_root,
    )
}

fn payload_first_page(pointer: PhysicalPointer) -> u64 {
    let PhysicalPointer::Value(pointer) = pointer else {
        panic!("expected non-null pointer");
    };
    segment_base_page(pointer.segment_no).unwrap() + u64::from(pointer.payload_relative_page)
}

fn payload_last_page(pointer: PhysicalPointer) -> u64 {
    let PhysicalPointer::Value(pointer) = pointer else {
        panic!("expected non-null pointer");
    };
    payload_first_page(PhysicalPointer::Value(pointer)) + u64::from(pointer.payload_pages.max(1)) - 1
}

fn segment_summary_page(pointer: PhysicalPointer) -> u64 {
    let PhysicalPointer::Value(pointer) = pointer else {
        panic!("expected non-null pointer");
    };
    segment_base_page(pointer.segment_no).unwrap() + u64::from(SUMMARY_BODY_PAGE)
}

fn stale_extent_in_state(
    image: &BTreeMap<u64, Page>,
    store: &SegmentStore<MemoryDevice>,
    allocation_state: SegmentAllocation,
) -> (u64, usize, u64) {
    let oldest_checkpoint_generation = [4_u64, 6]
        .into_iter()
        .filter_map(|body_page| {
            match decode_checkpoint(
                &image_page(image, body_page),
                &image_page(image, body_page + 1),
            )
            .unwrap()
            {
                DecodeStatus::Sealed(value) => Some(value.binding.generation),
                DecodeStatus::Empty | DecodeStatus::Unsealed => None,
            }
        })
        .min()
        .unwrap();
    let state = store.mounted.as_ref().unwrap();
    for segment_no in 1..state.admitted_segments {
        if state.allocation.segment_state(segment_no) != Some(allocation_state) {
            continue;
        }
        let base = segment_base_page(segment_no).unwrap();
        let header =
            match decode_segment_header(&image_page(image, base), &image_page(image, base + 1))
                .unwrap()
            {
                DecodeStatus::Sealed(value) => value,
                DecodeStatus::Empty | DecodeStatus::Unsealed => continue,
            };
        let summary = match decode_segment_summary(
            &image_page(image, base + u64::from(SUMMARY_BODY_PAGE)),
            &image_page(image, base + u64::from(SUMMARY_SEAL_PAGE)),
        )
        .unwrap()
        {
            DecodeStatus::Sealed(value) => value,
            DecodeStatus::Empty | DecodeStatus::Unsealed => continue,
        };
        let mut relative = DATA_FIRST_PAGE;
        for _ in 0..summary.record_count {
            let descriptor = base + u64::from(relative);
            let extent = match decode_extent(
                &image_page(image, descriptor),
                &image_page(image, descriptor + 1),
            )
            .unwrap()
            {
                DecodeStatus::Sealed(value) => value,
                DecodeStatus::Empty | DecodeStatus::Unsealed => break,
            };
            if extent.extent_kind == ExtentKind::Allocation
                && extent.binding.generation == header.binding.generation
                && extent.binding.target_checkpoint_generation < oldest_checkpoint_generation
            {
                let used = usize::try_from(extent.payload_byte_len).unwrap();
                assert!(used < PAGE_SIZE, "fixture needs one padded stale extent");
                return (
                    base + u64::from(extent.payload_first_relative_page),
                    used,
                    segment_no,
                );
            }
            relative += extent.record_span_pages;
        }
    }
    panic!("fixture must retain an extent in {allocation_state:?} older than both checkpoints")
}

#[test]
fn scrub_closure_memo_is_bounded_and_reduces_packed_graph_reads() {
    let device = MemoryDevice::blank();
    let mut store = format(device.clone());
    let mut batch = store.begin_staged_batch().unwrap();
    for seed in 0..4_u8 {
        let (object_id, commit_generation) = block_on(store.stage_blob_in_batch(
            &mut batch, OBJECT_KIND, crate::cas_codec::REFERENCE_CODEC_RAW,
            &[seed; PAGE_SIZE])).unwrap();
        let refs = TypedManifestRefsV1::new(TYPED_KIND, commit_generation,
            Vec::from([TypedObjectReference { object_id, commit_generation,
                object_kind: OBJECT_KIND }])).unwrap();
        let bytes = encode_typed_manifest_refs_v1(&refs).unwrap();
        block_on(store.stage_blob_in_batch(&mut batch, TYPED_KIND,
            REFERENCE_CODEC_TYPED_V1, &bytes)).unwrap();
    }
    let _objects = block_on(store.publish_staged_batch(batch)).unwrap();
    let state = store.mounted.as_ref().unwrap();
    device.reset_io();
    let cached = block_on(crate::scrub::verify_closure_for_test(
        &device, state, limits(), &[TYPED_KIND])).unwrap();
    let cached_reads = device.io_counts().0;
    assert_eq!(cached.status, ScrubStatus::Healthy);
    let mut small = limits();
    small.recovery_memory_bytes = 64 * 1024;
    device.reset_io();
    let plain = block_on(crate::scrub::verify_closure_for_test(
        &device, state, small, &[TYPED_KIND])).unwrap();
    assert!(cached_reads < device.io_counts().0);
    assert_eq!(plain.status, ScrubStatus::Healthy);
    assert!(plain.scrub_memory_high_water_bytes < small.recovery_memory_bytes);
    let mut normalized = cached;
    normalized.scrub_memory_high_water_bytes = plain.scrub_memory_high_water_bytes;
    assert_eq!(normalized, plain);
    small.recovery_memory_bytes = cached.scrub_memory_high_water_bytes - 1;
    let fallback = block_on(crate::scrub::verify_closure_for_test(
        &device, state, small, &[TYPED_KIND])).unwrap();
    assert_eq!(fallback.status, ScrubStatus::Healthy);
    assert!(fallback.scrub_memory_high_water_bytes <= small.recovery_memory_bytes);
    // Reject before graph allocation when even the retained roots do not fit.
    small.recovery_memory_bytes = state.resident_heap_bytes().unwrap()
        + 4 * core::mem::size_of::<crate::mark::MarkRoot>() - 1;
    assert!(matches!(block_on(crate::scrub::verify_closure_for_test(
        &device, state, small, &[TYPED_KIND])), Err(ScrubError::MemoryLimit)));
    assert_eq!(device.io_counts().1, 0);
}

#[test]
fn scrub_content_memo_reduces_reads_without_changing_health_or_budget_admission() {
    let device = MemoryDevice::blank();
    let mut store = format(device.clone());
    let mut batch = store.begin_staged_batch().unwrap();
    for seed in 0..8_u8 {
        block_on(store.stage_blob_in_batch(&mut batch, OBJECT_KIND,
            crate::cas_codec::REFERENCE_CODEC_RAW, &[seed; PAGE_SIZE])).unwrap();
    }
    let _objects = block_on(store.publish_staged_batch(batch)).unwrap();
    let state = store.mounted.as_ref().unwrap();
    device.reset_io();
    let plain = block_on(crate::scrub::verify_contents_for_test(
        &device, state, limits().recovery_memory_bytes, false)).unwrap();
    let plain_reads = device.io_counts().0;
    device.reset_io();
    let cached = block_on(crate::scrub::verify_contents_for_test(
        &device, state, limits().recovery_memory_bytes, true)).unwrap();
    assert!(device.io_counts().0 < plain_reads);
    assert_eq!(device.io_counts().1, 0);
    let mut normalized = cached;
    normalized.scrub_memory_high_water_bytes = plain.scrub_memory_high_water_bytes;
    assert_eq!(normalized, plain);
    assert_eq!(cached.status, ScrubStatus::Healthy);
    let tight = cached.scrub_memory_high_water_bytes - 1;
    let fallback = block_on(crate::scrub::verify_contents_for_test(
        &device, state, tight, true)).unwrap();
    assert_eq!(fallback.status, ScrubStatus::Healthy);
    assert!(fallback.scrub_memory_high_water_bytes <= tight);
    assert!(matches!(block_on(crate::scrub::verify_contents_for_test(
        &device, state, plain.scrub_memory_high_water_bytes - 1, true)),
        Err(ScrubError::MemoryLimit)));
    assert_eq!(device.io_counts().1, 0);
}

#[test]
fn scrub_checkpoint_memo_reduces_reads_and_falls_back_under_tight_budget() {
    let (image, _) = fixture();
    let device = MemoryDevice::from_image(image);
    let store = mount(device.clone());
    let state = store.mounted.as_ref().unwrap();
    let checkpoint = [4, 6].into_iter()
        .filter_map(|page| block_on(crate::store::read_checkpoint(&device, page)).unwrap())
        .max_by_key(|record| record.value().binding.generation).unwrap();
    device.reset_io();
    let plain = block_on(crate::store::recover_state(
        &device, state.superblock, checkpoint, limits())).unwrap();
    let plain_reads = device.io_counts().0;
    device.reset_io();
    let cached = block_on(crate::store::recover_state_for_scrub(
        &device, state.superblock, checkpoint, limits())).unwrap();
    assert!(device.io_counts().0 < plain_reads);
    assert_eq!(device.io_counts().1, 0);
    assert_eq!(cached.generation, plain.generation);
    assert_eq!(cached.catalog, plain.catalog);
    let mut tight = limits();
    tight.recovery_memory_bytes = 64 * 1024 + plain.recovery_peak_bytes / 2;
    // Ensure the memo is attempted, but leaves too little mandatory scratch.
    assert!(tight.recovery_memory_bytes >= 64 * 1024);
    device.reset_io();
    let fallback = block_on(crate::store::recover_state_for_scrub(
        &device, state.superblock, checkpoint, tight)).unwrap();
    assert_eq!(fallback.recovery_peak_bytes, tight.recovery_memory_bytes);
    assert_eq!(fallback.generation, plain.generation);
    assert_eq!(fallback.catalog, plain.catalog);
    assert_eq!(device.io_counts().1, 0);
}

#[test]
fn healthy_scrub_is_bounded_anonymous_read_only_and_verifies_fallback() {
    let (image, bytes) = fixture();
    let device = MemoryDevice::from_image(image);
    let store = mount(device.clone());
    let maintenance = store
        .mint_maintenance_root()
        .unwrap()
        .attenuate(&[MaintenanceOperation::Scrub])
        .unwrap();
    device.reset_io();

    let report = block_on(store.scrub(&maintenance)).unwrap();

    assert_eq!(report.status, ScrubStatus::Healthy);
    assert_eq!(report.verified_checkpoint_copies, 2);
    assert!(report.checkpoint_fallback_verified);
    assert_eq!(report.live_objects, 2);
    assert_eq!(report.unique_blobs, 1);
    assert_eq!(report.logical_live_bytes, (bytes.len() * 2) as u64);
    assert_eq!(report.unique_blob_bytes, bytes.len() as u64);
    assert_eq!(report.deduplicated_bytes_saved, bytes.len() as u64);
    assert_eq!(
        report.verified_segments,
        report.allocated_segments + report.retired_segments,
        "fallback verification must not double-count selected segments"
    );
    assert!(report.verified_record_pairs >= report.verified_segments * 3);
    assert!(report.verified_payload_bytes > 0);
    assert!(report.physical_high_water_ppm <= 1_000_000);
    assert!(report.gc_pressure_ppm <= 1_000_000);
    assert_eq!(report.device_io_failures, 0);
    assert!(report.scrub_memory_high_water_bytes <= limits().recovery_memory_bytes);
    assert!(device.io_counts().0 > 0);
    assert_eq!(device.io_counts().1, 0, "scrub must never write or flush");
    assert!(core::mem::size_of_val(&report) <= 192);
}

#[test]
fn persistent_typed_authority_closure_uses_the_trusted_runtime_policy() {
    let device = MemoryDevice::blank();
    let runtime = StoreRuntimeContext::with_typed_reference_kinds(&[TYPED_KIND]).unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(store.format(FormatOptions {
        store_uuid: uuid(),
        cleaner_reserve_segments: 4,
        limits: limits(),
    }))
    .unwrap();
    let child = put(&mut store, b"durable child");
    let parent = block_on(store.commit_typed_manifest(TYPED_KIND, &[&child])).unwrap();
    block_on(store.synchronize_gc_roots(&[&parent])).unwrap();
    let maintenance = store
        .mint_maintenance_root()
        .unwrap()
        .attenuate(&[MaintenanceOperation::Scrub])
        .unwrap();
    device.reset_io();

    let report = block_on(store.scrub(&maintenance)).unwrap();

    assert_eq!(report.status, ScrubStatus::Healthy);
    assert_eq!(report.live_objects, 2);
    assert_eq!(report.unique_blobs, 2);
    assert!(report.scrub_memory_high_water_bytes <= limits().recovery_memory_bytes);
    assert_eq!(device.io_counts().1, 0);

    let cached_reads = device.io_counts().0;

    // Force uncached recovery: the current resident state leaves less than
    // 64 KiB for candidates. Optional memo reservations are not a mandatory
    // scrub-memory minimum, so derive the exact scratch boundary here.
    let mut uncached_limits = limits();
    uncached_limits.recovery_memory_bytes = 64 * 1024;
    let uncached_device = MemoryDevice::from_image(device.image());
    let mut uncached = SegmentStore::new_with_runtime_context(
        uncached_device.clone(),
        uncached_limits,
        StoreRuntimeContext::with_typed_reference_kinds(&[TYPED_KIND]).unwrap(),
    );
    block_on(uncached.mount()).unwrap();
    let uncached_maintenance = uncached.mint_maintenance_root().unwrap()
        .attenuate(&[MaintenanceOperation::Scrub]).unwrap();
    uncached_device.reset_io();
    let uncached_report = block_on(uncached.scrub(&uncached_maintenance)).unwrap();
    assert!(cached_reads < uncached_device.io_counts().0);
    assert_eq!(uncached_device.io_counts().1, 0);
    assert_eq!(uncached_report.status, ScrubStatus::Healthy);
    assert!(uncached_report.scrub_memory_high_water_bytes < 64 * 1024);

    let mut exact_below = limits();
    exact_below.recovery_memory_bytes = uncached_report.scrub_memory_high_water_bytes - 1;
    let cold_device = MemoryDevice::from_image(device.image());
    let mut cold = SegmentStore::new_with_runtime_context(
        cold_device,
        exact_below,
        StoreRuntimeContext::with_typed_reference_kinds(&[TYPED_KIND]).unwrap(),
    );
    block_on(cold.mount()).expect("cold recovery itself must fit below scrub's aggregate peak");
    let cold_maintenance = cold
        .mint_maintenance_root()
        .unwrap()
        .attenuate(&[MaintenanceOperation::Scrub])
        .unwrap();
    assert!(matches!(
        block_on(cold.scrub(&cold_maintenance)),
        Err(ScrubError::MemoryLimit)
    ));
}

#[test]
fn runtime_only_policy_admitted_typed_objects_are_semantically_scrubbed() {
    let device = MemoryDevice::blank();
    let runtime = StoreRuntimeContext::with_typed_reference_kinds(&[TYPED_KIND]).unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(store.format(FormatOptions {
        store_uuid: uuid(),
        cleaner_reserve_segments: 4,
        limits: limits(),
    }))
    .unwrap();
    let malformed = b"authenticated Blob bytes, but not canonical refs-v1";
    let mut writer = store
        .begin_blob_with_reference_codec(
            TYPED_KIND,
            malformed.len() as u64,
            None,
            REFERENCE_CODEC_TYPED_V1,
        )
        .unwrap();
    block_on(writer.write_chunk(malformed)).unwrap();
    let _runtime_only = block_on(writer.commit()).unwrap();
    assert_eq!(
        store.mounted.as_ref().unwrap().authority_root,
        PhysicalPointer::Null
    );
    let maintenance = store
        .mint_maintenance_root()
        .unwrap()
        .attenuate(&[MaintenanceOperation::Scrub])
        .unwrap();
    device.reset_io();

    let report = block_on(store.scrub(&maintenance)).unwrap();

    assert_eq!(report.status, ScrubStatus::Corrupt);
    assert_eq!(
        report.corruption_domain,
        Some(ScrubCorruptionDomain::AuthorityGraph)
    );
    assert_eq!(device.io_counts().1, 0);
}

#[test]
fn runtime_only_policy_admitted_typed_objects_reject_dangling_children() {
    let device = MemoryDevice::blank();
    let runtime = StoreRuntimeContext::with_typed_reference_kinds(&[TYPED_KIND]).unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(store.format(FormatOptions {
        store_uuid: uuid(),
        cleaner_reserve_segments: 4,
        limits: limits(),
    }))
    .unwrap();
    let commit_generation = store.info().unwrap().generation + 1;
    let payload = encode_typed_manifest_refs_v1(
        &TypedManifestRefsV1::new(
            TYPED_KIND,
            commit_generation,
            Vec::from([TypedObjectReference {
                object_id: u128::from(commit_generation) + 10_000,
                commit_generation,
                object_kind: OBJECT_KIND,
            }]),
        )
        .unwrap(),
    )
    .unwrap();
    let mut writer = store
        .begin_blob_with_reference_codec(
            TYPED_KIND,
            payload.len() as u64,
            None,
            REFERENCE_CODEC_TYPED_V1,
        )
        .unwrap();
    block_on(writer.write_chunk(&payload)).unwrap();
    let _runtime_only = block_on(writer.commit()).unwrap();
    assert_eq!(
        store.mounted.as_ref().unwrap().authority_root,
        PhysicalPointer::Null
    );
    let maintenance = store
        .mint_maintenance_root()
        .unwrap()
        .attenuate(&[MaintenanceOperation::Scrub])
        .unwrap();
    device.reset_io();

    let report = block_on(store.scrub(&maintenance)).unwrap();

    assert_eq!(report.status, ScrubStatus::Corrupt);
    assert_eq!(
        report.corruption_domain,
        Some(ScrubCorruptionDomain::AuthorityGraph)
    );
    assert_eq!(device.io_counts().1, 0);
}

#[test]
fn allocated_stale_extent_payload_and_padding_are_not_skipped() {
    let (image, _) = fixture();
    let probe = mount(MemoryDevice::from_image(image.clone()));
    let (payload_page, used, segment_no) =
        stale_extent_in_state(&image, &probe, SegmentAllocation::Allocated);
    assert_eq!(
        probe
            .mounted
            .as_ref()
            .unwrap()
            .allocation
            .segment_state(segment_no),
        Some(SegmentAllocation::Allocated)
    );

    for offset in [17, used] {
        let device = MemoryDevice::from_image(image.clone());
        let store = mount(device.clone());
        let maintenance = store
            .mint_maintenance_root()
            .unwrap()
            .attenuate(&[MaintenanceOperation::Scrub])
            .unwrap();
        device.corrupt(payload_page, offset);
        device.reset_io();

        let report = block_on(store.scrub(&maintenance)).unwrap();

        assert_eq!(report.status, ScrubStatus::Corrupt, "offset {offset}");
        assert_eq!(
            report.corruption_domain,
            Some(ScrubCorruptionDomain::SegmentMetadata),
            "offset {offset}"
        );
        assert_eq!(device.io_counts().1, 0, "offset {offset}");
    }
}

#[test]
fn retired_extent_payload_and_padding_are_not_skipped() {
    let device = MemoryDevice::blank();
    let mut store = format(device.clone());
    let bytes: Vec<u8> = (0..PAGE_SIZE * 2)
        .map(|index| (index.wrapping_mul(29) ^ (index >> 2) ^ 0xa7) as u8)
        .collect();
    let retained = put(&mut store, &bytes);
    block_on(store.synchronize_gc_roots(&[&retained])).unwrap();
    let key = retained.backend_handle().root_key(&store.pins).unwrap();
    let pinned_generation = store.info().unwrap().generation;
    let owner = store.pins.allocate_owner().unwrap();
    let reader = PinRegistry::pin_object_reader_owned(
        &store.pins,
        key,
        pinned_generation,
        owner,
        PinAdmission::Ordinary,
    )
    .unwrap();
    let reader = reader.finish_recheck(key, pinned_generation).unwrap();

    assert!(matches!(
        block_on(store.collect_garbage()),
        Err(crate::gc::GcStoreError::Gc(
            crate::gc::GcError::ReaderStillPinned
        ))
    ));
    assert!(!store
        .mounted
        .as_ref()
        .unwrap()
        .allocation
        .retired_segments()
        .is_empty());
    let image = device.image();
    let (payload_page, used, segment_no) =
        stale_extent_in_state(&image, &store, SegmentAllocation::Retired);
    assert_eq!(
        store
            .mounted
            .as_ref()
            .unwrap()
            .allocation
            .segment_state(segment_no),
        Some(SegmentAllocation::Retired)
    );

    for offset in [17, used] {
        let device = MemoryDevice::from_image(image.clone());
        let store = mount(device.clone());
        let maintenance = store
            .mint_maintenance_root()
            .unwrap()
            .attenuate(&[MaintenanceOperation::Scrub])
            .unwrap();
        device.corrupt(payload_page, offset);
        let corrupted_image = device.image();
        device.reset_io();

        let report = block_on(store.scrub(&maintenance)).unwrap();

        assert_eq!(report.status, ScrubStatus::Corrupt);
        assert_eq!(
            report.corruption_domain,
            Some(ScrubCorruptionDomain::SegmentMetadata)
        );
        assert_eq!(device.io_counts().1, 0);
        assert_eq!(device.image(), corrupted_image);
    }

    drop(reader);
}

#[test]
fn scrub_rejects_valid_but_incomplete_current_mapping_against_recovered_checkpoint() {
    let (image, _) = fixture();
    let device = MemoryDevice::from_image(image);
    let mut store = mount(device.clone());
    let cas = store.mounted.as_mut().unwrap().cas.as_mut().unwrap();
    assert_eq!(cas.objects.len(), 2);
    assert_eq!(cas.blobs.len(), 1);
    // Both objects deduplicate to the same valid Blob. Removing the second
    // leaves a closed, content-valid graph, but not the durable publication.
    cas.objects.pop();
    assert!(crate::scrub::cas_mappings_are_closed(&cas.objects, &cas.blobs));
    let maintenance = store.mint_maintenance_root().unwrap()
        .attenuate(&[MaintenanceOperation::Scrub]).unwrap();
    device.reset_io();
    let report = block_on(store.scrub(&maintenance)).unwrap();
    assert_eq!(report.status, ScrubStatus::Corrupt);
    assert_eq!(report.corruption_domain, Some(ScrubCorruptionDomain::AllocationOrMapping));
    assert_eq!(device.io_counts().1, 0);
}

#[test]
fn object_blob_mapping_closure_rejects_orphan_blob_mappings() {
    let (image, _) = fixture();
    let store = mount(MemoryDevice::from_image(image));
    let cas = store.mounted.as_ref().unwrap().cas.as_ref().unwrap();
    assert!(crate::scrub::cas_mappings_are_closed(
        &cas.objects,
        &cas.blobs
    ));
    assert!(!cas.blobs.is_empty());
    assert!(!crate::scrub::cas_mappings_are_closed(&[], &cas.blobs));
}

#[test]
fn wrong_operation_and_cross_store_authority_are_rejected_before_io() {
    let (image, _) = fixture();
    let device = MemoryDevice::from_image(image);
    let store = mount(device.clone());
    let grow_only = store
        .mint_maintenance_root()
        .unwrap()
        .attenuate(&[MaintenanceOperation::Grow])
        .unwrap();
    device.reset_io();
    assert!(matches!(
        block_on(store.scrub(&grow_only)),
        Err(ScrubError::Unauthorized)
    ));
    assert_eq!(device.io_counts(), (0, 0));

    let foreign_device = MemoryDevice::blank();
    let foreign = format(foreign_device);
    let foreign_scrub = foreign
        .mint_maintenance_root()
        .unwrap()
        .attenuate(&[MaintenanceOperation::Scrub])
        .unwrap();
    device.reset_io();
    assert!(matches!(
        block_on(store.scrub(&foreign_scrub)),
        Err(ScrubError::Unauthorized)
    ));
    assert_eq!(device.io_counts(), (0, 0));
}

#[test]
fn device_failures_return_only_a_fixed_anonymous_error() {
    let (image, _) = fixture();
    let device = MemoryDevice::from_image(image);
    let store = mount(device.clone());
    let maintenance = store
        .mint_maintenance_root()
        .unwrap()
        .attenuate(&[MaintenanceOperation::Scrub])
        .unwrap();
    device.reset_io();
    device.fail_next_read(TestError::SensitiveLocation(0xdead_beef));

    let error = block_on(store.scrub(&maintenance)).unwrap_err();

    assert_eq!(error, ScrubError::DeviceUnavailable { failures: 1 });
    assert_eq!(format!("{error}"), "Storage V2 scrub device is unavailable");
    let debug = format!("{error:?}");
    assert!(!debug.contains("dead"));
    assert!(!debug.contains("beef"));
    assert_eq!(device.io_counts().1, 0);
}

#[derive(Clone, Copy, Debug)]
enum CorruptionCase {
    SuperblockLeftMalformed,
    SuperblockRightMalformed,
    SuperblockLeftUnsealed,
    SuperblockRightUnsealed,
    Data,
    Tree,
    Padding,
    Summary,
    Mapping,
    Authority,
    Allocation,
    CheckpointLeft,
    CheckpointRight,
}

#[test]
fn sealed_impossible_summary_counts_fail_before_extent_table_allocation() {
    let (image, _) = fixture();
    let (_, data, _, _, _) = live_pointers(&image);
    let summary_page = segment_summary_page(data);
    let original = match decode_segment_summary(&image_page(&image, summary_page),
        &image_page(&image, summary_page + 1)).unwrap() {
        DecodeStatus::Sealed(value) => value,
        _ => panic!("sealed fixture summary"),
    };
    for case in 0..3 {
        let device = MemoryDevice::from_image(image.clone());
        let store = mount(device.clone());
        let mut summary = original;
        match case {
            0 => {
                summary.record_count = u32::MAX - 1;
                summary.binding.ordinal = u32::MAX;
                summary.kind_counts = [u32::MAX - 1, 0, 0, 0, 0];
            }
            1 => summary.payload_page_count = summary.record_count - 1,
            _ => summary.next_free_page += 1,
        }
        let mut body = [0; PAGE_SIZE];
        let mut seal = [0; PAGE_SIZE];
        let digest = vibeos_segment_format::encode_segment_summary_body(&summary, &mut body).unwrap();
        vibeos_segment_format::encode_record_seal(digest, &mut seal).unwrap();
        assert!(matches!(decode_segment_summary(&body, &seal).unwrap(), DecodeStatus::Sealed(_)));
        {
            let mut media = device.0.lock().unwrap();
            media.pages.insert(summary_page, body);
            media.pages.insert(summary_page + 1, seal);
        }
        let damaged = device.image();
        let maintenance = store.mint_maintenance_root().unwrap()
            .attenuate(&[MaintenanceOperation::Scrub]).unwrap();
        device.reset_io();
        let report = block_on(store.scrub(&maintenance)).unwrap();
        assert_eq!(report.status, ScrubStatus::Corrupt, "case {case}");
        assert_eq!(report.corruption_domain, Some(ScrubCorruptionDomain::SegmentMetadata));
        assert_eq!(device.io_counts().1, 0);
        assert_eq!(device.image(), damaged);
    }
}

#[test]
fn detects_anchor_data_tree_summary_mapping_authority_and_allocation_corruption_without_repair() {
    let (image, _) = fixture();
    let (mapping, data, tree, authority, allocation) = live_pointers(&image);
    for case in [
        CorruptionCase::SuperblockLeftMalformed,
        CorruptionCase::SuperblockRightMalformed,
        CorruptionCase::SuperblockLeftUnsealed,
        CorruptionCase::SuperblockRightUnsealed,
        CorruptionCase::Data,
        CorruptionCase::Tree,
        CorruptionCase::Padding,
        CorruptionCase::Summary,
        CorruptionCase::Mapping,
        CorruptionCase::Authority,
        CorruptionCase::Allocation,
        CorruptionCase::CheckpointLeft,
        CorruptionCase::CheckpointRight,
    ] {
        let device = MemoryDevice::from_image(image.clone());
        let store = mount(device.clone());
        let maintenance = store
            .mint_maintenance_root()
            .unwrap()
            .attenuate(&[MaintenanceOperation::Scrub])
            .unwrap();
        let (page, offset) = match case {
            CorruptionCase::SuperblockLeftMalformed => (0, 0x80),
            CorruptionCase::SuperblockRightMalformed => (2, 0x80),
            CorruptionCase::SuperblockLeftUnsealed => (1, PAGE_SIZE - 1),
            CorruptionCase::SuperblockRightUnsealed => (3, PAGE_SIZE - 1),
            CorruptionCase::Data => (payload_first_page(data), 17),
            CorruptionCase::Tree => (payload_last_page(tree), 7),
            CorruptionCase::Padding => (payload_last_page(tree), PAGE_SIZE - 1),
            CorruptionCase::Summary => (segment_summary_page(data), 0x90),
            CorruptionCase::Mapping => (payload_first_page(mapping), 0x88),
            CorruptionCase::Authority => (payload_first_page(authority), 0x18),
            CorruptionCase::Allocation => (payload_first_page(allocation), 0x20),
            CorruptionCase::CheckpointLeft => (4, 0x80),
            CorruptionCase::CheckpointRight => (6, 0x80),
        };
        // A previous successful scrub must not hide subsequent media damage.
        assert_eq!(block_on(store.scrub(&maintenance)).unwrap().status, ScrubStatus::Healthy);
        device.corrupt(page, offset);
        let corrupted_image = device.image();
        device.reset_io();

        let report = block_on(store.scrub(&maintenance)).unwrap();

        assert_eq!(report.status, ScrubStatus::Corrupt, "case {case:?}");
        assert!(report.corruption_signals > 0, "case {case:?}");
        if matches!(case, CorruptionCase::Authority) {
            assert!(matches!(
                report.corruption_domain,
                Some(
                    ScrubCorruptionDomain::AuthorityGraph | ScrubCorruptionDomain::SegmentMetadata
                )
            ));
        }
        if matches!(
            case,
            CorruptionCase::SuperblockLeftMalformed
                | CorruptionCase::SuperblockRightMalformed
                | CorruptionCase::SuperblockLeftUnsealed
                | CorruptionCase::SuperblockRightUnsealed
                | CorruptionCase::CheckpointLeft
                | CorruptionCase::CheckpointRight
        ) {
            assert_eq!(
                report.corruption_domain,
                Some(ScrubCorruptionDomain::Anchor)
            );
        }
        assert!(
            matches!(
                report.corruption_domain,
                Some(
                    ScrubCorruptionDomain::Anchor
                        | ScrubCorruptionDomain::SegmentMetadata
                        | ScrubCorruptionDomain::AllocationOrMapping
                        | ScrubCorruptionDomain::BlobDataOrTree
                        | ScrubCorruptionDomain::AuthorityGraph
                )
            ),
            "case {case:?}"
        );
        assert_eq!(device.io_counts().1, 0, "case {case:?} wrote media");
        assert_eq!(
            device.image(),
            corrupted_image,
            "case {case:?} repaired media"
        );
    }
}

#[test]
fn segment_probe_workspace_is_admitted_before_device_io() {
    let (image, _) = fixture();
    let device = MemoryDevice::from_image(image);
    let mut store = mount(device.clone());
    let maintenance = store.mint_maintenance_root().unwrap()
        .attenuate(&[MaintenanceOperation::Scrub]).unwrap();
    let peak = store.mounted.as_ref().unwrap().resident_heap_bytes().unwrap()
        + crate::store::SEGMENT_PROBE_PAGE_WORKSPACE_BYTES;
    store.limits.recovery_memory_bytes = peak - 1;
    device.reset_io();
    device.fail_next_read(TestError::SensitiveLocation(0xdead_beef));
    assert_eq!(block_on(store.scrub(&maintenance)), Err(ScrubError::MemoryLimit));
    assert_eq!(device.io_counts(), (0, 0));

    store.limits.recovery_memory_bytes = peak;
    assert_eq!(block_on(store.scrub(&maintenance)),
        Err(ScrubError::DeviceUnavailable { failures: 1 }));
    assert_eq!(device.io_counts(), (1, 0));
}
