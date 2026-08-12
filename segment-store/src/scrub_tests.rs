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
    assert_eq!(manifest.extents.len(), 3);
    (
        checkpoint.catalog_root,
        manifest.extents[1].pointer,
        manifest.extents[2].pointer,
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
    assert!(
        report.scrub_memory_high_water_bytes > store.info().unwrap().recovery_peak_bytes,
        "typed mark scratch must be included in scrub's aggregate high-water"
    );
    assert_eq!(device.io_counts().1, 0);

    let mut exact_below = limits();
    exact_below.recovery_memory_bytes = report.scrub_memory_high_water_bytes - 1;
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
            CorruptionCase::Tree => (payload_first_page(tree), 7),
            CorruptionCase::Padding => (payload_first_page(tree), PAGE_SIZE - 1),
            CorruptionCase::Summary => (segment_summary_page(data), 0x90),
            CorruptionCase::Mapping => (payload_first_page(mapping), 0x88),
            CorruptionCase::Authority => (payload_first_page(authority), 0x18),
            CorruptionCase::Allocation => (payload_first_page(allocation), 0x20),
            CorruptionCase::CheckpointLeft => (4, 0x80),
            CorruptionCase::CheckpointRight => (6, 0x80),
        };
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
