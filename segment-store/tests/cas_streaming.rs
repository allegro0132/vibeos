use core::future::{pending, Future};
use core::pin::Pin;
use core::task::{Context, Poll};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::task::Waker;
use std::time::{SystemTime, UNIX_EPOCH};

use vibeos_segment_format::{admitted_pages, Page, StoreUuid, PAGE_SIZE};
use vibeos_segment_store::{
    resolve_authorized, AuthorizedObject, AuthorizedObjectSpace, AuthorizedPublication,
    CasObjectHandle, CasStoreError, FormatOptions, ObjectPublicationPersistence,
    ObjectPublicationTarget, PageDevice, PageDeviceInfo, PublicationIntent, PublishError,
    SegmentStore, StoreError, StoreInfo, StoreLimits, StoreRuntimeContext,
};
use vibeos_storage_device::MutationFailure;

const OBJECT_KIND: u32 = 0x424c_4f42;

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut Context::from_waker(waker)) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Effect {
    None,
    Visible,
    Durable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultAction {
    Normal,
    FailNotSubmitted,
    FailAmbiguous(Effect),
    Pending(Effect),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FaultPlan {
    mutation_index: usize,
    action: FaultAction,
}

#[derive(Clone)]
struct Media {
    page_count: u64,
    durable: BTreeMap<u64, Page>,
    visible: BTreeMap<u64, Page>,
    read_count: usize,
    read_pages: BTreeMap<u64, usize>,
    mutation_count: usize,
    fault: Option<FaultPlan>,
}

#[derive(Clone)]
struct FaultDevice(Arc<Mutex<Media>>);

impl FaultDevice {
    fn blank(segment_count: u64) -> Self {
        Self::from_durable(
            admitted_pages(segment_count).expect("test geometry must fit"),
            BTreeMap::new(),
        )
    }

    fn from_durable(page_count: u64, durable: BTreeMap<u64, Page>) -> Self {
        Self(Arc::new(Mutex::new(Media {
            page_count,
            visible: durable.clone(),
            durable,
            read_count: 0,
            read_pages: BTreeMap::new(),
            mutation_count: 0,
            fault: None,
        })))
    }

    fn durable_image(&self) -> BTreeMap<u64, Page> {
        self.0.lock().unwrap().durable.clone()
    }

    fn page_count(&self) -> u64 {
        self.0.lock().unwrap().page_count
    }

    fn reset_mutation_count(&self) {
        self.0.lock().unwrap().mutation_count = 0;
    }

    fn mutation_count(&self) -> usize {
        self.0.lock().unwrap().mutation_count
    }

    fn reset_reads(&self) {
        let mut media = self.0.lock().unwrap();
        media.read_count = 0;
        media.read_pages.clear();
    }

    fn read_count(&self) -> usize {
        self.0.lock().unwrap().read_count
    }

    fn distinct_read_pages(&self) -> usize {
        self.0.lock().unwrap().read_pages.len()
    }

    fn arm(&self, mutation_index: usize, action: FaultAction) {
        let mut media = self.0.lock().unwrap();
        media.mutation_count = 0;
        media.fault = Some(FaultPlan {
            mutation_index,
            action,
        });
    }

    fn power_cycle(&self) {
        let mut media = self.0.lock().unwrap();
        media.visible = media.durable.clone();
        media.read_count = 0;
        media.read_pages.clear();
        media.mutation_count = 0;
        media.fault = None;
    }

    fn next_action(&self) -> FaultAction {
        let mut media = self.0.lock().unwrap();
        let index = media.mutation_count;
        media.mutation_count += 1;
        media
            .fault
            .filter(|plan| plan.mutation_index == index)
            .map_or(FaultAction::Normal, |plan| plan.action)
    }

    fn write_effect(&self, page: u64, bytes: Page, effect: Effect) {
        let mut media = self.0.lock().unwrap();
        if !matches!(effect, Effect::None) {
            media.visible.insert(page, bytes);
        }
        if matches!(effect, Effect::Durable) {
            media.durable.insert(page, bytes);
        }
    }

    fn flush_effect(&self, effect: Effect) {
        if matches!(effect, Effect::Durable) {
            let mut media = self.0.lock().unwrap();
            media.durable = media.visible.clone();
        }
    }

    fn write_raw_image(&self, path: &Path) {
        let media = self.0.lock().unwrap();
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .expect("raw image must be created");
        file.set_len(media.page_count * PAGE_SIZE as u64)
            .expect("raw image length must be set");
        for (page_no, page) in &media.durable {
            file.seek(SeekFrom::Start(*page_no * PAGE_SIZE as u64))
                .expect("raw image seek must succeed");
            file.write_all(page)
                .expect("raw image page write must succeed");
        }
        file.flush().expect("raw image flush must succeed");
    }

    fn flip_durable_page_with_prefix(&self, prefix: &[u8], byte_offset: usize) {
        let mut media = self.0.lock().unwrap();
        let page_no = media
            .durable
            .iter()
            .find(|(_, page)| page.starts_with(prefix))
            .map(|(page_no, _)| *page_no)
            .expect("expected canonical Blob page was not found");
        let page = media.durable.get_mut(&page_no).unwrap();
        page[byte_offset] ^= 0x80;
        let page = *page;
        media.visible.insert(page_no, page);
    }
}

impl PageDevice for FaultDevice {
    type Error = TestError;

    fn info(&self) -> PageDeviceInfo {
        let page_count = self.page_count();
        PageDeviceInfo {
            device_id: [0xd4; 16],
            range_first_logical_block: 256,
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
        media.read_count += 1;
        *media.read_pages.entry(page).or_default() += 1;
        output.fill(0);
        if let Some(bytes) = media.visible.get(&page) {
            output.copy_from_slice(bytes);
        }
        Ok(())
    }

    async fn write_page(
        &self,
        page: u64,
        input: &Page,
    ) -> Result<(), MutationFailure<Self::Error>> {
        if page >= self.page_count() {
            return Err(MutationFailure::not_submitted(TestError::OutsideRange));
        }
        let bytes = *input;
        match self.next_action() {
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
        }
    }

    async fn flush(&self) -> Result<(), MutationFailure<Self::Error>> {
        match self.next_action() {
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
        }
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

fn store_uuid() -> StoreUuid {
    StoreUuid::new(*b"M7.4-CAS-TEST!!!").unwrap()
}

fn options(limits: StoreLimits) -> FormatOptions {
    FormatOptions {
        store_uuid: store_uuid(),
        cleaner_reserve_segments: 2,
        limits,
    }
}

fn format(device: FaultDevice) -> SegmentStore<FaultDevice> {
    let limits = limits();
    let mut store = SegmentStore::new(device, limits);
    block_on(store.format(options(limits))).expect("format must succeed");
    store
}

fn mount(device: FaultDevice) -> (SegmentStore<FaultDevice>, StoreInfo) {
    let mut store = SegmentStore::new(device, limits());
    let info = block_on(store.mount()).expect("cold mount must succeed");
    (store, info)
}

fn mount_with_runtime(
    device: FaultDevice,
    runtime: StoreRuntimeContext,
) -> (SegmentStore<FaultDevice>, StoreInfo) {
    let mut store = SegmentStore::new_with_runtime_context(device, limits(), runtime);
    let info = block_on(store.mount()).expect("cold mount must succeed");
    (store, info)
}

fn pattern_chunk(index: u32, len: usize) -> Vec<u8> {
    let start = u64::from(index) * PAGE_SIZE as u64;
    (0..len)
        .map(|offset| {
            let absolute = start + offset as u64;
            (absolute.wrapping_mul(131) ^ (absolute >> 7) ^ 0x5a) as u8
        })
        .collect()
}

fn stream_into_writer(
    writer: &mut vibeos_segment_store::BlobWriter<'_, FaultDevice>,
    exact_len: u64,
) {
    let mut remaining = exact_len;
    let mut index = 0_u32;
    while remaining != 0 {
        let len = remaining.min(PAGE_SIZE as u64) as usize;
        let chunk = pattern_chunk(index, len);
        block_on(writer.write_chunk(&chunk)).expect("ordered Blob chunk must be accepted");
        remaining -= len as u64;
        index += 1;
    }
}

fn put_stream(
    store: &mut SegmentStore<FaultDevice>,
    exact_len: u64,
) -> AuthorizedObject<CasObjectHandle> {
    let mut writer = store
        .begin_blob(OBJECT_KIND, exact_len, None)
        .expect("Blob writer must begin");
    stream_into_writer(&mut writer, exact_len);
    block_on(writer.commit()).expect("Blob must commit")
}

fn temp_image_path() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "vibeos-storage-v2-cas-{}-{unique}.img",
        std::process::id()
    ))
}

fn content(exact_len: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(exact_len as usize);
    let mut remaining = exact_len;
    let mut index = 0_u32;
    while remaining != 0 {
        let len = remaining.min(PAGE_SIZE as u64) as usize;
        bytes.extend_from_slice(&pattern_chunk(index, len));
        remaining -= len as u64;
        index += 1;
    }
    bytes
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TestCapability {
    slot: u32,
    generation: u64,
}

struct CapabilitySlot {
    generation: u64,
    alive: bool,
    object: Option<Arc<AuthorizedObject<CasObjectHandle>>>,
}

struct ModelSpace {
    incarnation: u64,
    slots: Mutex<Vec<CapabilitySlot>>,
}

impl ModelSpace {
    fn new() -> Self {
        Self {
            incarnation: 1,
            slots: Mutex::new(Vec::new()),
        }
    }
}

impl ObjectPublicationTarget<CasObjectHandle> for ModelSpace {
    type Capability = TestCapability;
    type Error = ();

    fn incarnation(&self) -> u64 {
        self.incarnation
    }

    fn persistence(&self) -> ObjectPublicationPersistence {
        ObjectPublicationPersistence::RuntimeOnly
    }

    fn publish_independent_root(
        &self,
        publication: AuthorizedPublication<Self, CasObjectHandle>,
    ) -> Result<Self::Capability, PublishError<Self::Error>> {
        let expected_incarnation = publication.expected_incarnation();
        let object = publication.into_object();
        if expected_incarnation != self.incarnation {
            return Err(PublishError::StaleIncarnation);
        }
        let mut slots = self.slots.lock().unwrap();
        let slot = slots.len() as u32;
        let generation = u64::from(slot) + 1;
        slots.push(CapabilitySlot {
            generation,
            alive: true,
            object: Some(object),
        });
        Ok(TestCapability { slot, generation })
    }
}

impl AuthorizedObjectSpace<CasObjectHandle> for ModelSpace {
    fn resolve_read(
        &self,
        capability: Self::Capability,
    ) -> Option<Arc<AuthorizedObject<CasObjectHandle>>> {
        self.slots
            .lock()
            .unwrap()
            .get(capability.slot as usize)
            .filter(|slot| slot.generation == capability.generation && slot.alive)
            .and_then(|slot| slot.object.clone())
    }

    fn revoke_root(&self, capability: Self::Capability) -> bool {
        let mut slots = self.slots.lock().unwrap();
        let Some(slot) = slots.get_mut(capability.slot as usize) else {
            return false;
        };
        if slot.generation != capability.generation || !slot.alive {
            return false;
        }
        slot.alive = false;
        slot.object.take();
        true
    }
}

#[test]
fn writer_rejects_noncanonical_chunks_and_accepts_exact_order_afterward() {
    let device = FaultDevice::blank(12);
    let mut store = format(device.clone());
    let mut writer = store.begin_blob(OBJECT_KIND, 4097, None).unwrap();

    device.reset_mutation_count();
    assert!(matches!(
        block_on(writer.write_chunk(&vec![0; 4095])),
        Err(CasStoreError::InvalidChunk)
    ));
    assert_eq!(
        device.mutation_count(),
        0,
        "rejected chunks must not mutate media"
    );
    assert!(matches!(
        block_on(writer.write_chunk(&vec![0; 4097])),
        Err(CasStoreError::InvalidChunk)
    ));
    assert_eq!(
        device.mutation_count(),
        0,
        "rejected chunks must not mutate media"
    );
    block_on(writer.write_chunk(&pattern_chunk(0, 4096))).unwrap();
    block_on(writer.write_chunk(&pattern_chunk(1, 1))).unwrap();
    assert!(matches!(
        block_on(writer.write_chunk(&[0])),
        Err(CasStoreError::InvalidChunk)
    ));
    let _object = block_on(writer.commit()).expect("valid ordered stream must still commit");
    assert_eq!(store.info().unwrap().object_count, 1);
}

#[test]
fn large_stream_survives_cold_mount_and_supports_directed_and_whole_verification() {
    let exact_len = 1024 * 1024 + 4097;
    let device = FaultDevice::blank(16);
    let mut store = format(device.clone());
    let object = put_stream(&mut store, exact_len);
    let runtime = store.runtime_context();
    let committed = store.info().unwrap();
    assert_eq!(committed.object_count, 1);
    drop(store);

    device.power_cycle();
    let (cold, recovered) = mount_with_runtime(device.clone(), runtime);
    assert_eq!(recovered.generation, committed.generation);
    assert_eq!(recovered.object_count, 1);

    device.reset_reads();
    let first = block_on(cold.get_blob_chunk(&object, 0)).expect("first chunk must verify");
    assert_eq!(first.bytes, pattern_chunk(0, PAGE_SIZE));
    vibeos_blob_format::verify_proof(first.descriptor, &first.bytes, &first.proof).unwrap();
    let first_reads = device.read_count();
    let first_pages = device.distinct_read_pages();
    assert!(
        first_reads < 128,
        "directed read unexpectedly scanned {first_reads} pages"
    );
    assert!(
        first_pages < 64,
        "directed read touched {first_pages} distinct pages"
    );

    device.reset_reads();
    let final_index = exact_len.div_ceil(PAGE_SIZE as u64) as u32 - 1;
    let final_chunk = block_on(cold.get_blob_chunk(&object, final_index))
        .expect("final partial chunk must verify");
    assert_eq!(final_chunk.bytes, pattern_chunk(final_index, 1));
    vibeos_blob_format::verify_proof(
        final_chunk.descriptor,
        &final_chunk.bytes,
        &final_chunk.proof,
    )
    .unwrap();
    assert!(
        device.read_count() < 128,
        "final directed read scanned the Blob"
    );
    assert!(device.distinct_read_pages() < 64);

    let verified = block_on(cold.verify_blob(&object)).expect("whole Blob must verify");
    assert_eq!(verified.descriptor.byte_len, exact_len);
    assert_eq!(
        verified.verified_encoded_bytes,
        vibeos_blob_format::BlobGeometry::for_len(exact_len)
            .unwrap()
            .encoded_len() as u64
    );

    let small_device = FaultDevice::blank(12);
    let mut small_store = format(small_device.clone());
    let small_object = put_stream(&mut small_store, (PAGE_SIZE * 2) as u64);
    let small_runtime = small_store.runtime_context();
    drop(small_store);
    small_device.power_cycle();
    let (small_cold, _) = mount_with_runtime(small_device.clone(), small_runtime);
    small_device.reset_reads();
    block_on(small_cold.get_blob_chunk(&small_object, 0)).unwrap();
    let small_reads = small_device.read_count();
    let small_pages = small_device.distinct_read_pages();
    assert!(
        first_reads <= small_reads + 32,
        "directed read grew with Blob content: small={small_reads}, large={first_reads}"
    );
    assert!(
        first_pages <= small_pages + 16,
        "directed distinct pages grew with Blob content: small={small_pages}, large={first_pages}"
    );
}

#[test]
fn empty_blob_is_canonical_across_commit_and_cold_mount() {
    let device = FaultDevice::blank(10);
    let mut store = format(device.clone());
    let writer = store.begin_blob(OBJECT_KIND, 0, None).unwrap();
    let object = block_on(writer.commit()).expect("empty Blob must commit without caller chunks");
    let runtime = store.runtime_context();
    let committed = store.info().unwrap();
    drop(store);

    device.power_cycle();
    let (cold, recovered) = mount_with_runtime(device, runtime);
    assert_eq!(recovered.generation, committed.generation);
    let chunk = block_on(cold.get_blob_chunk(&object, 0)).expect("empty leaf must verify");
    assert!(chunk.bytes.is_empty());
    assert!(chunk.proof.siblings.is_empty());
    assert_eq!(chunk.descriptor.leaf_count, 1);
    vibeos_blob_format::verify_proof(chunk.descriptor, &chunk.bytes, &chunk.proof).unwrap();
    let whole = block_on(cold.verify_blob(&object)).expect("empty Blob whole verify must pass");
    assert_eq!(whole.verified_encoded_bytes, 160);
}

#[test]
fn corrupted_content_and_required_proof_bytes_fail_closed() {
    let exact_len = (PAGE_SIZE * 2) as u64;
    let device = FaultDevice::blank(12);
    let mut store = format(device.clone());
    let object = put_stream(&mut store, exact_len);
    let runtime = store.runtime_context();
    device.power_cycle();
    let image = device.durable_image();
    let page_count = device.page_count();
    drop(store);

    let content_corrupt = FaultDevice::from_durable(page_count, image.clone());
    let first = pattern_chunk(0, PAGE_SIZE);
    content_corrupt.flip_durable_page_with_prefix(&first[..64], 7);
    content_corrupt.power_cycle();
    let (content_store, _) = mount_with_runtime(content_corrupt, runtime.clone());
    assert!(
        block_on(content_store.get_blob_chunk(&object, 0)).is_err(),
        "a corrupted requested content byte must not escape"
    );
    assert!(
        block_on(content_store.verify_blob(&object)).is_err(),
        "whole verification must detect content corruption"
    );

    let tree_corrupt = FaultDevice::from_durable(page_count, image);
    let encoded = vibeos_blob_format::encode_blob(OBJECT_KIND, &content(exact_len)).unwrap();
    let tree_offset = vibeos_blob_format::HEADER_SIZE + exact_len as usize;
    let tree = &encoded[tree_offset..];
    tree_corrupt.flip_durable_page_with_prefix(tree, vibeos_blob_format::HASH_SIZE);
    tree_corrupt.power_cycle();
    let (tree_store, _) = mount_with_runtime(tree_corrupt, runtime);
    assert!(
        block_on(tree_store.get_blob_chunk(&object, 0)).is_err(),
        "a corrupted sibling hash must invalidate the directed proof"
    );
    assert!(
        block_on(tree_store.verify_blob(&object)).is_err(),
        "whole verification must detect serialized-tree corruption"
    );
}

#[test]
fn identical_streams_share_one_blob_but_publish_independent_revocable_objects() {
    let exact_len = 1024 * 1024 + 4097;
    let device = FaultDevice::blank(20);
    let mut store = format(device.clone());
    let space = Arc::new(ModelSpace::new());

    let first = {
        let mut writer = store.begin_blob(OBJECT_KIND, exact_len, None).unwrap();
        let intent = PublicationIntent::capture(Arc::clone(&space));
        stream_into_writer(&mut writer, exact_len);
        block_on(writer.commit_to(intent)).expect("first capability must publish")
    };
    let after_first = store.info().unwrap();
    let second = {
        let mut writer = store.begin_blob(OBJECT_KIND, exact_len, None).unwrap();
        let intent = PublicationIntent::capture(Arc::clone(&space));
        stream_into_writer(&mut writer, exact_len);
        block_on(writer.commit_to(intent)).expect("second capability must publish")
    };
    let after_second = store.info().unwrap();
    assert_ne!(first, second, "every put must mint a fresh capability root");
    assert_eq!(after_second.object_count, after_first.object_count + 1);
    assert_eq!(
        after_second.allocated_segments,
        after_first.allocated_segments + 1,
        "a dedup hit may add metadata, but must not publish another Blob data segment"
    );

    let first_object = resolve_authorized(space.as_ref(), first).unwrap();
    let second_object = resolve_authorized(space.as_ref(), second).unwrap();
    assert_eq!(
        block_on(store.get_blob_chunk(first_object.as_ref(), 0))
            .unwrap()
            .bytes,
        pattern_chunk(0, PAGE_SIZE)
    );
    assert_eq!(
        block_on(store.get_blob_chunk(second_object.as_ref(), 0))
            .unwrap()
            .bytes,
        pattern_chunk(0, PAGE_SIZE)
    );
    assert!(space.revoke_root(first));
    assert!(resolve_authorized(space.as_ref(), first).is_err());
    let still_live = resolve_authorized(space.as_ref(), second).unwrap();
    block_on(store.verify_blob(still_live.as_ref())).expect("unrelated root must remain live");

    device.power_cycle();
    let image = temp_image_path();
    device.write_raw_image(&image);
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output = Command::new("python3")
        .arg("-B")
        .arg(repository.join("scripts/verify-storage-v2-cas.py"))
        .arg(&image)
        .output()
        .expect("independent CAS verifier must run");
    let _ = std::fs::remove_file(&image);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "Python verifier rejected Rust CAS image: {stdout}"
    );
    assert!(stdout.contains("\"status\":\"ok\""), "{stdout}");
    assert!(stdout.contains("\"object_count\":2"), "{stdout}");
    assert!(stdout.contains("\"blob_count\":1"), "{stdout}");
    assert!(stdout.contains("\"deduplicated_references\":1"), "{stdout}");
}

#[test]
fn wrong_expected_root_and_abandoned_writer_publish_nothing() {
    let device = FaultDevice::blank(12);
    let mut store = format(device.clone());
    let initial = store.info().unwrap();
    let mut writer = store
        .begin_blob(OBJECT_KIND, 4097, Some([0xa5; 32]))
        .unwrap();
    stream_into_writer(&mut writer, 4097);
    assert!(matches!(
        block_on(writer.commit()),
        Err(CasStoreError::ExpectedRootMismatch)
    ));
    assert_eq!(store.info(), Err(StoreError::RecoveryRequired));

    device.power_cycle();
    let (mut recovered, after_mismatch) = mount(device.clone());
    assert_eq!(after_mismatch.generation, initial.generation);
    assert_eq!(after_mismatch.object_count, 0);

    {
        let mut abandoned = recovered.begin_blob(OBJECT_KIND, 4096, None).unwrap();
        block_on(abandoned.write_chunk(&pattern_chunk(0, 4096))).unwrap();
    }
    assert_eq!(recovered.info(), Err(StoreError::RecoveryRequired));
    device.power_cycle();
    let (_cold, after_drop) = mount(device);
    assert_eq!(after_drop.generation, initial.generation);
    assert_eq!(after_drop.object_count, 0);
    assert_eq!(after_drop.allocated_segments, initial.allocated_segments);
}

#[test]
fn cancellation_after_a_durable_staging_write_leaves_the_old_checkpoint_mountable() {
    let device = FaultDevice::blank(12);
    let mut store = format(device.clone());
    let initial = store.info().unwrap();
    let mut writer = store.begin_blob(OBJECT_KIND, 4096, None).unwrap();
    device.arm(0, FaultAction::Pending(Effect::Durable));
    let chunk = pattern_chunk(0, 4096);
    let mut write = Box::pin(writer.write_chunk(&chunk));
    assert!(matches!(poll_once(write.as_mut()), Poll::Pending));
    drop(write);
    drop(writer);
    assert_eq!(store.info(), Err(StoreError::RecoveryRequired));

    device.power_cycle();
    let (_cold, recovered) = mount(device);
    assert_eq!(recovered.generation, initial.generation);
    assert_eq!(recovered.object_count, 0);
}

fn assert_old_or_exact_new_after_commit_fault(
    device: FaultDevice,
    old_info: StoreInfo,
    case: &str,
) {
    device.power_cycle();
    let (_recovered, info) = mount(device);
    assert!(
        (info.generation == old_info.generation && info.object_count == old_info.object_count)
            || (info.generation == old_info.generation + 1
                && info.object_count == old_info.object_count + 1),
        "{case}: recovery selected a mixed CAS state: old={old_info:?}, recovered={info:?}"
    );
}

#[test]
fn every_commit_mutation_boundary_recovers_the_old_or_exact_new_cas_checkpoint() {
    let seed_device = FaultDevice::blank(16);
    let mut seed_store = format(seed_device.clone());
    let _old_object = put_stream(&mut seed_store, PAGE_SIZE as u64);
    let old_info = seed_store.info().unwrap();
    seed_device.power_cycle();
    let seed_image = seed_device.durable_image();
    let page_count = seed_device.page_count();

    let probe_device = FaultDevice::from_durable(page_count, seed_image.clone());
    let (mut probe, _) = mount(probe_device.clone());
    let mut probe_writer = probe
        .begin_blob(OBJECT_KIND, PAGE_SIZE as u64 + 1, None)
        .unwrap();
    stream_into_writer(&mut probe_writer, PAGE_SIZE as u64 + 1);
    probe_device.reset_mutation_count();
    block_on(probe_writer.commit()).unwrap();
    let boundary_count = probe_device.mutation_count();
    assert!(
        boundary_count > 20,
        "probe did not exercise a real CAS commit"
    );

    let failures = [
        FaultAction::FailNotSubmitted,
        FaultAction::FailAmbiguous(Effect::None),
        FaultAction::FailAmbiguous(Effect::Visible),
        FaultAction::FailAmbiguous(Effect::Durable),
    ];
    for boundary in 0..boundary_count {
        for action in failures {
            let device = FaultDevice::from_durable(page_count, seed_image.clone());
            let (mut store, _) = mount(device.clone());
            let mut writer = store
                .begin_blob(OBJECT_KIND, PAGE_SIZE as u64 + 1, None)
                .unwrap();
            stream_into_writer(&mut writer, PAGE_SIZE as u64 + 1);
            device.arm(boundary, action);
            let result = block_on(writer.commit());
            assert!(
                result.is_err(),
                "fault at commit mutation {boundary} was not reached ({action:?})"
            );
            assert_eq!(store.info(), Err(StoreError::RecoveryRequired));
            assert_old_or_exact_new_after_commit_fault(
                device,
                old_info,
                &format!("commit mutation {boundary}, action {action:?}"),
            );
        }

        for effect in [Effect::None, Effect::Visible, Effect::Durable] {
            let device = FaultDevice::from_durable(page_count, seed_image.clone());
            let (mut store, _) = mount(device.clone());
            let mut writer = store
                .begin_blob(OBJECT_KIND, PAGE_SIZE as u64 + 1, None)
                .unwrap();
            stream_into_writer(&mut writer, PAGE_SIZE as u64 + 1);
            device.arm(boundary, FaultAction::Pending(effect));
            let mut commit = Box::pin(writer.commit());
            assert!(
                matches!(poll_once(commit.as_mut()), Poll::Pending),
                "pending fault at commit mutation {boundary} was not reached ({effect:?})"
            );
            drop(commit);
            assert_eq!(store.info(), Err(StoreError::RecoveryRequired));
            assert_old_or_exact_new_after_commit_fault(
                device,
                old_info,
                &format!("commit mutation {boundary}, cancelled with {effect:?}"),
            );
        }
    }
}
