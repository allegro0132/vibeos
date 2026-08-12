use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::{pending, Future};
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::collections::BTreeMap;
use std::fmt;
use std::format;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::string::String;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    decode_blob_manifest, decode_cas_snapshot, CasCodecContext, FormatOptions, GrowError,
    GrowablePageDevice, MaintenanceOperation, PageDevice, PageDeviceInfo, PrincipalQuotaLimits,
    SegmentStore, StoreError, StoreLimits, StoreRuntimeContext,
};
use vibeos_segment_format::{
    admitted_pages, decode_checkpoint, segment_base_page, DecodeStatus, Page, PhysicalPointer,
    StoreUuid, PAGE_SIZE, SEGMENT_PAGES,
};
use vibeos_storage_device::{
    BlockRangeCapability, BlockRangeProvisioner, DeviceId, DeviceSession, MutationFailure,
};

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

const FIRST_BLOCK: u64 = 128;
const BLOCKS_PER_PAGE: u64 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestError {
    OutsideRange,
    WrongDevice,
    NotAdjacent,
    Injected,
    DriverRestarted,
}

impl fmt::Display for TestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[derive(Clone)]
struct MemoryDevice(Arc<Mutex<Media>>);

struct Media {
    admitted_pages: u64,
    capacity_pages: u64,
    visible: BTreeMap<u64, Page>,
    durable: BTreeMap<u64, Page>,
    reads: usize,
    mutations: usize,
    fault: Option<FaultPlan>,
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
    mutation: usize,
    action: FaultAction,
}

impl MemoryDevice {
    fn blank(initial_segments: u64, capacity_segments: u64) -> Self {
        Self(Arc::new(Mutex::new(Media {
            admitted_pages: admitted_pages(initial_segments).unwrap(),
            capacity_pages: admitted_pages(capacity_segments).unwrap(),
            visible: BTreeMap::new(),
            durable: BTreeMap::new(),
            reads: 0,
            mutations: 0,
            fault: None,
        })))
    }

    fn from_durable(
        initial_segments: u64,
        capacity_segments: u64,
        durable: BTreeMap<u64, Page>,
    ) -> Self {
        Self(Arc::new(Mutex::new(Media {
            admitted_pages: admitted_pages(initial_segments).unwrap(),
            capacity_pages: admitted_pages(capacity_segments).unwrap(),
            visible: durable.clone(),
            durable,
            reads: 0,
            mutations: 0,
            fault: None,
        })))
    }

    fn durable_image(&self) -> BTreeMap<u64, Page> {
        self.0.lock().unwrap().durable.clone()
    }

    fn expose_full_parent_range(&self) {
        let mut media = self.0.lock().unwrap();
        media.admitted_pages = media.capacity_pages;
    }

    fn reset_io(&self) {
        let mut media = self.0.lock().unwrap();
        media.reads = 0;
        media.mutations = 0;
        media.fault = None;
    }

    fn io_counts(&self) -> (usize, usize) {
        let media = self.0.lock().unwrap();
        (media.reads, media.mutations)
    }

    fn arm(&self, mutation: usize, action: FaultAction) {
        let mut media = self.0.lock().unwrap();
        media.mutations = 0;
        media.fault = Some(FaultPlan { mutation, action });
    }

    fn power_cycle(&self) {
        let mut media = self.0.lock().unwrap();
        media.visible = media.durable.clone();
        media.reads = 0;
        media.mutations = 0;
        media.fault = None;
    }

    fn next_action(&self) -> FaultAction {
        let mut media = self.0.lock().unwrap();
        let mutation = media.mutations;
        media.mutations += 1;
        media
            .fault
            .filter(|fault| fault.mutation == mutation)
            .map_or(FaultAction::Normal, |fault| fault.action)
    }

    fn apply_write(&self, page: u64, bytes: Page, effect: Effect) {
        let mut media = self.0.lock().unwrap();
        if !matches!(effect, Effect::None) {
            media.visible.insert(page, bytes);
        }
        if matches!(effect, Effect::Durable) {
            media.durable.insert(page, bytes);
        }
    }

    fn apply_flush(&self, effect: Effect) {
        if matches!(effect, Effect::Durable) {
            let mut media = self.0.lock().unwrap();
            media.durable = media.visible.clone();
        }
    }
}

impl PageDevice for MemoryDevice {
    type Error = TestError;

    fn info(&self) -> PageDeviceInfo {
        let pages = self.0.lock().unwrap().admitted_pages;
        PageDeviceInfo {
            device_id: device_id().get().to_le_bytes(),
            range_first_logical_block: FIRST_BLOCK,
            logical_block_count: pages * BLOCKS_PER_PAGE,
            logical_block_size: 512,
            page_count: pages,
        }
    }

    async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
        let mut media = self.0.lock().unwrap();
        media.reads += 1;
        if page >= media.admitted_pages {
            return Err(TestError::OutsideRange);
        }
        output.fill(0);
        if let Some(bytes) = media.visible.get(&page) {
            *output = *bytes;
        }
        Ok(())
    }

    async fn write_page(
        &self,
        page: u64,
        input: &Page,
    ) -> Result<(), MutationFailure<Self::Error>> {
        if page >= self.0.lock().unwrap().admitted_pages {
            return Err(MutationFailure::not_submitted(TestError::OutsideRange));
        }
        let bytes = *input;
        match self.next_action() {
            FaultAction::Normal => {
                self.apply_write(page, bytes, Effect::Visible);
                Ok(())
            }
            FaultAction::FailNotSubmitted => {
                Err(MutationFailure::not_submitted(TestError::Injected))
            }
            FaultAction::FailAmbiguous(effect) => {
                self.apply_write(page, bytes, effect);
                Err(MutationFailure::ambiguous(TestError::DriverRestarted))
            }
            FaultAction::Pending(effect) => {
                self.apply_write(page, bytes, effect);
                pending().await
            }
        }
    }

    async fn flush(&self) -> Result<(), MutationFailure<Self::Error>> {
        match self.next_action() {
            FaultAction::Normal => {
                self.apply_flush(Effect::Durable);
                Ok(())
            }
            FaultAction::FailNotSubmitted => {
                Err(MutationFailure::not_submitted(TestError::Injected))
            }
            FaultAction::FailAmbiguous(effect) => {
                self.apply_flush(effect);
                Err(MutationFailure::ambiguous(TestError::DriverRestarted))
            }
            FaultAction::Pending(effect) => {
                self.apply_flush(effect);
                pending().await
            }
        }
    }
}

impl GrowablePageDevice for MemoryDevice {
    fn validate_growth(
        &self,
        durable_logical_block_count: u64,
        additional: BlockRangeCapability,
    ) -> Result<(), Self::Error> {
        if additional.session() != device_session() {
            return Err(TestError::DriverRestarted);
        }
        let additional = additional.range();
        if additional.device_id() != device_id() {
            return Err(TestError::WrongDevice);
        }
        let durable_end = FIRST_BLOCK + durable_logical_block_count;
        if additional.first_block() != durable_end {
            return Err(TestError::NotAdjacent);
        }
        let media = self.0.lock().unwrap();
        let durable_pages = durable_logical_block_count / BLOCKS_PER_PAGE;
        let enlarged_pages = durable_pages + additional.block_count() / BLOCKS_PER_PAGE;
        if media.admitted_pages != durable_pages && media.admitted_pages != enlarged_pages {
            return Err(TestError::NotAdjacent);
        }
        if enlarged_pages > media.capacity_pages {
            return Err(TestError::OutsideRange);
        }
        Ok(())
    }

    fn admit_growth(
        &mut self,
        durable_logical_block_count: u64,
        additional: BlockRangeCapability,
    ) -> Result<PageDeviceInfo, Self::Error> {
        self.validate_growth(durable_logical_block_count, additional)?;
        let additional = additional.range();
        if additional.device_id() != device_id() {
            return Err(TestError::WrongDevice);
        }
        let durable_end = FIRST_BLOCK + durable_logical_block_count;
        if additional.first_block() != durable_end {
            return Err(TestError::NotAdjacent);
        }
        let mut media = self.0.lock().unwrap();
        let durable_pages = durable_logical_block_count / BLOCKS_PER_PAGE;
        let enlarged_pages = durable_pages + additional.block_count() / BLOCKS_PER_PAGE;
        if media.admitted_pages != durable_pages && media.admitted_pages != enlarged_pages {
            return Err(TestError::NotAdjacent);
        }
        if enlarged_pages > media.capacity_pages {
            return Err(TestError::OutsideRange);
        }
        media.admitted_pages = enlarged_pages;
        drop(media);
        Ok(self.info())
    }
}

fn device_id() -> DeviceId {
    DeviceId::new(u128::from_le_bytes([0xd3; 16])).unwrap()
}

fn device_session() -> DeviceSession {
    DeviceSession::new(device_id(), 1).unwrap()
}

fn range_provisioner(capacity_segments: u64) -> BlockRangeProvisioner {
    // SAFETY: the test fixture is the sole root policy for this in-memory
    // device/session and derives every initial/suffix capability from it.
    unsafe {
        BlockRangeProvisioner::new(
            device_session(),
            FIRST_BLOCK,
            admitted_pages(capacity_segments).unwrap() * BLOCKS_PER_PAGE,
        )
        .unwrap()
    }
}

fn limits() -> StoreLimits {
    StoreLimits {
        max_catalog_entries: 64,
        max_replay_records: 4,
        recovery_memory_bytes: 256 * 1024,
        max_compat_object_bytes: 64 * 1024,
    }
}

fn limits_with_memory(recovery_memory_bytes: usize) -> StoreLimits {
    StoreLimits {
        recovery_memory_bytes,
        ..limits()
    }
}

fn format_with_runtime(
    device: MemoryDevice,
    runtime: StoreRuntimeContext,
    uuid: [u8; 16],
) -> SegmentStore<MemoryDevice> {
    let mut store = SegmentStore::new_with_runtime_context(device, limits(), runtime);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(uuid).unwrap(),
        cleaner_reserve_segments: 2,
        limits: limits(),
    }))
    .unwrap();
    store
}

fn adjacent_range(old_segments: u64, additional_segments: u64) -> BlockRangeCapability {
    let old_blocks = admitted_pages(old_segments).unwrap() * BLOCKS_PER_PAGE;
    let more_blocks = additional_segments * SEGMENT_PAGES * BLOCKS_PER_PAGE;
    range_provisioner(64)
        .derive(old_blocks, more_blocks)
        .unwrap()
}

fn forged_range(device: DeviceId, first_block: u64, block_count: u64) -> BlockRangeCapability {
    let session = DeviceSession::new(device, 1).unwrap();
    // SAFETY: test-only independent root deliberately models a foreign policy
    // domain so grow must reject it before mutation.
    unsafe { BlockRangeProvisioner::new(session, first_block, block_count) }
        .unwrap()
        .derive(0, block_count)
        .unwrap()
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn recover_growth(device: MemoryDevice) -> crate::StoreInfo {
    device.power_cycle();
    let mut recovered = SegmentStore::new(device, limits());
    block_on(recovered.mount()).expect("every grow boundary must cold-mount")
}

fn same_selected_state(left: crate::StoreInfo, right: crate::StoreInfo) -> bool {
    left.generation == right.generation
        && left.admitted_segments == right.admitted_segments
        && left.allocated_segments == right.allocated_segments
        && left.free_segments == right.free_segments
        && left.cleaner_reserved_segments == right.cleaner_reserved_segments
        && left.object_count == right.object_count
        && left.replay_count == right.replay_count
}

#[test]
fn grow_publishes_exact_free_suffix_before_it_is_reported() {
    let device = MemoryDevice::blank(8, 12);
    let mut store = format_with_runtime(device.clone(), StoreRuntimeContext::new(), [1; 16]);
    let maintenance = store
        .mint_maintenance_root()
        .unwrap()
        .attenuate(&[MaintenanceOperation::Grow])
        .unwrap();

    let before = store.info().unwrap();
    let after = block_on(store.grow(&maintenance, adjacent_range(8, 4))).unwrap();

    assert_eq!(after.generation, before.generation + 1);
    assert_eq!(after.admitted_segments, 12);
    assert_eq!(after.allocated_segments, before.allocated_segments + 1);
    assert_eq!(after.free_segments, before.free_segments + 3);
    assert_eq!(device.info().page_count, admitted_pages(12).unwrap());
}

#[test]
fn a_preprovisioned_parent_range_mounts_old_checkpoint_and_admits_exact_suffix() {
    let seed = MemoryDevice::blank(8, 12);
    drop(format_with_runtime(
        seed.clone(),
        StoreRuntimeContext::new(),
        [6; 16],
    ));
    let device = MemoryDevice::from_durable(8, 12, seed.durable_image());
    device.expose_full_parent_range();
    let mut store = SegmentStore::new(device, limits());
    assert_eq!(block_on(store.mount()).unwrap().admitted_segments, 8);
    let maintenance = store.mint_maintenance_root().unwrap();
    assert_eq!(
        block_on(store.grow(&maintenance, adjacent_range(8, 4)))
            .unwrap()
            .admitted_segments,
        12
    );
}

#[test]
fn authority_is_operation_domain_and_store_uuid_bound_before_io() {
    let runtime = StoreRuntimeContext::new();
    let device_a = MemoryDevice::blank(8, 12);
    let store_a = format_with_runtime(device_a.clone(), runtime.clone(), [1; 16]);
    let unmounted = SegmentStore::new_with_runtime_context(
        MemoryDevice::blank(8, 12),
        limits(),
        runtime.clone(),
    );
    assert!(matches!(
        unmounted.mint_maintenance_root(),
        Err(StoreError::NotMounted)
    ));

    let scrub_only = store_a
        .mint_maintenance_root()
        .unwrap()
        .attenuate(&[MaintenanceOperation::Scrub])
        .unwrap();
    let mut store_a = store_a;
    device_a.reset_io();
    assert!(matches!(
        block_on(store_a.grow(&scrub_only, adjacent_range(8, 4))),
        Err(GrowError::Unauthorized)
    ));
    assert_eq!(device_a.io_counts(), (0, 0));

    let foreign = format_with_runtime(MemoryDevice::blank(8, 12), runtime, [2; 16]);
    let foreign_grow = foreign
        .mint_maintenance_root()
        .unwrap()
        .attenuate(&[MaintenanceOperation::Grow])
        .unwrap();
    device_a.reset_io();
    assert!(matches!(
        block_on(store_a.grow(&foreign_grow, adjacent_range(8, 4))),
        Err(GrowError::Unauthorized)
    ));
    assert_eq!(device_a.io_counts(), (0, 0));
}

#[test]
fn trusted_provisioner_is_runtime_bound_and_production_usable() {
    let (runtime, provisioner) = StoreRuntimeContext::with_maintenance_provisioner();
    let cloned_runtime = runtime.clone();
    let device = MemoryDevice::blank(8, 12);
    let store = format_with_runtime(device.clone(), runtime, [7; 16]);
    let root = store.provision_maintenance_root(&provisioner).unwrap();
    assert!(root
        .attenuate(&[MaintenanceOperation::Grow, MaintenanceOperation::Scrub])
        .is_ok());

    let (_, foreign_provisioner) = StoreRuntimeContext::with_maintenance_provisioner();
    device.reset_io();
    assert!(matches!(
        store.provision_maintenance_root(&foreign_provisioner),
        Err(StoreError::MaintenanceAuthority)
    ));
    assert_eq!(device.io_counts(), (0, 0));

    let unmounted = SegmentStore::new_with_runtime_context(
        MemoryDevice::blank(8, 12),
        limits(),
        cloned_runtime,
    );
    assert!(matches!(
        unmounted.provision_maintenance_root(&provisioner),
        Err(StoreError::NotMounted)
    ));
}

#[test]
fn provisioner_revocation_invalidates_every_clone_before_io() {
    let (runtime, provisioner) = StoreRuntimeContext::with_maintenance_provisioner();
    let device = MemoryDevice::blank(8, 12);
    let mut store = format_with_runtime(device.clone(), runtime, [8; 16]);
    let root = store.provision_maintenance_root(&provisioner).unwrap();
    let grow = root.attenuate(&[MaintenanceOperation::Grow]).unwrap();
    let scrub = root.attenuate(&[MaintenanceOperation::Scrub]).unwrap();
    let cloned = grow.clone();

    provisioner.revoke_all().unwrap();
    device.reset_io();
    assert!(matches!(
        block_on(store.grow(&cloned, adjacent_range(8, 4))),
        Err(GrowError::Unauthorized)
    ));
    assert!(matches!(
        block_on(store.scrub(&scrub)),
        Err(crate::ScrubError::Unauthorized)
    ));
    assert_eq!(device.io_counts(), (0, 0));
    assert!(matches!(
        store.provision_maintenance_root(&provisioner),
        Err(StoreError::MaintenanceAuthority)
    ));
}

#[test]
fn governed_runtime_can_provision_quota_and_maintenance_from_one_domain() {
    let (runtime, quota, maintenance) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let principal = quota
        .admit_principal(PrincipalQuotaLimits {
            logical_bytes: 1,
            physical_bytes: 1,
        })
        .unwrap();
    assert_eq!(principal.ceilings().logical_bytes, 1);

    let store = format_with_runtime(MemoryDevice::blank(8, 12), runtime, [9; 16]);
    assert!(store.provision_maintenance_root(&maintenance).is_ok());
}

#[test]
fn wrong_device_gap_overlap_and_geometry_fail_before_mutation() {
    let device = MemoryDevice::blank(8, 12);
    let mut store = format_with_runtime(device.clone(), StoreRuntimeContext::new(), [3; 16]);
    let maintenance = store.mint_maintenance_root().unwrap();
    let exact = adjacent_range(8, 4);
    let old_end = exact.range().first_block();
    let cases = [
        forged_range(
            DeviceId::new(7).unwrap(),
            old_end,
            exact.range().block_count(),
        ),
        forged_range(device_id(), old_end - 1, exact.range().block_count()),
        forged_range(device_id(), old_end + 1, exact.range().block_count()),
        forged_range(device_id(), old_end, exact.range().block_count() - 1),
    ];
    for candidate in cases {
        device.reset_io();
        assert!(block_on(store.grow(&maintenance, candidate)).is_err());
        assert_eq!(device.io_counts().1, 0);
        assert_eq!(store.info().unwrap().admitted_segments, 8);
    }
}

#[test]
fn block_range_overflow_is_rejected_by_the_capability_constructor() {
    // SAFETY: construction intentionally probes overflow before any authority
    // can be returned.
    assert!(unsafe { BlockRangeProvisioner::new(device_session(), u64::MAX - 3, 8) }.is_err());
}

#[test]
fn every_grow_mutation_boundary_recovers_exact_old_or_exact_new() {
    let seed = MemoryDevice::blank(7, 12);
    let mut seeded = format_with_runtime(seed.clone(), StoreRuntimeContext::new(), [4; 16]);
    let seed_maintenance = seeded.mint_maintenance_root().unwrap();
    block_on(seeded.grow(&seed_maintenance, adjacent_range(7, 1))).unwrap();
    drop(seeded);
    let image = seed.durable_image();

    let probe_device = MemoryDevice::from_durable(8, 12, image.clone());
    let mut probe = SegmentStore::new(probe_device.clone(), limits());
    let old = block_on(probe.mount()).unwrap();
    let maintenance = probe.mint_maintenance_root().unwrap();
    probe_device.reset_io();
    let expected_new = block_on(probe.grow(&maintenance, adjacent_range(8, 4))).unwrap();
    let boundary_count = probe_device.io_counts().1;
    assert!(boundary_count > 10);

    let actions = [
        FaultAction::FailNotSubmitted,
        FaultAction::FailAmbiguous(Effect::None),
        FaultAction::FailAmbiguous(Effect::Visible),
        FaultAction::FailAmbiguous(Effect::Durable),
    ];
    for boundary in 0..boundary_count {
        for action in actions {
            let device = MemoryDevice::from_durable(8, 12, image.clone());
            let mut store = SegmentStore::new(device.clone(), limits());
            block_on(store.mount()).unwrap();
            let maintenance = store.mint_maintenance_root().unwrap();
            device.arm(boundary, action);
            assert!(
                block_on(store.grow(&maintenance, adjacent_range(8, 4))).is_err(),
                "fault boundary {boundary}, action {action:?} was not reached"
            );
            assert_eq!(store.info(), Err(StoreError::RecoveryRequired));
            let recovered = recover_growth(device);
            assert!(
                same_selected_state(recovered, old) || same_selected_state(recovered, expected_new),
                "mixed grow state at boundary {boundary}, action {action:?}: recovered={recovered:?}, old={old:?}, new={expected_new:?}"
            );
        }
        for effect in [Effect::None, Effect::Visible, Effect::Durable] {
            let device = MemoryDevice::from_durable(8, 12, image.clone());
            let mut store = SegmentStore::new(device.clone(), limits());
            block_on(store.mount()).unwrap();
            let maintenance = store.mint_maintenance_root().unwrap();
            device.arm(boundary, FaultAction::Pending(effect));
            let mut growth = Box::pin(store.grow(&maintenance, adjacent_range(8, 4)));
            assert!(
                matches!(poll_once(growth.as_mut()), Poll::Pending),
                "cancel boundary {boundary}, effect {effect:?} was not reached"
            );
            drop(growth);
            assert_eq!(store.info(), Err(StoreError::RecoveryRequired));
            let recovered = recover_growth(device);
            assert!(
                same_selected_state(recovered, old) || same_selected_state(recovered, expected_new),
                "mixed cancelled grow at boundary {boundary}, effect {effect:?}: recovered={recovered:?}, old={old:?}, new={expected_new:?}"
            );
        }
    }
}

#[test]
fn growth_memory_high_water_accepts_exact_and_rejects_one_less_before_mutation() {
    // Empty 8-segment state: old bitmap=2, enlarged bitmap=3, encoded v2
    // payload=131. The maximum stage is old + final + encoded + reread = 267.
    const EXACT_GROWTH_HEAP: usize = 2 + 3 + (131 * 2);
    let seed = MemoryDevice::blank(8, 12);
    drop(format_with_runtime(
        seed.clone(),
        StoreRuntimeContext::new(),
        [5; 16],
    ));
    let image = seed.durable_image();

    let below_device = MemoryDevice::from_durable(8, 12, image.clone());
    let mut below = SegmentStore::new(
        below_device.clone(),
        limits_with_memory(EXACT_GROWTH_HEAP - 1),
    );
    block_on(below.mount()).unwrap();
    let below_authority = below.mint_maintenance_root().unwrap();
    below_device.reset_io();
    assert!(matches!(
        block_on(below.grow(&below_authority, adjacent_range(8, 4))),
        Err(GrowError::Store(StoreError::MemoryLimit))
    ));
    assert_eq!(below_device.io_counts().1, 0);
    assert_eq!(below_device.info().page_count, admitted_pages(8).unwrap());

    let exact_device = MemoryDevice::from_durable(8, 12, image);
    let mut exact = SegmentStore::new(exact_device, limits_with_memory(EXACT_GROWTH_HEAP));
    block_on(exact.mount()).unwrap();
    let exact_authority = exact.mint_maintenance_root().unwrap();
    assert_eq!(
        block_on(exact.grow(&exact_authority, adjacent_range(8, 4)))
            .unwrap()
            .admitted_segments,
        12
    );
}

fn raw_image_path() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "vibeos-storage-v2-growth-{}-{unique}.img",
        std::process::id()
    ))
}

fn image_page(image: &BTreeMap<u64, Page>, page_no: u64) -> Page {
    image.get(&page_no).copied().unwrap_or([0; PAGE_SIZE])
}

fn selected_checkpoint(image: &BTreeMap<u64, Page>) -> vibeos_segment_format::Checkpoint {
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

fn write_raw_image(image: &BTreeMap<u64, Page>, segments: u64) -> PathBuf {
    let image_path = raw_image_path();
    let mut raw = File::create(&image_path).unwrap();
    for page_no in 0..admitted_pages(segments).unwrap() {
        raw.write_all(&image_page(image, page_no)).unwrap();
    }
    raw.sync_all().unwrap();
    drop(raw);
    image_path
}

fn run_raw_verifier(image: &BTreeMap<u64, Page>, segments: u64) -> (bool, String) {
    let image_path = write_raw_image(image, segments);
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let output = Command::new("python3")
        .arg("-B")
        .arg(repository.join("scripts/verify-storage-v2-maintenance.py"))
        .arg("--raw-image")
        .arg(&image_path)
        .output()
        .expect("independent maintenance verifier must run");
    let _ = std::fs::remove_file(&image_path);
    assert!(
        output.stderr.is_empty(),
        "verifier leaked stderr: {:?}",
        output.stderr
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.lines().count(),
        1,
        "verifier must emit exactly one compact JSON value: {stdout}"
    );
    let parsed = Command::new("python3")
        .arg("-c")
        .arg("import json,sys; value=json.loads(sys.argv[1]); assert isinstance(value,dict)")
        .arg(&stdout)
        .output()
        .expect("Python JSON parser must run");
    assert!(
        parsed.status.success(),
        "verifier emitted non-JSON: {stdout}"
    );
    (output.status.success(), stdout)
}

#[test]
fn rust_grown_powered_off_image_passes_the_anonymous_maintenance_verifier() {
    const INITIAL_SEGMENTS: u64 = 16;
    const FINAL_SEGMENTS: u64 = 20;
    let device = MemoryDevice::blank(INITIAL_SEGMENTS, FINAL_SEGMENTS);
    let mut store = format_with_runtime(device.clone(), StoreRuntimeContext::new(), [6; 16]);
    let bytes: Vec<u8> = (0..PAGE_SIZE + 137)
        .map(|index| (index.wrapping_mul(37) ^ (index >> 3) ^ 0x5a) as u8)
        .collect();
    let mut writer = store
        .begin_blob(0x4d37_3601, bytes.len() as u64, None)
        .unwrap();
    for chunk in bytes.chunks(PAGE_SIZE) {
        block_on(writer.write_chunk(chunk)).unwrap();
    }
    let object = block_on(writer.commit()).unwrap();
    block_on(store.synchronize_gc_roots(&[&object])).unwrap();
    let maintenance = store.mint_maintenance_root().unwrap();
    block_on(store.grow(&maintenance, adjacent_range(INITIAL_SEGMENTS, 4))).unwrap();

    let durable = device.durable_image();
    let (success, stdout) = run_raw_verifier(&durable, FINAL_SEGMENTS);
    assert!(
        success,
        "powered-off maintenance verification failed: {stdout}"
    );
    assert!(stdout.contains("\"state\":\"verified\""), "{stdout}");
    assert!(stdout.contains("\"status\":\"healthy\""), "{stdout}");
    assert!(stdout.contains("\"live_objects\":1"), "{stdout}");
    assert!(stdout.contains("\"unique_blobs\":1"), "{stdout}");

    let checkpoint = selected_checkpoint(&durable);
    let context = CasCodecContext::new(
        StoreUuid::new([6; 16]).unwrap(),
        checkpoint.admitted_segments,
        checkpoint.next_segment_generation,
    )
    .unwrap();
    let snapshot =
        decode_cas_snapshot(&pointer_payload(&durable, checkpoint.catalog_root), context).unwrap();
    let manifest = decode_blob_manifest(
        &pointer_payload(&durable, snapshot.blobs[0].manifest),
        context,
    )
    .unwrap();
    let PhysicalPointer::Value(allocation) = checkpoint.allocation_root else {
        panic!("grown checkpoint must name allocation-v2");
    };
    let PhysicalPointer::Value(blob) = manifest.extents[0].pointer else {
        panic!("manifest extent must have a physical pointer");
    };
    let padded = manifest
        .extents
        .iter()
        .find(|extent| extent.payload_byte_len % PAGE_SIZE as u64 != 0)
        .expect("fixture must contain one padded Blob extent");
    let PhysicalPointer::Value(padded_pointer) = padded.pointer else {
        panic!("padded manifest extent must have a physical pointer");
    };
    let padded_used = (padded.payload_byte_len % PAGE_SIZE as u64) as usize;
    let corruptions = [
        (0_u64, 0x80_usize),
        (
            segment_base_page(allocation.segment_no).unwrap()
                + u64::from(allocation.payload_relative_page),
            0x20,
        ),
        (segment_base_page(allocation.segment_no).unwrap(), 0x80),
        (
            segment_base_page(blob.segment_no).unwrap() + u64::from(blob.payload_relative_page),
            17,
        ),
        (
            segment_base_page(padded_pointer.segment_no).unwrap()
                + u64::from(padded_pointer.payload_relative_page)
                + u64::from(padded_pointer.payload_pages)
                - 1,
            padded_used,
        ),
    ];
    for (page_no, offset) in corruptions {
        let mut corrupted = durable.clone();
        corrupted.entry(page_no).or_insert([0; PAGE_SIZE])[offset] ^= 0x80;
        let (success, stdout) = run_raw_verifier(&corrupted, FINAL_SEGMENTS);
        assert!(!success, "corruption unexpectedly verified: {stdout}");
        assert!(stdout.contains("\"status\":\"corrupt\""), "{stdout}");
    }
}
