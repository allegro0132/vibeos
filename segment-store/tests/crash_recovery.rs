use core::future::{pending, Future};
use core::pin::Pin;
use core::task::{Context, Poll};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::process::Command;
use std::rc::Rc;
use std::task::Waker;
use std::time::{SystemTime, UNIX_EPOCH};

use vibeos_segment_format::{admitted_pages, payload_sha256, Page, StoreUuid};
use vibeos_segment_store::{
    CapacityClass, FormatOptions, ObjectHandle, PageDevice, PageDeviceInfo, SegmentStore,
    StoreError, StoreInfo, StoreLimits, MAX_ALLOCATION_V2_SEGMENTS,
};
use vibeos_storage_device::{MutationCertainty, MutationFailure};

const OBJECT_KIND: u32 = 7;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestError {
    Injected,
    DriverRestarted,
    ReadFailed,
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
    read_fault: Option<usize>,
    mutation_count: usize,
    fault: Option<FaultPlan>,
}

#[derive(Clone)]
struct FaultDevice(Rc<RefCell<Media>>);

impl FaultDevice {
    fn blank(segment_count: u64) -> Self {
        Self::from_durable(
            admitted_pages(segment_count).expect("test geometry must fit"),
            BTreeMap::new(),
        )
    }

    fn from_durable(page_count: u64, durable: BTreeMap<u64, Page>) -> Self {
        Self(Rc::new(RefCell::new(Media {
            page_count,
            visible: durable.clone(),
            durable,
            read_count: 0,
            read_fault: None,
            mutation_count: 0,
            fault: None,
        })))
    }

    fn durable_image(&self) -> BTreeMap<u64, Page> {
        self.0.borrow().durable.clone()
    }

    fn page_count(&self) -> u64 {
        self.0.borrow().page_count
    }

    fn reset_mutation_count(&self) {
        self.0.borrow_mut().mutation_count = 0;
    }

    fn arm_read(&self, read_index: usize) {
        let mut media = self.0.borrow_mut();
        media.read_count = 0;
        media.read_fault = Some(read_index);
    }

    fn clear_read_fault(&self) {
        let mut media = self.0.borrow_mut();
        media.read_count = 0;
        media.read_fault = None;
    }

    fn mutation_count(&self) -> usize {
        self.0.borrow().mutation_count
    }

    fn arm(&self, mutation_index: usize, action: FaultAction) {
        let mut media = self.0.borrow_mut();
        media.mutation_count = 0;
        media.fault = Some(FaultPlan {
            mutation_index,
            action,
        });
    }

    fn power_cycle(&self) {
        let mut media = self.0.borrow_mut();
        media.visible = media.durable.clone();
        media.read_count = 0;
        media.read_fault = None;
        media.mutation_count = 0;
        media.fault = None;
    }

    fn next_action(&self) -> FaultAction {
        let mut media = self.0.borrow_mut();
        let index = media.mutation_count;
        media.mutation_count += 1;
        media
            .fault
            .filter(|plan| plan.mutation_index == index)
            .map_or(FaultAction::Normal, |plan| plan.action)
    }

    fn write_effect(&self, page: u64, bytes: Page, effect: Effect) {
        let mut media = self.0.borrow_mut();
        if !matches!(effect, Effect::None) {
            media.visible.insert(page, bytes);
        }
        if matches!(effect, Effect::Durable) {
            media.durable.insert(page, bytes);
        }
    }

    fn flush_effect(&self, effect: Effect) {
        if matches!(effect, Effect::Durable) {
            let mut media = self.0.borrow_mut();
            media.durable = media.visible.clone();
        }
    }
}

impl PageDevice for FaultDevice {
    type Error = TestError;

    fn info(&self) -> PageDeviceInfo {
        let page_count = self.page_count();
        PageDeviceInfo {
            device_id: [0xd3; 16],
            range_first_logical_block: 128,
            logical_block_count: page_count * 8,
            logical_block_size: 512,
            page_count,
        }
    }

    async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
        let mut media = self.0.borrow_mut();
        if page >= media.page_count {
            return Err(TestError::OutsideRange);
        }
        let read_index = media.read_count;
        media.read_count += 1;
        if media.read_fault == Some(read_index) {
            return Err(TestError::ReadFailed);
        }
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
        recovery_memory_bytes: 256 * 1024,
        max_compat_object_bytes: 64 * 1024,
    }
}

fn store_uuid() -> StoreUuid {
    StoreUuid::new(*b"M7.3-CRASH-TEST!").unwrap()
}

fn options(limits: StoreLimits, cleaner_reserve_segments: u32) -> FormatOptions {
    FormatOptions {
        store_uuid: store_uuid(),
        cleaner_reserve_segments,
        limits,
    }
}

fn root(bytes: &[u8]) -> [u8; 32] {
    payload_sha256(bytes)
}

fn mount(device: FaultDevice, limits: StoreLimits) -> (SegmentStore<FaultDevice>, StoreInfo) {
    let mut store = SegmentStore::new(device, limits);
    let info = block_on(store.mount()).expect("cold mount must succeed");
    (store, info)
}

fn format(device: FaultDevice, limits: StoreLimits, reserve: u32) -> SegmentStore<FaultDevice> {
    let mut store = SegmentStore::new(device, limits);
    block_on(store.format(options(limits, reserve))).expect("format must succeed");
    store
}

#[test]
fn format_admits_the_allocation_v2_maximum_and_rejects_max_plus_one_before_writing() {
    let maximum = MAX_ALLOCATION_V2_SEGMENTS as u64;
    let generous = StoreLimits {
        recovery_memory_bytes: 2 * 1024 * 1024,
        ..limits()
    };
    let maximum_device = FaultDevice::blank(maximum);
    let maximum_store = format(maximum_device, generous, 2);
    let info = maximum_store.info().unwrap();
    assert_eq!(info.admitted_segments, maximum);
    assert_eq!(info.recovery_peak_bytes, maximum.div_ceil(4) as usize);

    let oversized = FaultDevice::blank(maximum + 1);
    let mut refused = SegmentStore::new(oversized.clone(), generous);
    assert_eq!(
        block_on(refused.format(options(generous, 2))),
        Err(StoreError::InvalidConfig)
    );
    assert_eq!(oversized.mutation_count(), 0);
    assert!(oversized.durable_image().is_empty());
}

#[test]
fn new_format_rejects_reserve_one_before_writing() {
    let store_limits = limits();
    let device = FaultDevice::blank(6);
    let mut store = SegmentStore::new(device.clone(), store_limits);
    assert_eq!(
        block_on(store.format(options(store_limits, 1))),
        Err(StoreError::InvalidConfig)
    );
    assert_eq!(device.mutation_count(), 0);
    assert!(device.durable_image().is_empty());
}

#[test]
fn format_rejects_an_initial_allocation_bitmap_over_the_recovery_budget() {
    let segments = 1024_u64;
    let constrained = StoreLimits {
        recovery_memory_bytes: segments.div_ceil(4) as usize - 1,
        ..limits()
    };
    let device = FaultDevice::blank(segments);
    let mut store = SegmentStore::new(device.clone(), constrained);
    assert_eq!(
        block_on(store.format(options(constrained, 2))),
        Err(StoreError::InvalidConfig)
    );
    assert_eq!(device.mutation_count(), 0);
    assert!(device.durable_image().is_empty());
}

fn seeded_store(
    segment_count: u64,
    limits: StoreLimits,
    reserve: u32,
) -> (FaultDevice, ObjectHandle, StoreInfo) {
    let device = FaultDevice::blank(segment_count);
    let mut store = format(device.clone(), limits, reserve);
    let handle = block_on(store.put(
        OBJECT_KIND,
        root(b"committed-before-fault"),
        b"committed-before-fault",
    ))
    .expect("seed put must commit");
    let info = store.info().unwrap();
    device.power_cycle();
    (device, handle, info)
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn assert_exact_old_or_new(
    device: FaultDevice,
    limits: StoreLimits,
    old_handle: &ObjectHandle,
    old_info: StoreInfo,
    case: &str,
) {
    device.power_cycle();
    let mut recovered = SegmentStore::new(device, limits);
    let info = block_on(recovered.mount())
        .unwrap_or_else(|error| panic!("{case}: cold mount failed: {error:?}"));
    assert!(
        (info.generation == old_info.generation && info.object_count == old_info.object_count)
            || (info.generation == old_info.generation + 1
                && info.object_count == old_info.object_count + 1),
        "mixed checkpoint/catalog state after recovery: old={old_info:?}, recovered={info:?}"
    );
    assert_eq!(
        block_on(recovered.get(old_handle)).unwrap(),
        b"committed-before-fault"
    );
}

fn assert_unformatted_or_exact_empty(device: FaultDevice, limits: StoreLimits, case: &str) {
    device.power_cycle();
    let mut recovered = SegmentStore::new(device, limits);
    match block_on(recovered.mount()) {
        Ok(info) => {
            assert_eq!(info.generation, 1, "{case}: wrong formatted generation");
            assert_eq!(info.object_count, 0, "{case}: format published objects");
            assert_eq!(info.replay_count, 0, "{case}: format published replay");
        }
        Err(StoreError::Unformatted) => {}
        Err(error) => panic!("{case}: partial format did not fail atomically: {error:?}"),
    }
}

#[test]
fn every_format_write_and_flush_boundary_is_atomic_under_fault_or_cancel() {
    let limits = limits();
    let probe_device = FaultDevice::blank(6);
    let mut probe = SegmentStore::new(probe_device.clone(), limits);
    probe_device.reset_mutation_count();
    block_on(probe.format(options(limits, 2))).unwrap();
    let boundary_count = probe_device.mutation_count();
    assert!(boundary_count >= 8);

    let actions = [
        FaultAction::FailNotSubmitted,
        FaultAction::FailAmbiguous(Effect::None),
        FaultAction::FailAmbiguous(Effect::Visible),
        FaultAction::FailAmbiguous(Effect::Durable),
    ];
    for boundary in 0..boundary_count {
        for action in actions {
            let device = FaultDevice::blank(6);
            device.arm(boundary, action);
            let mut store = SegmentStore::new(device.clone(), limits);
            assert!(block_on(store.format(options(limits, 2))).is_err());
            assert_eq!(store.info(), Err(StoreError::RecoveryRequired));
            let case = format!("format mutation {boundary}, action {action:?}");
            assert_unformatted_or_exact_empty(device, limits, &case);
        }
        for effect in [Effect::None, Effect::Visible, Effect::Durable] {
            let device = FaultDevice::blank(6);
            device.arm(boundary, FaultAction::Pending(effect));
            let mut store = SegmentStore::new(device.clone(), limits);
            let mut format = Box::pin(store.format(options(limits, 2)));
            assert_eq!(poll_once(format.as_mut()), Poll::Pending);
            drop(format);
            assert_eq!(store.info(), Err(StoreError::RecoveryRequired));
            let case = format!("format mutation {boundary}, pending effect {effect:?}");
            assert_unformatted_or_exact_empty(device, limits, &case);
        }
    }
}

#[test]
fn every_put_write_and_flush_boundary_recovers_an_exact_checkpoint() {
    let limits = limits();
    let (seed_device, old_handle, old_info) = seeded_store(24, limits, 2);
    let seed_image = seed_device.durable_image();
    let page_count = seed_device.page_count();

    let probe_device = FaultDevice::from_durable(page_count, seed_image.clone());
    let (mut probe, _) = mount(probe_device.clone(), limits);
    probe_device.reset_mutation_count();
    block_on(probe.put(
        OBJECT_KIND,
        root(b"transaction-under-test"),
        b"transaction-under-test",
    ))
    .unwrap();
    let boundary_count = probe_device.mutation_count();
    assert!(
        boundary_count > 4,
        "test must cover a real ordered transaction"
    );

    let actions = [
        FaultAction::FailNotSubmitted,
        FaultAction::FailAmbiguous(Effect::None),
        FaultAction::FailAmbiguous(Effect::Visible),
        FaultAction::FailAmbiguous(Effect::Durable),
    ];
    for boundary in 0..boundary_count {
        for action in actions {
            let device = FaultDevice::from_durable(page_count, seed_image.clone());
            let (mut store, _) = mount(device.clone(), limits);
            device.arm(boundary, action);
            let result = block_on(store.put(
                OBJECT_KIND,
                root(b"transaction-under-test"),
                b"transaction-under-test",
            ));
            assert!(
                result.is_err(),
                "fault at mutation {boundary} was not reached ({action:?})"
            );
            assert_eq!(store.info(), Err(StoreError::RecoveryRequired));
            let case = format!("mutation {boundary}, action {action:?}");
            assert_exact_old_or_new(device, limits, &old_handle, old_info, &case);
        }
    }
}

#[test]
fn cancellation_at_every_put_mutation_invalidates_cursors_and_recovers() {
    let limits = limits();
    let (seed_device, old_handle, old_info) = seeded_store(24, limits, 2);
    let seed_image = seed_device.durable_image();
    let page_count = seed_device.page_count();

    let probe_device = FaultDevice::from_durable(page_count, seed_image.clone());
    let (mut probe, _) = mount(probe_device.clone(), limits);
    probe_device.reset_mutation_count();
    block_on(probe.put(OBJECT_KIND, root(b"cancelled-put"), b"cancelled-put")).unwrap();
    let boundary_count = probe_device.mutation_count();

    for boundary in 0..boundary_count {
        for effect in [Effect::None, Effect::Visible, Effect::Durable] {
            let device = FaultDevice::from_durable(page_count, seed_image.clone());
            let (mut store, _) = mount(device.clone(), limits);
            device.arm(boundary, FaultAction::Pending(effect));
            let mut put =
                Box::pin(store.put(OBJECT_KIND, root(b"cancelled-put"), b"cancelled-put"));
            assert_eq!(poll_once(put.as_mut()), Poll::Pending);
            drop(put);
            assert_eq!(store.info(), Err(StoreError::RecoveryRequired));
            let case = format!("mutation {boundary}, pending effect {effect:?}");
            assert_exact_old_or_new(device, limits, &old_handle, old_info, &case);
        }
    }
}

#[test]
fn orphan_segment_zero_does_not_break_a_chain_starting_at_segment_one() {
    let limits = limits();
    let device = FaultDevice::blank(8);
    drop(format(device.clone(), limits, 2));
    device.power_cycle();

    let (mut interrupted, before) = mount(device.clone(), limits);
    // Boundary 30 is the final segment publication write: the segment is
    // durable, but the checkpoint still names the empty store.
    device.arm(30, FaultAction::Pending(Effect::Durable));
    let mut put = Box::pin(interrupted.put(
        OBJECT_KIND,
        root(b"unpublished-segment-zero"),
        b"unpublished-segment-zero",
    ));
    assert_eq!(poll_once(put.as_mut()), Poll::Pending);
    drop(put);
    assert_eq!(interrupted.info(), Err(StoreError::RecoveryRequired));
    device.power_cycle();
    let (mut recovered, after_orphan) = mount(device.clone(), limits);
    assert_eq!(after_orphan.generation, before.generation);
    assert_eq!(after_orphan.object_count, 0);
    assert_eq!(after_orphan.allocated_segments, 1);

    let committed = b"first-finalized-chain-member";
    let handle = block_on(recovered.put(OBJECT_KIND, root(committed), committed)).unwrap();
    assert_eq!(recovered.info().unwrap().allocated_segments, 2);

    device.power_cycle();
    let (cold, info) = mount(device, limits);
    assert_eq!(info.generation, before.generation + 1);
    assert_eq!(info.object_count, 1);
    assert_eq!(block_on(cold.get(&handle)).unwrap(), committed);
}

#[test]
fn first_not_submitted_restart_and_read_failures_have_explicit_state() {
    let limits = limits();
    let (seed_device, old_handle, old_info) = seeded_store(12, limits, 2);
    let seed_image = seed_device.durable_image();
    let page_count = seed_device.page_count();
    let attempted = b"attempt-after-seed";

    let not_submitted_device = FaultDevice::from_durable(page_count, seed_image.clone());
    let (mut not_submitted, _) = mount(not_submitted_device.clone(), limits);
    not_submitted_device.arm(0, FaultAction::FailNotSubmitted);
    let failure = block_on(not_submitted.put(OBJECT_KIND, root(attempted), attempted))
        .expect_err("the first write must be rejected before submission");
    match failure {
        StoreError::Mutation(failure) => {
            assert_eq!(failure.certainty(), MutationCertainty::NotSubmitted);
            assert_eq!(failure.error(), &TestError::Injected);
        }
        error => panic!("wrong first-write error: {error:?}"),
    }
    assert_eq!(not_submitted.info(), Err(StoreError::RecoveryRequired));
    assert_exact_old_or_new(
        not_submitted_device,
        limits,
        &old_handle,
        old_info,
        "first mutation not submitted",
    );

    let restarted_device = FaultDevice::from_durable(page_count, seed_image.clone());
    let (mut restarted, _) = mount(restarted_device.clone(), limits);
    restarted_device.arm(0, FaultAction::FailAmbiguous(Effect::Visible));
    let failure = block_on(restarted.put(OBJECT_KIND, root(attempted), attempted))
        .expect_err("driver restart must fail the transaction");
    match failure {
        StoreError::Mutation(failure) => {
            assert_eq!(failure.certainty(), MutationCertainty::Ambiguous);
            assert_eq!(failure.error(), &TestError::DriverRestarted);
        }
        error => panic!("wrong restart error: {error:?}"),
    }
    assert_eq!(restarted.info(), Err(StoreError::RecoveryRequired));
    assert_exact_old_or_new(
        restarted_device,
        limits,
        &old_handle,
        old_info,
        "driver restart",
    );

    let read_device = FaultDevice::from_durable(page_count, seed_image);
    let (reader, mounted_info) = mount(read_device.clone(), limits);
    read_device.arm_read(0);
    assert_eq!(
        block_on(reader.get(&old_handle)),
        Err(StoreError::Device(TestError::ReadFailed))
    );
    assert_eq!(reader.info().unwrap(), mounted_info);
    read_device.clear_read_fault();
    assert_eq!(
        block_on(reader.get(&old_handle)).unwrap(),
        b"committed-before-fault"
    );

    read_device.power_cycle();
    read_device.arm_read(0);
    let mut remount = SegmentStore::new(read_device.clone(), limits);
    assert_eq!(
        block_on(remount.mount()),
        Err(StoreError::Device(TestError::ReadFailed))
    );
    assert_eq!(remount.info(), Err(StoreError::NotMounted));
    read_device.clear_read_fault();
    let remounted = block_on(remount.mount()).unwrap();
    assert_eq!(remounted.generation, old_info.generation);
    assert_eq!(remounted.object_count, old_info.object_count);
    assert_eq!(remounted.allocated_segments, old_info.allocated_segments);
}

#[test]
fn capacity_errors_name_payload_metadata_and_cleaner_reserve() {
    let payload_limits = StoreLimits {
        max_compat_object_bytes: 8,
        ..limits()
    };
    let payload_device = FaultDevice::blank(8);
    let mut payload_store = format(payload_device, payload_limits, 2);
    assert_eq!(
        block_on(payload_store.put(OBJECT_KIND, root(&[0; 9]), &[0; 9])),
        Err(StoreError::Capacity(CapacityClass::Payload))
    );

    let metadata_limits = StoreLimits {
        max_catalog_entries: 1,
        ..limits()
    };
    let metadata_device = FaultDevice::blank(8);
    let mut metadata_store = format(metadata_device, metadata_limits, 2);
    block_on(metadata_store.put(OBJECT_KIND, root(b"first"), b"first")).unwrap();
    let before = metadata_store.info().unwrap();
    assert_eq!(
        block_on(metadata_store.put(OBJECT_KIND, root(b"second"), b"second")),
        Err(StoreError::Capacity(CapacityClass::Metadata))
    );
    assert_eq!(metadata_store.info().unwrap(), before);

    let reserve_limits = limits();
    let reserve_device = FaultDevice::blank(5);
    let mut reserve_store = format(reserve_device, reserve_limits, 2);
    let mut saw_reserve = false;
    for index in 0..8_u8 {
        let before = reserve_store.info().unwrap();
        match block_on(reserve_store.put(OBJECT_KIND, root(&[index]), &[index])) {
            Ok(_) => {}
            Err(StoreError::Capacity(CapacityClass::CleanerReserve)) => {
                assert_eq!(reserve_store.info().unwrap(), before);
                saw_reserve = true;
                break;
            }
            Err(error) => panic!("wrong capacity class before cleaner reserve: {error:?}"),
        }
    }
    assert!(saw_reserve, "ordinary puts consumed the cleaner reserve");
}

#[test]
fn dense_recovery_reports_and_enforces_its_memory_ceiling() {
    let limits = limits();
    let device = FaultDevice::blank(24);
    let mut store = format(device.clone(), limits, 2);
    let mut handles = Vec::new();
    for index in 0..12_u8 {
        handles.push(
            block_on(store.put(OBJECT_KIND, root(&[index; 32]), &[index; 32]))
                .expect("dense append must fit"),
        );
    }
    device.power_cycle();
    let image = device.durable_image();
    let (recovered, info) = mount(
        FaultDevice::from_durable(device.page_count(), image.clone()),
        limits,
    );
    assert_eq!(info.object_count, handles.len() as u32);
    assert!(info.recovery_peak_bytes > 0);
    assert!(info.recovery_peak_bytes <= limits.recovery_memory_bytes);
    for (index, handle) in handles.iter().enumerate() {
        assert_eq!(
            block_on(recovered.get(handle)).unwrap(),
            vec![index as u8; 32]
        );
    }

    let exact = StoreLimits {
        recovery_memory_bytes: info.recovery_peak_bytes,
        ..limits
    };
    let (_, exact_info) = mount(
        FaultDevice::from_durable(device.page_count(), image.clone()),
        exact,
    );
    assert_eq!(exact_info.recovery_peak_bytes, info.recovery_peak_bytes);

    let too_small = StoreLimits {
        recovery_memory_bytes: info.recovery_peak_bytes - 1,
        ..limits
    };
    let mut refused = SegmentStore::new(
        FaultDevice::from_durable(device.page_count(), image),
        too_small,
    );
    assert_eq!(block_on(refused.mount()), Err(StoreError::MemoryLimit));
}

#[test]
fn replay_merge_reports_and_enforces_its_aggregate_memory_ceiling() {
    let limits = limits();
    let device = FaultDevice::blank(12);
    let mut store = format(device.clone(), limits, 2);
    block_on(store.put(OBJECT_KIND, root(b"snapshot"), b"snapshot")).unwrap();
    block_on(store.put(OBJECT_KIND, root(b"replay"), b"replay")).unwrap();
    assert_eq!(store.info().unwrap().replay_count, 1);
    device.power_cycle();
    let image = device.durable_image();

    let (_, info) = mount(
        FaultDevice::from_durable(device.page_count(), image.clone()),
        limits,
    );
    assert_eq!(info.object_count, 2);
    assert_eq!(info.replay_count, 1);

    let exact = StoreLimits {
        recovery_memory_bytes: info.recovery_peak_bytes,
        ..limits
    };
    let (_, exact_info) = mount(
        FaultDevice::from_durable(device.page_count(), image.clone()),
        exact,
    );
    assert_eq!(exact_info.recovery_peak_bytes, info.recovery_peak_bytes);

    let too_small = StoreLimits {
        recovery_memory_bytes: info.recovery_peak_bytes - 1,
        ..limits
    };
    let mut refused = SegmentStore::new(
        FaultDevice::from_durable(device.page_count(), image),
        too_small,
    );
    assert_eq!(block_on(refused.mount()), Err(StoreError::MemoryLimit));
}

#[test]
fn production_image_is_reconstructed_by_the_independent_python_verifier() {
    let limits = limits();
    let device = FaultDevice::blank(6);
    let mut store = format(device.clone(), limits, 2);
    let first = b"rust-writer-python-reader-one";
    let second = b"rust-writer-python-reader-two";
    block_on(store.put(OBJECT_KIND, root(first), first)).unwrap();
    block_on(store.put(OBJECT_KIND + 1, root(second), second)).unwrap();
    device.power_cycle();

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let image_path = std::env::temp_dir().join(format!(
        "vibeos-storage-v2-{}-{unique}.img",
        std::process::id()
    ));
    let mut image = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&image_path)
        .unwrap();
    image.set_len(device.page_count() * 4096).unwrap();
    for (page_no, page) in device.durable_image() {
        image.seek(SeekFrom::Start(page_no * 4096)).unwrap();
        image.write_all(&page).unwrap();
    }
    image.sync_all().unwrap();
    drop(image);

    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output = Command::new("python3")
        .arg("-B")
        .arg(repository.join("scripts/storage-v2-image.py"))
        .arg(&image_path)
        .output()
        .unwrap();
    std::fs::remove_file(&image_path).unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "independent verifier rejected production image: {stdout}"
    );
    assert!(stdout.contains("\"status\":\"ok\""), "{stdout}");
    assert!(stdout.contains("\"object_count\":2"), "{stdout}");
    assert!(stdout.contains(&hex(&root(first))), "{stdout}");
    assert!(stdout.contains(&hex(&root(second))), "{stdout}");
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}
