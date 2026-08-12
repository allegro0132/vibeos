use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::Future;
use core::task::{Context, Poll, Waker};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use vibeos_segment_format::{admitted_pages, Page, StoreUuid, PAGE_SIZE};
use vibeos_storage_device::MutationFailure;

use crate::{
    canonical_attributable_physical_bytes, AuthorizedPublication, CasCommitError, CasObjectHandle,
    CasStoreError, FormatOptions, GcError, GcStoreError, GcTimeSource,
    ObjectPublicationPersistence, ObjectPublicationTarget, PageDevice, PageDeviceInfo,
    PrincipalQuotaLimits, PublicationIntent, PublishError, QuotaError, RuntimeObjectPinClass,
    ScrubStatus, SegmentStore, StoppedRuntimePinOwner, StoreError, StoreLimits,
    StoreRuntimeContext, QUOTA_DEDUP_UNIQUE_OBJECT_BYTES,
};

const OBJECT_KIND: u32 = 0x5155_4f54;
const TYPED_KIND: u32 = 0x5155_5459;

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
}

#[derive(Clone)]
struct Media {
    page_count: u64,
    pages: BTreeMap<u64, Page>,
    mutations: usize,
}

#[derive(Clone)]
struct MemoryDevice(Arc<Mutex<Media>>);

impl MemoryDevice {
    fn blank(segments: u64) -> Self {
        Self(Arc::new(Mutex::new(Media {
            page_count: admitted_pages(segments).unwrap(),
            pages: BTreeMap::new(),
            mutations: 0,
        })))
    }

    fn reset_mutations(&self) {
        self.0.lock().unwrap().mutations = 0;
    }

    fn mutations(&self) -> usize {
        self.0.lock().unwrap().mutations
    }
}

impl PageDevice for MemoryDevice {
    type Error = TestError;

    fn info(&self) -> PageDeviceInfo {
        let page_count = self.0.lock().unwrap().page_count;
        PageDeviceInfo {
            device_id: [0x71; 16],
            range_first_logical_block: 128,
            logical_block_count: page_count * 8,
            logical_block_size: 512,
            page_count,
        }
    }

    async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
        let media = self.0.lock().unwrap();
        if page >= media.page_count {
            return Err(TestError::OutsideRange);
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
        media.mutations += 1;
        media.pages.insert(page, *input);
        Ok(())
    }

    async fn flush(&self) -> Result<(), MutationFailure<Self::Error>> {
        self.0.lock().unwrap().mutations += 1;
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

fn format_governed(
    segments: u64,
    typed: bool,
) -> (
    SegmentStore<MemoryDevice>,
    MemoryDevice,
    crate::StorageQuotaProvisioner,
) {
    let device = MemoryDevice::blank(segments);
    let (runtime, provisioner) = if typed {
        StoreRuntimeContext::governed_with_typed_reference_kinds(&[TYPED_KIND]).unwrap()
    } else {
        StoreRuntimeContext::governed().unwrap()
    };
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(*b"M7.6-QUOTA-TEST!").unwrap(),
        cleaner_reserve_segments: 4,
        limits: limits(),
    }))
    .unwrap();
    (store, device, provisioner)
}

fn quota_limits(logical_bytes: u64, physical_bytes: u64) -> PrincipalQuotaLimits {
    PrincipalQuotaLimits {
        logical_bytes,
        physical_bytes,
    }
}

fn payload() -> Vec<u8> {
    (0..PAGE_SIZE + 37)
        .map(|index| (index.wrapping_mul(31) ^ (index >> 2)) as u8)
        .collect()
}

fn commit(
    store: &mut SegmentStore<MemoryDevice>,
    principal: &crate::StoragePrincipal,
    bytes: &[u8],
) -> crate::AuthorizedObject<crate::CasObjectHandle> {
    let mut writer = store
        .begin_blob_for_principal(principal, OBJECT_KIND, bytes.len() as u64, None)
        .unwrap();
    for chunk in bytes.chunks(PAGE_SIZE) {
        block_on(writer.write_chunk(chunk)).unwrap();
    }
    block_on(writer.commit()).unwrap()
}

struct Clock;

impl GcTimeSource for Clock {
    fn monotonic_ns(&self) -> u64 {
        1
    }
}

struct RejectPublication;
struct PersistentPublication;

impl ObjectPublicationTarget<CasObjectHandle> for RejectPublication {
    type Capability = ();
    type Error = ();

    fn incarnation(&self) -> u64 {
        1
    }

    fn persistence(&self) -> ObjectPublicationPersistence {
        ObjectPublicationPersistence::RuntimeOnly
    }

    fn publish_independent_root(
        &self,
        _publication: AuthorizedPublication<Self, CasObjectHandle>,
    ) -> Result<Self::Capability, PublishError<Self::Error>> {
        Err(PublishError::Target(()))
    }
}

impl ObjectPublicationTarget<CasObjectHandle> for PersistentPublication {
    type Capability = ();
    type Error = ();

    fn incarnation(&self) -> u64 {
        1
    }

    fn persistence(&self) -> ObjectPublicationPersistence {
        ObjectPublicationPersistence::Persistent
    }

    fn publish_independent_root(
        &self,
        _publication: AuthorizedPublication<Self, CasObjectHandle>,
    ) -> Result<Self::Capability, PublishError<Self::Error>> {
        Ok(())
    }
}

#[test]
fn exact_limits_admit_and_one_byte_over_denies_before_media_mutation() {
    let bytes = payload();
    let exact_len = bytes.len() as u64;
    let physical = canonical_attributable_physical_bytes(exact_len).unwrap();
    let (mut store, device, provisioner) = format_governed(16, false);

    let logical_short = provisioner
        .admit_principal(quota_limits(exact_len - 1, physical))
        .unwrap();
    device.reset_mutations();
    assert!(matches!(
        store.begin_blob_for_principal(&logical_short, OBJECT_KIND, exact_len, None),
        Err(CasStoreError::Quota(QuotaError::LogicalQuotaExceeded))
    ));
    assert_eq!(device.mutations(), 0);

    let physical_short = provisioner
        .admit_principal(quota_limits(exact_len, physical - 1))
        .unwrap();
    assert!(matches!(
        store.begin_blob_for_principal(&physical_short, OBJECT_KIND, exact_len, None),
        Err(CasStoreError::Quota(QuotaError::PhysicalQuotaExceeded))
    ));
    assert_eq!(device.mutations(), 0);

    let exact = provisioner
        .admit_principal(quota_limits(exact_len, physical))
        .unwrap();
    let quota = store.quota.clone().unwrap();
    let writer = store
        .begin_blob_for_principal(&exact, OBJECT_KIND, exact_len, None)
        .unwrap();
    assert_eq!(device.mutations(), 0);
    let usage = quota.principal_usage(&exact).unwrap();
    assert_eq!(usage.reserved_logical_bytes, exact_len);
    assert_eq!(usage.reserved_physical_bytes, physical);
    drop(writer);
    assert_eq!(
        store
            .principal_quota_usage(&exact)
            .unwrap()
            .reserved_logical_bytes,
        0
    );
    assert_eq!(device.mutations(), 0);
}

#[test]
fn governed_unprincipal_paths_and_ordinary_floor_fail_before_io() {
    let (mut store, device, provisioner) = format_governed(6, true);
    device.reset_mutations();
    assert!(matches!(
        store.begin_blob(OBJECT_KIND, 1, None),
        Err(CasStoreError::Store(StoreError::PrincipalRequired))
    ));
    assert!(matches!(
        block_on(store.begin_blob_with_foreground_gc(OBJECT_KIND, 1, None, &Clock)),
        Err(crate::ForegroundBlobError::Cas(CasStoreError::Store(
            StoreError::PrincipalRequired
        )))
    ));
    assert!(matches!(
        block_on(store.commit_typed_manifest(TYPED_KIND, &[])),
        Err(crate::TypedCommitError::Store(CasStoreError::Store(
            StoreError::PrincipalRequired
        )))
    ));
    assert!(matches!(
        block_on(store.commit_typed_manifest_with_foreground_gc(TYPED_KIND, &[], &Clock)),
        Err(crate::TypedCommitError::Store(CasStoreError::Store(
            StoreError::PrincipalRequired
        )))
    ));
    assert!(matches!(
        block_on(store.put(OBJECT_KIND, [0; 32], &[])),
        Err(StoreError::PrincipalRequired)
    ));
    assert_eq!(device.mutations(), 0);

    let floor_probe_len = vibeos_segment_format::SEGMENT_PAGES * PAGE_SIZE as u64;
    let physical = canonical_attributable_physical_bytes(floor_probe_len).unwrap();
    let principal = provisioner
        .admit_principal(quota_limits(floor_probe_len, physical))
        .unwrap();
    match block_on(store.begin_blob_with_foreground_gc_for_principal(
        &principal,
        OBJECT_KIND,
        floor_probe_len,
        None,
        &Clock,
    )) {
        Err(crate::ForegroundBlobError::Cas(CasStoreError::Quota(
            QuotaError::OrdinaryCapacityExceeded,
        ))) => {}
        Err(error) => panic!("unexpected foreground floor error: {error:?}"),
        Ok((writer, _)) => {
            drop(writer);
            panic!("ordinary floor unexpectedly admitted a writer")
        }
    }
    assert_eq!(
        device.mutations(),
        0,
        "quota floor denial must not start GC"
    );
}

#[test]
fn two_principal_dedup_charges_full_envelope_and_releases_independently() {
    let bytes = payload();
    let exact_len = bytes.len() as u64;
    let physical = canonical_attributable_physical_bytes(exact_len).unwrap();
    let (mut store, _device, provisioner) = format_governed(16, false);
    let first = provisioner
        .admit_principal(quota_limits(exact_len, physical))
        .unwrap();
    let second = provisioner
        .admit_principal(quota_limits(exact_len, physical))
        .unwrap();

    let first_object = commit(&mut store, &first, &bytes);
    let second_object = commit(&mut store, &second, &bytes);
    assert_eq!(
        store
            .principal_quota_usage(&first)
            .unwrap()
            .committed_physical_bytes,
        physical
    );
    assert_eq!(
        store
            .principal_quota_usage(&second)
            .unwrap()
            .committed_physical_bytes,
        physical
    );
    let diagnostics = store.quota_diagnostics().unwrap();
    assert_eq!(diagnostics.committed_physical_bytes, physical * 2);
    assert_eq!(
        diagnostics.cumulative_unique_physical_bytes,
        physical + QUOTA_DEDUP_UNIQUE_OBJECT_BYTES
    );
    assert_eq!(
        diagnostics.cumulative_dedup_savings_bytes,
        physical - QUOTA_DEDUP_UNIQUE_OBJECT_BYTES
    );
    let maintenance = store
        .mint_maintenance_root()
        .unwrap()
        .attenuate(&[crate::MaintenanceOperation::Scrub])
        .unwrap();
    let scrub = block_on(store.scrub(&maintenance)).unwrap();
    assert_eq!(scrub.status, ScrubStatus::Healthy);
    assert_eq!(scrub.quota_logical_high_water_bytes, exact_len * 2);
    assert_eq!(scrub.quota_physical_high_water_bytes, physical * 2);

    drop(first_object);
    assert_eq!(
        store
            .principal_quota_usage(&first)
            .unwrap()
            .committed_physical_bytes,
        0
    );
    assert_eq!(
        store
            .principal_quota_usage(&second)
            .unwrap()
            .committed_physical_bytes,
        physical
    );
    drop(second_object);
    assert_eq!(
        store
            .principal_quota_usage(&second)
            .unwrap()
            .committed_physical_bytes,
        0
    );
}

#[test]
fn runtime_pin_keeps_charge_and_unrelated_reads_survive_another_principal_denial() {
    let bytes = payload();
    let exact_len = bytes.len() as u64;
    let physical = canonical_attributable_physical_bytes(exact_len).unwrap();
    let (mut store, device, provisioner) = format_governed(16, false);
    let owner = provisioner
        .admit_principal(quota_limits(exact_len, physical))
        .unwrap();
    let denied = provisioner
        .admit_principal(quota_limits(exact_len - 1, physical))
        .unwrap();
    let object = commit(&mut store, &owner, &bytes);
    let pin = store
        .pin_runtime_object(&object, RuntimeObjectPinClass::InvocationLease)
        .unwrap();
    device.reset_mutations();
    assert!(matches!(
        store.begin_blob_for_principal(&denied, OBJECT_KIND, exact_len, None),
        Err(CasStoreError::Quota(QuotaError::LogicalQuotaExceeded))
    ));
    let chunk = block_on(store.get_blob_chunk(&object, 0)).unwrap();
    assert_eq!(chunk.bytes, bytes[..PAGE_SIZE]);
    assert_eq!(device.mutations(), 0);

    drop(object);
    assert_eq!(
        store
            .principal_quota_usage(&owner)
            .unwrap()
            .committed_physical_bytes,
        physical
    );
    drop(pin);
    assert_eq!(
        store
            .principal_quota_usage(&owner)
            .unwrap()
            .committed_physical_bytes,
        0
    );
}

#[test]
fn stopped_fault_domain_releases_leaked_runtime_pin_charge() {
    let bytes = payload();
    let exact_len = bytes.len() as u64;
    let physical = canonical_attributable_physical_bytes(exact_len).unwrap();
    let (mut store, _device, provisioner) = format_governed(16, false);
    let principal = provisioner
        .admit_principal(quota_limits(exact_len, physical))
        .unwrap();
    let object = commit(&mut store, &principal, &bytes);
    let owner = store.allocate_runtime_pin_owner().unwrap();
    let leaked = store
        .pin_runtime_object_owned(&object, RuntimeObjectPinClass::InvocationLease, &owner)
        .unwrap();
    core::mem::forget(leaked);
    drop(object);
    assert_eq!(
        store
            .principal_quota_usage(&principal)
            .unwrap()
            .committed_physical_bytes,
        physical
    );

    // SAFETY: the modeled fault domain has synchronously stopped, so its
    // forgotten runtime pin can never execute a destructor concurrently.
    let stopped = unsafe { StoppedRuntimePinOwner::after_synchronous_join(owner) };
    let released = store.release_stopped_runtime_pins(stopped).unwrap();
    assert_eq!(released.roots, 1);
    assert_eq!(released.readers, 0);
    assert_eq!(
        store
            .principal_quota_usage(&principal)
            .unwrap()
            .committed_physical_bytes,
        0
    );
}

#[test]
fn boot_local_charges_cannot_enter_persistent_root_policy() {
    let bytes = payload();
    let exact_len = bytes.len() as u64;
    let physical = canonical_attributable_physical_bytes(exact_len).unwrap();
    let (mut store, device, provisioner) = format_governed(16, false);
    let principal = provisioner
        .admit_principal(quota_limits(exact_len, physical))
        .unwrap();
    let object = commit(&mut store, &principal, &bytes);

    device.reset_mutations();
    assert!(matches!(
        block_on(store.synchronize_gc_roots(&[&object])),
        Err(GcStoreError::Gc(GcError::QuotaPersistenceUnavailable))
    ));
    assert_eq!(device.mutations(), 0);
    assert!(matches!(
        block_on(store.collect_garbage_with_initial_roots(&[&object])),
        Err(GcStoreError::Gc(GcError::QuotaPersistenceUnavailable))
    ));
    assert_eq!(device.mutations(), 0);
}

#[test]
fn persistent_publication_target_is_rejected_before_writer_mutation() {
    let exact_len = 1;
    let physical = canonical_attributable_physical_bytes(exact_len).unwrap();
    let (mut store, device, provisioner) = format_governed(16, false);
    let principal = provisioner
        .admit_principal(quota_limits(exact_len, physical))
        .unwrap();
    let writer = store
        .begin_blob_for_principal(&principal, OBJECT_KIND, exact_len, None)
        .unwrap();
    device.reset_mutations();
    let intent = PublicationIntent::capture(Arc::new(PersistentPublication));
    assert!(matches!(
        block_on(writer.commit_to(intent)),
        Err(CasCommitError::Store(CasStoreError::Store(
            StoreError::QuotaPersistenceUnavailable
        )))
    ));
    assert_eq!(device.mutations(), 0);
    let usage = store.principal_quota_usage(&principal).unwrap();
    assert_eq!(usage.reserved_logical_bytes, 0);
    assert_eq!(usage.committed_logical_bytes, 0);
}

#[test]
fn attenuation_only_reduces_effective_ceiling() {
    let physical = canonical_attributable_physical_bytes(10).unwrap();
    let (_store, _device, provisioner) = format_governed(16, false);
    let principal = provisioner
        .admit_principal(quota_limits(20, physical * 2))
        .unwrap();
    assert!(principal.attenuate(quota_limits(21, physical * 2)).is_err());
    let reduced = principal.attenuate(quota_limits(10, physical)).unwrap();
    assert_eq!(reduced.ceilings(), quota_limits(10, physical));
}

#[test]
fn cancellation_after_staging_rolls_back_and_publish_failure_releases_charge() {
    let bytes = payload();
    let exact_len = bytes.len() as u64;
    let physical = canonical_attributable_physical_bytes(exact_len).unwrap();
    let (mut store, _device, provisioner) = format_governed(16, false);
    let principal = provisioner
        .admit_principal(quota_limits(exact_len * 2, physical * 2))
        .unwrap();
    let quota = store.quota.clone().unwrap();

    let mut abandoned = store
        .begin_blob_for_principal(&principal, OBJECT_KIND, exact_len, None)
        .unwrap();
    block_on(abandoned.write_chunk(&bytes[..PAGE_SIZE])).unwrap();
    assert_eq!(
        quota
            .principal_usage(&principal)
            .unwrap()
            .reserved_physical_bytes,
        physical
    );
    drop(abandoned);
    assert_eq!(
        quota
            .principal_usage(&principal)
            .unwrap()
            .reserved_physical_bytes,
        0
    );
    block_on(store.mount()).unwrap();

    let intent = PublicationIntent::capture(Arc::new(RejectPublication));
    let mut writer = store
        .begin_blob_for_principal(&principal, OBJECT_KIND, exact_len, None)
        .unwrap();
    for chunk in bytes.chunks(PAGE_SIZE) {
        block_on(writer.write_chunk(chunk)).unwrap();
    }
    assert!(matches!(
        block_on(writer.commit_to(intent)),
        Err(CasCommitError::Publish(PublishError::Target(())))
    ));
    let usage = store.principal_quota_usage(&principal).unwrap();
    assert_eq!(usage.committed_logical_bytes, 0);
    assert_eq!(usage.committed_physical_bytes, 0);
    assert_eq!(store.info().unwrap().object_count, 1);
}

#[test]
fn same_runtime_remount_preserves_charge_and_fresh_runtime_cannot_resolve_authority() {
    let bytes = payload();
    let exact_len = bytes.len() as u64;
    let physical = canonical_attributable_physical_bytes(exact_len).unwrap();
    let (mut store, device, provisioner) = format_governed(16, false);
    let principal = provisioner
        .admit_principal(quota_limits(exact_len, physical))
        .unwrap();
    let object = commit(&mut store, &principal, &bytes);
    let runtime = store.runtime_context();
    drop(store);

    let mut remounted = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(remounted.mount()).unwrap();
    assert_eq!(
        remounted
            .principal_quota_usage(&principal)
            .unwrap()
            .committed_physical_bytes,
        physical
    );
    assert_eq!(
        block_on(remounted.get_blob_chunk(&object, 0))
            .unwrap()
            .bytes,
        bytes[..PAGE_SIZE]
    );
    drop(remounted);

    let (fresh_runtime, _fresh_provisioner) = StoreRuntimeContext::governed().unwrap();
    let mut fresh = SegmentStore::new_with_runtime_context(device, limits(), fresh_runtime);
    block_on(fresh.mount()).unwrap();
    assert_eq!(
        fresh.principal_quota_usage(&principal),
        Err(QuotaError::UnknownPrincipal)
    );
    assert!(matches!(
        block_on(fresh.get_blob_chunk(&object, 0)),
        Err(CasStoreError::Store(StoreError::ObjectUnavailable))
    ));
    drop(object);
}
