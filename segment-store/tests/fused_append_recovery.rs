//! Crash-boundary coverage for the fused durable-append fast path.
//!
//! The fused path publishes a fresh CAS object and the successor authority
//! snapshot under one metadata segment and one checkpoint, deferring the
//! per-phase segment flushes into the checkpoint slot protocol's first
//! barrier. This test cuts power at every device mutation boundary of one
//! such append against a volatile/durable fault media model and requires
//! recovery to yield exactly the predecessor or the successor authority
//! state — never a mixture — and the store to resume appends afterwards.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use vibeos_durable_format::{
    encode_object_transaction, preview_grant_transaction, DerivationId, DurableRights, GrantFlags,
    GrantRecord, ObjectId, ObjectKind, RecordBody, RecordChain, ResourceKind, RootPolicy,
    SlotIdentity, SpaceId, StoreId, TransactionId,
};
use vibeos_segment_format::{admitted_pages, Page, StoreUuid};
use vibeos_segment_store::{
    root_policy_commitment, FormatOptions, PageDevice, PageDeviceInfo, PersistentAuthorityImport,
    SegmentStore, StoreLimits, StoreRuntimeContext, LEGACY_SYSTEM_PRINCIPAL,
};
use vibeos_storage_device::MutationFailure;

const SEGMENTS: u64 = 20;
const OBJECT_KIND_RAW: u32 = 0x4655_5345;
const POLICY: &[u8] = b"fused append recovery policy v1";

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

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestError {
    OutsideRange,
}

impl core::fmt::Display for TestError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{:?}", self)
    }
}

/// Power-cut media model: ordinary writes land in the volatile image only;
/// a flush copies the volatile image into the durable one; a power cycle
/// discards everything volatile. One armed boundary makes that mutation hang
/// with no effect, modelling a cut immediately before it takes hold.
#[derive(Clone)]
struct FaultMedia {
    page_count: u64,
    durable: BTreeMap<u64, Page>,
    visible: BTreeMap<u64, Page>,
    mutation_count: usize,
    cut_at: Option<usize>,
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
                cut_at: None,
            })),
        }
    }

    fn arm(&self, boundary: usize) {
        let mut media = self.media.lock().unwrap();
        media.mutation_count = 0;
        media.cut_at = Some(boundary);
    }

    fn mutation_count(&self) -> usize {
        self.media.lock().unwrap().mutation_count
    }

    fn durable_image(&self) -> BTreeMap<u64, Page> {
        self.media.lock().unwrap().durable.clone()
    }

    /// True when the armed boundary would fire for this mutation.
    fn next_is_cut(&self) -> bool {
        let mut media = self.media.lock().unwrap();
        let index = media.mutation_count;
        media.mutation_count += 1;
        media.cut_at == Some(index)
    }
}

impl PageDevice for FaultDevice {
    type Error = TestError;

    fn info(&self) -> PageDeviceInfo {
        let page_count = self.media.lock().unwrap().page_count;
        PageDeviceInfo {
            device_id: [0x76; 16],
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
        if self.next_is_cut() {
            return core::future::pending().await;
        }
        self.media.lock().unwrap().visible.insert(page, *input);
        Ok(())
    }

    async fn flush(&self) -> Result<(), MutationFailure<Self::Error>> {
        if self.next_is_cut() {
            return core::future::pending().await;
        }
        let mut media = self.media.lock().unwrap();
        media.durable = media.visible.clone();
        Ok(())
    }
}

fn limits() -> StoreLimits {
    StoreLimits {
        // Large-object sweeps carry >2 MiB record streams through recovery.
        recovery_memory_bytes: 64 * 1024 * 1024,
        ..StoreLimits::default()
    }
}

fn store_id() -> StoreId {
    StoreId::new(0x4655_5345_4441_5050_454e).unwrap()
}

fn format_records() -> Vec<[u8; vibeos_durable_format::RECORD_SIZE]> {
    vec![RecordChain::new(store_id())
        .append(None, RecordBody::Format)
        .unwrap()]
}

fn import_plain(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
) -> PersistentAuthorityImport {
    PersistentAuthorityImport::from_m4(records, store_id(), &[], POLICY, Vec::new())
        .unwrap()
        .with_system_principal(LEGACY_SYSTEM_PRINCIPAL, 1 << 30, 1 << 30, false)
        .unwrap()
}

/// Append one object transaction plus a durable root grant for it, so the
/// successor authority admits exactly one persistent object.
fn granted_object_records(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    bytes: &[u8],
) -> (Vec<[u8; vibeos_durable_format::RECORD_SIZE]>, GrantRecord) {
    let preflight = vibeos_durable_format::preflight_recovery(records, store_id()).unwrap();
    let mut chain =
        RecordChain::from_checkpoint(store_id(), preflight.chain_checkpoint().unwrap()).unwrap();
    let transaction = preflight.id_high_water().max(1);
    let object = transaction.checked_add(1).unwrap();
    let grant_transaction = object.checked_add(1).unwrap();
    let derivation = grant_transaction.checked_add(1).unwrap();
    let space = derivation.checked_add(1).unwrap();
    let exclusive_end = space.checked_add(1).unwrap();
    let object_id = ObjectId::new(object).unwrap();
    let mut output = records.to_vec();
    output.push(
        chain
            .append(None, RecordBody::IdHighWater { exclusive_end })
            .unwrap(),
    );
    output.extend(
        encode_object_transaction(
            &mut chain,
            TransactionId::new(transaction).unwrap(),
            object_id,
            ObjectKind::new(OBJECT_KIND_RAW).unwrap(),
            bytes,
        )
        .unwrap()
        .records,
    );
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
    output.extend(
        preview_grant_transaction(
            &chain,
            TransactionId::new(grant_transaction).unwrap(),
            grant.clone(),
        )
        .unwrap()
        .0
        .records,
    );
    (output, grant)
}

fn granted_import(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    grant: &GrantRecord,
) -> PersistentAuthorityImport {
    PersistentAuthorityImport::from_m4(
        records,
        store_id(),
        &[RootPolicy {
            grant: grant.clone(),
        }],
        POLICY,
        Vec::new(),
    )
    .unwrap()
    .with_system_principal(LEGACY_SYSTEM_PRINCIPAL, 1 << 30, 1 << 30, false)
    .unwrap()
}

/// Format a store, install the initial (empty) authority stream, and return
/// the durable image plus the canonical initial record stream.
fn prepared_image() -> (BTreeMap<u64, Page>, Vec<[u8; vibeos_durable_format::RECORD_SIZE]>) {
    let device = FaultDevice::from_image(SEGMENTS, BTreeMap::new());
    let (runtime, _quota, provisioner) =
        StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(&[])
            .unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(*b"FUSED-APPEND-CUT").unwrap(),
        cleaner_reserve_segments: 2,
        limits: limits(),
    }))
    .unwrap();
    let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
    let records = format_records();
    let view =
        block_on(store.import_persistent_authority(&maintenance, import_plain(&records))).unwrap();
    let records: Vec<[u8; vibeos_durable_format::RECORD_SIZE]> = view
        .record_stream()
        .chunks_exact(vibeos_durable_format::RECORD_SIZE)
        .map(|chunk| chunk.try_into().unwrap())
        .collect();
    drop(store);
    (device.durable_image(), records)
}

fn payload(size: usize) -> Vec<u8> {
    (0..size).map(|index| (index * 197 + 0x11) as u8).collect()
}

/// Drive one granted-object append over `device`. Returns Ready(Ok) when the
/// append completed, Ready(Err) when it failed cleanly, Pending when the
/// armed cut fired.
fn drive_append(device: &FaultDevice, size: usize) -> Poll<Result<(), String>> {
    let (runtime, _quota, provisioner) =
        StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(&[])
            .unwrap();
    let mut store =
        SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    if let Err(error) = block_on(store.mount()) {
        return Poll::Ready(Err(format!("mount: {:?}", error)));
    }
    let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
    let writer = store.derive_persistent_authority_writer(&maintenance).unwrap();
    let view = match block_on(store.recover_persistent_authority(root_policy_commitment(POLICY))) {
        Ok(view) => view,
        Err(error) => return Poll::Ready(Err(format!("recover: {:?}", error))),
    };
    let records: Vec<[u8; vibeos_durable_format::RECORD_SIZE]> = view
        .record_stream()
        .chunks_exact(vibeos_durable_format::RECORD_SIZE)
        .map(|chunk| chunk.try_into().unwrap())
        .collect();
    let (next_records, grant) = granted_object_records(&records, &payload(size));
    let update = granted_import(&next_records, &grant);
    let generation = view.checkpoint_generation();
    let principal = view.principals()[0].clone();
    let mut future = Box::pin(store.append_persistent_authority(
        &writer,
        generation,
        update,
        &principal,
    ));
    match poll_once(future.as_mut()) {
        Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
        Poll::Ready(Err(error)) => Poll::Ready(Err(format!("append: {:?}", error))),
        Poll::Pending => Poll::Pending,
    }
}

/// Mount the durable image cold and classify the recovered authority state.
/// Returns the number of admitted objects after verifying any object content.
fn recovered_objects(image: BTreeMap<u64, Page>, size: usize) -> usize {
    let device = FaultDevice::from_image(SEGMENTS, image);
    let (runtime, _quota, _provisioner) =
        StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(&[])
            .unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device, limits(), runtime);
    block_on(store.mount()).unwrap_or_else(|error| panic!("cold mount: {:?}", error));
    let view = block_on(store.recover_persistent_authority(root_policy_commitment(POLICY)))
        .unwrap_or_else(|error| panic!("cold recover: {:?}", error));
    for handle in view.objects() {
        let bytes = block_on(store.read_persistent_object(handle))
            .unwrap_or_else(|error| panic!("cold read: {:?}", error));
        assert_eq!(bytes, payload(size), "recovered object content diverged");
    }
    view.objects().len()
}

fn sweep_cut_boundaries(size: usize, stride: usize) {
    let (initial_image, _records) = prepared_image();

    // Unfaulted baseline: count the mutation boundaries of one append.
    let device = FaultDevice::from_image(SEGMENTS, initial_image.clone());
    match drive_append(&device, size) {
        Poll::Ready(Ok(())) => {}
        other => panic!("baseline append did not complete: {:?}", other.is_pending()),
    }
    let boundaries = device.mutation_count();
    assert!(boundaries > 20, "implausibly few mutations: {}", boundaries);
    assert_eq!(recovered_objects(device.durable_image(), size), 1);

    for boundary in (0..boundaries).step_by(stride) {
        let device = FaultDevice::from_image(SEGMENTS, initial_image.clone());
        device.arm(boundary);
        let outcome = drive_append(&device, size);
        assert!(
            outcome.is_pending(),
            "boundary {}: cut did not fire (mutations={})",
            boundary,
            device.mutation_count()
        );
        // Power cycle: everything volatile is lost; remount the durable image.
        let objects = recovered_objects(device.durable_image(), size);
        assert!(
            objects == 0 || objects == 1,
            "boundary {}: recovered {} objects",
            boundary,
            objects
        );
        if objects == 0 {
            // The predecessor state must still accept the append.
            let retry = FaultDevice::from_image(SEGMENTS, device.durable_image());
            match drive_append(&retry, size) {
                Poll::Ready(Ok(())) => {}
                other => panic!(
                    "boundary {}: resume append failed: pending={}",
                    boundary,
                    other.is_pending()
                ),
            }
            assert_eq!(recovered_objects(retry.durable_image(), size), 1);
        }
    }
}

#[test]
fn every_fused_append_cut_boundary_recovers_predecessor_or_successor() {
    sweep_cut_boundaries(4096, 1);
}

/// Above the former 368,640-byte compatibility envelope but still within one
/// authority extent, so the fused single-checkpoint path carries it.
#[test]
fn large_fused_append_cut_boundaries_recover() {
    sweep_cut_boundaries(372_000, 5);
}

/// A 1 MiB object's ~1.5 MiB record stream exceeds one authority extent and
/// takes the general publication path with a multi-extent authority chain.
#[test]
fn one_mib_append_cut_boundaries_recover() {
    sweep_cut_boundaries(1024 * 1024, 17);
}
