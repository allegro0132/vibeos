//! Streaming canonical Blob CAS over the frozen Storage V2 segment ABI.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;
use core::sync::atomic::Ordering;

use sha2::{Digest, Sha256};
use vibeos_blob_format::{
    verify_proof, BlobDescriptor, BlobError, BlobGeometry, BlobView, Hash, MerkleProof,
    MerkleTreeSink, StreamingError, StreamingMerkle, HASH_SIZE, HEADER_SIZE, LEAF_SIZE,
    MAX_STREAMING_EMISSIONS_PER_STEP,
};
use vibeos_segment_format::{
    descriptor_chain_initial, descriptor_chain_next, encode_extent_body, encode_record_seal,
    encode_segment_header_body, encode_segment_seal_body, encode_segment_summary_body,
    payload_chain_initial, payload_chain_next, payload_sha256, segment_base_page, BodyDigest,
    Checkpoint, ExtentKind, ExtentRecord, FormatError, Page, PhysicalPointer, PointerValue,
    RecordBinding, SegmentHeader, SegmentSeal, SegmentSummary, StoreUuid, ANCHOR_SEGMENT_NO,
    DATA_END_PAGE, DATA_FIRST_PAGE, PAGE_SIZE, SEGMENT_PAGES,
    SEGMENT_SEAL_BODY_PAGE, SEGMENT_SEAL_PAGE, SUMMARY_BODY_PAGE, SUMMARY_SEAL_PAGE,
};

use crate::allocation_v2::{
    encode_allocation_v2, AllocationTransition, AllocationV2, SegmentAllocation,
};
use crate::authority::{
    AuthorizedObject, ObjectPublicationPersistence, ObjectPublicationTarget, PublicationIntent,
    PublishError,
};
use crate::cas_codec::{
    decode_blob_manifest, encode_blob_manifest, encode_cas_snapshot, BlobKey, BlobManifest,
    BlobMapping, CasCodecContext, CasCodecError, CasSnapshot, ManifestExtent, ObjectMapping,
    BLOB_MAPPING_LEN, CANONICAL_CONTENT_EXTENT_LEN, CAS_SNAPSHOT_HEADER_LEN, MAX_BLOB_EXTENTS,
    MAX_METADATA_PAYLOAD_LEN, OBJECT_MAPPING_LEN, REFERENCE_CODEC_RAW,
};
use crate::codec::{encode_allocation, AllocationState};
use crate::device::{PageDevice, PageDeviceInfo};
use crate::gc::{GcStoreError, GcTelemetry, GcTimeSource};
use crate::maintenance::MaintenanceOperationLease;
use crate::pins::{
    OwnedObjectReadPin, OwnedRuntimeRootPin, PinAdmission, PinRegistry, RootKey,
    RootRetentionHandle, RuntimeRootClass,
};
use crate::quota::{
    canonical_attributable_physical_bytes, CommittedQuotaCharge, PrincipalQuotaTable,
    QuotaReservation, StoragePrincipal, QUOTA_DEDUP_UNIQUE_OBJECT_BYTES,
};
use crate::store::{
    read_pointer_payload, read_pointer_payloads, scan_segment, validate_cas_blob_descriptors,
    write_checkpoint, CapacityClass, CasMountedState, MountedState, SegmentStore, StoreError,
    READER_PIN_SLOTS, ROOT_PIN_SLOTS,
};

const METADATA_KIND_MANIFEST: u32 = 0xffff_0010;
const METADATA_KIND_CAS_SNAPSHOT: u32 = 0xffff_0011;
const METADATA_KIND_ALLOCATION: u32 = 0xffff_0002;
const METADATA_KIND_PERSISTENT_AUTHORITY: u32 = 0xffff_0021;
// The cheap readback path decodes and fully re-verifies the staged blob from
// one batched read; the expensive path re-derives the tree through many
// single-range reads. 512 KiB keeps the cheap path within the ordinary
// recovery-memory budget while covering the 128 KiB qualification size.
const SMALL_STAGED_BLOB_READBACK_LIMIT: u64 = 512 * 1024;
const MAX_BATCHED_BLOB_READ_LIMIT: usize = 512 * 1024;

/// Buffered writes of a deferred-barrier publication window. Pages are
/// staged in memory and drained to the device as contiguous multi-page
/// requests immediately before the checkpoint slot protocol, whose first
/// flush is the shared durability barrier for the whole window.
pub(crate) struct PageSink {
    entries: Vec<(u64, Box<Page>)>,
}

impl PageSink {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn push<E>(&mut self, page: u64, bytes: &Page) -> Result<(), StoreError<E>> {
        self.entries
            .try_reserve(1)
            .map_err(|_| StoreError::MemoryLimit)?;
        let mut copy = heap_page();
        copy.copy_from_slice(bytes);
        self.entries.push((page, copy));
        Ok(())
    }

    /// Drain every staged page as contiguous ascending runs. Later writes to
    /// the same page win, exactly like direct device ordering would.
    pub(crate) async fn drain<D: PageDevice>(
        mut self,
        device: &D,
    ) -> Result<(), StoreError<D::Error>> {
        self.entries
            .sort_by(|left, right| left.0.cmp(&right.0));
        // Deduplicate: keep the last write per page.
        let mut deduped: Vec<(u64, Box<Page>)> = Vec::new();
        deduped
            .try_reserve_exact(self.entries.len())
            .map_err(|_| StoreError::MemoryLimit)?;
        for entry in self.entries {
            if deduped.last().is_some_and(|last| last.0 == entry.0) {
                *deduped.last_mut().expect("non-empty") = entry;
            } else {
                deduped.push(entry);
            }
        }
        let mut index = 0;
        while index < deduped.len() {
            let first_page = deduped[index].0;
            let mut end = index + 1;
            while end < deduped.len() && deduped[end].0 == first_page + (end - index) as u64 {
                end += 1;
            }
            let mut run = Vec::new();
            run.try_reserve_exact(end - index)
                .map_err(|_| StoreError::MemoryLimit)?;
            for entry in &deduped[index..end] {
                run.push(*entry.1);
            }
            device
                .write_pages(first_page, &run)
                .await
                .map_err(StoreError::Mutation)?;
            index = end;
        }
        Ok(())
    }
}

async fn sink_or_write_page<D: PageDevice>(
    device: &D,
    sink: Option<&mut PageSink>,
    page: u64,
    bytes: &Page,
) -> Result<(), StoreError<D::Error>> {
    match sink {
        Some(sink) => sink.push(page, bytes),
        None => write_page(device, page, bytes).await,
    }
}

/// A read-only device view backed by span snapshots fetched with batched
/// multi-page reads. Reads inside a span are served from the buffer; reads
/// outside fall through to the inner device. Mutations pass through, though
/// verification callers never issue any.
pub(crate) struct SpanSnapshotDevice<'a, D> {
    inner: &'a D,
    spans: Vec<(u64, Vec<Page>)>,
}

impl<'a, D: PageDevice> SpanSnapshotDevice<'a, D> {
    pub(crate) async fn capture(
        inner: &'a D,
        ranges: &[(u64, u64)],
    ) -> Result<SpanSnapshotDevice<'a, D>, StoreError<D::Error>> {
        let mut spans = Vec::new();
        spans
            .try_reserve_exact(ranges.len())
            .map_err(|_| StoreError::MemoryLimit)?;
        for (first, count) in ranges {
            let count = usize::try_from(*count).map_err(|_| StoreError::MemoryLimit)?;
            let mut pages = Vec::new();
            pages
                .try_reserve_exact(count)
                .map_err(|_| StoreError::MemoryLimit)?;
            pages.resize(count, [0; PAGE_SIZE]);
            inner
                .read_pages(*first, &mut pages)
                .await
                .map_err(StoreError::Device)?;
            spans.push((*first, pages));
        }
        Ok(SpanSnapshotDevice { inner, spans })
    }
}

impl<D: PageDevice> PageDevice for SpanSnapshotDevice<'_, D> {
    type Error = D::Error;

    fn info(&self) -> PageDeviceInfo {
        self.inner.info()
    }

    async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
        for (first, pages) in &self.spans {
            if page >= *first && page < *first + pages.len() as u64 {
                output.copy_from_slice(&pages[(page - first) as usize]);
                return Ok(());
            }
        }
        self.inner.read_page(page, output).await
    }

    async fn write_page(
        &self,
        page: u64,
        input: &Page,
    ) -> Result<(), vibeos_storage_device::MutationFailure<Self::Error>> {
        self.inner.write_page(page, input).await
    }

    async fn flush(&self) -> Result<(), vibeos_storage_device::MutationFailure<Self::Error>> {
        self.inner.flush().await
    }
}

/// A device view that overlays a [`PageSink`]'s still-buffered writes over
/// the inner device, so verification logic that runs before the sink drains
/// observes exactly what the media will contain.
pub(crate) struct SinkOverlayDevice<'a, D> {
    inner: &'a D,
    sink: Option<&'a PageSink>,
}

impl<'a, D> SinkOverlayDevice<'a, D> {
    pub(crate) fn new(inner: &'a D, sink: Option<&'a PageSink>) -> Self {
        Self { inner, sink }
    }
}

impl<D: PageDevice> PageDevice for SinkOverlayDevice<'_, D> {
    type Error = D::Error;

    fn info(&self) -> PageDeviceInfo {
        self.inner.info()
    }

    async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
        if let Some(sink) = self.sink {
            // Later writes win, so search from the end.
            if let Some((_, bytes)) = sink.entries.iter().rev().find(|(sunk, _)| *sunk == page) {
                output.copy_from_slice(bytes.as_ref());
                return Ok(());
            }
        }
        self.inner.read_page(page, output).await
    }

    async fn write_page(
        &self,
        page: u64,
        input: &Page,
    ) -> Result<(), vibeos_storage_device::MutationFailure<Self::Error>> {
        self.inner.write_page(page, input).await
    }

    async fn flush(&self) -> Result<(), vibeos_storage_device::MutationFailure<Self::Error>> {
        self.inner.flush().await
    }
}

/// Allocate page-sized I/O scratch directly in the heap-backed representation.
/// Keeping `Page` arrays out of async generator variants is part of the kernel
/// stack contract: these buffers routinely live across device awaits.
fn heap_page() -> Box<Page> {
    alloc::vec![0_u8; PAGE_SIZE]
        .into_boxed_slice()
        .try_into()
        .unwrap_or_else(|_| unreachable!("fixed page allocation has the exact page length"))
}

pub struct CasObjectHandle {
    store_uuid: StoreUuid,
    object_id: u128,
    object_kind: u32,
    exact_len: u64,
    commit_generation: u64,
    authority: Arc<ObjectAuthorityLease>,
}

struct ObjectAuthorityLease {
    root_pin: Option<OwnedRuntimeRootPin<ROOT_PIN_SLOTS, READER_PIN_SLOTS>>,
    quota_charge: Option<(PrincipalQuotaTable, CommittedQuotaCharge)>,
}

impl Drop for ObjectAuthorityLease {
    fn drop(&mut self) {
        // Revoke the final runtime root before making its quota available to a
        // concurrent admission. Struct fields would otherwise be dropped only
        // after this body, briefly exposing an authorized but uncharged Object.
        drop(self.root_pin.take());
        if let Some((table, charge)) = self.quota_charge.take() {
            let _ = table.account_authority_revoked(charge);
        }
    }
}

struct PendingCasObjectHandle {
    store_uuid: StoreUuid,
    object_id: u128,
    object_kind: u32,
    exact_len: u64,
    commit_generation: u64,
    root_pin: OwnedRuntimeRootPin<ROOT_PIN_SLOTS, READER_PIN_SLOTS>,
    is_new_blob: bool,
}

impl PendingCasObjectHandle {
    fn complete(
        self,
        quota_charge: Option<(PrincipalQuotaTable, CommittedQuotaCharge)>,
    ) -> CasObjectHandle {
        CasObjectHandle {
            store_uuid: self.store_uuid,
            object_id: self.object_id,
            object_kind: self.object_kind,
            exact_len: self.exact_len,
            commit_generation: self.commit_generation,
            authority: Arc::new(ObjectAuthorityLease {
                root_pin: Some(self.root_pin),
                quota_charge,
            }),
        }
    }
}

/// Why an already-authorized object must remain in a GC root snapshot after
/// the caller's ordinary object resource may be released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeObjectPinClass {
    InvocationLease,
    ExplicitSnapshot,
    AuthorityTransaction,
    MigrationTransaction,
}

/// A bounded runtime root created only from an existing authorized object.
/// Dropping the guard releases the exact root-slot lease.
pub struct RuntimeObjectPin {
    _pin: OwnedRuntimeRootPin<ROOT_PIN_SLOTS, READER_PIN_SLOTS>,
}

/// Opaque identity shared by every pin owned by one runtime fault domain.
/// It conveys no object authority and can be minted only by this store's
/// runtime context.
pub struct RuntimePinOwner {
    owner: crate::pins::PinOwner,
    registry: crate::store::SharedStorePinRegistry,
}

impl core::fmt::Debug for RuntimePinOwner {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RuntimePinOwner")
            .finish_non_exhaustive()
    }
}

/// Scheduler proof that a runtime fault domain has synchronously stopped.
/// The constructor is explicit: a timeout or elapsed clock is not proof.
pub struct StoppedRuntimePinOwner {
    stopped: crate::pins::FaultDomainStopped,
    registry: crate::store::SharedStorePinRegistry,
}

impl StoppedRuntimePinOwner {
    /// # Safety
    ///
    /// The caller must be the trusted executor/fault-domain bridge and must
    /// have synchronously joined the task represented by `owner`. Timeouts,
    /// cancellation requests, and elapsed time do not satisfy this contract.
    pub unsafe fn after_synchronous_join(owner: RuntimePinOwner) -> Self {
        Self {
            stopped: crate::pins::FaultDomainStopped::after_join(owner.owner),
            registry: owner.registry,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimePinOwnerError {
    WrongStore,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReleasedRuntimePins {
    pub roots: usize,
    pub readers: usize,
}

impl Clone for CasObjectHandle {
    fn clone(&self) -> Self {
        Self {
            store_uuid: self.store_uuid,
            object_id: self.object_id,
            object_kind: self.object_kind,
            exact_len: self.exact_len,
            commit_generation: self.commit_generation,
            authority: Arc::clone(&self.authority),
        }
    }
}

impl core::fmt::Debug for CasObjectHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CasObjectHandle")
            .field("object_kind", &self.object_kind)
            .field("exact_len", &self.exact_len)
            .finish_non_exhaustive()
    }
}

impl CasObjectHandle {
    pub const fn object_kind(&self) -> u32 {
        self.object_kind
    }

    pub const fn exact_len(&self) -> u64 {
        self.exact_len
    }

    pub(crate) fn root_key(
        &self,
        registry: &crate::store::SharedStorePinRegistry,
    ) -> Result<RootKey, crate::pins::PinError> {
        let root_pin = self
            .authority
            .root_pin
            .as_ref()
            .ok_or(crate::pins::PinError::RecheckFailed)?;
        if !root_pin.is_active() || !root_pin.belongs_to(registry) {
            return Err(crate::pins::PinError::RecheckFailed);
        }
        RootKey::new(self.object_id, self.commit_generation, self.object_kind)
    }

    pub(crate) fn authority_key(&self) -> Result<RootKey, crate::pins::PinError> {
        RootKey::new(self.object_id, self.commit_generation, self.object_kind)
    }

    pub(crate) const fn store_uuid(&self) -> StoreUuid {
        self.store_uuid
    }

    pub(crate) const fn persistent_binding_parts(&self) -> (u128, u64, u32) {
        (self.object_id, self.commit_generation, self.object_kind)
    }

    pub(crate) fn is_quota_charged(&self) -> bool {
        self.authority
            .quota_charge
            .as_ref()
            .is_some_and(|(_, charge)| charge.is_active())
    }

    /// Bind this live runtime charge to the stable logical object authenticated
    /// by the authority append which created it. No object or principal lookup
    /// capability is exposed; the table keeps only a weak transfer witness.
    pub(crate) fn bind_persistent_quota_candidate(
        &self,
        stable_object_id: u128,
    ) -> Result<(), crate::quota::QuotaError> {
        match self.authority.quota_charge.as_ref() {
            Some((table, charge)) => {
                table.bind_persistent_candidate(stable_object_id, self.object_id, charge)
            }
            None => Ok(()),
        }
    }

    pub(crate) fn can_attach_quota_charge(&mut self) -> bool {
        Arc::get_mut(&mut self.authority).is_some_and(|authority| {
            authority.root_pin.is_some() && authority.quota_charge.is_none()
        })
    }

    pub(crate) fn attach_quota_charge(
        &mut self,
        table: PrincipalQuotaTable,
        charge: CommittedQuotaCharge,
    ) {
        let authority = Arc::get_mut(&mut self.authority)
            .expect("promotable quota adoption preflights unique authority ownership");
        assert!(authority.root_pin.is_some());
        assert!(authority.quota_charge.is_none());
        authority.quota_charge = Some((table, charge));
    }
}

pub(crate) fn recover_persistent_cas_object(
    store_uuid: StoreUuid,
    mapping: ObjectMapping,
) -> AuthorizedObject<CasObjectHandle> {
    AuthorizedObject::from_committed(
        CasObjectHandle {
            store_uuid,
            object_id: mapping.object_id,
            object_kind: mapping.blob_key.object_kind(),
            exact_len: mapping.blob_key.exact_len(),
            commit_generation: mapping.commit_generation,
            authority: Arc::new(ObjectAuthorityLease {
                // The checkpoint's persistent root set, not a boot-local pin,
                // owns the lifetime of this recovered authority.
                root_pin: None,
                quota_charge: None,
            }),
        },
        mapping.blob_key.object_kind(),
        mapping.blob_key.exact_len(),
        ObjectPublicationPersistence::Persistent,
    )
}

/// Reconstitute boot-local authority only after a higher layer has matched an
/// authenticated logical object record to this exact catalog mapping and Blob
/// root. This is crate-private; raw ObjectId/CAS lookup never crosses the API.
pub(crate) fn recover_promotable_cas_object(
    store_uuid: StoreUuid,
    mapping: ObjectMapping,
    pins: &crate::store::SharedStorePinRegistry,
) -> Result<AuthorizedObject<CasObjectHandle>, crate::pins::PinError> {
    let key = RootKey::new(
        mapping.object_id,
        mapping.commit_generation,
        mapping.blob_key.object_kind(),
    )?;
    let owner = pins.allocate_owner()?;
    let root_pin = PinRegistry::pin_root_owned(
        pins,
        key,
        RuntimeRootClass::AuthorityTransaction,
        owner,
        PinAdmission::CompletionCritical,
    )?;
    Ok(AuthorizedObject::from_committed(
        CasObjectHandle {
            store_uuid,
            object_id: mapping.object_id,
            object_kind: mapping.blob_key.object_kind(),
            exact_len: mapping.blob_key.exact_len(),
            commit_generation: mapping.commit_generation,
            authority: Arc::new(ObjectAuthorityLease {
                root_pin: Some(root_pin),
                quota_charge: None,
            }),
        },
        mapping.blob_key.object_kind(),
        mapping.blob_key.exact_len(),
        ObjectPublicationPersistence::RuntimeOnly,
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCasChunk {
    pub descriptor: BlobDescriptor,
    pub index: u32,
    pub bytes: Vec<u8>,
    pub proof: MerkleProof,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedCasBlob {
    pub descriptor: BlobDescriptor,
    pub verified_encoded_bytes: u64,
}

#[derive(Debug)]
pub enum CasStoreError<E> {
    Store(StoreError<E>),
    Blob(BlobError),
    Codec(CasCodecError),
    InvalidChunk,
    ExpectedRootMismatch,
    HashCollision,
    WriterFailed,
    Quota(crate::quota::QuotaError),
}

#[derive(Debug)]
pub enum ForegroundBlobError<E> {
    Cas(CasStoreError<E>),
    Gc(GcStoreError<E>),
}

impl<E: fmt::Display> fmt::Display for ForegroundBlobError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cas(error) => write!(formatter, "{error}"),
            Self::Gc(error) => write!(formatter, "{error}"),
        }
    }
}

impl<E> From<CasStoreError<E>> for ForegroundBlobError<E> {
    fn from(error: CasStoreError<E>) -> Self {
        Self::Cas(error)
    }
}

impl<E> From<GcStoreError<E>> for ForegroundBlobError<E> {
    fn from(error: GcStoreError<E>) -> Self {
        Self::Gc(error)
    }
}

impl<E: fmt::Display> fmt::Display for CasStoreError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "{error}"),
            Self::Blob(error) => write!(f, "{error}"),
            Self::Codec(error) => write!(f, "{error}"),
            Self::InvalidChunk => f.write_str("Blob chunk is not the next exact canonical chunk"),
            Self::ExpectedRootMismatch => f.write_str("caller Blob root hint does not match input"),
            Self::HashCollision => f.write_str("BlobKey collision failed full-byte verification"),
            Self::WriterFailed => f.write_str("Blob writer cannot resume after an I/O failure"),
            Self::Quota(error) => write!(f, "{error}"),
        }
    }
}

impl<E> From<StoreError<E>> for CasStoreError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Store(value)
    }
}

impl<E> From<BlobError> for CasStoreError<E> {
    fn from(value: BlobError) -> Self {
        Self::Blob(value)
    }
}

impl<E> From<CasCodecError> for CasStoreError<E> {
    fn from(value: CasCodecError) -> Self {
        Self::Codec(value)
    }
}

impl<E> From<crate::quota::QuotaError> for CasStoreError<E> {
    fn from(value: crate::quota::QuotaError) -> Self {
        Self::Quota(value)
    }
}

impl<E> From<FormatError> for CasStoreError<E> {
    fn from(value: FormatError) -> Self {
        Self::Store(StoreError::Format(value))
    }
}

#[derive(Debug)]
pub enum CasCommitError<DeviceError, PublishErrorType> {
    Store(CasStoreError<DeviceError>),
    Publish(PublishError<PublishErrorType>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EmissionError {
    Full,
}

#[derive(Clone, Copy)]
struct Emission {
    index: u32,
    hash: Hash,
}

struct EmissionSink {
    values: [Option<Emission>; MAX_STREAMING_EMISSIONS_PER_STEP],
    len: usize,
}

impl EmissionSink {
    const fn new() -> Self {
        Self {
            values: [None; MAX_STREAMING_EMISSIONS_PER_STEP],
            len: 0,
        }
    }

    fn take(&mut self) -> [Option<Emission>; MAX_STREAMING_EMISSIONS_PER_STEP] {
        self.len = 0;
        core::mem::replace(&mut self.values, [None; MAX_STREAMING_EMISSIONS_PER_STEP])
    }
}

impl MerkleTreeSink for EmissionSink {
    type Error = EmissionError;

    fn write_hash(&mut self, index: u32, hash: Hash) -> Result<(), Self::Error> {
        if self.len == self.values.len() {
            return Err(EmissionError::Full);
        }
        self.values[self.len] = Some(Emission { index, hash });
        self.len += 1;
        Ok(())
    }
}

#[derive(Clone)]
struct ScratchExtent {
    extent_index: u32,
    extent_count: u32,
    encoded_offset: u64,
    payload_byte_len: u64,
    segment_no: u64,
    segment_generation: u64,
    ordinal: u32,
    descriptor_relative_page: u32,
    payload_relative_page: u32,
}

impl ScratchExtent {
    fn pointer(&self, store_uuid: StoreUuid, payload_hash: Hash) -> PhysicalPointer {
        PhysicalPointer::Value(PointerValue {
            store_uuid,
            segment_no: self.segment_no,
            segment_generation: self.segment_generation,
            descriptor_relative_page: self.descriptor_relative_page,
            payload_relative_page: self.payload_relative_page,
            payload_pages: self.payload_byte_len.div_ceil(PAGE_SIZE as u64) as u32,
            ordinal: self.ordinal,
            exact_byte_len: self.payload_byte_len,
            extent_kind: ExtentKind::Blob,
            payload_sha256: payload_hash,
        })
    }
}

#[derive(Clone, Copy)]
struct ScratchSegment {
    segment_no: u64,
    segment_generation: u64,
    first_extent: usize,
    extent_end: usize,
}

pub struct BlobWriter<'a, D: PageDevice> {
    store: &'a mut SegmentStore<D>,
    state: Option<MountedState>,
    object_kind: u32,
    reference_codec: u16,
    geometry: BlobGeometry,
    expected_root: Option<Hash>,
    merkle: Option<StreamingMerkle<EmissionSink>>,
    extents: Vec<ScratchExtent>,
    segments: Vec<ScratchSegment>,
    /// Sparse in-memory Merkle tree pages; written to media only at finish.
    tree_pages: Vec<Option<Box<Page>>>,
    /// Running per-content-extent payload hashers fed as chunks stream in.
    content_hashers: Vec<Sha256>,
    header_hash: Option<Hash>,
    tree_hash: Option<Hash>,
    prepared: bool,
    mutated: bool,
    failed: bool,
    quota_reservation: Option<QuotaReservation>,
    /// Present when this writer stages for a fused publication: scratch
    /// payload/seal pages accumulate here and drain as batched requests
    /// before the fused checkpoint.
    staged_sink: Option<PageSink>,
}

impl<D: PageDevice> SegmentStore<D> {
    fn gc_can_relieve_blob_admission(error: &CasStoreError<D::Error>) -> bool {
        matches!(
            error,
            CasStoreError::Store(StoreError::GcResumeRequired)
                | CasStoreError::Store(StoreError::Capacity(
                    CapacityClass::Metadata | CapacityClass::CleanerReserve
                ))
        )
    }

    /// Normal foreground admission path for a streaming Blob. If the exact
    /// request would consume root-policy or cleaner headroom, run one bounded
    /// low-live-ratio collection before returning capacity failure, then retry
    /// admission against the newly mounted generation. The optional telemetry
    /// is present only when foreground cleaning ran.
    pub async fn begin_blob_with_foreground_gc<C: GcTimeSource>(
        &mut self,
        object_kind: u32,
        exact_len: u64,
        expected_root: Option<Hash>,
        clock: &C,
    ) -> Result<(BlobWriter<'_, D>, Option<GcTelemetry>), ForegroundBlobError<D::Error>> {
        if self.quota.is_some() {
            return Err(CasStoreError::Store(StoreError::PrincipalRequired).into());
        }
        let telemetry = self
            .prepare_blob_with_reference_codec_foreground_gc(
                object_kind,
                exact_len,
                expected_root,
                REFERENCE_CODEC_RAW,
                clock,
            )
            .await?;
        let writer = self.begin_blob_with_reference_codec(
            object_kind,
            exact_len,
            expected_root,
            REFERENCE_CODEC_RAW,
        )?;
        Ok((writer, telemetry))
    }

    pub async fn begin_blob_with_foreground_gc_for_principal<C: GcTimeSource>(
        &mut self,
        principal: &StoragePrincipal,
        object_kind: u32,
        exact_len: u64,
        expected_root: Option<Hash>,
        clock: &C,
    ) -> Result<(BlobWriter<'_, D>, Option<GcTelemetry>), ForegroundBlobError<D::Error>> {
        self.begin_blob_with_reference_codec_foreground_gc_for_principal(
            principal,
            object_kind,
            exact_len,
            expected_root,
            REFERENCE_CODEC_RAW,
            clock,
        )
        .await
    }

    pub(crate) async fn begin_blob_with_reference_codec_foreground_gc_for_principal<
        C: GcTimeSource,
    >(
        &mut self,
        principal: &StoragePrincipal,
        object_kind: u32,
        exact_len: u64,
        expected_root: Option<Hash>,
        reference_codec: u16,
        clock: &C,
    ) -> Result<(BlobWriter<'_, D>, Option<GcTelemetry>), ForegroundBlobError<D::Error>> {
        BlobGeometry::for_len(exact_len).map_err(CasStoreError::from)?;
        StreamingMerkle::begin(object_kind, exact_len, EmissionSink::new())
            .map_err(map_streaming_error)?;
        // Reserve both principal dimensions before a foreground collection is
        // allowed to mutate media. The detached reservation survives every
        // non-writing admission probe and every bounded GC cycle below.
        let reservation = self.reserve_blob_quota(principal, exact_len)?;
        let maximum_cycles = self.info().map_err(CasStoreError::from)?.admitted_segments;
        let mut cycles = 0_u64;
        let mut aggregate = GcTelemetry::default();
        let mut started = None;
        loop {
            let admission = self
                .begin_blob_with_reference_codec_internal(
                    object_kind,
                    exact_len,
                    expected_root,
                    reference_codec,
                    None,
                )
                .map(drop);
            match admission {
                Ok(()) => break,
                Err(error) if Self::gc_can_relieve_blob_admission(&error) => {
                    if cycles == maximum_cycles {
                        return Err(error.into());
                    }
                    started.get_or_insert_with(|| clock.monotonic_ns());
                    aggregate.saturating_merge_cycle(self.collect_garbage().await?);
                    cycles += 1;
                }
                Err(error) => return Err(error.into()),
            }
        }
        let telemetry = started.map(|start| {
            aggregate.foreground_pause_ns = clock.monotonic_ns().saturating_sub(start);
            aggregate.pause_time_measured = true;
            aggregate
        });
        let writer = self.begin_blob_with_reference_codec_internal(
            object_kind,
            exact_len,
            expected_root,
            reference_codec,
            Some(reservation),
        )?;
        Ok((writer, telemetry))
    }

    pub(crate) async fn prepare_blob_with_reference_codec_foreground_gc<C: GcTimeSource>(
        &mut self,
        object_kind: u32,
        exact_len: u64,
        expected_root: Option<Hash>,
        reference_codec: u16,
        clock: &C,
    ) -> Result<Option<GcTelemetry>, ForegroundBlobError<D::Error>> {
        let maximum_cycles = self.info().map_err(CasStoreError::from)?.admitted_segments;
        let mut cycles = 0_u64;
        let mut aggregate = GcTelemetry::default();
        let mut started = None;
        loop {
            // Probe admission and immediately drop the non-writing writer so
            // its mutable borrow cannot span a subsequent cleaning cycle.
            let admission = self
                .begin_blob_with_reference_codec(
                    object_kind,
                    exact_len,
                    expected_root,
                    reference_codec,
                )
                .map(drop);
            match admission {
                Ok(()) => break,
                Err(error) if Self::gc_can_relieve_blob_admission(&error) => {
                    if cycles == maximum_cycles {
                        return Err(error.into());
                    }
                    started.get_or_insert_with(|| clock.monotonic_ns());
                    aggregate.saturating_merge_cycle(self.collect_garbage().await?);
                    cycles += 1;
                }
                Err(error) => return Err(error.into()),
            }
        }
        let telemetry = started.map(|start| {
            aggregate.foreground_pause_ns = clock.monotonic_ns().saturating_sub(start);
            aggregate.pause_time_measured = true;
            aggregate
        });
        Ok(telemetry)
    }

    pub fn allocate_runtime_pin_owner(&self) -> Result<RuntimePinOwner, CasStoreError<D::Error>> {
        self.require_current_generation()?;
        self.pins
            .allocate_owner()
            .map(|owner| RuntimePinOwner {
                owner,
                registry: self.pins.clone(),
            })
            .map_err(|_| StoreError::Capacity(CapacityClass::Metadata).into())
    }

    /// Release every leaked pin for a fault domain only after the scheduler
    /// has synchronously joined it. Other owners' pins are untouched.
    pub fn release_stopped_runtime_pins(
        &self,
        stopped: StoppedRuntimePinOwner,
    ) -> Result<ReleasedRuntimePins, RuntimePinOwnerError> {
        if !Arc::ptr_eq(&stopped.registry, &self.pins) {
            return Err(RuntimePinOwnerError::WrongStore);
        }
        let released = self.pins.release_stopped_owner(stopped.stopped);
        Ok(ReleasedRuntimePins {
            roots: released.roots,
            readers: released.readers,
        })
    }

    /// Pin an existing authorized object for one runtime operation or explicit
    /// snapshot. This accepts no ObjectId or digest and therefore cannot turn
    /// media identity into authority.
    pub fn pin_runtime_object(
        &self,
        object: &AuthorizedObject<CasObjectHandle>,
        class: RuntimeObjectPinClass,
    ) -> Result<RuntimeObjectPin, CasStoreError<D::Error>> {
        let owner = self.allocate_runtime_pin_owner()?;
        self.pin_runtime_object_owned(object, class, &owner)
    }

    /// Variant used by a task/fault-domain bridge so every pin can be reaped
    /// together after synchronous task termination.
    pub fn pin_runtime_object_owned(
        &self,
        object: &AuthorizedObject<CasObjectHandle>,
        class: RuntimeObjectPinClass,
        owner: &RuntimePinOwner,
    ) -> Result<RuntimeObjectPin, CasStoreError<D::Error>> {
        if !Arc::ptr_eq(&owner.registry, &self.pins) {
            return Err(StoreError::ObjectUnavailable.into());
        }
        let state = self.require_current_generation()?;
        let handle = object.backend_handle();
        let key = handle
            .root_key(&self.pins)
            .map_err(|_| StoreError::ObjectUnavailable)?;
        let cas = state.cas.as_ref().ok_or(StoreError::ObjectUnavailable)?;
        let mapping = cas
            .objects
            .binary_search_by_key(&key.object_id(), |mapping| mapping.object_id)
            .ok()
            .map(|index| cas.objects[index])
            .filter(|mapping| {
                mapping.commit_generation == key.commit_generation()
                    && mapping.blob_key.object_kind() == key.object_kind()
            })
            .ok_or(StoreError::ObjectUnavailable)?;
        if mapping.blob_key.exact_len() != object.exact_len() {
            return Err(StoreError::ObjectUnavailable.into());
        }
        let (runtime_class, admission) = match class {
            RuntimeObjectPinClass::InvocationLease => {
                (RuntimeRootClass::InvocationLease, PinAdmission::Ordinary)
            }
            RuntimeObjectPinClass::ExplicitSnapshot => {
                (RuntimeRootClass::ExplicitSnapshot, PinAdmission::Ordinary)
            }
            RuntimeObjectPinClass::AuthorityTransaction => (
                RuntimeRootClass::AuthorityTransaction,
                PinAdmission::CompletionCritical,
            ),
            RuntimeObjectPinClass::MigrationTransaction => (
                RuntimeRootClass::MigrationTransaction,
                PinAdmission::CompletionCritical,
            ),
        };
        let retention: RootRetentionHandle = handle.authority.clone();
        let pin = PinRegistry::pin_root_owned_retained(
            &self.pins,
            key,
            runtime_class,
            owner.owner,
            admission,
            retention,
        )
        .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
        Ok(RuntimeObjectPin { _pin: pin })
    }

    pub fn begin_blob(
        &mut self,
        object_kind: u32,
        exact_len: u64,
        expected_root: Option<Hash>,
    ) -> Result<BlobWriter<'_, D>, CasStoreError<D::Error>> {
        if self.quota.is_some() {
            return Err(StoreError::PrincipalRequired.into());
        }
        self.begin_blob_with_reference_codec(
            object_kind,
            exact_len,
            expected_root,
            REFERENCE_CODEC_RAW,
        )
    }

    /// Migration-only raw writer. The caller must already hold the explicit
    /// maintenance lease; persistent quota state is installed by the final
    /// authority checkpoint rather than by a boot-local charge token.
    pub(crate) fn begin_blob_for_persistent_import(
        &mut self,
        object_kind: u32,
        exact_len: u64,
    ) -> Result<BlobWriter<'_, D>, CasStoreError<D::Error>> {
        self.begin_blob_with_reference_codec_internal(
            object_kind,
            exact_len,
            None,
            REFERENCE_CODEC_RAW,
            None,
        )
    }

    /// Begin a governed raw Blob write. The store derives both quota charges
    /// and ordinary capacity internally before returning a writer, so callers
    /// cannot understate physical attribution or borrow cleaner reserve.
    pub fn begin_blob_for_principal(
        &mut self,
        principal: &StoragePrincipal,
        object_kind: u32,
        exact_len: u64,
        expected_root: Option<Hash>,
    ) -> Result<BlobWriter<'_, D>, CasStoreError<D::Error>> {
        BlobGeometry::for_len(exact_len)?;
        StreamingMerkle::begin(object_kind, exact_len, EmissionSink::new())
            .map_err(map_streaming_error)?;
        let reservation = self.reserve_blob_quota(principal, exact_len)?;
        self.begin_blob_with_reference_codec_internal(
            object_kind,
            exact_len,
            expected_root,
            REFERENCE_CODEC_RAW,
            Some(reservation),
        )
    }

    pub(crate) fn begin_blob_with_reference_codec(
        &mut self,
        object_kind: u32,
        exact_len: u64,
        expected_root: Option<Hash>,
        reference_codec: u16,
    ) -> Result<BlobWriter<'_, D>, CasStoreError<D::Error>> {
        if self.quota.is_some() {
            return Err(StoreError::PrincipalRequired.into());
        }
        self.begin_blob_with_reference_codec_internal(
            object_kind,
            exact_len,
            expected_root,
            reference_codec,
            None,
        )
    }

    /// Trusted-service writer used only while an exact store maintenance
    /// lease is held. This keeps system-owned typed roots out of application
    /// quota domains without reopening the unprincipal public write path.
    pub(crate) fn begin_blob_with_reference_codec_for_maintenance(
        &mut self,
        _lease: &MaintenanceOperationLease,
        object_kind: u32,
        exact_len: u64,
        expected_root: Option<Hash>,
        reference_codec: u16,
    ) -> Result<BlobWriter<'_, D>, CasStoreError<D::Error>> {
        self.begin_blob_with_reference_codec_internal(
            object_kind,
            exact_len,
            expected_root,
            reference_codec,
            None,
        )
    }

    pub(crate) fn begin_blob_with_reference_codec_for_principal(
        &mut self,
        principal: &StoragePrincipal,
        object_kind: u32,
        exact_len: u64,
        expected_root: Option<Hash>,
        reference_codec: u16,
    ) -> Result<BlobWriter<'_, D>, CasStoreError<D::Error>> {
        BlobGeometry::for_len(exact_len)?;
        StreamingMerkle::begin(object_kind, exact_len, EmissionSink::new())
            .map_err(map_streaming_error)?;
        let reservation = self.reserve_blob_quota(principal, exact_len)?;
        self.begin_blob_with_reference_codec_internal(
            object_kind,
            exact_len,
            expected_root,
            reference_codec,
            Some(reservation),
        )
    }

    pub(crate) fn reserve_blob_quota(
        &self,
        principal: &StoragePrincipal,
        exact_len: u64,
    ) -> Result<QuotaReservation, CasStoreError<D::Error>> {
        let state = self.require_current_generation()?;
        let counts = state.allocation.counts().map_err(|_| StoreError::Corrupt)?;
        let protected = u64::from(state.cleaner_reserve_segments)
            .checked_add(u64::from(crate::store::ROOT_POLICY_HEADROOM_SEGMENTS))
            .ok_or(StoreError::Corrupt)?;
        let ordinary_segments = counts.free.saturating_sub(protected);
        let ordinary_available_bytes = ordinary_segments
            .checked_mul(SEGMENT_PAGES)
            .and_then(|pages| pages.checked_mul(PAGE_SIZE as u64))
            .ok_or(StoreError::Corrupt)?;
        let physical_bytes = canonical_attributable_physical_bytes(exact_len)?;
        self.quota
            .as_ref()
            .ok_or(crate::quota::QuotaError::UnknownPrincipal)?
            .reserve(
                principal,
                exact_len,
                physical_bytes,
                ordinary_available_bytes,
            )
            .map_err(Into::into)
    }

    pub(crate) fn begin_blob_with_quota_reservation(
        &mut self,
        object_kind: u32,
        exact_len: u64,
        reservation: QuotaReservation,
    ) -> Result<BlobWriter<'_, D>, CasStoreError<D::Error>> {
        self.begin_blob_with_reference_codec_internal(
            object_kind,
            exact_len,
            None,
            REFERENCE_CODEC_RAW,
            Some(reservation),
        )
    }

    fn begin_blob_with_reference_codec_internal(
        &mut self,
        object_kind: u32,
        exact_len: u64,
        expected_root: Option<Hash>,
        reference_codec: u16,
        quota_reservation: Option<QuotaReservation>,
    ) -> Result<BlobWriter<'_, D>, CasStoreError<D::Error>> {
        if reference_codec != REFERENCE_CODEC_RAW
            && reference_codec != crate::cas_codec::REFERENCE_CODEC_TYPED_V1
            && reference_codec != crate::cas_codec::REFERENCE_CODEC_FS_V1
        {
            return Err(StoreError::InvalidConfig.into());
        }
        // Immutable caller errors must be rejected before a foreground caller
        // can decide to clean, and therefore before any GC media mutation.
        let geometry = BlobGeometry::for_len(exact_len)?;
        let merkle = StreamingMerkle::begin(object_kind, exact_len, EmissionSink::new())
            .map_err(map_streaming_error)?;
        let current = self.require_current_generation()?;
        if !current.catalog.is_empty() {
            return Err(StoreError::CatalogMode.into());
        }
        if !current.allocation.retired_segments().is_empty() {
            return Err(StoreError::GcResumeRequired.into());
        }
        let cas_object_count = current.cas.as_ref().map_or(0, |cas| cas.objects.len());
        if cas_object_count >= self.limits.max_catalog_entries as usize {
            return Err(StoreError::Capacity(CapacityClass::Metadata).into());
        }
        let prospective_objects = cas_object_count
            .checked_add(1)
            .ok_or(StoreError::Capacity(CapacityClass::Metadata))?;
        // The root is not known until streaming completes, so admission uses
        // the safe worst case that this is a new Blob mapping. This guarantees
        // every admitted commit can be cold-mounted within the configured
        // recovery ceiling.
        let prospective_blobs = current
            .cas
            .as_ref()
            .map_or(0, |cas| cas.blobs.len())
            .checked_add(1)
            .ok_or(StoreError::Capacity(CapacityClass::Metadata))?;
        let snapshot_bytes = CAS_SNAPSHOT_HEADER_LEN
            .checked_add(
                prospective_objects
                    .checked_mul(OBJECT_MAPPING_LEN)
                    .ok_or(StoreError::Capacity(CapacityClass::Metadata))?,
            )
            .and_then(|bytes| {
                prospective_blobs
                    .checked_mul(BLOB_MAPPING_LEN)
                    .and_then(|more| bytes.checked_add(more))
            })
            .ok_or(StoreError::Capacity(CapacityClass::Metadata))?;
        let recovered_tables = prospective_objects
            .checked_mul(core::mem::size_of::<ObjectMapping>())
            .and_then(|bytes| {
                prospective_blobs
                    .checked_mul(core::mem::size_of::<BlobMapping>())
                    .and_then(|more| bytes.checked_add(more))
            })
            .ok_or(StoreError::Capacity(CapacityClass::Metadata))?;
        if snapshot_bytes > MAX_METADATA_PAYLOAD_LEN
            || snapshot_bytes
                .checked_add(recovered_tables)
                .is_none_or(|peak| peak > self.limits.recovery_memory_bytes)
        {
            return Err(StoreError::Capacity(CapacityClass::Metadata).into());
        }
        let checkpoint_generation = current
            .generation
            .checked_add(1)
            .ok_or(StoreError::IdExhausted)?;
        let (mut extents, mut segments) = plan_scratch(
            current.superblock.binding.store_uuid,
            current.next_physical_segment,
            current.next_segment_generation,
            checkpoint_generation,
            geometry,
        )?;
        let required = u64::try_from(segments.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or(StoreError::Capacity(CapacityClass::Payload))?;
        let first_segment = current
            .find_free_run(required, false)
            .ok_or(StoreError::Capacity(CapacityClass::CleanerReserve))?;
        if first_segment != current.next_physical_segment {
            (extents, segments) = plan_scratch(
                current.superblock.binding.store_uuid,
                first_segment,
                current.next_segment_generation,
                checkpoint_generation,
                geometry,
            )?;
        }
        let state = self.mounted.take().ok_or(StoreError::NotMounted)?;
        self.poisoned = true;
        let content_count = usize::try_from(geometry.exact_len())
            .map_err(|_| StoreError::ObjectTooLarge)?
            .div_ceil(CANONICAL_CONTENT_EXTENT_LEN as usize);
        let mut content_hashers = Vec::new();
        content_hashers
            .try_reserve_exact(content_count)
            .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
        for _ in 0..content_count {
            content_hashers.push(Sha256::new());
        }
        let tree_page_count = usize::try_from(geometry.tree_len())
            .map_err(|_| StoreError::ObjectTooLarge)?
            .div_ceil(PAGE_SIZE);
        let mut tree_pages = Vec::new();
        tree_pages
            .try_reserve_exact(tree_page_count)
            .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
        tree_pages.resize(tree_page_count, None);
        Ok(BlobWriter {
            store: self,
            state: Some(state),
            object_kind,
            reference_codec,
            geometry,
            expected_root,
            merkle: Some(merkle),
            extents,
            segments,
            tree_pages,
            content_hashers,
            header_hash: None,
            tree_hash: None,
            prepared: false,
            mutated: false,
            failed: false,
            quota_reservation,
            staged_sink: None,
        })
    }

    pub async fn get_blob_chunk(
        &self,
        object: &AuthorizedObject<CasObjectHandle>,
        index: u32,
    ) -> Result<VerifiedCasChunk, CasStoreError<D::Error>> {
        let read_pin = self.pin_blob_reader(object)?;
        let (descriptor, manifest) = self.resolve_authorized_manifest(object).await?;
        let geometry = BlobGeometry::for_len(descriptor.byte_len)?;
        if index >= geometry.leaf_count() {
            return Err(BlobError::ChunkOutOfRange.into());
        }
        let content_offset = HEADER_SIZE as u64 + u64::from(index) * LEAF_SIZE as u64;
        let chunk_len = if descriptor.byte_len == 0 {
            0
        } else {
            descriptor
                .byte_len
                .saturating_sub(u64::from(index) * LEAF_SIZE as u64)
                .min(LEAF_SIZE as u64) as usize
        };
        let bytes = if chunk_len == 0 {
            Vec::new()
        } else {
            read_manifest_range(
                &self.device,
                self.mounted.as_ref().ok_or(StoreError::NotMounted)?,
                &manifest,
                content_offset,
                chunk_len,
            )
            .await?
        };
        let mut siblings = Vec::new();
        siblings
            .try_reserve_exact(geometry.height() as usize)
            .map_err(|_| StoreError::MemoryLimit)?;
        let mut position = index as usize;
        let mut level_width = geometry.padded_leaf_count() as usize;
        let mut level_base = 0_usize;
        while level_width > 1 {
            let node_index = level_base
                .checked_add(position ^ 1)
                .ok_or(StoreError::Corrupt)?;
            let node_offset = u64::try_from(geometry.tree_offset())
                .ok()
                .and_then(|offset| offset.checked_add((node_index * HASH_SIZE) as u64))
                .ok_or(StoreError::Corrupt)?;
            let node = read_manifest_range(
                &self.device,
                self.mounted.as_ref().ok_or(StoreError::NotMounted)?,
                &manifest,
                node_offset,
                HASH_SIZE,
            )
            .await?;
            siblings.push(
                node.as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Corrupt)?,
            );
            level_base = level_base
                .checked_add(level_width)
                .ok_or(StoreError::Corrupt)?;
            position /= 2;
            level_width /= 2;
        }
        let proof = MerkleProof {
            leaf_index: index,
            siblings,
        };
        verify_proof(descriptor, &bytes, &proof)?;
        drop(read_pin);
        Ok(VerifiedCasChunk {
            descriptor,
            index,
            bytes,
            proof,
        })
    }

    pub async fn verify_blob(
        &self,
        object: &AuthorizedObject<CasObjectHandle>,
    ) -> Result<VerifiedCasBlob, CasStoreError<D::Error>> {
        let read_pin = self.pin_blob_reader(object)?;
        let (descriptor, manifest) = self.resolve_authorized_manifest(object).await?;
        let state = self.mounted.as_ref().ok_or(StoreError::NotMounted)?;
        verify_resolved_blob(&self.device, state, descriptor, &manifest).await?;
        drop(read_pin);
        Ok(VerifiedCasBlob {
            descriptor,
            verified_encoded_bytes: manifest.encoded_blob_len,
        })
    }

    /// Resolve authority and the manifest once, then return the complete
    /// logical Blob while performing the same full Merkle verification as
    /// `verify_blob`. This avoids re-resolving and re-scanning the manifest for
    /// every leaf in callers which need the whole object.
    pub(crate) async fn read_verified_blob(
        &self,
        object: &AuthorizedObject<CasObjectHandle>,
    ) -> Result<Vec<u8>, CasStoreError<D::Error>> {
        let read_pin = self.pin_blob_reader(object)?;
        let (descriptor, manifest) = self.resolve_authorized_manifest_unverified(object).await?;
        let state = self.mounted.as_ref().ok_or(StoreError::NotMounted)?;
        // The batched path retains resolved payloads, one contiguous encoded
        // image, and the decoded output at the same time. Keep that working
        // set below one recovery-memory budget even when a caller supplies a
        // smaller-than-default limit.
        let batched_limit = MAX_BATCHED_BLOB_READ_LIMIT.min(self.limits.recovery_memory_bytes / 4);
        let bytes = if manifest.encoded_blob_len <= batched_limit as u64 {
            read_small_verified_blob(&self.device, state, descriptor, &manifest).await?
        } else {
            validate_resolved_manifest(&self.device, state, descriptor, &manifest).await?;
            read_and_verify_resolved_blob(&self.device, state, descriptor, &manifest).await?
        };
        drop(read_pin);
        Ok(bytes)
    }

    async fn resolve_authorized_manifest(
        &self,
        object: &AuthorizedObject<CasObjectHandle>,
    ) -> Result<(BlobDescriptor, BlobManifest), CasStoreError<D::Error>> {
        let (descriptor, manifest) = self.resolve_authorized_manifest_unverified(object).await?;
        let state = self.mounted.as_ref().ok_or(StoreError::NotMounted)?;
        validate_resolved_manifest(&self.device, state, descriptor, &manifest).await?;
        Ok((descriptor, manifest))
    }

    async fn resolve_authorized_manifest_unverified(
        &self,
        object: &AuthorizedObject<CasObjectHandle>,
    ) -> Result<(BlobDescriptor, BlobManifest), CasStoreError<D::Error>> {
        let state = self.mounted.as_ref().ok_or(if self.poisoned {
            StoreError::RecoveryRequired
        } else {
            StoreError::NotMounted
        })?;
        if self.published_generation.load(Ordering::Acquire) != state.generation {
            return Err(StoreError::RecoveryRequired.into());
        }
        let cas = state.cas.as_ref().ok_or(StoreError::ObjectUnavailable)?;
        let handle = object.backend_handle();
        if handle.root_key(&self.pins).is_err()
            && !state.persistent_roots.as_ref().is_some_and(|roots| {
                roots.entries().iter().any(|root| {
                    root.object_id == handle.object_id
                        && root.commit_generation == handle.commit_generation
                        && root.object_kind == handle.object_kind
                })
            })
        {
            return Err(StoreError::ObjectUnavailable.into());
        }
        if handle.store_uuid != state.superblock.binding.store_uuid
            || handle.object_kind != object.object_kind()
            || handle.exact_len != object.exact_len()
        {
            return Err(StoreError::ObjectUnavailable.into());
        }
        let mapping = cas
            .objects
            .binary_search_by_key(&handle.object_id, |mapping| mapping.object_id)
            .ok()
            .map(|index| cas.objects[index])
            .filter(|mapping| {
                mapping.commit_generation == handle.commit_generation
                    && mapping.blob_key.object_kind() == handle.object_kind
                    && mapping.blob_key.exact_len() == handle.exact_len
            })
            .ok_or(StoreError::ObjectUnavailable)?;
        let blob = cas
            .blobs
            .binary_search_by_key(&mapping.blob_key, |blob| blob.blob_key)
            .ok()
            .map(|index| cas.blobs[index])
            .ok_or(StoreError::ObjectUnavailable)?;
        let payload = read_pointer_payload(
            &self.device,
            state.superblock.binding.store_uuid,
            state.admitted_segments,
            state.next_segment_generation,
            state.generation,
            blob.manifest,
            ExtentKind::Catalog,
            self.limits.recovery_memory_bytes,
        )
        .await?;
        let context = CasCodecContext::new(
            state.superblock.binding.store_uuid,
            state.admitted_segments,
            state.next_segment_generation,
        )?;
        let manifest = decode_blob_manifest(&payload.bytes, context)?;
        if manifest.blob_key != mapping.blob_key {
            return Err(StoreError::Corrupt.into());
        }
        let descriptor = BlobDescriptor {
            object_kind: mapping.blob_key.object_kind(),
            byte_len: mapping.blob_key.exact_len(),
            leaf_count: BlobGeometry::for_len(mapping.blob_key.exact_len())?.leaf_count(),
            tree_node_count: BlobGeometry::for_len(mapping.blob_key.exact_len())?.tree_node_count(),
            root: mapping.blob_key.merkle_root(),
        };
        Ok((descriptor, manifest))
    }

    fn pin_blob_reader(
        &self,
        object: &AuthorizedObject<CasObjectHandle>,
    ) -> Result<OwnedObjectReadPin<ROOT_PIN_SLOTS, READER_PIN_SLOTS>, CasStoreError<D::Error>> {
        let state = self.mounted.as_ref().ok_or(if self.poisoned {
            StoreError::RecoveryRequired
        } else {
            StoreError::NotMounted
        })?;
        if self.published_generation.load(Ordering::Acquire) != state.generation {
            return Err(StoreError::RecoveryRequired.into());
        }
        let handle = object.backend_handle();
        let key = handle
            .authority_key()
            .map_err(|_| StoreError::ObjectUnavailable)?;
        let runtime_root = handle.root_key(&self.pins).ok();
        let durable_root = state.persistent_roots.as_ref().is_some_and(|roots| {
            roots.entries().iter().any(|root| {
                root.object_id == key.object_id()
                    && root.commit_generation == key.commit_generation()
                    && root.object_kind == key.object_kind()
            })
        });
        if runtime_root != Some(key) && !durable_root {
            return Err(StoreError::ObjectUnavailable.into());
        }
        let owner = self
            .pins
            .allocate_owner()
            .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
        let pin = PinRegistry::pin_object_reader_owned(
            &self.pins,
            key,
            state.generation,
            owner,
            PinAdmission::Ordinary,
        )
        .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
        let observed_generation = self.published_generation.load(Ordering::Acquire);
        pin.finish_recheck(key, observed_generation)
            .map_err(|_| StoreError::ObjectUnavailable.into())
    }
}

/// Verify one already-resolved manifest without exercising object authority.
/// This is crate-private so GC and scrub can authenticate staged media without
/// turning a content digest or catalog identity into an object-opening API.
pub(crate) async fn verify_manifest_blob<D: PageDevice>(
    device: &D,
    state: &MountedState,
    manifest: &BlobManifest,
) -> Result<(), CasStoreError<D::Error>> {
    let geometry = BlobGeometry::for_len(manifest.blob_key.exact_len())?;
    let descriptor = BlobDescriptor {
        object_kind: manifest.blob_key.object_kind(),
        byte_len: manifest.blob_key.exact_len(),
        leaf_count: geometry.leaf_count(),
        tree_node_count: geometry.tree_node_count(),
        root: manifest.blob_key.merkle_root(),
    };
    validate_cas_blob_descriptors(
        device,
        state.superblock.binding.store_uuid,
        state.admitted_segments,
        state.next_segment_generation,
        state.generation,
        manifest,
    )
    .await?;
    let header = read_manifest_range(device, state, manifest, 0, HEADER_SIZE).await?;
    let header: &[u8; HEADER_SIZE] = header
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::Corrupt)?;
    if BlobDescriptor::decode_header(header)? != descriptor {
        return Err(StoreError::Corrupt.into());
    }
    verify_resolved_blob(device, state, descriptor, manifest).await
}

async fn validate_resolved_manifest<D: PageDevice>(
    device: &D,
    state: &MountedState,
    descriptor: BlobDescriptor,
    manifest: &BlobManifest,
) -> Result<(), CasStoreError<D::Error>> {
    validate_cas_blob_descriptors(
        device,
        state.superblock.binding.store_uuid,
        state.admitted_segments,
        state.next_segment_generation,
        state.generation,
        manifest,
    )
    .await?;
    let header = read_manifest_range(device, state, manifest, 0, HEADER_SIZE).await?;
    let header: &[u8; HEADER_SIZE] = header
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::Corrupt)?;
    if BlobDescriptor::decode_header(header)? != descriptor {
        return Err(StoreError::Corrupt.into());
    }
    Ok(())
}

async fn read_small_verified_blob<D: PageDevice>(
    device: &D,
    state: &MountedState,
    descriptor: BlobDescriptor,
    manifest: &BlobManifest,
) -> Result<Vec<u8>, CasStoreError<D::Error>> {
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(manifest.extents.len())
        .map_err(|_| StoreError::MemoryLimit)?;
    requests.extend(manifest.extents.iter().map(|extent| {
        (
            extent.pointer,
            ExtentKind::Blob,
            CANONICAL_CONTENT_EXTENT_LEN as usize,
        )
    }));
    let resolved = read_pointer_payloads(
        device,
        state.superblock.binding.store_uuid,
        state.admitted_segments,
        state.next_segment_generation,
        state.generation,
        &requests,
    )
    .await?;
    if resolved.len() != manifest.extents.len() {
        return Err(StoreError::Corrupt.into());
    }
    let encoded_len =
        usize::try_from(manifest.encoded_blob_len).map_err(|_| StoreError::MemoryLimit)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| StoreError::MemoryLimit)?;
    for (declared, observed) in manifest.extents.iter().zip(&resolved) {
        let extent = observed.extent;
        if encoded.len() as u64 != declared.encoded_offset
            || extent.extent_kind != ExtentKind::Blob
            || extent.object_kind != descriptor.object_kind
            || extent.extent_index != declared.extent_index
            || extent.extent_count != declared.extent_count
            || extent.content_byte_len != descriptor.byte_len
            || extent.encoded_blob_len != manifest.encoded_blob_len
            || extent.encoded_offset != declared.encoded_offset
            || extent.payload_byte_len != declared.payload_byte_len
            || extent.merkle_root != descriptor.root
            || observed.bytes.len() as u64 != declared.payload_byte_len
        {
            return Err(StoreError::Corrupt.into());
        }
        encoded.extend_from_slice(&observed.bytes);
    }
    if encoded.len() != encoded_len {
        return Err(StoreError::Corrupt.into());
    }
    let blob = BlobView::decode(&encoded)?;
    if blob.descriptor() != descriptor {
        return Err(StoreError::Corrupt.into());
    }
    blob.verify_all()?;
    Ok(blob.data().to_vec())
}

async fn verify_resolved_blob<D: PageDevice>(
    device: &D,
    state: &MountedState,
    descriptor: BlobDescriptor,
    manifest: &BlobManifest,
) -> Result<(), CasStoreError<D::Error>> {
    let geometry = BlobGeometry::for_len(descriptor.byte_len)?;
    let mut builder = StreamingMerkle::begin(
        descriptor.object_kind,
        descriptor.byte_len,
        EmissionSink::new(),
    )
    .map_err(map_streaming_error)?;
    for index in 0..geometry.leaf_count() {
        if descriptor.byte_len == 0 {
            break;
        }
        let chunk_len = descriptor
            .byte_len
            .saturating_sub(u64::from(index) * LEAF_SIZE as u64)
            .min(LEAF_SIZE as u64) as usize;
        let bytes = read_manifest_range(
            device,
            state,
            manifest,
            HEADER_SIZE as u64 + u64::from(index) * LEAF_SIZE as u64,
            chunk_len,
        )
        .await?;
        builder
            .push_chunk(index, &bytes)
            .map_err(map_streaming_error)?;
        verify_tree_emissions(device, state, manifest, geometry, builder.sink_mut().take()).await?;
    }
    while builder.padding_remaining().map_err(map_streaming_error)? != 0 {
        builder.pad_next().map_err(map_streaming_error)?;
        verify_tree_emissions(device, state, manifest, geometry, builder.sink_mut().take()).await?;
    }
    let computed = builder.finalize().map_err(map_streaming_error)?;
    if computed.descriptor != descriptor {
        return Err(StoreError::Corrupt.into());
    }
    Ok(())
}

async fn read_and_verify_resolved_blob<D: PageDevice>(
    device: &D,
    state: &MountedState,
    descriptor: BlobDescriptor,
    manifest: &BlobManifest,
) -> Result<Vec<u8>, CasStoreError<D::Error>> {
    let geometry = BlobGeometry::for_len(descriptor.byte_len)?;
    let exact_len = usize::try_from(descriptor.byte_len).map_err(|_| StoreError::MemoryLimit)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(exact_len)
        .map_err(|_| StoreError::MemoryLimit)?;
    let mut builder = StreamingMerkle::begin(
        descriptor.object_kind,
        descriptor.byte_len,
        EmissionSink::new(),
    )
    .map_err(map_streaming_error)?;
    for index in 0..geometry.leaf_count() {
        if descriptor.byte_len == 0 {
            break;
        }
        let chunk_len = descriptor
            .byte_len
            .saturating_sub(u64::from(index) * LEAF_SIZE as u64)
            .min(LEAF_SIZE as u64) as usize;
        let bytes = read_manifest_range(
            device,
            state,
            manifest,
            HEADER_SIZE as u64 + u64::from(index) * LEAF_SIZE as u64,
            chunk_len,
        )
        .await?;
        builder
            .push_chunk(index, &bytes)
            .map_err(map_streaming_error)?;
        output.extend_from_slice(&bytes);
        verify_tree_emissions(device, state, manifest, geometry, builder.sink_mut().take()).await?;
    }
    while builder.padding_remaining().map_err(map_streaming_error)? != 0 {
        builder.pad_next().map_err(map_streaming_error)?;
        verify_tree_emissions(device, state, manifest, geometry, builder.sink_mut().take()).await?;
    }
    let computed = builder.finalize().map_err(map_streaming_error)?;
    if computed.descriptor != descriptor || output.len() != exact_len {
        return Err(StoreError::Corrupt.into());
    }
    Ok(output)
}

impl<D: PageDevice> Drop for BlobWriter<'_, D> {
    fn drop(&mut self) {
        if !self.mutated {
            if let Some(state) = self.state.take() {
                self.store.mounted = Some(state);
                self.store.poisoned = false;
            }
        }
    }
}

async fn verify_tree_emissions<D: PageDevice>(
    device: &D,
    state: &MountedState,
    manifest: &BlobManifest,
    geometry: BlobGeometry,
    emissions: [Option<Emission>; MAX_STREAMING_EMISSIONS_PER_STEP],
) -> Result<(), CasStoreError<D::Error>> {
    let tree_offset = geometry.tree_offset() as u64;
    for emission in emissions.into_iter().flatten() {
        if emission.index >= geometry.tree_node_count() {
            return Err(StoreError::Corrupt.into());
        }
        let offset = tree_offset
            .checked_add(u64::from(emission.index) * HASH_SIZE as u64)
            .ok_or(StoreError::Corrupt)?;
        let stored = read_manifest_range(device, state, manifest, offset, HASH_SIZE).await?;
        if stored.as_slice() != emission.hash {
            return Err(StoreError::Corrupt.into());
        }
    }
    Ok(())
}

pub(crate) async fn read_manifest_range<D: PageDevice>(
    device: &D,
    state: &MountedState,
    manifest: &BlobManifest,
    encoded_offset: u64,
    len: usize,
) -> Result<Vec<u8>, CasStoreError<D::Error>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let len_u64 = u64::try_from(len).map_err(|_| StoreError::Corrupt)?;
    let encoded_end = encoded_offset
        .checked_add(len_u64)
        .ok_or(StoreError::Corrupt)?;
    if encoded_end > manifest.encoded_blob_len {
        return Err(StoreError::Corrupt.into());
    }
    let declared = manifest
        .extents
        .iter()
        .find(|extent| {
            extent
                .encoded_offset
                .checked_add(extent.payload_byte_len)
                .is_some_and(|extent_end| {
                    encoded_offset >= extent.encoded_offset && encoded_end <= extent_end
                })
        })
        .ok_or(StoreError::Corrupt)?;
    let PhysicalPointer::Value(pointer) = declared.pointer else {
        return Err(StoreError::Corrupt.into());
    };
    if pointer.store_uuid != state.superblock.binding.store_uuid
        || pointer.segment_no >= state.admitted_segments
        || pointer.segment_generation == 0
        || pointer.segment_generation >= state.next_segment_generation
        || pointer.extent_kind != ExtentKind::Blob
        || pointer.exact_byte_len != declared.payload_byte_len
    {
        return Err(StoreError::Corrupt.into());
    }
    let within = encoded_offset - declared.encoded_offset;
    let first_page = within / PAGE_SIZE as u64;
    let first_byte = usize::try_from(within % PAGE_SIZE as u64).map_err(|_| StoreError::Corrupt)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(len)
        .map_err(|_| StoreError::MemoryLimit)?;
    output.resize(len, 0);
    let base = segment_base_page(pointer.segment_no)?;
    let mut copied = 0_usize;
    let mut page_index = first_page;
    while copied != len {
        let mut page = heap_page();
        let physical = base
            .checked_add(u64::from(pointer.payload_relative_page))
            .and_then(|value| value.checked_add(page_index))
            .ok_or(StoreError::Corrupt)?;
        device
            .read_page(physical, &mut page)
            .await
            .map_err(StoreError::Device)?;
        let in_page = if page_index == first_page {
            first_byte
        } else {
            0
        };
        let take = (len - copied).min(PAGE_SIZE - in_page);
        output[copied..copied + take].copy_from_slice(&page[in_page..in_page + take]);
        copied += take;
        page_index = page_index.checked_add(1).ok_or(StoreError::Corrupt)?;
    }
    Ok(output)
}

impl<'a, D: PageDevice> BlobWriter<'a, D> {
    pub const fn exact_len(&self) -> u64 {
        self.geometry.exact_len()
    }

    pub fn received_len(&self) -> u64 {
        self.merkle
            .as_ref()
            .map_or(self.geometry.exact_len(), StreamingMerkle::received_len)
    }

    pub async fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), CasStoreError<D::Error>> {
        if self.failed {
            return Err(CasStoreError::WriterFailed);
        }
        // Validate the complete logical operation in memory before the first
        // durable mutation. A wrong length/order therefore leaves no orphan and
        // dropping the writer restores the still-mounted store.
        let merkle = self.merkle.as_ref().ok_or(CasStoreError::WriterFailed)?;
        let index = merkle.next_chunk_index();
        let received = merkle.received_len();
        let remaining = merkle
            .exact_len()
            .checked_sub(received)
            .ok_or(CasStoreError::InvalidChunk)?;
        let expected_len = remaining.min(LEAF_SIZE as u64) as usize;
        if expected_len == 0 || bytes.len() != expected_len {
            return Err(CasStoreError::InvalidChunk);
        }
        let content_offset = u64::from(index)
            .checked_mul(LEAF_SIZE as u64)
            .and_then(|offset| offset.checked_add(HEADER_SIZE as u64))
            .ok_or(StoreError::ObjectTooLarge)?;
        self.prepare().await?;
        if let Err(error) = self
            .merkle
            .as_mut()
            .ok_or(CasStoreError::WriterFailed)?
            .push_chunk(index, bytes)
            .map_err(map_streaming_error)
        {
            self.failed = true;
            return Err(error);
        }
        let content_slot = usize::try_from(index)
            .map_err(|_| StoreError::Corrupt)?
            .checked_mul(LEAF_SIZE)
            .ok_or(StoreError::Corrupt)?
            / CANONICAL_CONTENT_EXTENT_LEN as usize;
        if let Some(hasher) = self.content_hashers.get_mut(content_slot) {
            hasher.update(bytes);
        }
        let mut page = heap_page();
        page[..bytes.len()].copy_from_slice(bytes);
        if let Err(error) = self.write_exact_page(content_offset, &page).await {
            self.failed = true;
            return Err(error);
        }
        if let Err(error) = self.drain_emissions().await {
            self.failed = true;
            return Err(error);
        }
        Ok(())
    }

    async fn prepare(&mut self) -> Result<(), CasStoreError<D::Error>> {
        if self.prepared {
            return Ok(());
        }
        self.mutated = true;
        self.state.as_ref().ok_or(CasStoreError::WriterFailed)?;
        let extra_metadata_segment = self
            .segments
            .last()
            .and_then(|segment| segment.segment_no.checked_add(1))
            .ok_or(StoreError::Capacity(CapacityClass::Payload))?;
        let zero = heap_page();
        for segment_no in self
            .segments
            .iter()
            .map(|segment| segment.segment_no)
            .chain(core::iter::once(extra_metadata_segment))
        {
            let base = segment_base_page(segment_no)?;
            self.store
                .device
                .write_page(base + u64::from(SEGMENT_SEAL_PAGE), zero.as_ref())
                .await
                .map_err(StoreError::Mutation)?;
        }
        self.store
            .device
            .flush()
            .await
            .map_err(StoreError::Mutation)?;
        for segment_no in self
            .segments
            .iter()
            .map(|segment| segment.segment_no)
            .chain(core::iter::once(extra_metadata_segment))
        {
            let base = segment_base_page(segment_no)?;
            let mut observed = heap_page();
            self.store
                .device
                .read_page(base + u64::from(SEGMENT_SEAL_PAGE), &mut observed)
                .await
                .map_err(StoreError::Device)?;
            if observed != zero {
                self.failed = true;
                return Err(StoreError::Corrupt.into());
            }
        }
        self.prepared = true;
        Ok(())
    }

    async fn write_exact_page(
        &mut self,
        encoded_offset: u64,
        page: &Page,
    ) -> Result<(), CasStoreError<D::Error>> {
        // Extents carry exact logical byte lengths but occupy whole physical
        // pages.  Header and final-content extents are intentionally shorter
        // than a page, so locate by the first logical byte and permit the
        // zero-padded physical tail to be written with it.
        let (extent, within) = find_scratch_page(&self.extents, encoded_offset)?;
        let physical = segment_base_page(extent.segment_no)?
            .checked_add(u64::from(extent.payload_relative_page))
            .and_then(|page| page.checked_add(within / PAGE_SIZE as u64))
            .ok_or(StoreError::Corrupt)?;
        sink_or_write_page(&self.store.device, self.staged_sink.as_mut(), physical, page)
            .await?;
        Ok(())
    }

    /// Route this writer's scratch writes through an in-memory sink so a
    /// fused publication can drain them as batched device requests.
    pub(crate) fn enable_staged_batching(&mut self) {
        if self.staged_sink.is_none() {
            self.staged_sink = Some(PageSink::new());
        }
    }

    async fn drain_emissions(&mut self) -> Result<(), CasStoreError<D::Error>> {
        let emissions = self
            .merkle
            .as_mut()
            .ok_or(CasStoreError::WriterFailed)?
            .sink_mut()
            .take();
        for emission in emissions.into_iter().flatten() {
            let tree_relative = u64::from(emission.index)
                .checked_mul(HASH_SIZE as u64)
                .ok_or(StoreError::Corrupt)?;
            let encoded_offset = u64::try_from(self.geometry.tree_offset())
                .ok()
                .and_then(|offset| offset.checked_add(tree_relative))
                .ok_or(StoreError::Corrupt)?;
            let (_extent, within) =
                find_scratch_extent(&self.extents, encoded_offset, HASH_SIZE as u64)?;
            let tree_page =
                usize::try_from(within / PAGE_SIZE as u64).map_err(|_| StoreError::Corrupt)?;
            let in_page =
                usize::try_from(within % PAGE_SIZE as u64).map_err(|_| StoreError::Corrupt)?;
            // Patch the in-memory tree page instead of a media read-modify-
            // write; all tree pages are written once at finish time.
            let page = match self.tree_pages.get_mut(tree_page) {
                Some(slot) => match slot {
                    Some(page) => page,
                    None => {
                        *slot = Some(heap_page());
                        slot.as_mut().expect("freshly inserted tree page")
                    }
                },
                None => return Err(StoreError::Corrupt.into()),
            };
            page[in_page..in_page + HASH_SIZE].copy_from_slice(&emission.hash);
        }
        Ok(())
    }

    pub fn commit(
        self,
    ) -> impl Future<Output = Result<AuthorizedObject<CasObjectHandle>, CasStoreError<D::Error>>> + 'a
    {
        // Move the modest writer state to its final heap address before the
        // async generator is constructed. This is deliberately not
        // `Box::pin(async { ... })`: no large child future is first
        // materialized on the kernel stack.
        let mut writer = Box::new(self);
        async move {
            let root = writer.finish_blob_encoding(false).await?;
            let (pending, object_kind, exact_len, previous, checkpoint, successor) =
                writer.commit_encoded_snapshot(root).await?;
            // The checkpoint is durable, but publication is still withheld. A
            // cold reread installs the exact selected successor before
            // authority can escape. The predecessor was already verified by
            // the current mount and is retained only as a transition witness.
            writer
                .store
                .mount_verified_successor(previous, checkpoint, successor, true)
                .await?;
            let quota_charge = match writer.quota_reservation.take() {
                Some(reservation) => {
                    let table = writer
                        .store
                        .quota
                        .clone()
                        .ok_or(crate::quota::QuotaError::UnknownPrincipal)?;
                    let charge = if pending.is_new_blob {
                        reservation.commit()
                    } else {
                        reservation.commit_with_unique_physical(QUOTA_DEDUP_UNIQUE_OBJECT_BYTES)?
                    };
                    Some((table, charge))
                }
                None => None,
            };
            let handle = pending.complete(quota_charge);
            let maximum_persistence = if handle.is_quota_charged() {
                ObjectPublicationPersistence::RuntimeOnly
            } else {
                ObjectPublicationPersistence::Persistent
            };
            Ok(AuthorizedObject::from_committed(
                handle,
                object_kind,
                exact_len,
                maximum_persistence,
            ))
        }
    }

    /// Complete the streaming Merkle state and persist the canonical header.
    /// This phase intentionally ends before catalog publication so its Merkle
    /// locals cannot overlap the snapshot or cold-mount child futures.
    async fn finish_blob_encoding(
        &mut self,
        defer_barriers: bool,
    ) -> Result<Hash, CasStoreError<D::Error>> {
        if self.failed {
            return Err(CasStoreError::WriterFailed);
        }
        // Incomplete input is an ordinary caller error. Detect it before
        // prepare() writes the scratch publication barriers.
        self.merkle
            .as_ref()
            .ok_or(CasStoreError::WriterFailed)?
            .padding_remaining()
            .map_err(map_streaming_error)?;
        self.prepare().await?;
        loop {
            let remaining = self
                .merkle
                .as_ref()
                .ok_or(CasStoreError::WriterFailed)?
                .padding_remaining()
                .map_err(map_streaming_error)?;
            if remaining == 0 {
                break;
            }
            self.merkle
                .as_mut()
                .ok_or(CasStoreError::WriterFailed)?
                .pad_next()
                .map_err(map_streaming_error)?;
            self.drain_emissions().await?;
        }
        let streaming = self
            .merkle
            .take()
            .ok_or(CasStoreError::WriterFailed)?
            .finalize()
            .map_err(map_streaming_error)?;
        if self
            .expected_root
            .is_some_and(|expected| expected != streaming.descriptor.root)
        {
            return Err(CasStoreError::ExpectedRootMismatch);
        }

        let mut header_page = heap_page();
        header_page[..HEADER_SIZE].copy_from_slice(&streaming.header);
        self.header_hash = Some(Sha256::digest(&streaming.header).into());
        self.write_exact_page(0, &header_page).await?;
        // Write every buffered tree page (canonical zeros where no emission
        // landed), then hash the exact tree payload from memory.
        let tree_extent = self
            .extents
            .last()
            .cloned()
            .ok_or(CasStoreError::WriterFailed)?;
        let tree_len =
            usize::try_from(self.geometry.tree_len()).map_err(|_| StoreError::Corrupt)?;
        for slot in self.tree_pages.iter_mut() {
            if slot.is_none() {
                *slot = Some(heap_page());
            }
        }
        let tree_base = segment_base_page(tree_extent.segment_no)?;
        for slot_index in 0..self.tree_pages.len() {
            let physical = tree_base
                .checked_add(u64::from(tree_extent.payload_relative_page))
                .and_then(|page| page.checked_add(slot_index as u64))
                .ok_or(StoreError::Corrupt)?;
            let page = *self.tree_pages[slot_index]
                .as_ref()
                .expect("materialized tree page")
                .clone();
            sink_or_write_page(&self.store.device, self.staged_sink.as_mut(), physical, &page)
                .await?;
        }
        let mut tree_hasher = Sha256::new();
        let mut remaining = tree_len;
        for page in &self.tree_pages {
            let take = remaining.min(PAGE_SIZE);
            tree_hasher.update(&page.as_ref().expect("materialized tree page")[..take]);
            remaining -= take;
        }
        if remaining != 0 {
            return Err(StoreError::Corrupt.into());
        }
        self.tree_hash = Some(tree_hasher.finalize().into());
        // Scratch content, tree pages, and the canonical header are still
        // unreachable from every sealed extent and checkpoint. They may share
        // one data-dependency barrier before hashing and metadata publication;
        // cancellation or a power cut before this point can expose no object.
        // A deferring caller folds that barrier into the checkpoint slot
        // protocol's first flush, which precedes the checkpoint body write.
        if !defer_barriers {
            self.store
                .device
                .flush()
                .await
                .map_err(StoreError::Mutation)?;
        }
        Ok(streaming.descriptor.root)
    }

    /// Compute the staged manifest from the streaming in-memory state and
    /// authenticate any dedup candidate. Shared by the immediate-commit and
    /// staged (fused authority) commit paths.
    async fn staged_manifest_and_dedup(
        &mut self,
        root: Hash,
    ) -> Result<(BlobKey, BlobManifest, Vec<Hash>, Option<BlobMapping>), CasStoreError<D::Error>>
    {
        let state = self.state.as_ref().ok_or(CasStoreError::WriterFailed)?;
        let blob_key = BlobKey::sha256(self.object_kind, self.geometry.exact_len(), root)?;

        let mut payload_hashes = Vec::new();
        payload_hashes
            .try_reserve_exact(self.extents.len())
            .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
        // Extent payload hashes come from the streaming in-memory state: the
        // canonical header, the per-extent content hashers, and the buffered
        // tree pages. No media re-read is needed for data just written.
        payload_hashes.push(self.header_hash.take().ok_or(CasStoreError::WriterFailed)?);
        for hasher in self.content_hashers.drain(..) {
            payload_hashes.push(hasher.finalize().into());
        }
        payload_hashes.push(self.tree_hash.take().ok_or(CasStoreError::WriterFailed)?);
        if payload_hashes.len() != self.extents.len() {
            return Err(StoreError::Corrupt.into());
        }
        let scratch_manifest = make_manifest(
            state.superblock.binding.store_uuid,
            blob_key,
            self.geometry.encoded_len() as u64,
            &self.extents,
            &payload_hashes,
        );

        let existing = state.cas.as_ref().and_then(|cas| {
            cas.blobs
                .binary_search_by_key(&blob_key, |mapping| mapping.blob_key)
                .ok()
                .map(|index| cas.blobs[index])
        });
        let existing_mapping = if let Some(mapping) = existing {
            // A key's existing manifest needs one full compare-verification
            // against freshly recomputed content hashes per process: sealed
            // segments are immutable and any later divergence under the same
            // key is already the fatal hash-collision path.
            if !self.store.dedup_verified.contains(&blob_key) {
                let context = CasCodecContext::new(
                    state.superblock.binding.store_uuid,
                    state.admitted_segments,
                    state.next_segment_generation,
                )?;
                // Scratch content may still be buffered in the staged sink;
                // give the comparison a view of the future media contents.
                let overlay =
                    SinkOverlayDevice::new(&self.store.device, self.staged_sink.as_ref());
                let payload = read_pointer_payload(
                    &overlay,
                    state.superblock.binding.store_uuid,
                    state.admitted_segments,
                    state.next_segment_generation,
                    state.generation,
                    mapping.manifest,
                    ExtentKind::Catalog,
                    self.store.limits.recovery_memory_bytes,
                )
                .await?;
                let manifest = decode_blob_manifest(&payload.bytes, context)?;
                if manifest.blob_key != blob_key
                    || !compare_manifests(
                        &overlay,
                        state,
                        &scratch_manifest,
                        &manifest,
                        &self.extents,
                        &payload_hashes,
                    )
                    .await?
                {
                    return Err(CasStoreError::HashCollision);
                }
                self.store.dedup_verified.insert(blob_key);
            }
            Some(mapping)
        } else {
            None
        };
        Ok((blob_key, scratch_manifest, payload_hashes, existing_mapping))
    }

    /// Authenticate any dedup candidate and publish the new CAS checkpoint.
    /// Returning before the subsequent mount keeps the snapshot future out of
    /// the mount suspension variant rather than summing both stack footprints.
    async fn commit_encoded_snapshot(
        &mut self,
        root: Hash,
    ) -> Result<
        (
            PendingCasObjectHandle,
            u32,
            u64,
            MountedState,
            Checkpoint,
            MountedState,
        ),
        CasStoreError<D::Error>,
    > {
        let (blob_key, scratch_manifest, payload_hashes, existing_mapping) =
            self.staged_manifest_and_dedup(root).await?;
        let state = self.state.take().ok_or(CasStoreError::WriterFailed)?;
        let (pending, checkpoint, successor) = commit_snapshot(
            &self.store.device,
            &state,
            self.store.limits,
            blob_key,
            scratch_manifest,
            existing_mapping,
            &self.extents,
            &self.segments,
            &payload_hashes,
            &self.store.pins,
            self.reference_codec,
            None,
            None,
            None,
        )
        .await?;
        Ok((
            pending,
            self.object_kind,
            self.geometry.exact_len(),
            state,
            checkpoint,
            successor,
        ))
    }

    /// Make the blob payload durable and authenticate any dedup candidate,
    /// but write no metadata segment and no checkpoint. New-blob scratch
    /// segments are sealed against the successor checkpoint generation; the
    /// caller must complete publication through
    /// [`SegmentStore::publish_staged_object_with_authority`], which commits
    /// the object mapping and the authority snapshot under one checkpoint.
    /// The store stays poisoned until that publication mounts the successor.
    pub(crate) fn stage_commit(
        self,
    ) -> impl Future<Output = Result<StagedObjectCommit, CasStoreError<D::Error>>> + 'a {
        let mut writer = Box::new(self);
        async move {
            let root = writer.finish_blob_encoding(true).await?;
            let (blob_key, manifest, payload_hashes, existing) =
                writer.staged_manifest_and_dedup(root).await?;
            let state = writer.state.take().ok_or(CasStoreError::WriterFailed)?;
            let checkpoint_generation = state
                .generation
                .checked_add(1)
                .ok_or(StoreError::IdExhausted)?;
            let mut last_scratch_seal = None;
            if existing.is_none() {
                let mut previous = state.last_segment;
                if writer.staged_sink.is_none() {
                    writer.staged_sink = Some(PageSink::new());
                }
                for segment in &writer.segments {
                    previous = Some(
                        seal_scratch_segment(
                            &writer.store.device,
                            &state,
                            checkpoint_generation,
                            blob_key,
                            manifest.encoded_blob_len,
                            *segment,
                            &writer.extents,
                            &payload_hashes,
                            previous,
                            true,
                            writer.staged_sink.as_mut(),
                        )
                        .await?,
                    );
                }
                last_scratch_seal = previous;
            } else {
                // Deduplicated content: the buffered scratch pages will never
                // be referenced by any seal or checkpoint. Discard them so
                // they are not even written to media.
                writer.staged_sink = Some(PageSink::new());
            }
            let quota_charge = match writer.quota_reservation.take() {
                Some(reservation) => {
                    let table = writer
                        .store
                        .quota
                        .clone()
                        .ok_or(crate::quota::QuotaError::UnknownPrincipal)?;
                    let charge = if existing.is_none() {
                        reservation.commit()
                    } else {
                        reservation.commit_with_unique_physical(QUOTA_DEDUP_UNIQUE_OBJECT_BYTES)?
                    };
                    Some((table, charge))
                }
                None => None,
            };
            Ok(StagedObjectCommit {
                predecessor: state,
                blob_key,
                manifest,
                existing,
                extents: core::mem::take(&mut writer.extents),
                segments: core::mem::take(&mut writer.segments),
                payload_hashes,
                reference_codec: writer.reference_codec,
                object_kind: writer.object_kind,
                exact_len: writer.geometry.exact_len(),
                quota_charge,
                last_scratch_seal,
                sink: writer.staged_sink.take().unwrap_or_else(PageSink::new),
            })
        }
    }

    pub async fn commit_to<T>(
        self,
        intent: PublicationIntent<T, CasObjectHandle>,
    ) -> Result<T::Capability, CasCommitError<D::Error, T::Error>>
    where
        T: ObjectPublicationTarget<CasObjectHandle> + ?Sized,
    {
        if self.quota_reservation.is_some()
            && intent.persistence() == ObjectPublicationPersistence::Persistent
        {
            return Err(CasCommitError::Store(CasStoreError::Store(
                StoreError::QuotaPersistenceUnavailable,
            )));
        }
        let object = self.commit().await.map_err(CasCommitError::Store)?;
        intent.publish(object).map_err(CasCommitError::Publish)
    }
}

#[derive(Clone)]
pub(crate) struct FinalRecord {
    pub(crate) value: ExtentRecord,
    pub(crate) digest: BodyDigest,
    pub(crate) body: Box<Page>,
    pub(crate) seal: Box<Page>,
}

impl FinalRecord {
    pub(crate) fn pointer(&self) -> PhysicalPointer {
        PhysicalPointer::Value(PointerValue {
            store_uuid: self.value.binding.store_uuid,
            segment_no: self.value.binding.segment_no,
            segment_generation: self.value.binding.generation,
            descriptor_relative_page: self.value.payload_first_relative_page - 2,
            payload_relative_page: self.value.payload_first_relative_page,
            payload_pages: self.value.payload_pages,
            ordinal: self.value.binding.ordinal,
            exact_byte_len: self.value.payload_byte_len,
            extent_kind: self.value.extent_kind,
            payload_sha256: self.value.payload_sha256,
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_record(
    store_uuid: StoreUuid,
    segment_no: u64,
    segment_generation: u64,
    checkpoint_generation: u64,
    ordinal: u32,
    descriptor_relative_page: u32,
    extent_kind: ExtentKind,
    object_kind: u32,
    extent_index: u32,
    extent_count: u32,
    content_byte_len: u64,
    encoded_blob_len: u64,
    encoded_offset: u64,
    payload_byte_len: u64,
    merkle_root: Hash,
    payload_hash: Hash,
) -> Result<FinalRecord, FormatError> {
    let payload_pages = u32::try_from(payload_byte_len.div_ceil(PAGE_SIZE as u64))
        .map_err(|_| FormatError::ArithmeticOverflow)?;
    let value = ExtentRecord {
        binding: RecordBinding {
            store_uuid,
            generation: segment_generation,
            segment_no,
            ordinal,
            self_page: segment_base_page(segment_no)? + u64::from(descriptor_relative_page),
            target_checkpoint_generation: checkpoint_generation,
        },
        extent_kind,
        object_kind,
        extent_index,
        extent_count,
        payload_pages,
        content_byte_len,
        encoded_blob_len,
        encoded_offset,
        payload_byte_len,
        payload_first_relative_page: descriptor_relative_page + 2,
        record_span_pages: payload_pages + 2,
        merkle_root,
        payload_sha256: payload_hash,
    };
    let mut body = heap_page();
    let mut seal = heap_page();
    let digest = encode_extent_body(&value, &mut body)?;
    encode_record_seal(digest, &mut seal)?;
    Ok(FinalRecord {
        value,
        digest,
        body,
        seal,
    })
}

pub(crate) async fn write_page<D: PageDevice>(
    device: &D,
    page: u64,
    bytes: &Page,
) -> Result<(), StoreError<D::Error>> {
    device
        .write_page(page, bytes)
        .await
        .map_err(StoreError::Mutation)
}

pub(crate) async fn flush<D: PageDevice>(device: &D) -> Result<(), StoreError<D::Error>> {
    device.flush().await.map_err(StoreError::Mutation)
}

async fn read_scratch_range<D: PageDevice>(
    device: &D,
    extents: &[ScratchExtent],
    encoded_offset: u64,
    len: usize,
) -> Result<Vec<u8>, StoreError<D::Error>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let (extent, within) = find_scratch_extent::<D::Error>(
        extents,
        encoded_offset,
        u64::try_from(len).map_err(|_| StoreError::Corrupt)?,
    )
    .map_err(|error| match error {
        CasStoreError::Store(error) => error,
        _ => StoreError::Corrupt,
    })?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(len)
        .map_err(|_| StoreError::MemoryLimit)?;
    output.resize(len, 0);
    let base = segment_base_page(extent.segment_no)?;
    let first_page = within / PAGE_SIZE as u64;
    let first_byte = usize::try_from(within % PAGE_SIZE as u64).map_err(|_| StoreError::Corrupt)?;
    let mut copied = 0_usize;
    let mut page_index = first_page;
    while copied != len {
        let mut page = heap_page();
        device
            .read_page(
                base + u64::from(extent.payload_relative_page) + page_index,
                &mut page,
            )
            .await
            .map_err(StoreError::Device)?;
        let in_page = if page_index == first_page {
            first_byte
        } else {
            0
        };
        let take = (len - copied).min(PAGE_SIZE - in_page);
        output[copied..copied + take].copy_from_slice(&page[in_page..in_page + take]);
        copied += take;
        page_index = page_index.checked_add(1).ok_or(StoreError::Corrupt)?;
    }
    Ok(output)
}

async fn verify_scratch_emissions<D: PageDevice>(
    device: &D,
    extents: &[ScratchExtent],
    geometry: BlobGeometry,
    emissions: [Option<Emission>; MAX_STREAMING_EMISSIONS_PER_STEP],
) -> Result<(), CasStoreError<D::Error>> {
    for emission in emissions.into_iter().flatten() {
        if emission.index >= geometry.tree_node_count() {
            return Err(StoreError::Corrupt.into());
        }
        let offset = (geometry.tree_offset() as u64)
            .checked_add(u64::from(emission.index) * HASH_SIZE as u64)
            .ok_or(StoreError::Corrupt)?;
        let stored = read_scratch_range(device, extents, offset, HASH_SIZE).await?;
        if stored.as_slice() != emission.hash {
            return Err(StoreError::Corrupt.into());
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn verify_staged_blob<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    manifest: &BlobManifest,
    scratch_extents: &[ScratchExtent],
) -> Result<(), CasStoreError<D::Error>> {
    if manifest.encoded_blob_len <= SMALL_STAGED_BLOB_READBACK_LIMIT {
        let mut requests = Vec::new();
        requests
            .try_reserve_exact(manifest.extents.len())
            .map_err(|_| StoreError::MemoryLimit)?;
        requests.extend(manifest.extents.iter().map(|extent| {
            (
                extent.pointer,
                ExtentKind::Blob,
                CANONICAL_CONTENT_EXTENT_LEN as usize,
            )
        }));
        let resolved = read_pointer_payloads(
            device,
            store_uuid,
            admitted_segments,
            next_segment_generation,
            checkpoint_generation,
            &requests,
        )
        .await?;
        let encoded_len =
            usize::try_from(manifest.encoded_blob_len).map_err(|_| StoreError::MemoryLimit)?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(encoded_len)
            .map_err(|_| StoreError::MemoryLimit)?;
        for (declared, observed) in manifest.extents.iter().zip(&resolved) {
            let extent = observed.extent;
            if encoded.len() as u64 != declared.encoded_offset
                || extent.extent_kind != ExtentKind::Blob
                || extent.object_kind != manifest.blob_key.object_kind()
                || extent.extent_index != declared.extent_index
                || extent.extent_count != declared.extent_count
                || extent.content_byte_len != manifest.blob_key.exact_len()
                || extent.encoded_blob_len != manifest.encoded_blob_len
                || extent.encoded_offset != declared.encoded_offset
                || extent.payload_byte_len != declared.payload_byte_len
                || extent.merkle_root != manifest.blob_key.merkle_root()
                || observed.bytes.len() as u64 != declared.payload_byte_len
            {
                return Err(StoreError::Corrupt.into());
            }
            encoded.extend_from_slice(&observed.bytes);
        }
        if encoded.len() != encoded_len {
            return Err(StoreError::Corrupt.into());
        }
        let blob = BlobView::decode(&encoded)?;
        if blob.descriptor().object_kind != manifest.blob_key.object_kind()
            || blob.descriptor().byte_len != manifest.blob_key.exact_len()
            || blob.descriptor().root != manifest.blob_key.merkle_root()
        {
            return Err(StoreError::Corrupt.into());
        }
        blob.verify_all()?;
        return Ok(());
    }
    validate_cas_blob_descriptors(
        device,
        store_uuid,
        admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        manifest,
    )
    .await?;
    // This pass verifies every exact extent payload hash and, through
    // scan_segment(), every descriptor/summary/final-seal chain. At most one
    // canonical extent (1 MiB) is resident at a time.
    for declared in &manifest.extents {
        let resolved = read_pointer_payload(
            device,
            store_uuid,
            admitted_segments,
            next_segment_generation,
            checkpoint_generation,
            declared.pointer,
            ExtentKind::Blob,
            CANONICAL_CONTENT_EXTENT_LEN as usize,
        )
        .await?;
        if resolved.bytes.len() as u64 != declared.payload_byte_len {
            return Err(StoreError::Corrupt.into());
        }
    }

    let geometry = BlobGeometry::for_len(manifest.blob_key.exact_len())?;
    let expected_descriptor = BlobDescriptor {
        object_kind: manifest.blob_key.object_kind(),
        byte_len: manifest.blob_key.exact_len(),
        leaf_count: geometry.leaf_count(),
        tree_node_count: geometry.tree_node_count(),
        root: manifest.blob_key.merkle_root(),
    };
    let header = read_scratch_range(device, scratch_extents, 0, HEADER_SIZE).await?;
    let header: &[u8; HEADER_SIZE] = header
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::Corrupt)?;
    if BlobDescriptor::decode_header(header)? != expected_descriptor {
        return Err(StoreError::Corrupt.into());
    }

    // Independently bind the read-back content and serialized tree to the
    // catalog root in one O(n) pass with a fixed-capacity emission buffer.
    let mut builder = StreamingMerkle::begin(
        expected_descriptor.object_kind,
        expected_descriptor.byte_len,
        EmissionSink::new(),
    )
    .map_err(map_streaming_error)?;
    for index in 0..geometry.leaf_count() {
        if expected_descriptor.byte_len == 0 {
            break;
        }
        let len = expected_descriptor
            .byte_len
            .saturating_sub(u64::from(index) * LEAF_SIZE as u64)
            .min(LEAF_SIZE as u64) as usize;
        let bytes = read_scratch_range(
            device,
            scratch_extents,
            HEADER_SIZE as u64 + u64::from(index) * LEAF_SIZE as u64,
            len,
        )
        .await?;
        builder
            .push_chunk(index, &bytes)
            .map_err(map_streaming_error)?;
        verify_scratch_emissions(device, scratch_extents, geometry, builder.sink_mut().take())
            .await?;
    }
    while builder.padding_remaining().map_err(map_streaming_error)? != 0 {
        builder.pad_next().map_err(map_streaming_error)?;
        verify_scratch_emissions(device, scratch_extents, geometry, builder.sink_mut().take())
            .await?;
    }
    if builder.finalize().map_err(map_streaming_error)?.descriptor != expected_descriptor {
        return Err(StoreError::Corrupt.into());
    }
    Ok(())
}

fn make_manifest(
    store_uuid: StoreUuid,
    blob_key: BlobKey,
    encoded_blob_len: u64,
    extents: &[ScratchExtent],
    payload_hashes: &[Hash],
) -> BlobManifest {
    BlobManifest {
        blob_key,
        encoded_blob_len,
        extents: extents
            .iter()
            .zip(payload_hashes)
            .map(|(extent, hash)| ManifestExtent {
                extent_index: extent.extent_index,
                extent_count: extent.extent_count,
                encoded_offset: extent.encoded_offset,
                payload_byte_len: extent.payload_byte_len,
                pointer: extent.pointer(store_uuid, *hash),
            })
            .collect(),
    }
}

async fn compare_manifests<D: PageDevice>(
    device: &D,
    state: &MountedState,
    scratch_manifest: &BlobManifest,
    existing_manifest: &BlobManifest,
    scratch_extents: &[ScratchExtent],
    scratch_hashes: &[Hash],
) -> Result<bool, StoreError<D::Error>> {
    if scratch_manifest.blob_key != existing_manifest.blob_key
        || scratch_manifest.encoded_blob_len != existing_manifest.encoded_blob_len
        || scratch_manifest.extents.len() != existing_manifest.extents.len()
    {
        return Ok(false);
    }
    for (((scratch_declared, existing), scratch), scratch_hash) in scratch_manifest
        .extents
        .iter()
        .zip(&existing_manifest.extents)
        .zip(scratch_extents)
        .zip(scratch_hashes)
    {
        if scratch_declared.extent_index != existing.extent_index
            || scratch_declared.extent_count != existing.extent_count
            || scratch_declared.encoded_offset != existing.encoded_offset
            || scratch_declared.payload_byte_len != existing.payload_byte_len
        {
            return Ok(false);
        }
        let PhysicalPointer::Value(existing_pointer) = existing.pointer else {
            return Ok(false);
        };
        let scanned = scan_segment(
            device,
            state.superblock.binding.store_uuid,
            state.admitted_segments,
            state.next_segment_generation,
            state.generation,
            existing_pointer,
        )
        .await?;
        let Some(extent) = scanned.matched else {
            return Ok(false);
        };
        if extent.payload_sha256 != existing_pointer.payload_sha256
            || existing_pointer.exact_byte_len != scratch.payload_byte_len
        {
            return Ok(false);
        }
        let existing_base = segment_base_page(existing_pointer.segment_no)?;
        let scratch_base = segment_base_page(scratch.segment_no)?;
        let mut existing_hasher = Sha256::new();
        let mut remaining =
            usize::try_from(scratch.payload_byte_len).map_err(|_| StoreError::Corrupt)?;
        for page_index in 0..scratch.payload_byte_len.div_ceil(PAGE_SIZE as u64) {
            let mut left = heap_page();
            let mut right = heap_page();
            device
                .read_page(
                    scratch_base + u64::from(scratch.payload_relative_page) + page_index,
                    &mut left,
                )
                .await
                .map_err(StoreError::Device)?;
            device
                .read_page(
                    existing_base + u64::from(existing_pointer.payload_relative_page) + page_index,
                    &mut right,
                )
                .await
                .map_err(StoreError::Device)?;
            let take = remaining.min(PAGE_SIZE);
            if left[..take] != right[..take] {
                return Ok(false);
            }
            existing_hasher.update(&right[..take]);
            remaining -= take;
        }
        let existing_hash: Hash = existing_hasher.finalize().into();
        if existing_hash != existing_pointer.payload_sha256 || existing_hash != *scratch_hash {
            return Ok(false);
        }
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
async fn seal_scratch_segment<D: PageDevice>(
    device: &D,
    state: &MountedState,
    checkpoint_generation: u64,
    blob_key: BlobKey,
    encoded_blob_len: u64,
    segment: ScratchSegment,
    extents: &[ScratchExtent],
    payload_hashes: &[Hash],
    previous: Option<(u64, u64, Hash)>,
    defer_barriers: bool,
    mut sink: Option<&mut PageSink>,
) -> Result<(u64, u64, Hash), StoreError<D::Error>> {
    let base = segment_base_page(segment.segment_no)?;
    let (previous_segment_no, previous_segment_generation, previous_hash) =
        previous.unwrap_or((ANCHOR_SEGMENT_NO, 0, [0; 32]));
    let header = SegmentHeader {
        binding: RecordBinding {
            store_uuid: state.superblock.binding.store_uuid,
            generation: segment.segment_generation,
            segment_no: segment.segment_no,
            ordinal: 0,
            self_page: base,
            target_checkpoint_generation: checkpoint_generation,
        },
        base_page: base,
        previous_segment_no,
        previous_segment_generation,
        previous_segment_seal_body_sha256: previous_hash,
    };
    let mut header_body = heap_page();
    let mut header_seal = heap_page();
    let header_digest = encode_segment_header_body(&header, &mut header_body)?;
    encode_record_seal(header_digest, &mut header_seal)?;

    let mut records = Vec::new();
    records
        .try_reserve_exact(segment.extent_end - segment.first_extent)
        .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
    for index in segment.first_extent..segment.extent_end {
        let scratch = &extents[index];
        let record = build_record(
            state.superblock.binding.store_uuid,
            scratch.segment_no,
            scratch.segment_generation,
            checkpoint_generation,
            scratch.ordinal,
            scratch.descriptor_relative_page,
            ExtentKind::Blob,
            blob_key.object_kind(),
            scratch.extent_index,
            scratch.extent_count,
            blob_key.exact_len(),
            encoded_blob_len,
            scratch.encoded_offset,
            scratch.payload_byte_len,
            blob_key.merkle_root(),
            payload_hashes[index],
        )?;
        records.push(record);
    }

    // The scratch payload was made durable by finish_blob_encoding().  Publish
    // this segment's descriptors as one transaction: no seal is written until
    // every descriptor body is durable, and the segment summary is not written
    // until every descriptor seal is durable.  A crash at either barrier leaves
    // an unsealed segment, exactly as the former per-record barriers did.
    sink_or_write_page(device, sink.as_deref_mut(), base, &header_body).await?;
    for record in &records {
        sink_or_write_page(
            device,
            sink.as_deref_mut(),
            base + u64::from(record.value.payload_first_relative_page - 2),
            &record.body,
        )
        .await?;
    }
    if !defer_barriers {
        flush(device).await?;
    }
    sink_or_write_page(device, sink.as_deref_mut(), base + 1, &header_seal).await?;
    for record in &records {
        sink_or_write_page(
            device,
            sink.as_deref_mut(),
            base + u64::from(record.value.payload_first_relative_page - 1),
            &record.seal,
        )
        .await?;
    }
    if !defer_barriers {
        flush(device).await?;
    }
    finalize_segment(
        device,
        state.superblock.binding.store_uuid,
        checkpoint_generation,
        segment.segment_no,
        segment.segment_generation,
        header_digest,
        &records,
        defer_barriers,
        sink,
    )
    .await
}

pub(crate) async fn finalize_segment<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    checkpoint_generation: u64,
    segment_no: u64,
    segment_generation: u64,
    header_digest: BodyDigest,
    records: &[FinalRecord],
    defer_barriers: bool,
    mut sink: Option<&mut PageSink>,
) -> Result<(u64, u64, Hash), StoreError<D::Error>> {
    let base = segment_base_page(segment_no)?;
    let mut descriptor_chain = descriptor_chain_initial(store_uuid, segment_no, segment_generation);
    let mut payload_chain = payload_chain_initial(store_uuid, segment_no, segment_generation);
    let mut kind_counts = [0_u32; 5];
    let mut kind_bytes = [0_u64; 5];
    let mut payload_page_count = 0_u32;
    let mut total_payload_bytes = 0_u64;
    for record in records {
        descriptor_chain = descriptor_chain_next(
            store_uuid,
            segment_no,
            segment_generation,
            descriptor_chain,
            record.value.binding.ordinal,
            record.digest.body_sha256(),
            record.value.payload_sha256,
        );
        payload_chain = payload_chain_next(
            store_uuid,
            segment_no,
            segment_generation,
            payload_chain,
            record.value.binding.ordinal,
            record.value.payload_byte_len,
            record.value.payload_sha256,
        );
        let kind = record.value.extent_kind as usize - 1;
        kind_counts[kind] += 1;
        kind_bytes[kind] += record.value.payload_byte_len;
        payload_page_count += record.value.payload_pages;
        total_payload_bytes += record.value.payload_byte_len;
    }
    let first = records.first().ok_or(StoreError::Corrupt)?;
    let last = records.last().ok_or(StoreError::Corrupt)?;
    let next_free_page = last
        .value
        .payload_first_relative_page
        .checked_add(last.value.payload_pages)
        .ok_or(StoreError::Corrupt)?;
    let record_count = u32::try_from(records.len()).map_err(|_| StoreError::Corrupt)?;
    let summary = SegmentSummary {
        binding: RecordBinding {
            store_uuid,
            generation: segment_generation,
            segment_no,
            ordinal: record_count + 1,
            self_page: base + u64::from(SUMMARY_BODY_PAGE),
            target_checkpoint_generation: checkpoint_generation,
        },
        record_count,
        next_free_page,
        payload_page_count,
        total_payload_bytes,
        first_target_checkpoint_generation: first.value.binding.target_checkpoint_generation,
        last_target_checkpoint_generation: last.value.binding.target_checkpoint_generation,
        header_body_sha256: header_digest.body_sha256(),
        descriptor_chain_sha256: descriptor_chain,
        payload_chain_sha256: payload_chain,
        kind_counts,
        kind_bytes,
    };
    let mut summary_body = heap_page();
    let mut summary_seal = heap_page();
    let summary_digest = encode_segment_summary_body(&summary, &mut summary_body)?;
    encode_record_seal(summary_digest, &mut summary_seal)?;
    let seal = SegmentSeal {
        binding: RecordBinding {
            store_uuid,
            generation: segment_generation,
            segment_no,
            ordinal: record_count + 2,
            self_page: base + u64::from(SEGMENT_SEAL_BODY_PAGE),
            target_checkpoint_generation: checkpoint_generation,
        },
        header_body_sha256: header_digest.body_sha256(),
        summary_body_sha256: summary_digest.body_sha256(),
        final_descriptor_chain_sha256: descriptor_chain,
        final_payload_chain_sha256: payload_chain,
        record_count,
        next_free_page,
        payload_page_count,
        total_payload_bytes,
        target_checkpoint_generation: checkpoint_generation,
    };
    let mut seal_body = heap_page();
    let mut final_seal = heap_page();
    let seal_digest = encode_segment_seal_body(&seal, &mut seal_body)?;
    encode_record_seal(seal_digest, &mut final_seal)?;
    sink_or_write_page(device, sink.as_deref_mut(), base + u64::from(SUMMARY_BODY_PAGE), &summary_body)
        .await?;
    if !defer_barriers {
        flush(device).await?;
    }
    sink_or_write_page(device, sink.as_deref_mut(), base + u64::from(SUMMARY_SEAL_PAGE), &summary_seal)
        .await?;
    sink_or_write_page(
        device,
        sink.as_deref_mut(),
        base + u64::from(SEGMENT_SEAL_BODY_PAGE),
        &seal_body,
    )
    .await?;
    if !defer_barriers {
        flush(device).await?;
    }
    sink_or_write_page(device, sink.as_deref_mut(), base + u64::from(SEGMENT_SEAL_PAGE), &final_seal)
        .await?;
    // The caller immediately begins either the next segment's first durable
    // phase or checkpoint-slot clearing. That barrier also makes this final
    // seal durable, so a standalone flush here would add no ordering edge.
    // With deferred barriers no checkpoint can name this segment until the
    // slot protocol's first flush lands, which covers every phase above.
    Ok((segment_no, segment_generation, seal_digest.body_sha256()))
}

/// Authority state committed in the same metadata segment and checkpoint as
/// a staged CAS object, so one durable transaction publishes both.
pub(crate) struct FusedAuthorityPublication {
    pub(crate) authority_bytes: Vec<u8>,
    pub(crate) persistent_authority: crate::authority_snapshot::PersistentAuthoritySnapshot,
    pub(crate) persistent_roots: crate::root_codec::PersistentRootSet,
}

/// A blob whose payload phase completed via [`BlobWriter::stage_commit`]:
/// scratch data is durable (and sealed for a new blob) but no metadata
/// segment or checkpoint exists yet. `predecessor` is the mounted state the
/// writer consumed; the store stays poisoned until
/// [`SegmentStore::publish_staged_object_with_authority`] mounts a successor.
pub(crate) struct StagedObjectCommit {
    pub(crate) predecessor: MountedState,
    pub(crate) blob_key: BlobKey,
    pub(crate) manifest: BlobManifest,
    pub(crate) existing: Option<BlobMapping>,
    pub(crate) extents: Vec<ScratchExtent>,
    pub(crate) segments: Vec<ScratchSegment>,
    pub(crate) payload_hashes: Vec<Hash>,
    pub(crate) reference_codec: u16,
    pub(crate) object_kind: u32,
    pub(crate) exact_len: u64,
    /// The staging reservation already committed into a charge, so the quota
    /// table carries no outstanding reservation when the caller installs the
    /// persistent quota snapshot ahead of the fused publication — the same
    /// ordering the two-transaction path reaches through `commit()`.
    pub(crate) quota_charge: Option<(PrincipalQuotaTable, CommittedQuotaCharge)>,
    pub(crate) last_scratch_seal: Option<(u64, u64, Hash)>,
    pub(crate) sink: PageSink,
}

impl<D: PageDevice> SegmentStore<D> {
    /// Publish a staged object mapping together with a persistent-authority
    /// snapshot in one metadata segment and one checkpoint, then mount the
    /// verified successor. This is the durable-append fast path: it replaces
    /// the former sequence of two independent segment transactions and two
    /// checkpoint publications per logical object append.
    pub(crate) async fn publish_staged_object_with_authority(
        &mut self,
        mut staged: StagedObjectCommit,
        fused: FusedAuthorityPublication,
    ) -> Result<AuthorizedObject<CasObjectHandle>, CasStoreError<D::Error>> {
        let state = staged.predecessor;
        let (pending, checkpoint, successor) = commit_snapshot(
            &self.device,
            &state,
            self.limits,
            staged.blob_key,
            staged.manifest,
            staged.existing,
            &staged.extents,
            &staged.segments,
            &staged.payload_hashes,
            &self.pins,
            staged.reference_codec,
            Some(&fused),
            staged.last_scratch_seal,
            Some(staged.sink),
        )
        .await?;
        self.mount_verified_successor(state, checkpoint, successor, true)
            .await?;
        let handle = pending.complete(staged.quota_charge.take());
        let maximum_persistence = if handle.is_quota_charged() {
            ObjectPublicationPersistence::RuntimeOnly
        } else {
            ObjectPublicationPersistence::Persistent
        };
        Ok(AuthorizedObject::from_committed(
            handle,
            staged.object_kind,
            staged.exact_len,
            maximum_persistence,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
async fn commit_snapshot<D: PageDevice>(
    device: &D,
    state: &MountedState,
    limits: crate::store::StoreLimits,
    blob_key: BlobKey,
    scratch_manifest: BlobManifest,
    existing: Option<BlobMapping>,
    scratch_extents: &[ScratchExtent],
    scratch_segments: &[ScratchSegment],
    payload_hashes: &[Hash],
    pins: &crate::store::SharedStorePinRegistry,
    reference_codec: u16,
    fused: Option<&FusedAuthorityPublication>,
    staged_scratch_seal: Option<(u64, u64, Hash)>,
    mut sink: Option<PageSink>,
) -> Result<(PendingCasObjectHandle, Checkpoint, MountedState), CasStoreError<D::Error>> {
    let checkpoint_generation = state
        .generation
        .checked_add(1)
        .ok_or(StoreError::IdExhausted)?;
    // In fused publication no checkpoint can name any page written below
    // until the checkpoint slot protocol's first flush; that shared barrier
    // replaces the per-phase segment flushes.
    let defer_barriers = fused.is_some();
    let is_new = existing.is_none();
    let data_segment_count = if is_new { scratch_segments.len() } else { 0 };
    let scratch_first_segment = scratch_segments
        .first()
        .map(|segment| segment.segment_no)
        .ok_or(StoreError::Corrupt)?;
    let metadata_segment_no = if is_new {
        scratch_segments
            .last()
            .and_then(|segment| segment.segment_no.checked_add(1))
            .ok_or(StoreError::IdExhausted)?
    } else {
        scratch_first_segment
    };
    let metadata_generation = state
        .next_segment_generation
        .checked_add(data_segment_count as u64)
        .ok_or(StoreError::IdExhausted)?;
    let next_segment_generation = metadata_generation
        .checked_add(1)
        .ok_or(StoreError::IdExhausted)?;
    let mut previous = state.last_segment;
    if is_new {
        if let Some(seal) = staged_scratch_seal {
            // stage_commit() already sealed the scratch segments against this
            // exact checkpoint generation; chain from its final seal.
            previous = Some(seal);
        } else {
            for segment in scratch_segments {
                previous = Some(
                    seal_scratch_segment(
                        device,
                        state,
                        checkpoint_generation,
                        blob_key,
                        scratch_manifest.encoded_blob_len,
                        *segment,
                        scratch_extents,
                        payload_hashes,
                        previous,
                        defer_barriers,
                        None,
                    )
                    .await?,
                );
            }
        }
    }

    let base = segment_base_page(metadata_segment_no)?;
    let (previous_segment_no, previous_segment_generation, previous_hash) =
        previous.unwrap_or((ANCHOR_SEGMENT_NO, 0, [0; 32]));
    let header = SegmentHeader {
        binding: RecordBinding {
            store_uuid: state.superblock.binding.store_uuid,
            generation: metadata_generation,
            segment_no: metadata_segment_no,
            ordinal: 0,
            self_page: base,
            target_checkpoint_generation: checkpoint_generation,
        },
        base_page: base,
        previous_segment_no,
        previous_segment_generation,
        previous_segment_seal_body_sha256: previous_hash,
    };
    let mut header_body = heap_page();
    let mut header_seal = heap_page();
    let header_digest = encode_segment_header_body(&header, &mut header_body)?;
    encode_record_seal(header_digest, &mut header_seal)?;

    let context = CasCodecContext::new(
        state.superblock.binding.store_uuid,
        state.admitted_segments,
        next_segment_generation,
    )?;
    let mut relative = DATA_FIRST_PAGE;
    let mut ordinal = 1_u32;
    let mut records = Vec::new();
    let mut manifest_record_and_bytes = None;
    let new_blob_mapping = if is_new {
        let manifest_bytes = encode_blob_manifest(&scratch_manifest, context)?;
        let record = build_record(
            state.superblock.binding.store_uuid,
            metadata_segment_no,
            metadata_generation,
            checkpoint_generation,
            ordinal,
            relative,
            ExtentKind::Catalog,
            METADATA_KIND_MANIFEST,
            0,
            1,
            manifest_bytes.len() as u64,
            manifest_bytes.len() as u64,
            0,
            manifest_bytes.len() as u64,
            payload_sha256(&manifest_bytes),
            payload_sha256(&manifest_bytes),
        )?;
        relative += record.value.record_span_pages;
        ordinal += 1;
        let mapping = BlobMapping {
            blob_key,
            manifest: record.pointer(),
        };
        manifest_record_and_bytes = Some((record, manifest_bytes));
        let record = &manifest_record_and_bytes
            .as_ref()
            .ok_or(StoreError::Corrupt)?
            .0;
        records.push(record.clone());
        mapping
    } else {
        existing.ok_or(StoreError::Corrupt)?
    };

    let mut objects = state
        .cas
        .as_ref()
        .map_or_else(Vec::new, |cas| cas.objects.clone());
    let mut blobs = state
        .cas
        .as_ref()
        .map_or_else(Vec::new, |cas| cas.blobs.clone());
    objects
        .try_reserve_exact(1)
        .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
    objects.push(ObjectMapping {
        object_id: state.next_object_id,
        blob_key,
        commit_generation: checkpoint_generation,
        reference_codec,
    });
    if is_new {
        blobs
            .try_reserve_exact(1)
            .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
        let insert = blobs
            .binary_search_by_key(&blob_key, |mapping| mapping.blob_key)
            .unwrap_err();
        blobs.insert(insert, new_blob_mapping);
    }
    if objects.len() > limits.max_catalog_entries as usize
        || blobs.len() > limits.max_catalog_entries as usize
    {
        return Err(StoreError::Capacity(CapacityClass::Metadata).into());
    }
    let snapshot = CasSnapshot {
        checkpoint_generation,
        objects,
        blobs,
    };
    let snapshot_bytes = encode_cas_snapshot(&snapshot, context)?;
    let snapshot_record = build_record(
        state.superblock.binding.store_uuid,
        metadata_segment_no,
        metadata_generation,
        checkpoint_generation,
        ordinal,
        relative,
        ExtentKind::Catalog,
        METADATA_KIND_CAS_SNAPSHOT,
        0,
        1,
        snapshot_bytes.len() as u64,
        snapshot_bytes.len() as u64,
        0,
        snapshot_bytes.len() as u64,
        payload_sha256(&snapshot_bytes),
        payload_sha256(&snapshot_bytes),
    )?;
    relative += snapshot_record.value.record_span_pages;
    ordinal += 1;
    let catalog_root = snapshot_record.pointer();
    let snapshot_index = records.len();
    records.push(snapshot_record);

    let authority_index = if let Some(fused) = fused {
        let record = build_record(
            state.superblock.binding.store_uuid,
            metadata_segment_no,
            metadata_generation,
            checkpoint_generation,
            ordinal,
            relative,
            ExtentKind::Authority,
            METADATA_KIND_PERSISTENT_AUTHORITY,
            0,
            1,
            fused.authority_bytes.len() as u64,
            fused.authority_bytes.len() as u64,
            0,
            fused.authority_bytes.len() as u64,
            payload_sha256(&fused.authority_bytes),
            payload_sha256(&fused.authority_bytes),
        )?;
        relative += record.value.record_span_pages;
        ordinal += 1;
        let index = records.len();
        records.push(record);
        Some(index)
    } else {
        None
    };
    let authority_root = authority_index
        .map(|index| records[index].pointer())
        .unwrap_or(state.authority_root);

    let (allocation, allocation_version, allocation_bytes) = if state.allocation_version == 2 {
        let mut allocated_segments = Vec::new();
        allocated_segments
            .try_reserve_exact(data_segment_count + 1)
            .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
        if is_new {
            allocated_segments.extend(scratch_segments.iter().map(|segment| segment.segment_no));
        }
        allocated_segments.push(metadata_segment_no);
        let allocation = state
            .allocation
            .apply_transition(AllocationTransition {
                checkpoint_generation,
                next_segment_generation,
                allocate: &allocated_segments,
                retire: &[],
                reclaim: &[],
            })
            .map_err(|_| StoreError::Corrupt)?;
        let bytes = encode_allocation_v2(&allocation).map_err(|_| StoreError::Corrupt)?;
        (allocation, 2, bytes)
    } else {
        let allocated_prefix_segments = metadata_segment_no + 1;
        let legacy = AllocationState {
            checkpoint_generation,
            admitted_segments: state.admitted_segments,
            allocated_prefix_segments,
            next_segment_generation,
            cleaner_reserve_segments: state.cleaner_reserve_segments,
        };
        let allocation = AllocationV2::from_v1_prefix(legacy).map_err(|_| StoreError::Corrupt)?;
        let bytes = encode_allocation(legacy)
            .map_err(|_| StoreError::Corrupt)?
            .to_vec();
        (allocation, 1, bytes)
    };
    let allocation_record = build_record(
        state.superblock.binding.store_uuid,
        metadata_segment_no,
        metadata_generation,
        checkpoint_generation,
        ordinal,
        relative,
        ExtentKind::Allocation,
        METADATA_KIND_ALLOCATION,
        0,
        1,
        allocation_bytes.len() as u64,
        allocation_bytes.len() as u64,
        0,
        allocation_bytes.len() as u64,
        payload_sha256(&allocation_bytes),
        payload_sha256(&allocation_bytes),
    )?;
    relative += allocation_record.value.record_span_pages;
    let allocation_root = allocation_record.pointer();
    let allocation_index = records.len();
    records.push(allocation_record);
    if relative > DATA_END_PAGE {
        return Err(StoreError::Capacity(CapacityClass::Metadata).into());
    }
    let mut payload_records = Vec::new();
    payload_records
        .try_reserve_exact(records.len())
        .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
    if let Some((record, bytes)) = &manifest_record_and_bytes {
        payload_records.push((record, bytes.as_slice()));
    }
    payload_records.push((&records[snapshot_index], snapshot_bytes.as_slice()));
    if let (Some(index), Some(fused)) = (authority_index, fused) {
        payload_records.push((&records[index], fused.authority_bytes.as_slice()));
    }
    payload_records.push((&records[allocation_index], allocation_bytes.as_slice()));
    write_payload_records_with_header(
        device,
        base,
        Some((&header_body, &header_seal)),
        &payload_records,
        defer_barriers,
        sink.as_mut(),
    )
    .await?;
    let (_, _, metadata_seal_hash) = finalize_segment(
        device,
        state.superblock.binding.store_uuid,
        checkpoint_generation,
        metadata_segment_no,
        metadata_generation,
        header_digest,
        &records,
        defer_barriers,
        sink.as_mut(),
    )
    .await?;
    crate::bench_mark(7);
    // Batched publication: everything staged above lands as a few large
    // contiguous requests before the checkpoint slot protocol's barrier.
    if let Some(sink) = sink.take() {
        sink.drain(device).await?;
    }
    crate::bench_mark(8);

    let slot = ((checkpoint_generation - 1) & 1) as u8;
    let checkpoint = Checkpoint {
        binding: RecordBinding {
            store_uuid: state.superblock.binding.store_uuid,
            generation: checkpoint_generation,
            segment_no: ANCHOR_SEGMENT_NO,
            ordinal: u32::from(slot),
            self_page: 4 + u64::from(slot) * 2,
            target_checkpoint_generation: checkpoint_generation,
        },
        slot,
        previous_generation: state.generation,
        admitted_range_pages: vibeos_segment_format::admitted_pages(state.admitted_segments)?,
        admitted_segments: state.admitted_segments,
        next_segment_generation,
        replay_count: 0,
        max_replay_records: limits.max_replay_records,
        cleaner_reserve_segments: state.cleaner_reserve_segments,
        catalog_root,
        authority_root,
        allocation_root,
        replay_tail: PhysicalPointer::Null,
    };
    write_checkpoint(device, &checkpoint, true).await?;
    crate::bench_mark(9);
    // Verify the complete newly selected state after the checkpoint itself has
    // been durably read back. This catches a misdirected/torn checkpoint write
    // that damaged a data segment, while avoiding a scan of unchanged history.
    // Authority remains withheld until mount_verified_successor also re-reads
    // and selects this exact checkpoint pair.
    // Serve the whole read-back from batched span snapshots: the metadata
    // segment plus, for a new blob, every scratch segment. This reads the
    // exact same media bytes as the former page-by-page verification while
    // paying a handful of large device requests instead of one per page.
    let mut verify_ranges: Vec<(u64, u64)> = Vec::new();
    verify_ranges
        .try_reserve_exact(2 + 2 * scratch_segments.len())
        .map_err(|_| StoreError::MemoryLimit)?;
    verify_ranges.push((base, u64::from(relative)));
    verify_ranges.push((base + u64::from(SUMMARY_BODY_PAGE), 4));
    if is_new {
        for segment in scratch_segments {
            let segment_base = segment_base_page(segment.segment_no)?;
            let mut end_relative = DATA_FIRST_PAGE;
            for extent in &scratch_extents[segment.first_extent..segment.extent_end] {
                let pages = u32::try_from(extent.payload_byte_len.div_ceil(PAGE_SIZE as u64))
                    .map_err(|_| StoreError::Corrupt)?;
                end_relative = end_relative.max(
                    extent
                        .payload_relative_page
                        .checked_add(pages)
                        .ok_or(StoreError::Corrupt)?,
                );
            }
            verify_ranges.push((segment_base, u64::from(end_relative)));
            verify_ranges.push((segment_base + u64::from(SUMMARY_BODY_PAGE), 4));
        }
    }
    let verify_device = SpanSnapshotDevice::capture(device, &verify_ranges).await?;
    let expected_manifest = if is_new {
        verify_staged_blob(
            &verify_device,
            state.superblock.binding.store_uuid,
            state.admitted_segments,
            next_segment_generation,
            checkpoint_generation,
            &scratch_manifest,
            scratch_extents,
        )
        .await?;
        Some(encode_blob_manifest(&scratch_manifest, context)?)
    } else {
        None
    };
    let mut requests = Vec::new();
    let mut expected = Vec::new();
    requests
        .try_reserve_exact(4)
        .map_err(|_| StoreError::MemoryLimit)?;
    expected
        .try_reserve_exact(4)
        .map_err(|_| StoreError::MemoryLimit)?;
    if let Some(bytes) = expected_manifest.as_ref() {
        requests.push((
            new_blob_mapping.manifest,
            ExtentKind::Catalog,
            limits.recovery_memory_bytes,
        ));
        expected.push(bytes.as_slice());
    }
    requests.push((
        catalog_root,
        ExtentKind::Catalog,
        limits.recovery_memory_bytes,
    ));
    expected.push(snapshot_bytes.as_slice());
    requests.push((
        allocation_root,
        ExtentKind::Allocation,
        limits.recovery_memory_bytes,
    ));
    expected.push(allocation_bytes.as_slice());
    if let Some(fused) = fused {
        requests.push((
            authority_root,
            ExtentKind::Authority,
            limits.recovery_memory_bytes,
        ));
        expected.push(fused.authority_bytes.as_slice());
    }
    let observed = read_pointer_payloads(
        &verify_device,
        state.superblock.binding.store_uuid,
        state.admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        &requests,
    )
    .await?;
    if observed.len() != expected.len()
        || observed
            .iter()
            .zip(expected)
            .any(|(actual, bytes)| actual.bytes != bytes)
    {
        return Err(StoreError::Corrupt.into());
    }
    crate::bench_mark(10);
    let next_physical_segment = (0..state.admitted_segments)
        .find(|segment_no| allocation.segment_state(*segment_no) == Some(SegmentAllocation::Free))
        .unwrap_or(state.admitted_segments);
    let next_object_id = state
        .next_object_id
        .checked_add(1)
        .ok_or(StoreError::IdExhausted)?
        .max(u128::from(checkpoint_generation));
    let mut successor = MountedState {
        superblock: state.superblock,
        generation: checkpoint_generation,
        admitted_segments: state.admitted_segments,
        next_physical_segment,
        next_segment_generation,
        next_object_id,
        cleaner_reserve_segments: state.cleaner_reserve_segments,
        replay_count: 0,
        catalog_root,
        replay_tail: PhysicalPointer::Null,
        authority_root,
        allocation_root,
        allocation,
        allocation_version,
        persistent_roots: match fused {
            Some(fused) => Some(fused.persistent_roots.clone()),
            None => state.persistent_roots.clone(),
        },
        persistent_authority: match fused {
            Some(fused) => Some(fused.persistent_authority.clone()),
            None => state.persistent_authority.clone(),
        },
        catalog: state.catalog.clone(),
        cas: Some(CasMountedState {
            objects: snapshot.objects,
            blobs: snapshot.blobs,
        }),
        recovery_peak_bytes: 0,
        last_segment: Some((metadata_segment_no, metadata_generation, metadata_seal_hash)),
        last_segment_previous: Some((
            previous_segment_no,
            previous_segment_generation,
            previous_hash,
        )),
        last_segment_target_checkpoint_generation: checkpoint_generation,
    };
    successor.recovery_peak_bytes = successor
        .resident_heap_bytes()
        .ok_or(StoreError::MemoryLimit)?;
    if successor.recovery_peak_bytes > limits.recovery_memory_bytes {
        return Err(StoreError::MemoryLimit.into());
    }
    let root_key = RootKey::new(
        state.next_object_id,
        checkpoint_generation,
        blob_key.object_kind(),
    )
    .map_err(|_| StoreError::Corrupt)?;
    let owner = pins
        .allocate_owner()
        .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
    let root_pin = PinRegistry::pin_root_owned(
        pins,
        root_key,
        RuntimeRootClass::ObjectResource,
        owner,
        PinAdmission::CompletionCritical,
    )
    .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
    Ok((
        PendingCasObjectHandle {
            store_uuid: state.superblock.binding.store_uuid,
            object_id: state.next_object_id,
            object_kind: blob_key.object_kind(),
            exact_len: blob_key.exact_len(),
            commit_generation: checkpoint_generation,
            root_pin,
            is_new_blob: is_new,
        },
        checkpoint,
        successor,
    ))
}

pub(crate) async fn write_payload_records_with_header<D: PageDevice>(
    device: &D,
    base: u64,
    header: Option<(&Page, &Page)>,
    records: &[(&FinalRecord, &[u8])],
    defer_barriers: bool,
    mut sink: Option<&mut PageSink>,
) -> Result<(), StoreError<D::Error>> {
    // Payload and descriptor bodies are two dependency phases. Records in the
    // same segment transaction share each barrier. Descriptor seals are left
    // pending for the immediately following segment-summary body barrier: no
    // checkpoint can name the segment until its final seal is written, so a
    // cut before that shared barrier still leaves the whole segment unreachable.
    for (record, payload) in records {
        let mut copied = 0_usize;
        let mut page_index = 0_u32;
        while page_index < record.value.payload_pages {
            let batch_pages = (record.value.payload_pages - page_index).min(32) as usize;
            let mut pages = alloc::vec![[0; PAGE_SIZE]; batch_pages];
            for page in &mut pages {
                let take = (payload.len() - copied).min(PAGE_SIZE);
                page[..take].copy_from_slice(&payload[copied..copied + take]);
                copied += take;
            }
            match sink.as_deref_mut() {
                Some(sink) => {
                    for (offset, page) in pages.iter().enumerate() {
                        sink.push(
                            base + u64::from(record.value.payload_first_relative_page + page_index)
                                + offset as u64,
                            page,
                        )?;
                    }
                }
                None => {
                    device
                        .write_pages(
                            base + u64::from(
                                record.value.payload_first_relative_page + page_index,
                            ),
                            &pages,
                        )
                        .await
                        .map_err(StoreError::Mutation)?;
                }
            }
            page_index += batch_pages as u32;
        }
    }
    if let Some((body, _)) = header {
        sink_or_write_page(device, sink.as_deref_mut(), base, body).await?;
    }
    if !defer_barriers {
        flush(device).await?;
    }
    if let Some((_, seal)) = header {
        sink_or_write_page(device, sink.as_deref_mut(), base + 1, seal).await?;
    }
    for (record, _) in records {
        let descriptor_relative = record.value.payload_first_relative_page - 2;
        sink_or_write_page(
            device,
            sink.as_deref_mut(),
            base + u64::from(descriptor_relative),
            &record.body,
        )
        .await?;
    }
    if !defer_barriers {
        flush(device).await?;
    }
    for (record, _) in records {
        let descriptor_relative = record.value.payload_first_relative_page - 2;
        sink_or_write_page(
            device,
            sink.as_deref_mut(),
            base + u64::from(descriptor_relative + 1),
            &record.seal,
        )
        .await?;
    }
    Ok(())
}

fn map_streaming_error<E>(error: StreamingError<EmissionError>) -> CasStoreError<E> {
    match error {
        StreamingError::Blob(error) => CasStoreError::Blob(error),
        StreamingError::Sink(_) | StreamingError::Poisoned => CasStoreError::WriterFailed,
        _ => CasStoreError::InvalidChunk,
    }
}

fn plan_scratch<E>(
    _store_uuid: StoreUuid,
    first_segment: u64,
    first_generation: u64,
    _checkpoint_generation: u64,
    geometry: BlobGeometry,
) -> Result<(Vec<ScratchExtent>, Vec<ScratchSegment>), CasStoreError<E>> {
    let content_count = usize::try_from(geometry.exact_len())
        .map_err(|_| StoreError::ObjectTooLarge)?
        .div_ceil(CANONICAL_CONTENT_EXTENT_LEN as usize);
    let extent_count = content_count + 2;
    if extent_count > MAX_BLOB_EXTENTS {
        return Err(StoreError::ObjectTooLarge.into());
    }
    let mut lengths = Vec::new();
    lengths
        .try_reserve_exact(extent_count)
        .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
    lengths.push(HEADER_SIZE as u64);
    let mut remaining = geometry.exact_len();
    while remaining != 0 {
        let len = remaining.min(CANONICAL_CONTENT_EXTENT_LEN);
        lengths.push(len);
        remaining -= len;
    }
    lengths.push(geometry.tree_len() as u64);

    let mut extents = Vec::new();
    extents
        .try_reserve_exact(extent_count)
        .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
    let mut segments = Vec::new();
    segments
        .try_reserve_exact(extent_count)
        .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
    let mut segment_no = first_segment;
    let mut generation = first_generation;
    let mut relative = DATA_FIRST_PAGE;
    let mut ordinal = 1_u32;
    let mut first_extent = 0_usize;
    let mut encoded_offset = 0_u64;
    for (index, len) in lengths.into_iter().enumerate() {
        let payload_pages = u32::try_from(len.div_ceil(PAGE_SIZE as u64))
            .map_err(|_| StoreError::ObjectTooLarge)?;
        let span = payload_pages.checked_add(2).ok_or(StoreError::Corrupt)?;
        if relative
            .checked_add(span)
            .is_none_or(|end| end > DATA_END_PAGE)
        {
            segments.push(ScratchSegment {
                segment_no,
                segment_generation: generation,
                first_extent,
                extent_end: extents.len(),
            });
            segment_no = segment_no.checked_add(1).ok_or(StoreError::IdExhausted)?;
            generation = generation.checked_add(1).ok_or(StoreError::IdExhausted)?;
            relative = DATA_FIRST_PAGE;
            ordinal = 1;
            first_extent = extents.len();
        }
        extents.push(ScratchExtent {
            extent_index: index as u32,
            extent_count: extent_count as u32,
            encoded_offset,
            payload_byte_len: len,
            segment_no,
            segment_generation: generation,
            ordinal,
            descriptor_relative_page: relative,
            payload_relative_page: relative + 2,
        });
        encoded_offset = encoded_offset.checked_add(len).ok_or(StoreError::Corrupt)?;
        relative += span;
        ordinal += 1;
    }
    segments.push(ScratchSegment {
        segment_no,
        segment_generation: generation,
        first_extent,
        extent_end: extents.len(),
    });
    if encoded_offset != geometry.encoded_len() as u64 {
        return Err(StoreError::Corrupt.into());
    }
    Ok((extents, segments))
}

fn find_scratch_extent<E>(
    extents: &[ScratchExtent],
    offset: u64,
    len: u64,
) -> Result<(&ScratchExtent, u64), CasStoreError<E>> {
    let end = offset.checked_add(len).ok_or(StoreError::Corrupt)?;
    let extent = extents
        .iter()
        .find(|extent| {
            let extent_end = extent
                .encoded_offset
                .checked_add(extent.payload_byte_len)
                .unwrap_or(0);
            offset >= extent.encoded_offset && end <= extent_end
        })
        .ok_or(StoreError::Corrupt)?;
    Ok((extent, offset - extent.encoded_offset))
}

fn find_scratch_page<E>(
    extents: &[ScratchExtent],
    offset: u64,
) -> Result<(&ScratchExtent, u64), CasStoreError<E>> {
    let extent = extents
        .iter()
        .find(|extent| {
            extent
                .encoded_offset
                .checked_add(extent.payload_byte_len)
                .is_some_and(|end| offset >= extent.encoded_offset && offset < end)
        })
        .ok_or(StoreError::Corrupt)?;
    let within = offset - extent.encoded_offset;
    if !within.is_multiple_of(PAGE_SIZE as u64)
        || extent.payload_byte_len.saturating_sub(within) == 0
    {
        return Err(CasStoreError::InvalidChunk);
    }
    Ok((extent, within))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scratch_page_location_uses_extent_relative_alignment() {
        let geometry = BlobGeometry::for_len(CANONICAL_CONTENT_EXTENT_LEN + 1).unwrap();
        let (extents, _) =
            plan_scratch::<()>(StoreUuid::new([1; 16]).unwrap(), 1, 2, 3, geometry).unwrap();
        assert_eq!(extents.len(), 4);
        assert_eq!(extents[0].encoded_offset, 0);
        assert_eq!(extents[0].payload_byte_len, HEADER_SIZE as u64);
        assert_eq!(extents[1].encoded_offset, HEADER_SIZE as u64);
        assert_eq!(extents[1].payload_byte_len, CANONICAL_CONTENT_EXTENT_LEN);
        assert_eq!(extents[2].payload_byte_len, 1);

        let (header, within) = find_scratch_page::<()>(&extents, 0).unwrap();
        assert_eq!(header.extent_index, 0);
        assert_eq!(within, 0);

        // Globally offset 128 is not page-aligned, but it is the first logical
        // byte of an independently page-backed content extent.
        let (content, within) = find_scratch_page::<()>(&extents, HEADER_SIZE as u64).unwrap();
        assert_eq!(content.extent_index, 1);
        assert_eq!(within, 0);
        let (_, within) =
            find_scratch_page::<()>(&extents, HEADER_SIZE as u64 + PAGE_SIZE as u64).unwrap();
        assert_eq!(within, PAGE_SIZE as u64);

        // A one-byte final logical content extent still authorizes its
        // zero-padded physical page. Its exact end resolves to the independent
        // tree extent, never to the content extent's padding.
        let final_content_offset = HEADER_SIZE as u64 + CANONICAL_CONTENT_EXTENT_LEN;
        let (partial, within) = find_scratch_page::<()>(&extents, final_content_offset).unwrap();
        assert_eq!(partial.extent_index, 2);
        assert_eq!(partial.payload_byte_len, 1);
        assert_eq!(within, 0);
        let (tree, tree_within) =
            find_scratch_page::<()>(&extents, final_content_offset + 1).unwrap();
        assert_eq!(tree.extent_index, 3);
        assert_eq!(tree_within, 0);
        assert!(matches!(
            find_scratch_page::<()>(&extents, HEADER_SIZE as u64 + 1),
            Err(CasStoreError::InvalidChunk)
        ));
        assert!(find_scratch_page::<()>(&extents, geometry.encoded_len() as u64).is_err());
    }

    #[test]
    fn exact_range_never_crosses_canonical_extent_boundaries() {
        let geometry = BlobGeometry::for_len(CANONICAL_CONTENT_EXTENT_LEN + 1).unwrap();
        let (extents, _) =
            plan_scratch::<()>(StoreUuid::new([1; 16]).unwrap(), 1, 2, 3, geometry).unwrap();
        assert!(find_scratch_extent::<()>(&extents, 0, HEADER_SIZE as u64).is_ok());
        assert!(find_scratch_extent::<()>(
            &extents,
            HEADER_SIZE as u64,
            CANONICAL_CONTENT_EXTENT_LEN,
        )
        .is_ok());
        assert!(find_scratch_extent::<()>(
            &extents,
            HEADER_SIZE as u64 + CANONICAL_CONTENT_EXTENT_LEN - 1,
            2,
        )
        .is_err());
    }
}
