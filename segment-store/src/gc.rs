//! M7.5 root-based collection and crash-safe segment reuse protocol.
//!
//! This module deliberately separates *reachability* from *physical reuse*.
//! [`MarkPlan`] is the only authority for retaining objects and Blobs; segment
//! live-byte counters are selection hints only.  [`GcProtocol`] then enforces
//! the irreversible order around one deterministic partial relocation:
//!
//! 1. copy and authenticate every live extent into free cleaner targets;
//! 2. publish checkpoint `G + 1`, allocating targets and retiring selected sources;
//! 3. wait until no reader is pinned at generation `G` or older;
//! 4. clear the old checkpoint seal and read back an exact all-zero page;
//! 5. publish checkpoint `G + 2`, reclaiming retired sources to `Free`.
//!
//! A caller must not issue discard before step 5.  A crash before `G + 1`
//! selects `G`; a crash afterward selects `G + 1`, where sources remain
//! `Retired`; only a sealed `G + 2` makes them reusable.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use vibeos_blob_format::{BlobGeometry, BlobView, HASH_SIZE};
use vibeos_segment_format::{
    admitted_pages, descriptor_chain_initial, descriptor_chain_next, encode_record_seal,
    encode_segment_header_body, encode_segment_seal_body, encode_segment_summary_body,
    payload_chain_initial, payload_chain_next, payload_sha256, segment_base_page, BodyDigest,
    Checkpoint, ExtentKind, Page, PhysicalPointer, RecordBinding, SegmentHeader, SegmentSeal,
    SegmentSummary, StoreUuid, ANCHOR_SEGMENT_NO, DATA_END_PAGE, DATA_FIRST_PAGE, PAGE_SIZE,
    SEGMENT_SEAL_BODY_PAGE, SEGMENT_SEAL_PAGE, SUMMARY_BODY_PAGE, SUMMARY_SEAL_PAGE,
};

use crate::allocation_v2::{
    encode_allocation_v2, AllocationTransition, AllocationV2, AllocationV2Error, SegmentAllocation,
};
use crate::authority::AuthorizedObject;
use crate::authority_snapshot::{
    encode_persistent_authority_snapshot, AuthoritySnapshotError, PersistentAuthoritySnapshot,
};
use crate::cas::{
    build_record, flush, verify_manifest_blob, write_page, write_payload_records_with_header,
    CasObjectHandle, CasStoreError, FinalRecord,
};
use crate::cas_codec::{
    decode_blob_manifest, encode_blob_manifest, encode_cas_snapshot, BlobKey, BlobManifest,
    BlobMapping, CasCodecContext, CasSnapshot, ManifestExtent, ObjectMapping,
    BLOB_MANIFEST_HEADER_LEN, MANIFEST_EXTENT_LEN,
};
use crate::device::PageDevice;
use crate::mark::{
    CatalogView, ChildReference, MarkBudget, MarkPlan, MarkPlanner, MarkRoot, RootClass,
    TypedChildSource,
};
use crate::pins::{PinError, PinRegistry, RootKey, RuntimeRoot, RuntimeRootSnapshot};
use crate::root_codec::{
    encode_persistent_root_set, PersistentRootEntry, PersistentRootSet, RootCodecError,
};
use crate::store::{
    read_pointer_payload, read_pointer_payloads, write_checkpoint, MountedState, SegmentStore,
    StoreError, StoreLimits, ROOT_PIN_SLOTS,
};
use crate::typed_manifest::{
    ReferenceCodecAdmission, TypedObjectReference, TYPED_REFERENCE_ENTRY_LEN, TYPED_REFS_HEADER_LEN,
};

/// Maximum number of attempts used for a stable runtime-root snapshot.  A
/// busy registry is retried by the caller; roots are never sampled weakly.
pub(crate) const GC_ROOT_SNAPSHOT_ATTEMPTS: usize = 8;

const METADATA_KIND_MANIFEST: u32 = 0xffff_0010;
const METADATA_KIND_CAS_SNAPSHOT: u32 = 0xffff_0011;
const METADATA_KIND_ALLOCATION: u32 = 0xffff_0002;
const METADATA_KIND_ROOT_SET: u32 = 0xffff_0020;
const METADATA_KIND_PERSISTENT_AUTHORITY: u32 = 0xffff_0021;

/// Allocate page I/O scratch directly in its final heap representation so the
/// segment-builder futures remain safe for the kernel's bounded stack.
fn heap_page() -> Box<Page> {
    vec![0_u8; PAGE_SIZE]
        .into_boxed_slice()
        .try_into()
        .unwrap_or_else(|_| unreachable!("fixed page allocation has the exact page length"))
}

/// A full-compaction pass is bounded by the same catalog ceiling as recovery.
/// The largest transient byte buffer is one canonical Blob extent (1 MiB).
pub(crate) const GC_CHILD_BUDGET: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcError {
    InvalidGeneration,
    ObjectIdHighWaterUnavailable,
    InvalidPhase,
    InvalidSegmentSet,
    MissingPersistentRootPolicy,
    RootDoesNotResolve,
    MissingRelocatedBlob,
    DuplicateRelocatedBlob,
    ReaderStillPinned,
    OldCheckpointNotCleared,
    ArithmeticOverflow,
    MemoryLimit,
    NotMounted,
    NotCas,
    Capacity,
    Corrupt,
    CorruptAt(&'static str),
    Allocation(AllocationV2Error),
    RootCodec(RootCodecError),
    AuthoritySnapshot(AuthoritySnapshotError),
    Pins,
    QuotaPersistenceUnavailable,
}

impl fmt::Display for GcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidGeneration => "GC generation sequence is invalid",
            Self::ObjectIdHighWaterUnavailable => {
                "GC ObjectId high-water is not durably covered by checkpoint generation"
            }
            Self::InvalidPhase => "GC protocol phase is invalid for this operation",
            Self::InvalidSegmentSet => "GC source/target segment set is invalid",
            Self::MissingPersistentRootPolicy => "persistent GC root policy is unsynchronized",
            Self::RootDoesNotResolve => "GC root does not resolve to an exact object mapping",
            Self::MissingRelocatedBlob => "live Blob has no authenticated relocated manifest",
            Self::DuplicateRelocatedBlob => "relocated Blob list is not strictly ordered",
            Self::ReaderStillPinned => "an old extent-map reader is still pinned",
            Self::OldCheckpointNotCleared => "old checkpoint seal lacks exact-zero evidence",
            Self::ArithmeticOverflow => "GC arithmetic overflowed",
            Self::MemoryLimit => "GC fixed memory budget was exceeded",
            Self::NotMounted => "Storage V2 GC requires a mounted store",
            Self::NotCas => "Storage V2 GC requires the CAS catalog profile",
            Self::Capacity => "cleaner reserve cannot hold the live relocation",
            Self::Corrupt => "GC input or copied media failed authentication",
            Self::CorruptAt(stage) => return write!(f, "GC failed authentication at {stage}"),
            Self::Allocation(error) => return write!(f, "{error}"),
            Self::RootCodec(error) => return write!(f, "{error}"),
            Self::AuthoritySnapshot(error) => return write!(f, "{error}"),
            Self::Pins => "runtime pin admission or snapshot failed",
            Self::QuotaPersistenceUnavailable => {
                "boot-local quota attribution cannot enter persistent root policy"
            }
        })
    }
}

impl core::error::Error for GcError {}

impl From<AllocationV2Error> for GcError {
    fn from(value: AllocationV2Error) -> Self {
        Self::Allocation(value)
    }
}

impl From<RootCodecError> for GcError {
    fn from(value: RootCodecError) -> Self {
        Self::RootCodec(value)
    }
}

impl From<AuthoritySnapshotError> for GcError {
    fn from(value: AuthoritySnapshotError) -> Self {
        Self::AuthoritySnapshot(value)
    }
}

impl From<PinError> for GcError {
    fn from(_value: PinError) -> Self {
        Self::Pins
    }
}

#[derive(Debug)]
pub enum GcStoreError<E> {
    Store(StoreError<E>),
    Gc(GcError),
}

impl<E: fmt::Display> fmt::Display for GcStoreError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "{error}"),
            Self::Gc(error) => write!(f, "{error}"),
        }
    }
}

impl<E> From<StoreError<E>> for GcStoreError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Store(value)
    }
}

impl<E> From<GcError> for GcStoreError<E> {
    fn from(value: GcError) -> Self {
        Self::Gc(value)
    }
}

/// One Blob manifest after every referenced extent has been copied and
/// authenticated at its target location.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RelocatedBlob {
    pub(crate) blob_key: BlobKey,
    pub(crate) manifest: PhysicalPointer,
    /// Exact encoded Blob bytes copied, excluding manifest/snapshot metadata.
    pub(crate) copied_bytes: u64,
}

/// Filter the selected CAS through the authoritative mark result and bind each
/// live Blob to its newly verified manifest.  Shared Blobs remain one physical
/// entry even when several live objects name them.
pub(crate) fn build_relocated_snapshot(
    checkpoint_generation: u64,
    objects: &[ObjectMapping],
    blobs: &[BlobMapping],
    mark: &MarkPlan,
    relocated: &[RelocatedBlob],
) -> Result<CasSnapshot, GcError> {
    if checkpoint_generation
        != mark
            .epoch_generation()
            .checked_add(1)
            .ok_or(GcError::ArithmeticOverflow)?
    {
        return Err(GcError::InvalidGeneration);
    }
    if relocated
        .windows(2)
        .any(|pair| pair[0].blob_key >= pair[1].blob_key)
    {
        return Err(GcError::DuplicateRelocatedBlob);
    }

    let mut live_objects = Vec::new();
    live_objects
        .try_reserve_exact(mark.live_objects().len())
        .map_err(|_| GcError::MemoryLimit)?;
    for key in mark.live_objects() {
        let index = objects
            .binary_search_by_key(&key.object_id(), |object| object.object_id)
            .map_err(|_| GcError::RootDoesNotResolve)?;
        let object = objects[index];
        if object.commit_generation != key.commit_generation()
            || object.blob_key.object_kind() != key.object_kind()
        {
            return Err(GcError::RootDoesNotResolve);
        }
        live_objects.push(object);
    }

    let mut live_blobs = Vec::new();
    live_blobs
        .try_reserve_exact(mark.live_blobs().len())
        .map_err(|_| GcError::MemoryLimit)?;
    for key in mark.live_blobs() {
        if blobs
            .binary_search_by_key(key, |blob| blob.blob_key)
            .is_err()
        {
            return Err(GcError::RootDoesNotResolve);
        }
        let index = relocated
            .binary_search_by_key(key, |blob| blob.blob_key)
            .map_err(|_| GcError::MissingRelocatedBlob)?;
        live_blobs.push(BlobMapping {
            blob_key: *key,
            manifest: relocated[index].manifest,
        });
    }
    if relocated.len() != live_blobs.len() {
        return Err(GcError::DuplicateRelocatedBlob);
    }

    Ok(CasSnapshot {
        checkpoint_generation,
        objects: live_objects,
        blobs: live_blobs,
    })
}

/// Convert capability-resolved identities into a canonical persistent root
/// payload.  The caller must derive `witnesses` from `AuthorizedObject`
/// handles; this function deliberately accepts the crate-private [`RootKey`]
/// and cannot open an object from an ambient identifier.
pub(crate) fn build_persistent_root_set(
    checkpoint_generation: u64,
    witnesses: &[RootKey],
    objects: &[ObjectMapping],
) -> Result<PersistentRootSet, GcError> {
    if checkpoint_generation == 0 {
        return Err(GcError::InvalidGeneration);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(witnesses.len())
        .map_err(|_| GcError::MemoryLimit)?;
    for witness in witnesses {
        let index = objects
            .binary_search_by_key(&witness.object_id(), |object| object.object_id)
            .map_err(|_| GcError::RootDoesNotResolve)?;
        let object = objects[index];
        if object.commit_generation != witness.commit_generation()
            || object.blob_key.object_kind() != witness.object_kind()
        {
            return Err(GcError::RootDoesNotResolve);
        }
        entries.push(PersistentRootEntry {
            object_id: witness.object_id(),
            commit_generation: witness.commit_generation(),
            object_kind: witness.object_kind(),
        });
    }
    entries.sort_unstable_by_key(|entry| entry.object_id);
    entries.dedup_by_key(|entry| entry.object_id);
    PersistentRootSet::new(checkpoint_generation, entries).map_err(Into::into)
}

/// Capture the union of durable policy and runtime pins into one bounded mark
/// root vector. `None` is intentionally rejected, while `Some(empty-set)` is
/// authoritative and permits collection when there are no runtime pins.
pub(crate) fn capture_mark_roots<const ROOT_SLOTS: usize, const READER_SLOTS: usize>(
    policy: Option<&PersistentRootSet>,
    pins: &PinRegistry<ROOT_SLOTS, READER_SLOTS>,
    maximum_roots: usize,
    memory_limit: usize,
) -> Result<Vec<MarkRoot>, GcError> {
    let policy = policy.ok_or(GcError::MissingPersistentRootPolicy)?;
    let snapshot_bytes = vector_bytes(ROOT_SLOTS, core::mem::size_of::<RuntimeRoot>())?;
    let roots_bytes = vector_bytes(maximum_roots, core::mem::size_of::<MarkRoot>())?;
    if snapshot_bytes
        .checked_add(roots_bytes)
        .is_none_or(|bytes| bytes > memory_limit)
    {
        return Err(GcError::MemoryLimit);
    }
    let mut runtime = RuntimeRootSnapshot::with_capacity(ROOT_SLOTS)?;
    pins.snapshot_roots(&mut runtime, GC_ROOT_SNAPSHOT_ATTEMPTS)?;
    let total = policy
        .entries()
        .len()
        .checked_add(runtime.roots().len())
        .ok_or(GcError::ArithmeticOverflow)?;
    if total > maximum_roots {
        return Err(GcError::MemoryLimit);
    }
    let mut roots = Vec::new();
    roots
        .try_reserve_exact(maximum_roots)
        .map_err(|_| GcError::MemoryLimit)?;
    for entry in policy.entries() {
        roots.push(MarkRoot {
            key: RootKey::new(entry.object_id, entry.commit_generation, entry.object_kind)?,
            class: RootClass::PersistentPolicy,
        });
    }
    for runtime in runtime.roots() {
        roots.push(MarkRoot {
            key: runtime.key,
            class: RootClass::Runtime,
        });
    }
    roots.sort_unstable_by_key(|root| root.key);
    roots.dedup_by_key(|root| root.key);
    Ok(roots)
}

/// Typed-child adapter used by the asynchronous engine.  MarkPlanner itself is
/// deliberately synchronous, so all admitted typed payloads are authenticated
/// and decoded into this bounded table before traversal starts.
pub(crate) struct DecodedTypedChildren {
    entries: Vec<(u128, Vec<ChildReference>)>,
    allocated_bytes: usize,
    peak_bytes: usize,
}

impl DecodedTypedChildren {
    pub(crate) const fn allocated_bytes(&self) -> usize {
        self.allocated_bytes
    }

    pub(crate) const fn peak_bytes(&self) -> usize {
        self.peak_bytes
    }
}

struct GcMemoryAccount {
    limit: usize,
    current: usize,
    peak: usize,
}

impl GcMemoryAccount {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            current: 0,
            peak: 0,
        }
    }

    fn retain(&mut self, bytes: usize) -> Result<(), GcError> {
        self.current = self
            .current
            .checked_add(bytes)
            .ok_or(GcError::ArithmeticOverflow)?;
        self.peak = self.peak.max(self.current);
        if self.current > self.limit {
            return Err(GcError::MemoryLimit);
        }
        Ok(())
    }

    fn release(&mut self, bytes: usize) -> Result<(), GcError> {
        self.current = self
            .current
            .checked_sub(bytes)
            .ok_or(GcError::ArithmeticOverflow)?;
        Ok(())
    }

    fn transient(&mut self, bytes: usize) -> Result<(), GcError> {
        let high = self
            .current
            .checked_add(bytes)
            .ok_or(GcError::ArithmeticOverflow)?;
        self.peak = self.peak.max(high);
        if high > self.limit {
            return Err(GcError::MemoryLimit);
        }
        Ok(())
    }
}

fn vector_bytes(capacity: usize, element_size: usize) -> Result<usize, GcError> {
    capacity
        .checked_mul(element_size)
        .ok_or(GcError::ArithmeticOverflow)
}

fn generation_covers_object_id_high_water(generation: u64, next_object_id: u128) -> bool {
    next_object_id <= u128::from(generation)
}

fn decoded_entries_bytes(entries: &Vec<(u128, Vec<ChildReference>)>) -> Result<usize, GcError> {
    entries.iter().try_fold(
        vector_bytes(
            entries.capacity(),
            core::mem::size_of::<(u128, Vec<ChildReference>)>(),
        )?,
        |total, entry| {
            vector_bytes(entry.1.capacity(), core::mem::size_of::<ChildReference>())
                .and_then(|bytes| total.checked_add(bytes).ok_or(GcError::ArithmeticOverflow))
        },
    )
}

fn typed_decode_workspace_bytes(
    pending: &Vec<RootKey>,
    visited: &Vec<RootKey>,
    entries: &Vec<(u128, Vec<ChildReference>)>,
) -> Result<usize, GcError> {
    vector_bytes(pending.capacity(), core::mem::size_of::<RootKey>())?
        .checked_add(vector_bytes(
            visited.capacity(),
            core::mem::size_of::<RootKey>(),
        )?)
        .and_then(|bytes| bytes.checked_add(decoded_entries_bytes(entries).ok()?))
        .ok_or(GcError::ArithmeticOverflow)
}

impl TypedChildSource for DecodedTypedChildren {
    type Error = ();

    fn read_children(
        &self,
        object: &ObjectMapping,
        out: &mut [ChildReference],
    ) -> Result<usize, Self::Error> {
        let children = self
            .entries
            .binary_search_by_key(&object.object_id, |entry| entry.0)
            .ok()
            .map(|index| self.entries[index].1.as_slice())
            .ok_or(())?;
        if children.len() > out.len() {
            return Ok(children.len());
        }
        out[..children.len()].copy_from_slice(children);
        Ok(children.len())
    }
}

pub(crate) async fn decode_typed_children<D: PageDevice>(
    device: &D,
    state: &MountedState,
    limits: StoreLimits,
    roots: &[MarkRoot],
    typed_reference_kinds: &[u32],
) -> Result<DecodedTypedChildren, GcStoreError<D::Error>> {
    let cas = state.cas.as_ref().ok_or(GcError::NotCas)?;
    let object_budget =
        usize::try_from(limits.max_catalog_entries).map_err(|_| GcError::MemoryLimit)?;
    if object_budget == 0 || roots.len() > object_budget {
        return Err(GcError::MemoryLimit.into());
    }
    let fixed_requested = object_budget
        .checked_mul(
            core::mem::size_of::<RootKey>() * 2
                + core::mem::size_of::<(u128, Vec<ChildReference>)>(),
        )
        .ok_or(GcError::ArithmeticOverflow)?;
    if fixed_requested > limits.recovery_memory_bytes {
        return Err(GcError::MemoryLimit.into());
    }
    let mut pending = Vec::new();
    pending
        .try_reserve_exact(object_budget)
        .map_err(|_| GcError::MemoryLimit)?;
    for root in roots {
        if pending.binary_search(&root.key).is_err() {
            let insert = pending.binary_search(&root.key).unwrap_err();
            pending.insert(insert, root.key);
        }
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(object_budget)
        .map_err(|_| GcError::MemoryLimit)?;
    let context = CasCodecContext::new(
        state.superblock.binding.store_uuid,
        state.admitted_segments,
        state.next_segment_generation,
    )
    .map_err(|_| GcError::CorruptAt("relocate-context"))?;
    let mut visited = Vec::new();
    visited
        .try_reserve_exact(object_budget)
        .map_err(|_| GcError::MemoryLimit)?;
    let mut peak_bytes = typed_decode_workspace_bytes(&pending, &visited, &entries)?;
    if peak_bytes > limits.recovery_memory_bytes {
        return Err(GcError::MemoryLimit.into());
    }
    while let Some(key) = pending.pop() {
        if visited.binary_search(&key).is_ok() {
            continue;
        }
        if visited.len() == object_budget {
            return Err(GcError::MemoryLimit.into());
        }
        let visited_insert = visited.binary_search(&key).unwrap_err();
        visited.insert(visited_insert, key);
        let object = cas
            .objects
            .binary_search_by_key(&key.object_id(), |object| object.object_id)
            .ok()
            .map(|index| cas.objects[index])
            .filter(|object| {
                object.commit_generation == key.commit_generation()
                    && object.blob_key.object_kind() == key.object_kind()
            })
            .ok_or(GcError::RootDoesNotResolve)?;
        if object.reference_codec == 0 {
            continue;
        }
        if object.reference_codec != crate::cas_codec::REFERENCE_CODEC_TYPED_V1
            && object.reference_codec != crate::cas_codec::REFERENCE_CODEC_FS_V1
        {
            return Err(GcError::Corrupt.into());
        }
        if object.reference_codec == crate::cas_codec::REFERENCE_CODEC_FS_V1
            && !matches!(
                object.blob_key.object_kind(),
                crate::FS_ROOT_V1_KIND | crate::FS_BTREE_NODE_V1_KIND | crate::FS_DATA_V1_KIND
            )
        {
            return Err(GcError::Corrupt.into());
        }
        if typed_reference_kinds
            .binary_search(&object.blob_key.object_kind())
            .is_err()
        {
            // A media tag never admits its own parser. Unregistered kinds are
            // opaque even when their bytes happen to be valid VIBEREF1.
            entries.push((object.object_id, Vec::new()));
            continue;
        }
        // Reject an over-budget typed payload from the authenticated BlobKey
        // before reading its manifest or allocating any Blob-sized buffer.
        // The exact logical length is part of the Merkle identity, so this
        // preflight cannot be bypassed by media contents.
        let maximum_typed_len = TYPED_REFS_HEADER_LEN
            .checked_add(
                GC_CHILD_BUDGET
                    .checked_mul(TYPED_REFERENCE_ENTRY_LEN)
                    .ok_or(GcError::ArithmeticOverflow)?,
            )
            .ok_or(GcError::ArithmeticOverflow)?;
        let typed_exact_len =
            usize::try_from(object.blob_key.exact_len()).map_err(|_| GcError::MemoryLimit)?;
        if typed_exact_len > maximum_typed_len {
            return Err(GcError::MemoryLimit.into());
        }
        let blob = cas
            .blobs
            .binary_search_by_key(&object.blob_key, |blob| blob.blob_key)
            .ok()
            .map(|index| cas.blobs[index])
            .ok_or(GcError::Corrupt)?;
        let workspace = typed_decode_workspace_bytes(&pending, &visited, &entries)?;
        let manifest_len = match blob.manifest {
            PhysicalPointer::Value(pointer) => {
                usize::try_from(pointer.exact_byte_len).map_err(|_| GcError::MemoryLimit)?
            }
            PhysicalPointer::Null => return Err(GcError::Corrupt.into()),
        };
        let manifest_payload_peak = workspace
            .checked_add(manifest_len)
            .ok_or(GcError::ArithmeticOverflow)?;
        peak_bytes = peak_bytes.max(manifest_payload_peak);
        if manifest_payload_peak > limits.recovery_memory_bytes {
            return Err(GcError::MemoryLimit.into());
        }
        let payload = read_pointer_payload(
            device,
            state.superblock.binding.store_uuid,
            state.admitted_segments,
            state.next_segment_generation,
            state.generation,
            blob.manifest,
            ExtentKind::Catalog,
            limits.recovery_memory_bytes - workspace,
        )
        .await?;
        let maximum_manifest_extents = payload
            .bytes
            .len()
            .saturating_sub(BLOB_MANIFEST_HEADER_LEN)
            .checked_div(MANIFEST_EXTENT_LEN)
            .and_then(|count| count.checked_add(1))
            .ok_or(GcError::ArithmeticOverflow)?;
        let manifest_decode_bytes = vector_bytes(
            maximum_manifest_extents,
            core::mem::size_of::<ManifestExtent>(),
        )?;
        let manifest_decode_peak = workspace
            .checked_add(payload.bytes.capacity())
            .and_then(|bytes| bytes.checked_add(manifest_decode_bytes))
            .ok_or(GcError::ArithmeticOverflow)?;
        peak_bytes = peak_bytes.max(manifest_decode_peak);
        if manifest_decode_peak > limits.recovery_memory_bytes {
            return Err(GcError::MemoryLimit.into());
        }
        let manifest =
            decode_blob_manifest(&payload.bytes, context).map_err(|_| GcError::Corrupt)?;
        let manifest_resident = vector_bytes(
            manifest.extents.capacity(),
            core::mem::size_of::<ManifestExtent>(),
        )?;
        drop(payload);
        let blob_memory = limits
            .recovery_memory_bytes
            .checked_sub(workspace)
            .and_then(|bytes| bytes.checked_sub(manifest_resident))
            .ok_or(GcError::MemoryLimit)?;
        let encoded = read_authenticated_blob(device, state, blob_memory, &manifest).await?;
        let blob_peak = workspace
            .checked_add(manifest_resident)
            .and_then(|bytes| bytes.checked_add(encoded.capacity()))
            .and_then(|bytes| {
                manifest
                    .extents
                    .iter()
                    .try_fold(0_usize, |largest, extent| {
                        usize::try_from(extent.payload_byte_len)
                            .map(|value| largest.max(value))
                            .map_err(|_| GcError::MemoryLimit)
                    })
                    .ok()
                    .and_then(|largest| bytes.checked_add(largest))
            })
            .ok_or(GcError::ArithmeticOverflow)?;
        peak_bytes = peak_bytes.max(blob_peak);
        drop(manifest);
        let geometry =
            BlobGeometry::for_len(object.blob_key.exact_len()).map_err(|_| GcError::Corrupt)?;
        let tree_verify_bytes = usize::try_from(geometry.tree_node_count())
            .map_err(|_| GcError::MemoryLimit)?
            .checked_mul(HASH_SIZE)
            .ok_or(GcError::ArithmeticOverflow)?;
        let verify_peak = workspace
            .checked_add(encoded.capacity())
            .and_then(|bytes| bytes.checked_add(tree_verify_bytes))
            .ok_or(GcError::ArithmeticOverflow)?;
        peak_bytes = peak_bytes.max(verify_peak);
        if verify_peak > limits.recovery_memory_bytes {
            return Err(GcError::MemoryLimit.into());
        }
        let view = BlobView::decode(&encoded).map_err(|_| GcError::Corrupt)?;
        view.verify_all().map_err(|_| GcError::Corrupt)?;
        if view.data().len() != typed_exact_len {
            return Err(GcError::MemoryLimit.into());
        }
        let maximum_references = view
            .data()
            .len()
            .saturating_sub(TYPED_REFS_HEADER_LEN)
            .checked_div(TYPED_REFERENCE_ENTRY_LEN)
            .ok_or(GcError::ArithmeticOverflow)?;
        let decoded_reference_bytes = vector_bytes(
            maximum_references,
            core::mem::size_of::<TypedObjectReference>(),
        )?;
        let retained_child_bytes =
            vector_bytes(maximum_references, core::mem::size_of::<ChildReference>())?;
        let typed_decode_peak = workspace
            .checked_add(encoded.capacity())
            .and_then(|bytes| bytes.checked_add(decoded_reference_bytes))
            .and_then(|bytes| bytes.checked_add(retained_child_bytes))
            .ok_or(GcError::ArithmeticOverflow)?;
        peak_bytes = peak_bytes.max(typed_decode_peak);
        if typed_decode_peak > limits.recovery_memory_bytes {
            return Err(GcError::MemoryLimit.into());
        }
        let object_kind = object.blob_key.object_kind();
        let decoded = if object.reference_codec == crate::cas_codec::REFERENCE_CODEC_FS_V1
            && matches!(
                object_kind,
                crate::FS_ROOT_V1_KIND | crate::FS_BTREE_NODE_V1_KIND | crate::FS_DATA_V1_KIND
            ) {
            crate::decode_fs_typed_references(object_kind, view.data(), object.commit_generation)
                .map_err(|_| GcError::Corrupt)?
        } else {
            let admission =
                ReferenceCodecAdmission::refs_v1(object_kind).map_err(|_| GcError::Corrupt)?;
            admission
                .decode(object_kind, view.data())
                .map_err(|_| GcError::Corrupt)?
        };
        if object.reference_codec == crate::cas_codec::REFERENCE_CODEC_TYPED_V1
            && decoded.manifest_commit_generation != object.commit_generation
        {
            return Err(GcError::Corrupt.into());
        }
        if decoded.references().len() > GC_CHILD_BUDGET {
            return Err(GcError::MemoryLimit.into());
        }
        let mut object_children = Vec::new();
        object_children
            .try_reserve_exact(decoded.references().len())
            .map_err(|_| GcError::MemoryLimit)?;
        let actual_decode_peak = workspace
            .checked_add(encoded.capacity())
            .and_then(|bytes| {
                bytes.checked_add(
                    vector_bytes(
                        decoded.references().len(),
                        core::mem::size_of::<TypedObjectReference>(),
                    )
                    .ok()?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    vector_bytes(
                        object_children.capacity(),
                        core::mem::size_of::<ChildReference>(),
                    )
                    .ok()?,
                )
            })
            .ok_or(GcError::ArithmeticOverflow)?;
        peak_bytes = peak_bytes.max(actual_decode_peak);
        if actual_decode_peak > limits.recovery_memory_bytes {
            return Err(GcError::MemoryLimit.into());
        }
        for reference in decoded.into_references() {
            object_children.push(
                ChildReference::new(
                    reference.object_id,
                    reference.commit_generation,
                    reference.object_kind,
                )
                .map_err(|_| GcError::Corrupt)?,
            );
        }
        for child in &object_children {
            let child_key =
                RootKey::new(child.object_id, child.commit_generation, child.object_kind)
                    .map_err(GcError::from)?;
            if visited.binary_search(&child_key).is_err()
                && pending.binary_search(&child_key).is_err()
            {
                if pending.len() == object_budget {
                    return Err(GcError::MemoryLimit.into());
                }
                let insert = pending.binary_search(&child_key).unwrap_err();
                pending.insert(insert, child_key);
            }
        }
        entries.push((object.object_id, object_children));
    }
    entries.sort_unstable_by_key(|entry| entry.0);
    let allocated_bytes = decoded_entries_bytes(&entries)?;
    Ok(DecodedTypedChildren {
        entries,
        allocated_bytes,
        peak_bytes,
    })
}

async fn read_authenticated_blob<D: PageDevice>(
    device: &D,
    state: &MountedState,
    memory_limit: usize,
    manifest: &BlobManifest,
) -> Result<Vec<u8>, GcStoreError<D::Error>> {
    let encoded_len =
        usize::try_from(manifest.encoded_blob_len).map_err(|_| GcError::MemoryLimit)?;
    let largest_extent = manifest
        .extents
        .iter()
        .try_fold(0_usize, |largest, extent| {
            usize::try_from(extent.payload_byte_len)
                .map(|bytes| largest.max(bytes))
                .map_err(|_| GcError::MemoryLimit)
        })?;
    if encoded_len
        .checked_add(largest_extent)
        .is_none_or(|bytes| bytes > memory_limit)
    {
        return Err(GcError::MemoryLimit.into());
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| GcError::MemoryLimit)?;
    if encoded
        .capacity()
        .checked_add(largest_extent)
        .is_none_or(|bytes| bytes > memory_limit)
    {
        return Err(GcError::MemoryLimit.into());
    }
    for declared in &manifest.extents {
        if encoded.len() as u64 != declared.encoded_offset {
            return Err(GcError::Corrupt.into());
        }
        let payload = read_pointer_payload(
            device,
            state.superblock.binding.store_uuid,
            state.admitted_segments,
            state.next_segment_generation,
            state.generation,
            declared.pointer,
            ExtentKind::Blob,
            memory_limit
                .checked_sub(encoded.capacity())
                .ok_or(GcError::MemoryLimit)?,
        )
        .await?;
        if encoded
            .capacity()
            .checked_add(payload.bytes.capacity())
            .is_none_or(|bytes| bytes > memory_limit)
        {
            return Err(GcError::MemoryLimit.into());
        }
        if payload.bytes.len() as u64 != declared.payload_byte_len {
            return Err(GcError::Corrupt.into());
        }
        encoded.extend_from_slice(&payload.bytes);
    }
    if encoded.len() != encoded_len {
        return Err(GcError::Corrupt.into());
    }
    Ok(encoded)
}

/// Exact segment sets and immutable allocation maps for one compaction cycle.
/// `sources` is a sorted subset of segments which were `Allocated` at `G`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GcSegmentPlan {
    pub(crate) epoch_generation: u64,
    pub(crate) relocation_generation: u64,
    pub(crate) reuse_generation: u64,
    pub(crate) sources: Vec<u64>,
    pub(crate) targets: Vec<u64>,
    pub(crate) barrier_segment: u64,
    pub(crate) relocation_allocation: AllocationV2,
    pub(crate) reuse_allocation: AllocationV2,
}

impl GcSegmentPlan {
    /// Build the two durable maps before any copy begins. `targets` includes
    /// all G+1 data and metadata segments. `barrier_segment` is distinct free
    /// scratch used to store the G+2 allocation payload itself.
    #[cfg(test)]
    pub(crate) fn full_compaction(
        selected: &AllocationV2,
        sources: Vec<u64>,
        targets: Vec<u64>,
        barrier_segment: u64,
    ) -> Result<Self, GcError> {
        let allocated_count = selected.counts()?.allocated;
        if usize::try_from(allocated_count).ok() != Some(sources.len())
            || sources
                .iter()
                .copied()
                .ne((0..selected.admitted_segments).filter(|segment| {
                    selected.segment_state(*segment) == Some(SegmentAllocation::Allocated)
                }))
        {
            return Err(GcError::InvalidSegmentSet);
        }
        Self::partial_compaction(selected, sources, targets, barrier_segment)
    }

    pub(crate) fn partial_compaction(
        selected: &AllocationV2,
        sources: Vec<u64>,
        targets: Vec<u64>,
        barrier_segment: u64,
    ) -> Result<Self, GcError> {
        if selected.checkpoint_generation == u64::MAX {
            return Err(GcError::InvalidGeneration);
        }
        let relocation_generation = selected.checkpoint_generation + 1;
        let reuse_generation = relocation_generation
            .checked_add(1)
            .ok_or(GcError::InvalidGeneration)?;
        validate_sorted_unique(&sources)?;
        validate_sorted_unique(&targets)?;
        if sources.is_empty()
            || targets.is_empty()
            || targets.binary_search(&barrier_segment).is_ok()
            || sources.binary_search(&barrier_segment).is_ok()
            || sets_intersect(&sources, &targets)
        {
            return Err(GcError::InvalidSegmentSet);
        }

        if sources
            .iter()
            .any(|segment| selected.segment_state(*segment) != Some(SegmentAllocation::Allocated))
            || targets
                .iter()
                .any(|segment| selected.segment_state(*segment) != Some(SegmentAllocation::Free))
            || selected.segment_state(barrier_segment) != Some(SegmentAllocation::Free)
        {
            return Err(GcError::InvalidSegmentSet);
        }

        let after_targets = selected
            .next_segment_generation
            .checked_add(targets.len() as u64)
            .ok_or(GcError::ArithmeticOverflow)?;
        let relocation_allocation = selected.apply_transition(AllocationTransition {
            checkpoint_generation: relocation_generation,
            next_segment_generation: after_targets,
            allocate: &targets,
            retire: &sources,
            reclaim: &[],
        })?;
        let reuse_allocation = relocation_allocation.apply_transition(AllocationTransition {
            checkpoint_generation: reuse_generation,
            next_segment_generation: after_targets
                .checked_add(1)
                .ok_or(GcError::ArithmeticOverflow)?,
            allocate: core::slice::from_ref(&barrier_segment),
            retire: &[],
            reclaim: &sources,
        })?;

        Ok(Self {
            epoch_generation: selected.checkpoint_generation,
            relocation_generation,
            reuse_generation,
            sources,
            targets,
            barrier_segment,
            relocation_allocation,
            reuse_allocation,
        })
    }
}

fn validate_sorted_unique(values: &[u64]) -> Result<(), GcError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        Err(GcError::InvalidSegmentSet)
    } else {
        Ok(())
    }
}

fn sets_intersect(left: &[u64], right: &[u64]) -> bool {
    let (mut left_index, mut right_index) = (0, 0);
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].cmp(&right[right_index]) {
            core::cmp::Ordering::Less => left_index += 1,
            core::cmp::Ordering::Greater => right_index += 1,
            core::cmp::Ordering::Equal => return true,
        }
    }
    false
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GcPhase {
    Copying,
    RelocationPublished,
    ReadersQuiescent,
    OldCheckpointCleared,
    ReuseBarrierPublished,
}

/// Evidence is constructible only from the exact page read back after the old
/// seal write+flush.  Checking a prefix or trusting write completion is not
/// sufficient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExactZeroCheckpointSeal(());

impl ExactZeroCheckpointSeal {
    pub(crate) fn from_readback(page: &[u8; PAGE_SIZE]) -> Result<Self, GcError> {
        if page.iter().all(|byte| *byte == 0) {
            Ok(Self(()))
        } else {
            Err(GcError::OldCheckpointNotCleared)
        }
    }
}

/// In-memory transaction guard for the durable sequence. I/O integration must
/// call transitions only after the named seal/flush/readback has succeeded.
pub(crate) struct GcProtocol {
    plan: GcSegmentPlan,
    phase: GcPhase,
    telemetry: GcTelemetry,
}

impl GcProtocol {
    pub(crate) fn begin(plan: GcSegmentPlan, stats: GcTelemetry) -> Result<Self, GcError> {
        if stats.epoch_generation != plan.epoch_generation {
            return Err(GcError::InvalidGeneration);
        }
        Ok(Self {
            plan,
            phase: GcPhase::Copying,
            telemetry: stats,
        })
    }

    /// Call only after G+1 checkpoint body and seal were flushed and cold-read
    /// validation selected the exact relocation map.
    pub(crate) fn relocation_published(&mut self) -> Result<(), GcError> {
        if self.phase != GcPhase::Copying {
            return Err(GcError::InvalidPhase);
        }
        self.phase = GcPhase::RelocationPublished;
        Ok(())
    }

    pub(crate) fn observe_quiescence<const ROOT_SLOTS: usize, const READER_SLOTS: usize>(
        &mut self,
        pins: &PinRegistry<ROOT_SLOTS, READER_SLOTS>,
    ) -> Result<(), GcError> {
        if self.phase != GcPhase::RelocationPublished {
            return Err(GcError::InvalidPhase);
        }
        self.telemetry.quiescence_scans = self
            .telemetry
            .quiescence_scans
            .checked_add(1)
            .ok_or(GcError::ArithmeticOverflow)?;
        if !pins.is_quiescent_through(self.plan.epoch_generation) {
            return Err(GcError::ReaderStillPinned);
        }
        self.phase = GcPhase::ReadersQuiescent;
        Ok(())
    }

    pub(crate) fn old_checkpoint_cleared(
        &mut self,
        _evidence: ExactZeroCheckpointSeal,
    ) -> Result<(), GcError> {
        if self.phase != GcPhase::ReadersQuiescent {
            return Err(GcError::InvalidPhase);
        }
        self.phase = GcPhase::OldCheckpointCleared;
        Ok(())
    }

    /// Call only after G+2 is sealed and cold recovery selects its exact reuse
    /// allocation map. Sources become eligible for allocator use and optional
    /// discard only after this returns.
    pub(crate) fn reuse_barrier_published(&mut self) -> Result<(), GcError> {
        if self.phase != GcPhase::OldCheckpointCleared {
            return Err(GcError::InvalidPhase);
        }
        self.phase = GcPhase::ReuseBarrierPublished;
        self.telemetry.relocation_generation = self.plan.relocation_generation;
        self.telemetry.reuse_generation = self.plan.reuse_generation;
        self.telemetry.retired_segments = self.plan.sources.len() as u32;
        self.telemetry.reclaimed_segments = self.plan.sources.len() as u32;
        self.telemetry.target_segments = self.plan.targets.len() as u32 + 1;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<GcTelemetry, GcError> {
        if self.phase != GcPhase::ReuseBarrierPublished {
            return Err(GcError::InvalidPhase);
        }
        Ok(self.telemetry)
    }
}

/// Bounded per-cycle counters. Cumulative aggregation belongs to the caller
/// and must use saturating arithmetic so telemetry can never block recovery.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GcTelemetry {
    pub epoch_generation: u64,
    pub relocation_generation: u64,
    pub reuse_generation: u64,
    pub root_count: u32,
    pub live_object_count: u32,
    pub live_blob_count: u32,
    pub copied_bytes: u64,
    pub reclaimed_bytes: u64,
    pub metadata_bytes: u64,
    pub retired_segments: u32,
    pub reclaimed_segments: u32,
    pub target_segments: u32,
    pub quiescence_scans: u32,
    /// Accounted peak heap bytes for the mounted-state clone and every fixed
    /// GC workspace retained during this cycle.
    pub memory_high_water_bytes: usize,
    /// Parts per million of cleaner-target capacity consumed at G+1.
    pub reserve_pressure_ppm: u32,
    /// Wall-independent monotonic time spent inside the foreground GC call.
    pub foreground_pause_ns: u64,
    /// False for callers which use [`SegmentStore::collect_garbage`] without
    /// supplying a clock.
    pub pause_time_measured: bool,
    /// Number of physical GC cycles represented by this sample. A direct
    /// collection reports one; foreground admission may saturating-aggregate
    /// several cycles.
    pub foreground_cycles: u32,
}

/// Caller-supplied monotonic clock used to keep the `no_std` store independent
/// of any platform timer implementation.
pub trait GcTimeSource {
    fn monotonic_ns(&self) -> u64;
}

fn elapsed_ns(start: u64, end: u64) -> u64 {
    end.saturating_sub(start)
}

impl GcTelemetry {
    pub fn write_amplification_ppm(&self) -> u64 {
        self.copied_bytes
            .saturating_add(self.metadata_bytes)
            .saturating_mul(1_000_000)
            .checked_div(self.reclaimed_bytes)
            .unwrap_or(0)
    }

    /// Aggregate another completed cycle. Counters saturate so observability
    /// can never turn a successful recovery action into a failure.
    pub fn saturating_merge_cycle(&mut self, next: Self) {
        if self.foreground_cycles == 0 {
            self.epoch_generation = next.epoch_generation;
        }
        self.relocation_generation = next.relocation_generation;
        self.reuse_generation = next.reuse_generation;
        self.root_count = self.root_count.max(next.root_count);
        self.live_object_count = self.live_object_count.max(next.live_object_count);
        self.live_blob_count = self.live_blob_count.max(next.live_blob_count);
        self.copied_bytes = self.copied_bytes.saturating_add(next.copied_bytes);
        self.reclaimed_bytes = self.reclaimed_bytes.saturating_add(next.reclaimed_bytes);
        self.metadata_bytes = self.metadata_bytes.saturating_add(next.metadata_bytes);
        self.retired_segments = self.retired_segments.saturating_add(next.retired_segments);
        self.reclaimed_segments = self
            .reclaimed_segments
            .saturating_add(next.reclaimed_segments);
        self.target_segments = self.target_segments.saturating_add(next.target_segments);
        self.quiescence_scans = self.quiescence_scans.saturating_add(next.quiescence_scans);
        self.memory_high_water_bytes = self
            .memory_high_water_bytes
            .max(next.memory_high_water_bytes);
        self.reserve_pressure_ppm = self.reserve_pressure_ppm.max(next.reserve_pressure_ppm);
        self.foreground_pause_ns = self
            .foreground_pause_ns
            .saturating_add(next.foreground_pause_ns);
        self.pause_time_measured |= next.pause_time_measured;
        self.foreground_cycles = self
            .foreground_cycles
            .saturating_add(next.foreground_cycles.max(1));
    }
}

pub(crate) fn select_free_segments(
    allocation: &AllocationV2,
    count: usize,
) -> Result<Vec<u64>, GcError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| GcError::MemoryLimit)?;
    for segment_no in 0..allocation.admitted_segments {
        if allocation.segment_state(segment_no) == Some(SegmentAllocation::Free) {
            output.push(segment_no);
            if output.len() == count {
                return Ok(output);
            }
        }
    }
    Err(GcError::Capacity)
}

fn pointer_segment(pointer: PhysicalPointer) -> Option<u64> {
    match pointer {
        PhysicalPointer::Null => None,
        PhysicalPointer::Value(value) => Some(value.segment_no),
    }
}

/// Rank allocated segments by authoritative live Blob bytes, then segment
/// number. All segments have identical capacity, so byte order is live-ratio
/// order without lossy fixed-point division.
fn ranked_gc_sources(
    allocation: &AllocationV2,
    manifests: &[BlobManifest],
) -> Result<Vec<(u64, u64)>, GcError> {
    let count =
        usize::try_from(allocation.counts()?.allocated).map_err(|_| GcError::MemoryLimit)?;
    let mut ranked = Vec::new();
    ranked
        .try_reserve_exact(count)
        .map_err(|_| GcError::MemoryLimit)?;
    for segment_no in 0..allocation.admitted_segments {
        if allocation.segment_state(segment_no) == Some(SegmentAllocation::Allocated) {
            ranked.push((0_u64, segment_no));
        }
    }
    for manifest in manifests {
        for extent in &manifest.extents {
            let segment_no = pointer_segment(extent.pointer).ok_or(GcError::Corrupt)?;
            let slot = ranked
                .iter_mut()
                .find(|entry| entry.1 == segment_no)
                .ok_or(GcError::Corrupt)?;
            slot.0 = slot
                .0
                .checked_add(extent.payload_byte_len)
                .ok_or(GcError::ArithmeticOverflow)?;
        }
    }
    ranked.sort_unstable_by_key(|&(live_bytes, segment_no)| (live_bytes, segment_no));
    Ok(ranked)
}

fn source_contains(sources: &[u64], pointer: PhysicalPointer) -> bool {
    pointer_segment(pointer).is_some_and(|segment_no| sources.binary_search(&segment_no).is_ok())
}

fn validate_gc_source_budget(
    allocation: &AllocationV2,
    source_count: usize,
    memory_limit: usize,
) -> Result<(), GcError> {
    let allocated =
        usize::try_from(allocation.counts()?.allocated).map_err(|_| GcError::MemoryLimit)?;
    if source_count > allocated {
        return Err(GcError::InvalidSegmentSet);
    }
    let retirement_bytes = source_count
        .checked_mul(crate::allocation_v2::RETIRED_SEGMENT_ENTRY_LEN)
        .ok_or(GcError::ArithmeticOverflow)?;
    let encoded_bytes = crate::allocation_v2::ALLOCATION_V2_HEADER_LEN
        .checked_add(allocation.packed_bitmap().len())
        .and_then(|bytes| bytes.checked_add(retirement_bytes))
        .ok_or(GcError::ArithmeticOverflow)?;
    let candidate_bytes = allocated
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(GcError::ArithmeticOverflow)?;
    let ranking_bytes = allocated
        .checked_mul(core::mem::size_of::<(u64, u64)>())
        .ok_or(GcError::ArithmeticOverflow)?;
    let worklist_peak = ranking_bytes
        .checked_add(candidate_bytes)
        .ok_or(GcError::ArithmeticOverflow)?;
    if encoded_bytes > crate::allocation_v2::MAX_ALLOCATION_V2_PAYLOAD_LEN
        || worklist_peak > memory_limit
    {
        return Err(GcError::MemoryLimit);
    }
    Ok(())
}

fn mounted_state_heap_bytes(state: &MountedState) -> Result<usize, GcError> {
    state
        .resident_heap_bytes()
        .ok_or(GcError::ArithmeticOverflow)
}

fn metadata_pages(bytes: usize) -> Result<u32, GcError> {
    let payload = u64::try_from(bytes).map_err(|_| GcError::ArithmeticOverflow)?;
    u32::try_from(payload.div_ceil(PAGE_SIZE as u64)).map_err(|_| GcError::ArithmeticOverflow)
}

fn cas_snapshot_len(object_count: usize, blob_count: usize) -> Result<usize, GcError> {
    crate::cas_codec::CAS_SNAPSHOT_HEADER_LEN
        .checked_add(
            object_count
                .checked_mul(crate::cas_codec::OBJECT_MAPPING_LEN)
                .ok_or(GcError::ArithmeticOverflow)?,
        )
        .and_then(|bytes| {
            blob_count
                .checked_mul(crate::cas_codec::BLOB_MAPPING_LEN)
                .and_then(|more| bytes.checked_add(more))
        })
        .ok_or(GcError::ArithmeticOverflow)
}

fn blob_manifest_encoded_len(manifest: &BlobManifest) -> Result<usize, GcError> {
    BLOB_MANIFEST_HEADER_LEN
        .checked_add(
            manifest
                .extents
                .len()
                .checked_mul(MANIFEST_EXTENT_LEN)
                .ok_or(GcError::ArithmeticOverflow)?,
        )
        .ok_or(GcError::ArithmeticOverflow)
}

fn persistent_root_encoded_len(roots: &PersistentRootSet) -> Result<usize, GcError> {
    crate::root_codec::PERSISTENT_ROOT_SET_HEADER_LEN
        .checked_add(
            roots
                .entries()
                .len()
                .checked_mul(crate::root_codec::PERSISTENT_ROOT_ENTRY_LEN)
                .ok_or(GcError::ArithmeticOverflow)?,
        )
        .ok_or(GcError::ArithmeticOverflow)
}

#[allow(clippy::too_many_arguments)]
fn relocation_workspace_upper_bound(
    state: &MountedState,
    mark: &MarkPlan,
    manifests: &[BlobManifest],
    manifest_lens: &[usize],
    plan: &GcSegmentPlan,
    snapshot_len: usize,
    root_len: usize,
    allocation_len: usize,
) -> Result<usize, GcError> {
    if manifests.len() != manifest_lens.len() {
        return Err(GcError::InvalidSegmentSet);
    }
    let maximum_payload = manifests
        .iter()
        .flat_map(|manifest| manifest.extents.iter())
        .filter(|extent| source_contains(&plan.sources, extent.pointer))
        .try_fold(0_usize, |largest, extent| {
            usize::try_from(extent.payload_byte_len)
                .map(|bytes| largest.max(bytes))
                .map_err(|_| GcError::MemoryLimit)
        })?;
    let maximum_extent_count = manifests
        .iter()
        .map(|manifest| manifest.extents.len())
        .max()
        .unwrap_or(0);
    let maximum_manifest_len = manifest_lens.iter().copied().max().unwrap_or(0);
    let relocated_bytes = vector_bytes(manifests.len(), core::mem::size_of::<RelocatedBlob>())?;
    let new_extents_bytes =
        vector_bytes(maximum_extent_count, core::mem::size_of::<ManifestExtent>())?;
    let snapshot_tables = vector_bytes(
        mark.live_objects().len(),
        core::mem::size_of::<ObjectMapping>(),
    )?
    .checked_add(vector_bytes(
        mark.live_blobs().len(),
        core::mem::size_of::<BlobMapping>(),
    )?)
    .ok_or(GcError::ArithmeticOverflow)?;
    // Encoded catalog/root/allocation payloads remain live while cold-readback
    // allocates a second copy of the largest one. Manifest verification instead
    // holds its encoded payload plus decoded extent table and one page buffer.
    let root_readback = snapshot_len.max(root_len).max(allocation_len);
    let manifest_readback = maximum_manifest_len
        .checked_add(new_extents_bytes)
        .and_then(|bytes| bytes.checked_add(PAGE_SIZE))
        .ok_or(GcError::ArithmeticOverflow)?;
    let verification = root_readback.max(manifest_readback);
    [
        root_len,
        allocation_len,
        vector_bytes(plan.targets.len(), core::mem::size_of::<u64>())?,
        relocated_bytes,
        new_extents_bytes,
        maximum_payload,
        maximum_manifest_len,
        snapshot_tables,
        snapshot_len,
        mounted_state_heap_bytes(state)?,
        verification,
    ]
    .into_iter()
    .try_fold(0_usize, |total, bytes| {
        total.checked_add(bytes).ok_or(GcError::ArithmeticOverflow)
    })
}

#[allow(clippy::too_many_arguments)]
fn post_relocation_workspace_upper_bound(
    state: &MountedState,
    roots: &PersistentRootSet,
    manifests: &[BlobManifest],
    manifest_lens: &[usize],
    plan: &GcSegmentPlan,
    snapshot_len: usize,
    root_len: usize,
    relocation_allocation_len: usize,
) -> Result<usize, GcError> {
    if manifests.len() != manifest_lens.len() {
        return Err(GcError::InvalidSegmentSet);
    }
    let old_allocation = state
        .allocation
        .allocated_bytes()
        .ok_or(GcError::ArithmeticOverflow)?;
    let old_roots = state
        .persistent_roots
        .as_ref()
        .and_then(PersistentRootSet::allocated_bytes)
        .unwrap_or(0);
    let relocated_state = mounted_state_heap_bytes(state)?
        .checked_sub(old_allocation)
        .and_then(|bytes| bytes.checked_sub(old_roots))
        .and_then(|bytes| {
            plan.relocation_allocation
                .allocated_bytes()
                .and_then(|more| bytes.checked_add(more))
        })
        .and_then(|bytes| {
            roots
                .allocated_bytes()
                .and_then(|more| bytes.checked_add(more))
        })
        .ok_or(GcError::ArithmeticOverflow)?;
    let reuse_allocation_len = crate::allocation_v2::ALLOCATION_V2_HEADER_LEN
        .checked_add(plan.reuse_allocation.packed_bitmap().len())
        .ok_or(GcError::ArithmeticOverflow)?;
    let maximum_manifest = manifests.iter().zip(manifest_lens).try_fold(
        0_usize,
        |largest, (manifest, encoded_len)| {
            vector_bytes(
                manifest.extents.capacity(),
                core::mem::size_of::<ManifestExtent>(),
            )
            .and_then(|decoded| {
                encoded_len
                    .checked_add(decoded)
                    .map(|bytes| largest.max(bytes))
                    .ok_or(GcError::ArithmeticOverflow)
            })
        },
    )?;
    let catalog_tables = state
        .cas
        .as_ref()
        .ok_or(GcError::NotCas)?
        .objects
        .capacity()
        .checked_mul(core::mem::size_of::<ObjectMapping>())
        .and_then(|bytes| {
            state
                .cas
                .as_ref()?
                .blobs
                .capacity()
                .checked_mul(core::mem::size_of::<BlobMapping>())
                .and_then(|more| bytes.checked_add(more))
        })
        .ok_or(GcError::ArithmeticOverflow)?;
    let recovery_resident = relocated_state;
    let latest_recovery_peak = recovery_resident
        .checked_add(
            snapshot_len
                .max(root_len)
                .max(relocation_allocation_len)
                .max(reuse_allocation_len)
                .max(maximum_manifest),
        )
        .and_then(|bytes| bytes.checked_add(catalog_tables))
        .ok_or(GcError::ArithmeticOverflow)?;
    let transition_witness = old_allocation.max(
        plan.relocation_allocation
            .allocated_bytes()
            .ok_or(GcError::ArithmeticOverflow)?,
    );
    let mount_peak = transition_witness
        .checked_add(latest_recovery_peak)
        .ok_or(GcError::ArithmeticOverflow)?;

    // During both remounts the old local state and all mark/planning tables
    // remain live. The returned mounted state is then cloned for the barrier,
    // so reserve one additional relocated state plus the encoded/readback G+2
    // allocation payload. This is deliberately conservative and is checked
    // before the first target write.
    mount_peak
        .checked_add(relocated_state)
        .and_then(|bytes| {
            reuse_allocation_len
                .checked_mul(2)
                .and_then(|more| bytes.checked_add(more))
        })
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<u64>()))
        .ok_or(GcError::ArithmeticOverflow)
}

/// Simulate canonical packing so all target segments can be reserved before
/// the first copy. Each physical source extent remains one physical target
/// extent; no operation holds more than that exact payload in memory.
fn required_gc_segments(
    manifests: &[BlobManifest],
    manifest_payload_lens: &[usize],
    sources: &[u64],
    snapshot_len: usize,
    root_len: usize,
    allocation_len: usize,
) -> Result<usize, GcError> {
    let mut segments = 1_usize;
    let mut relative = DATA_FIRST_PAGE;
    let mut place = |payload_len: usize| -> Result<(), GcError> {
        let span = metadata_pages(payload_len)?
            .checked_add(2)
            .ok_or(GcError::ArithmeticOverflow)?;
        if span > DATA_END_PAGE - DATA_FIRST_PAGE {
            return Err(GcError::Capacity);
        }
        if relative
            .checked_add(span)
            .is_none_or(|end| end > DATA_END_PAGE)
        {
            segments = segments.checked_add(1).ok_or(GcError::ArithmeticOverflow)?;
            relative = DATA_FIRST_PAGE;
        }
        relative = relative
            .checked_add(span)
            .ok_or(GcError::ArithmeticOverflow)?;
        Ok(())
    };
    if manifests.len() != manifest_payload_lens.len() {
        return Err(GcError::InvalidSegmentSet);
    }
    for (manifest, manifest_len) in manifests.iter().zip(manifest_payload_lens) {
        for extent in &manifest.extents {
            if source_contains(sources, extent.pointer) {
                place(usize::try_from(extent.payload_byte_len).map_err(|_| GcError::Capacity)?)?;
            }
        }
        place(*manifest_len)?;
    }
    for len in [snapshot_len, root_len, allocation_len] {
        place(len)?;
    }
    Ok(segments)
}

pub(crate) struct SegmentBuilder {
    store_uuid: StoreUuid,
    checkpoint_generation: u64,
    segments: Vec<u64>,
    first_segment_generation: u64,
    index: usize,
    relative: u32,
    ordinal: u32,
    header_digest: Option<BodyDigest>,
    header_body: Option<Box<Page>>,
    header_seal: Option<Box<Page>>,
    summary: SegmentSummaryAccumulator,
    previous: Option<(u64, u64, [u8; 32])>,
}

#[derive(Clone, Copy)]
pub(crate) struct SegmentPayload<'a> {
    pub(crate) extent_kind: ExtentKind,
    pub(crate) object_kind: u32,
    pub(crate) extent_index: u32,
    pub(crate) extent_count: u32,
    pub(crate) content_byte_len: u64,
    pub(crate) encoded_blob_len: u64,
    pub(crate) encoded_offset: u64,
    pub(crate) merkle_root: [u8; 32],
    pub(crate) bytes: &'a [u8],
}

#[derive(Clone, Copy)]
struct SegmentSummaryAccumulator {
    descriptor_chain: [u8; 32],
    payload_chain: [u8; 32],
    kind_counts: [u32; 5],
    kind_bytes: [u64; 5],
    payload_page_count: u32,
    total_payload_bytes: u64,
    record_count: u32,
    next_free_page: u32,
    first_target_checkpoint_generation: u64,
    last_target_checkpoint_generation: u64,
}

impl SegmentSummaryAccumulator {
    fn empty(store_uuid: StoreUuid, segment_no: u64, segment_generation: u64) -> Self {
        Self {
            descriptor_chain: descriptor_chain_initial(store_uuid, segment_no, segment_generation),
            payload_chain: payload_chain_initial(store_uuid, segment_no, segment_generation),
            kind_counts: [0; 5],
            kind_bytes: [0; 5],
            payload_page_count: 0,
            total_payload_bytes: 0,
            record_count: 0,
            next_free_page: DATA_FIRST_PAGE,
            first_target_checkpoint_generation: 0,
            last_target_checkpoint_generation: 0,
        }
    }

    fn push(&mut self, record: &FinalRecord) -> Result<(), GcError> {
        let value = &record.value;
        self.descriptor_chain = descriptor_chain_next(
            value.binding.store_uuid,
            value.binding.segment_no,
            value.binding.generation,
            self.descriptor_chain,
            value.binding.ordinal,
            record.digest.body_sha256(),
            value.payload_sha256,
        );
        self.payload_chain = payload_chain_next(
            value.binding.store_uuid,
            value.binding.segment_no,
            value.binding.generation,
            self.payload_chain,
            value.binding.ordinal,
            value.payload_byte_len,
            value.payload_sha256,
        );
        let kind = value.extent_kind as usize - 1;
        self.kind_counts[kind] = self.kind_counts[kind]
            .checked_add(1)
            .ok_or(GcError::ArithmeticOverflow)?;
        self.kind_bytes[kind] = self.kind_bytes[kind]
            .checked_add(value.payload_byte_len)
            .ok_or(GcError::ArithmeticOverflow)?;
        self.payload_page_count = self
            .payload_page_count
            .checked_add(value.payload_pages)
            .ok_or(GcError::ArithmeticOverflow)?;
        self.total_payload_bytes = self
            .total_payload_bytes
            .checked_add(value.payload_byte_len)
            .ok_or(GcError::ArithmeticOverflow)?;
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or(GcError::ArithmeticOverflow)?;
        self.next_free_page = value
            .payload_first_relative_page
            .checked_add(value.payload_pages)
            .ok_or(GcError::ArithmeticOverflow)?;
        if self.first_target_checkpoint_generation == 0 {
            self.first_target_checkpoint_generation = value.binding.target_checkpoint_generation;
        }
        self.last_target_checkpoint_generation = value.binding.target_checkpoint_generation;
        Ok(())
    }
}

impl SegmentBuilder {
    pub(crate) async fn begin<D: PageDevice>(
        device: &D,
        state: &MountedState,
        checkpoint_generation: u64,
        segments: Vec<u64>,
    ) -> Result<Self, GcStoreError<D::Error>> {
        let first = *segments.first().ok_or(GcError::InvalidSegmentSet)?;
        let mut builder = Self {
            store_uuid: state.superblock.binding.store_uuid,
            checkpoint_generation,
            segments,
            first_segment_generation: state.next_segment_generation,
            index: 0,
            relative: DATA_FIRST_PAGE,
            ordinal: 1,
            header_digest: None,
            header_body: None,
            header_seal: None,
            summary: SegmentSummaryAccumulator::empty(
                state.superblock.binding.store_uuid,
                first,
                state.next_segment_generation,
            ),
            previous: state.last_segment,
        };
        builder.open(device, first).await?;
        Ok(builder)
    }

    fn segment_generation(&self) -> Result<u64, GcError> {
        self.first_segment_generation
            .checked_add(self.index as u64)
            .ok_or(GcError::ArithmeticOverflow)
    }

    async fn open<D: PageDevice>(
        &mut self,
        device: &D,
        segment_no: u64,
    ) -> Result<(), GcStoreError<D::Error>> {
        let segment_generation = self.segment_generation()?;
        let base = segment_base_page(segment_no).map_err(StoreError::Format)?;
        // An unsealed target is never authoritative. Exact-zero the final seal
        // before writing payload and verify the zero write durably.
        let zero = heap_page();
        write_page(device, base + u64::from(SEGMENT_SEAL_PAGE), &zero).await?;
        flush(device).await?;
        let mut observed = heap_page();
        device
            .read_page(base + u64::from(SEGMENT_SEAL_PAGE), &mut observed)
            .await
            .map_err(StoreError::Device)?;
        if observed != zero {
            return Err(GcError::Corrupt.into());
        }
        let (previous_segment_no, previous_segment_generation, previous_hash) =
            self.previous.unwrap_or((ANCHOR_SEGMENT_NO, 0, [0; 32]));
        let header = SegmentHeader {
            binding: RecordBinding {
                store_uuid: self.store_uuid,
                generation: segment_generation,
                segment_no,
                ordinal: 0,
                self_page: base,
                target_checkpoint_generation: self.checkpoint_generation,
            },
            base_page: base,
            previous_segment_no,
            previous_segment_generation,
            previous_segment_seal_body_sha256: previous_hash,
        };
        let mut body = heap_page();
        let mut seal = heap_page();
        let header_digest =
            encode_segment_header_body(&header, &mut body).map_err(StoreError::Format)?;
        encode_record_seal(header_digest, &mut seal).map_err(StoreError::Format)?;
        self.header_digest = Some(header_digest);
        self.header_body = Some(body);
        self.header_seal = Some(seal);
        self.relative = DATA_FIRST_PAGE;
        self.ordinal = 1;
        self.summary =
            SegmentSummaryAccumulator::empty(self.store_uuid, segment_no, segment_generation);
        Ok(())
    }

    fn take_header_pages(&mut self) -> Result<Option<(Box<Page>, Box<Page>)>, GcError> {
        match (self.header_body.take(), self.header_seal.take()) {
            (Some(body), Some(seal)) => Ok(Some((body, seal))),
            (None, None) => Ok(None),
            _ => Err(GcError::Corrupt),
        }
    }

    async fn finish_current<D: PageDevice>(
        &mut self,
        device: &D,
        flush_final_seal: bool,
    ) -> Result<(), GcStoreError<D::Error>> {
        if self.summary.record_count == 0 {
            return Err(GcError::InvalidSegmentSet.into());
        }
        let segment_no = self.segments[self.index];
        self.previous = Some(
            finalize_accumulated_segment(
                device,
                self.store_uuid,
                self.checkpoint_generation,
                segment_no,
                self.segment_generation()?,
                self.header_digest.ok_or(GcError::Corrupt)?,
                self.summary,
                flush_final_seal,
            )
            .await?,
        );
        Ok(())
    }

    async fn ensure<D: PageDevice>(
        &mut self,
        device: &D,
        payload_len: usize,
    ) -> Result<(), GcStoreError<D::Error>> {
        let span = metadata_pages(payload_len)?
            .checked_add(2)
            .ok_or(GcError::ArithmeticOverflow)?;
        if self
            .relative
            .checked_add(span)
            .is_some_and(|end| end <= DATA_END_PAGE)
        {
            return Ok(());
        }
        self.finish_current(device, true).await?;
        self.index = self
            .index
            .checked_add(1)
            .ok_or(GcError::ArithmeticOverflow)?;
        let segment_no = *self.segments.get(self.index).ok_or(GcError::Capacity)?;
        self.open(device, segment_no).await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn payload<D: PageDevice>(
        &mut self,
        device: &D,
        extent_kind: ExtentKind,
        object_kind: u32,
        extent_index: u32,
        extent_count: u32,
        content_byte_len: u64,
        encoded_blob_len: u64,
        encoded_offset: u64,
        merkle_root: [u8; 32],
        bytes: &[u8],
    ) -> Result<PhysicalPointer, GcStoreError<D::Error>> {
        self.ensure(device, bytes.len()).await?;
        let segment_no = self.segments[self.index];
        let base = segment_base_page(segment_no).map_err(StoreError::Format)?;
        let hash = payload_sha256(bytes);
        let record = build_record(
            self.store_uuid,
            segment_no,
            self.segment_generation()?,
            self.checkpoint_generation,
            self.ordinal,
            self.relative,
            extent_kind,
            object_kind,
            extent_index,
            extent_count,
            content_byte_len,
            encoded_blob_len,
            encoded_offset,
            bytes.len() as u64,
            merkle_root,
            hash,
        )
        .map_err(StoreError::Format)?;
        let header_pages = self.take_header_pages()?;
        let header = header_pages
            .as_ref()
            .map(|(body, seal)| (body.as_ref(), seal.as_ref()));
        write_payload_records_with_header(device, base, header, &[(&record, bytes)], false).await?;
        self.relative = self
            .relative
            .checked_add(record.value.record_span_pages)
            .ok_or(GcError::ArithmeticOverflow)?;
        self.ordinal = self
            .ordinal
            .checked_add(1)
            .ok_or(GcError::ArithmeticOverflow)?;
        let pointer = record.pointer();
        self.summary.push(&record)?;
        Ok(pointer)
    }

    pub(crate) async fn payload_batch<D: PageDevice>(
        &mut self,
        device: &D,
        payloads: &[SegmentPayload<'_>],
    ) -> Result<Vec<PhysicalPointer>, GcStoreError<D::Error>> {
        if payloads.is_empty() {
            return Err(GcError::InvalidSegmentSet.into());
        }
        let span = payloads.iter().try_fold(0_u32, |total, payload| {
            metadata_pages(payload.bytes.len())?
                .checked_add(2)
                .and_then(|more| total.checked_add(more))
                .ok_or(GcError::ArithmeticOverflow)
        })?;
        if self
            .relative
            .checked_add(span)
            .is_none_or(|end| end > DATA_END_PAGE)
        {
            let mut pointers = Vec::new();
            pointers
                .try_reserve_exact(payloads.len())
                .map_err(|_| GcError::MemoryLimit)?;
            for payload in payloads {
                pointers.push(
                    self.payload(
                        device,
                        payload.extent_kind,
                        payload.object_kind,
                        payload.extent_index,
                        payload.extent_count,
                        payload.content_byte_len,
                        payload.encoded_blob_len,
                        payload.encoded_offset,
                        payload.merkle_root,
                        payload.bytes,
                    )
                    .await?,
                );
            }
            return Ok(pointers);
        }

        let segment_no = self.segments[self.index];
        let segment_generation = self.segment_generation()?;
        let base = segment_base_page(segment_no).map_err(StoreError::Format)?;
        let mut relative = self.relative;
        let mut ordinal = self.ordinal;
        let mut records = Vec::new();
        records
            .try_reserve_exact(payloads.len())
            .map_err(|_| GcError::MemoryLimit)?;
        for payload in payloads {
            let hash = payload_sha256(payload.bytes);
            let record = build_record(
                self.store_uuid,
                segment_no,
                segment_generation,
                self.checkpoint_generation,
                ordinal,
                relative,
                payload.extent_kind,
                payload.object_kind,
                payload.extent_index,
                payload.extent_count,
                payload.content_byte_len,
                payload.encoded_blob_len,
                payload.encoded_offset,
                payload.bytes.len() as u64,
                payload.merkle_root,
                hash,
            )
            .map_err(StoreError::Format)?;
            relative = relative
                .checked_add(record.value.record_span_pages)
                .ok_or(GcError::ArithmeticOverflow)?;
            ordinal = ordinal.checked_add(1).ok_or(GcError::ArithmeticOverflow)?;
            records.push(record);
        }
        let mut writes = Vec::new();
        writes
            .try_reserve_exact(records.len())
            .map_err(|_| GcError::MemoryLimit)?;
        writes.extend(
            records
                .iter()
                .zip(payloads)
                .map(|(record, payload)| (record, payload.bytes)),
        );
        let header_pages = self.take_header_pages()?;
        let header = header_pages
            .as_ref()
            .map(|(body, seal)| (body.as_ref(), seal.as_ref()));
        write_payload_records_with_header(device, base, header, &writes, false).await?;
        let mut pointers = Vec::new();
        pointers
            .try_reserve_exact(records.len())
            .map_err(|_| GcError::MemoryLimit)?;
        for record in &records {
            pointers.push(record.pointer());
            self.summary.push(record)?;
        }
        self.relative = relative;
        self.ordinal = ordinal;
        Ok(pointers)
    }

    pub(crate) async fn finish<D: PageDevice>(
        mut self,
        device: &D,
    ) -> Result<(u64, u64, [u8; 32]), GcStoreError<D::Error>> {
        self.finish_current(device, true).await?;
        if self.index + 1 != self.segments.len() {
            return Err(GcError::InvalidSegmentSet.into());
        }
        self.previous.ok_or(GcError::Corrupt.into())
    }

    /// Finish the final segment without an otherwise redundant standalone
    /// flush. The caller must immediately clear a checkpoint slot; that
    /// operation's first barrier durably orders this final seal before the new
    /// checkpoint body and seal can be published.
    pub(crate) async fn finish_before_checkpoint<D: PageDevice>(
        mut self,
        device: &D,
    ) -> Result<(u64, u64, [u8; 32]), GcStoreError<D::Error>> {
        self.finish_current(device, false).await?;
        if self.index + 1 != self.segments.len() {
            return Err(GcError::InvalidSegmentSet.into());
        }
        self.previous.ok_or(GcError::Corrupt.into())
    }
}

#[allow(clippy::too_many_arguments)]
async fn finalize_accumulated_segment<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    checkpoint_generation: u64,
    segment_no: u64,
    segment_generation: u64,
    header_digest: BodyDigest,
    accumulated: SegmentSummaryAccumulator,
    flush_final_seal: bool,
) -> Result<(u64, u64, [u8; 32]), GcStoreError<D::Error>> {
    if accumulated.record_count == 0
        || accumulated.first_target_checkpoint_generation == 0
        || accumulated.last_target_checkpoint_generation == 0
    {
        return Err(GcError::Corrupt.into());
    }
    let base = segment_base_page(segment_no).map_err(StoreError::Format)?;
    let summary = SegmentSummary {
        binding: RecordBinding {
            store_uuid,
            generation: segment_generation,
            segment_no,
            ordinal: accumulated.record_count + 1,
            self_page: base + u64::from(SUMMARY_BODY_PAGE),
            target_checkpoint_generation: checkpoint_generation,
        },
        record_count: accumulated.record_count,
        next_free_page: accumulated.next_free_page,
        payload_page_count: accumulated.payload_page_count,
        total_payload_bytes: accumulated.total_payload_bytes,
        first_target_checkpoint_generation: accumulated.first_target_checkpoint_generation,
        last_target_checkpoint_generation: accumulated.last_target_checkpoint_generation,
        header_body_sha256: header_digest.body_sha256(),
        descriptor_chain_sha256: accumulated.descriptor_chain,
        payload_chain_sha256: accumulated.payload_chain,
        kind_counts: accumulated.kind_counts,
        kind_bytes: accumulated.kind_bytes,
    };
    let mut summary_body = heap_page();
    let mut summary_seal = heap_page();
    let summary_digest =
        encode_segment_summary_body(&summary, &mut summary_body).map_err(StoreError::Format)?;
    encode_record_seal(summary_digest, &mut summary_seal).map_err(StoreError::Format)?;
    let seal = SegmentSeal {
        binding: RecordBinding {
            store_uuid,
            generation: segment_generation,
            segment_no,
            ordinal: accumulated.record_count + 2,
            self_page: base + u64::from(SEGMENT_SEAL_BODY_PAGE),
            target_checkpoint_generation: checkpoint_generation,
        },
        header_body_sha256: header_digest.body_sha256(),
        summary_body_sha256: summary_digest.body_sha256(),
        final_descriptor_chain_sha256: accumulated.descriptor_chain,
        final_payload_chain_sha256: accumulated.payload_chain,
        record_count: accumulated.record_count,
        next_free_page: accumulated.next_free_page,
        payload_page_count: accumulated.payload_page_count,
        total_payload_bytes: accumulated.total_payload_bytes,
        target_checkpoint_generation: checkpoint_generation,
    };
    let mut seal_body = heap_page();
    let mut final_seal = heap_page();
    let seal_digest =
        encode_segment_seal_body(&seal, &mut seal_body).map_err(StoreError::Format)?;
    encode_record_seal(seal_digest, &mut final_seal).map_err(StoreError::Format)?;
    write_page(device, base + u64::from(SUMMARY_BODY_PAGE), &summary_body).await?;
    flush(device).await?;
    write_page(device, base + u64::from(SUMMARY_SEAL_PAGE), &summary_seal).await?;
    write_page(device, base + u64::from(SEGMENT_SEAL_BODY_PAGE), &seal_body).await?;
    flush(device).await?;
    write_page(device, base + u64::from(SEGMENT_SEAL_PAGE), &final_seal).await?;
    if flush_final_seal {
        flush(device).await?;
    }
    Ok((segment_no, segment_generation, seal_digest.body_sha256()))
}

async fn load_live_manifests<D: PageDevice>(
    device: &D,
    state: &MountedState,
    limits: StoreLimits,
    mark: &MarkPlan,
    retained_bytes: usize,
) -> Result<Vec<BlobManifest>, GcStoreError<D::Error>> {
    let cas = state.cas.as_ref().ok_or(GcError::NotCas)?;
    let context = CasCodecContext::new(
        state.superblock.binding.store_uuid,
        state.admitted_segments,
        state.next_segment_generation,
    )
    .map_err(|_| GcError::Corrupt)?;
    let mut manifests = Vec::new();
    let table_bytes = vector_bytes(
        mark.live_blobs().len(),
        core::mem::size_of::<BlobManifest>(),
    )?;
    if retained_bytes
        .checked_add(table_bytes)
        .is_none_or(|bytes| bytes > limits.recovery_memory_bytes)
    {
        return Err(GcError::MemoryLimit.into());
    }
    manifests
        .try_reserve_exact(mark.live_blobs().len())
        .map_err(|_| GcError::MemoryLimit)?;
    for key in mark.live_blobs() {
        let existing_extents =
            manifests
                .iter()
                .try_fold(0_usize, |bytes, manifest: &BlobManifest| {
                    vector_bytes(
                        manifest.extents.capacity(),
                        core::mem::size_of::<ManifestExtent>(),
                    )
                    .and_then(|more| bytes.checked_add(more).ok_or(GcError::ArithmeticOverflow))
                })?;
        let blob = cas
            .blobs
            .binary_search_by_key(key, |blob| blob.blob_key)
            .ok()
            .map(|index| cas.blobs[index])
            .ok_or(GcError::Corrupt)?;
        let payload = read_pointer_payload(
            device,
            state.superblock.binding.store_uuid,
            state.admitted_segments,
            state.next_segment_generation,
            state.generation,
            blob.manifest,
            ExtentKind::Catalog,
            limits
                .recovery_memory_bytes
                .checked_sub(retained_bytes)
                .and_then(|bytes| bytes.checked_sub(table_bytes))
                .and_then(|bytes| bytes.checked_sub(existing_extents))
                .ok_or(GcError::MemoryLimit)?,
        )
        .await?;
        let maximum_new_extents = payload
            .bytes
            .len()
            .saturating_sub(BLOB_MANIFEST_HEADER_LEN)
            .checked_div(MANIFEST_EXTENT_LEN)
            .and_then(|count| count.checked_add(1))
            .ok_or(GcError::ArithmeticOverflow)?;
        let maximum_new_extent_bytes =
            vector_bytes(maximum_new_extents, core::mem::size_of::<ManifestExtent>())?;
        if retained_bytes
            .checked_add(table_bytes)
            .and_then(|bytes| bytes.checked_add(existing_extents))
            .and_then(|bytes| bytes.checked_add(payload.bytes.capacity()))
            .and_then(|bytes| bytes.checked_add(maximum_new_extent_bytes))
            .is_none_or(|bytes| bytes > limits.recovery_memory_bytes)
        {
            return Err(GcError::MemoryLimit.into());
        }
        let manifest =
            decode_blob_manifest(&payload.bytes, context).map_err(|_| GcError::Corrupt)?;
        if manifest.blob_key != *key {
            return Err(GcError::Corrupt.into());
        }
        manifests.push(manifest);
    }
    Ok(manifests)
}

fn manifest_table_bytes(manifests: &[BlobManifest]) -> Result<usize, GcError> {
    vector_bytes(manifests.len(), core::mem::size_of::<BlobManifest>())?
        .checked_add(manifests.iter().try_fold(0_usize, |bytes, manifest| {
            vector_bytes(
                manifest.extents.capacity(),
                core::mem::size_of::<ManifestExtent>(),
            )
            .and_then(|more| bytes.checked_add(more).ok_or(GcError::ArithmeticOverflow))
        })?)
        .ok_or(GcError::ArithmeticOverflow)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn verify_staged_payload<D: PageDevice>(
    device: &D,
    state: &MountedState,
    checkpoint_generation: u64,
    next_segment_generation: u64,
    pointer: PhysicalPointer,
    kind: ExtentKind,
    expected: &[u8],
    maximum_bytes: usize,
) -> Result<(), GcStoreError<D::Error>> {
    let observed = read_pointer_payload(
        device,
        state.superblock.binding.store_uuid,
        state.admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        pointer,
        kind,
        maximum_bytes,
    )
    .await?;
    if observed.bytes != expected {
        return Err(GcError::Corrupt.into());
    }
    Ok(())
}

pub(crate) async fn verify_staged_payloads<D: PageDevice>(
    device: &D,
    state: &MountedState,
    checkpoint_generation: u64,
    next_segment_generation: u64,
    expected: &[(PhysicalPointer, ExtentKind, &[u8])],
    maximum_bytes: usize,
) -> Result<(), GcStoreError<D::Error>> {
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(expected.len())
        .map_err(|_| GcError::MemoryLimit)?;
    requests.extend(
        expected
            .iter()
            .map(|(pointer, kind, _)| (*pointer, *kind, maximum_bytes)),
    );
    let observed = read_pointer_payloads(
        device,
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
            .any(|(actual, (_, _, bytes))| actual.bytes != *bytes)
    {
        return Err(GcError::Corrupt.into());
    }
    Ok(())
}

/// Authenticate one newly copied Blob extent through the same descriptor,
/// segment-seal, and payload-hash path used by production reads.  Physical
/// page padding is outside the exact payload digest, so GC additionally
/// requires the acknowledged target's final-page tail to remain canonical
/// zeroes before any checkpoint can name the target.
async fn verify_staged_copied_extent<D: PageDevice>(
    device: &D,
    state: &MountedState,
    checkpoint_generation: u64,
    next_segment_generation: u64,
    declared: &ManifestExtent,
) -> Result<(), GcStoreError<D::Error>> {
    let maximum_bytes =
        usize::try_from(declared.payload_byte_len).map_err(|_| GcError::MemoryLimit)?;
    let observed = read_pointer_payload(
        device,
        state.superblock.binding.store_uuid,
        state.admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        declared.pointer,
        ExtentKind::Blob,
        maximum_bytes,
    )
    .await
    .map_err(|error| match error {
        StoreError::Corrupt => {
            GcStoreError::Gc(GcError::CorruptAt("relocate-copied-payload-readback"))
        }
        other => GcStoreError::Store(other),
    })?;
    if observed.bytes.len() != maximum_bytes {
        return Err(GcError::CorruptAt("relocate-copied-payload-length").into());
    }
    drop(observed);

    let PhysicalPointer::Value(pointer) = declared.pointer else {
        return Err(GcError::CorruptAt("relocate-copied-pointer").into());
    };
    let tail = maximum_bytes % PAGE_SIZE;
    if tail == 0 {
        return Ok(());
    }
    let last_payload_relative = u64::from(pointer.payload_pages)
        .checked_sub(1)
        .ok_or(GcError::CorruptAt("relocate-copied-pointer"))?;
    let last_payload_page = segment_base_page(pointer.segment_no)
        .map_err(StoreError::Format)?
        .checked_add(u64::from(pointer.payload_relative_page))
        .and_then(|page| page.checked_add(last_payload_relative))
        .ok_or(GcError::ArithmeticOverflow)?;
    let mut page = heap_page();
    device
        .read_page(last_payload_page, &mut page)
        .await
        .map_err(StoreError::Device)?;
    if page[tail..].iter().any(|byte| *byte != 0) {
        return Err(GcError::CorruptAt("relocate-copied-padding-readback").into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn relocate_live_state<D: PageDevice>(
    device: &D,
    state: &MountedState,
    limits: StoreLimits,
    mark: &MarkPlan,
    root_count: usize,
    roots: &PersistentRootSet,
    authority: Option<&PersistentAuthoritySnapshot>,
    manifests: &[BlobManifest],
    manifest_lens: &[usize],
    plan: &GcSegmentPlan,
) -> Result<
    (
        PhysicalPointer,
        PhysicalPointer,
        PhysicalPointer,
        [u8; 32],
        GcTelemetry,
    ),
    GcStoreError<D::Error>,
> {
    let cas = state.cas.as_ref().ok_or(GcError::NotCas)?;
    let target_next_generation = plan.relocation_allocation.next_segment_generation;
    let context = CasCodecContext::new(
        state.superblock.binding.store_uuid,
        state.admitted_segments,
        target_next_generation,
    )
    .map_err(|_| GcError::Corrupt)?;
    let (root_bytes, root_kind) = match authority {
        Some(snapshot) => (
            encode_persistent_authority_snapshot(
                &snapshot
                    .relocated(plan.relocation_generation)
                    .map_err(GcError::from)?,
            )
            .map_err(GcError::from)?,
            METADATA_KIND_PERSISTENT_AUTHORITY,
        ),
        None => (
            encode_persistent_root_set(roots).map_err(GcError::from)?,
            METADATA_KIND_ROOT_SET,
        ),
    };
    let allocation_bytes =
        encode_allocation_v2(&plan.relocation_allocation).map_err(GcError::from)?;

    // Table widths are frozen; physical pointer values cannot affect length.
    let snapshot_len = cas_snapshot_len(mark.live_objects().len(), mark.live_blobs().len())?;
    let required = required_gc_segments(
        manifests,
        manifest_lens,
        &plan.sources,
        snapshot_len,
        root_bytes.len(),
        allocation_bytes.len(),
    )?;
    if required != plan.targets.len() {
        return Err(GcError::InvalidSegmentSet.into());
    }

    let mut builder = SegmentBuilder::begin(
        device,
        state,
        plan.relocation_generation,
        plan.targets.clone(),
    )
    .await?;
    let mut relocated = Vec::new();
    relocated
        .try_reserve_exact(manifests.len())
        .map_err(|_| GcError::MemoryLimit)?;
    let mut copied_bytes = 0_u64;
    for manifest in manifests {
        let mut new_extents = Vec::new();
        new_extents
            .try_reserve_exact(manifest.extents.len())
            .map_err(|_| GcError::MemoryLimit)?;
        for declared in &manifest.extents {
            if !source_contains(&plan.sources, declared.pointer) {
                new_extents.push(*declared);
                continue;
            }
            let payload = read_pointer_payload(
                device,
                state.superblock.binding.store_uuid,
                state.admitted_segments,
                state.next_segment_generation,
                state.generation,
                declared.pointer,
                ExtentKind::Blob,
                usize::try_from(declared.payload_byte_len).map_err(|_| GcError::MemoryLimit)?,
            )
            .await?;
            let bytes = payload.bytes;
            let pointer = builder
                .payload(
                    device,
                    ExtentKind::Blob,
                    manifest.blob_key.object_kind(),
                    declared.extent_index,
                    declared.extent_count,
                    manifest.blob_key.exact_len(),
                    manifest.encoded_blob_len,
                    declared.encoded_offset,
                    manifest.blob_key.merkle_root(),
                    &bytes,
                )
                .await?;
            copied_bytes = copied_bytes
                .checked_add(bytes.len() as u64)
                .ok_or(GcError::ArithmeticOverflow)?;
            new_extents.push(ManifestExtent {
                extent_index: declared.extent_index,
                extent_count: declared.extent_count,
                encoded_offset: declared.encoded_offset,
                payload_byte_len: declared.payload_byte_len,
                pointer,
            });
        }
        let new_manifest = BlobManifest {
            blob_key: manifest.blob_key,
            encoded_blob_len: manifest.encoded_blob_len,
            extents: new_extents,
        };
        let bytes = encode_blob_manifest(&new_manifest, context)
            .map_err(|_| GcError::CorruptAt("relocate-manifest-encode"))?;
        let pointer = builder
            .payload(
                device,
                ExtentKind::Catalog,
                METADATA_KIND_MANIFEST,
                0,
                1,
                bytes.len() as u64,
                bytes.len() as u64,
                0,
                payload_sha256(&bytes),
                &bytes,
            )
            .await?;
        relocated.push(RelocatedBlob {
            blob_key: manifest.blob_key,
            manifest: pointer,
            copied_bytes: manifest.encoded_blob_len,
        });
    }
    let snapshot = build_relocated_snapshot(
        plan.relocation_generation,
        &cas.objects,
        &cas.blobs,
        mark,
        &relocated,
    )?;
    let snapshot_bytes = encode_cas_snapshot(&snapshot, context)
        .map_err(|_| GcError::CorruptAt("relocate-snapshot-encode"))?;
    let catalog_root = builder
        .payload(
            device,
            ExtentKind::Catalog,
            METADATA_KIND_CAS_SNAPSHOT,
            0,
            1,
            snapshot_bytes.len() as u64,
            snapshot_bytes.len() as u64,
            0,
            payload_sha256(&snapshot_bytes),
            &snapshot_bytes,
        )
        .await?;
    let authority_root = builder
        .payload(
            device,
            ExtentKind::Authority,
            root_kind,
            0,
            1,
            root_bytes.len() as u64,
            root_bytes.len() as u64,
            0,
            payload_sha256(&root_bytes),
            &root_bytes,
        )
        .await?;
    let allocation_root = builder
        .payload(
            device,
            ExtentKind::Allocation,
            METADATA_KIND_ALLOCATION,
            0,
            1,
            allocation_bytes.len() as u64,
            allocation_bytes.len() as u64,
            0,
            payload_sha256(&allocation_bytes),
            &allocation_bytes,
        )
        .await?;
    let last = builder.finish(device).await?;

    // A sealed target is still only staged data. Cold-read every checkpoint
    // root and stream-verify each copied Blob before G+1 can make the targets
    // authoritative. This catches acknowledged-but-corrupted device writes
    // while the old source segments are still the selected truth.
    verify_staged_payload(
        device,
        state,
        plan.relocation_generation,
        target_next_generation,
        catalog_root,
        ExtentKind::Catalog,
        &snapshot_bytes,
        limits.recovery_memory_bytes,
    )
    .await?;
    verify_staged_payload(
        device,
        state,
        plan.relocation_generation,
        target_next_generation,
        authority_root,
        ExtentKind::Authority,
        &root_bytes,
        limits.recovery_memory_bytes,
    )
    .await?;
    verify_staged_payload(
        device,
        state,
        plan.relocation_generation,
        target_next_generation,
        allocation_root,
        ExtentKind::Allocation,
        &allocation_bytes,
        limits.recovery_memory_bytes,
    )
    .await?;
    let mut staged_state = state.clone();
    staged_state.generation = plan.relocation_generation;
    staged_state.next_segment_generation = target_next_generation;
    for mapping in &snapshot.blobs {
        let manifest_payload = read_pointer_payload(
            device,
            state.superblock.binding.store_uuid,
            state.admitted_segments,
            target_next_generation,
            plan.relocation_generation,
            mapping.manifest,
            ExtentKind::Catalog,
            limits.recovery_memory_bytes,
        )
        .await?;
        let manifest = decode_blob_manifest(&manifest_payload.bytes, context)
            .map_err(|_| GcError::CorruptAt("relocate-manifest-readback"))?;
        if manifest.blob_key != mapping.blob_key {
            return Err(GcError::CorruptAt("relocate-manifest-key").into());
        }
        drop(manifest_payload);
        for extent in &manifest.extents {
            if source_contains(&plan.targets, extent.pointer) {
                verify_staged_copied_extent(
                    device,
                    state,
                    plan.relocation_generation,
                    target_next_generation,
                    extent,
                )
                .await?;
            }
        }
        verify_manifest_blob(device, &staged_state, &manifest)
            .await
            .map_err(|error| match error {
                CasStoreError::Store(error) => GcStoreError::Store(error),
                _ => GcStoreError::Gc(GcError::CorruptAt("relocate-blob-readback")),
            })?;
    }
    let metadata_bytes = manifest_lens.iter().try_fold(
        snapshot_bytes
            .len()
            .checked_add(root_bytes.len())
            .and_then(|bytes| bytes.checked_add(allocation_bytes.len()))
            .ok_or(GcError::ArithmeticOverflow)?,
        |total, manifest_len| {
            total
                .checked_add(*manifest_len)
                .ok_or(GcError::ArithmeticOverflow)
        },
    )? as u64;
    let telemetry = GcTelemetry {
        epoch_generation: state.generation,
        root_count: u32::try_from(root_count).unwrap_or(u32::MAX),
        live_object_count: u32::try_from(snapshot.objects.len()).unwrap_or(u32::MAX),
        live_blob_count: u32::try_from(snapshot.blobs.len()).unwrap_or(u32::MAX),
        copied_bytes,
        reclaimed_bytes: plan.sources.len() as u64
            * vibeos_segment_format::SEGMENT_PAGES
            * PAGE_SIZE as u64,
        metadata_bytes,
        reserve_pressure_ppm: u32::try_from(
            (plan.targets.len() as u64 + 1).saturating_mul(1_000_000)
                / u64::from(state.cleaner_reserve_segments),
        )
        .unwrap_or(u32::MAX),
        ..GcTelemetry::default()
    };
    Ok((
        catalog_root,
        authority_root,
        allocation_root,
        last.2,
        telemetry,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish_checkpoint<D: PageDevice>(
    device: &D,
    state: &MountedState,
    limits: StoreLimits,
    generation: u64,
    next_segment_generation: u64,
    catalog_root: PhysicalPointer,
    authority_root: PhysicalPointer,
    allocation_root: PhysicalPointer,
) -> Result<Checkpoint, GcStoreError<D::Error>> {
    let slot = ((generation - 1) & 1) as u8;
    let checkpoint = Checkpoint {
        binding: RecordBinding {
            store_uuid: state.superblock.binding.store_uuid,
            generation,
            segment_no: ANCHOR_SEGMENT_NO,
            ordinal: u32::from(slot),
            self_page: 4 + u64::from(slot) * 2,
            target_checkpoint_generation: generation,
        },
        slot,
        previous_generation: generation - 1,
        admitted_range_pages: admitted_pages(state.admitted_segments)
            .map_err(StoreError::Format)?,
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
    Ok(checkpoint)
}

async fn clear_old_checkpoint_seal<D: PageDevice>(
    device: &D,
    generation: u64,
) -> Result<ExactZeroCheckpointSeal, GcStoreError<D::Error>> {
    let slot = (generation - 1) & 1;
    let seal_page = 5 + slot * 2;
    let zero = heap_page();
    write_page(device, seal_page, &zero).await?;
    flush(device).await?;
    let mut observed = heap_page();
    device
        .read_page(seal_page, &mut observed)
        .await
        .map_err(StoreError::Device)?;
    ExactZeroCheckpointSeal::from_readback(&observed).map_err(Into::into)
}

/// Persist an exact GC root policy from already-authorized witnesses. A null
/// authority pointer remains "unsynchronized"; this API writes even an empty
/// canonical root payload and upgrades the allocation map to v2.
impl<D: PageDevice> SegmentStore<D> {
    async fn resume_retired_reuse(
        &mut self,
        state: MountedState,
        mut memory: GcMemoryAccount,
    ) -> Result<GcTelemetry, GcStoreError<D::Error>> {
        let state_bytes = mounted_state_heap_bytes(&state)?;
        let relocation_generation = state.generation;
        let epoch_generation = relocation_generation
            .checked_sub(1)
            .ok_or(GcError::InvalidGeneration)?;
        let retired = state.allocation.retired_segments();
        if retired.is_empty()
            || retired
                .iter()
                .any(|entry| entry.retire_generation != relocation_generation)
        {
            return Err(GcError::Corrupt.into());
        }
        if !self.pins.is_quiescent_through(epoch_generation) {
            return Err(GcError::ReaderStillPinned.into());
        }
        let mut sources = Vec::new();
        memory.transient(vector_bytes(retired.len(), core::mem::size_of::<u64>())?)?;
        sources
            .try_reserve_exact(retired.len())
            .map_err(|_| GcError::MemoryLimit)?;
        sources.extend(retired.iter().map(|entry| entry.segment_no));
        memory.retain(vector_bytes(
            sources.capacity(),
            core::mem::size_of::<u64>(),
        )?)?;
        memory.transient(core::mem::size_of::<u64>())?;
        let barrier = select_free_segments(&state.allocation, 1)?;
        memory.retain(vector_bytes(
            barrier.capacity(),
            core::mem::size_of::<u64>(),
        )?)?;
        let reuse_generation = relocation_generation
            .checked_add(1)
            .ok_or(GcError::InvalidGeneration)?;
        let next_segment_generation = state
            .next_segment_generation
            .checked_add(1)
            .ok_or(GcError::ArithmeticOverflow)?;
        memory.transient(state.allocation.packed_bitmap().len())?;
        let reuse_allocation = state
            .allocation
            .apply_transition(AllocationTransition {
                checkpoint_generation: reuse_generation,
                next_segment_generation,
                allocate: &barrier,
                retire: &[],
                reclaim: &sources,
            })
            .map_err(GcError::from)?;
        memory.retain(
            reuse_allocation
                .allocated_bytes()
                .ok_or(GcError::ArithmeticOverflow)?,
        )?;
        let allocation_len = crate::allocation_v2::ALLOCATION_V2_HEADER_LEN
            .checked_add(reuse_allocation.packed_bitmap().len())
            .ok_or(GcError::ArithmeticOverflow)?;
        memory.transient(
            allocation_len
                .checked_mul(2)
                .ok_or(GcError::ArithmeticOverflow)?,
        )?;
        let allocation_bytes = encode_allocation_v2(&reuse_allocation).map_err(GcError::from)?;
        memory.retain(allocation_bytes.capacity())?;
        let cas = state.cas.as_ref().ok_or(GcError::NotCas)?;
        let live_object_count = u32::try_from(cas.objects.len()).unwrap_or(u32::MAX);
        let live_blob_count = u32::try_from(cas.blobs.len()).unwrap_or(u32::MAX);
        let cleaner_reserve_segments = state.cleaner_reserve_segments;
        let root_count = state
            .persistent_roots
            .as_ref()
            .ok_or(GcError::MissingPersistentRootPolicy)?
            .entries()
            .len();

        // A cold mount of G+1 reaches this path. No source becomes writable
        // until the exact old G seal is gone and this G+2 map is sealed.
        self.mounted = None;
        self.poisoned = true;
        memory.release(state_bytes)?;
        let zero = clear_old_checkpoint_seal(&self.device, epoch_generation).await?;
        let _ = zero;
        let mut builder =
            SegmentBuilder::begin(&self.device, &state, reuse_generation, barrier).await?;
        let allocation_root = builder
            .payload(
                &self.device,
                ExtentKind::Allocation,
                METADATA_KIND_ALLOCATION,
                0,
                1,
                allocation_bytes.len() as u64,
                allocation_bytes.len() as u64,
                0,
                payload_sha256(&allocation_bytes),
                &allocation_bytes,
            )
            .await?;
        builder.finish(&self.device).await?;
        verify_staged_payload(
            &self.device,
            &state,
            reuse_generation,
            next_segment_generation,
            allocation_root,
            ExtentKind::Allocation,
            &allocation_bytes,
            self.limits.recovery_memory_bytes,
        )
        .await?;
        publish_checkpoint(
            &self.device,
            &state,
            self.limits,
            reuse_generation,
            next_segment_generation,
            state.catalog_root,
            state.authority_root,
            allocation_root,
        )
        .await?;
        let source_count = sources.len();
        let memory_high_water_bytes = memory.peak;
        drop(allocation_bytes);
        drop(reuse_allocation);
        drop(sources);
        drop(state);
        self.mount().await?;
        Ok(GcTelemetry {
            epoch_generation,
            relocation_generation,
            reuse_generation,
            root_count: u32::try_from(root_count).unwrap_or(u32::MAX),
            live_object_count,
            live_blob_count,
            reclaimed_bytes: source_count as u64
                * vibeos_segment_format::SEGMENT_PAGES
                * PAGE_SIZE as u64,
            metadata_bytes: allocation_len as u64,
            retired_segments: source_count as u32,
            reclaimed_segments: source_count as u32,
            target_segments: 1,
            quiescence_scans: 1,
            memory_high_water_bytes,
            reserve_pressure_ppm: u32::try_from(
                1_000_000_u64 / u64::from(cleaner_reserve_segments),
            )
            .unwrap_or(u32::MAX),
            foreground_cycles: 1,
            ..GcTelemetry::default()
        })
    }

    pub async fn synchronize_gc_roots(
        &mut self,
        roots: &[&AuthorizedObject<CasObjectHandle>],
    ) -> Result<(), GcStoreError<D::Error>> {
        // VIBEAUT2 is the sole durable owner of both the root closure and its
        // logical authority/quota policy. Replacing it with a bare VIBERST2
        // payload would silently discard that policy.
        if self
            .require_current_generation()?
            .persistent_authority
            .is_some()
        {
            return Err(GcError::InvalidPhase.into());
        }
        if roots
            .iter()
            .any(|root| root.backend_handle().is_quota_charged())
        {
            return Err(GcError::QuotaPersistenceUnavailable.into());
        }
        let mut memory = GcMemoryAccount::new(self.limits.recovery_memory_bytes);
        let state_bytes = mounted_state_heap_bytes(self.require_current_generation()?)?;
        let cloned_states = state_bytes
            .checked_mul(2)
            .ok_or(GcError::ArithmeticOverflow)?;
        memory.transient(cloned_states)?;
        let state = self.require_current_generation()?.clone();
        memory.retain(cloned_states)?;
        if !state.allocation.retired_segments().is_empty() {
            return Err(StoreError::GcResumeRequired.into());
        }
        let cas = state.cas.as_ref().ok_or(GcError::NotCas)?;
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(GcError::InvalidGeneration)?;
        let mut witnesses = Vec::new();
        memory.transient(vector_bytes(roots.len(), core::mem::size_of::<RootKey>())?)?;
        witnesses
            .try_reserve_exact(roots.len())
            .map_err(|_| GcError::MemoryLimit)?;
        memory.retain(vector_bytes(
            witnesses.capacity(),
            core::mem::size_of::<RootKey>(),
        )?)?;
        for root in roots {
            let handle = root.backend_handle();
            if handle.store_uuid() != state.superblock.binding.store_uuid
                || handle.object_kind() != root.object_kind()
                || handle.exact_len() != root.exact_len()
            {
                return Err(GcError::RootDoesNotResolve.into());
            }
            witnesses.push(handle.root_key(&self.pins).map_err(GcError::from)?);
        }
        memory.transient(vector_bytes(
            witnesses.len(),
            core::mem::size_of::<PersistentRootEntry>(),
        )?)?;
        let persistent = build_persistent_root_set(generation, &witnesses, &cas.objects)?;
        let persistent_bytes = persistent
            .allocated_bytes()
            .ok_or(GcError::ArithmeticOverflow)?;
        memory.retain(persistent_bytes)?;
        let root_len = persistent_root_encoded_len(&persistent)?;
        memory.transient(root_len)?;
        let root_bytes = encode_persistent_root_set(&persistent).map_err(GcError::from)?;
        memory.retain(root_bytes.capacity())?;

        memory.transient(core::mem::size_of::<u64>())?;
        let free = select_free_segments(&state.allocation, 1)?;
        memory.retain(vector_bytes(free.capacity(), core::mem::size_of::<u64>())?)?;
        let next_segment_generation = state
            .next_segment_generation
            .checked_add(1)
            .ok_or(GcError::ArithmeticOverflow)?;
        // apply_transition clones the packed bitmap and rebuilds the retired
        // table. Prove that allocation before asking Vec to reserve it.
        let transition_allocation_bound = state
            .allocation
            .packed_bitmap()
            .len()
            .checked_add(
                state
                    .allocation
                    .retired_segments()
                    .len()
                    .checked_mul(core::mem::size_of::<crate::allocation_v2::RetiredSegment>())
                    .ok_or(GcError::ArithmeticOverflow)?,
            )
            .ok_or(GcError::ArithmeticOverflow)?;
        memory.transient(transition_allocation_bound)?;
        let allocation = state
            .allocation
            .apply_transition(AllocationTransition {
                checkpoint_generation: generation,
                next_segment_generation,
                allocate: &free,
                retire: &[],
                reclaim: &[],
            })
            .map_err(GcError::from)?;
        let allocation_resident = allocation
            .allocated_bytes()
            .ok_or(GcError::ArithmeticOverflow)?;
        memory.retain(allocation_resident)?;
        let allocation_len = crate::allocation_v2::ALLOCATION_V2_HEADER_LEN
            .checked_add(allocation.packed_bitmap().len())
            .and_then(|bytes| {
                allocation
                    .retired_segments()
                    .len()
                    .checked_mul(crate::allocation_v2::RETIRED_SEGMENT_ENTRY_LEN)
                    .and_then(|more| bytes.checked_add(more))
            })
            .ok_or(GcError::ArithmeticOverflow)?;
        memory.transient(allocation_len)?;
        let allocation_bytes = encode_allocation_v2(&allocation).map_err(GcError::from)?;
        memory.retain(allocation_bytes.capacity())?;

        // Publishing a checkpoint that the configured ceiling cannot remount
        // would turn a successful root-policy update into a durable denial of
        // service. Conservatively prove both operation heap and the subsequent
        // dual-checkpoint recovery before the first media mutation.
        let old_allocation = state
            .allocation
            .allocated_bytes()
            .ok_or(GcError::ArithmeticOverflow)?;
        let recovery_bound = state
            .recovery_peak_bytes
            .checked_add(old_allocation)
            .and_then(|bytes| bytes.checked_add(allocation_resident))
            .and_then(|bytes| bytes.checked_add(persistent_bytes))
            .and_then(|bytes| bytes.checked_add(root_bytes.capacity()))
            .and_then(|bytes| bytes.checked_add(allocation_bytes.capacity()))
            .ok_or(GcError::ArithmeticOverflow)?;
        if recovery_bound > self.limits.recovery_memory_bytes {
            return Err(GcError::MemoryLimit.into());
        }
        memory.transient(root_bytes.capacity().max(allocation_bytes.capacity()))?;
        // From the first media mutation onward, cached cursors are poisoned.
        // Any error requires mount() to select a sealed checkpoint again.
        self.mounted = None;
        self.poisoned = true;
        let mut builder = SegmentBuilder::begin(&self.device, &state, generation, free).await?;
        let authority_root = builder
            .payload(
                &self.device,
                ExtentKind::Authority,
                METADATA_KIND_ROOT_SET,
                0,
                1,
                root_bytes.len() as u64,
                root_bytes.len() as u64,
                0,
                payload_sha256(&root_bytes),
                &root_bytes,
            )
            .await?;
        let allocation_root = builder
            .payload(
                &self.device,
                ExtentKind::Allocation,
                METADATA_KIND_ALLOCATION,
                0,
                1,
                allocation_bytes.len() as u64,
                allocation_bytes.len() as u64,
                0,
                payload_sha256(&allocation_bytes),
                &allocation_bytes,
            )
            .await?;
        builder.finish(&self.device).await?;
        verify_staged_payload(
            &self.device,
            &state,
            generation,
            next_segment_generation,
            authority_root,
            ExtentKind::Authority,
            &root_bytes,
            self.limits.recovery_memory_bytes,
        )
        .await?;
        verify_staged_payload(
            &self.device,
            &state,
            generation,
            next_segment_generation,
            allocation_root,
            ExtentKind::Allocation,
            &allocation_bytes,
            self.limits.recovery_memory_bytes,
        )
        .await?;
        publish_checkpoint(
            &self.device,
            &state,
            self.limits,
            generation,
            next_segment_generation,
            state.catalog_root,
            authority_root,
            allocation_root,
        )
        .await?;
        drop(root_bytes);
        drop(allocation_bytes);
        drop(allocation);
        drop(persistent);
        drop(witnesses);
        drop(state);
        self.mount().await?;
        Ok(())
    }

    /// Measure one collection using a caller-owned monotonic clock. A clock
    /// rollback saturates the duration to zero and can never fail collection.
    pub async fn collect_garbage_timed<C: GcTimeSource>(
        &mut self,
        clock: &C,
    ) -> Result<GcTelemetry, GcStoreError<D::Error>> {
        let start = clock.monotonic_ns();
        let mut telemetry = self.collect_garbage().await?;
        telemetry.foreground_pause_ns = elapsed_ns(start, clock.monotonic_ns());
        telemetry.pause_time_measured = true;
        Ok(telemetry)
    }

    /// Deterministic low-live-ratio compaction. The collector grows a ranked
    /// source prefix until target data plus the G+2 barrier fit the cleaner
    /// reserve and yield a net segment reclamation. If needed the prefix grows
    /// to every allocated segment, preserving the full-compaction fallback.
    pub async fn collect_garbage(&mut self) -> Result<GcTelemetry, GcStoreError<D::Error>> {
        self.collect_garbage_with_policy(None).await
    }

    /// Bootstrap the first persistent GC root policy while collecting a legal
    /// pre-M7.5 CAS image whose checkpoint has a Null authority root.
    ///
    /// Every witness must already be an [`AuthorizedObject`] issued by this
    /// exact runtime context. The store resolves each opaque handle against the
    /// selected CAS catalog before any media mutation; an ObjectId or BlobKey
    /// read from media can therefore never mint authority. The canonical root
    /// set is written inside the same `G + 1` relocation as the CAS snapshot
    /// and allocation-v2 map, so this path needs no preliminary metadata
    /// segment or ordinary-allocation headroom.
    ///
    /// This entry point is accepted only while the selected checkpoint has a
    /// Null authority root. Once `G + 1` is durable, ordinary
    /// [`Self::collect_garbage`] resumes or performs subsequent cycles.
    pub async fn collect_garbage_with_initial_roots(
        &mut self,
        roots: &[&AuthorizedObject<CasObjectHandle>],
    ) -> Result<GcTelemetry, GcStoreError<D::Error>> {
        if roots
            .iter()
            .any(|root| root.backend_handle().is_quota_charged())
        {
            return Err(GcError::QuotaPersistenceUnavailable.into());
        }
        self.collect_garbage_with_policy(Some(roots)).await
    }

    async fn collect_garbage_with_policy(
        &mut self,
        initial_roots: Option<&[&AuthorizedObject<CasObjectHandle>]>,
    ) -> Result<GcTelemetry, GcStoreError<D::Error>> {
        let mut memory = GcMemoryAccount::new(self.limits.recovery_memory_bytes);
        let state_bytes = mounted_state_heap_bytes(self.require_current_generation()?)?;
        let two_states = state_bytes
            .checked_mul(2)
            .ok_or(GcError::ArithmeticOverflow)?;
        // Prove room for the clone before Clone performs any allocation.
        memory.transient(two_states)?;
        let state = self.require_current_generation()?.clone();
        memory.retain(two_states)?;
        // Generation is the frozen-format durable ObjectId high-water. A
        // production store mounts with next_object_id == generation; a catalog
        // imported with larger IDs remains readable/writable but cannot be
        // destructively filtered until a future format carries its high-water.
        if !generation_covers_object_id_high_water(state.generation, state.next_object_id) {
            return Err(GcError::ObjectIdHighWaterUnavailable.into());
        }
        // Relocation always needs at least one G+1 target and one distinct
        // G+2 barrier segment. Historical reserve-one images remain fully
        // mountable/readable, but cannot safely enter this protocol.
        if state.cleaner_reserve_segments < 2 {
            return Err(GcError::Capacity.into());
        }
        if initial_roots.is_some()
            && (state.authority_root != PhysicalPointer::Null || state.persistent_roots.is_some())
        {
            return Err(GcError::InvalidPhase.into());
        }
        if !state.allocation.retired_segments().is_empty() {
            return self.resume_retired_reuse(state, memory).await;
        }
        let cas = state.cas.as_ref().ok_or(GcError::NotCas)?;
        let relocation_generation = state
            .generation
            .checked_add(1)
            .ok_or(GcError::InvalidGeneration)?;
        let mut initial_policy = None;
        if let Some(initial_roots) = initial_roots {
            if initial_roots.len() > self.limits.max_catalog_entries as usize {
                return Err(GcError::MemoryLimit.into());
            }
            let witness_bound = vector_bytes(initial_roots.len(), core::mem::size_of::<RootKey>())?;
            memory.transient(witness_bound)?;
            let mut witnesses = Vec::new();
            witnesses
                .try_reserve_exact(initial_roots.len())
                .map_err(|_| GcError::MemoryLimit)?;
            let witness_bytes =
                vector_bytes(witnesses.capacity(), core::mem::size_of::<RootKey>())?;
            memory.retain(witness_bytes)?;
            for root in initial_roots {
                let handle = root.backend_handle();
                if handle.store_uuid() != state.superblock.binding.store_uuid
                    || handle.object_kind() != root.object_kind()
                    || handle.exact_len() != root.exact_len()
                {
                    return Err(GcError::RootDoesNotResolve.into());
                }
                witnesses.push(handle.root_key(&self.pins).map_err(GcError::from)?);
            }
            memory.transient(vector_bytes(
                witnesses.len(),
                core::mem::size_of::<PersistentRootEntry>(),
            )?)?;
            let policy =
                build_persistent_root_set(relocation_generation, &witnesses, &cas.objects)?;
            memory.retain(
                policy
                    .allocated_bytes()
                    .ok_or(GcError::ArithmeticOverflow)?,
            )?;
            memory.release(witness_bytes)?;
            drop(witnesses);
            initial_policy = Some(policy);
        }
        let maximum_roots = (self.limits.max_catalog_entries as usize)
            .checked_add(ROOT_PIN_SLOTS)
            .ok_or(GcError::ArithmeticOverflow)?;
        let selected_policy = state.persistent_roots.as_ref().or(initial_policy.as_ref());
        let roots = capture_mark_roots(
            selected_policy,
            self.pins.as_ref(),
            maximum_roots,
            self.limits
                .recovery_memory_bytes
                .checked_sub(memory.current)
                .ok_or(GcError::MemoryLimit)?,
        )?;
        let roots_bytes = vector_bytes(roots.capacity(), core::mem::size_of::<MarkRoot>())?;
        memory.retain(roots_bytes)?;
        memory.transient(vector_bytes(
            ROOT_PIN_SLOTS,
            core::mem::size_of::<RuntimeRoot>(),
        )?)?;
        let decode_base = memory.current;
        let typed = decode_typed_children(
            &self.device,
            &state,
            StoreLimits {
                recovery_memory_bytes: self
                    .limits
                    .recovery_memory_bytes
                    .checked_sub(decode_base)
                    .ok_or(GcError::MemoryLimit)?,
                ..self.limits
            },
            &roots,
            &self.typed_reference_kinds,
        )
        .await?;
        memory.transient(typed.peak_bytes)?;
        memory.retain(typed.allocated_bytes)?;
        let budget = MarkBudget::new(
            self.limits.max_catalog_entries as usize,
            self.limits.max_catalog_entries as usize,
            GC_CHILD_BUDGET,
            maximum_roots,
        );
        let planned_mark_bytes = (self.limits.max_catalog_entries as usize)
            .checked_mul(core::mem::size_of::<RootKey>() * 2 + core::mem::size_of::<BlobKey>())
            .and_then(|bytes| {
                GC_CHILD_BUDGET
                    .checked_mul(core::mem::size_of::<ChildReference>())
                    .and_then(|more| bytes.checked_add(more))
            })
            .ok_or(GcError::ArithmeticOverflow)?;
        memory.transient(planned_mark_bytes)?;
        let mut planner = MarkPlanner::new(budget).map_err(|_| GcError::MemoryLimit)?;
        let mut mark =
            MarkPlan::with_budget(state.generation, budget).map_err(|_| GcError::MemoryLimit)?;
        memory.retain(
            planner
                .allocated_bytes()
                .ok_or(GcError::ArithmeticOverflow)?,
        )?;
        memory.retain(mark.allocated_bytes().ok_or(GcError::ArithmeticOverflow)?)?;
        planner
            .mark(
                CatalogView {
                    checkpoint_generation: state.generation,
                    objects: &cas.objects,
                    blobs: &cas.blobs,
                },
                &roots,
                &typed,
                &mut mark,
            )
            .map_err(|_| GcError::CorruptAt("mark"))?;
        let planner_bytes = planner
            .allocated_bytes()
            .ok_or(GcError::ArithmeticOverflow)?;
        memory.release(planner_bytes)?;
        drop(planner);
        memory.release(typed.allocated_bytes)?;
        drop(typed);
        let manifests =
            load_live_manifests(&self.device, &state, self.limits, &mark, memory.current)
                .await
                .map_err(|error| match error {
                    GcStoreError::Gc(GcError::Corrupt) => {
                        GcStoreError::Gc(GcError::CorruptAt("load-manifests"))
                    }
                    other => other,
                })?;
        memory.retain(manifest_table_bytes(&manifests)?)?;
        let relocated_roots = if let Some(policy) = initial_policy.take() {
            policy
        } else {
            let persistent = state
                .persistent_roots
                .as_ref()
                .ok_or(GcError::MissingPersistentRootPolicy)?;
            let root_clone_bytes = vector_bytes(
                persistent.entries().len(),
                core::mem::size_of::<PersistentRootEntry>(),
            )?;
            memory.transient(root_clone_bytes)?;
            let roots =
                PersistentRootSet::new(relocation_generation, persistent.entries().to_vec())
                    .map_err(GcError::from)?;
            memory.retain(roots.allocated_bytes().ok_or(GcError::ArithmeticOverflow)?)?;
            roots
        };
        let manifest_lens_bytes = vector_bytes(manifests.len(), core::mem::size_of::<usize>())?;
        memory.transient(manifest_lens_bytes)?;
        let mut manifest_lens = Vec::new();
        manifest_lens
            .try_reserve_exact(manifests.len())
            .map_err(|_| GcError::MemoryLimit)?;
        for manifest in &manifests {
            manifest_lens.push(blob_manifest_encoded_len(manifest)?);
        }
        let manifest_lens_bytes =
            vector_bytes(manifest_lens.capacity(), core::mem::size_of::<usize>())?;
        memory.retain(manifest_lens_bytes)?;
        let root_len = match state.persistent_authority.as_ref() {
            Some(authority) => {
                let relocated = authority
                    .relocated(relocation_generation)
                    .map_err(GcError::from)?;
                encode_persistent_authority_snapshot(&relocated)
                    .map_err(GcError::from)?
                    .len()
            }
            None => persistent_root_encoded_len(&relocated_roots)?,
        };
        // Exact snapshot length from table counts.
        let snapshot_len = cas_snapshot_len(mark.live_objects().len(), mark.live_blobs().len())?;
        // Rank equal-capacity segments by authoritative live extent bytes.
        // Grow the low-live prefix until relocation plus its G+2 barrier both
        // fit the cleaner reserve and reclaim more segments than they consume.
        // Reaching the complete prefix is the conservative full-compaction
        // fallback; no write occurs before a yielding prefix is found.
        let allocated_count =
            usize::try_from(state.allocation.counts().map_err(GcError::from)?.allocated)
                .map_err(|_| GcError::MemoryLimit)?;
        let ranking_bytes = vector_bytes(allocated_count, core::mem::size_of::<(u64, u64)>())?;
        memory.transient(ranking_bytes)?;
        let ranked_sources = ranked_gc_sources(&state.allocation, &manifests)?;
        let ranking_bytes = vector_bytes(
            ranked_sources.capacity(),
            core::mem::size_of::<(u64, u64)>(),
        )?;
        memory.retain(ranking_bytes)?;
        // One preallocated numeric candidate coexists with the ranking table;
        // no collect/map conversion may create an unaccounted second buffer.
        let candidate_bound = vector_bytes(ranked_sources.len(), core::mem::size_of::<u64>())?;
        memory.transient(candidate_bound)?;
        let mut candidate = Vec::new();
        candidate
            .try_reserve_exact(ranked_sources.len())
            .map_err(|_| GcError::MemoryLimit)?;
        let candidate_bytes = vector_bytes(candidate.capacity(), core::mem::size_of::<u64>())?;
        memory.retain(candidate_bytes)?;
        let mut selected = None;
        for prefix_len in 1..=ranked_sources.len() {
            validate_gc_source_budget(
                &state.allocation,
                prefix_len,
                self.limits.recovery_memory_bytes,
            )?;
            let segment_no = ranked_sources[prefix_len - 1].1;
            let insertion = candidate
                .binary_search(&segment_no)
                .unwrap_or_else(|index| index);
            candidate.insert(insertion, segment_no);
            let allocation_len = crate::allocation_v2::ALLOCATION_V2_HEADER_LEN
                .checked_add(state.allocation.packed_bitmap().len())
                .and_then(|bytes| {
                    candidate
                        .len()
                        .checked_mul(crate::allocation_v2::RETIRED_SEGMENT_ENTRY_LEN)
                        .and_then(|more| bytes.checked_add(more))
                })
                .ok_or(GcError::ArithmeticOverflow)?;
            let required = required_gc_segments(
                &manifests,
                &manifest_lens,
                &candidate,
                snapshot_len,
                root_len,
                allocation_len,
            )?;
            let reservation = required.checked_add(1).ok_or(GcError::ArithmeticOverflow)?;
            if candidate.len() > reservation
                && u64::try_from(reservation).map_err(|_| GcError::ArithmeticOverflow)?
                    <= u64::from(state.cleaner_reserve_segments)
            {
                let net = candidate.len() - reservation;
                // Prefer the best yielding strict partial prefix. The full-set
                // candidate is a fallback only when no partial prefix yields.
                if prefix_len < ranked_sources.len() {
                    if selected
                        .as_ref()
                        .is_none_or(|entry: &(usize, usize, usize, usize)| net > entry.0 - entry.3)
                    {
                        selected = Some((prefix_len, allocation_len, required, reservation));
                    }
                } else if selected.is_none() {
                    selected = Some((prefix_len, allocation_len, required, reservation));
                }
            }
        }
        let (selected_len, provisional_allocation_len, required, reservation) =
            selected.ok_or(GcError::Capacity)?;
        candidate.clear();
        candidate.extend(ranked_sources[..selected_len].iter().map(|entry| entry.1));
        candidate.sort_unstable();
        memory.release(ranking_bytes)?;
        drop(ranked_sources);
        let sources = candidate;
        memory.transient(vector_bytes(reservation, core::mem::size_of::<u64>())?)?;
        let free = select_free_segments(&state.allocation, reservation)?;
        memory.retain(vector_bytes(free.capacity(), core::mem::size_of::<u64>())?)?;
        memory.transient(vector_bytes(required, core::mem::size_of::<u64>())?)?;
        let targets = free[..required].to_vec();
        memory.retain(vector_bytes(
            targets.capacity(),
            core::mem::size_of::<u64>(),
        )?)?;
        let barrier_segment = free[required];
        let relocation_allocation_bound = state
            .allocation
            .packed_bitmap()
            .len()
            .checked_add(
                sources
                    .len()
                    .checked_mul(core::mem::size_of::<crate::allocation_v2::RetiredSegment>())
                    .ok_or(GcError::ArithmeticOverflow)?,
            )
            .ok_or(GcError::ArithmeticOverflow)?;
        let reuse_allocation_bound = state.allocation.packed_bitmap().len();
        memory.transient(
            relocation_allocation_bound
                .checked_add(reuse_allocation_bound)
                .ok_or(GcError::ArithmeticOverflow)?,
        )?;
        let plan = GcSegmentPlan::partial_compaction(
            &state.allocation,
            sources,
            targets,
            barrier_segment,
        )?;
        memory.release(vector_bytes(free.capacity(), core::mem::size_of::<u64>())?)?;
        drop(free);
        memory.retain(
            plan.relocation_allocation
                .allocated_bytes()
                .and_then(|bytes| {
                    plan.reuse_allocation
                        .allocated_bytes()
                        .and_then(|more| bytes.checked_add(more))
                })
                .ok_or(GcError::ArithmeticOverflow)?,
        )?;
        memory.transient(relocation_workspace_upper_bound(
            &state,
            &mark,
            &manifests,
            &manifest_lens,
            &plan,
            snapshot_len,
            root_len,
            provisional_allocation_len,
        )?)?;
        memory.transient(post_relocation_workspace_upper_bound(
            &state,
            &relocated_roots,
            &manifests,
            &manifest_lens,
            &plan,
            snapshot_len,
            root_len,
            provisional_allocation_len,
        )?)?;
        self.mounted = None;
        self.poisoned = true;
        memory.release(state_bytes)?;
        let (catalog_root, authority_root, allocation_root, _last_hash, telemetry) =
            relocate_live_state(
                &self.device,
                &state,
                self.limits,
                &mark,
                roots.len(),
                &relocated_roots,
                state.persistent_authority.as_ref(),
                &manifests,
                &manifest_lens,
                &plan,
            )
            .await
            .map_err(|error| match error {
                GcStoreError::Gc(GcError::Corrupt) => {
                    GcStoreError::Gc(GcError::CorruptAt("relocate"))
                }
                other => other,
            })?;
        let mut protocol = GcProtocol::begin(plan, telemetry)?;
        publish_checkpoint(
            &self.device,
            &state,
            self.limits,
            protocol.plan.relocation_generation,
            protocol.plan.relocation_allocation.next_segment_generation,
            catalog_root,
            authority_root,
            allocation_root,
        )
        .await?;
        self.mount().await?;
        protocol.relocation_published()?;
        protocol.observe_quiescence(self.pins.as_ref())?;
        let barrier_state = self.mounted.as_ref().ok_or(GcError::NotMounted)?.clone();
        self.mounted = None;
        self.poisoned = true;
        let zero = clear_old_checkpoint_seal(&self.device, state.generation).await?;
        protocol.old_checkpoint_cleared(zero)?;

        // G+2 has its own sealed allocation record. Catalog and authority
        // payloads remain the authenticated G+1 roots and are legal because
        // recovery accepts snapshot generation <= checkpoint generation.
        let allocation_bytes =
            encode_allocation_v2(&protocol.plan.reuse_allocation).map_err(GcError::from)?;
        protocol.telemetry.metadata_bytes = protocol
            .telemetry
            .metadata_bytes
            .saturating_add(allocation_bytes.len() as u64);
        let mut barrier = SegmentBuilder::begin(
            &self.device,
            &barrier_state,
            protocol.plan.reuse_generation,
            vec![protocol.plan.barrier_segment],
        )
        .await?;
        let reuse_allocation_root = barrier
            .payload(
                &self.device,
                ExtentKind::Allocation,
                METADATA_KIND_ALLOCATION,
                0,
                1,
                allocation_bytes.len() as u64,
                allocation_bytes.len() as u64,
                0,
                payload_sha256(&allocation_bytes),
                &allocation_bytes,
            )
            .await?;
        barrier.finish(&self.device).await?;
        verify_staged_payload(
            &self.device,
            &barrier_state,
            protocol.plan.reuse_generation,
            protocol.plan.reuse_allocation.next_segment_generation,
            reuse_allocation_root,
            ExtentKind::Allocation,
            &allocation_bytes,
            self.limits.recovery_memory_bytes,
        )
        .await?;
        publish_checkpoint(
            &self.device,
            &barrier_state,
            self.limits,
            protocol.plan.reuse_generation,
            protocol.plan.reuse_allocation.next_segment_generation,
            catalog_root,
            authority_root,
            reuse_allocation_root,
        )
        .await?;
        self.mount().await?;
        protocol.reuse_barrier_published()?;
        protocol.telemetry.memory_high_water_bytes = memory.peak;
        protocol.telemetry.foreground_cycles = 1;
        protocol.finish().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allocation_v2::SegmentAllocation;
    use crate::pins::{PinAdmission, RuntimeRootClass};
    use core::cell::Cell;

    fn selected() -> AllocationV2 {
        AllocationV2::new(
            9,
            30,
            2,
            &[
                SegmentAllocation::Allocated,
                SegmentAllocation::Allocated,
                SegmentAllocation::Allocated,
                SegmentAllocation::Free,
                SegmentAllocation::Free,
                SegmentAllocation::Free,
                SegmentAllocation::Free,
            ],
            &[],
        )
        .unwrap()
    }

    #[test]
    fn full_compaction_builds_retire_then_reuse_maps() {
        let plan =
            GcSegmentPlan::full_compaction(&selected(), vec![0, 1, 2], vec![3, 4], 5).unwrap();
        assert_eq!(plan.relocation_generation, 10);
        assert_eq!(plan.reuse_generation, 11);
        for source in [0, 1, 2] {
            assert_eq!(
                plan.relocation_allocation.segment_state(source),
                Some(SegmentAllocation::Retired)
            );
            assert_eq!(
                plan.reuse_allocation.segment_state(source),
                Some(SegmentAllocation::Free)
            );
        }
        for target in [3, 4] {
            assert_eq!(
                plan.reuse_allocation.segment_state(target),
                Some(SegmentAllocation::Allocated)
            );
        }
        assert_eq!(
            plan.reuse_allocation.segment_state(5),
            Some(SegmentAllocation::Allocated)
        );
    }

    #[test]
    fn partial_compaction_retires_only_selected_sources() {
        let plan = GcSegmentPlan::partial_compaction(&selected(), vec![0, 2], vec![3], 4).unwrap();
        assert_eq!(
            plan.relocation_allocation.segment_state(0),
            Some(SegmentAllocation::Retired)
        );
        assert_eq!(
            plan.relocation_allocation.segment_state(1),
            Some(SegmentAllocation::Allocated)
        );
        assert_eq!(
            plan.relocation_allocation.segment_state(2),
            Some(SegmentAllocation::Retired)
        );
        assert_eq!(
            plan.reuse_allocation.segment_state(0),
            Some(SegmentAllocation::Free)
        );
        assert_eq!(
            plan.reuse_allocation.segment_state(1),
            Some(SegmentAllocation::Allocated)
        );
    }

    #[test]
    fn selected_source_budget_uses_partial_count() {
        let one_source_bytes =
            3 * (core::mem::size_of::<(u64, u64)>() + core::mem::size_of::<u64>());
        assert_eq!(
            validate_gc_source_budget(&selected(), 1, one_source_bytes - 1),
            Err(GcError::MemoryLimit)
        );
        validate_gc_source_budget(&selected(), 1, one_source_bytes).unwrap();
        assert_eq!(
            validate_gc_source_budget(&selected(), 4, usize::MAX),
            Err(GcError::InvalidSegmentSet)
        );
    }

    #[test]
    fn checkpoint_generation_must_cover_gc_object_id_high_water() {
        assert!(generation_covers_object_id_high_water(9, 9));
        assert!(generation_covers_object_id_high_water(9, 8));
        assert!(!generation_covers_object_id_high_water(9, 10));
        assert!(!generation_covers_object_id_high_water(9, u128::MAX));
    }

    struct FakeClock {
        first: Cell<bool>,
        start: u64,
        end: u64,
    }

    impl GcTimeSource for FakeClock {
        fn monotonic_ns(&self) -> u64 {
            if self.first.replace(false) {
                self.start
            } else {
                self.end
            }
        }
    }

    #[test]
    fn pause_clock_rollback_saturates() {
        let clock = FakeClock {
            first: Cell::new(true),
            start: u64::MAX,
            end: 4,
        };
        assert_eq!(elapsed_ns(clock.monotonic_ns(), clock.monotonic_ns()), 0);
        assert_eq!(elapsed_ns(4, u64::MAX), u64::MAX - 4);
    }

    #[test]
    fn telemetry_cycle_merge_saturates_counters() {
        let mut total = GcTelemetry {
            copied_bytes: u64::MAX,
            reclaimed_segments: u32::MAX,
            foreground_cycles: u32::MAX,
            ..GcTelemetry::default()
        };
        total.saturating_merge_cycle(GcTelemetry {
            copied_bytes: 1,
            reclaimed_segments: 1,
            foreground_pause_ns: 9,
            pause_time_measured: true,
            ..GcTelemetry::default()
        });
        assert_eq!(total.copied_bytes, u64::MAX);
        assert_eq!(total.reclaimed_segments, u32::MAX);
        assert_eq!(total.foreground_cycles, u32::MAX);
        assert_eq!(total.foreground_pause_ns, 9);
        assert!(total.pause_time_measured);
    }

    #[test]
    fn protocol_forbids_reuse_until_reader_drops_and_old_seal_is_zero() {
        let plan =
            GcSegmentPlan::full_compaction(&selected(), vec![0, 1, 2], vec![3, 4], 5).unwrap();
        let pins = PinRegistry::<2, 2>::new(0, 0).unwrap();
        let owner = pins.allocate_owner().unwrap();
        let key = RootKey::new(1, 9, 7).unwrap();
        let reader = pins
            .pin_object_reader(key, 9, owner, PinAdmission::Ordinary)
            .unwrap()
            .finish_recheck(key, 9)
            .unwrap();
        let mut protocol = GcProtocol::begin(
            plan,
            GcTelemetry {
                epoch_generation: 9,
                ..GcTelemetry::default()
            },
        )
        .unwrap();
        protocol.relocation_published().unwrap();
        assert_eq!(
            protocol.observe_quiescence(&pins),
            Err(GcError::ReaderStillPinned)
        );
        drop(reader);
        protocol.observe_quiescence(&pins).unwrap();
        assert_eq!(
            ExactZeroCheckpointSeal::from_readback(&[1; PAGE_SIZE]),
            Err(GcError::OldCheckpointNotCleared)
        );
        let zero = ExactZeroCheckpointSeal::from_readback(&[0; PAGE_SIZE]).unwrap();
        protocol.old_checkpoint_cleared(zero).unwrap();
        protocol.reuse_barrier_published().unwrap();
        let telemetry = protocol.finish().unwrap();
        assert_eq!(telemetry.reclaimed_segments, 3);
        assert_eq!(telemetry.quiescence_scans, 2);
    }

    #[test]
    fn null_root_policy_is_not_an_empty_root_set() {
        let pins = PinRegistry::<2, 1>::new(0, 0).unwrap();
        assert_eq!(
            capture_mark_roots(None, &pins, 2, usize::MAX),
            Err(GcError::MissingPersistentRootPolicy)
        );
        let empty = PersistentRootSet::new(9, Vec::new()).unwrap();
        assert!(capture_mark_roots(Some(&empty), &pins, 2, usize::MAX)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn runtime_roots_are_union_not_persistent_policy_replacements() {
        let pins = PinRegistry::<2, 1>::new(0, 0).unwrap();
        let owner = pins.allocate_owner().unwrap();
        let key = RootKey::new(2, 8, 7).unwrap();
        let _pin = pins
            .pin_root(
                key,
                RuntimeRootClass::ObjectResource,
                owner,
                PinAdmission::Ordinary,
            )
            .unwrap();
        let policy = PersistentRootSet::new(
            9,
            vec![PersistentRootEntry {
                object_id: 1,
                commit_generation: 7,
                object_kind: 7,
            }],
        )
        .unwrap();
        let roots = capture_mark_roots(Some(&policy), &pins, 4, usize::MAX).unwrap();
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0].key.object_id(), 1);
        assert_eq!(roots[1].key.object_id(), 2);
    }

    fn packing_manifest_at(index: usize, payload_pages: u64, segment_no: u64) -> BlobManifest {
        let payload_byte_len = payload_pages * PAGE_SIZE as u64;
        BlobManifest {
            blob_key: BlobKey::sha256(7, payload_byte_len, [index as u8 + 1; 32]).unwrap(),
            encoded_blob_len: payload_byte_len,
            extents: vec![ManifestExtent {
                extent_index: 0,
                extent_count: 1,
                encoded_offset: 0,
                payload_byte_len,
                pointer: PhysicalPointer::Value(vibeos_segment_format::PointerValue {
                    store_uuid: StoreUuid::new(*b"gc-packing-test!").unwrap(),
                    segment_no,
                    segment_generation: 1,
                    descriptor_relative_page: 2,
                    payload_relative_page: 3,
                    payload_pages: payload_pages as u32,
                    ordinal: 1,
                    exact_byte_len: payload_byte_len,
                    extent_kind: ExtentKind::Blob,
                    payload_sha256: [0; 32],
                }),
            }],
        }
    }

    fn packing_manifest(index: usize, payload_pages: u64) -> BlobManifest {
        packing_manifest_at(index, payload_pages, 0)
    }

    #[test]
    fn source_ranking_is_live_bytes_then_segment_number() {
        let manifests = vec![packing_manifest_at(0, 2, 1), packing_manifest_at(1, 1, 0)];
        assert_eq!(
            ranked_gc_sources(&selected(), &manifests).unwrap(),
            vec![(0, 2), (PAGE_SIZE as u64, 0), (2 * PAGE_SIZE as u64, 1)]
        );
    }

    #[test]
    fn packing_counts_only_extents_in_selected_sources() {
        let manifests = vec![
            packing_manifest_at(0, 256, 0),
            packing_manifest_at(1, 256, 1),
            packing_manifest_at(2, 256, 0),
            packing_manifest_at(3, 256, 1),
        ];
        let manifest_lens = vec![PAGE_SIZE; manifests.len()];
        let partial = required_gc_segments(
            &manifests,
            &manifest_lens,
            &[0],
            PAGE_SIZE,
            PAGE_SIZE,
            PAGE_SIZE,
        )
        .unwrap();
        let full = required_gc_segments(
            &manifests,
            &manifest_lens,
            &[0, 1],
            PAGE_SIZE,
            PAGE_SIZE,
            PAGE_SIZE,
        )
        .unwrap();
        assert!(partial < full);
    }

    fn grouped_manifest_packing(
        manifests: &[BlobManifest],
        manifest_payload_lens: &[usize],
    ) -> usize {
        let mut segments = 1_usize;
        let mut relative = DATA_FIRST_PAGE;
        let mut place = |payload_len: usize| {
            let span = metadata_pages(payload_len).unwrap() + 2;
            if relative + span > DATA_END_PAGE {
                segments += 1;
                relative = DATA_FIRST_PAGE;
            }
            relative += span;
        };
        for manifest in manifests {
            for extent in &manifest.extents {
                place(extent.payload_byte_len as usize);
            }
        }
        for length in manifest_payload_lens {
            place(*length);
        }
        for length in [PAGE_SIZE; 3] {
            place(length);
        }
        segments
    }

    #[test]
    fn packing_plan_matches_interleaved_writer_when_grouping_underestimates() {
        let manifests: Vec<_> = (0..7)
            .map(|index| packing_manifest(index, if index % 2 == 0 { 245 } else { 256 }))
            .collect();
        let manifest_lens = vec![PAGE_SIZE; manifests.len()];
        assert_eq!(
            grouped_manifest_packing(&manifests, &manifest_lens),
            2,
            "fixture must detect the old grouped-order under-estimate"
        );
        assert_eq!(
            required_gc_segments(
                &manifests,
                &manifest_lens,
                &[0],
                PAGE_SIZE,
                PAGE_SIZE,
                PAGE_SIZE,
            )
            .unwrap(),
            3
        );
    }

    #[test]
    fn packing_plan_matches_interleaved_writer_when_grouping_overestimates() {
        let manifests: Vec<_> = (0..8)
            .map(|index| packing_manifest(index, if index % 2 == 0 { 233 } else { 256 }))
            .collect();
        let manifest_lens = vec![PAGE_SIZE; manifests.len()];
        assert_eq!(
            grouped_manifest_packing(&manifests, &manifest_lens),
            3,
            "fixture must detect the old grouped-order over-estimate"
        );
        assert_eq!(
            required_gc_segments(
                &manifests,
                &manifest_lens,
                &[0],
                PAGE_SIZE,
                PAGE_SIZE,
                PAGE_SIZE,
            )
            .unwrap(),
            2
        );
    }
}
