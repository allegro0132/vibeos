//! Checkpoint-roots-only framing experiment. No media admission or publication.
//!
//! Payloads retain their existing codecs and pointers. Callers must authenticate
//! the expected container digest/binding through a checkpoint and separately
//! validate each payload's semantics and authority before using it.

#[cfg(test)]
#[path = "experimental_root_bundle_device_tests.rs"]
mod device_tests;

use sha2::{Digest, Sha256};
use alloc::vec::Vec;
use core::ops::Range;
use vibeos_segment_format::{DATA_END_PAGE, MAX_EXTENT_PAYLOAD_PAGES, PAGE_SIZE};
use vibeos_segment_format::{
    decode_physical_pointer, encode_physical_pointer, pointers_overlap, validate_pointer,
    ExtentKind, PhysicalPointer, StoreUuid, POINTER_SIZE,
    ExtentRecord, VerifiedRecord, payload_sha256,
};

const HEADER: usize = 64;
const ENTRY: usize = 64;
pub const PREFIX: usize = HEADER + 3 * ENTRY;
pub const MAX_BYTES: usize = MAX_EXTENT_PAYLOAD_PAGES as usize * PAGE_SIZE;
const MAGIC: &[u8; 8] = b"EXPBND01";
pub const OBJECT_KIND_ROOT_BUNDLE: u32 = 0xffff_0030;

/// Read and structurally select experimental anchors from this device. This is
/// not a mounted store: allocation transitions and root semantics are unchecked.
/// A single four-page workspace is reused, then released before payload reads.
#[cfg(feature = "experimental-root-bundle")]
pub async fn select_device_checkpoint<D: crate::PageDevice>(device: &D, anchor_budget: usize,
    expected_max_replay_records: u32)
    -> Result<vibeos_segment_format::experimental_root_checkpoint::SelectedCheckpoint, crate::StoreError<D::Error>>
{
    use crate::StoreError;
    use vibeos_segment_format::{experimental_root_checkpoint as format, ANCHOR_PAGES, SEGMENT_PAGES};
    let info = device.info();
    if !matches!(info.logical_block_size, 512 | 1024 | 2048 | 4096)
        || info.page_count <= ANCHOR_PAGES
        || (info.page_count - ANCHOR_PAGES) % SEGMENT_PAGES != 0
        || info.range_first_logical_block.checked_add(info.logical_block_count).is_none()
        || expected_max_replay_records == 0 {
        return Err(StoreError::InvalidConfig);
    }
    let blocks_per_page = PAGE_SIZE as u64 / u64::from(info.logical_block_size);
    if info.logical_block_count % blocks_per_page != 0
        || info.logical_block_count / blocks_per_page != info.page_count {
        return Err(StoreError::InvalidConfig);
    }
    if anchor_budget < 4 * PAGE_SIZE { return Err(StoreError::MemoryLimit); }
    let mut pages = Vec::new();
    pages.try_reserve_exact(4).map_err(|_| StoreError::MemoryLimit)?;
    if pages.capacity() > anchor_budget / PAGE_SIZE { return Err(StoreError::MemoryLimit); }
    pages.resize(4, [0; PAGE_SIZE]);
    device.read_pages(0, &mut pages).await.map_err(StoreError::Device)?;
    let admitted = format::admit((&pages[0], &pages[1]), (&pages[2], &pages[3]))?
        .ok_or(StoreError::Unformatted)?;
    let superblock = admitted.superblock();
    if superblock.device_id != info.device_id
        || superblock.range_first_logical_block != info.range_first_logical_block
        || superblock.logical_block_size != info.logical_block_size
        || superblock.initial_block_count > info.logical_block_count
        || superblock.initial_range_pages > info.page_count
        || superblock.initial_range_pages.checked_mul(blocks_per_page) != Some(superblock.initial_block_count)
        || superblock.max_replay_records != expected_max_replay_records {
        return Err(StoreError::Corrupt);
    }
    device.read_pages(4, &mut pages).await.map_err(StoreError::Device)?;
    admitted.select_checkpoints((&pages[0], &pages[1]), (&pages[2], &pages[3]), info.page_count)?
        .ok_or(StoreError::Unformatted)
}

pub(crate) struct PreparedRootBundle {
    pub(crate) payload: Vec<u8>,
    pub(crate) record: crate::cas::FinalRecord,
    pub(crate) saved_pages: usize,
}

/// Prepare bytes/descriptor only. The caller must reserve the destination and
/// publish it through the existing segment/checkpoint protocol. `None` requests
/// the separated layout, preserving its admission limits.
/// Workspace counts new payload capacity and two descriptor pages; input root
/// buffers and the caller's other publication state remain separately charged.
pub(crate) fn prepare_bundle<E>(binding: Binding, roots: Roots<'_>, checkpoint_generation: u64,
    ordinal: u32, workspace_budget: usize) -> Result<Option<PreparedRootBundle>, crate::StoreError<E>>
{
    use crate::StoreError;
    binding.validate().map_err(|_| StoreError::Corrupt)?;
    vibeos_segment_format::segment_base_page(binding.segment)?;
    if checkpoint_generation == 0 || ordinal == 0 { return Err(StoreError::Corrupt); }
    let len = match roots.encoded_len(MAX_BYTES) {
        Ok(len) => len,
        Err(Error::Budget) => return Ok(None),
        Err(_) => return Err(StoreError::Corrupt),
    };
    if binding.validate_span(len).is_err() { return Ok(None); }
    let separate_pages: usize = [roots.catalog, roots.authority, roots.allocation]
        .iter().map(|bytes| 2 + bytes.len().div_ceil(PAGE_SIZE)).sum();
    let bundle_pages = 2 + len.div_ceil(PAGE_SIZE);
    if bundle_pages >= separate_pages || len + 2 * PAGE_SIZE > workspace_budget { return Ok(None); }
    let mut payload = Vec::new();
    payload.try_reserve_exact(len).map_err(|_| StoreError::MemoryLimit)?;
    if payload.capacity() > workspace_budget - 2 * PAGE_SIZE { return Err(StoreError::MemoryLimit); }
    payload.resize(len, 0);
    encode_framing_into(binding, roots, &mut payload, len).map_err(|_| StoreError::Corrupt)?;
    let hash = payload_sha256(&payload);
    let record = crate::cas::build_record(StoreUuid::new(binding.store)?, binding.segment,
        binding.generation, checkpoint_generation, ordinal, binding.descriptor, ExtentKind::Catalog,
        OBJECT_KIND_ROOT_BUNDLE, 0, 1, len as u64, len as u64, 0, len as u64, hash, hash)?;
    Ok(Some(PreparedRootBundle { payload, record, saved_pages: separate_pages - bundle_pages }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Binding {
    pub store: [u8; 16],
    pub segment: u64,
    pub generation: u64,
    pub descriptor: u32,
}

impl Binding {
    fn validate(self) -> Result<(), Error> {
        if self.store == [0; 16] || self.generation == 0 || !(2..DATA_END_PAGE).contains(&self.descriptor) {
            return Err(Error::Binding);
        }
        Ok(())
    }

    fn validate_span(self, len: usize) -> Result<(), Error> {
        self.validate()?;
        let end = self.descriptor as usize + 2 + len.div_ceil(PAGE_SIZE);
        if end > DATA_END_PAGE as usize { return Err(Error::Binding); }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role { Catalog = 2, Authority = 3, Allocation = 4 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error { Budget, Length, Binding, Framing, Digest }

#[derive(Clone, Copy, Debug)]
pub struct ReadContext {
    pub store: StoreUuid,
    pub admitted_segments: u64,
    pub next_segment_generation: u64,
    pub checkpoint_generation: u64,
    pub budget: usize,
}

/// One verified payload, exposing only members selected by the supplied root set.
pub struct DecodedRootBundle<'a> {
    roots: Roots<'a>,
    selected: [bool; 3],
}

/// Owns one device-read buffer and indexes selected members without rehashing.
pub struct OwnedRootBundle {
    bytes: Vec<u8>,
    ranges: [Range<usize>; 3],
    selected: [bool; 3],
    source_pointer: PhysicalPointer,
    target_checkpoint_generation: u64,
}

/// Allocation map with its decoded version and checkpoint binding preserved.
#[cfg(feature = "experimental-root-bundle")]
pub struct RecoveredAllocation {
    allocation: crate::AllocationV2,
    checkpoint: vibeos_segment_format::experimental_root_checkpoint::BundleCheckpoint,
    version: u16,
}

#[cfg(feature = "experimental-root-bundle")]
pub struct RecoveredAllocationPair {
    pub previous: Option<RecoveredAllocation>,
    pub current: RecoveredAllocation,
}

/// Device-selected recovery data. No runtime mount or write authority is
/// installed by producing this value. `roots` is absent for empty bootstrap.
#[cfg(feature = "experimental-root-bundle")]
pub struct RecoveredCheckpoint {
    pub selected: vibeos_segment_format::experimental_root_checkpoint::SelectedCheckpoint,
    pub allocations: RecoveredAllocationPair,
    pub roots: Option<RecoveredBundleRoots>,
}

/// Select experimental anchors and recover their current data under one
/// dynamic-memory allowance. Anchor buffers are released before root reads.
#[cfg(feature = "experimental-root-bundle")]
pub async fn recover_device_checkpoint<D: crate::PageDevice>(device: &D,
    memory_limit: usize, resident_bytes: usize, max_entries: usize, expected_max_replay_records: u32)
    -> Result<RecoveredCheckpoint, crate::StoreError<D::Error>>
{
    let anchor_budget = memory_limit.checked_sub(resident_bytes).ok_or(crate::StoreError::MemoryLimit)?;
    let selected = select_device_checkpoint(device, anchor_budget, expected_max_replay_records).await?;
    let (allocations, roots) = if selected.value().base.allocation_root == PhysicalPointer::Null {
        (recover_same_admission_allocations(device, &selected, memory_limit, resident_bytes).await?, None)
    } else {
        let (allocations, roots) = recover_checkpoint_roots(device, &selected, memory_limit, resident_bytes, max_entries).await?;
        (allocations, Some(roots))
    };
    Ok(RecoveredCheckpoint { selected, allocations, roots })
}

/// Dispatch non-null CAS/full-authority roots by their explicit layout bits.
/// This returns recovery data only; bootstrap, growth and authority deltas
/// still require their dedicated integration paths.
#[cfg(feature = "experimental-root-bundle")]
pub async fn recover_checkpoint_roots<D: crate::PageDevice>(device: &D,
    selected: &vibeos_segment_format::experimental_root_checkpoint::SelectedCheckpoint,
    memory_limit: usize, resident_bytes: usize, max_entries: usize)
    -> Result<(RecoveredAllocationPair, RecoveredBundleRoots), crate::StoreError<D::Error>>
{
    use crate::StoreError;
    let cp = selected.value();
    if cp.root_bundle_mask & 3 == 3 && cp.base.catalog_root == cp.base.authority_root {
        return recover_bundled_checkpoint(device, selected, memory_limit, resident_bytes, max_entries).await;
    }
    let maps = recover_same_admission_allocations(device, selected, memory_limit, resident_bytes).await?;
    let old = maps.previous.as_ref().map_or(Some(0), |map| map.map().allocated_bytes()).ok_or(StoreError::MemoryLimit)?;
    let resident = resident_bytes.checked_add(old).ok_or(StoreError::MemoryLimit)?;
    let current = maps.current.map().allocated_bytes().ok_or(StoreError::MemoryLimit)?;
    let catalog = if cp.root_bundle_mask & 1 == 0 {
        recover_separate_catalog(device, &maps.current, memory_limit, resident, max_entries).await?
    } else {
        let budget = resident.checked_add(current).and_then(|n| memory_limit.checked_sub(n)).ok_or(StoreError::MemoryLimit)?;
        let (refs, context) = RootReferences::from_checkpoint(selected.current(), budget).map_err(|_| StoreError::Corrupt)?;
        refs.read_bundle(device, Role::Catalog, context).await?.recover_catalog(device,
            &maps.current, memory_limit, resident, max_entries).await?
    };
    let (authority, roots) = if cp.root_bundle_mask & 2 == 0 {
        recover_separate_authority(device, &maps.current, &catalog, memory_limit, resident).await?
    } else {
        let tables = catalog.objects.capacity().checked_mul(core::mem::size_of::<crate::ObjectMapping>())
            .and_then(|n| catalog.blobs.capacity().checked_mul(core::mem::size_of::<crate::BlobMapping>())
                .and_then(|m| n.checked_add(m))).ok_or(StoreError::MemoryLimit)?;
        let budget = resident.checked_add(current).and_then(|n| n.checked_add(tables))
            .and_then(|n| memory_limit.checked_sub(n)).ok_or(StoreError::MemoryLimit)?;
        let (refs, context) = RootReferences::from_checkpoint(selected.current(), budget).map_err(|_| StoreError::Corrupt)?;
        refs.read_bundle(device, Role::Authority, context).await?.decode_authority_snapshot(
            &maps.current, &catalog, memory_limit, resident)?
    };
    Ok((maps, RecoveredBundleRoots { catalog, authority, roots }))
}

/// Explicit no-replay compatibility entry point.
#[cfg(feature = "experimental-root-bundle")]
pub async fn recover_bundled_checkpoint_without_replay<D: crate::PageDevice>(device: &D,
    selected: &vibeos_segment_format::experimental_root_checkpoint::SelectedCheckpoint,
    memory_limit: usize, resident_bytes: usize, max_entries: usize)
    -> Result<(RecoveredAllocationPair, RecoveredBundleRoots), crate::StoreError<D::Error>>
{
    if selected.value().base.replay_count != 0 { return Err(crate::StoreError::Corrupt); }
    recover_bundled_checkpoint(device, selected, memory_limit, resident_bytes, max_entries).await
}

/// Recover bundled catalog/authority and CAS replay after validating both
/// allocation generations. Reuse the allocation container when shared, or
/// release it before reading the catalog/authority container for a mixed layout.
#[cfg(feature = "experimental-root-bundle")]
pub async fn recover_bundled_checkpoint<D: crate::PageDevice>(device: &D,
    selected: &vibeos_segment_format::experimental_root_checkpoint::SelectedCheckpoint,
    memory_limit: usize, resident_bytes: usize, max_entries: usize)
    -> Result<(RecoveredAllocationPair, RecoveredBundleRoots), crate::StoreError<D::Error>>
{
    use crate::StoreError;
    let checkpoint = selected.value();
    if checkpoint.root_bundle_mask & 3 != 3
        || checkpoint.base.catalog_root != checkpoint.base.authority_root {
        return Err(StoreError::Corrupt);
    }
    let (allocations, bundle) = recover_allocation_pair(device, selected, memory_limit, resident_bytes, true).await?;
    let previous_bytes = allocations.previous.as_ref().map_or(Some(0), |map| map.map().allocated_bytes())
        .ok_or(StoreError::MemoryLimit)?;
    let resident = resident_bytes.checked_add(previous_bytes).ok_or(StoreError::MemoryLimit)?;
    let bundle = match bundle {
        Some(bundle) if bundle.source_pointer == checkpoint.base.catalog_root => bundle,
        other => {
            drop(other);
            let current_bytes = allocations.current.map().allocated_bytes().ok_or(StoreError::MemoryLimit)?;
            let live = resident.checked_add(current_bytes).ok_or(StoreError::MemoryLimit)?;
            let budget = memory_limit.checked_sub(live).ok_or(StoreError::MemoryLimit)?;
            let (refs, context) = RootReferences::from_checkpoint(selected.current(), budget).map_err(|_| StoreError::Corrupt)?;
            refs.read_bundle(device, Role::Catalog, context).await?
        }
    };
    let roots = bundle.recover_roots(device,
        &allocations.current, memory_limit, resident, max_entries).await?;
    Ok((allocations, roots))
}

/// Recover two allocation roots sequentially, releasing each encoded buffer
/// before reading the next and charging the retained old map against the budget.
/// This entry point covers unchanged admission with bundled or separate roots;
/// empty bootstrap checkpoints are supported, while growth requires its own path.
#[cfg(feature = "experimental-root-bundle")]
pub async fn recover_same_admission_allocations<D: crate::PageDevice>(device: &D,
    selected: &vibeos_segment_format::experimental_root_checkpoint::SelectedCheckpoint,
    memory_limit: usize, resident_bytes: usize) -> Result<RecoveredAllocationPair, crate::StoreError<D::Error>>
{
    Ok(recover_allocation_pair(device, selected, memory_limit, resident_bytes, false).await?.0)
}

#[cfg(feature = "experimental-root-bundle")]
async fn recover_allocation_pair<D: crate::PageDevice>(device: &D,
    selected: &vibeos_segment_format::experimental_root_checkpoint::SelectedCheckpoint,
    memory_limit: usize, resident_bytes: usize, retain_current: bool)
    -> Result<(RecoveredAllocationPair, Option<OwnedRootBundle>), crate::StoreError<D::Error>>
{
    use crate::StoreError;
    let mut retained = None;
    let mut previous: Option<RecoveredAllocation> = None;
    for (checkpoint, is_current) in selected.previous().map(|cp| (cp, false)).into_iter()
        .chain(core::iter::once((selected.current(), true))) {
        let old_bytes = previous.as_ref().map_or(Some(0), |old| old.map().allocated_bytes())
            .ok_or(StoreError::MemoryLimit)?;
        let resident = resident_bytes.checked_add(old_bytes).ok_or(StoreError::MemoryLimit)?;
        let budget = memory_limit.checked_sub(resident).ok_or(StoreError::MemoryLimit)?;
        let (refs, context) = RootReferences::from_checkpoint(checkpoint, budget).map_err(|_| StoreError::Corrupt)?;
        let recovered = match refs.0[2] {
            RootReference::Separate(PhysicalPointer::Null) => {
                let value = checkpoint.value();
                let base = &value.base;
                if base.binding.generation != 1 || base.next_segment_generation != 1
                    || [base.catalog_root, base.authority_root, base.replay_tail]
                        .iter().any(|p| *p != PhysicalPointer::Null)
                    || base.admitted_segments > crate::allocation_v2::MAX_ALLOCATION_V2_SEGMENTS as u64 {
                    return Err(StoreError::Corrupt);
                }
                let bitmap_bytes = usize::try_from(base.admitted_segments.div_ceil(4))
                    .map_err(|_| StoreError::MemoryLimit)?;
                crate::store::recovery_preflight_decode(memory_limit, resident, 0, bitmap_bytes)?;
                let allocation = crate::AllocationV2::from_v1_prefix(crate::AllocationState {
                    checkpoint_generation: 1, admitted_segments: base.admitted_segments,
                    allocated_prefix_segments: 0, next_segment_generation: 1,
                    cleaner_reserve_segments: base.cleaner_reserve_segments,
                }).map_err(|_| StoreError::Corrupt)?;
                let actual = crate::store::allocation_resident_bytes(&allocation)
                    .map_err(|_| StoreError::MemoryLimit)?;
                crate::store::recovery_preflight_decode(memory_limit, resident, 0, actual)?;
                RecoveredAllocation { allocation, checkpoint: *value, version: 1 }
            }
            RootReference::Bundle(_) => {
                let bundle = refs.read_bundle(device, Role::Allocation, context).await?;
                let recovered = bundle.recover_allocation(checkpoint, memory_limit, resident)?;
                if is_current && retain_current { retained = Some(bundle); }
                recovered
            }
            RootReference::Separate(pointer) => {
                let PhysicalPointer::Value(value) = pointer else { return Err(StoreError::Corrupt); };
                if value.exact_byte_len > budget as u64 { return Err(StoreError::MemoryLimit); }
                let payload = crate::store::read_pointer_payload_with_read_capacity(device, context.store,
                    context.admitted_segments, context.next_segment_generation, context.checkpoint_generation,
                    pointer, ExtentKind::Allocation, budget, None, budget).await?;
                if payload.extent.binding.target_checkpoint_generation != context.checkpoint_generation {
                    return Err(StoreError::Corrupt);
                }
                recover_allocation_bytes(&payload.bytes, payload.bytes.capacity(), checkpoint.value(),
                    memory_limit, resident)?
            }
        };
        if is_current {
            if let Some(old) = &previous { old.validate_same_admission_successor(&recovered)?; }
            return Ok((RecoveredAllocationPair { previous, current: recovered }, retained));
        }
        previous = Some(recovered);
    }
    Err(StoreError::Corrupt)
}

#[cfg(feature = "experimental-root-bundle")]
impl RecoveredAllocation {
    pub fn map(&self) -> &crate::AllocationV2 { &self.allocation }

    /// Validate an ordinary publication, relocation or reuse barrier with an
    /// unchanged admitted range. Growth requires its separate carrier/chain
    /// validation and must not be admitted through this entry point.
    pub fn validate_same_admission_successor<E>(&self, newer: &Self) -> Result<(), crate::StoreError<E>> {
        let old = &self.checkpoint.base;
        let new = &newer.checkpoint.base;
        if old.binding.generation.checked_add(1) != Some(new.binding.generation)
            || new.previous_generation != old.binding.generation
            || old.binding.store_uuid != new.binding.store_uuid
            || old.cleaner_reserve_segments != new.cleaner_reserve_segments
            || old.max_replay_records != new.max_replay_records
            || old.admitted_segments != new.admitted_segments
            || old.admitted_range_pages != new.admitted_range_pages {
            return Err(crate::StoreError::Corrupt);
        }
        crate::store::validate_allocation_checkpoint_transition(&self.allocation, &newer.allocation,
            old.binding.generation, new.binding.generation, old.next_segment_generation,
            new.next_segment_generation, newer.version)
    }
}


#[cfg(feature = "experimental-root-bundle")]
fn recover_allocation_bytes<E>(bytes: &[u8], encoded_capacity: usize,
    checkpoint: &vibeos_segment_format::experimental_root_checkpoint::BundleCheckpoint,
    memory_limit: usize, resident_bytes: usize) -> Result<RecoveredAllocation, crate::StoreError<E>>
{
    use crate::{AllocationV2, StoreError};
    let base = &checkpoint.base;
    let version = bytes.get(8..10).map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or(StoreError::Corrupt)?;
    let bound = crate::store::allocation_decode_capacity_upper_bound(bytes, version, base.admitted_segments)?;
    crate::store::recovery_preflight_decode(memory_limit, resident_bytes, encoded_capacity, bound)?;
    let allocation = match version {
        1 => {
            let legacy = crate::decode_allocation(bytes).map_err(|_| StoreError::Corrupt)?;
            let PhysicalPointer::Value(pointer) = base.allocation_root else { return Err(StoreError::Corrupt); };
            if legacy.allocated_prefix_segments == 0
                || pointer.segment_no.checked_add(1) != Some(legacy.allocated_prefix_segments) {
                return Err(StoreError::Corrupt);
            }
            AllocationV2::from_v1_prefix(legacy).map_err(|_| StoreError::Corrupt)?
        }
        2 => crate::decode_allocation_v2(bytes).map_err(|_| StoreError::Corrupt)?,
        _ => return Err(StoreError::Corrupt),
    };
    if allocation.checkpoint_generation != base.binding.generation
        || allocation.admitted_segments != base.admitted_segments
        || allocation.next_segment_generation != base.next_segment_generation
        || allocation.cleaner_reserve_segments != base.cleaner_reserve_segments {
        return Err(StoreError::Corrupt);
    }
    for pointer in [base.catalog_root, base.authority_root, base.allocation_root, base.replay_tail] {
        crate::store::require_allocated_pointer(&allocation, pointer)?;
    }
    let actual = crate::store::allocation_resident_bytes(&allocation).map_err(|_| StoreError::MemoryLimit)?;
    crate::store::recovery_preflight_decode(memory_limit, resident_bytes, encoded_capacity, actual)?;
    Ok(RecoveredAllocation { allocation, checkpoint: *checkpoint, version })
}

#[cfg(feature = "experimental-root-bundle")]
async fn validate_catalog_references<D: crate::PageDevice>(device: &D, allocation: &RecoveredAllocation,
    snapshot: &crate::CasSnapshot, memory_limit: usize, resident_bytes: usize)
    -> Result<(), crate::StoreError<D::Error>>
{
    use crate::StoreError;
    let base = &allocation.checkpoint.base;
        let table_bytes = snapshot.objects.capacity().checked_mul(core::mem::size_of::<crate::ObjectMapping>())
            .and_then(|n| snapshot.blobs.capacity().checked_mul(core::mem::size_of::<crate::BlobMapping>())
                .and_then(|m| n.checked_add(m))).ok_or(StoreError::MemoryLimit)?;
        let resident = resident_bytes.checked_add(table_bytes)
            .and_then(|n| allocation.map().allocated_bytes().and_then(|m| n.checked_add(m)))
            .ok_or(StoreError::MemoryLimit)?;
        let budget = memory_limit.checked_sub(resident).ok_or(StoreError::MemoryLimit)?;
        let context = crate::CasCodecContext::new(base.binding.store_uuid,
            base.admitted_segments, base.next_segment_generation).map_err(|_| StoreError::Corrupt)?;
        for blob in &snapshot.blobs {
            let PhysicalPointer::Value(pointer) = blob.manifest else { return Err(StoreError::Corrupt); };
            if pointer.exact_byte_len > budget as u64 { return Err(StoreError::MemoryLimit); }
            let payload = crate::store::read_pointer_payload_with_read_capacity(device, base.binding.store_uuid,
                base.admitted_segments, base.next_segment_generation, base.binding.generation,
                blob.manifest, ExtentKind::Catalog, budget, None, budget).await?;
            let upper = crate::store::blob_manifest_decode_capacity_upper_bound(&payload.bytes)?;
            crate::store::recovery_preflight_decode(memory_limit, resident, payload.bytes.capacity(), upper)?;
            let manifest = crate::decode_blob_manifest(&payload.bytes, context).map_err(|_| StoreError::Corrupt)?;
            if manifest.blob_key != blob.blob_key { return Err(StoreError::Corrupt); }
            for extent in &manifest.extents {
                crate::store::require_allocated_pointer(allocation.map(), extent.pointer)?;
            }
            let actual = manifest.extents.capacity().checked_mul(core::mem::size_of::<crate::ManifestExtent>())
                .ok_or(StoreError::MemoryLimit)?;
            crate::store::recovery_preflight_decode(memory_limit, resident, payload.bytes.capacity(), actual)?;
            drop(payload);
            crate::store::validate_cas_blob_descriptors(device, base.binding.store_uuid,
                base.admitted_segments, base.next_segment_generation, base.binding.generation,
                &manifest, None).await?;
        }
    Ok(())
}

#[cfg(feature = "experimental-root-bundle")]
async fn replay_catalog<D: crate::PageDevice>(device: &D, allocation: &RecoveredAllocation,
    mut snapshot: crate::CasSnapshot, memory_limit: usize, resident_bytes: usize, max_entries: usize)
    -> Result<crate::CasSnapshot, crate::StoreError<D::Error>>
{
    use crate::StoreError;
    if allocation.checkpoint.base.replay_count == 0 { return Ok(snapshot); }
        let base = &allocation.checkpoint.base;
        let context = crate::CasCodecContext::new(base.binding.store_uuid, base.admitted_segments,
            base.next_segment_generation).map_err(|_| StoreError::Corrupt)?;
        let count = base.replay_count as usize;
        let object_limit = snapshot.objects.len().checked_add(count).ok_or(StoreError::MemoryLimit)?;
        if object_limit > max_entries { return Err(StoreError::Corrupt); }
        let old_tables = snapshot.objects.capacity().checked_mul(core::mem::size_of::<crate::ObjectMapping>())
            .and_then(|n| snapshot.blobs.capacity().checked_mul(core::mem::size_of::<crate::BlobMapping>())
                .and_then(|m| n.checked_add(m))).ok_or(StoreError::MemoryLimit)?;
        let resident = resident_bytes.checked_add(old_tables)
            .and_then(|n| allocation.map().allocated_bytes().and_then(|m| n.checked_add(m)))
            .ok_or(StoreError::MemoryLimit)?;
        let chain_bound = count.checked_mul(core::mem::size_of::<crate::CasDelta>()).ok_or(StoreError::MemoryLimit)?;
        crate::store::recovery_preflight_decode(memory_limit, resident, 0, chain_bound)?;
        let mut chain = Vec::<crate::CasDelta>::new();
        chain.try_reserve_exact(count).map_err(|_| StoreError::MemoryLimit)?;
        let chain_bytes = chain.capacity().checked_mul(core::mem::size_of::<crate::CasDelta>()).ok_or(StoreError::MemoryLimit)?;
        let live = resident.checked_add(chain_bytes).ok_or(StoreError::MemoryLimit)?;
        let budget = memory_limit.checked_sub(live).ok_or(StoreError::MemoryLimit)?;
        let mut pointer = base.replay_tail;
        for depth in (1..=base.replay_count).rev() {
            crate::store::require_allocated_pointer(allocation.map(), pointer)?;
            let PhysicalPointer::Value(value) = pointer else { return Err(StoreError::Corrupt); };
            if value.exact_byte_len > budget as u64 { return Err(StoreError::MemoryLimit); }
            let payload = crate::store::read_pointer_payload_with_read_capacity(device, base.binding.store_uuid,
                base.admitted_segments, base.next_segment_generation, base.binding.generation,
                pointer, ExtentKind::CatalogDelta, budget, None, budget).await?;
            let delta = crate::decode_cas_delta(&payload.bytes, context).map_err(|_| StoreError::Corrupt)?;
            if delta.chain_count != depth || delta.checkpoint_generation > base.binding.generation
                || delta.checkpoint_generation != payload.extent.binding.target_checkpoint_generation {
                return Err(StoreError::Corrupt);
            }
            pointer = delta.previous_delta;
            chain.push(delta);
        }
        if pointer != PhysicalPointer::Null { return Err(StoreError::Corrupt); }
        let additions = chain.iter().filter(|delta| delta.new_blob.is_some()).count();
        let blob_limit = snapshot.blobs.len().checked_add(additions).ok_or(StoreError::MemoryLimit)?;
        if blob_limit > max_entries { return Err(StoreError::Corrupt); }
        // Charge complete successor tables while old allocations are still
        // live, covering allocator overlap during each reserve.
        let growth = object_limit.checked_mul(core::mem::size_of::<crate::ObjectMapping>())
            .and_then(|n| blob_limit.checked_mul(core::mem::size_of::<crate::BlobMapping>())
                .and_then(|m| n.checked_add(m))).ok_or(StoreError::MemoryLimit)?;
        crate::store::recovery_preflight_decode(memory_limit, live, 0, growth)?;
        snapshot.objects.try_reserve_exact(count).map_err(|_| StoreError::MemoryLimit)?;
        snapshot.blobs.try_reserve_exact(additions).map_err(|_| StoreError::MemoryLimit)?;
        let actual_tables = snapshot.objects.capacity().checked_mul(core::mem::size_of::<crate::ObjectMapping>())
            .and_then(|n| snapshot.blobs.capacity().checked_mul(core::mem::size_of::<crate::BlobMapping>())
                .and_then(|m| n.checked_add(m))).ok_or(StoreError::MemoryLimit)?;
        let actual_live = resident_bytes.checked_add(chain_bytes)
            .and_then(|n| allocation.map().allocated_bytes().and_then(|m| n.checked_add(m)))
            .ok_or(StoreError::MemoryLimit)?;
        crate::store::recovery_preflight_decode(memory_limit, actual_live, 0, actual_tables)?;
        let mut generation = snapshot.checkpoint_generation;
        let mut object_id = snapshot.objects.last().map_or(0, |object| object.object_id);
        for delta in chain.iter().rev() {
            if delta.checkpoint_generation < generation || delta.object.object_id <= object_id {
                return Err(StoreError::Corrupt);
            }
            generation = delta.checkpoint_generation;
            object_id = delta.object.object_id;
            match (delta.new_blob, snapshot.blobs.binary_search_by_key(&delta.object.blob_key, |blob| blob.blob_key)) {
                (None, Ok(_)) => {},
                (Some(blob), Err(index)) if blob.blob_key == delta.object.blob_key => snapshot.blobs.insert(index, blob),
                _ => return Err(StoreError::Corrupt),
            }
            snapshot.objects.push(delta.object);
        }
        drop(chain);
        snapshot.checkpoint_generation = base.binding.generation;
        for blob in &snapshot.blobs { crate::store::require_allocated_pointer(allocation.map(), blob.manifest)?; }
    Ok(snapshot)
}

/// Decoded roots whose catalog references and CAS replay have been checked.
/// This is recovery data, not an installed mount or authority grant.
#[cfg(feature = "experimental-root-bundle")]
pub struct RecoveredBundleRoots {
    pub catalog: crate::CasSnapshot,
    pub authority: crate::PersistentAuthoritySnapshot,
    pub roots: crate::PersistentRootSet,
}

#[cfg(feature = "experimental-root-bundle")]
fn decode_catalog_bytes<E>(bytes: &[u8], encoded_capacity: usize, target_generation: u64,
    allocation: &RecoveredAllocation, memory_limit: usize, resident_bytes: usize, max_entries: usize)
    -> Result<crate::CasSnapshot, crate::StoreError<E>>
{
    use crate::StoreError;
    let base = &allocation.checkpoint.base;
    if target_generation > base.binding.generation { return Err(StoreError::Corrupt); }
        let map_bytes = crate::store::allocation_resident_bytes(allocation.map())
            .map_err(|_| StoreError::MemoryLimit)?;
        let resident = resident_bytes.checked_add(map_bytes).ok_or(StoreError::MemoryLimit)?;
        let upper = crate::store::cas_snapshot_decode_capacity_upper_bound(bytes)?;
        // The size preflight above establishes the fixed header bounds. Reject
        // oversized tables before the codec allocates their decoded storage.
        let objects = u32::from_le_bytes(bytes[0x18..0x1c].try_into().map_err(|_| StoreError::Corrupt)?) as usize;
        let blobs = u32::from_le_bytes(bytes[0x1c..0x20].try_into().map_err(|_| StoreError::Corrupt)?) as usize;
        if objects > max_entries || blobs > max_entries { return Err(StoreError::Corrupt); }
        crate::store::recovery_preflight_decode(memory_limit, resident, encoded_capacity, upper)?;
        let context = crate::CasCodecContext::new(base.binding.store_uuid,
            base.admitted_segments, base.next_segment_generation).map_err(|_| StoreError::Corrupt)?;
        let decoded = crate::decode_cas_snapshot(bytes, context).map_err(|_| StoreError::Corrupt)?;
        if decoded.checkpoint_generation != target_generation
            || decoded.objects.len() > max_entries || decoded.blobs.len() > max_entries {
            return Err(StoreError::Corrupt);
        }
        for blob in &decoded.blobs {
            crate::store::require_allocated_pointer(allocation.map(), blob.manifest)?;
        }
        let actual = decoded.objects.capacity().checked_mul(core::mem::size_of::<crate::ObjectMapping>())
            .and_then(|n| decoded.blobs.capacity().checked_mul(core::mem::size_of::<crate::BlobMapping>())
                .and_then(|m| n.checked_add(m))).ok_or(StoreError::MemoryLimit)?;
        crate::store::recovery_preflight_decode(memory_limit, resident, encoded_capacity, actual)?;
        Ok(decoded)
}

/// Recover a separate CAS catalog root with the same replay/reference checks
/// as a bundled member. Full authority recovery remains a separate step.
#[cfg(feature = "experimental-root-bundle")]
pub async fn recover_separate_catalog<D: crate::PageDevice>(device: &D,
    allocation: &RecoveredAllocation, memory_limit: usize, resident_bytes: usize, max_entries: usize)
    -> Result<crate::CasSnapshot, crate::StoreError<D::Error>>
{
    use crate::StoreError;
    let base = &allocation.checkpoint.base;
    if allocation.checkpoint.root_bundle_mask & 1 != 0 { return Err(StoreError::Corrupt); }
    let PhysicalPointer::Value(pointer) = base.catalog_root else { return Err(StoreError::Corrupt); };
    let resident = resident_bytes.checked_add(allocation.map().allocated_bytes().ok_or(StoreError::MemoryLimit)?)
        .ok_or(StoreError::MemoryLimit)?;
    let budget = memory_limit.checked_sub(resident).ok_or(StoreError::MemoryLimit)?;
    if pointer.exact_byte_len > budget as u64 { return Err(StoreError::MemoryLimit); }
    let payload = crate::store::read_pointer_payload_with_read_capacity(device, base.binding.store_uuid,
        base.admitted_segments, base.next_segment_generation, base.binding.generation,
        base.catalog_root, ExtentKind::Catalog, budget, None, budget).await?;
    let snapshot = decode_catalog_bytes(&payload.bytes, payload.bytes.capacity(),
        payload.extent.binding.target_checkpoint_generation, allocation, memory_limit, resident_bytes, max_entries)?;
    drop(payload);
    let snapshot = replay_catalog(device, allocation, snapshot, memory_limit, resident_bytes, max_entries).await?;
    validate_catalog_references(device, allocation, &snapshot, memory_limit, resident_bytes).await?;
    Ok(snapshot)
}

#[cfg(feature = "experimental-root-bundle")]
fn decode_authority_bytes<E>(bytes: &[u8], encoded_capacity: usize, target_generation: u64,
    allocation: &RecoveredAllocation, catalog: &crate::CasSnapshot, memory_limit: usize, resident_bytes: usize)
    -> Result<(crate::PersistentAuthoritySnapshot, crate::PersistentRootSet), crate::StoreError<E>>
{
    use crate::StoreError;
    if target_generation > allocation.checkpoint.base.binding.generation { return Err(StoreError::Corrupt); }
        let tables = catalog.objects.capacity().checked_mul(core::mem::size_of::<crate::ObjectMapping>())
            .and_then(|n| catalog.blobs.capacity().checked_mul(core::mem::size_of::<crate::BlobMapping>())
                .and_then(|m| n.checked_add(m))).ok_or(StoreError::MemoryLimit)?;
        let resident = resident_bytes.checked_add(tables)
            .and_then(|n| allocation.map().allocated_bytes().and_then(|m| n.checked_add(m)))
            .ok_or(StoreError::MemoryLimit)?;
        let upper = crate::store::persistent_authority_recovery_capacity_upper_bound(bytes)?;
        crate::store::recovery_preflight_decode(memory_limit, resident, encoded_capacity, upper)?;
        let live = resident.checked_add(encoded_capacity).ok_or(StoreError::MemoryLimit)?;
        let budget = memory_limit.checked_sub(live).ok_or(StoreError::MemoryLimit)?;
        let (authority, peak) = crate::authority_snapshot::decode_persistent_authority_snapshot_bounded(bytes, budget)
            .map_err(|error| match error {
                crate::AuthoritySnapshotError::MemoryLimit => StoreError::MemoryLimit,
                _ => StoreError::Corrupt,
            })?;
        crate::store::recovery_preflight_decode(memory_limit, live, 0, peak)?;
        if authority.checkpoint_generation() != target_generation {
            return Err(StoreError::Corrupt);
        }
        let roots = crate::store::authority_roots_from_snapshot(&authority)?;
        for root in roots.entries() {
            let index = catalog.objects.binary_search_by_key(&root.object_id, |object| object.object_id)
                .map_err(|_| StoreError::Corrupt)?;
            let object = &catalog.objects[index];
            if object.commit_generation != root.commit_generation || object.blob_key.object_kind() != root.object_kind {
                return Err(StoreError::Corrupt);
            }
        }
        let actual = authority.allocated_bytes().and_then(|n| roots.allocated_bytes().and_then(|m| n.checked_add(m)))
            .ok_or(StoreError::MemoryLimit)?;
        crate::store::recovery_preflight_decode(memory_limit, live, 0, actual)?;
        Ok((authority, roots))
}

/// Recover an explicitly separate full authority snapshot. Legacy root sets
/// and authority deltas require their respective decoders.
#[cfg(feature = "experimental-root-bundle")]
pub async fn recover_separate_authority<D: crate::PageDevice>(device: &D,
    allocation: &RecoveredAllocation, catalog: &crate::CasSnapshot, memory_limit: usize, resident_bytes: usize)
    -> Result<(crate::PersistentAuthoritySnapshot, crate::PersistentRootSet), crate::StoreError<D::Error>>
{
    use crate::StoreError;
    let base = &allocation.checkpoint.base;
    if allocation.checkpoint.root_bundle_mask & 2 != 0 { return Err(StoreError::Corrupt); }
    let PhysicalPointer::Value(pointer) = base.authority_root else { return Err(StoreError::Corrupt); };
    let tables = catalog.objects.capacity().checked_mul(core::mem::size_of::<crate::ObjectMapping>())
        .and_then(|n| catalog.blobs.capacity().checked_mul(core::mem::size_of::<crate::BlobMapping>())
            .and_then(|m| n.checked_add(m))).ok_or(StoreError::MemoryLimit)?;
    let resident = resident_bytes.checked_add(tables)
        .and_then(|n| allocation.map().allocated_bytes().and_then(|m| n.checked_add(m)))
        .ok_or(StoreError::MemoryLimit)?;
    let budget = memory_limit.checked_sub(resident).ok_or(StoreError::MemoryLimit)?;
    if pointer.exact_byte_len > budget as u64 { return Err(StoreError::MemoryLimit); }
    let payload = crate::store::read_pointer_payload_with_read_capacity(device, base.binding.store_uuid,
        base.admitted_segments, base.next_segment_generation, base.binding.generation,
        base.authority_root, ExtentKind::Authority, budget, None, budget).await?;
    decode_authority_bytes(&payload.bytes, payload.bytes.capacity(), payload.extent.binding.target_checkpoint_generation,
        allocation, catalog, memory_limit, resident_bytes)
}

impl OwnedRootBundle {
    /// Recover a selected allocation member while charging both this retained
    /// container and the decoded map. This does not validate a transition from
    /// the older checkpoint or recover catalog/authority semantics.
    #[cfg(feature = "experimental-root-bundle")]
    pub fn recover_allocation<E>(&self,
        checkpoint: &vibeos_segment_format::experimental_root_checkpoint::RecoveryCheckpoint,
        memory_limit: usize, resident_bytes: usize) -> Result<RecoveredAllocation, crate::StoreError<E>>
    {
        use crate::StoreError;
        let checkpoint = checkpoint.value();
        let base = &checkpoint.base;
        if checkpoint.root_bundle_mask & 4 == 0 || base.allocation_root != self.source_pointer
            || self.target_checkpoint_generation != base.binding.generation {
            return Err(StoreError::Corrupt);
        }
        let bytes = self.get(Role::Allocation).map_err(|_| StoreError::Corrupt)?;
        recover_allocation_bytes(bytes, self.bytes.capacity(), checkpoint, memory_limit, resident_bytes)
    }

    /// Decode a full authority snapshot and resolve its roots against the
    /// caller's recovered catalog. Authority deltas require their separate path.
    #[cfg(feature = "experimental-root-bundle")]
    pub fn decode_authority_snapshot<E>(&self, allocation: &RecoveredAllocation,
        catalog: &crate::CasSnapshot, memory_limit: usize, resident_bytes: usize)
        -> Result<(crate::PersistentAuthoritySnapshot, crate::PersistentRootSet), crate::StoreError<E>>
    {
        use crate::StoreError;
        let base = &allocation.checkpoint.base;
        if allocation.checkpoint.root_bundle_mask & 2 == 0 || base.authority_root != self.source_pointer
            || self.target_checkpoint_generation > base.binding.generation {
            return Err(StoreError::Corrupt);
        }
        let bytes = self.get(Role::Authority).map_err(|_| StoreError::Corrupt)?;
        decode_authority_bytes(bytes, self.bytes.capacity(), self.target_checkpoint_generation,
            allocation, catalog, memory_limit, resident_bytes)
    }

    /// Recover bundled catalog, CAS replay and full authority together. Keep
    /// the container only through replay/authority decode, then release it
    /// before manifest reads. Authority deltas are not handled here.
    #[cfg(feature = "experimental-root-bundle")]
    pub async fn recover_roots<D: crate::PageDevice>(self, device: &D,
        allocation: &RecoveredAllocation, memory_limit: usize, resident_bytes: usize,
        max_entries: usize) -> Result<RecoveredBundleRoots, crate::StoreError<D::Error>>
    {
        use crate::StoreError;
        let catalog = self.decode_catalog_snapshot(allocation, memory_limit, resident_bytes, max_entries)?;
        let replay_resident = resident_bytes.checked_add(self.bytes.capacity()).ok_or(StoreError::MemoryLimit)?;
        let catalog = replay_catalog(device, allocation, catalog, memory_limit, replay_resident, max_entries).await?;
        let (authority, roots) = self.decode_authority_snapshot(allocation, &catalog, memory_limit, resident_bytes)?;
        drop(self);
        let resident = authority.allocated_bytes()
            .and_then(|n| roots.allocated_bytes().and_then(|m| n.checked_add(m)))
            .and_then(|n| resident_bytes.checked_add(n)).ok_or(StoreError::MemoryLimit)?;
        validate_catalog_references(device, allocation, &catalog, memory_limit, resident).await?;
        Ok(RecoveredBundleRoots { catalog, authority, roots })
    }

    /// Decode catalog and full authority from this container once, then release
    /// it before reading manifests while charging all retained decoded roots.
    #[cfg(feature = "experimental-root-bundle")]
    pub async fn recover_roots_without_replay<D: crate::PageDevice>(self, device: &D,
        allocation: &RecoveredAllocation, memory_limit: usize, resident_bytes: usize,
        max_entries: usize) -> Result<RecoveredBundleRoots, crate::StoreError<D::Error>>
    {
        use crate::StoreError;
        let base = &allocation.checkpoint.base;
        if base.replay_count != 0 || base.replay_tail != PhysicalPointer::Null {
            return Err(StoreError::Corrupt);
        }
        self.recover_roots(device, allocation, memory_limit, resident_bytes, max_entries).await
    }

    /// Consume the container, then authenticate all manifests and Blob
    /// descriptors for a snapshot without replay. This is not a complete mount:
    /// authority, replay and the other checkpoint remain caller responsibilities.
    #[cfg(feature = "experimental-root-bundle")]
    pub async fn recover_catalog_without_replay<D: crate::PageDevice>(self, device: &D,
        allocation: &RecoveredAllocation, memory_limit: usize, resident_bytes: usize,
        max_entries: usize) -> Result<crate::CasSnapshot, crate::StoreError<D::Error>>
    {
        use crate::StoreError;
        let base = &allocation.checkpoint.base;
        if base.replay_count != 0 || base.replay_tail != PhysicalPointer::Null {
            return Err(StoreError::Corrupt);
        }
        let snapshot = self.decode_catalog_snapshot(allocation, memory_limit, resident_bytes, max_entries)?;
        drop(self);
        validate_catalog_references(device, allocation, &snapshot, memory_limit, resident_bytes).await?;
        Ok(snapshot)
    }

    /// Recover a catalog snapshot plus its bounded CAS replay chain. Authority
    /// must be resolved separately against the resulting object table.
    #[cfg(feature = "experimental-root-bundle")]
    pub async fn recover_catalog<D: crate::PageDevice>(self, device: &D,
        allocation: &RecoveredAllocation, memory_limit: usize, resident_bytes: usize,
        max_entries: usize) -> Result<crate::CasSnapshot, crate::StoreError<D::Error>>
    {
        let snapshot = self.decode_catalog_snapshot(allocation, memory_limit, resident_bytes, max_entries)?;
        drop(self);
        let snapshot = replay_catalog(device, allocation, snapshot, memory_limit, resident_bytes, max_entries).await?;
        validate_catalog_references(device, allocation, &snapshot, memory_limit, resident_bytes).await?;
        Ok(snapshot)
    }

    /// Decode only the bundled CAS snapshot. Replay and referenced manifests
    /// still require validation before the result can be used as mounted state.
    #[cfg(feature = "experimental-root-bundle")]
    pub fn decode_catalog_snapshot<E>(&self, allocation: &RecoveredAllocation,
        memory_limit: usize, resident_bytes: usize, max_entries: usize)
        -> Result<crate::CasSnapshot, crate::StoreError<E>>
    {
        use crate::StoreError;
        let checkpoint = &allocation.checkpoint;
        let base = &checkpoint.base;
        if checkpoint.root_bundle_mask & 1 == 0 || base.catalog_root != self.source_pointer
            || self.target_checkpoint_generation > base.binding.generation {
            return Err(StoreError::Corrupt);
        }
        let bytes = self.get(Role::Catalog).map_err(|_| StoreError::Corrupt)?;
        decode_catalog_bytes(bytes, self.bytes.capacity(), self.target_checkpoint_generation,
            allocation, memory_limit, resident_bytes, max_entries)
    }

    pub fn get(&self, role: Role) -> Result<&[u8], Error> {
        let index = role as usize - 2;
        if !self.selected[index] { return Err(Error::Binding); }
        Ok(&self.bytes[self.ranges[index].clone()])
    }

    pub fn retained_payload_capacity(&self) -> usize { self.bytes.capacity() }
}

impl<'a> DecodedRootBundle<'a> {
    pub fn get(&self, role: Role) -> Result<&'a [u8], Error> {
        if !self.selected[role as usize - 2] { return Err(Error::Binding); }
        Ok(self.roots.get(role))
    }
}

/// Typed checkpoint-field experiment. The role is fixed by its root-set slot.
/// Bundle pointers name the entire container, never an individual member range.
/// Catalog is the provisional physical extent kind; a reader must additionally
/// check the dedicated bundle object kind before interpreting its payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootReference {
    Separate(PhysicalPointer),
    Bundle(PhysicalPointer),
}

impl RootReference {
    pub fn pointer(self) -> PhysicalPointer {
        match self { Self::Separate(p) | Self::Bundle(p) => p }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootReferences(pub [RootReference; 3]);

impl RootReferences {
    /// Adapts a structurally selected experimental checkpoint. Allocation and
    /// payload recovery, plus actual device-capability matching, remain required.
    #[cfg(feature = "experimental-root-bundle")]
    pub fn from_checkpoint(checkpoint: &vibeos_segment_format::experimental_root_checkpoint::RecoveryCheckpoint,
        payload_budget: usize) -> Result<(Self, ReadContext), Error>
    {
        let checkpoint = checkpoint.value();
        checkpoint.validate().map_err(|_| Error::Binding)?;
        let base = &checkpoint.base;
        let pointers = [base.catalog_root, base.authority_root, base.allocation_root];
        let roots = Self(core::array::from_fn(|index| {
            if checkpoint.root_bundle_mask & (1 << index) != 0 { RootReference::Bundle(pointers[index]) }
            else { RootReference::Separate(pointers[index]) }
        }));
        roots.validate(base.binding.store_uuid, base.admitted_segments, base.next_segment_generation)?;
        Ok((roots, ReadContext { store: base.binding.store_uuid, admitted_segments: base.admitted_segments,
            next_segment_generation: base.next_segment_generation, checkpoint_generation: base.binding.generation,
            budget: payload_budget }))
    }

    /// Read through the existing sealed-segment scanner and physical hash check.
    /// Context/root-set authentication remains the checkpoint caller's duty.
    /// `budget` limits payload capacity, not fixed scanner/descriptor overhead.
    pub async fn read_bundle<D: crate::PageDevice>(self, device: &D, role: Role, context: ReadContext)
        -> Result<OwnedRootBundle, crate::StoreError<D::Error>>
    {
        use crate::StoreError;
        self.validate(context.store, context.admitted_segments, context.next_segment_generation)
            .map_err(|_| StoreError::Corrupt)?;
        let RootReference::Bundle(PhysicalPointer::Value(pointer)) = self.0[role as usize - 2] else {
            return Err(StoreError::Corrupt);
        };
        let len = usize::try_from(pointer.exact_byte_len).map_err(|_| StoreError::Corrupt)?;
        check_budget(len, context.budget).map_err(|e| match e {
            Error::Budget => StoreError::MemoryLimit, _ => StoreError::Corrupt,
        })?;
        let binding = Binding { store: *pointer.store_uuid.as_bytes(), segment: pointer.segment_no,
            generation: pointer.segment_generation, descriptor: pointer.descriptor_relative_page };
        binding.validate_span(len).map_err(|_| StoreError::Corrupt)?;
        let resolved = crate::store::read_pointer_payload_with_read_capacity(device, context.store,
            context.admitted_segments, context.next_segment_generation, context.checkpoint_generation,
            PhysicalPointer::Value(pointer), ExtentKind::Catalog, context.budget, None, context.budget).await?;
        // The store reader has already checked the sealed segment, descriptor
        // identity, complete metadata extent shape and raw whole-payload hash.
        if resolved.extent.object_kind != OBJECT_KIND_ROOT_BUNDLE { return Err(StoreError::Corrupt); }
        if resolved.bytes.capacity() > context.budget { return Err(StoreError::MemoryLimit); }
        let roots = decode_authenticated_framing(&resolved.bytes, binding).map_err(|_| StoreError::Corrupt)?;
        let mut at = PREFIX;
        let ranges = [roots.catalog, roots.authority, roots.allocation].map(|member| {
            let start = at;
            at += member.len();
            start..at
        });
        let selected = self.0.map(|r| r == RootReference::Bundle(PhysicalPointer::Value(pointer)));
        Ok(OwnedRootBundle { bytes: resolved.bytes, ranges, selected,
            source_pointer: PhysicalPointer::Value(pointer),
            target_checkpoint_generation: resolved.extent.binding.target_checkpoint_generation })
    }

    /// Caller supplies an authenticated checkpoint root set and a descriptor
    /// already verified in its segment's sealed descriptor chain. A sealed
    /// descriptor alone is insufficient to prove segment membership.
    pub fn decode_bundle_payload<'a>(self, role: Role, bytes: &'a [u8],
        descriptor: &VerifiedRecord<ExtentRecord>, context: ReadContext)
        -> Result<DecodedRootBundle<'a>, Error>
    {
        check_budget(bytes.len(), context.budget)?;
        self.validate(context.store, context.admitted_segments, context.next_segment_generation)?;
        let RootReference::Bundle(PhysicalPointer::Value(pointer)) = self.0[role as usize - 2] else {
            return Err(Error::Binding);
        };
        let record = descriptor.value();
        if record.binding.store_uuid != pointer.store_uuid
            || record.binding.segment_no != pointer.segment_no
            || record.binding.generation != pointer.segment_generation
            || record.binding.ordinal != pointer.ordinal
            || record.binding.target_checkpoint_generation > context.checkpoint_generation
            || record.extent_kind != pointer.extent_kind
            || record.object_kind != OBJECT_KIND_ROOT_BUNDLE
            || record.payload_first_relative_page != pointer.payload_relative_page
            || record.payload_pages != pointer.payload_pages
            || record.payload_byte_len != pointer.exact_byte_len
            || record.payload_sha256 != pointer.payload_sha256
            || record.content_byte_len != pointer.exact_byte_len
            || record.encoded_blob_len != pointer.exact_byte_len
            || record.encoded_offset != 0 || record.extent_index != 0 || record.extent_count != 1
            || record.merkle_root != pointer.payload_sha256
            || bytes.len() as u64 != pointer.exact_byte_len {
            return Err(Error::Binding);
        }
        let binding = Binding { store: *pointer.store_uuid.as_bytes(), segment: pointer.segment_no,
            generation: pointer.segment_generation, descriptor: pointer.descriptor_relative_page };
        binding.validate_span(bytes.len())?;
        // Physical pointers always commit raw SHA-256. Do not substitute the
        // host-model domain-separated container digest or hash the payload twice.
        if payload_sha256(bytes) != pointer.payload_sha256 { return Err(Error::Digest); }
        let roots = decode_authenticated_framing(bytes, binding)?;
        let selected = self.0.map(|r| r == RootReference::Bundle(PhysicalPointer::Value(pointer)));
        Ok(DecodedRootBundle { roots, selected })
    }

    /// Validates root fields only, not a full checkpoint or media admission.
    pub fn validate(self, store: StoreUuid, admitted: u64, next_generation: u64) -> Result<(), Error> {
        if next_generation == 0 { return Err(Error::Binding); }
        for (index, reference) in self.0.iter().copied().enumerate() {
            let kind = match reference {
                RootReference::Bundle(PhysicalPointer::Null) => return Err(Error::Binding),
                RootReference::Bundle(_) => ExtentKind::Catalog,
                RootReference::Separate(_) => [ExtentKind::Catalog, ExtentKind::Authority, ExtentKind::Allocation][index],
            };
            validate_pointer(reference.pointer(), store, admitted, kind).map_err(|_| Error::Binding)?;
            if let PhysicalPointer::Value(p) = reference.pointer() {
                if p.segment_generation >= next_generation { return Err(Error::Binding); }
            }
            for previous in self.0[..index].iter().copied() {
                if let (PhysicalPointer::Value(left), PhysicalPointer::Value(right)) =
                    (previous.pointer(), reference.pointer()) {
                    if left.segment_no == right.segment_no && left.segment_generation != right.segment_generation {
                        return Err(Error::Binding);
                    }
                }
                if pointers_overlap(previous.pointer(), reference.pointer()) {
                    let intentional = matches!((previous, reference),
                        (RootReference::Bundle(left), RootReference::Bundle(right)) if left == right);
                    if !intentional { return Err(Error::Binding); }
                }
            }
        }
        Ok(())
    }

    /// Returns an explicit 3-bit selector and the existing 96-byte pointer slots.
    /// No current checkpoint decoder accepts this selector.
    pub fn encode_fields(self, store: StoreUuid, admitted: u64, next_generation: u64)
        -> Result<(u32, [[u8; POINTER_SIZE]; 3]), Error>
    {
        self.validate(store, admitted, next_generation)?;
        let mut mask = 0;
        let mut slots = [[0; POINTER_SIZE]; 3];
        for (index, reference) in self.0.iter().copied().enumerate() {
            if matches!(reference, RootReference::Bundle(_)) { mask |= 1 << index; }
            encode_physical_pointer(reference.pointer(), &mut slots[index]).map_err(|_| Error::Binding)?;
        }
        Ok((mask, slots))
    }

    pub fn decode_fields(mask: u32, slots: &[[u8; POINTER_SIZE]; 3], store: StoreUuid,
                         admitted: u64, next_generation: u64) -> Result<Self, Error> {
        if mask & !7 != 0 { return Err(Error::Framing); }
        let mut roots = [RootReference::Separate(PhysicalPointer::Null); 3];
        for (index, slot) in slots.iter().enumerate() {
            let pointer = decode_physical_pointer(slot).map_err(|_| Error::Binding)?;
            roots[index] = if mask & (1 << index) != 0 {
                RootReference::Bundle(pointer)
            } else { RootReference::Separate(pointer) };
        }
        let result = Self(roots);
        result.validate(store, admitted, next_generation)?;
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Roots<'a> {
    pub catalog: &'a [u8],
    pub authority: &'a [u8],
    pub allocation: &'a [u8],
}

impl<'a> Roots<'a> {
    pub fn get(self, role: Role) -> &'a [u8] {
        match role {
            Role::Catalog => self.catalog,
            Role::Authority => self.authority,
            Role::Allocation => self.allocation,
        }
    }

    pub fn encoded_len(self, budget: usize) -> Result<usize, Error> {
        let mut total = PREFIX;
        for bytes in [self.catalog, self.authority, self.allocation] {
            if bytes.is_empty() { return Err(Error::Length); }
            total = total.checked_add(bytes.len()).ok_or(Error::Length)?;
        }
        check_budget(total, budget)?;
        Ok(total)
    }
}

fn check_budget(len: usize, budget: usize) -> Result<(), Error> {
    if len > budget.min(MAX_BYTES) { return Err(Error::Budget); }
    if len < PREFIX { return Err(Error::Length); }
    Ok(())
}

pub fn container_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"EXPERIMENT-CONTAINER-v0\0");
    hash.update(bytes);
    hash.finalize().into()
}

fn member_digest(role: u16, bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"EXPERIMENT-MEMBER-v0\0");
    hash.update(role.to_le_bytes());
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    hash.finalize().into()
}

/// Encodes into an exactly sized caller-owned buffer, without allocating.
pub fn encode_into(binding: Binding, roots: Roots<'_>, out: &mut [u8], budget: usize)
    -> Result<[u8; 32], Error>
{
    encode_framing_into(binding, roots, out, budget)?;
    Ok(container_digest(out))
}

fn encode_framing_into(binding: Binding, roots: Roots<'_>, out: &mut [u8], budget: usize)
    -> Result<(), Error>
{
    if out.len() != roots.encoded_len(budget)? { return Err(Error::Length); }
    binding.validate_span(out.len())?;
    out.fill(0);
    out[..8].copy_from_slice(MAGIC);
    out[8..24].copy_from_slice(&binding.store);
    out[24..32].copy_from_slice(&binding.segment.to_le_bytes());
    out[32..40].copy_from_slice(&binding.generation.to_le_bytes());
    out[40..44].copy_from_slice(&binding.descriptor.to_le_bytes());
    out[44..46].copy_from_slice(&3_u16.to_le_bytes());
    let total = out.len() as u64;
    out[48..56].copy_from_slice(&total.to_le_bytes());
    let mut at = PREFIX;
    for (index, bytes) in [roots.catalog, roots.authority, roots.allocation].into_iter().enumerate() {
        let role = index as u16 + 2;
        let entry = HEADER + index * ENTRY;
        out[entry..entry + 2].copy_from_slice(&role.to_le_bytes());
        out[entry + 2..entry + 4].copy_from_slice(&(index as u16).to_le_bytes());
        out[entry + 8..entry + 16].copy_from_slice(&(at as u64).to_le_bytes());
        out[entry + 16..entry + 24].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
        out[entry + 24..entry + 56].copy_from_slice(&member_digest(role, bytes));
        out[at..at + bytes.len()].copy_from_slice(bytes);
        at += bytes.len();
    }
    Ok(())
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("bounded field"))
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("bounded field"))
}

/// Validates all framing/digests and returns slices borrowing the input buffer.
/// `expected` and `binding` must come from authenticated state, not this payload.
pub fn decode<'a>(bytes: &'a [u8], binding: Binding, expected: [u8; 32], budget: usize)
    -> Result<Roots<'a>, Error>
{
    check_budget(bytes.len(), budget)?;
    binding.validate_span(bytes.len())?;
    if container_digest(bytes) != expected { return Err(Error::Digest); }
    decode_authenticated_framing(bytes, binding)
}

// Private: callers have checked length/budget, binding span and whole-payload
// authentication before reaching these bounded slice operations.
fn decode_authenticated_framing(bytes: &[u8], binding: Binding) -> Result<Roots<'_>, Error> {
    if &bytes[..8] != MAGIC || u16_at(bytes, 44) != 3 || u16_at(bytes, 46) != 0
        || u64_at(bytes, 48) != bytes.len() as u64 || bytes[56..64] != [0; 8] {
        return Err(Error::Framing);
    }
    if bytes[8..24] != binding.store || u64_at(bytes, 24) != binding.segment
        || u64_at(bytes, 32) != binding.generation
        || bytes[40..44] != binding.descriptor.to_le_bytes() {
        return Err(Error::Binding);
    }
    let mut at = PREFIX;
    let mut members: [&[u8]; 3] = [&[]; 3];
    for (index, member) in members.iter_mut().enumerate() {
        let entry = HEADER + index * ENTRY;
        if u16_at(bytes, entry) != index as u16 + 2 || u16_at(bytes, entry + 2) != index as u16
            || bytes[entry + 4..entry + 8] != [0; 4] || bytes[entry + 56..entry + 64] != [0; 8]
            || u64_at(bytes, entry + 8) != at as u64 {
            return Err(Error::Framing);
        }
        let len = usize::try_from(u64_at(bytes, entry + 16)).map_err(|_| Error::Length)?;
        if len == 0 || len > bytes.len() - at { return Err(Error::Length); }
        *member = &bytes[at..at + len];
        if bytes[entry + 24..entry + 56] != member_digest(index as u16 + 2, member) {
            return Err(Error::Digest);
        }
        at += len;
    }
    if at != bytes.len() { return Err(Error::Length); }
    Ok(Roots { catalog: members[0], authority: members[1], allocation: members[2] })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn binding() -> Binding { Binding { store: [1; 16], segment: 7, generation: 3, descriptor: 2 } }
    fn roots() -> Roots<'static> { Roots { catalog: b"catalog", authority: b"authority", allocation: b"allocation" } }

    #[test]
    fn physical_payload_adapter_binds_descriptor_hash_and_selected_members() {
        use vibeos_segment_format::{decode_extent_verified, encode_extent_body, encode_record_seal,
            segment_base_page, DecodeStatus, PointerValue, RecordBinding};
        fn seal(record: ExtentRecord) -> VerifiedRecord<ExtentRecord> {
            let mut body = [0; PAGE_SIZE];
            let mut seal = [0; PAGE_SIZE];
            let digest = encode_extent_body(&record, &mut body).unwrap();
            encode_record_seal(digest, &mut seal).unwrap();
            let DecodeStatus::Sealed(verified) = decode_extent_verified(&body, &seal).unwrap() else {
                panic!("fixture must be sealed");
            };
            verified
        }
        let store = StoreUuid::new([1; 16]).unwrap();
        let mut bytes = vec![0; roots().encoded_len(MAX_BYTES).unwrap()];
        let host_digest = encode_into(binding(), roots(), &mut bytes, MAX_BYTES).unwrap();
        let raw_digest = payload_sha256(&bytes);
        assert_ne!(host_digest, raw_digest);
        let pointer = PointerValue { store_uuid: store, segment_no: 7, segment_generation: 3,
            descriptor_relative_page: 2, payload_relative_page: 4, payload_pages: 1,
            ordinal: 1, exact_byte_len: bytes.len() as u64, extent_kind: ExtentKind::Catalog,
            payload_sha256: raw_digest };
        let record = ExtentRecord {
            binding: RecordBinding { store_uuid: store, generation: 3, segment_no: 7, ordinal: 1,
                self_page: segment_base_page(7).unwrap() + 2, target_checkpoint_generation: 4 },
            extent_kind: ExtentKind::Catalog, object_kind: OBJECT_KIND_ROOT_BUNDLE,
            extent_index: 0, extent_count: 1, payload_pages: 1,
            content_byte_len: bytes.len() as u64, encoded_blob_len: bytes.len() as u64,
            encoded_offset: 0, payload_byte_len: bytes.len() as u64,
            payload_first_relative_page: 4, record_span_pages: 3,
            merkle_root: raw_digest, payload_sha256: raw_digest,
        };
        let descriptor = seal(record);
        let context = ReadContext { store, admitted_segments: 16, next_segment_generation: 4,
            checkpoint_generation: 4, budget: bytes.len() };
        let refs = RootReferences([RootReference::Bundle(PhysicalPointer::Value(pointer)); 3]);
        let decoded = refs.decode_bundle_payload(Role::Catalog, &bytes, &descriptor, context).unwrap();
        assert_eq!(decoded.get(Role::Catalog).unwrap().as_ptr(), bytes[PREFIX..].as_ptr());
        assert_eq!(decoded.get(Role::Authority).unwrap(), roots().authority);
        let mut mixed = refs;
        mixed.0[1] = RootReference::Separate(PhysicalPointer::Value(PointerValue {
            segment_no: 8, extent_kind: ExtentKind::Authority, ..pointer }));
        let decoded = mixed.decode_bundle_payload(Role::Catalog, &bytes, &descriptor, context).unwrap();
        assert_eq!(decoded.get(Role::Allocation).unwrap(), roots().allocation);
        assert_eq!(decoded.get(Role::Authority), Err(Error::Binding));
        assert!(mixed.decode_bundle_payload(Role::Authority, &bytes, &descriptor, context).is_err());
        for wrong in [
            ExtentRecord { object_kind: OBJECT_KIND_ROOT_BUNDLE + 1, ..record },
            ExtentRecord { extent_count: 2, ..record },
            ExtentRecord { content_byte_len: record.content_byte_len + 1, ..record },
            ExtentRecord { merkle_root: host_digest, ..record },
            ExtentRecord { binding: RecordBinding { ordinal: 2, ..record.binding }, ..record },
            ExtentRecord { binding: RecordBinding { target_checkpoint_generation: 5, ..record.binding }, ..record },
        ] {
            assert!(refs.decode_bundle_payload(Role::Catalog, &bytes, &seal(wrong), context).is_err());
        }
        assert!(refs.decode_bundle_payload(Role::Catalog, &bytes, &descriptor,
            ReadContext { budget: bytes.len() - 1, ..context }).is_err());
        let wrong_refs = RootReferences([RootReference::Bundle(PhysicalPointer::Value(PointerValue {
            payload_sha256: host_digest, ..pointer })); 3]);
        let wrong_descriptor = seal(ExtentRecord { payload_sha256: host_digest, merkle_root: host_digest, ..record });
        assert!(matches!(wrong_refs.decode_bundle_payload(Role::Catalog, &bytes, &wrong_descriptor, context), Err(Error::Digest)));
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(refs.decode_bundle_payload(Role::Catalog, &corrupt, &descriptor, context).is_err());
        let changed_hash = payload_sha256(&corrupt);
        let changed_refs = RootReferences([RootReference::Bundle(PhysicalPointer::Value(PointerValue {
            payload_sha256: changed_hash, ..pointer })); 3]);
        let changed_descriptor = seal(ExtentRecord { payload_sha256: changed_hash, merkle_root: changed_hash, ..record });
        assert!(matches!(changed_refs.decode_bundle_payload(Role::Catalog, &corrupt, &changed_descriptor, context), Err(Error::Digest)));
    }

    #[test]
    fn root_fields_allow_only_explicit_identical_bundle_aliases() {
        use vibeos_segment_format::PointerValue;
        let store = StoreUuid::new([1; 16]).unwrap();
        let value = PointerValue { store_uuid: store, segment_no: 7, segment_generation: 3,
            descriptor_relative_page: 2, payload_relative_page: 4, payload_pages: 2,
            ordinal: 1, exact_byte_len: 5065, extent_kind: ExtentKind::Catalog, payload_sha256: [9; 32] };
        let pointer = PhysicalPointer::Value(value);
        let refs = RootReferences([RootReference::Bundle(pointer); 3]);
        let (mask, slots) = refs.encode_fields(store, 16, 4).unwrap();
        assert_eq!(mask, 7);
        assert_eq!(RootReferences::decode_fields(mask, &slots, store, 16, 4).unwrap(), refs);
        for bad_mask in [0, 1, 2, 3, 4, 5, 6, 8, u32::MAX] {
            assert!(RootReferences::decode_fields(bad_mask, &slots, store, 16, 4).is_err());
        }
        assert!(refs.validate(store, 7, 4).is_err());
        assert!(refs.validate(store, 16, 3).is_err());
        assert!(refs.validate(StoreUuid::new([2; 16]).unwrap(), 16, 4).is_err());
        let mut partial = refs;
        partial.0[1] = RootReference::Bundle(PhysicalPointer::Value(PointerValue {
            descriptor_relative_page: 3, payload_relative_page: 5, ..value }));
        assert!(partial.validate(store, 16, 4).is_err());
        let mut changed_hash = refs;
        changed_hash.0[1] = RootReference::Bundle(PhysicalPointer::Value(PointerValue {
            payload_sha256: [8; 32], ..value }));
        assert!(changed_hash.validate(store, 16, 4).is_err());
        let mut stale = refs;
        stale.0[1] = RootReference::Bundle(PhysicalPointer::Value(PointerValue {
            segment_generation: 2, ..value }));
        assert!(stale.validate(store, 16, 4).is_err());
        let mut mixed = refs;
        mixed.0[1] = RootReference::Separate(PhysicalPointer::Value(PointerValue {
            segment_no: 8, extent_kind: ExtentKind::Authority, ..value }));
        let (mask, slots) = mixed.encode_fields(store, 16, 4).unwrap();
        assert_eq!(mask, 5);
        assert_eq!(RootReferences::decode_fields(mask, &slots, store, 16, 4).unwrap(), mixed);
        assert!(RootReferences([RootReference::Bundle(PhysicalPointer::Null); 3])
            .validate(store, 16, 4).is_err());
    }

    #[test]
    fn roots_roundtrip_borrows_input_and_binds_location() {
        let mut out = vec![0; roots().encoded_len(MAX_BYTES).unwrap()];
        let digest = encode_into(binding(), roots(), &mut out, MAX_BYTES).unwrap();
        let read = decode(&out, binding(), digest, MAX_BYTES).unwrap();
        assert_eq!(read, roots());
        assert_eq!(read.get(Role::Catalog).as_ptr(), out[PREFIX..].as_ptr());
        for other in [Binding { generation: 4, ..binding() }, Binding { segment: 8, ..binding() },
                      Binding { descriptor: 3, ..binding() }, Binding { store: [2; 16], ..binding() }] {
            assert_eq!(decode(&out, other, digest, MAX_BYTES), Err(Error::Binding));
        }
    }

    #[test]
    fn mutations_and_truncations_fail_even_with_rehashed_container() {
        let mut out = vec![0; roots().encoded_len(MAX_BYTES).unwrap()];
        let digest = encode_into(binding(), roots(), &mut out, MAX_BYTES).unwrap();
        for index in 0..out.len() {
            for bit in 0..8 {
                let mut bad = out.clone();
                bad[index] ^= 1 << bit;
                assert!(decode(&bad, binding(), digest, MAX_BYTES).is_err());
                assert!(decode(&bad, binding(), container_digest(&bad), MAX_BYTES).is_err());
            }
        }
        for end in 0..out.len() {
            let short = &out[..end];
            assert!(decode(short, binding(), container_digest(short), MAX_BYTES).is_err());
        }
        out.push(0);
        assert!(decode(&out, binding(), container_digest(&out), MAX_BYTES).is_err());
    }

    #[test]
    fn budget_is_explicit_and_failed_encoding_does_not_touch_output() {
        let len = roots().encoded_len(MAX_BYTES).unwrap();
        let mut out = vec![0xa5; len];
        assert_eq!(encode_into(binding(), roots(), &mut out, len - 1), Err(Error::Budget));
        assert!(out.iter().all(|b| *b == 0xa5));
        let hash = encode_into(binding(), roots(), &mut out, len).unwrap();
        assert_eq!(decode(&out, binding(), hash, len - 1), Err(Error::Budget));
        assert!(decode(&out, binding(), hash, len).is_ok());
        assert_eq!(Roots { catalog: &[], ..roots() }.encoded_len(MAX_BYTES), Err(Error::Length));
        let big = vec![0; MAX_BYTES];
        assert_eq!(Roots { catalog: &big, ..roots() }.encoded_len(usize::MAX), Err(Error::Budget));
        let maximum = Roots { catalog: &big[..MAX_BYTES - PREFIX - 2], authority: b"a", allocation: b"b" };
        let mut full = vec![0; maximum.encoded_len(MAX_BYTES).unwrap()];
        let full_hash = encode_into(binding(), maximum, &mut full, MAX_BYTES).unwrap();
        assert_eq!(decode(&full, binding(), full_hash, MAX_BYTES).unwrap(), maximum);
        let mut bounded = vec![0; len];
        let last = Binding { descriptor: DATA_END_PAGE - 3, ..binding() };
        assert!(encode_into(last, roots(), &mut bounded, len).is_ok());
        let beyond = Binding { descriptor: DATA_END_PAGE - 2, ..binding() };
        assert_eq!(encode_into(beyond, roots(), &mut bounded, len), Err(Error::Binding));
    }
}
