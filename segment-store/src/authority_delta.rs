//! Experimental authority append payload codec. Test-only until physical
//! predecessor binding, bounded replay, GC and offline recovery are integrated.
//! These bytes are not yet an admitted on-media format or an authority handle.

use crate::authority_snapshot::{
    decode_persistent_authority_snapshot, encode_persistent_authority_metadata,
    encode_persistent_authority_snapshot, persistent_authority_encoded_len,
    validate_authority_bytes, validate_canonical_authority_bytes,
    PersistentAuthoritySnapshot, MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN,
};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

const HEADER: usize = 128;
const MAGIC: &[u8; 8] = b"VIBEAUD1";

#[derive(Debug, PartialEq, Eq)]
enum DeltaError {
    Invalid,
    Memory,
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn snapshot_digest(metadata: &[u8], records: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(metadata);
    hasher.update(records);
    hasher.finalize().into()
}
fn number(bytes: &[u8], at: usize) -> Result<usize, DeltaError> {
    usize::try_from(u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()))
        .map_err(|_| DeltaError::Invalid)
}
fn put(bytes: &mut [u8], at: usize, value: usize) {
    bytes[at..at + 8].copy_from_slice(&(value as u64).to_le_bytes());
}

/// Copy current non-stream tables in full. Only an exact predecessor record
/// stream prefix is omitted, so principal/quota/root updates cannot disappear.
fn encode(
    base: &PersistentAuthoritySnapshot,
    next: &PersistentAuthoritySnapshot,
) -> Result<Option<Vec<u8>>, DeltaError> {
    encode_with_prefix(base, next, 0)
}

// Reserve physical-envelope space in the same allocation as the delta. Large
// links must not retain a second full payload merely to prepend their header.
fn encode_with_prefix(
    base: &PersistentAuthoritySnapshot,
    next: &PersistentAuthoritySnapshot,
    prefix: usize,
) -> Result<Option<Vec<u8>>, DeltaError> {
    if next.checkpoint_generation() <= base.checkpoint_generation()
        || next.record_stream().len() <= base.record_stream().len()
        || !next.record_stream().starts_with(base.record_stream())
    {
        return Ok(None);
    }
    let before = encode_persistent_authority_metadata(base).map_err(|_| DeltaError::Invalid)?;
    let after = encode_persistent_authority_metadata(next).map_err(|_| DeltaError::Invalid)?;
    let base_offset = before.len();
    let next_offset = after.len();
    let base_len = persistent_authority_encoded_len(base).map_err(|_| DeltaError::Invalid)?;
    let next_len = persistent_authority_encoded_len(next).map_err(|_| DeltaError::Invalid)?;
    let common = base.record_stream().len();
    let len = prefix.checked_add(HEADER)
        .and_then(|n| n.checked_add(next_len - common))
        .ok_or(DeltaError::Invalid)?;
    if len >= next_len {
        return Ok(None);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(len)
        .map_err(|_| DeltaError::Memory)?;
    output.resize(prefix + HEADER, 0);
    let header = &mut output[prefix..];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&1_u16.to_le_bytes());
    header[10..12].copy_from_slice(&(HEADER as u16).to_le_bytes());
    put(header, 16, base_len);
    put(header, 24, base_offset);
    put(header, 32, next_len);
    put(header, 40, next_offset);
    put(header, 48, common);
    header[56..88].copy_from_slice(&snapshot_digest(&before, base.record_stream()));
    header[88..120].copy_from_slice(&snapshot_digest(&after, next.record_stream()));
    output.extend_from_slice(&after);
    output.extend_from_slice(&next.record_stream()[common..]);
    Ok(Some(output))
}

// Compare the canonical encoding without serializing its record stream again.
// The decoded snapshot has already passed full record/graph validation. Keep
// byte equality (not just digest equality), including all reserved metadata.
fn canonical_snapshot_matches(
    snapshot: &PersistentAuthoritySnapshot,
    bytes: &[u8],
) -> Result<bool, DeltaError> {
    let metadata = encode_persistent_authority_metadata(snapshot)
        .map_err(|_| DeltaError::Invalid)?;
    Ok(metadata.len().checked_add(snapshot.record_stream().len()) == Some(bytes.len())
        && bytes.starts_with(&metadata)
        && bytes[metadata.len()..] == *snapshot.record_stream())
}

/// Reconstruct inert canonical snapshot bytes. Even a matching result digest
/// does not bypass the existing snapshot and record-chain decoder. Admission
/// against external policy remains the responsibility of the existing caller.
fn reconstruct(base: &[u8], delta: &[u8]) -> Result<Vec<u8>, DeltaError> {
    reconstruct_checked(base, delta).map(|(bytes, _, _)| bytes)
}

// Return generations from the same complete validation used to rebuild bytes;
// the physical-link layer must not decode both snapshots a second time.
fn reconstruct_checked(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, u64, u64), DeltaError> {
    if delta.len() < HEADER
        || delta.len() > MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN
        || base.len() > MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN
        || &delta[..8] != MAGIC
        || delta[8..10] != 1_u16.to_le_bytes()
        || delta[10..12] != (HEADER as u16).to_le_bytes()
        || delta[12..16]
            .iter()
            .chain(&delta[120..128])
            .any(|&b| b != 0)
    {
        return Err(DeltaError::Invalid);
    }
    let base_len = number(delta, 16)?;
    let base_offset = number(delta, 24)?;
    let next_len = number(delta, 32)?;
    let next_offset = number(delta, 40)?;
    let common = number(delta, 48)?;
    if base_len != base.len()
        || next_len > MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN
        || common == 0
        || !common.is_multiple_of(vibeos_durable_format::RECORD_SIZE)
        || base_offset.checked_add(common) != Some(base.len())
        || next_offset
            .checked_add(common)
            .is_none_or(|n| n >= next_len)
        || HEADER.checked_add(next_len.checked_sub(common).ok_or(DeltaError::Invalid)?)
            != Some(delta.len())
        || delta.len() >= next_len
        || digest(base).as_slice() != &delta[56..88]
    {
        return Err(DeltaError::Invalid);
    }
    let (predecessor_generation, verified_base_offset) =
        validate_canonical_authority_bytes(base).map_err(|_| DeltaError::Invalid)?;
    if verified_base_offset != base_offset {
        return Err(DeltaError::Invalid);
    }
    // Bounds and maximum output length are proved before reserving output.
    let prefix_end = HEADER.checked_add(next_offset).ok_or(DeltaError::Invalid)?;
    if prefix_end > delta.len() {
        return Err(DeltaError::Invalid);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(next_len)
        .map_err(|_| DeltaError::Memory)?;
    output.extend_from_slice(&delta[HEADER..prefix_end]);
    output.extend_from_slice(&base[base_offset..]);
    output.extend_from_slice(&delta[prefix_end..]);
    if output.len() != next_len || digest(&output).as_slice() != &delta[88..120] {
        return Err(DeltaError::Invalid);
    }
    let (successor_generation, verified_next_offset) =
        validate_canonical_authority_bytes(&output).map_err(|_| DeltaError::Invalid)?;
    if successor_generation <= predecessor_generation || verified_next_offset != next_offset {
        return Err(DeltaError::Invalid);
    }
    Ok((output, predecessor_generation, successor_generation))
}

// Experimental envelope: canonical pointer plus predecessor/result checkpoint
// generations. The physical extent framing authenticates this whole envelope.
const LINK_HEADER: usize = 128;
const LINK_MAGIC: &[u8; 8] = b"VIBEAUL1";
const MAX_REPLAY_DEPTH: u32 = 32;

#[derive(Clone, Copy)]
struct LinkContext {
    store_uuid: vibeos_segment_format::StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
}

struct Link<'a> {
    predecessor: vibeos_segment_format::PhysicalPointer,
    depth: u32,
    predecessor_generation: u64,
    generation: u64,
    delta: &'a [u8],
}

fn decode_link(bytes: &[u8], context: LinkContext) -> Result<Link<'_>, DeltaError> {
    use vibeos_segment_format::{
        decode_physical_pointer, validate_pointer, ExtentKind, PhysicalPointer,
    };
    if bytes.len() < LINK_HEADER + HEADER
        || bytes.len() > MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN
        || &bytes[..8] != LINK_MAGIC
        || bytes[12..16] != [0; 4]
    {
        return Err(DeltaError::Invalid);
    }
    let depth = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let predecessor = decode_physical_pointer(bytes[16..112].try_into().unwrap())
        .map_err(|_| DeltaError::Invalid)?;
    let PhysicalPointer::Value(value) = predecessor else {
        return Err(DeltaError::Invalid);
    };
    validate_pointer(
        predecessor,
        context.store_uuid,
        context.admitted_segments,
        ExtentKind::Authority,
    )
    .map_err(|_| DeltaError::Invalid)?;
    let predecessor_generation = u64::from_le_bytes(bytes[112..120].try_into().unwrap());
    let generation = u64::from_le_bytes(bytes[120..128].try_into().unwrap());
    if depth == 0
        || depth > MAX_REPLAY_DEPTH
        || value.segment_generation >= context.next_segment_generation
        || predecessor_generation == 0
        || predecessor_generation >= generation
        || generation > context.checkpoint_generation
    {
        return Err(DeltaError::Invalid);
    }
    Ok(Link {
        predecessor,
        depth,
        predecessor_generation,
        generation,
        delta: &bytes[LINK_HEADER..],
    })
}

fn encode_link(
    base: &PersistentAuthoritySnapshot,
    next: &PersistentAuthoritySnapshot,
    predecessor: vibeos_segment_format::PhysicalPointer,
    predecessor_depth: u32,
    context: LinkContext,
) -> Result<Option<Vec<u8>>, DeltaError> {
    use vibeos_segment_format::encode_physical_pointer;
    let Some(depth) = predecessor_depth
        .checked_add(1)
        .filter(|&n| n <= MAX_REPLAY_DEPTH)
    else {
        return Ok(None);
    };
    let Some(mut bytes) = encode_with_prefix(base, next, LINK_HEADER)? else {
        return Ok(None);
    };
    if bytes.len() > MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN {
        return Ok(None);
    }
    bytes[..8].copy_from_slice(LINK_MAGIC);
    bytes[8..12].copy_from_slice(&depth.to_le_bytes());
    let mut pointer = [0; vibeos_segment_format::POINTER_SIZE];
    encode_physical_pointer(predecessor, &mut pointer).map_err(|_| DeltaError::Invalid)?;
    bytes[16..112].copy_from_slice(&pointer);
    bytes[112..120].copy_from_slice(&base.checkpoint_generation().to_le_bytes());
    bytes[120..128].copy_from_slice(&next.checkpoint_generation().to_le_bytes());
    decode_link(&bytes, context)?;
    Ok(Some(bytes))
}

/// Apply after the device resolver has authenticated the exact predecessor
/// pointer's payload/segment and reconstructed it. Depth is observed from that
/// predecessor, never trusted solely from the child. Full snapshots have depth
/// zero. Returning inert bytes still does not admit a capability or policy.
fn apply_link(
    resolved_pointer: vibeos_segment_format::PhysicalPointer,
    base: &[u8],
    predecessor_depth: u32,
    bytes: &[u8],
    context: LinkContext,
) -> Result<Vec<u8>, DeltaError> {
    let link = decode_link(bytes, context)?;
    if link.predecessor != resolved_pointer || predecessor_depth.checked_add(1) != Some(link.depth)
    {
        return Err(DeltaError::Invalid);
    }
    let (output, predecessor_generation, generation) = reconstruct_checked(base, link.delta)?;
    if predecessor_generation != link.predecessor_generation || generation != link.generation {
        return Err(DeltaError::Invalid);
    }
    Ok(output)
}

/// Payload budget is cumulative across fetched ancestors, not just one extent.
/// `buffer_bytes` bounds owned fetched payloads plus the overlapping rebuilt
/// snapshot buffer, ancestor/pending tables, and conservative table reallocation
/// overlap. Decoder/preflight and source scan workspace are separate costs;
/// this is not a total replay heap budget.
struct ReplayLimits {
    payload_bytes: usize,
    snapshot_bytes: usize,
    buffer_bytes: usize,
}

#[derive(Debug)]
enum ReplayError<E> {
    Codec(DeltaError),
    Source(E),
}
impl<E> From<DeltaError> for ReplayError<E> {
    fn from(error: DeltaError) -> Self {
        Self::Codec(error)
    }
}

trait AuthoritySource {
    type Error;
    /// Authenticate the pointer, segment and complete authority extent chain.
    /// Return canonical payload bytes and the extent's target generation.
    async fn read(
        &mut self,
        pointer: vibeos_segment_format::PhysicalPointer,
        maximum: usize,
    ) -> Result<(Vec<u8>, u64), Self::Error>;
}

// Recovery borrows the canonical bitmap; small codec fixtures can supply an
// explicit slice without constructing a production allocation map.
enum AllocatedSegments<'a> {
    Bitmap(&'a crate::allocation_v2::AllocationV2),
    Fixture(&'a [u64]),
}
impl AllocatedSegments<'_> {
    fn contains(&self, segment: u64) -> bool {
        match self {
            Self::Bitmap(map) => map.segment_state(segment) == Some(crate::SegmentAllocation::Allocated),
            Self::Fixture(segments) => segments.contains(&segment),
        }
    }

    fn iter(&self, admitted: u64) -> impl Iterator<Item = u64> + '_ {
        (0..admitted).filter(|&segment| self.contains(segment))
    }
}

struct DeviceAuthoritySource<'a, D> {
    device: &'a D,
    context: LinkContext,
    allocated: AllocatedSegments<'a>,
    memo: Option<&'a crate::store::VerifiedSegmentScans>,
    // Owned by this recovery only; supplied by the preceding authenticated read.
    verified_tip: Option<(vibeos_segment_format::PhysicalPointer, Vec<u8>, u64)>,
}
impl<D: crate::PageDevice> AuthoritySource for DeviceAuthoritySource<'_, D> {
    type Error = crate::StoreError<D::Error>;
    async fn read(
        &mut self,
        pointer: vibeos_segment_format::PhysicalPointer,
        maximum: usize,
    ) -> Result<(Vec<u8>, u64), Self::Error> {
        let vibeos_segment_format::PhysicalPointer::Value(value) = pointer else {
            return Err(crate::StoreError::Corrupt);
        };
        if !self.allocated.contains(value.segment_no) {
            return Err(crate::StoreError::Corrupt);
        }
        if let Some((verified_pointer, bytes, generation)) = self.verified_tip.take() {
            if pointer != verified_pointer {
                return Err(crate::StoreError::Corrupt);
            }
            if bytes.capacity() > maximum {
                return Err(crate::StoreError::MemoryLimit);
            }
            return Ok((bytes, generation));
        }
        let (bytes, record) = crate::store::read_pointer_authority_payload_with_memo(
            self.device,
            self.context.store_uuid,
            self.context.admitted_segments,
            self.context.next_segment_generation,
            self.context.checkpoint_generation,
            pointer,
            self.allocated.iter(self.context.admitted_segments),
            maximum,
            self.memo,
        )
        .await?;
        Ok((bytes, record.binding.target_checkpoint_generation))
    }
}

struct ReplayedAuthority {
    bytes: Vec<u8>,
    depth: u32,
    // Includes the tip and full-snapshot base; future GC must protect all of
    // them or materialize a full snapshot before reclaiming any ancestor.
    ancestors: Vec<vibeos_segment_format::PhysicalPointer>,
    payload_bytes: usize,
    peak_buffer_bytes: usize,
}

/// Select an experimental delta only from the actual reconstructed media bytes.
/// A supported legacy full snapshot is readable but cannot be the canonical V2
/// digest base. None tells the publisher to materialize a full snapshot first.
/// The caller must retain all replay ancestors until that checkpoint is durable.
fn encode_replayed_link(
    base: &ReplayedAuthority,
    next: &PersistentAuthoritySnapshot,
    context: LinkContext,
) -> Result<Option<Vec<u8>>, DeltaError> {
    let snapshot = decode_persistent_authority_snapshot(&base.bytes)
        .map_err(|_| DeltaError::Invalid)?;
    if next.checkpoint_generation() <= snapshot.checkpoint_generation()
        || next.checkpoint_generation() > context.checkpoint_generation
        || base.depth > MAX_REPLAY_DEPTH
        || base.ancestors.len() != base.depth as usize + 1
    {
        return Err(DeltaError::Invalid);
    }
    if !canonical_snapshot_matches(&snapshot, &base.bytes)? {
        // Only legacy full bases may legitimately differ from canonical V2.
        if base.depth != 0 || base.bytes[8..10] != 1_u16.to_le_bytes() {
            return Err(DeltaError::Invalid);
        }
        return Ok(None);
    }
    encode_link(&snapshot, next, base.ancestors[0], base.depth, context)
}

/// Reserve one table entry while accounting for a moving reallocation: the old
/// allocation may remain live until the replacement has been allocated. Pending
/// table capacity remains charged after pop because Vec retains that storage.
fn reserve_replay_entry<T>(
    table: &mut Vec<T>,
    resident: &mut usize,
    peak: &mut usize,
    limit: usize,
) -> Result<(), DeltaError> {
    if table.len() < table.capacity() {
        return Ok(());
    }
    let item = core::mem::size_of::<T>();
    let old = table.capacity().checked_mul(item).ok_or(DeltaError::Memory)?;
    let requested = table.len().checked_add(1)
        .and_then(|n| n.checked_mul(item)).ok_or(DeltaError::Memory)?;
    let overlap = resident.checked_add(requested).ok_or(DeltaError::Memory)?;
    if overlap > limit {
        return Err(DeltaError::Memory);
    }
    table.try_reserve_exact(1).map_err(|_| DeltaError::Memory)?;
    // Vec may supply more capacity than requested. Check that capacity too;
    // allocator-internal overhead is outside this owned-allocation budget.
    let actual = table.capacity().checked_mul(item).ok_or(DeltaError::Memory)?;
    let overlap = resident.checked_add(actual).ok_or(DeltaError::Memory)?;
    if overlap > limit {
        return Err(DeltaError::Memory);
    }
    *peak = (*peak).max(overlap);
    *resident = overlap.checked_sub(old).ok_or(DeltaError::Memory)?;
    Ok(())
}

async fn replay<L: AuthoritySource>(
    source: &mut L,
    tip: vibeos_segment_format::PhysicalPointer,
    context: LinkContext,
    limits: ReplayLimits,
) -> Result<ReplayedAuthority, ReplayError<L::Error>> {
    use vibeos_segment_format::{validate_pointer, ExtentKind, PhysicalPointer};
    let mut pointer = tip;
    let mut ancestors = Vec::new();
    let mut pending: Vec<(PhysicalPointer, Vec<u8>)> = Vec::new();
    let mut consumed = 0_usize;
    let mut resident_buffers = 0_usize;
    let mut peak_buffers = 0_usize;
    let mut expected = None;
    let mut bytes;
    loop {
        if ancestors.len() > MAX_REPLAY_DEPTH as usize || ancestors.contains(&pointer) {
            return Err(DeltaError::Invalid.into());
        }
        let PhysicalPointer::Value(value) = pointer else {
            return Err(DeltaError::Invalid.into());
        };
        validate_pointer(
            pointer,
            context.store_uuid,
            context.admitted_segments,
            ExtentKind::Authority,
        )
        .map_err(|_| DeltaError::Invalid)?;
        if value.segment_generation >= context.next_segment_generation {
            return Err(DeltaError::Invalid.into());
        }
        let remaining = limits
            .payload_bytes
            .checked_sub(consumed)
            .ok_or(DeltaError::Memory)?
            .min(limits.buffer_bytes.checked_sub(resident_buffers).ok_or(DeltaError::Memory)?);
        if value.exact_byte_len > remaining as u64 {
            return Err(DeltaError::Memory.into());
        }
        let (loaded, generation) = source
            .read(pointer, remaining)
            .await
            .map_err(ReplayError::Source)?;
        if loaded.capacity() > remaining {
            return Err(DeltaError::Memory.into());
        }
        resident_buffers = resident_buffers.checked_add(loaded.capacity()).ok_or(DeltaError::Memory)?;
        peak_buffers = peak_buffers.max(resident_buffers);
        consumed = consumed
            .checked_add(loaded.len())
            .ok_or(DeltaError::Memory)?;
        reserve_replay_entry(&mut ancestors, &mut resident_buffers,
            &mut peak_buffers, limits.buffer_bytes)?;
        ancestors.push(pointer);
        if generation == 0 || generation > context.checkpoint_generation {
            return Err(DeltaError::Invalid.into());
        }
        if loaded.starts_with(LINK_MAGIC) {
            let link = decode_link(&loaded, context)?;
            if generation != link.generation
                || expected.is_some_and(|pair| pair != (link.depth, generation))
            {
                return Err(DeltaError::Invalid.into());
            }
            if pending.len() >= MAX_REPLAY_DEPTH as usize {
                return Err(DeltaError::Invalid.into());
            }
            // Check the declared materialized size before retaining this link.
            if number(link.delta, 32)? > limits.snapshot_bytes {
                return Err(DeltaError::Memory.into());
            }
            expected = Some((link.depth - 1, link.predecessor_generation));
            pointer = link.predecessor;
            reserve_replay_entry(&mut pending, &mut resident_buffers,
                &mut peak_buffers, limits.buffer_bytes)?;
            pending.push((pointer, loaded));
        } else {
            if expected.is_some_and(|pair| pair != (0, generation)) {
                return Err(DeltaError::Invalid.into());
            }
            if loaded.len() > limits.snapshot_bytes {
                return Err(DeltaError::Memory.into());
            }
            let metadata_budget = limits.buffer_bytes.checked_sub(resident_buffers).ok_or(DeltaError::Memory)?;
            let (base_generation, _, metadata_bytes) =
                crate::authority_snapshot::validate_authority_metadata_bounded(&loaded, metadata_budget)
                    .map_err(|error| match error {
                        crate::authority_snapshot::AuthoritySnapshotError::OutOfBounds => DeltaError::Memory,
                        _ => DeltaError::Invalid,
                    })?;
            peak_buffers = peak_buffers.max(resident_buffers.checked_add(metadata_bytes).ok_or(DeltaError::Memory)?);
            if base_generation != generation {
                return Err(DeltaError::Invalid.into());
            }
            bytes = loaded;
            break;
        }
    }
    let mut depth = 0;
    while let Some((predecessor, delta)) = pending.pop() {
        let link = decode_link(&delta, context)?;
        let next_len = number(link.delta, 32)?;
        let overlapping = resident_buffers.checked_add(next_len).ok_or(DeltaError::Memory)?;
        if overlapping > limits.buffer_bytes {
            return Err(DeltaError::Memory.into());
        }
        // Check before apply_link can reserve its successor buffer. Decoding
        // scratch allocations inside apply_link have a separate budget gap.
        peak_buffers = peak_buffers.max(overlapping);
        let old_capacity = bytes.capacity();
        let next = apply_link(predecessor, &bytes, depth, &delta, context)?;
        // The allocator may supply more capacity than the requested length.
        // Old bytes and the pending delta are still live at this point.
        let actual_overlap = resident_buffers.checked_add(next.capacity()).ok_or(DeltaError::Memory)?;
        if actual_overlap > limits.buffer_bytes {
            return Err(DeltaError::Memory.into());
        }
        peak_buffers = peak_buffers.max(actual_overlap);
        resident_buffers = resident_buffers.checked_sub(old_capacity)
            .and_then(|n| n.checked_sub(delta.capacity()))
            .and_then(|n| n.checked_add(next.capacity())).ok_or(DeltaError::Memory)?;
        if resident_buffers > limits.buffer_bytes {
            return Err(DeltaError::Memory.into());
        }
        bytes = next;
        depth += 1;
    }
    Ok(ReplayedAuthority {
        bytes,
        depth,
        ancestors,
        payload_bytes: consumed,
        peak_buffer_bytes: peak_buffers,
    })
}

// Test-only bridge into checkpoint recovery. Production mount must continue
// rejecting this experimental format until budgets and offline admission land.
pub(crate) async fn replay_checkpoint_for_test<D: crate::PageDevice>(
    device: &D,
    superblock: &vibeos_segment_format::Superblock,
    checkpoint: &vibeos_segment_format::Checkpoint,
    allocation: &crate::allocation_v2::AllocationV2,
    maximum: usize,
    verified_bytes: Vec<u8>,
    verified_generation: u64,
    memo: Option<&crate::store::VerifiedSegmentScans>,
) -> Result<Vec<u8>, crate::StoreError<D::Error>> {
    let context = LinkContext {
        store_uuid: superblock.binding.store_uuid,
        admitted_segments: checkpoint.admitted_segments,
        next_segment_generation: checkpoint.next_segment_generation,
        checkpoint_generation: checkpoint.binding.generation,
    };
    let mut source = DeviceAuthoritySource { device, context, allocated: AllocatedSegments::Bitmap(allocation), verified_tip: Some((checkpoint.authority_root, verified_bytes, verified_generation)),  memo, };
    replay(&mut source, checkpoint.authority_root, context,
        ReplayLimits { payload_bytes: maximum, snapshot_bytes: maximum, buffer_bytes: maximum.saturating_mul(3) }).await
        .map(|r| r.bytes).map_err(|e| match e {
            ReplayError::Source(e) => e,
            ReplayError::Codec(DeltaError::Memory) => crate::StoreError::MemoryLimit,
            ReplayError::Codec(DeltaError::Invalid) => crate::StoreError::Corrupt,
        })
}

// Test-only provenance witness. It stores no duplicate snapshot or ancestor
// buffers, and can only be installed after a verified successful publication.
#[derive(Clone)]
pub(crate) struct VerifiedBaseForTest {
    generation: u64,
    root: vibeos_segment_format::PhysicalPointer,
    admitted: u64,
    next_segment: u64,
    store_uuid: vibeos_segment_format::StoreUuid,
    digest: [u8; 32],
    depth: u32,
}

impl VerifiedBaseForTest {
    pub(crate) fn from_published<E>(state: &crate::store::MountedState, depth: u32) -> Result<Self, crate::StoreError<E>> {
        let snapshot = state.persistent_authority.as_ref().ok_or(crate::StoreError::Corrupt)?;
        let metadata = encode_persistent_authority_metadata(snapshot).map_err(|_| crate::StoreError::Corrupt)?;
        Ok(Self { generation: state.generation, root: state.authority_root,
            admitted: state.admitted_segments, next_segment: state.next_segment_generation,
            store_uuid: state.superblock.binding.store_uuid,
            digest: snapshot_digest(&metadata, snapshot.record_stream()), depth })
    }

    pub(crate) fn matches(&self, state: &crate::store::MountedState) -> bool {
        Self::from_published::<()>(state, self.depth).is_ok_and(|other|
            self.generation == other.generation && self.root == other.root
            && self.admitted == other.admitted && self.next_segment == other.next_segment
            && self.store_uuid == other.store_uuid && self.digest == other.digest
            && self.depth <= MAX_REPLAY_DEPTH)
    }
}

pub(crate) async fn encode_next_for_test<D: crate::PageDevice>(
    device: &D,
    state: &crate::store::MountedState,
    next: &PersistentAuthoritySnapshot,
    maximum: usize,
    cached: Option<&VerifiedBaseForTest>,
) -> Result<(Vec<u8>, u32), crate::StoreError<D::Error>> {
    let context = LinkContext {
        store_uuid: state.superblock.binding.store_uuid,
        admitted_segments: state.admitted_segments,
        next_segment_generation: state.next_segment_generation,
        checkpoint_generation: next.checkpoint_generation(),
    };
    if let Some(cached) = cached.filter(|cached| cached.matches(state)) {
        let base = state.persistent_authority.as_ref().ok_or(crate::StoreError::Corrupt)?;
        if next.checkpoint_generation() <= base.checkpoint_generation() {
            return Err(crate::StoreError::Corrupt);
        }
        return match encode_link(base, next, state.authority_root, cached.depth, context)
            .map_err(|_| crate::StoreError::Corrupt)? {
            Some(bytes) => Ok((bytes, cached.depth + 1)),
            None => encode_persistent_authority_snapshot(next)
                .map(|bytes| (bytes, 0)).map_err(|_| crate::StoreError::Corrupt),
        };
    }
    let mut source = DeviceAuthoritySource { device, context, allocated: AllocatedSegments::Bitmap(&state.allocation), verified_tip: None,  memo: None, };
    let recovered = replay(&mut source, state.authority_root, context,
        ReplayLimits { payload_bytes: maximum, snapshot_bytes: maximum, buffer_bytes: maximum.saturating_mul(3) }).await
        .map_err(|_| crate::StoreError::Corrupt)?;
    match encode_replayed_link(&recovered, next, context).map_err(|_| crate::StoreError::Corrupt)? {
        Some(bytes) => Ok((bytes, recovered.depth + 1)),
        None => encode_persistent_authority_snapshot(next)
            .map(|bytes| (bytes, 0)).map_err(|_| crate::StoreError::Corrupt),
    }
}

pub(crate) async fn replay_device_for_test<D: crate::PageDevice>(
    device: &D,
    state: &crate::store::MountedState,
    maximum: usize,
) -> Result<Vec<u8>, crate::StoreError<D::Error>> {
    let context = LinkContext {
        store_uuid: state.superblock.binding.store_uuid,
        admitted_segments: state.admitted_segments,
        next_segment_generation: state.next_segment_generation,
        checkpoint_generation: state.generation,
    };
    let mut source = DeviceAuthoritySource {
        device,
        context,
        allocated: AllocatedSegments::Bitmap(&state.allocation),
        verified_tip: None,
     memo: None, };
    replay(
        &mut source,
        state.authority_root,
        context,
        ReplayLimits {
            payload_bytes: maximum,
            snapshot_bytes: maximum,
            buffer_bytes: maximum.saturating_mul(3),
        },
    )
    .await
    .map(|value| value.bytes)
    .map_err(|error| match error {
        ReplayError::Source(error) => error,
        ReplayError::Codec(DeltaError::Memory) => crate::StoreError::MemoryLimit,
        ReplayError::Codec(DeltaError::Invalid) => crate::StoreError::Corrupt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_snapshot::{PersistentPrincipalPolicy, StablePrincipalId};
    use alloc::vec;
    use vibeos_durable_format::{RecordBody, RecordChain, StoreId};

    #[test]
    fn borrowed_allocation_filters_retired_free_and_unadmitted_segments() {
        use crate::allocation_v2::{AllocationV2, RetiredSegment, SegmentAllocation};
        let mut states = vec![SegmentAllocation::Free; 4096];
        for index in (1..states.len()).step_by(7) {
            states[index] = SegmentAllocation::Allocated;
        }
        states[2] = SegmentAllocation::Retired;
        let map = AllocationV2::new(4, 5, 2, &states,
            &[RetiredSegment { segment_no: 2, retire_generation: 3 }]).unwrap();
        let borrowed = AllocatedSegments::Bitmap(&map);
        assert!(!borrowed.contains(0));
        assert!(borrowed.contains(1));
        assert!(!borrowed.contains(2));
        assert!(!borrowed.contains(4096));
        assert!(!borrowed.contains(u64::MAX));
        for admitted in [0, 1, 2, 100, 4096, 4100] {
            let expected: Vec<_> = states.iter().enumerate()
                .take(admitted as usize)
                .filter(|(_, state)| **state == SegmentAllocation::Allocated)
                .map(|(index, _)| index as u64).collect();
            assert_eq!(borrowed.iter(admitted).collect::<Vec<_>>(), expected);
        }
    }

    #[test]
    fn replay_table_budget_covers_reallocation_and_retained_capacity() {
        let mut table = Vec::<u64>::new();
        let mut resident = 100;
        let mut peak = resident;
        assert_eq!(reserve_replay_entry(&mut table, &mut resident, &mut peak, 107),
            Err(DeltaError::Memory));
        assert_eq!((table.capacity(), resident, peak), (0, 100, 100));
        reserve_replay_entry(&mut table, &mut resident, &mut peak, 108).unwrap();
        table.push(9);
        assert_eq!((resident, peak), (108, 108));
        // Growing to two entries needs old + replacement, not just the net
        // increase. Rejection must happen before changing the allocation.
        assert_eq!(reserve_replay_entry(&mut table, &mut resident, &mut peak, 123),
            Err(DeltaError::Memory));
        assert_eq!((table.capacity(), resident, peak), (1, 108, 108));
        assert_eq!(table, vec![9]);
        reserve_replay_entry(&mut table, &mut resident, &mut peak, 124).unwrap();
        table.push(10);
        assert_eq!((resident, peak), (116, 124));
        table.pop();
        // Pop releases the entry's payload elsewhere, but not this table's
        // backing allocation. Reusing its spare entry adds no allocation.
        reserve_replay_entry(&mut table, &mut resident, &mut peak, 116).unwrap();
        assert_eq!((table.capacity(), resident, peak), (2, 116, 124));
    }

    #[derive(Clone)]
    struct Source {
        entries: Vec<(vibeos_segment_format::PhysicalPointer, Vec<u8>, u64)>,
        calls: usize,
    }
    impl AuthoritySource for Source {
        type Error = &'static str;
        async fn read(
            &mut self,
            pointer: vibeos_segment_format::PhysicalPointer,
            maximum: usize,
        ) -> Result<(Vec<u8>, u64), Self::Error> {
            self.calls += 1;
            let (_, bytes, generation) = self
                .entries
                .iter()
                .find(|(p, _, _)| *p == pointer)
                .ok_or("missing")?;
            let vibeos_segment_format::PhysicalPointer::Value(value) = pointer else {
                return Err("null");
            };
            if bytes.len() > maximum {
                return Err("budget");
            }
            if bytes.len() as u64 != value.exact_byte_len || digest(bytes) != value.payload_sha256 {
                return Err("damaged");
            }
            Ok((bytes.clone(), *generation))
        }
    }
    fn run<F: core::future::Future>(future: F) -> F::Output {
        let mut future = alloc::boxed::Box::pin(future);
        loop {
            match future.as_mut().poll(&mut core::task::Context::from_waker(
                core::task::Waker::noop(),
            )) {
                core::task::Poll::Ready(result) => return result,
                core::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[derive(Default)]
    struct Media {
        pages: core::cell::RefCell<std::collections::BTreeMap<u64, vibeos_segment_format::Page>>,
        writes: core::cell::Cell<usize>,
        reads: core::cell::Cell<usize>,
    }
    impl crate::PageDevice for Media {
        type Error = ();
        fn info(&self) -> crate::PageDeviceInfo {
            crate::PageDeviceInfo {
                device_id: [7; 16],
                range_first_logical_block: 0,
                logical_block_count: 16 * 1024 * 8 + 16 * 8,
                logical_block_size: 512,
                page_count: 16 * 1024 + 16,
            }
        }
        async fn read_page(
            &self,
            page: u64,
            output: &mut vibeos_segment_format::Page,
        ) -> Result<(), ()> {
            self.reads.set(self.reads.get() + 1);
            *output = self.pages.borrow().get(&page).copied().unwrap_or([0; 4096]);
            Ok(())
        }
        async fn write_page(
            &self,
            page: u64,
            input: &vibeos_segment_format::Page,
        ) -> vibeos_storage_device::MutationResult<(), ()> {
            self.pages.borrow_mut().insert(page, *input);
            self.writes.set(self.writes.get() + 1);
            Ok(())
        }
        async fn flush(&self) -> vibeos_storage_device::MutationResult<(), ()> {
            Ok(())
        }
    }

    async fn write_authority_fixture(
        device: &Media,
        context: LinkContext,
        segment: u64,
        generation: u64,
        payload: &[u8],
    ) -> vibeos_segment_format::PhysicalPointer {
        use vibeos_segment_format::*;
        let base = segment_base_page(segment).unwrap();
        let header = SegmentHeader {
            binding: RecordBinding {
                store_uuid: context.store_uuid,
                generation: segment + 1,
                segment_no: segment,
                ordinal: 0,
                self_page: base,
                target_checkpoint_generation: generation,
            },
            base_page: base,
            previous_segment_no: ANCHOR_SEGMENT_NO,
            previous_segment_generation: 0,
            previous_segment_seal_body_sha256: [0; 32],
        };
        let mut body = [0; PAGE_SIZE];
        let mut seal = [0; PAGE_SIZE];
        let header_digest = encode_segment_header_body(&header, &mut body).unwrap();
        encode_record_seal(header_digest, &mut seal).unwrap();
        let record = crate::cas::build_record(
            context.store_uuid,
            segment,
            segment + 1,
            generation,
            1,
            DATA_FIRST_PAGE,
            ExtentKind::Authority,
            0xffff0021,
            0,
            1,
            payload.len() as u64,
            payload.len() as u64,
            0,
            payload.len() as u64,
            digest(payload),
            digest(payload),
        )
        .unwrap();
        let pointer = record.pointer();
        crate::cas::write_payload_records_with_header(
            device,
            base,
            Some((&body, &seal)),
            &[(&record, payload)],
            false,
            None,
        )
        .await
        .unwrap();
        crate::cas::finalize_segment(
            device,
            context.store_uuid,
            generation,
            segment,
            segment + 1,
            header_digest,
            &[record],
            false,
            None,
        )
        .await
        .unwrap();
        pointer
    }

    #[test]
    fn sealed_device_delta_replays_and_rejects_damaged_ancestor_frames() {
        use vibeos_segment_format::*;
        let device = Media::default();
        let (_, mut context) = link_fixture();
        context.checkpoint_generation = 5;
        let (base, next) = pair();
        let before = encode_persistent_authority_snapshot(&base).unwrap();
        let mut chain = RecordChain::new(StoreId::new(7).unwrap());
        let mut records = chain.append(None, RecordBody::Format).unwrap().to_vec();
        for exclusive_end in [32, 64, 128] {
            records.extend_from_slice(
                &chain
                    .append(None, RecordBody::IdHighWater { exclusive_end })
                    .unwrap(),
            );
        }
        let final_snapshot =
            PersistentAuthoritySnapshot::new(5, [3; 32], records, vec![], vec![]).unwrap();
        let after = encode_persistent_authority_snapshot(&final_snapshot).unwrap();
        let predecessor = run(write_authority_fixture(&device, context, 0, 3, &before));
        let delta = encode_link(&base, &next, predecessor, 0, context)
            .unwrap()
            .unwrap();
        let middle = run(write_authority_fixture(&device, context, 1, 4, &delta));
        let second = encode_link(&next, &final_snapshot, middle, 1, context)
            .unwrap()
            .unwrap();
        let tip = run(write_authority_fixture(&device, context, 2, 5, &second));
        // Optional cross-language fixtures; never used by production code.
        if let Some(directory) = std::env::var_os("VIBE_AUTHORITY_DELTA_FIXTURES") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            for (name, bytes) in [
                ("base.bin", before.as_slice()),
                ("first.bin", delta.as_slice()),
                (
                    "middle.bin",
                    encode_persistent_authority_snapshot(&next)
                        .unwrap()
                        .as_slice(),
                ),
                ("second.bin", second.as_slice()),
                ("result.bin", after.as_slice()),
            ] {
                std::fs::write(directory.join(name), bytes).unwrap();
            }
        }

        let mut source = DeviceAuthoritySource {
            device: &device,
            context,
            allocated: AllocatedSegments::Fixture(&[0, 1, 2]),
            verified_tip: None,
         memo: None, };
        let budget = before.len() + delta.len() + second.len();
        let limits = || ReplayLimits {
            payload_bytes: budget,
            snapshot_bytes: after.len(),
            buffer_bytes: MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN.saturating_mul(3),
        };
        let writes = device.writes.get();
        let reads_before = device.reads.get();
        let result = run(replay(&mut source, tip, context, limits())).unwrap();
        let unseeded_reads = device.reads.get() - reads_before;
        assert_eq!(result.bytes, after);
        // Mount has already authenticated this exact tip. Transfer its owned
        // payload once, and compare device reads with an unseeded replay.
        let (verified_bytes, verified_generation) = run(source.read(tip, budget)).unwrap();
        source.verified_tip = Some((tip, verified_bytes, verified_generation));
        let reads_before = device.reads.get();
        let seeded = run(replay(&mut source, tip, context, limits())).unwrap();
        let seeded_reads = device.reads.get() - reads_before;
        assert_eq!(seeded.bytes, after);
        assert_eq!(seeded.payload_bytes, result.payload_bytes);
        assert!(source.verified_tip.is_none(), "verified payload must be consumed once");
        assert!(seeded_reads < unseeded_reads);
        std::println!("verified tip transfer: replay reads {unseeded_reads} -> {seeded_reads} pages (initial read excluded from both)");
        assert_eq!(result.depth, 2);
        assert_eq!(result.ancestors, vec![tip, middle, predecessor]);
        assert_eq!(result.payload_bytes, budget);
        assert_eq!(device.writes.get(), writes);
        let base_page = segment_base_page(0).unwrap();
        for relative in [
            DATA_FIRST_PAGE,
            DATA_FIRST_PAGE + 1,
            DATA_FIRST_PAGE + 2,
            SUMMARY_SEAL_PAGE,
            SEGMENT_SEAL_PAGE,
        ] {
            let page = base_page + u64::from(relative);
            let saved = device.pages.borrow()[&page];
            device.pages.borrow_mut().get_mut(&page).unwrap()[0] ^= 1;
            assert!(
                run(replay(&mut source, tip, context, limits())).is_err(),
                "ancestor page {relative}"
            );
            assert_eq!(device.writes.get(), writes);
            device.pages.borrow_mut().insert(page, saved);
        }
        let middle_page = segment_base_page(1).unwrap() + u64::from(DATA_FIRST_PAGE + 2);
        let saved = device.pages.borrow_mut().remove(&middle_page).unwrap();
        assert!(run(replay(&mut source, tip, context, limits())).is_err());
        device.pages.borrow_mut().insert(middle_page, saved);
        assert_eq!(device.writes.get(), writes);
        let mut unallocated = DeviceAuthoritySource {
            device: &device,
            context,
            allocated: AllocatedSegments::Fixture(&[1, 2]),
            verified_tip: None,
         memo: None, };
        assert!(run(replay(&mut unallocated, tip, context, limits())).is_err());
        // GC's existing writer uses relocated() and emits a full snapshot.
        // Prove the resulting root is independent of the old delta ancestors.
        let relocated = final_snapshot.relocated(6).unwrap();
        let full = encode_persistent_authority_snapshot(&relocated).unwrap();
        context.checkpoint_generation = 6;
        let full_root = run(write_authority_fixture(&device, context, 3, 6, &full));
        // A complete root-segment payload must never enumerate other segments.
        // Panic on iteration catches an accidental eager allocation-map walk.
        let (direct, _) = run(crate::store::read_pointer_authority_payload(
            &device,
            context.store_uuid,
            context.admitted_segments,
            context.next_segment_generation,
            context.checkpoint_generation,
            full_root,
            core::iter::from_fn(|| -> Option<u64> {
                panic!("single-segment authority enumerated allocation map")
            }),
            full.len(),
        )).unwrap();
        assert_eq!(direct, full);

        let mut old_source = DeviceAuthoritySource {
            device: &device,
            context,
            allocated: AllocatedSegments::Fixture(&[0, 1, 2, 3]),
            verified_tip: None,
         memo: None, };
        assert_eq!(
            run(replay(&mut old_source, tip, context, limits()))
                .unwrap()
                .bytes,
            after
        );
        let mut new_source = DeviceAuthoritySource {
            device: &device,
            context,
            allocated: AllocatedSegments::Fixture(&[3]),
            verified_tip: None,
         memo: None, };
        let result = run(replay(
            &mut new_source,
            full_root,
            context,
            ReplayLimits {
                payload_bytes: full.len(),
                snapshot_bytes: full.len(),
                buffer_bytes: MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN.saturating_mul(3),
            },
        ))
        .unwrap();
        assert_eq!(result.depth, 0);
        assert_eq!(result.ancestors, vec![full_root]);
        assert_eq!(result.bytes, full);
        let first_old_page = segment_base_page(0).unwrap();
        let old_end = segment_base_page(3).unwrap();
        device
            .pages
            .borrow_mut()
            .retain(|&page, _| page < first_old_page || page >= old_end);
        assert!(run(replay(&mut old_source, tip, context, limits())).is_err());
        assert_eq!(
            run(replay(
                &mut new_source,
                full_root,
                context,
                ReplayLimits {
                    payload_bytes: full.len(),
                    snapshot_bytes: full.len(),
                    buffer_bytes: MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN.saturating_mul(3),
                }
            ))
            .unwrap()
            .bytes,
            full
        );
        // Append after materialization starts from depth zero, not the old
        // chain's depth; old segments need not be allocated or readable.
        let mut chain = RecordChain::new(StoreId::new(7).unwrap());
        let mut records = chain.append(None, RecordBody::Format).unwrap().to_vec();
        for exclusive_end in [32, 64, 128, 256] {
            records.extend_from_slice(
                &chain
                    .append(None, RecordBody::IdHighWater { exclusive_end })
                    .unwrap(),
            );
        }
        let resumed =
            PersistentAuthoritySnapshot::new(7, [3; 32], records, vec![], vec![]).unwrap();
        context.checkpoint_generation = 7;
        let link = encode_link(&relocated, &resumed, full_root, 0, context)
            .unwrap()
            .unwrap();
        let resumed_root = run(write_authority_fixture(&device, context, 4, 7, &link));
        let expected = encode_persistent_authority_snapshot(&resumed).unwrap();
        let mut resumed_source = DeviceAuthoritySource {
            device: &device,
            context,
            allocated: AllocatedSegments::Fixture(&[3, 4]),
            verified_tip: None,
         memo: None, };
        let result = run(replay(
            &mut resumed_source,
            resumed_root,
            context,
            ReplayLimits {
                payload_bytes: full.len() + link.len(),
                snapshot_bytes: expected.len(),
                buffer_bytes: MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN.saturating_mul(3),
            },
        ))
        .unwrap();
        assert_eq!(result.bytes, expected);
        assert_eq!(result.depth, 1);
        assert_eq!(result.ancestors, vec![resumed_root, full_root]);
    }

    fn pair() -> (PersistentAuthoritySnapshot, PersistentAuthoritySnapshot) {
        let mut chain = RecordChain::new(StoreId::new(7).unwrap());
        let mut records = chain.append(None, RecordBody::Format).unwrap().to_vec();
        records.extend_from_slice(
            &chain
                .append(None, RecordBody::IdHighWater { exclusive_end: 32 })
                .unwrap(),
        );
        let base =
            PersistentAuthoritySnapshot::new(3, [1; 32], records.clone(), vec![], vec![]).unwrap();
        records.extend_from_slice(
            &chain
                .append(None, RecordBody::IdHighWater { exclusive_end: 64 })
                .unwrap(),
        );
        let next = PersistentAuthoritySnapshot::new(
            4,
            [2; 32],
            records,
            vec![],
            vec![PersistentPrincipalPolicy {
                principal: StablePrincipalId::new([3; 16]).unwrap(),
                logical_limit_bytes: 100,
                physical_limit_bytes: 200,
                committed_logical_bytes: 10,
                committed_physical_bytes: 20,
                admission_revoked: true,
            }],
        )
        .unwrap();
        (base, next)
    }

    fn link_fixture() -> (vibeos_segment_format::PhysicalPointer, LinkContext) {
        use vibeos_segment_format::{ExtentKind, PhysicalPointer, PointerValue, StoreUuid};
        let store_uuid = StoreUuid::new([7; 16]).unwrap();
        (
            PhysicalPointer::Value(PointerValue {
                store_uuid,
                segment_no: 1,
                segment_generation: 2,
                descriptor_relative_page: 2,
                payload_relative_page: 4,
                payload_pages: 1,
                ordinal: 1,
                exact_byte_len: 1152,
                extent_kind: ExtentKind::Authority,
                payload_sha256: [9; 32],
            }),
            LinkContext {
                store_uuid,
                admitted_segments: 16,
                next_segment_generation: 8,
                checkpoint_generation: 4,
            },
        )
    }

    #[test]
    fn replayed_legacy_base_requires_full_materialization_before_delta() {
        use vibeos_segment_format::PhysicalPointer;
        let (base, next) = pair();
        let (pointer, context) = link_fixture();
        let canonical = encode_persistent_authority_snapshot(&base).unwrap();
        let mut legacy = canonical.clone();
        legacy[8..10].copy_from_slice(&1_u16.to_le_bytes());
        legacy[0x70..0x80].fill(0);
        for (bytes, expect_delta) in [(legacy, false), (canonical.clone(), true)] {
            let check_borrowed = |input: &[u8]| {
                let owned = decode_persistent_authority_snapshot(input)
                    .map(|snapshot| snapshot.checkpoint_generation());
                assert_eq!(validate_authority_bytes(input).map(|(generation, _)| generation),
                    owned);
            };
            check_borrowed(&bytes);
            for end in 0..bytes.len() {
                check_borrowed(&bytes[..end]);
            }
            let mut mutated = bytes.clone();
            for at in 0..mutated.len() {
                mutated[at] ^= 1;
                check_borrowed(&mutated);
                mutated[at] ^= 1;
            }
            let PhysicalPointer::Value(mut value) = pointer else { unreachable!() };
            value.exact_byte_len = bytes.len() as u64;
            value.payload_sha256 = digest(&bytes);
            let actual = PhysicalPointer::Value(value);
            let mut source = Source { entries: vec![(actual, bytes.clone(), 3)], calls: 0 };
            let recovered = run(replay(&mut source, actual, context, ReplayLimits {
                payload_bytes: bytes.len(), snapshot_bytes: bytes.len(),
                buffer_bytes: MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN.saturating_mul(3),
            })).unwrap();
            let selected = encode_replayed_link(&recovered, &next, context).unwrap();
            assert_eq!(selected.is_some(), expect_delta);
            if let Some(delta) = selected {
                assert_eq!(apply_link(actual, &bytes, 0, &delta, context).unwrap(),
                    encode_persistent_authority_snapshot(&next).unwrap());
            } else {
                // Reading V1 is supported, but a canonically encoded delta
                // against that decoded snapshot cannot replay over V1 bytes.
                let unsafe_delta = encode_link(&base, &next, actual, 0, context).unwrap().unwrap();
                assert!(apply_link(actual, &bytes, 0, &unsafe_delta, context).is_err());
            }
            assert!(encode_replayed_link(&recovered, &base, context).is_err());
            let mut stale_context = context;
            stale_context.checkpoint_generation = base.checkpoint_generation();
            assert!(encode_replayed_link(&recovered, &next, stale_context).is_err());

            let mut damaged = recovered;
            damaged.bytes[0] ^= 1;
            assert!(encode_replayed_link(&damaged, &next, context).is_err());
        }
    }

    #[test]
    fn reserved_link_prefix_preserves_exact_delta_bytes_and_size_fallback() {
        let (base, next) = pair();
        let raw = encode(&base, &next).unwrap().unwrap();
        let full = persistent_authority_encoded_len(&next).unwrap();
        for prefix in [0, 1, LINK_HEADER] {
            let framed = encode_with_prefix(&base, &next, prefix).unwrap().unwrap();
            assert_eq!(framed.len(), prefix + raw.len());
            assert!(framed[..prefix].iter().all(|byte| *byte == 0));
            assert_eq!(&framed[prefix..], raw.as_slice());
        }
        assert!(encode_with_prefix(&base, &next, full - raw.len()).unwrap().is_none());
        assert!(matches!(encode_with_prefix(&base, &next, usize::MAX), Err(DeltaError::Invalid)));
        let (pointer, context) = link_fixture();
        let link = encode_link(&base, &next, pointer, 0, context).unwrap().unwrap();
        assert_eq!(decode_link(&link, context).unwrap().delta, raw.as_slice());
    }

    #[test]
    fn physical_link_binds_context_generation_and_observed_depth() {
        use vibeos_segment_format::{ExtentKind, PhysicalPointer};
        let (base, next) = pair();
        let (pointer, context) = link_fixture();
        let before = encode_persistent_authority_snapshot(&base).unwrap();
        let after = encode_persistent_authority_snapshot(&next).unwrap();
        let bytes = encode_link(&base, &next, pointer, 0, context)
            .unwrap()
            .unwrap();
        assert_eq!(
            apply_link(pointer, &before, 0, &bytes, context).unwrap(),
            after
        );
        assert!(apply_link(pointer, &before, 1, &bytes, context).is_err());
        assert!(apply_link(PhysicalPointer::Null, &before, 0, &bytes, context).is_err());
        assert!(
            encode_link(&base, &next, pointer, MAX_REPLAY_DEPTH, context)
                .unwrap()
                .is_none()
        );
        assert!(encode_link(&base, &next, pointer, u32::MAX, context)
            .unwrap()
            .is_none());
        let PhysicalPointer::Value(value) = pointer else {
            unreachable!()
        };
        let mut wrong = value;
        wrong.extent_kind = ExtentKind::Blob;
        assert!(encode_link(&base, &next, PhysicalPointer::Value(wrong), 0, context).is_err());
        let mut wrong_context = context;
        wrong_context.admitted_segments = 1;
        assert!(decode_link(&bytes, wrong_context).is_err());
        wrong_context = context;
        wrong_context.next_segment_generation = 2;
        assert!(decode_link(&bytes, wrong_context).is_err());
        wrong_context = context;
        wrong_context.checkpoint_generation = 3;
        assert!(decode_link(&bytes, wrong_context).is_err());
        wrong_context = context;
        wrong_context.store_uuid = vibeos_segment_format::StoreUuid::new([8; 16]).unwrap();
        assert!(decode_link(&bytes, wrong_context).is_err());
        // A forged smaller depth cannot shorten the observed chain.
        let deep = encode_link(&base, &next, pointer, MAX_REPLAY_DEPTH - 1, context)
            .unwrap()
            .unwrap();
        assert!(apply_link(pointer, &before, 0, &deep, context).is_err());
        assert_eq!(
            apply_link(pointer, &before, MAX_REPLAY_DEPTH - 1, &deep, context).unwrap(),
            after
        );
        for at in [112, 120] {
            let mut bad = bytes.clone();
            bad[at] ^= 1;
            assert!(apply_link(pointer, &before, 0, &bad, context).is_err());
        }
    }

    #[test]
    fn replay_to_limit_matches_full_snapshots_and_then_falls_back() {
        use vibeos_segment_format::{ExtentKind, PhysicalPointer, PointerValue, PAGE_SIZE};
        let (_, mut context) = link_fixture();
        context.admitted_segments = 64;
        context.next_segment_generation = 64;
        context.checkpoint_generation = 64;
        let mut chain = RecordChain::new(StoreId::new(7).unwrap());
        let mut records = chain.append(None, RecordBody::Format).unwrap().to_vec();
        let mut base =
            PersistentAuthoritySnapshot::new(1, [1; 32], records.clone(), vec![], vec![]).unwrap();
        let mut reconstructed = encode_persistent_authority_snapshot(&base).unwrap();
        let mut physical = reconstructed.clone();
        let mut source = Source {
            entries: vec![],
            calls: 0,
        };
        let mut tip = PhysicalPointer::Null;
        for depth in 1..=MAX_REPLAY_DEPTH + 1 {
            records.extend_from_slice(
                &chain
                    .append(
                        None,
                        RecordBody::IdHighWater {
                            exclusive_end: 32 * u128::from(depth),
                        },
                    )
                    .unwrap(),
            );
            let next = PersistentAuthoritySnapshot::new(
                u64::from(depth) + 1,
                [1; 32],
                records.clone(),
                vec![],
                vec![],
            )
            .unwrap();
            let pointer = PhysicalPointer::Value(PointerValue {
                store_uuid: context.store_uuid,
                segment_no: u64::from(depth),
                segment_generation: u64::from(depth),
                descriptor_relative_page: 2,
                payload_relative_page: 4,
                payload_pages: physical.len().div_ceil(PAGE_SIZE) as u32,
                ordinal: 1,
                exact_byte_len: physical.len() as u64,
                extent_kind: ExtentKind::Authority,
                payload_sha256: digest(&physical),
            });
            source
                .entries
                .push((pointer, physical.clone(), base.checkpoint_generation()));
            tip = pointer;
            let result = encode_link(&base, &next, pointer, depth - 1, context).unwrap();
            if depth > MAX_REPLAY_DEPTH {
                assert!(result.is_none());
                break;
            }
            let bytes = result.unwrap();
            let next_bytes = encode_persistent_authority_snapshot(&next).unwrap();
            reconstructed =
                apply_link(pointer, &reconstructed, depth - 1, &bytes, context).unwrap();
            assert_eq!(reconstructed, next_bytes, "depth {depth}");
            let mut false_depth = bytes.clone();
            false_depth[8..12].copy_from_slice(&(depth - 1).to_le_bytes());
            assert!(apply_link(pointer, &reconstructed, depth, &false_depth, context).is_err());
            physical = bytes;
            base = next;
        }
        let budget = source
            .entries
            .iter()
            .map(|(_, b, _)| b.len())
            .sum::<usize>();
        let replayed = run(replay(
            &mut source,
            tip,
            context,
            ReplayLimits {
                payload_bytes: budget,
                snapshot_bytes: reconstructed.len(),
                buffer_bytes: MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN.saturating_mul(3),
            },
        ))
        .unwrap();
        assert_eq!(replayed.bytes, reconstructed);
        assert_eq!(replayed.depth, MAX_REPLAY_DEPTH);
        assert_eq!(replayed.ancestors.len(), MAX_REPLAY_DEPTH as usize + 1);
        assert_eq!(replayed.payload_bytes, budget);
        let successor = PersistentAuthoritySnapshot::new(
            base.checkpoint_generation() + 1, [1; 32], records.clone(), vec![], vec![],
        ).unwrap();
        assert!(encode_replayed_link(&replayed, &successor, context).unwrap().is_none());

        assert_eq!(source.calls, MAX_REPLAY_DEPTH as usize + 1);
        let limits = || ReplayLimits {
            payload_bytes: budget,
            snapshot_bytes: reconstructed.len(),
            buffer_bytes: MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN.saturating_mul(3),
        };
        let peak = replayed.peak_buffer_bytes;
        assert!(peak > reconstructed.len());
        let exact = run(replay(&mut source, tip, context, ReplayLimits {
            buffer_bytes: peak, ..limits()
        })).unwrap();
        assert_eq!(exact.bytes, reconstructed);
        assert_eq!(exact.peak_buffer_bytes, peak);
        assert!(matches!(run(replay(&mut source, tip, context, ReplayLimits {
            buffer_bytes: peak - 1, ..limits()
        })), Err(ReplayError::Codec(DeltaError::Memory))));
        let mut unread = source.clone();
        unread.calls = 0;
        let PhysicalPointer::Value(tip_value) = tip else { unreachable!() };
        assert!(matches!(run(replay(&mut unread, tip, context, ReplayLimits {
            buffer_bytes: tip_value.exact_byte_len as usize - 1, ..limits()
        })), Err(ReplayError::Codec(DeltaError::Memory))));
        assert_eq!(unread.calls, 0, "known payload cannot fit: reject before source allocation");
        std::println!("32-link owned buffer/table peak: {peak} bytes; exact budget passes, one byte less rejects");
        assert!(run(replay(
            &mut source,
            tip,
            context,
            ReplayLimits {
                payload_bytes: budget - 1,
                ..limits()
            }
        ))
        .is_err());
        assert!(run(replay(
            &mut source,
            tip,
            context,
            ReplayLimits {
                snapshot_bytes: reconstructed.len() - 1,
                ..limits()
            }
        ))
        .is_err());
        let mut damaged = source.clone();
        damaged.entries[0].1[0] ^= 1;
        assert!(run(replay(&mut damaged, tip, context, limits())).is_err());
        let mut missing = source.clone();
        missing.entries.remove(10);
        assert!(run(replay(&mut missing, tip, context, limits())).is_err());
        let mut wrong_generation = source.clone();
        wrong_generation.entries[0].2 += 1;
        assert!(run(replay(&mut wrong_generation, tip, context, limits())).is_err());
    }

    #[test]
    fn round_trip_preserves_changed_policy_and_principal_tables() {
        let (base, mut next) = pair();
        next.objects
            .push(crate::authority_snapshot::PersistentObjectBinding {
                stable_object_id: 11,
                v2_object_id: 12,
                commit_generation: 4,
                object_kind: 5,
            });
        let next = next
            .with_external_roots(vec![crate::root_codec::PersistentRootEntry {
                object_id: 13,
                commit_generation: 4,
                object_kind: 6,
            }])
            .unwrap();
        let delta = encode(&base, &next).unwrap().unwrap();
        let before = encode_persistent_authority_snapshot(&base).unwrap();
        let after = encode_persistent_authority_snapshot(&next).unwrap();
        let check_borrowed = |bytes: &[u8]| {
            let owned_canonical = decode_persistent_authority_snapshot(bytes)
                .and_then(|value| encode_persistent_authority_snapshot(&value))
                .is_ok_and(|encoded| encoded == bytes);
            assert_eq!(validate_canonical_authority_bytes(bytes).is_ok(), owned_canonical);
        };
        for (snapshot, full) in [(&base, &before), (&next, &after)] {
            let metadata = encode_persistent_authority_metadata(snapshot).unwrap();
            assert_eq!(metadata, full[..full.len() - snapshot.record_stream().len()]);
            assert_eq!(snapshot_digest(&metadata, snapshot.record_stream()), digest(full));
            assert_eq!(persistent_authority_encoded_len(snapshot).unwrap(), full.len());
            assert!(canonical_snapshot_matches(snapshot, full).unwrap());
            check_borrowed(full);
            // The split comparison must be exactly as strict as comparing the
            // full canonical encoding, including reserved bytes and suffixes.
            for len in 0..full.len() {
                assert!(!canonical_snapshot_matches(snapshot, &full[..len]).unwrap());
                check_borrowed(&full[..len]);
            }
            let mut damaged = full.clone();
            for at in 0..damaged.len() {
                damaged[at] ^= 1;
                assert!(!canonical_snapshot_matches(snapshot, &damaged).unwrap());
                check_borrowed(&damaged);
                damaged[at] ^= 1;
            }
            damaged.push(0);
            assert!(!canonical_snapshot_matches(snapshot, &damaged).unwrap());
            check_borrowed(&damaged);

        }

        if let Some(directory) = std::env::var_os("VIBE_AUTHORITY_DELTA_FIXTURES") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            let (pointer, context) = link_fixture();
            let linked = encode_link(&base, &next, pointer, 0, context)
                .unwrap()
                .unwrap();
            for (name, bytes) in [
                ("rich-base.bin", &before),
                ("rich-link.bin", &linked),
                ("rich-result.bin", &after),
            ] {
                std::fs::write(directory.join(name), bytes).unwrap();
            }
        }
        assert_eq!(reconstruct(&before, &delta).unwrap(), after);
        assert_eq!(
            after.len() - delta.len(),
            base.record_stream().len() - HEADER
        );
        assert!(encode(&next, &base).unwrap().is_none());
        assert!(encode(&base, &base).unwrap().is_none());
    }

    #[test]
    fn rewritten_or_nonappending_history_falls_back_to_snapshot() {
        let (base, next) = pair();
        let same_stream = PersistentAuthoritySnapshot::new(
            5,
            [4; 32],
            base.record_stream().to_vec(),
            vec![],
            vec![],
        )
        .unwrap();
        assert!(encode(&base, &same_stream).unwrap().is_none());
        let mut chain = RecordChain::new(StoreId::new(8).unwrap());
        let mut records = chain.append(None, RecordBody::Format).unwrap().to_vec();
        for exclusive_end in [32, 64, 128] {
            records.extend_from_slice(
                &chain
                    .append(None, RecordBody::IdHighWater { exclusive_end })
                    .unwrap(),
            );
        }
        let rewritten =
            PersistentAuthoritySnapshot::new(6, [4; 32], records, vec![], vec![]).unwrap();
        assert!(encode(&base, &rewritten).unwrap().is_none());
        let delta = encode(&base, &next).unwrap().unwrap();
        let wrong_base = encode_persistent_authority_snapshot(&same_stream).unwrap();
        assert!(reconstruct(&wrong_base, &delta).is_err());
    }

    #[test]
    fn every_truncation_and_single_byte_corruption_is_rejected() {
        let (base, next) = pair();
        let before = encode_persistent_authority_snapshot(&base).unwrap();
        let delta = encode(&base, &next).unwrap().unwrap();
        for len in 0..delta.len() {
            assert!(reconstruct(&before, &delta[..len]).is_err(), "prefix {len}");
        }
        for i in 0..delta.len() {
            let mut bad = delta.clone();
            bad[i] ^= 1;
            assert!(reconstruct(&before, &bad).is_err(), "delta byte {i}");
        }
        let mut tail = delta.clone();
        tail.push(0);
        assert!(reconstruct(&before, &tail).is_err());
        for i in 0..before.len() {
            let mut bad = before.clone();
            bad[i] ^= 1;
            assert!(reconstruct(&bad, &delta).is_err(), "base byte {i}");
        }
    }

    #[test]
    fn bounds_and_record_chain_are_checked_even_with_recomputed_digest() {
        let (base, next) = pair();
        let before = encode_persistent_authority_snapshot(&base).unwrap();
        let after = encode_persistent_authority_snapshot(&next).unwrap();
        let delta = encode(&base, &next).unwrap().unwrap();
        for at in [16, 24, 32, 40, 48] {
            let mut bad = delta.clone();
            bad[at..at + 8].fill(255);
            assert!(reconstruct(&before, &bad).is_err());
        }
        let mut bad = delta.clone();
        *bad.last_mut().unwrap() ^= 1;
        let mut changed = after;
        *changed.last_mut().unwrap() ^= 1;
        bad[88..120].copy_from_slice(&digest(&changed));
        assert!(reconstruct(&before, &bad).is_err());
    }
}
