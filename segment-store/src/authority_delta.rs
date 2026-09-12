//! Experimental authority append payload codec, available to tests and the
//! explicit experimental-authority-delta feature. Default builds reject this
//! format. Full publication-memory admission and deployment remain incomplete.

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
    encode_with_prefix_bounded(base, next, prefix, usize::MAX).map(|(bytes, _)| bytes)
}

// The caller owns both input snapshots. Charge encoder allocations only and
// release predecessor metadata before reserving the final delta buffer.
fn encode_with_prefix_bounded(
    base: &PersistentAuthoritySnapshot,
    next: &PersistentAuthoritySnapshot,
    prefix: usize,
    maximum_bytes: usize,
) -> Result<(Option<Vec<u8>>, usize), DeltaError> {
    if next.checkpoint_generation() <= base.checkpoint_generation()
        || next.record_stream().len() <= base.record_stream().len()
        || !next.record_stream().starts_with(base.record_stream())
    {
        return Ok((None, 0));
    }
    let (before, mut peak) = crate::authority_snapshot::encode_snapshot_bounded(
        base, false, maximum_bytes,
    ).map_err(metadata_error)?;
    let after_budget = maximum_bytes.checked_sub(before.capacity()).ok_or(DeltaError::Memory)?;
    let (after, after_peak) = crate::authority_snapshot::encode_snapshot_bounded(
        next, false, after_budget,
    ).map_err(metadata_error)?;
    peak = peak.max(before.capacity().checked_add(after_peak).ok_or(DeltaError::Memory)?);
    let base_offset = before.len();
    let next_offset = after.len();
    let base_len = persistent_authority_encoded_len(base).map_err(metadata_error)?;
    let next_len = persistent_authority_encoded_len(next).map_err(metadata_error)?;
    let common = base.record_stream().len();
    let len = prefix.checked_add(HEADER)
        .and_then(|n| n.checked_add(next_len - common))
        .ok_or(DeltaError::Invalid)?;
    if len >= next_len {
        return Ok((None, peak));
    }
    let before_digest = snapshot_digest(&before, base.record_stream());
    drop(before);
    let output_budget = maximum_bytes.checked_sub(after.capacity()).ok_or(DeltaError::Memory)?;
    if len > output_budget { return Err(DeltaError::Memory); }
    let mut output = Vec::new();
    output
        .try_reserve_exact(len)
        .map_err(|_| DeltaError::Memory)?;
    if output.capacity() > output_budget { return Err(DeltaError::Memory); }
    peak = peak.max(after.capacity().checked_add(output.capacity()).ok_or(DeltaError::Memory)?);
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
    header[56..88].copy_from_slice(&before_digest);
    header[88..120].copy_from_slice(&snapshot_digest(&after, next.record_stream()));
    output.extend_from_slice(&after);
    output.extend_from_slice(&next.record_stream()[common..]);
    Ok((Some(output), peak))
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
    reconstruct_checked_bounded(base, delta, usize::MAX).map(|(bytes, before, after, _)| (bytes, before, after))
}

fn metadata_error(error: crate::authority_snapshot::AuthoritySnapshotError) -> DeltaError {
    match error {
        crate::authority_snapshot::AuthoritySnapshotError::MemoryLimit => DeltaError::Memory,
        _ => DeltaError::Invalid,
    }
}

#[cfg(test)]
std::thread_local! {
    static SNAPSHOT_VALIDATION_PASSES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

// This proof borrows the exact immutable bytes that passed complete snapshot
// and semantic validation. It cannot outlive or be applied to another buffer.
struct ValidatedSnapshot<'a> {
    bytes: &'a [u8],
    generation: u64,
    record_offset: usize,
    canonical: bool,
}

impl<'a> ValidatedSnapshot<'a> {
    fn validate(bytes: &'a [u8], budget: usize) -> Result<(Self, usize), DeltaError> {
        #[cfg(test)]
        SNAPSHOT_VALIDATION_PASSES.with(|count| count.set(count.get() + 1));
        let (generation, record_offset, metadata) =
            crate::authority_snapshot::validate_authority_bytes_bounded(bytes, budget)
                .map_err(metadata_error)?;
        Ok((Self { bytes, generation, record_offset,
            canonical: bytes[8..10] == crate::authority_snapshot::PERSISTENT_AUTHORITY_SNAPSHOT_VERSION.to_le_bytes(),
        }, metadata))
    }
}

// Owned successor plus the facts established by validating that successor.
// Keeping these together permits reuse only within this replay invocation.
struct ValidatedSnapshotBytes {
    bytes: Vec<u8>,
    generation: u64,
    record_offset: usize,
    canonical: bool,
}

impl ValidatedSnapshotBytes {
    fn as_validated(&self) -> ValidatedSnapshot<'_> {
        ValidatedSnapshot { bytes: &self.bytes, generation: self.generation,
            record_offset: self.record_offset, canonical: self.canonical }
    }
}

// Additional owned memory beyond the caller's retained base/link buffers.
// Includes validation metadata and semantic replay workspace.
fn reconstruct_checked_bounded(base: &[u8], delta: &[u8], budget: usize)
    -> Result<(Vec<u8>, u64, u64, usize), DeltaError>
{
    let (validated, base_metadata) = ValidatedSnapshot::validate(base, budget)?;
    let predecessor_generation = validated.generation;
    let (next, peak) = reconstruct_validated(validated, delta, budget)?;
    Ok((next.bytes, predecessor_generation, next.generation, base_metadata.max(peak)))
}

fn reconstruct_validated(base: ValidatedSnapshot<'_>, delta: &[u8], budget: usize)
    -> Result<(ValidatedSnapshotBytes, usize), DeltaError>
{
    if !base.canonical { return Err(DeltaError::Invalid); }
    let predecessor_generation = base.generation;
    let verified_base_offset = base.record_offset;
    let base = base.bytes;
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
    if verified_base_offset != base_offset {
        return Err(DeltaError::Invalid);
    }
    // Bounds and maximum output length are proved before reserving output.
    let prefix_end = HEADER.checked_add(next_offset).ok_or(DeltaError::Invalid)?;
    if prefix_end > delta.len() {
        return Err(DeltaError::Invalid);
    }
    let mut output = Vec::new();
    if next_len > budget { return Err(DeltaError::Memory); }
    output.try_reserve_exact(next_len).map_err(|_| DeltaError::Memory)?;
    let metadata_budget = budget.checked_sub(output.capacity()).ok_or(DeltaError::Memory)?;
    output.extend_from_slice(&delta[HEADER..prefix_end]);
    output.extend_from_slice(&base[base_offset..]);
    output.extend_from_slice(&delta[prefix_end..]);
    if output.len() != next_len || digest(&output).as_slice() != &delta[88..120] {
        return Err(DeltaError::Invalid);
    }
    let (proof, next_metadata) = ValidatedSnapshot::validate(&output, metadata_budget)?;
    let successor_generation = proof.generation;
    let verified_next_offset = proof.record_offset;
    if !proof.canonical || successor_generation <= predecessor_generation || verified_next_offset != next_offset {
        return Err(DeltaError::Invalid);
    }
    let peak = output.capacity().checked_add(next_metadata).ok_or(DeltaError::Memory)?;
    Ok((ValidatedSnapshotBytes { bytes: output, generation: successor_generation,
        record_offset: verified_next_offset, canonical: true }, peak))
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
    encode_link_bounded(base, next, predecessor, predecessor_depth, context, usize::MAX)
        .map(|(bytes, _)| bytes)
}

fn encode_link_bounded(
    base: &PersistentAuthoritySnapshot,
    next: &PersistentAuthoritySnapshot,
    predecessor: vibeos_segment_format::PhysicalPointer,
    predecessor_depth: u32,
    context: LinkContext,
    budget: usize,
) -> Result<(Option<Vec<u8>>, usize), DeltaError> {
    use vibeos_segment_format::encode_physical_pointer;
    let Some(depth) = predecessor_depth
        .checked_add(1)
        .filter(|&n| n <= MAX_REPLAY_DEPTH)
    else {
        return Ok((None, 0));
    };
    let (bytes, peak) = encode_with_prefix_bounded(base, next, LINK_HEADER, budget)?;
    let Some(mut bytes) = bytes else { return Ok((None, peak)); };
    if bytes.len() > MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN {
        return Ok((None, peak));
    }
    bytes[..8].copy_from_slice(LINK_MAGIC);
    bytes[8..12].copy_from_slice(&depth.to_le_bytes());
    let mut pointer = [0; vibeos_segment_format::POINTER_SIZE];
    encode_physical_pointer(predecessor, &mut pointer).map_err(|_| DeltaError::Invalid)?;
    bytes[16..112].copy_from_slice(&pointer);
    bytes[112..120].copy_from_slice(&base.checkpoint_generation().to_le_bytes());
    bytes[120..128].copy_from_slice(&next.checkpoint_generation().to_le_bytes());
    decode_link(&bytes, context)?;
    Ok((Some(bytes), peak))
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
    apply_link_bounded(resolved_pointer, base, predecessor_depth, bytes, context, usize::MAX)
        .map(|(bytes, _)| bytes)
}

fn apply_link_bounded(
    resolved_pointer: vibeos_segment_format::PhysicalPointer,
    base: &[u8], predecessor_depth: u32, bytes: &[u8], context: LinkContext,
    budget: usize,
) -> Result<(Vec<u8>, usize), DeltaError> {
    let link = decode_link(bytes, context)?;
    if link.predecessor != resolved_pointer || predecessor_depth.checked_add(1) != Some(link.depth)
    {
        return Err(DeltaError::Invalid);
    }
    let (output, predecessor_generation, generation, peak) = reconstruct_checked_bounded(base, link.delta, budget)?;
    if predecessor_generation != link.predecessor_generation || generation != link.generation {
        return Err(DeltaError::Invalid);
    }
    Ok((output, peak))
}

fn apply_validated_link(
    resolved_pointer: vibeos_segment_format::PhysicalPointer,
    base: ValidatedSnapshot<'_>, predecessor_depth: u32, bytes: &[u8],
    context: LinkContext, budget: usize,
) -> Result<(ValidatedSnapshotBytes, usize), DeltaError> {
    let link = decode_link(bytes, context)?;
    if link.predecessor != resolved_pointer || predecessor_depth.checked_add(1) != Some(link.depth)
        || base.generation != link.predecessor_generation
    {
        return Err(DeltaError::Invalid);
    }
    let (next, peak) = reconstruct_validated(base, link.delta, budget)?;
    if next.generation != link.generation { return Err(DeltaError::Invalid); }
    Ok((next, peak))
}

/// Payload budget is cumulative across fetched ancestors, not just one extent.
/// `buffer_bytes` bounds owned fetched payloads plus the overlapping rebuilt
/// snapshot buffer, ancestor/pending tables, and conservative table reallocation
/// overlap, plus metadata and semantic workspace during base/link validation.
/// Includes source-declared fixed page workspace while fetching payloads.
/// Source descriptor/result/chain phases and payload overlap are charged.
/// The source memo growth allowance is reserved across replay. Semantic replay
/// uses the allowance remaining after resident buffers and metadata. This bounds
/// requested capacities, excluding allocator bookkeeping and stack.
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
    /// Caller-owned source buffers that remain live throughout replay. Reserve
    /// their growth allowance, not only currently populated capacity.
    fn retained_buffer_reservation(&self) -> usize { 0 }
    /// Fixed page buffers overlapping the next read's returned payload.
    /// Dynamic descriptor tables and caller-owned caches are separate costs.
    fn read_page_workspace_bytes(&self) -> usize { 0 }
    /// Authenticate the pointer, segment and complete authority extent chain.
    /// Return payload, target generation and peak owned payload/descriptor
    /// allocation during the read (excluding separately reserved fixed pages).
    /// Enforce buffer_limit before each covered allocation.
    async fn read(
        &mut self,
        pointer: vibeos_segment_format::PhysicalPointer,
        maximum: usize,
        buffer_limit: usize,
    ) -> Result<(Vec<u8>, u64, usize), Self::Error>;
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
    fn retained_buffer_reservation(&self) -> usize {
        self.memo.map_or(0, |memo| memo.reservation_bytes())
    }
    fn read_page_workspace_bytes(&self) -> usize {
        if self.verified_tip.is_some() { 0 }
        else { crate::store::SEGMENT_PROBE_PAGE_WORKSPACE_BYTES }
    }
    async fn read(
        &mut self,
        pointer: vibeos_segment_format::PhysicalPointer,
        maximum: usize,
        buffer_limit: usize,
    ) -> Result<(Vec<u8>, u64, usize), Self::Error> {
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
            if bytes.capacity() > maximum || bytes.capacity() > buffer_limit {
                return Err(crate::StoreError::MemoryLimit);
            }
            let peak = bytes.capacity();
            return Ok((bytes, generation, peak));
        }
        let (bytes, record, source_peak) = crate::store::read_pointer_authority_payload_with_buffer_limit(
            self.device,
            self.context.store_uuid,
            self.context.admitted_segments,
            self.context.next_segment_generation,
            self.context.checkpoint_generation,
            pointer,
            self.allocated.iter(self.context.admitted_segments),
            maximum,
            buffer_limit,
            self.memo,
        )
        .await?;
        Ok((bytes, record.binding.target_checkpoint_generation, source_peak))
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
    encode_replayed_link_bounded(base, next, context, usize::MAX).map(|(bytes, _)| bytes)
}

// Includes reconstructed bytes/ancestor capacity retained by the caller while
// this phase decodes, compares canonical metadata, and encodes the next link.
fn encode_replayed_link_bounded(
    base: &ReplayedAuthority,
    next: &PersistentAuthoritySnapshot,
    context: LinkContext,
    budget: usize,
) -> Result<(Option<Vec<u8>>, usize), DeltaError> {
    let resident = base.ancestors.capacity().checked_mul(core::mem::size_of::<vibeos_segment_format::PhysicalPointer>())
        .and_then(|n| n.checked_add(base.bytes.capacity())).ok_or(DeltaError::Memory)?;
    let remaining = budget.checked_sub(resident).ok_or(DeltaError::Memory)?;
    let (snapshot, decode_peak) = crate::authority_snapshot::decode_persistent_authority_snapshot_bounded(
        &base.bytes, remaining,
    ).map_err(metadata_error)?;
    let mut peak = resident.checked_add(decode_peak).ok_or(DeltaError::Memory)?;
    let retained = resident.checked_add(snapshot.allocated_bytes().ok_or(DeltaError::Memory)?)
        .ok_or(DeltaError::Memory)?;
    let remaining = budget.checked_sub(retained).ok_or(DeltaError::Memory)?;
    if next.checkpoint_generation() <= snapshot.checkpoint_generation()
        || next.checkpoint_generation() > context.checkpoint_generation
        || base.depth > MAX_REPLAY_DEPTH
        || base.ancestors.len() != base.depth as usize + 1
    {
        return Err(DeltaError::Invalid);
    }
    let (metadata, metadata_peak) = crate::authority_snapshot::encode_snapshot_bounded(
        &snapshot, false, remaining,
    ).map_err(metadata_error)?;
    peak = peak.max(retained.checked_add(metadata_peak).ok_or(DeltaError::Memory)?);
    let canonical = metadata.len().checked_add(snapshot.record_stream().len()) == Some(base.bytes.len())
        && base.bytes.starts_with(&metadata) && base.bytes[metadata.len()..] == *snapshot.record_stream();
    drop(metadata);
    if !canonical {
        // Only legacy full bases may legitimately differ from canonical V2.
        if base.depth != 0 || base.bytes[8..10] != 1_u16.to_le_bytes() {
            return Err(DeltaError::Invalid);
        }
        return Ok((None, peak));
    }
    let (bytes, encode_peak) = encode_link_bounded(&snapshot, next, base.ancestors[0], base.depth, context, remaining)?;
    peak = peak.max(retained.checked_add(encode_peak).ok_or(DeltaError::Memory)?);
    Ok((bytes, peak))
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
    let mut resident_buffers = source.retained_buffer_reservation();
    if resident_buffers > limits.buffer_bytes { return Err(DeltaError::Memory.into()); }
    let mut peak_buffers = resident_buffers;
    let mut expected = None;
    let mut validated;
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
        let source_pages = source.read_page_workspace_bytes();
        let available = limits.buffer_bytes.checked_sub(resident_buffers)
            .and_then(|bytes| bytes.checked_sub(source_pages)).ok_or(DeltaError::Memory)?;
        let remaining = limits
            .payload_bytes
            .checked_sub(consumed)
            .ok_or(DeltaError::Memory)?
            .min(available);
        if value.exact_byte_len > remaining as u64 {
            return Err(DeltaError::Memory.into());
        }
        let (loaded, generation, source_peak) = source
            .read(pointer, remaining, available)
            .await
            .map_err(ReplayError::Source)?;
        if loaded.capacity() > remaining {
            return Err(DeltaError::Memory.into());
        }
        if source_peak < loaded.capacity() { return Err(DeltaError::Invalid.into()); }
        let read_peak = resident_buffers.checked_add(source_pages)
            .and_then(|bytes| bytes.checked_add(source_peak)).ok_or(DeltaError::Memory)?;
        resident_buffers = resident_buffers.checked_add(loaded.capacity()).ok_or(DeltaError::Memory)?;
        if read_peak > limits.buffer_bytes { return Err(DeltaError::Memory.into()); }
        peak_buffers = peak_buffers.max(read_peak);
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
            let (proof, metadata_bytes) = ValidatedSnapshot::validate(&loaded, metadata_budget)?;
            let base_generation = proof.generation;
            let record_offset = proof.record_offset;
            let canonical = proof.canonical;
            peak_buffers = peak_buffers.max(resident_buffers.checked_add(metadata_bytes).ok_or(DeltaError::Memory)?);
            if base_generation != generation {
                return Err(DeltaError::Invalid.into());
            }
            validated = ValidatedSnapshotBytes { bytes: loaded, generation: base_generation, record_offset, canonical };
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
        // Reserve successor bytes and metadata tables against the remaining
        // budget while all caller-owned buffers and tables are still live.
        peak_buffers = peak_buffers.max(overlapping);
        let old_capacity = validated.bytes.capacity();
        let available = limits.buffer_bytes.checked_sub(resident_buffers).ok_or(DeltaError::Memory)?;
        let (next, extra_peak) = apply_validated_link(predecessor, validated.as_validated(), depth, &delta, context, available)?;
        peak_buffers = peak_buffers.max(resident_buffers.checked_add(extra_peak).ok_or(DeltaError::Memory)?);
        // The allocator may supply more capacity than the requested length.
        // Old bytes and the pending delta are still live at this point.
        let actual_overlap = resident_buffers.checked_add(next.bytes.capacity()).ok_or(DeltaError::Memory)?;
        if actual_overlap > limits.buffer_bytes {
            return Err(DeltaError::Memory.into());
        }
        peak_buffers = peak_buffers.max(actual_overlap);
        resident_buffers = resident_buffers.checked_sub(old_capacity)
            .and_then(|n| n.checked_sub(delta.capacity()))
            .and_then(|n| n.checked_add(next.bytes.capacity())).ok_or(DeltaError::Memory)?;
        if resident_buffers > limits.buffer_bytes {
            return Err(DeltaError::Memory.into());
        }
        validated = next;
        depth += 1;
    }
    Ok(ReplayedAuthority {
        bytes: validated.bytes,
        depth,
        ancestors,
        payload_bytes: consumed,
        peak_buffer_bytes: peak_buffers,
    })
}

// Recovery and writer cold replay receive an explicit workspace allowance.
// Neither path may expand it; the standalone device fixture adapter is separate.
fn caller_replay_limits(maximum: usize) -> ReplayLimits {
    ReplayLimits { payload_bytes: maximum, snapshot_bytes: maximum, buffer_bytes: maximum }
}

fn codec_store_error<E>(error: DeltaError) -> crate::StoreError<E> {
    match error {
        DeltaError::Memory => crate::StoreError::MemoryLimit,
        DeltaError::Invalid => crate::StoreError::Corrupt,
    }
}

fn replay_store_error<E>(error: ReplayError<crate::StoreError<E>>) -> crate::StoreError<E> {
    match error {
        ReplayError::Source(error) => error,
        ReplayError::Codec(error) => codec_store_error(error),
    }
}

// Experimental bridge; default admission and offline rollout remain separate.
pub(crate) async fn replay_checkpoint_for_test<D: crate::PageDevice>(
    device: &D,
    superblock: &vibeos_segment_format::Superblock,
    checkpoint: &vibeos_segment_format::Checkpoint,
    allocation: &crate::allocation_v2::AllocationV2,
    maximum: usize,
    verified_bytes: Vec<u8>,
    verified_generation: u64,
    memo: Option<&crate::store::VerifiedSegmentScans>,
) -> Result<(Vec<u8>, usize, u32), crate::StoreError<D::Error>> {
    let context = LinkContext {
        store_uuid: superblock.binding.store_uuid,
        admitted_segments: checkpoint.admitted_segments,
        next_segment_generation: checkpoint.next_segment_generation,
        checkpoint_generation: checkpoint.binding.generation,
    };
    let mut source = DeviceAuthoritySource { device, context, allocated: AllocatedSegments::Bitmap(allocation), verified_tip: Some((checkpoint.authority_root, verified_bytes, verified_generation)),  memo, };
    replay(&mut source, checkpoint.authority_root, context,
        caller_replay_limits(maximum)).await
        .map(|r| (r.bytes, r.peak_buffer_bytes, r.depth)).map_err(replay_store_error)
}

// Experimental provenance witness. It stores no duplicate snapshot or ancestor
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

// Prepared before media mutation under the caller's remaining workspace.
// Only the exact snapshot supplied to prepare may be published before bind.
// This value has no heap allocations and is not itself a provenance witness.
pub(crate) struct PreparedBaseForTest {
    generation: u64,
    digest: [u8; 32],
}

impl PreparedBaseForTest {
    pub(crate) fn prepare<E>(snapshot: &PersistentAuthoritySnapshot, budget: usize)
        -> Result<Self, crate::StoreError<E>>
    {
        Self::prepare_with_peak(snapshot, budget).map(|(prepared, _)| prepared)
    }

    pub(crate) fn prepare_with_peak<E>(snapshot: &PersistentAuthoritySnapshot, budget: usize)
        -> Result<(Self, usize), crate::StoreError<E>>
    {
        let (metadata, peak) = crate::authority_snapshot::encode_snapshot_bounded(snapshot, false, budget)
            .map_err(metadata_error).map_err(codec_store_error)?;
        Ok((Self { generation: snapshot.checkpoint_generation(),
            digest: snapshot_digest(&metadata, snapshot.record_stream()) }, peak))
    }

    // Call only after successful publication and read-back of the prepared
    // snapshot. The resulting witness binds the actual physical root/state.
    pub(crate) fn bind<E>(self, state: &crate::store::MountedState, depth: u32)
        -> Result<VerifiedBaseForTest, crate::StoreError<E>>
    {
        if self.generation != state.generation || depth > MAX_REPLAY_DEPTH
            || state.persistent_authority.as_ref().is_none_or(|s| s.checkpoint_generation() != self.generation)
        {
            return Err(crate::StoreError::Corrupt);
        }
        Ok(VerifiedBaseForTest { generation: state.generation, root: state.authority_root,
            admitted: state.admitted_segments, next_segment: state.next_segment_generation,
            store_uuid: state.superblock.binding.store_uuid,
            digest: self.digest, depth })
    }
}

impl VerifiedBaseForTest {
    // Convenience for test fixtures already published outside the experimental
    // caller. The writer uses bounded preparation before publication instead.
    pub(crate) fn from_published<E>(state: &crate::store::MountedState, depth: u32) -> Result<Self, crate::StoreError<E>> {
        let snapshot = state.persistent_authority.as_ref().ok_or(crate::StoreError::Corrupt)?;
        PreparedBaseForTest::prepare(snapshot, usize::MAX)?.bind(state, depth)
    }

    pub(crate) fn matches(&self, state: &crate::store::MountedState) -> bool {
        self.matches_bounded(state, usize::MAX).unwrap_or(false)
    }

    // Called only after the growth checkpoint and its successor witness have
    // been verified. Growth may change geometry, but not authority identity.
    #[cfg(feature = "experimental-authority-delta")]
    pub(crate) fn after_verified_growth(&self, state: &crate::store::MountedState, budget: usize) -> Option<Self> {
        if self.generation.checked_add(1) != Some(state.generation)
            || self.root != state.authority_root
            || self.store_uuid != state.superblock.binding.store_uuid
            || state.admitted_segments <= self.admitted
            || state.next_segment_generation <= self.next_segment
        { return None; }
        let mut next = self.clone();
        next.generation = state.generation;
        next.admitted = state.admitted_segments;
        next.next_segment = state.next_segment_generation;
        // This also checks the unchanged canonical snapshot digest and depth.
        if next.matches_bounded(state, budget).ok()? { Some(next) } else { None }
    }

    fn matches_bounded(&self, state: &crate::store::MountedState, budget: usize) -> Result<bool, DeltaError> {
        if self.generation != state.generation || self.root != state.authority_root
            || self.admitted != state.admitted_segments || self.next_segment != state.next_segment_generation
            || self.store_uuid != state.superblock.binding.store_uuid || self.depth > MAX_REPLAY_DEPTH {
            return Ok(false);
        }
        let snapshot = state.persistent_authority.as_ref().ok_or(DeltaError::Invalid)?;
        let (metadata, _) = crate::authority_snapshot::encode_snapshot_bounded(snapshot, false, budget)
            .map_err(metadata_error)?;
        Ok(self.digest == snapshot_digest(&metadata, snapshot.record_stream()))
    }
}

// Bound all encoder-owned workspace across witness validation, replay, decode,
// canonical comparison and output encoding. Borrowed state/next are caller-owned;
// publication buffers and installing the new witness are separate phases.
pub(crate) async fn encode_next_for_test<D: crate::PageDevice>(
    device: &D,
    state: &crate::store::MountedState,
    next: &PersistentAuthoritySnapshot,
    workspace_bytes: usize,
    cached: Option<&VerifiedBaseForTest>,
) -> Result<(Vec<u8>, u32), crate::StoreError<D::Error>> {
    let context = LinkContext {
        store_uuid: state.superblock.binding.store_uuid,
        admitted_segments: state.admitted_segments,
        next_segment_generation: state.next_segment_generation,
        checkpoint_generation: next.checkpoint_generation(),
    };
    let cached = match cached {
        Some(cached) if cached.matches_bounded(state, workspace_bytes).map_err(codec_store_error)? => Some(cached),
        _ => None,
    };
    if let Some(cached) = cached {
        let base = state.persistent_authority.as_ref().ok_or(crate::StoreError::Corrupt)?;
        if next.checkpoint_generation() <= base.checkpoint_generation() {
            return Err(crate::StoreError::Corrupt);
        }
        return match encode_link_bounded(base, next, state.authority_root, cached.depth, context, workspace_bytes)
            .map_err(codec_store_error)? {
            (Some(bytes), _) => Ok((bytes, cached.depth + 1)),
            (None, _) => crate::authority_snapshot::encode_snapshot_bounded(next, true, workspace_bytes)
                .map(|(bytes, _)| (bytes, 0)).map_err(|error| codec_store_error(metadata_error(error))),
        };
    }
    let mut source = DeviceAuthoritySource { device, context, allocated: AllocatedSegments::Bitmap(&state.allocation), verified_tip: None,  memo: None, };
    let recovered = replay(&mut source, state.authority_root, context,
        caller_replay_limits(workspace_bytes)).await
        .map_err(replay_store_error)?;
    let (bytes, _) = encode_replayed_link_bounded(&recovered, next, context, workspace_bytes)
        .map_err(codec_store_error)?;
    match bytes {
        Some(bytes) => Ok((bytes, recovered.depth + 1)),
        None => {
            // No predecessor buffer is needed after deciding to materialize.
            drop(recovered);
            crate::authority_snapshot::encode_snapshot_bounded(next, true, workspace_bytes)
                .map(|(bytes, _)| (bytes, 0)).map_err(|error| codec_store_error(metadata_error(error)))
        }
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
            buffer_bytes: maximum.saturating_mul(3)
            .saturating_add(crate::store::SEGMENT_PROBE_PAGE_WORKSPACE_BYTES),
        },
    )
    .await
    .map(|value| value.bytes)
    .map_err(replay_store_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_snapshot::{PersistentPrincipalPolicy, StablePrincipalId};
    use alloc::vec;
    use vibeos_durable_format::{RecordBody, RecordChain, StoreId};

    #[test]
    fn prepared_witness_obeys_exact_metadata_budget_and_full_snapshot_digest() {
        let mut chain = RecordChain::new(StoreId::new(7).unwrap());
        let records = [chain.append(None, RecordBody::Format).unwrap(),
            chain.append(None, RecordBody::IdHighWater { exclusive_end: 128 }).unwrap()];
        let snapshot = PersistentAuthoritySnapshot::new(3, [9; 32],
            records.iter().flatten().copied().collect(), vec![], vec![]).unwrap();
        // With empty tables, workspace is exactly the canonical header, even
        // though the digest must include the complete (larger) record stream.
        let budget = crate::authority_snapshot::PERSISTENT_AUTHORITY_HEADER_LEN;
        for denied in [0, budget - 1] {
            assert!(matches!(PreparedBaseForTest::prepare::<()>(&snapshot, denied),
                Err(crate::StoreError::MemoryLimit)));
        }
        let prepared = PreparedBaseForTest::prepare::<()>(&snapshot, budget).unwrap();
        assert_eq!(prepared.generation, 3);
        let complete = encode_persistent_authority_snapshot(&snapshot).unwrap();
        assert_eq!(prepared.digest, digest(&complete));
        std::eprintln!("DELTA_WITNESS_BUDGET exact_workspace={budget} snapshot_bytes={}", complete.len());
    }

    #[test]
    fn reconstruction_budget_includes_successor_semantic_workspace() {
        use vibeos_segment_format::PhysicalPointer;
        use vibeos_durable_format::{encode_object_transaction, ObjectId, ObjectKind, TransactionId};
        let mut chain = RecordChain::new(StoreId::new(7).unwrap());
        let mut sectors = vec![chain.append(None, RecordBody::Format).unwrap(),
            chain.append(None, RecordBody::IdHighWater { exclusive_end: 128 }).unwrap()];
        sectors.extend(encode_object_transaction(&mut chain, TransactionId::new(9).unwrap(),
            ObjectId::new(10).unwrap(), ObjectKind::new(7).unwrap(), &[0x59; 4096]).unwrap().records);
        let base = PersistentAuthoritySnapshot::new(1, [1; 32],
            sectors.iter().flatten().copied().collect(), vec![], vec![]).unwrap();
        sectors.push(chain.append(None, RecordBody::IdHighWater { exclusive_end: 256 }).unwrap());
        let next = PersistentAuthoritySnapshot::new(2, [1; 32],
            sectors.iter().flatten().copied().collect(), vec![], vec![]).unwrap();
        let base_bytes = encode_persistent_authority_snapshot(&base).unwrap();
        let next_bytes = encode_persistent_authority_snapshot(&next).unwrap();
        let delta = encode(&base, &next).unwrap().unwrap();
        let (actual, before, after, peak) = reconstruct_checked_bounded(&base_bytes, &delta, usize::MAX).unwrap();
        let (_, _, validation_peak) = crate::authority_snapshot::validate_authority_bytes_bounded(&next_bytes, usize::MAX).unwrap();
        assert_eq!(actual, next_bytes);
        assert_eq!((before, after), (1, 2));
        assert_eq!(peak, actual.capacity() + validation_peak);
        assert!(validation_peak > 0);
        assert_eq!(reconstruct_checked_bounded(&base_bytes, &delta, next_bytes.len()), Err(DeltaError::Memory));
        assert_eq!(reconstruct_checked_bounded(&base_bytes, &delta, peak).unwrap().0, next_bytes);
        // Also check the outer reader: its loaded base and ancestor table
        // stay resident while semantic replay consumes the remaining allowance.
        let (pointer, context) = link_fixture();
        let PhysicalPointer::Value(mut value) = pointer else { unreachable!() };
        value.exact_byte_len = base_bytes.len() as u64;
        value.payload_pages = base_bytes.len().div_ceil(4096) as u32;
        value.payload_sha256 = digest(&base_bytes);
        let pointer = PhysicalPointer::Value(value);
        let mut source = Source { entries: vec![(pointer, base_bytes.clone(), 1)], calls: 0 };
        let limits = ReplayLimits { payload_bytes: base_bytes.len(), snapshot_bytes: base_bytes.len(),
            buffer_bytes: MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN * 3 };
        let recovered = run(replay(&mut source, pointer, context, limits)).unwrap();
        let resident = recovered.bytes.capacity()
            + recovered.ancestors.capacity() * core::mem::size_of::<PhysicalPointer>();
        let (_, _, base_validation) = crate::authority_snapshot::validate_authority_bytes_bounded(&base_bytes, usize::MAX).unwrap();
        assert_eq!(recovered.peak_buffer_bytes, resident + base_validation);
        assert!(matches!(run(replay(&mut source, pointer, context, ReplayLimits {
            payload_bytes: base_bytes.len(), snapshot_bytes: base_bytes.len(), buffer_bytes: resident,
        })), Err(ReplayError::Codec(DeltaError::Memory))));
        std::eprintln!("DELTA_SEMANTIC_BUDGET successor_bytes={} semantic_peak={} extra_peak={peak}", next_bytes.len(), validation_peak);
    }

    #[test]
    fn checkpoint_replay_does_not_expand_remaining_allowance() {
        use vibeos_segment_format::PhysicalPointer;
        for maximum in [0, 1, 4096, usize::MAX] {
            let limits = caller_replay_limits(maximum);
            assert_eq!(limits.payload_bytes, maximum);
            assert_eq!(limits.snapshot_bytes, maximum);
            assert_eq!(limits.buffer_bytes, maximum);
        }
        let (base, _) = pair();
        let bytes = encode_persistent_authority_snapshot(&base).unwrap();
        let (pointer, context) = link_fixture();
        let PhysicalPointer::Value(mut value) = pointer else { unreachable!() };
        value.exact_byte_len = bytes.len() as u64;
        value.payload_pages = bytes.len().div_ceil(4096) as u32;
        value.payload_sha256 = digest(&bytes);
        let pointer = PhysicalPointer::Value(value);
        let mut source = Source { entries: vec![(pointer, bytes.clone(), base.checkpoint_generation())], calls: 0 };
        // The payload alone fits, but its retained ancestor/validation workspace
        // does not. The former 3x adapter allowance would hide this rejection.
        assert!(matches!(run(replay(&mut source, pointer, context,
            caller_replay_limits(bytes.len()))), Err(ReplayError::Codec(DeltaError::Memory))));
        let roomy = bytes.len() * 3 + 4096;
        let result = run(replay(&mut source, pointer, context, caller_replay_limits(roomy))).unwrap();
        assert_eq!(result.bytes, bytes);
        assert!(result.peak_buffer_bytes <= roomy);
        let exact = run(replay(&mut source, pointer, context,
            caller_replay_limits(result.peak_buffer_bytes))).unwrap();
        assert_eq!(exact.bytes, bytes);
        assert!(exact.peak_buffer_bytes <= result.peak_buffer_bytes);
        std::eprintln!("CHECKPOINT_DELTA_BUDGET payload_bytes={} admitted_peak={}", bytes.len(), result.peak_buffer_bytes);
    }

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
            buffer_limit: usize,
        ) -> Result<(Vec<u8>, u64, usize), Self::Error> {
            self.calls += 1;
            let (_, bytes, generation) = self
                .entries
                .iter()
                .find(|(p, _, _)| *p == pointer)
                .ok_or("missing")?;
            let vibeos_segment_format::PhysicalPointer::Value(value) = pointer else {
                return Err("null");
            };
            if bytes.len() > maximum || bytes.len() > buffer_limit {
                return Err("budget");
            }
            if bytes.len() as u64 != value.exact_byte_len || digest(bytes) != value.payload_sha256 {
                return Err("damaged");
            }
            let loaded = bytes.clone();
            let peak = loaded.capacity();
            Ok((loaded, *generation, peak))
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
        let (verified_bytes, verified_generation, _) = run(source.read(tip, budget, budget)).unwrap();
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
    fn cold_encoder_budget_counts_resident_replay_and_decoded_snapshot() {
        let (base, next) = pair();
        let (pointer, context) = link_fixture();
        let bytes = encode_persistent_authority_snapshot(&base).unwrap();
        let recovered = ReplayedAuthority { payload_bytes: bytes.len(), bytes,
            depth: 0, ancestors: vec![pointer], peak_buffer_bytes: 0 };
        let resident = recovered.bytes.capacity() + recovered.ancestors.capacity()
            * core::mem::size_of::<vibeos_segment_format::PhysicalPointer>();
        let (decoded, decode_peak) = crate::authority_snapshot::decode_persistent_authority_snapshot_bounded(
            &recovered.bytes, usize::MAX).unwrap();
        let (_, metadata_peak) = crate::authority_snapshot::encode_snapshot_bounded(&decoded, false, usize::MAX).unwrap();
        let (expected, encode_peak) = encode_link_bounded(&decoded, &next, pointer, 0, context, usize::MAX).unwrap();
        let retained = decoded.allocated_bytes().unwrap();
        let (actual, peak) = encode_replayed_link_bounded(&recovered, &next, context, usize::MAX).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(peak, resident + decode_peak.max(retained + metadata_peak.max(encode_peak)));
        assert_eq!(encode_replayed_link_bounded(&recovered, &next, context, peak).unwrap(), (actual, peak));
        for budget in [resident, resident + retained, peak - 1] {
            assert_eq!(encode_replayed_link_bounded(&recovered, &next, context, budget), Err(DeltaError::Memory));
        }
        std::eprintln!("COLD_ENCODE_BUDGET resident={resident} decoded={retained} encode_peak={encode_peak} total_peak={peak}");
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
    fn link_budget_includes_successor_bytes_and_simultaneous_metadata() {
        let (base, next) = pair();
        let base_bytes = encode_persistent_authority_snapshot(&base).unwrap();
        let expected = encode_persistent_authority_snapshot(&next).unwrap();
        let (pointer, context) = link_fixture();
        let link = encode_link(&base, &next, pointer, 0, context).unwrap().unwrap();
        let (decoded, peak) = apply_link_bounded(pointer, &base_bytes, 0, &link, context, usize::MAX).unwrap();
        assert_eq!(decoded, expected);
        assert!(peak > decoded.capacity(), "successor metadata must remain charged alongside output");
        assert_eq!(apply_link_bounded(pointer, &base_bytes, 0, &link, context, peak).unwrap().0, expected);
        assert!(matches!(apply_link_bounded(pointer, &base_bytes, 0, &link, context, peak - 1), Err(DeltaError::Memory)));
        assert!(matches!(apply_link_bounded(pointer, &base_bytes, 0, &link, context, expected.len()), Err(DeltaError::Memory)));
    }

    #[test]
    fn validated_predecessor_reuse_preserves_link_rejection_and_output() {
        let (base, next) = pair();
        let base_bytes = encode_persistent_authority_snapshot(&base).unwrap();
        let (pointer, context) = link_fixture();
        let link = encode_link(&base, &next, pointer, 0, context).unwrap().unwrap();
        let compare = |candidate: &[u8]| {
            let (proof, _) = ValidatedSnapshot::validate(&base_bytes, usize::MAX).unwrap();
            let fast = apply_validated_link(pointer, proof, 0, candidate, context, usize::MAX)
                .map(|(next, _)| next.bytes);
            assert_eq!(fast, apply_link(pointer, &base_bytes, 0, candidate, context));
        };
        compare(&link);
        for end in 0..link.len() { compare(&link[..end]); }
        for offset in 0..link.len() {
            let mut changed = link.clone();
            changed[offset] ^= 1;
            compare(&changed);
        }
        let (proof, _) = ValidatedSnapshot::validate(&base_bytes, usize::MAX).unwrap();
        let (output, peak) = apply_validated_link(pointer, proof, 0, &link, context, usize::MAX).unwrap();
        assert_eq!(output.bytes, encode_persistent_authority_snapshot(&next).unwrap());
        for budget in [peak, peak - 1] {
            let (proof, _) = ValidatedSnapshot::validate(&base_bytes, usize::MAX).unwrap();
            let result = apply_validated_link(pointer, proof, 0, &link, context, budget);
            if budget == peak { assert_eq!(result.unwrap().0.bytes, output.bytes); }
            else { assert!(matches!(result, Err(DeltaError::Memory))); }
        }
    }

    #[test]
    fn bounded_encoder_releases_predecessor_metadata_before_output() {
        let (base, next) = pair();
        let before = encode_persistent_authority_metadata(&base).unwrap();
        let after = encode_persistent_authority_metadata(&next).unwrap();
        for prefix in [0, LINK_HEADER] {
            let (encoded, peak) = encode_with_prefix_bounded(&base, &next, prefix, usize::MAX).unwrap();
            let encoded = encoded.unwrap();
            let expected_peak = (before.capacity() + after.capacity())
                .max(after.capacity() + encoded.capacity());
            assert_eq!(peak, expected_peak);
            let previous_overlap = before.capacity() + after.capacity() + encoded.capacity();
            assert!(peak < previous_overlap);
            assert_eq!(encode_with_prefix_bounded(&base, &next, prefix, peak - 1), Err(DeltaError::Memory));
            let exact = encode_with_prefix_bounded(&base, &next, prefix, peak).unwrap();
            assert_eq!(exact, (Some(encoded.clone()), peak));
            assert_eq!(reconstruct(&crate::encode_persistent_authority_snapshot(&base).unwrap(),
                &encoded[prefix..]).unwrap(), crate::encode_persistent_authority_snapshot(&next).unwrap());
            std::eprintln!("DELTA_ENCODE_BUDGET prefix={prefix} previous_overlap={previous_overlap} peak={peak}");
        }
        assert_eq!(encode_with_prefix_bounded(&base, &base, 0, 0).unwrap(), (None, 0));
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
        SNAPSHOT_VALIDATION_PASSES.with(|count| count.set(0));
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
        assert_eq!(SNAPSHOT_VALIDATION_PASSES.with(|count| count.get()),
            MAX_REPLAY_DEPTH as usize + 1, "validate the full base and each successor exactly once");
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
        struct PagedSource(Source);
        impl AuthoritySource for PagedSource {
            type Error = &'static str;
            fn retained_buffer_reservation(&self) -> usize { 16 * 1024 }
            fn read_page_workspace_bytes(&self) -> usize { 32 * 1024 }
            async fn read(&mut self, pointer: PhysicalPointer, maximum: usize, buffer_limit: usize)
                -> Result<(Vec<u8>, u64, usize), Self::Error> {
                self.0.read(pointer, maximum, buffer_limit).await
            }
        }
        let mut paged = PagedSource(unread.clone());
        assert!(matches!(run(replay(&mut paged, tip, context, ReplayLimits {
            buffer_bytes: 16 * 1024 - 1, ..limits()
        })), Err(ReplayError::Codec(DeltaError::Memory))));
        assert_eq!(paged.0.calls, 0, "source reservation must fit before any read");
        assert!(matches!(run(replay(&mut paged, tip, context, ReplayLimits {
            buffer_bytes: tip_value.exact_byte_len as usize + 32 * 1024 - 1, ..limits()
        })), Err(ReplayError::Codec(DeltaError::Memory))));
        assert_eq!(paged.0.calls, 0, "payload plus page workspace must fit before reading");
        let with_pages = run(replay(&mut paged, tip, context, limits())).unwrap();
        let paged_peak = with_pages.peak_buffer_bytes;
        assert!(paged_peak >= peak + 16 * 1024);
        let exact_pages = run(replay(&mut paged, tip, context, ReplayLimits {
            buffer_bytes: paged_peak, ..limits()
        })).unwrap();
        assert_eq!(exact_pages.bytes, reconstructed);
        assert!(matches!(run(replay(&mut paged, tip, context, ReplayLimits {
            buffer_bytes: paged_peak - 1, ..limits()
        })), Err(ReplayError::Codec(DeltaError::Memory))));
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
