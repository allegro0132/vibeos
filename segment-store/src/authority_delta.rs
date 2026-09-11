//! Experimental authority append payload codec. Test-only until physical
//! predecessor binding, bounded replay, GC and offline recovery are integrated.
//! These bytes are not yet an admitted on-media format or an authority handle.

use crate::authority_snapshot::{
    decode_persistent_authority_snapshot, encode_persistent_authority_snapshot,
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
    if next.checkpoint_generation() <= base.checkpoint_generation()
        || next.record_stream().len() <= base.record_stream().len()
        || !next.record_stream().starts_with(base.record_stream())
    {
        return Ok(None);
    }
    let before = encode_persistent_authority_snapshot(base).map_err(|_| DeltaError::Invalid)?;
    let after = encode_persistent_authority_snapshot(next).map_err(|_| DeltaError::Invalid)?;
    let base_offset = before.len() - base.record_stream().len();
    let next_offset = after.len() - next.record_stream().len();
    let common = base.record_stream().len();
    let len = HEADER
        .checked_add(after.len() - common)
        .ok_or(DeltaError::Invalid)?;
    if len >= after.len() {
        return Ok(None);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(len)
        .map_err(|_| DeltaError::Memory)?;
    output.resize(HEADER, 0);
    output[..8].copy_from_slice(MAGIC);
    output[8..10].copy_from_slice(&1_u16.to_le_bytes());
    output[10..12].copy_from_slice(&(HEADER as u16).to_le_bytes());
    put(&mut output, 16, before.len());
    put(&mut output, 24, base_offset);
    put(&mut output, 32, after.len());
    put(&mut output, 40, next_offset);
    put(&mut output, 48, common);
    output[56..88].copy_from_slice(&digest(&before));
    output[88..120].copy_from_slice(&digest(&after));
    output.extend_from_slice(&after[..next_offset]);
    output.extend_from_slice(&after[next_offset + common..]);
    Ok(Some(output))
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
    let predecessor =
        decode_persistent_authority_snapshot(base).map_err(|_| DeltaError::Invalid)?;
    if predecessor.record_stream().len() != common
        || encode_persistent_authority_snapshot(&predecessor).map_err(|_| DeltaError::Invalid)?
            != base
    {
        return Err(DeltaError::Invalid);
    }
    let predecessor_generation = predecessor.checkpoint_generation();
    // The record bytes remain in `base`; release the decoded tables/stream
    // before allocating the successor and running its full preflight.
    drop(predecessor);
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
    let successor =
        decode_persistent_authority_snapshot(&output).map_err(|_| DeltaError::Invalid)?;
    if successor.checkpoint_generation() <= predecessor_generation
        || output.len() - successor.record_stream().len() != next_offset
        || !successor.record_stream().starts_with(&base[base_offset..])
        || encode_persistent_authority_snapshot(&successor).map_err(|_| DeltaError::Invalid)?
            != output
    {
        return Err(DeltaError::Invalid);
    }
    Ok((
        output,
        predecessor_generation,
        successor.checkpoint_generation(),
    ))
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
    let Some(delta) = encode(base, next)? else {
        return Ok(None);
    };
    let len = LINK_HEADER
        .checked_add(delta.len())
        .ok_or(DeltaError::Invalid)?;
    let full = encode_persistent_authority_snapshot(next).map_err(|_| DeltaError::Invalid)?;
    if len >= full.len() || len > MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| DeltaError::Memory)?;
    bytes.resize(LINK_HEADER, 0);
    bytes[..8].copy_from_slice(LINK_MAGIC);
    bytes[8..12].copy_from_slice(&depth.to_le_bytes());
    let mut pointer = [0; vibeos_segment_format::POINTER_SIZE];
    encode_physical_pointer(predecessor, &mut pointer).map_err(|_| DeltaError::Invalid)?;
    bytes[16..112].copy_from_slice(&pointer);
    bytes[112..120].copy_from_slice(&base.checkpoint_generation().to_le_bytes());
    bytes[120..128].copy_from_slice(&next.checkpoint_generation().to_le_bytes());
    bytes.extend_from_slice(&delta);
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
/// This does not yet account for decoder/preflight heap or segment scan I/O.
struct ReplayLimits {
    payload_bytes: usize,
    snapshot_bytes: usize,
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

struct DeviceAuthoritySource<'a, D> {
    device: &'a D,
    context: LinkContext,
    allocated: &'a [u64],
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
        if !self.allocated.contains(&value.segment_no) {
            return Err(crate::StoreError::Corrupt);
        }
        let (bytes, record) = crate::store::read_pointer_authority_payload(
            self.device,
            self.context.store_uuid,
            self.context.admitted_segments,
            self.context.next_segment_generation,
            self.context.checkpoint_generation,
            pointer,
            self.allocated,
            maximum,
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
            .ok_or(DeltaError::Memory)?;
        if value.exact_byte_len > remaining as u64 {
            return Err(DeltaError::Memory.into());
        }
        let (loaded, generation) = source
            .read(pointer, remaining)
            .await
            .map_err(ReplayError::Source)?;
        if loaded.len() > remaining {
            return Err(DeltaError::Memory.into());
        }
        consumed = consumed
            .checked_add(loaded.len())
            .ok_or(DeltaError::Memory)?;
        ancestors
            .try_reserve_exact(1)
            .map_err(|_| DeltaError::Memory)?;
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
            pending
                .try_reserve_exact(1)
                .map_err(|_| DeltaError::Memory)?;
            pending.push((pointer, loaded));
        } else {
            if expected.is_some_and(|pair| pair != (0, generation)) {
                return Err(DeltaError::Invalid.into());
            }
            if loaded.len() > limits.snapshot_bytes {
                return Err(DeltaError::Memory.into());
            }
            let snapshot =
                decode_persistent_authority_snapshot(&loaded).map_err(|_| DeltaError::Invalid)?;
            if snapshot.checkpoint_generation() != generation {
                return Err(DeltaError::Invalid.into());
            }
            bytes = loaded;
            break;
        }
    }
    let mut depth = 0;
    while let Some((predecessor, delta)) = pending.pop() {
        bytes = apply_link(predecessor, &bytes, depth, &delta, context)?;
        depth += 1;
    }
    Ok(ReplayedAuthority {
        bytes,
        depth,
        ancestors,
        payload_bytes: consumed,
    })
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
    let allocated: Vec<_> = (0..state.admitted_segments)
        .filter(|&n| state.allocation.segment_state(n) == Some(crate::SegmentAllocation::Allocated))
        .collect();
    let mut source = DeviceAuthoritySource {
        device,
        context,
        allocated: &allocated,
    };
    replay(
        &mut source,
        state.authority_root,
        context,
        ReplayLimits {
            payload_bytes: maximum,
            snapshot_bytes: maximum,
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
            allocated: &[0, 1, 2],
        };
        let budget = before.len() + delta.len() + second.len();
        let limits = || ReplayLimits {
            payload_bytes: budget,
            snapshot_bytes: after.len(),
        };
        let writes = device.writes.get();
        let result = run(replay(&mut source, tip, context, limits())).unwrap();
        assert_eq!(result.bytes, after);
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
            allocated: &[1, 2],
        };
        assert!(run(replay(&mut unallocated, tip, context, limits())).is_err());
        // GC's existing writer uses relocated() and emits a full snapshot.
        // Prove the resulting root is independent of the old delta ancestors.
        let relocated = final_snapshot.relocated(6).unwrap();
        let full = encode_persistent_authority_snapshot(&relocated).unwrap();
        context.checkpoint_generation = 6;
        let full_root = run(write_authority_fixture(&device, context, 3, 6, &full));
        let mut old_source = DeviceAuthoritySource {
            device: &device,
            context,
            allocated: &[0, 1, 2, 3],
        };
        assert_eq!(
            run(replay(&mut old_source, tip, context, limits()))
                .unwrap()
                .bytes,
            after
        );
        let mut new_source = DeviceAuthoritySource {
            device: &device,
            context,
            allocated: &[3],
        };
        let result = run(replay(
            &mut new_source,
            full_root,
            context,
            ReplayLimits {
                payload_bytes: full.len(),
                snapshot_bytes: full.len(),
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
            allocated: &[3, 4],
        };
        let result = run(replay(
            &mut resumed_source,
            resumed_root,
            context,
            ReplayLimits {
                payload_bytes: full.len() + link.len(),
                snapshot_bytes: expected.len(),
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
            },
        ))
        .unwrap();
        assert_eq!(replayed.bytes, reconstructed);
        assert_eq!(replayed.depth, MAX_REPLAY_DEPTH);
        assert_eq!(replayed.ancestors.len(), MAX_REPLAY_DEPTH as usize + 1);
        assert_eq!(replayed.payload_bytes, budget);
        assert_eq!(source.calls, MAX_REPLAY_DEPTH as usize + 1);
        let limits = || ReplayLimits {
            payload_bytes: budget,
            snapshot_bytes: reconstructed.len(),
        };
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
