//! Streaming canonical Blob CAS over the frozen Storage V2 segment ABI.

use alloc::vec::Vec;
use core::fmt;

use sha2::{Digest, Sha256};
use vibeos_blob_format::{
    BlobDescriptor, BlobError, BlobGeometry, HASH_SIZE, HEADER_SIZE, Hash, LEAF_SIZE,
    MAX_STREAMING_EMISSIONS_PER_STEP, MerkleProof, MerkleTreeSink, StreamingError, StreamingMerkle,
    verify_proof,
};
use vibeos_segment_format::{
    ANCHOR_SEGMENT_NO, BodyDigest, Checkpoint, DATA_END_PAGE, DATA_FIRST_PAGE, ExtentKind,
    ExtentRecord, FormatError, MAX_EXTENT_PAYLOAD_PAGES, PAGE_SIZE, Page, PhysicalPointer,
    PointerValue, RecordBinding, SEGMENT_SEAL_BODY_PAGE, SEGMENT_SEAL_PAGE, SUMMARY_BODY_PAGE,
    SUMMARY_SEAL_PAGE, SegmentHeader, SegmentSeal, SegmentSummary, StoreUuid,
    descriptor_chain_initial, descriptor_chain_next, encode_extent_body, encode_record_seal,
    encode_segment_header_body, encode_segment_seal_body, encode_segment_summary_body,
    payload_chain_initial, payload_chain_next, payload_sha256, segment_base_page,
};

use crate::authority::{
    AuthorizedObject, ObjectPublicationTarget, PublicationIntent, PublishError,
};
use crate::cas_codec::{
    BLOB_MAPPING_LEN, BlobKey, BlobManifest, BlobMapping, CANONICAL_CONTENT_EXTENT_LEN,
    CAS_SNAPSHOT_HEADER_LEN, CasCodecContext, CasCodecError, CasSnapshot, MAX_BLOB_EXTENTS,
    MAX_METADATA_PAYLOAD_LEN, ManifestExtent, OBJECT_MAPPING_LEN, ObjectMapping,
    decode_blob_manifest, encode_blob_manifest, encode_cas_snapshot,
};
use crate::codec::{AllocationState, encode_allocation};
use crate::device::PageDevice;
use crate::store::{
    CapacityClass, MountedState, SegmentStore, StoreError, read_pointer_payload, scan_segment,
    validate_cas_blob_descriptors, write_checkpoint,
};

const METADATA_KIND_MANIFEST: u32 = 0xffff_0010;
const METADATA_KIND_CAS_SNAPSHOT: u32 = 0xffff_0011;
const METADATA_KIND_ALLOCATION: u32 = 0xffff_0002;
const MAX_TREE_PAGES: usize = MAX_EXTENT_PAYLOAD_PAGES as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CasObjectHandle {
    store_uuid: StoreUuid,
    object_id: u128,
    object_kind: u32,
    exact_len: u64,
    commit_generation: u64,
}

impl CasObjectHandle {
    pub const fn object_kind(&self) -> u32 {
        self.object_kind
    }

    pub const fn exact_len(&self) -> u64 {
        self.exact_len
    }
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
    geometry: BlobGeometry,
    expected_root: Option<Hash>,
    merkle: Option<StreamingMerkle<EmissionSink>>,
    extents: Vec<ScratchExtent>,
    segments: Vec<ScratchSegment>,
    tree_initialized: [bool; MAX_TREE_PAGES],
    prepared: bool,
    mutated: bool,
    failed: bool,
}

impl<D: PageDevice> SegmentStore<D> {
    pub fn begin_blob(
        &mut self,
        object_kind: u32,
        exact_len: u64,
        expected_root: Option<Hash>,
    ) -> Result<BlobWriter<'_, D>, CasStoreError<D::Error>> {
        let current = self.mounted.as_ref().ok_or(if self.poisoned {
            StoreError::RecoveryRequired
        } else {
            StoreError::NotMounted
        })?;
        if !current.catalog.is_empty() {
            return Err(StoreError::CatalogMode.into());
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
        let geometry = BlobGeometry::for_len(exact_len)?;
        let checkpoint_generation = current
            .generation
            .checked_add(1)
            .ok_or(StoreError::IdExhausted)?;
        let (extents, segments) = plan_scratch(
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
        let ordinary_end = current
            .admitted_segments
            .saturating_sub(u64::from(current.cleaner_reserve_segments));
        if current
            .next_physical_segment
            .checked_add(required)
            .is_none_or(|end| end > ordinary_end)
        {
            return Err(StoreError::Capacity(CapacityClass::CleanerReserve).into());
        }
        let merkle = StreamingMerkle::begin(object_kind, exact_len, EmissionSink::new())
            .map_err(map_streaming_error)?;
        let state = self.mounted.take().ok_or(StoreError::NotMounted)?;
        self.poisoned = true;
        Ok(BlobWriter {
            store: self,
            state: Some(state),
            object_kind,
            geometry,
            expected_root,
            merkle: Some(merkle),
            extents,
            segments,
            tree_initialized: [false; MAX_TREE_PAGES],
            prepared: false,
            mutated: false,
            failed: false,
        })
    }

    pub async fn get_blob_chunk(
        &self,
        object: &AuthorizedObject<CasObjectHandle>,
        index: u32,
    ) -> Result<VerifiedCasChunk, CasStoreError<D::Error>> {
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
        let (descriptor, manifest) = self.resolve_authorized_manifest(object).await?;
        let state = self.mounted.as_ref().ok_or(StoreError::NotMounted)?;
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
                &self.device,
                state,
                &manifest,
                HEADER_SIZE as u64 + u64::from(index) * LEAF_SIZE as u64,
                chunk_len,
            )
            .await?;
            builder
                .push_chunk(index, &bytes)
                .map_err(map_streaming_error)?;
            verify_tree_emissions(
                &self.device,
                state,
                &manifest,
                geometry,
                builder.sink_mut().take(),
            )
            .await?;
        }
        while builder.padding_remaining().map_err(map_streaming_error)? != 0 {
            builder.pad_next().map_err(map_streaming_error)?;
            verify_tree_emissions(
                &self.device,
                state,
                &manifest,
                geometry,
                builder.sink_mut().take(),
            )
            .await?;
        }
        let computed = builder.finalize().map_err(map_streaming_error)?;
        if computed.descriptor != descriptor {
            return Err(StoreError::Corrupt.into());
        }
        Ok(VerifiedCasBlob {
            descriptor,
            verified_encoded_bytes: manifest.encoded_blob_len,
        })
    }

    async fn resolve_authorized_manifest(
        &self,
        object: &AuthorizedObject<CasObjectHandle>,
    ) -> Result<(BlobDescriptor, BlobManifest), CasStoreError<D::Error>> {
        let state = self.mounted.as_ref().ok_or(if self.poisoned {
            StoreError::RecoveryRequired
        } else {
            StoreError::NotMounted
        })?;
        let cas = state.cas.as_ref().ok_or(StoreError::ObjectUnavailable)?;
        let handle = object.backend_handle();
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
        validate_cas_blob_descriptors(
            &self.device,
            state.superblock.binding.store_uuid,
            state.admitted_segments,
            state.next_segment_generation,
            state.generation,
            &manifest,
        )
        .await?;
        let descriptor = BlobDescriptor {
            object_kind: mapping.blob_key.object_kind(),
            byte_len: mapping.blob_key.exact_len(),
            leaf_count: BlobGeometry::for_len(mapping.blob_key.exact_len())?.leaf_count(),
            tree_node_count: BlobGeometry::for_len(mapping.blob_key.exact_len())?.tree_node_count(),
            root: mapping.blob_key.merkle_root(),
        };
        let header = read_manifest_range(&self.device, state, &manifest, 0, HEADER_SIZE).await?;
        let header: &[u8; HEADER_SIZE] = header
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupt)?;
        if BlobDescriptor::decode_header(header)? != descriptor {
            return Err(StoreError::Corrupt.into());
        }
        Ok((descriptor, manifest))
    }
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

async fn read_manifest_range<D: PageDevice>(
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
        let mut page = [0; PAGE_SIZE];
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

impl<D: PageDevice> BlobWriter<'_, D> {
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
        let mut page = [0; PAGE_SIZE];
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
        let state = self.state.as_ref().ok_or(CasStoreError::WriterFailed)?;
        let extra_metadata_segment = state
            .next_physical_segment
            .checked_add(self.segments.len() as u64)
            .ok_or(StoreError::Capacity(CapacityClass::Payload))?;
        for segment_no in self
            .segments
            .iter()
            .map(|segment| segment.segment_no)
            .chain(core::iter::once(extra_metadata_segment))
        {
            let base = segment_base_page(segment_no)?;
            let zero = [0; PAGE_SIZE];
            self.store
                .device
                .write_page(base + u64::from(SEGMENT_SEAL_PAGE), &zero)
                .await
                .map_err(StoreError::Mutation)?;
            self.store
                .device
                .flush()
                .await
                .map_err(StoreError::Mutation)?;
            let mut observed = [0; PAGE_SIZE];
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
        self.store
            .device
            .write_page(physical, page)
            .await
            .map_err(StoreError::Mutation)?;
        self.store
            .device
            .flush()
            .await
            .map_err(StoreError::Mutation)?;
        Ok(())
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
            let (extent, within) =
                find_scratch_extent(&self.extents, encoded_offset, HASH_SIZE as u64)?;
            let tree_page =
                usize::try_from(within / PAGE_SIZE as u64).map_err(|_| StoreError::Corrupt)?;
            if tree_page >= self.tree_initialized.len() {
                return Err(StoreError::Corrupt.into());
            }
            let physical = segment_base_page(extent.segment_no)?
                .checked_add(u64::from(extent.payload_relative_page))
                .and_then(|page| page.checked_add(tree_page as u64))
                .ok_or(StoreError::Corrupt)?;
            let mut page = [0; PAGE_SIZE];
            if self.tree_initialized[tree_page] {
                self.store
                    .device
                    .read_page(physical, &mut page)
                    .await
                    .map_err(StoreError::Device)?;
            }
            let in_page =
                usize::try_from(within % PAGE_SIZE as u64).map_err(|_| StoreError::Corrupt)?;
            page[in_page..in_page + HASH_SIZE].copy_from_slice(&emission.hash);
            self.store
                .device
                .write_page(physical, &page)
                .await
                .map_err(StoreError::Mutation)?;
            self.store
                .device
                .flush()
                .await
                .map_err(StoreError::Mutation)?;
            self.tree_initialized[tree_page] = true;
        }
        Ok(())
    }

    pub async fn commit(
        mut self,
    ) -> Result<AuthorizedObject<CasObjectHandle>, CasStoreError<D::Error>> {
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

        let mut header_page = [0; PAGE_SIZE];
        header_page[..HEADER_SIZE].copy_from_slice(&streaming.header);
        self.write_exact_page(0, &header_page).await?;
        let state = self.state.as_ref().ok_or(CasStoreError::WriterFailed)?;
        let blob_key = BlobKey::sha256(
            self.object_kind,
            self.geometry.exact_len(),
            streaming.descriptor.root,
        )?;

        let mut payload_hashes = Vec::new();
        payload_hashes
            .try_reserve_exact(self.extents.len())
            .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
        for extent in &self.extents {
            payload_hashes.push(hash_scratch_extent(&self.store.device, extent).await?);
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
        let existing_manifest = if let Some(mapping) = existing {
            let context = CasCodecContext::new(
                state.superblock.binding.store_uuid,
                state.admitted_segments,
                state.next_segment_generation,
            )?;
            let payload = read_pointer_payload(
                &self.store.device,
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
                    &self.store.device,
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
            Some((mapping, manifest))
        } else {
            None
        };

        let state = self.state.take().ok_or(CasStoreError::WriterFailed)?;
        let handle = commit_snapshot(
            &self.store.device,
            &state,
            self.store.limits,
            blob_key,
            scratch_manifest,
            existing_manifest.map(|(mapping, _)| mapping),
            &self.extents,
            &self.segments,
            &payload_hashes,
        )
        .await?;
        // The checkpoint is durable, but publication is still withheld. A cold
        // reread installs the exact selected state before authority can escape.
        self.store.mount().await?;
        Ok(AuthorizedObject::from_committed(
            handle,
            self.object_kind,
            self.geometry.exact_len(),
        ))
    }

    pub async fn commit_to<T>(
        self,
        intent: PublicationIntent<T, CasObjectHandle>,
    ) -> Result<T::Capability, CasCommitError<D::Error, T::Error>>
    where
        T: ObjectPublicationTarget<CasObjectHandle> + ?Sized,
    {
        let object = self.commit().await.map_err(CasCommitError::Store)?;
        intent.publish(object).map_err(CasCommitError::Publish)
    }
}

#[derive(Clone)]
struct FinalRecord {
    value: ExtentRecord,
    digest: BodyDigest,
    body: Page,
    seal: Page,
}

impl FinalRecord {
    fn pointer(&self) -> PhysicalPointer {
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
fn build_record(
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
    let mut body = [0; PAGE_SIZE];
    let mut seal = [0; PAGE_SIZE];
    let digest = encode_extent_body(&value, &mut body)?;
    encode_record_seal(digest, &mut seal)?;
    Ok(FinalRecord {
        value,
        digest,
        body,
        seal,
    })
}

async fn write_page<D: PageDevice>(
    device: &D,
    page: u64,
    bytes: &Page,
) -> Result<(), StoreError<D::Error>> {
    device
        .write_page(page, bytes)
        .await
        .map_err(StoreError::Mutation)
}

async fn flush<D: PageDevice>(device: &D) -> Result<(), StoreError<D::Error>> {
    device.flush().await.map_err(StoreError::Mutation)
}

async fn hash_scratch_extent<D: PageDevice>(
    device: &D,
    extent: &ScratchExtent,
) -> Result<Hash, StoreError<D::Error>> {
    let base = segment_base_page(extent.segment_no)?;
    let mut remaining =
        usize::try_from(extent.payload_byte_len).map_err(|_| StoreError::Corrupt)?;
    let mut hasher = Sha256::new();
    for page_index in 0..extent.payload_byte_len.div_ceil(PAGE_SIZE as u64) {
        let mut page = [0; PAGE_SIZE];
        device
            .read_page(
                base + u64::from(extent.payload_relative_page) + page_index,
                &mut page,
            )
            .await
            .map_err(StoreError::Device)?;
        let take = remaining.min(PAGE_SIZE);
        hasher.update(&page[..take]);
        remaining -= take;
    }
    if remaining != 0 {
        return Err(StoreError::Corrupt);
    }
    Ok(hasher.finalize().into())
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
        let mut page = [0; PAGE_SIZE];
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
            let mut left = [0; PAGE_SIZE];
            let mut right = [0; PAGE_SIZE];
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
    let mut header_body = [0; PAGE_SIZE];
    let mut header_seal = [0; PAGE_SIZE];
    let header_digest = encode_segment_header_body(&header, &mut header_body)?;
    encode_record_seal(header_digest, &mut header_seal)?;
    write_page(device, base, &header_body).await?;
    flush(device).await?;
    write_page(device, base + 1, &header_seal).await?;
    flush(device).await?;

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
        write_page(
            device,
            base + u64::from(scratch.descriptor_relative_page),
            &record.body,
        )
        .await?;
        flush(device).await?;
        write_page(
            device,
            base + u64::from(scratch.descriptor_relative_page + 1),
            &record.seal,
        )
        .await?;
        flush(device).await?;
        records.push(record);
    }
    finalize_segment(
        device,
        state.superblock.binding.store_uuid,
        checkpoint_generation,
        segment.segment_no,
        segment.segment_generation,
        header_digest,
        &records,
    )
    .await
}

async fn finalize_segment<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    checkpoint_generation: u64,
    segment_no: u64,
    segment_generation: u64,
    header_digest: BodyDigest,
    records: &[FinalRecord],
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
    let mut summary_body = [0; PAGE_SIZE];
    let mut summary_seal = [0; PAGE_SIZE];
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
    let mut seal_body = [0; PAGE_SIZE];
    let mut final_seal = [0; PAGE_SIZE];
    let seal_digest = encode_segment_seal_body(&seal, &mut seal_body)?;
    encode_record_seal(seal_digest, &mut final_seal)?;
    write_page(device, base + u64::from(SUMMARY_BODY_PAGE), &summary_body).await?;
    flush(device).await?;
    write_page(device, base + u64::from(SUMMARY_SEAL_PAGE), &summary_seal).await?;
    flush(device).await?;
    write_page(device, base + u64::from(SEGMENT_SEAL_BODY_PAGE), &seal_body).await?;
    flush(device).await?;
    write_page(device, base + u64::from(SEGMENT_SEAL_PAGE), &final_seal).await?;
    flush(device).await?;
    Ok((segment_no, segment_generation, seal_digest.body_sha256()))
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
) -> Result<CasObjectHandle, CasStoreError<D::Error>> {
    let checkpoint_generation = state
        .generation
        .checked_add(1)
        .ok_or(StoreError::IdExhausted)?;
    let is_new = existing.is_none();
    let data_segment_count = if is_new { scratch_segments.len() } else { 0 };
    let metadata_segment_no = state
        .next_physical_segment
        .checked_add(data_segment_count as u64)
        .ok_or(StoreError::IdExhausted)?;
    let metadata_generation = state
        .next_segment_generation
        .checked_add(data_segment_count as u64)
        .ok_or(StoreError::IdExhausted)?;
    let next_segment_generation = metadata_generation
        .checked_add(1)
        .ok_or(StoreError::IdExhausted)?;
    let mut previous = state.last_segment;
    if is_new {
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
                )
                .await?,
            );
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
    let mut header_body = [0; PAGE_SIZE];
    let mut header_seal = [0; PAGE_SIZE];
    let header_digest = encode_segment_header_body(&header, &mut header_body)?;
    encode_record_seal(header_digest, &mut header_seal)?;
    write_page(device, base, &header_body).await?;
    flush(device).await?;
    write_page(device, base + 1, &header_seal).await?;
    flush(device).await?;

    let context = CasCodecContext::new(
        state.superblock.binding.store_uuid,
        state.admitted_segments,
        next_segment_generation,
    )?;
    let mut relative = DATA_FIRST_PAGE;
    let mut ordinal = 1_u32;
    let mut records = Vec::new();
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
        write_payload_record(device, base, &record, &manifest_bytes).await?;
        relative += record.value.record_span_pages;
        ordinal += 1;
        let mapping = BlobMapping {
            blob_key,
            manifest: record.pointer(),
        };
        records.push(record);
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
    write_payload_record(device, base, &snapshot_record, &snapshot_bytes).await?;
    relative += snapshot_record.value.record_span_pages;
    ordinal += 1;
    let catalog_root = snapshot_record.pointer();
    records.push(snapshot_record);

    let allocated_prefix_segments = metadata_segment_no + 1;
    let allocation = AllocationState {
        checkpoint_generation,
        admitted_segments: state.admitted_segments,
        allocated_prefix_segments,
        next_segment_generation,
        cleaner_reserve_segments: state.cleaner_reserve_segments,
    };
    let allocation_bytes = encode_allocation(allocation).map_err(|_| StoreError::Corrupt)?;
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
    write_payload_record(device, base, &allocation_record, &allocation_bytes).await?;
    relative += allocation_record.value.record_span_pages;
    let allocation_root = allocation_record.pointer();
    records.push(allocation_record);
    if relative > DATA_END_PAGE {
        return Err(StoreError::Capacity(CapacityClass::Metadata).into());
    }
    finalize_segment(
        device,
        state.superblock.binding.store_uuid,
        checkpoint_generation,
        metadata_segment_no,
        metadata_generation,
        header_digest,
        &records,
    )
    .await?;

    // Re-read every newly published root after the containing segment is fully
    // sealed and before the checkpoint can name it. This mirrors the frozen
    // M7.3 publication proof and also independently verifies Blob bytes/tree.
    if is_new {
        verify_staged_blob(
            device,
            state.superblock.binding.store_uuid,
            state.admitted_segments,
            next_segment_generation,
            checkpoint_generation,
            &scratch_manifest,
            scratch_extents,
        )
        .await?;
        let expected_manifest = encode_blob_manifest(&scratch_manifest, context)?;
        let observed_manifest = read_pointer_payload(
            device,
            state.superblock.binding.store_uuid,
            state.admitted_segments,
            next_segment_generation,
            checkpoint_generation,
            new_blob_mapping.manifest,
            ExtentKind::Catalog,
            limits.recovery_memory_bytes,
        )
        .await?;
        if observed_manifest.bytes != expected_manifest {
            return Err(StoreError::Corrupt.into());
        }
    }
    let observed_snapshot = read_pointer_payload(
        device,
        state.superblock.binding.store_uuid,
        state.admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        catalog_root,
        ExtentKind::Catalog,
        limits.recovery_memory_bytes,
    )
    .await?;
    if observed_snapshot.bytes != snapshot_bytes {
        return Err(StoreError::Corrupt.into());
    }
    let observed_allocation = read_pointer_payload(
        device,
        state.superblock.binding.store_uuid,
        state.admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        allocation_root,
        ExtentKind::Allocation,
        limits.recovery_memory_bytes,
    )
    .await?;
    if observed_allocation.bytes != allocation_bytes {
        return Err(StoreError::Corrupt.into());
    }

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
        authority_root: PhysicalPointer::Null,
        allocation_root,
        replay_tail: PhysicalPointer::Null,
    };
    write_checkpoint(device, &checkpoint, true).await?;
    Ok(CasObjectHandle {
        store_uuid: state.superblock.binding.store_uuid,
        object_id: state.next_object_id,
        object_kind: blob_key.object_kind(),
        exact_len: blob_key.exact_len(),
        commit_generation: checkpoint_generation,
    })
}

async fn write_payload_record<D: PageDevice>(
    device: &D,
    base: u64,
    record: &FinalRecord,
    payload: &[u8],
) -> Result<(), StoreError<D::Error>> {
    let mut copied = 0_usize;
    for page_index in 0..record.value.payload_pages {
        let mut page = [0; PAGE_SIZE];
        let take = (payload.len() - copied).min(PAGE_SIZE);
        page[..take].copy_from_slice(&payload[copied..copied + take]);
        write_page(
            device,
            base + u64::from(record.value.payload_first_relative_page + page_index),
            &page,
        )
        .await?;
        copied += take;
    }
    flush(device).await?;
    let descriptor_relative = record.value.payload_first_relative_page - 2;
    write_page(device, base + u64::from(descriptor_relative), &record.body).await?;
    flush(device).await?;
    write_page(
        device,
        base + u64::from(descriptor_relative + 1),
        &record.seal,
    )
    .await?;
    flush(device).await
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
        assert!(
            find_scratch_extent::<()>(&extents, HEADER_SIZE as u64, CANONICAL_CONTENT_EXTENT_LEN,)
                .is_ok()
        );
        assert!(
            find_scratch_extent::<()>(
                &extents,
                HEADER_SIZE as u64 + CANONICAL_CONTENT_EXTENT_LEN - 1,
                2,
            )
            .is_err()
        );
    }
}
