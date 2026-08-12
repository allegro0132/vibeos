//! Append, checkpoint, and bounded recovery state machine.

use alloc::vec;
use alloc::vec::Vec;
use core::{fmt, mem};

use vibeos_segment_format::{
    ANCHOR_PAGES, ANCHOR_SEGMENT_NO, BodyDigest, Checkpoint, DATA_END_PAGE, DATA_FIRST_PAGE,
    DecodeStatus, ExtentKind, ExtentRecord, FormatError, FormatGeometry, MAX_EXTENT_PAYLOAD_PAGES,
    PAGE_SIZE, Page, PhysicalPointer, PointerValue, RecordBinding, SEGMENT_PAGES,
    SEGMENT_SEAL_BODY_PAGE, SEGMENT_SEAL_PAGE, SUMMARY_BODY_PAGE, SUMMARY_SEAL_PAGE, SegmentHeader,
    SegmentSeal, SegmentSummary, StoreUuid, Superblock, VerifiedRecord, admitted_pages,
    decode_checkpoint_verified, decode_extent_verified, decode_segment_header_verified,
    decode_segment_seal_verified, decode_segment_summary_verified, decode_superblock_verified,
    descriptor_chain_initial, descriptor_chain_next, encode_checkpoint_body, encode_extent_body,
    encode_record_seal, encode_segment_header_body, encode_segment_seal_body,
    encode_segment_summary_body, encode_superblock_body, payload_chain_initial, payload_chain_next,
    payload_sha256, segment_base_page, select_checkpoint_for_superblock, select_superblock,
};
use vibeos_storage_device::{MutationCertainty, MutationFailure};

use crate::cas_codec::{
    BlobManifest, BlobMapping, CasCodecContext, ObjectMapping, decode_blob_manifest,
    decode_cas_snapshot,
};
use crate::codec::{
    AllocationState, CATALOG_ENTRY_LEN, CATALOG_SNAPSHOT_HEADER_LEN, CatalogEntry, CatalogPayload,
    CatalogPayloadKind, CodecError, decode_allocation, decode_catalog, encode_allocation,
    encode_catalog,
};
use crate::device::PageDevice;

const METADATA_KIND_CATALOG: u32 = 0xffff_0001;
const METADATA_KIND_ALLOCATION: u32 = 0xffff_0002;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityClass {
    Payload,
    Metadata,
    CleanerReserve,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreLimits {
    pub max_catalog_entries: u32,
    pub max_replay_records: u32,
    pub recovery_memory_bytes: usize,
    pub max_compat_object_bytes: u64,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            max_catalog_entries: 4096,
            max_replay_records: 32,
            recovery_memory_bytes: 2 * 1024 * 1024,
            max_compat_object_bytes: (MAX_EXTENT_PAYLOAD_PAGES as u64) * (PAGE_SIZE as u64),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormatOptions {
    pub store_uuid: StoreUuid,
    pub cleaner_reserve_segments: u32,
    pub limits: StoreLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectHandle {
    store_uuid: StoreUuid,
    object_id: u128,
    object_kind: u32,
    exact_len: u64,
    commit_generation: u64,
    content_root: [u8; 32],
}

impl ObjectHandle {
    pub const fn object_kind(&self) -> u32 {
        self.object_kind
    }

    pub const fn exact_len(&self) -> u64 {
        self.exact_len
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreInfo {
    pub generation: u64,
    pub admitted_segments: u64,
    pub allocated_segments: u64,
    pub free_segments: u64,
    pub cleaner_reserved_segments: u32,
    pub object_count: u32,
    pub replay_count: u32,
    pub recovery_peak_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreError<E> {
    NotMounted,
    AlreadyFormatted,
    Unformatted,
    InvalidConfig,
    Device(E),
    Mutation(MutationFailure<E>),
    Format(FormatError),
    Corrupt,
    RecoveryRequired,
    Capacity(CapacityClass),
    MemoryLimit,
    ObjectTooLarge,
    ObjectUnavailable,
    ObjectMismatch,
    CatalogMode,
    IdExhausted,
}

impl<E: fmt::Display> fmt::Display for StoreError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotMounted => f.write_str("Storage V2 store is not mounted"),
            Self::AlreadyFormatted => f.write_str("Storage V2 store is already formatted"),
            Self::Unformatted => f.write_str("Storage V2 store is not formatted"),
            Self::InvalidConfig => f.write_str("Storage V2 configuration is invalid"),
            Self::Device(error) => write!(f, "Storage V2 device read failed: {error}"),
            Self::Mutation(_) => f.write_str("Storage V2 device mutation failed"),
            Self::Format(error) => write!(f, "{error}"),
            Self::Corrupt => f.write_str("Storage V2 media is corrupt"),
            Self::RecoveryRequired => f.write_str("Storage V2 requires cold recovery"),
            Self::Capacity(class) => write!(f, "Storage V2 {class:?} capacity exhausted"),
            Self::MemoryLimit => f.write_str("Storage V2 recovery memory ceiling exceeded"),
            Self::ObjectTooLarge => f.write_str("object exceeds the M7.3 compatibility profile"),
            Self::ObjectUnavailable => f.write_str("object is unavailable"),
            Self::ObjectMismatch => f.write_str("object handle does not match this store"),
            Self::CatalogMode => {
                f.write_str("operation is incompatible with the mounted catalog mode")
            }
            Self::IdExhausted => f.write_str("object identifier space is exhausted"),
        }
    }
}

impl<E> From<FormatError> for StoreError<E> {
    fn from(value: FormatError) -> Self {
        Self::Format(value)
    }
}

#[derive(Clone)]
pub(crate) struct CasMountedState {
    pub(crate) objects: Vec<ObjectMapping>,
    pub(crate) blobs: Vec<BlobMapping>,
}

#[derive(Clone)]
pub(crate) struct MountedState {
    pub(crate) superblock: Superblock,
    pub(crate) generation: u64,
    pub(crate) admitted_segments: u64,
    pub(crate) next_physical_segment: u64,
    pub(crate) next_segment_generation: u64,
    pub(crate) next_object_id: u128,
    pub(crate) cleaner_reserve_segments: u32,
    pub(crate) replay_count: u32,
    pub(crate) catalog_root: PhysicalPointer,
    pub(crate) replay_tail: PhysicalPointer,
    pub(crate) catalog: Vec<CatalogEntry>,
    pub(crate) cas: Option<CasMountedState>,
    pub(crate) recovery_peak_bytes: usize,
    pub(crate) last_segment: Option<(u64, u64, [u8; 32])>,
}

pub struct SegmentStore<D> {
    pub(crate) device: D,
    pub(crate) limits: StoreLimits,
    pub(crate) mounted: Option<MountedState>,
    pub(crate) poisoned: bool,
}

impl<D: PageDevice> SegmentStore<D> {
    pub fn new(device: D, limits: StoreLimits) -> Self {
        Self {
            device,
            limits,
            mounted: None,
            poisoned: false,
        }
    }

    pub fn into_device(self) -> D {
        self.device
    }

    pub fn info(&self) -> Result<StoreInfo, StoreError<D::Error>> {
        let state = self.mounted.as_ref().ok_or(if self.poisoned {
            StoreError::RecoveryRequired
        } else {
            StoreError::NotMounted
        })?;
        Ok(state.info())
    }

    pub async fn format(
        &mut self,
        options: FormatOptions,
    ) -> Result<StoreInfo, StoreError<D::Error>> {
        validate_limits(options.limits)?;
        if self.mounted.is_some() {
            return Err(StoreError::AlreadyFormatted);
        }
        let device_info = self.device.info();
        let segments = segments_for_page_count(device_info.page_count)?;
        if options.cleaner_reserve_segments == 0
            || u64::from(options.cleaner_reserve_segments) >= segments
            || options.limits.max_replay_records == 0
        {
            return Err(StoreError::InvalidConfig);
        }

        // Formatting never guesses whether anchor bytes are disposable.  Data
        // segments are outside the format-identification boundary and may hold
        // bytes from an unrelated earlier use of an explicitly provisioned
        // range; the new superblock/checkpoint initially reference none of them.
        let mut page = [0; PAGE_SIZE];
        for page_no in 0..ANCHOR_PAGES {
            self.device
                .read_page(page_no, &mut page)
                .await
                .map_err(StoreError::Device)?;
            if page.iter().any(|byte| *byte != 0) {
                return Err(StoreError::AlreadyFormatted);
            }
        }

        self.limits = options.limits;
        self.poisoned = true;
        let base_binding = RecordBinding {
            store_uuid: options.store_uuid,
            generation: 1,
            segment_no: ANCHOR_SEGMENT_NO,
            ordinal: 0,
            self_page: 0,
            target_checkpoint_generation: 0,
        };
        let superblock_base = Superblock {
            binding: base_binding,
            copy: 0,
            geometry: FormatGeometry::STORAGE_V2,
            cleaner_reserve_segments: options.cleaner_reserve_segments,
            initial_range_pages: device_info.page_count,
            initial_segments: segments,
            device_id: device_info.device_id,
            range_first_logical_block: device_info.range_first_logical_block,
            initial_block_count: device_info.logical_block_count,
            logical_block_size: device_info.logical_block_size,
            max_replay_records: options.limits.max_replay_records,
        };
        let mut superblocks = [superblock_base; 2];
        superblocks[1].copy = 1;
        superblocks[1].binding.ordinal = 1;
        superblocks[1].binding.self_page = 2;

        let mut bodies = [[0; PAGE_SIZE]; 2];
        let mut seals = [[0; PAGE_SIZE]; 2];
        for index in 0..2 {
            let digest = encode_superblock_body(&superblocks[index], &mut bodies[index])?;
            encode_record_seal(digest, &mut seals[index])?;
            write_page(&self.device, (index * 2) as u64, &bodies[index]).await?;
            flush(&self.device).await?;
        }
        for (index, seal) in seals.iter().enumerate() {
            write_page(&self.device, (index * 2 + 1) as u64, seal).await?;
            flush(&self.device).await?;
        }

        let checkpoint = Checkpoint {
            binding: RecordBinding {
                store_uuid: options.store_uuid,
                generation: 1,
                segment_no: ANCHOR_SEGMENT_NO,
                ordinal: 0,
                self_page: 4,
                target_checkpoint_generation: 1,
            },
            slot: 0,
            previous_generation: 0,
            admitted_range_pages: device_info.page_count,
            admitted_segments: segments,
            next_segment_generation: 1,
            replay_count: 0,
            max_replay_records: options.limits.max_replay_records,
            cleaner_reserve_segments: options.cleaner_reserve_segments,
            catalog_root: PhysicalPointer::Null,
            authority_root: PhysicalPointer::Null,
            allocation_root: PhysicalPointer::Null,
            replay_tail: PhysicalPointer::Null,
        };
        write_checkpoint(&self.device, &checkpoint, false).await?;
        self.poisoned = false;
        self.mount().await
    }

    pub async fn mount(&mut self) -> Result<StoreInfo, StoreError<D::Error>> {
        self.mounted = None;
        self.poisoned = false;
        validate_limits(self.limits)?;
        let device_info = self.device.info();
        segments_for_page_count(device_info.page_count)?;

        let left = read_superblock(&self.device, 0).await?;
        let right = read_superblock(&self.device, 2).await?;
        let selected = select_superblock(left, right)?.ok_or(StoreError::Unformatted)?;
        let superblock = *selected.value();
        if superblock.device_id != device_info.device_id
            || superblock.range_first_logical_block != device_info.range_first_logical_block
            || superblock.initial_block_count != device_info.logical_block_count
            || superblock.logical_block_size != device_info.logical_block_size
            || superblock.initial_range_pages > device_info.page_count
            || superblock.max_replay_records != self.limits.max_replay_records
        {
            return Err(StoreError::Corrupt);
        }
        let left = read_checkpoint(&self.device, 4).await?;
        let right = read_checkpoint(&self.device, 6).await?;
        let selected =
            select_checkpoint_for_superblock(selected, left, right, device_info.page_count)?
                .ok_or(StoreError::Unformatted)?;
        // A complete publication marker is a promise to decode strictly even
        // on the older slot.  Validate both sealed stores before choosing which
        // state to install; malformed old metadata is not silently ignored.
        for candidate in [left, right].into_iter().flatten() {
            recover_state(&self.device, superblock, candidate, self.limits).await?;
        }
        let state = recover_state(&self.device, superblock, selected, self.limits).await?;
        let info = state.info();
        self.mounted = Some(state);
        self.poisoned = false;
        Ok(info)
    }

    pub async fn put(
        &mut self,
        object_kind: u32,
        content_root: [u8; 32],
        bytes: &[u8],
    ) -> Result<ObjectHandle, StoreError<D::Error>> {
        let Some(current) = self.mounted.as_ref() else {
            return Err(if self.poisoned {
                StoreError::RecoveryRequired
            } else {
                StoreError::NotMounted
            });
        };
        let byte_len = u64::try_from(bytes.len()).map_err(|_| StoreError::ObjectTooLarge)?;
        if byte_len > self.limits.max_compat_object_bytes
            || byte_len > (MAX_EXTENT_PAYLOAD_PAGES as u64) * (PAGE_SIZE as u64)
        {
            return Err(StoreError::Capacity(CapacityClass::Payload));
        }
        if object_kind == 0 || payload_sha256(bytes) != content_root {
            return Err(StoreError::ObjectMismatch);
        }
        if current.cas.is_some() {
            return Err(StoreError::CatalogMode);
        }
        if current.catalog.len() >= self.limits.max_catalog_entries as usize {
            return Err(StoreError::Capacity(CapacityClass::Metadata));
        }
        let prospective_count = current
            .catalog
            .len()
            .checked_add(1)
            .ok_or(StoreError::Capacity(CapacityClass::Metadata))?;
        let next_is_snapshot = current.catalog_root == PhysicalPointer::Null
            || current.replay_count + 1 >= self.limits.max_replay_records;
        let snapshot_bytes = CATALOG_SNAPSHOT_HEADER_LEN
            .checked_add(
                prospective_count
                    .checked_mul(CATALOG_ENTRY_LEN)
                    .ok_or(StoreError::Capacity(CapacityClass::Metadata))?,
            )
            .ok_or(StoreError::Capacity(CapacityClass::Metadata))?;
        if (next_is_snapshot && snapshot_bytes > MAX_EXTENT_PAYLOAD_PAGES as usize * PAGE_SIZE)
            || recovery_memory_upper_bound(prospective_count, snapshot_bytes)
                > self.limits.recovery_memory_bytes
        {
            return Err(StoreError::Capacity(CapacityClass::Metadata));
        }
        if current.next_physical_segment
            >= current
                .admitted_segments
                .saturating_sub(u64::from(current.cleaner_reserve_segments))
        {
            return Err(StoreError::Capacity(CapacityClass::CleanerReserve));
        }

        // Taking the state before the first await makes cancellation invalidate
        // every cached cursor.  Only a complete reread below installs a state.
        let state = self.mounted.take().ok_or(StoreError::NotMounted)?;
        self.poisoned = true;
        let result = append_object(
            &self.device,
            &state,
            self.limits,
            object_kind,
            content_root,
            bytes,
        )
        .await;
        match result {
            Ok((handle, recovered)) => {
                self.mounted = Some(recovered);
                self.poisoned = false;
                Ok(handle)
            }
            Err(error) => Err(error),
        }
    }

    pub async fn get(&self, handle: &ObjectHandle) -> Result<Vec<u8>, StoreError<D::Error>> {
        let state = self.mounted.as_ref().ok_or(if self.poisoned {
            StoreError::RecoveryRequired
        } else {
            StoreError::NotMounted
        })?;
        let entry = state
            .catalog
            .iter()
            .find(|entry| entry.object_id == handle.object_id)
            .copied()
            .ok_or(StoreError::ObjectUnavailable)?;
        if handle.store_uuid != state.superblock.binding.store_uuid
            || handle.object_kind != entry.object_kind
            || handle.exact_len != entry.exact_len
            || handle.commit_generation != entry.commit_generation
            || handle.content_root != entry.content_root
        {
            return Err(StoreError::ObjectMismatch);
        }
        if entry.exact_len == 0 {
            if entry.blob != PhysicalPointer::Null {
                return Err(StoreError::Corrupt);
            }
            return Ok(Vec::new());
        }
        let resolved = read_pointer_payload(
            &self.device,
            state.superblock.binding.store_uuid,
            state.admitted_segments,
            state.next_segment_generation,
            state.generation,
            entry.blob,
            ExtentKind::Blob,
            self.limits.max_compat_object_bytes as usize,
        )
        .await?;
        if resolved.bytes.len() as u64 != entry.exact_len
            || resolved.extent.object_kind != entry.object_kind
            || resolved.extent.binding.target_checkpoint_generation != entry.commit_generation
            || resolved.extent.content_byte_len != entry.exact_len
            || resolved.extent.encoded_blob_len != entry.exact_len
            || resolved.extent.encoded_offset != 0
            || resolved.extent.merkle_root != entry.content_root
            || payload_sha256(&resolved.bytes) != entry.content_root
        {
            return Err(StoreError::Corrupt);
        }
        Ok(resolved.bytes)
    }
}

impl MountedState {
    fn info(&self) -> StoreInfo {
        let allocated_segments = self.next_physical_segment;
        let free_segments = self.admitted_segments.saturating_sub(allocated_segments);
        StoreInfo {
            generation: self.generation,
            admitted_segments: self.admitted_segments,
            allocated_segments,
            free_segments,
            cleaner_reserved_segments: self.cleaner_reserve_segments,
            object_count: self
                .cas
                .as_ref()
                .map_or(self.catalog.len(), |cas| cas.objects.len())
                as u32,
            replay_count: self.replay_count,
            recovery_peak_bytes: self.recovery_peak_bytes,
        }
    }
}

fn validate_limits<E>(limits: StoreLimits) -> Result<(), StoreError<E>> {
    let maximum_catalog_entries = (MAX_EXTENT_PAYLOAD_PAGES as usize * PAGE_SIZE
        - CATALOG_SNAPSHOT_HEADER_LEN)
        / CATALOG_ENTRY_LEN;
    if limits.max_catalog_entries == 0
        || limits.max_catalog_entries as usize > maximum_catalog_entries
        || limits.max_replay_records == 0
        || limits.recovery_memory_bytes < mem::size_of::<CatalogEntry>()
        || limits.max_compat_object_bytes > (MAX_EXTENT_PAYLOAD_PAGES as u64) * PAGE_SIZE as u64
    {
        Err(StoreError::InvalidConfig)
    } else {
        Ok(())
    }
}

fn recovery_memory_upper_bound(entry_count: usize, largest_snapshot_bytes: usize) -> usize {
    entry_count
        .checked_mul(mem::size_of::<CatalogEntry>())
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| bytes.checked_add(largest_snapshot_bytes))
        .unwrap_or(usize::MAX)
}

fn segments_for_page_count<E>(page_count: u64) -> Result<u64, StoreError<E>> {
    let data_pages = page_count
        .checked_sub(ANCHOR_PAGES)
        .ok_or(StoreError::InvalidConfig)?;
    if data_pages == 0 || data_pages % SEGMENT_PAGES != 0 {
        return Err(StoreError::InvalidConfig);
    }
    Ok(data_pages / SEGMENT_PAGES)
}

async fn write_page<D: PageDevice>(
    device: &D,
    page: u64,
    input: &Page,
) -> Result<(), StoreError<D::Error>> {
    device
        .write_page(page, input)
        .await
        .map_err(StoreError::Mutation)
}

async fn flush<D: PageDevice>(device: &D) -> Result<(), StoreError<D::Error>> {
    device.flush().await.map_err(StoreError::Mutation)
}

async fn read_pair<D: PageDevice>(
    device: &D,
    body_page: u64,
) -> Result<(Page, Page), StoreError<D::Error>> {
    let mut body = [0; PAGE_SIZE];
    let mut seal = [0; PAGE_SIZE];
    device
        .read_page(body_page, &mut body)
        .await
        .map_err(StoreError::Device)?;
    device
        .read_page(body_page + 1, &mut seal)
        .await
        .map_err(StoreError::Device)?;
    Ok((body, seal))
}

fn optional_verified<T>(status: DecodeStatus<VerifiedRecord<T>>) -> Option<VerifiedRecord<T>> {
    match status {
        DecodeStatus::Sealed(value) => Some(value),
        DecodeStatus::Empty | DecodeStatus::Unsealed => None,
    }
}

async fn read_superblock<D: PageDevice>(
    device: &D,
    page: u64,
) -> Result<Option<VerifiedRecord<Superblock>>, StoreError<D::Error>> {
    let (body, seal) = read_pair(device, page).await?;
    Ok(optional_verified(decode_superblock_verified(&body, &seal)?))
}

async fn read_checkpoint<D: PageDevice>(
    device: &D,
    page: u64,
) -> Result<Option<VerifiedRecord<Checkpoint>>, StoreError<D::Error>> {
    let (body, seal) = read_pair(device, page).await?;
    Ok(optional_verified(decode_checkpoint_verified(&body, &seal)?))
}

pub(crate) async fn write_checkpoint<D: PageDevice>(
    device: &D,
    checkpoint: &Checkpoint,
    clear_first: bool,
) -> Result<VerifiedRecord<Checkpoint>, StoreError<D::Error>> {
    let body_page = 4 + u64::from(checkpoint.slot) * 2;
    if clear_first {
        let zero = [0; PAGE_SIZE];
        // Remove the old publication marker before touching its body.  Clearing
        // the body first could leave a durable old seal authenticating zero or
        // torn bytes, which is correctly fatal to the strict decoder.
        write_page(device, body_page + 1, &zero).await?;
        flush(device).await?;
        let mut observed_seal = [0; PAGE_SIZE];
        device
            .read_page(body_page + 1, &mut observed_seal)
            .await
            .map_err(StoreError::Device)?;
        if observed_seal.iter().any(|byte| *byte != 0) {
            return Err(StoreError::Corrupt);
        }
    }
    let mut body = [0; PAGE_SIZE];
    let mut seal = [0; PAGE_SIZE];
    let digest = encode_checkpoint_body(checkpoint, &mut body)?;
    encode_record_seal(digest, &mut seal)?;
    write_page(device, body_page, &body).await?;
    flush(device).await?;
    write_page(device, body_page + 1, &seal).await?;
    flush(device).await?;
    let (observed_body, observed_seal) = read_pair(device, body_page).await?;
    match decode_checkpoint_verified(&observed_body, &observed_seal)? {
        DecodeStatus::Sealed(value) if value.value() == checkpoint => Ok(value),
        _ => Err(StoreError::Corrupt),
    }
}

fn codec_error<E>(error: CodecError) -> StoreError<E> {
    match error {
        CodecError::ArithmeticOverflow => StoreError::Format(FormatError::ArithmeticOverflow),
        CodecError::Format(_) => StoreError::Corrupt,
        _ => StoreError::Corrupt,
    }
}

pub(crate) struct ScannedSegment {
    pub(crate) matched: Option<ExtentRecord>,
    pub(crate) segment_seal_body_sha256: [u8; 32],
}

pub(crate) async fn scan_segment<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    pointer: PointerValue,
) -> Result<ScannedSegment, StoreError<D::Error>> {
    if pointer.store_uuid != store_uuid
        || pointer.segment_no >= admitted_segments
        || pointer.segment_generation == 0
        || pointer.segment_generation >= next_segment_generation
    {
        return Err(StoreError::Corrupt);
    }
    let base = segment_base_page(pointer.segment_no)?;
    let (header_body, header_seal) = read_pair(device, base).await?;
    let header = match decode_segment_header_verified(&header_body, &header_seal)? {
        DecodeStatus::Sealed(value) => value,
        _ => return Err(StoreError::Corrupt),
    };
    if header.value().binding.store_uuid != store_uuid
        || header.value().binding.segment_no != pointer.segment_no
        || header.value().binding.generation != pointer.segment_generation
        || header.value().binding.target_checkpoint_generation > checkpoint_generation
    {
        return Err(StoreError::Corrupt);
    }

    let (summary_body, summary_seal_page) =
        read_pair(device, base + u64::from(SUMMARY_BODY_PAGE)).await?;
    let summary = match decode_segment_summary_verified(&summary_body, &summary_seal_page)? {
        DecodeStatus::Sealed(value) => value,
        _ => return Err(StoreError::Corrupt),
    };
    let (segment_seal_body, final_seal_page) =
        read_pair(device, base + u64::from(SEGMENT_SEAL_BODY_PAGE)).await?;
    let segment_seal = match decode_segment_seal_verified(&segment_seal_body, &final_seal_page)? {
        DecodeStatus::Sealed(value) => value,
        _ => return Err(StoreError::Corrupt),
    };

    let mut relative = DATA_FIRST_PAGE;
    let mut descriptor_chain =
        descriptor_chain_initial(store_uuid, pointer.segment_no, pointer.segment_generation);
    let mut payload_chain =
        payload_chain_initial(store_uuid, pointer.segment_no, pointer.segment_generation);
    let mut payload_pages = 0_u32;
    let mut total_bytes = 0_u64;
    let mut kind_counts = [0_u32; 5];
    let mut kind_bytes = [0_u64; 5];
    let mut first_target = 0_u64;
    let mut last_target = 0_u64;
    let mut matched = None;
    for ordinal in 1..=summary.value().record_count {
        let (body, seal) = read_pair(device, base + u64::from(relative)).await?;
        let extent = match decode_extent_verified(&body, &seal)? {
            DecodeStatus::Sealed(value) => value,
            _ => return Err(StoreError::Corrupt),
        };
        let value = *extent.value();
        if value.binding.store_uuid != store_uuid
            || value.binding.segment_no != pointer.segment_no
            || value.binding.generation != pointer.segment_generation
            || value.binding.ordinal != ordinal
            || value.binding.self_page != base + u64::from(relative)
            || value.binding.target_checkpoint_generation > checkpoint_generation
            || value.payload_first_relative_page != relative + 2
            || (last_target != 0 && value.binding.target_checkpoint_generation < last_target)
        {
            return Err(StoreError::Corrupt);
        }
        if first_target == 0 {
            first_target = value.binding.target_checkpoint_generation;
        }
        last_target = value.binding.target_checkpoint_generation;
        descriptor_chain = descriptor_chain_next(
            store_uuid,
            pointer.segment_no,
            pointer.segment_generation,
            descriptor_chain,
            ordinal,
            extent.digest().body_sha256(),
            value.payload_sha256,
        );
        payload_chain = payload_chain_next(
            store_uuid,
            pointer.segment_no,
            pointer.segment_generation,
            payload_chain,
            ordinal,
            value.payload_byte_len,
            value.payload_sha256,
        );
        payload_pages = payload_pages
            .checked_add(value.payload_pages)
            .ok_or(StoreError::Corrupt)?;
        total_bytes = total_bytes
            .checked_add(value.payload_byte_len)
            .ok_or(StoreError::Corrupt)?;
        let kind = extent_kind_index(value.extent_kind);
        kind_counts[kind] = kind_counts[kind]
            .checked_add(1)
            .ok_or(StoreError::Corrupt)?;
        kind_bytes[kind] = kind_bytes[kind]
            .checked_add(value.payload_byte_len)
            .ok_or(StoreError::Corrupt)?;
        if relative == pointer.descriptor_relative_page && ordinal == pointer.ordinal {
            matched = Some(value);
        }
        relative = relative
            .checked_add(value.record_span_pages)
            .ok_or(StoreError::Corrupt)?;
    }
    let summary_value = summary.value();
    let seal_value = segment_seal.value();
    if relative != summary_value.next_free_page
        || payload_pages != summary_value.payload_page_count
        || total_bytes != summary_value.total_payload_bytes
        || first_target != summary_value.first_target_checkpoint_generation
        || last_target != summary_value.last_target_checkpoint_generation
        || header.digest().body_sha256() != summary_value.header_body_sha256
        || descriptor_chain != summary_value.descriptor_chain_sha256
        || payload_chain != summary_value.payload_chain_sha256
        || kind_counts != summary_value.kind_counts
        || kind_bytes != summary_value.kind_bytes
        || segment_seal.value().binding.store_uuid != store_uuid
        || seal_value.binding.segment_no != pointer.segment_no
        || seal_value.binding.generation != pointer.segment_generation
        || seal_value.header_body_sha256 != header.digest().body_sha256()
        || seal_value.summary_body_sha256 != summary.digest().body_sha256()
        || seal_value.final_descriptor_chain_sha256 != descriptor_chain
        || seal_value.final_payload_chain_sha256 != payload_chain
        || seal_value.record_count != summary_value.record_count
        || seal_value.next_free_page != summary_value.next_free_page
        || seal_value.payload_page_count != summary_value.payload_page_count
        || seal_value.total_payload_bytes != summary_value.total_payload_bytes
        || seal_value.target_checkpoint_generation
            != summary_value.last_target_checkpoint_generation
    {
        return Err(StoreError::Corrupt);
    }
    Ok(ScannedSegment {
        matched,
        segment_seal_body_sha256: segment_seal.digest().body_sha256(),
    })
}

pub(crate) struct ResolvedPayload {
    pub(crate) bytes: Vec<u8>,
    pub(crate) extent: ExtentRecord,
    pub(crate) segment_seal_body_sha256: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn read_pointer_payload<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    pointer: PhysicalPointer,
    expected_kind: ExtentKind,
    maximum_bytes: usize,
) -> Result<ResolvedPayload, StoreError<D::Error>> {
    let PhysicalPointer::Value(pointer) = pointer else {
        return Err(StoreError::Corrupt);
    };
    if pointer.extent_kind != expected_kind
        || pointer.exact_byte_len > maximum_bytes as u64
        || pointer.exact_byte_len > MAX_EXTENT_PAYLOAD_PAGES as u64 * PAGE_SIZE as u64
    {
        return Err(StoreError::Corrupt);
    }
    let scanned = scan_segment(
        device,
        store_uuid,
        admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        pointer,
    )
    .await?;
    let extent = scanned.matched.ok_or(StoreError::Corrupt)?;
    if extent.extent_kind != pointer.extent_kind
        || extent.payload_first_relative_page != pointer.payload_relative_page
        || extent.payload_pages != pointer.payload_pages
        || extent.payload_byte_len != pointer.exact_byte_len
        || extent.payload_sha256 != pointer.payload_sha256
        || (expected_kind != ExtentKind::Blob
            && (extent.extent_index != 0
                || extent.extent_count != 1
                || extent.content_byte_len != pointer.exact_byte_len
                || extent.encoded_blob_len != pointer.exact_byte_len
                || extent.encoded_offset != 0
                || extent.merkle_root != pointer.payload_sha256))
    {
        return Err(StoreError::Corrupt);
    }
    let exact_len = usize::try_from(pointer.exact_byte_len).map_err(|_| StoreError::Corrupt)?;
    let mut bytes = vec![0; exact_len];
    let base = segment_base_page(pointer.segment_no)?;
    let mut copied = 0;
    for index in 0..pointer.payload_pages {
        let mut page = [0; PAGE_SIZE];
        device
            .read_page(
                base + u64::from(pointer.payload_relative_page) + u64::from(index),
                &mut page,
            )
            .await
            .map_err(StoreError::Device)?;
        let remaining = exact_len - copied;
        let take = remaining.min(PAGE_SIZE);
        bytes[copied..copied + take].copy_from_slice(&page[..take]);
        copied += take;
    }
    if copied != exact_len || payload_sha256(&bytes) != pointer.payload_sha256 {
        return Err(StoreError::Corrupt);
    }
    Ok(ResolvedPayload {
        bytes,
        extent,
        segment_seal_body_sha256: scanned.segment_seal_body_sha256,
    })
}

async fn recover_state<D: PageDevice>(
    device: &D,
    superblock: Superblock,
    checkpoint: VerifiedRecord<Checkpoint>,
    limits: StoreLimits,
) -> Result<MountedState, StoreError<D::Error>> {
    let checkpoint = *checkpoint.value();
    let mut catalog = Vec::new();
    let mut cas = None;
    let mut cas_max_referenced_segment = None::<u64>;
    let mut recovery_peak = 0_usize;
    if checkpoint.catalog_root != PhysicalPointer::Null {
        let snapshot = read_pointer_payload(
            device,
            superblock.binding.store_uuid,
            checkpoint.admitted_segments,
            checkpoint.next_segment_generation,
            checkpoint.binding.generation,
            checkpoint.catalog_root,
            ExtentKind::Catalog,
            limits.recovery_memory_bytes,
        )
        .await?;
        if snapshot.bytes.starts_with(b"VIBECAS2") {
            if checkpoint.replay_count != 0
                || checkpoint.replay_tail != PhysicalPointer::Null
                || checkpoint.authority_root != PhysicalPointer::Null
            {
                return Err(StoreError::Corrupt);
            }
            let context = CasCodecContext::new(
                superblock.binding.store_uuid,
                checkpoint.admitted_segments,
                checkpoint.next_segment_generation,
            )
            .map_err(|_| StoreError::Corrupt)?;
            let decoded =
                decode_cas_snapshot(&snapshot.bytes, context).map_err(|_| StoreError::Corrupt)?;
            if decoded.checkpoint_generation != checkpoint.binding.generation
                || decoded.checkpoint_generation
                    != snapshot.extent.binding.target_checkpoint_generation
                || decoded.objects.len() > limits.max_catalog_entries as usize
                || decoded.blobs.len() > limits.max_catalog_entries as usize
            {
                return Err(StoreError::Corrupt);
            }
            let cas_bytes = decoded
                .objects
                .capacity()
                .checked_mul(mem::size_of::<ObjectMapping>())
                .and_then(|bytes| {
                    decoded
                        .blobs
                        .capacity()
                        .checked_mul(mem::size_of::<BlobMapping>())
                        .and_then(|more| bytes.checked_add(more))
                })
                .ok_or(StoreError::MemoryLimit)?;
            let snapshot_capacity = snapshot.bytes.capacity();
            recovery_peak = cas_bytes
                .checked_add(snapshot_capacity)
                .ok_or(StoreError::MemoryLimit)?;
            // The decoded tables own their data; release the encoded snapshot
            // before reading a manifest so the measured recovery peak is also
            // the actual live-memory bound.
            drop(snapshot);
            for blob in &decoded.blobs {
                let PhysicalPointer::Value(manifest_pointer) = blob.manifest else {
                    return Err(StoreError::Corrupt);
                };
                cas_max_referenced_segment = Some(
                    cas_max_referenced_segment.map_or(manifest_pointer.segment_no, |current| {
                        current.max(manifest_pointer.segment_no)
                    }),
                );
                let manifest = read_pointer_payload(
                    device,
                    superblock.binding.store_uuid,
                    checkpoint.admitted_segments,
                    checkpoint.next_segment_generation,
                    checkpoint.binding.generation,
                    blob.manifest,
                    ExtentKind::Catalog,
                    limits.recovery_memory_bytes,
                )
                .await?;
                let decoded_manifest = decode_blob_manifest(&manifest.bytes, context)
                    .map_err(|_| StoreError::Corrupt)?;
                if decoded_manifest.blob_key != blob.blob_key {
                    return Err(StoreError::Corrupt);
                }
                for declared in &decoded_manifest.extents {
                    let PhysicalPointer::Value(pointer) = declared.pointer else {
                        return Err(StoreError::Corrupt);
                    };
                    cas_max_referenced_segment = Some(
                        cas_max_referenced_segment.map_or(pointer.segment_no, |current| {
                            current.max(pointer.segment_no)
                        }),
                    );
                }
                validate_cas_blob_descriptors(
                    device,
                    superblock.binding.store_uuid,
                    checkpoint.admitted_segments,
                    checkpoint.next_segment_generation,
                    checkpoint.binding.generation,
                    &decoded_manifest,
                )
                .await?;
                recovery_peak = recovery_peak.max(
                    cas_bytes
                        .checked_add(manifest.bytes.capacity())
                        .and_then(|bytes| {
                            bytes.checked_add(
                                decoded_manifest.extents.capacity()
                                    * mem::size_of::<crate::cas_codec::ManifestExtent>(),
                            )
                        })
                        .ok_or(StoreError::MemoryLimit)?,
                );
            }
            cas = Some(CasMountedState {
                objects: decoded.objects,
                blobs: decoded.blobs,
            });
        } else {
            let decoded = decode_catalog(&snapshot.bytes, superblock.binding.store_uuid)
                .map_err(codec_error)?;
            if decoded.kind != CatalogPayloadKind::Snapshot
                || decoded.checkpoint_generation > checkpoint.binding.generation
                || decoded.checkpoint_generation
                    != snapshot.extent.binding.target_checkpoint_generation
                || decoded.chain_count != decoded.entries.len() as u64
                || decoded.previous_delta != PhysicalPointer::Null
            {
                return Err(StoreError::Corrupt);
            }
            if decoded.entries.len() > limits.max_catalog_entries as usize {
                return Err(StoreError::MemoryLimit);
            }
            catalog = decoded.entries;
            recovery_peak = measured_catalog_bytes(&catalog)
                .checked_add(snapshot.bytes.capacity())
                .ok_or(StoreError::MemoryLimit)?;
        }
        if recovery_peak > limits.recovery_memory_bytes {
            return Err(StoreError::MemoryLimit);
        }
    }

    if checkpoint.authority_root != PhysicalPointer::Null {
        let authority = read_pointer_payload(
            device,
            superblock.binding.store_uuid,
            checkpoint.admitted_segments,
            checkpoint.next_segment_generation,
            checkpoint.binding.generation,
            checkpoint.authority_root,
            ExtentKind::Authority,
            limits.recovery_memory_bytes,
        )
        .await?;
        recovery_peak = recovery_peak.max(
            measured_catalog_bytes(&catalog)
                .checked_add(authority.bytes.capacity())
                .ok_or(StoreError::MemoryLimit)?,
        );
        if recovery_peak > limits.recovery_memory_bytes {
            return Err(StoreError::MemoryLimit);
        }
    }

    let mut reverse_deltas = Vec::new();
    let replay_capacity_bytes = usize::try_from(checkpoint.replay_count)
        .ok()
        .and_then(|count| count.checked_mul(mem::size_of::<CatalogEntry>()))
        .ok_or(StoreError::MemoryLimit)?;
    let replay_allocation_peak = measured_catalog_bytes(&catalog)
        .checked_add(replay_capacity_bytes)
        .ok_or(StoreError::MemoryLimit)?;
    if replay_allocation_peak > limits.recovery_memory_bytes {
        return Err(StoreError::MemoryLimit);
    }
    reverse_deltas
        .try_reserve_exact(checkpoint.replay_count as usize)
        .map_err(|_| StoreError::MemoryLimit)?;
    recovery_peak = recovery_peak.max(
        measured_catalog_bytes(&catalog)
            .checked_add(reverse_deltas.capacity() * mem::size_of::<CatalogEntry>())
            .ok_or(StoreError::MemoryLimit)?,
    );
    let mut pointer = checkpoint.replay_tail;
    let mut expected_depth = u64::from(checkpoint.replay_count);
    while expected_depth != 0 {
        let delta = read_pointer_payload(
            device,
            superblock.binding.store_uuid,
            checkpoint.admitted_segments,
            checkpoint.next_segment_generation,
            checkpoint.binding.generation,
            pointer,
            ExtentKind::CatalogDelta,
            limits.recovery_memory_bytes,
        )
        .await?;
        let decoded =
            decode_catalog(&delta.bytes, superblock.binding.store_uuid).map_err(codec_error)?;
        if decoded.kind != CatalogPayloadKind::Delta
            || decoded.entries.len() != 1
            || decoded.chain_count != expected_depth
            || decoded.checkpoint_generation > checkpoint.binding.generation
            || decoded.checkpoint_generation != delta.extent.binding.target_checkpoint_generation
        {
            return Err(StoreError::Corrupt);
        }
        reverse_deltas.push(decoded.entries[0]);
        pointer = decoded.previous_delta;
        expected_depth -= 1;
        let peak = measured_catalog_bytes(&catalog)
            .checked_add(reverse_deltas.capacity() * mem::size_of::<CatalogEntry>())
            .and_then(|value| value.checked_add(delta.bytes.capacity()))
            .ok_or(StoreError::MemoryLimit)?;
        recovery_peak = recovery_peak.max(peak);
        if recovery_peak > limits.recovery_memory_bytes {
            return Err(StoreError::MemoryLimit);
        }
    }
    if pointer != PhysicalPointer::Null {
        return Err(StoreError::Corrupt);
    }
    for entry in reverse_deltas.into_iter().rev() {
        catalog.push(entry);
    }
    if cas.is_none() {
        validate_catalog(
            &catalog,
            superblock.binding.store_uuid,
            checkpoint.admitted_segments,
            checkpoint.next_segment_generation,
            checkpoint.binding.generation,
            limits,
        )?;
    }
    recovery_peak = recovery_peak.max(measured_catalog_bytes(&catalog));
    if recovery_peak > limits.recovery_memory_bytes {
        return Err(StoreError::MemoryLimit);
    }
    let (allocated_prefix, last_segment) = if checkpoint.allocation_root == PhysicalPointer::Null {
        if checkpoint.binding.generation != 1 || !catalog.is_empty() || cas.is_some() {
            return Err(StoreError::Corrupt);
        }
        (0, None)
    } else {
        let allocation = read_pointer_payload(
            device,
            superblock.binding.store_uuid,
            checkpoint.admitted_segments,
            checkpoint.next_segment_generation,
            checkpoint.binding.generation,
            checkpoint.allocation_root,
            ExtentKind::Allocation,
            limits.recovery_memory_bytes,
        )
        .await?;
        let decoded = decode_allocation(&allocation.bytes).map_err(codec_error)?;
        if decoded.checkpoint_generation != checkpoint.binding.generation
            || decoded.checkpoint_generation
                != allocation.extent.binding.target_checkpoint_generation
            || decoded.admitted_segments != checkpoint.admitted_segments
            || decoded.allocated_prefix_segments == 0
            || decoded.allocated_prefix_segments > checkpoint.admitted_segments
            || decoded.next_segment_generation != checkpoint.next_segment_generation
            || decoded.cleaner_reserve_segments != checkpoint.cleaner_reserve_segments
        {
            return Err(StoreError::Corrupt);
        }
        let PhysicalPointer::Value(root) = checkpoint.allocation_root else {
            return Err(StoreError::Corrupt);
        };
        if root.segment_no + 1 != decoded.allocated_prefix_segments {
            return Err(StoreError::Corrupt);
        }
        recovery_peak = recovery_peak.max(
            measured_catalog_bytes(&catalog)
                .checked_add(allocation.bytes.capacity())
                .ok_or(StoreError::MemoryLimit)?,
        );
        (
            decoded.allocated_prefix_segments,
            Some((
                root.segment_no,
                root.segment_generation,
                allocation.segment_seal_body_sha256,
            )),
        )
    };
    if recovery_peak > limits.recovery_memory_bytes {
        return Err(StoreError::MemoryLimit);
    }
    if cas_max_referenced_segment.is_some_and(|segment_no| segment_no >= allocated_prefix) {
        return Err(StoreError::Corrupt);
    }

    for pointer in [
        checkpoint.catalog_root,
        checkpoint.authority_root,
        checkpoint.allocation_root,
        checkpoint.replay_tail,
    ] {
        if let PhysicalPointer::Value(pointer) = pointer {
            if pointer.segment_no >= allocated_prefix {
                return Err(StoreError::Corrupt);
            }
        }
    }
    for entry in &catalog {
        if let PhysicalPointer::Value(pointer) = entry.blob {
            if pointer.segment_no >= allocated_prefix {
                return Err(StoreError::Corrupt);
            }
            validate_blob_descriptor(
                device,
                superblock.binding.store_uuid,
                checkpoint.admitted_segments,
                checkpoint.next_segment_generation,
                checkpoint.binding.generation,
                entry,
                pointer,
            )
            .await?;
        }
    }

    // Never overwrite a published tail. M7.3 quarantines through the last
    // non-zero final-seal page after the committed frontier. Internal bytes
    // behind an exact-zero publication page are safe to replace only through
    // the explicit zero/flush/reread gate in append_object.
    let mut next_physical_segment = allocated_prefix;
    for segment_no in allocated_prefix..checkpoint.admitted_segments {
        let base = segment_base_page(segment_no)?;
        let mut final_seal = [0; PAGE_SIZE];
        device
            .read_page(base + u64::from(SEGMENT_SEAL_PAGE), &mut final_seal)
            .await
            .map_err(StoreError::Device)?;
        if final_seal.iter().any(|byte| *byte != 0) {
            next_physical_segment = segment_no.checked_add(1).ok_or(StoreError::Corrupt)?;
        }
    }
    let next_object_id = cas
        .as_ref()
        .and_then(|cas| cas.objects.last().map(|entry| entry.object_id))
        .or_else(|| catalog.last().map(|entry| entry.object_id))
        .map(|object_id| object_id.checked_add(1).ok_or(StoreError::IdExhausted))
        .transpose()?
        .unwrap_or(1);
    Ok(MountedState {
        superblock,
        generation: checkpoint.binding.generation,
        admitted_segments: checkpoint.admitted_segments,
        next_physical_segment,
        next_segment_generation: checkpoint.next_segment_generation,
        next_object_id,
        cleaner_reserve_segments: checkpoint.cleaner_reserve_segments,
        replay_count: checkpoint.replay_count,
        catalog_root: checkpoint.catalog_root,
        replay_tail: checkpoint.replay_tail,
        catalog,
        cas,
        recovery_peak_bytes: recovery_peak,
        last_segment,
    })
}

#[allow(clippy::too_many_arguments)]
async fn validate_blob_descriptor<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    entry: &CatalogEntry,
    pointer: PointerValue,
) -> Result<(), StoreError<D::Error>> {
    let scanned = scan_segment(
        device,
        store_uuid,
        admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        pointer,
    )
    .await?;
    let extent = scanned.matched.ok_or(StoreError::Corrupt)?;
    if extent.extent_kind != ExtentKind::Blob
        || extent.binding.target_checkpoint_generation != entry.commit_generation
        || extent.object_kind != entry.object_kind
        || extent.extent_index != 0
        || extent.extent_count != 1
        || extent.content_byte_len != entry.exact_len
        || extent.encoded_blob_len != entry.exact_len
        || extent.encoded_offset != 0
        || extent.payload_byte_len != entry.exact_len
        || extent.payload_first_relative_page != pointer.payload_relative_page
        || extent.payload_pages != pointer.payload_pages
        || extent.merkle_root != entry.content_root
        || extent.payload_sha256 != entry.content_root
    {
        return Err(StoreError::Corrupt);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn validate_cas_blob_descriptors<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    manifest: &BlobManifest,
) -> Result<(), StoreError<D::Error>> {
    for declared in &manifest.extents {
        let PhysicalPointer::Value(pointer) = declared.pointer else {
            return Err(StoreError::Corrupt);
        };
        let scanned = scan_segment(
            device,
            store_uuid,
            admitted_segments,
            next_segment_generation,
            checkpoint_generation,
            pointer,
        )
        .await?;
        let extent = scanned.matched.ok_or(StoreError::Corrupt)?;
        if extent.extent_kind != ExtentKind::Blob
            || extent.object_kind != manifest.blob_key.object_kind()
            || extent.extent_index != declared.extent_index
            || extent.extent_count != declared.extent_count
            || extent.content_byte_len != manifest.blob_key.exact_len()
            || extent.encoded_blob_len != manifest.encoded_blob_len
            || extent.encoded_offset != declared.encoded_offset
            || extent.payload_byte_len != declared.payload_byte_len
            || extent.merkle_root != manifest.blob_key.merkle_root()
            || extent.payload_first_relative_page != pointer.payload_relative_page
            || extent.payload_pages != pointer.payload_pages
            || extent.payload_sha256 != pointer.payload_sha256
        {
            return Err(StoreError::Corrupt);
        }
    }
    Ok(())
}

fn measured_catalog_bytes(catalog: &Vec<CatalogEntry>) -> usize {
    catalog.capacity() * mem::size_of::<CatalogEntry>()
}

fn validate_catalog<E>(
    catalog: &[CatalogEntry],
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    limits: StoreLimits,
) -> Result<(), StoreError<E>> {
    if catalog.len() > limits.max_catalog_entries as usize {
        return Err(StoreError::MemoryLimit);
    }
    let mut previous = 0_u128;
    for entry in catalog {
        if entry.object_id == 0
            || entry.object_id <= previous
            || entry.object_kind == 0
            || entry.commit_generation == 0
            || entry.commit_generation > checkpoint_generation
            || (entry.exact_len == 0) != (entry.blob == PhysicalPointer::Null)
        {
            return Err(StoreError::Corrupt);
        }
        if let PhysicalPointer::Value(pointer) = entry.blob {
            if pointer.store_uuid != store_uuid
                || pointer.extent_kind != ExtentKind::Blob
                || pointer.segment_no >= admitted_segments
                || pointer.segment_generation >= next_segment_generation
                || pointer.exact_byte_len != entry.exact_len
                || pointer.payload_sha256 != entry.content_root
            {
                return Err(StoreError::Corrupt);
            }
        }
        previous = entry.object_id;
    }
    Ok(())
}

struct BuiltExtent<'a> {
    value: ExtentRecord,
    digest: BodyDigest,
    body: Page,
    seal: Page,
    payload: &'a [u8],
}

impl BuiltExtent<'_> {
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
fn build_extent<'a>(
    store_uuid: StoreUuid,
    segment_no: u64,
    segment_generation: u64,
    checkpoint_generation: u64,
    ordinal: u32,
    relative_page: u32,
    kind: ExtentKind,
    object_kind: u32,
    content_len: u64,
    content_root: [u8; 32],
    payload: &'a [u8],
) -> Result<BuiltExtent<'a>, FormatError> {
    let payload_len = u64::try_from(payload.len()).map_err(|_| FormatError::ArithmeticOverflow)?;
    if payload_len == 0 {
        return Err(FormatError::InvalidPayloadLength);
    }
    let payload_pages = u32::try_from(payload.len().div_ceil(PAGE_SIZE))
        .map_err(|_| FormatError::ArithmeticOverflow)?;
    let record_span_pages = payload_pages
        .checked_add(2)
        .ok_or(FormatError::ArithmeticOverflow)?;
    let base = segment_base_page(segment_no)?;
    let value = ExtentRecord {
        binding: RecordBinding {
            store_uuid,
            generation: segment_generation,
            segment_no,
            ordinal,
            self_page: base + u64::from(relative_page),
            target_checkpoint_generation: checkpoint_generation,
        },
        extent_kind: kind,
        object_kind,
        extent_index: 0,
        extent_count: 1,
        payload_pages,
        content_byte_len: content_len,
        encoded_blob_len: payload_len,
        encoded_offset: 0,
        payload_byte_len: payload_len,
        payload_first_relative_page: relative_page + 2,
        record_span_pages,
        merkle_root: content_root,
        payload_sha256: payload_sha256(payload),
    };
    let mut body = [0; PAGE_SIZE];
    let mut seal = [0; PAGE_SIZE];
    let digest = encode_extent_body(&value, &mut body)?;
    encode_record_seal(digest, &mut seal)?;
    Ok(BuiltExtent {
        value,
        digest,
        body,
        seal,
        payload,
    })
}

async fn write_extent<D: PageDevice>(
    device: &D,
    base: u64,
    extent: &BuiltExtent<'_>,
) -> Result<(), StoreError<D::Error>> {
    let relative = extent.value.binding.self_page - base;
    let mut copied = 0;
    for page_index in 0..extent.value.payload_pages {
        let mut page = [0; PAGE_SIZE];
        let remaining = extent.payload.len() - copied;
        let take = remaining.min(PAGE_SIZE);
        page[..take].copy_from_slice(&extent.payload[copied..copied + take]);
        write_page(
            device,
            base + u64::from(extent.value.payload_first_relative_page + page_index),
            &page,
        )
        .await?;
        copied += take;
    }
    flush(device).await?;
    write_page(device, base + relative, &extent.body).await?;
    flush(device).await?;
    write_page(device, base + relative + 1, &extent.seal).await?;
    flush(device).await?;
    Ok(())
}

async fn append_object<D: PageDevice>(
    device: &D,
    state: &MountedState,
    limits: StoreLimits,
    object_kind: u32,
    content_root: [u8; 32],
    bytes: &[u8],
) -> Result<(ObjectHandle, MountedState), StoreError<D::Error>> {
    let checkpoint_generation = state
        .generation
        .checked_add(1)
        .ok_or(StoreError::IdExhausted)?;
    let segment_no = state.next_physical_segment;
    let segment_generation = state.next_segment_generation;
    let next_segment_generation = segment_generation
        .checked_add(1)
        .ok_or(StoreError::IdExhausted)?;
    let base = segment_base_page(segment_no)?;
    // Reuse is allowed only when the publication page is durably cleared and
    // rereads as exact zero.  M7.3 never treats discard as this proof.
    let zero = [0; PAGE_SIZE];
    write_page(device, base + u64::from(SEGMENT_SEAL_PAGE), &zero).await?;
    flush(device).await?;
    let mut observed_final_seal = [0; PAGE_SIZE];
    device
        .read_page(
            base + u64::from(SEGMENT_SEAL_PAGE),
            &mut observed_final_seal,
        )
        .await
        .map_err(StoreError::Device)?;
    if observed_final_seal.iter().any(|byte| *byte != 0) {
        return Err(StoreError::Corrupt);
    }
    let (previous_segment_no, previous_segment_generation, previous_hash) = state
        .last_segment
        .unwrap_or((ANCHOR_SEGMENT_NO, 0, [0; 32]));
    let header = SegmentHeader {
        binding: RecordBinding {
            store_uuid: state.superblock.binding.store_uuid,
            generation: segment_generation,
            segment_no,
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

    let mut ordinal = 1_u32;
    let mut relative = DATA_FIRST_PAGE;
    let blob = if bytes.is_empty() {
        None
    } else {
        let value = build_extent(
            state.superblock.binding.store_uuid,
            segment_no,
            segment_generation,
            checkpoint_generation,
            ordinal,
            relative,
            ExtentKind::Blob,
            object_kind,
            bytes.len() as u64,
            content_root,
            bytes,
        )?;
        ordinal += 1;
        relative += value.value.record_span_pages;
        Some(value)
    };
    let blob_pointer = blob
        .as_ref()
        .map_or(PhysicalPointer::Null, BuiltExtent::pointer);
    let entry = CatalogEntry {
        object_id: state.next_object_id,
        object_kind,
        exact_len: bytes.len() as u64,
        commit_generation: checkpoint_generation,
        content_root,
        blob: blob_pointer,
    };

    let make_snapshot = state.catalog_root == PhysicalPointer::Null
        || state.replay_count + 1 >= limits.max_replay_records;
    let mut snapshot_entries = Vec::new();
    let (catalog_kind, previous_delta, replay_count) = if make_snapshot {
        snapshot_entries
            .try_reserve_exact(state.catalog.len() + 1)
            .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
        snapshot_entries.extend_from_slice(&state.catalog);
        snapshot_entries.push(entry);
        (CatalogPayloadKind::Snapshot, PhysicalPointer::Null, 0)
    } else {
        (
            CatalogPayloadKind::Delta,
            state.replay_tail,
            state.replay_count + 1,
        )
    };
    let catalog_payload = CatalogPayload {
        kind: catalog_kind,
        checkpoint_generation,
        chain_count: if make_snapshot {
            snapshot_entries.len() as u64
        } else {
            u64::from(replay_count)
        },
        previous_delta,
        entries: if make_snapshot {
            snapshot_entries
        } else {
            vec![entry]
        },
    };
    let catalog_bytes = encode_catalog(&catalog_payload, state.superblock.binding.store_uuid)
        .map_err(codec_error)?;
    if catalog_bytes.len() > MAX_EXTENT_PAYLOAD_PAGES as usize * PAGE_SIZE {
        return Err(StoreError::Capacity(CapacityClass::Metadata));
    }
    let catalog_extent_kind = if make_snapshot {
        ExtentKind::Catalog
    } else {
        ExtentKind::CatalogDelta
    };
    let catalog_extent = build_extent(
        state.superblock.binding.store_uuid,
        segment_no,
        segment_generation,
        checkpoint_generation,
        ordinal,
        relative,
        catalog_extent_kind,
        METADATA_KIND_CATALOG,
        catalog_bytes.len() as u64,
        payload_sha256(&catalog_bytes),
        &catalog_bytes,
    )?;
    ordinal += 1;
    relative += catalog_extent.value.record_span_pages;
    let catalog_pointer = catalog_extent.pointer();

    let allocation = AllocationState {
        checkpoint_generation,
        admitted_segments: state.admitted_segments,
        allocated_prefix_segments: segment_no + 1,
        next_segment_generation,
        cleaner_reserve_segments: state.cleaner_reserve_segments,
    };
    let allocation_bytes = encode_allocation(allocation).map_err(codec_error)?;
    let allocation_extent = build_extent(
        state.superblock.binding.store_uuid,
        segment_no,
        segment_generation,
        checkpoint_generation,
        ordinal,
        relative,
        ExtentKind::Allocation,
        METADATA_KIND_ALLOCATION,
        allocation_bytes.len() as u64,
        payload_sha256(&allocation_bytes),
        &allocation_bytes,
    )?;
    relative += allocation_extent.value.record_span_pages;
    if relative > DATA_END_PAGE {
        return Err(StoreError::Capacity(if bytes.is_empty() {
            CapacityClass::Metadata
        } else {
            CapacityClass::Payload
        }));
    }

    let mut descriptor_chain = descriptor_chain_initial(
        state.superblock.binding.store_uuid,
        segment_no,
        segment_generation,
    );
    let mut payload_chain = payload_chain_initial(
        state.superblock.binding.store_uuid,
        segment_no,
        segment_generation,
    );
    let mut kind_counts = [0_u32; 5];
    let mut kind_bytes = [0_u64; 5];
    let mut payload_page_count = 0_u32;
    let mut total_payload_bytes = 0_u64;
    let mut record_count = 0_u32;
    for extent in blob
        .iter()
        .chain(core::iter::once(&catalog_extent))
        .chain(core::iter::once(&allocation_extent))
    {
        descriptor_chain = descriptor_chain_next(
            state.superblock.binding.store_uuid,
            segment_no,
            segment_generation,
            descriptor_chain,
            extent.value.binding.ordinal,
            extent.digest.body_sha256(),
            extent.value.payload_sha256,
        );
        payload_chain = payload_chain_next(
            state.superblock.binding.store_uuid,
            segment_no,
            segment_generation,
            payload_chain,
            extent.value.binding.ordinal,
            extent.value.payload_byte_len,
            extent.value.payload_sha256,
        );
        let kind = extent_kind_index(extent.value.extent_kind);
        kind_counts[kind] += 1;
        kind_bytes[kind] += extent.value.payload_byte_len;
        payload_page_count += extent.value.payload_pages;
        total_payload_bytes += extent.value.payload_byte_len;
        record_count += 1;
    }
    let summary = SegmentSummary {
        binding: RecordBinding {
            store_uuid: state.superblock.binding.store_uuid,
            generation: segment_generation,
            segment_no,
            ordinal: record_count + 1,
            self_page: base + u64::from(SUMMARY_BODY_PAGE),
            target_checkpoint_generation: checkpoint_generation,
        },
        record_count,
        next_free_page: relative,
        payload_page_count,
        total_payload_bytes,
        first_target_checkpoint_generation: checkpoint_generation,
        last_target_checkpoint_generation: checkpoint_generation,
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
    let segment_seal = SegmentSeal {
        binding: RecordBinding {
            store_uuid: state.superblock.binding.store_uuid,
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
        next_free_page: relative,
        payload_page_count,
        total_payload_bytes,
        target_checkpoint_generation: checkpoint_generation,
    };
    let mut segment_seal_body = [0; PAGE_SIZE];
    let mut final_segment_seal = [0; PAGE_SIZE];
    let segment_seal_digest = encode_segment_seal_body(&segment_seal, &mut segment_seal_body)?;
    encode_record_seal(segment_seal_digest, &mut final_segment_seal)?;

    // Every structural pair and extent follows the frozen M7.2 dependency
    // order.  The extra flushes are intentional until a device-specific FUA
    // proof can replace an exact boundary.
    write_page(device, base, &header_body).await?;
    flush(device).await?;
    write_page(device, base + 1, &header_seal).await?;
    flush(device).await?;
    if let Some(blob) = blob.as_ref() {
        write_extent(device, base, blob).await?;
    }
    write_extent(device, base, &catalog_extent).await?;
    write_extent(device, base, &allocation_extent).await?;
    write_page(device, base + u64::from(SUMMARY_BODY_PAGE), &summary_body).await?;
    flush(device).await?;
    write_page(device, base + u64::from(SUMMARY_SEAL_PAGE), &summary_seal).await?;
    flush(device).await?;
    write_page(
        device,
        base + u64::from(SEGMENT_SEAL_BODY_PAGE),
        &segment_seal_body,
    )
    .await?;
    flush(device).await?;
    // Final segment publication.
    write_page(
        device,
        base + u64::from(SEGMENT_SEAL_PAGE),
        &final_segment_seal,
    )
    .await?;
    flush(device).await?;

    let allocation_pointer = allocation_extent.pointer();
    // A checkpoint can name the segment only after a powered-on verification
    // of every exact payload and the complete structural seal chain.
    if let Some(blob) = blob.as_ref() {
        let verified = read_pointer_payload(
            device,
            state.superblock.binding.store_uuid,
            state.admitted_segments,
            next_segment_generation,
            checkpoint_generation,
            blob.pointer(),
            ExtentKind::Blob,
            limits.max_compat_object_bytes as usize,
        )
        .await?;
        if verified.bytes.as_slice() != bytes {
            return Err(StoreError::Corrupt);
        }
    }
    let verified_catalog = read_pointer_payload(
        device,
        state.superblock.binding.store_uuid,
        state.admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        catalog_pointer,
        catalog_extent_kind,
        limits.recovery_memory_bytes,
    )
    .await?;
    if verified_catalog.bytes != catalog_bytes {
        return Err(StoreError::Corrupt);
    }
    let verified_allocation = read_pointer_payload(
        device,
        state.superblock.binding.store_uuid,
        state.admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        allocation_pointer,
        ExtentKind::Allocation,
        limits.recovery_memory_bytes,
    )
    .await?;
    if verified_allocation.bytes.as_slice() != allocation_bytes {
        return Err(StoreError::Corrupt);
    }
    let (catalog_root, replay_tail) = if make_snapshot {
        (catalog_pointer, PhysicalPointer::Null)
    } else {
        (state.catalog_root, catalog_pointer)
    };
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
        admitted_range_pages: admitted_pages(state.admitted_segments)?,
        admitted_segments: state.admitted_segments,
        next_segment_generation,
        replay_count,
        max_replay_records: limits.max_replay_records,
        cleaner_reserve_segments: state.cleaner_reserve_segments,
        catalog_root,
        authority_root: PhysicalPointer::Null,
        allocation_root: allocation_pointer,
        replay_tail,
    };
    write_checkpoint(device, &checkpoint, true).await?;
    let selected_super = select_superblock(
        read_superblock(device, 0).await?,
        read_superblock(device, 2).await?,
    )?
    .ok_or(StoreError::Corrupt)?;
    if selected_super.value() != &state.superblock {
        return Err(StoreError::Corrupt);
    }
    let left = read_checkpoint(device, 4).await?;
    let right = read_checkpoint(device, 6).await?;
    let selected =
        select_checkpoint_for_superblock(selected_super, left, right, device.info().page_count)?
            .ok_or(StoreError::Corrupt)?;
    if selected.value() != &checkpoint {
        return Err(StoreError::Corrupt);
    }
    for candidate in [left, right].into_iter().flatten() {
        recover_state(device, state.superblock, candidate, limits).await?;
    }
    let recovered = recover_state(device, state.superblock, selected, limits).await?;
    let handle = ObjectHandle {
        store_uuid: state.superblock.binding.store_uuid,
        object_id: entry.object_id,
        object_kind,
        exact_len: bytes.len() as u64,
        commit_generation: checkpoint_generation,
        content_root,
    };
    Ok((handle, recovered))
}

fn extent_kind_index(kind: ExtentKind) -> usize {
    match kind {
        ExtentKind::Blob => 0,
        ExtentKind::Catalog => 1,
        ExtentKind::Authority => 2,
        ExtentKind::Allocation => 3,
        ExtentKind::CatalogDelta => 4,
    }
}

#[allow(dead_code)]
fn _mutation_is_ambiguous<E>(failure: &MutationFailure<E>) -> bool {
    failure.certainty() == MutationCertainty::Ambiguous
}

const _: () = {
    assert!(CATALOG_ENTRY_LEN <= PAGE_SIZE);
};
