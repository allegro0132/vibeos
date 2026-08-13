//! Read-only, authority-gated Storage V2 media verification.
//!
//! Scrub deliberately reports only fixed-size aggregate health.  Object IDs,
//! Blob keys, roots, kinds, physical pointers, and content never cross this
//! API.  Every path below is read-only: corruption is diagnosed and left for
//! an explicit recovery or migration operation.

use alloc::boxed::Box;
use core::fmt;

use sha2::{Digest, Sha256};
use vibeos_segment_format::{
    decode_extent_verified, decode_segment_header_verified, payload_sha256, segment_base_page,
    select_checkpoint_for_superblock, select_superblock, Checkpoint, DecodeStatus, ExtentKind,
    ExtentRecord, PhysicalPointer, PointerValue, DATA_FIRST_PAGE, PAGE_SIZE, SEGMENT_PAGES,
};

use crate::allocation_v2::SegmentAllocation;
use crate::cas::verify_manifest_blob;
use crate::cas_codec::{
    decode_blob_manifest, BlobMapping, CasCodecContext, ObjectMapping, REFERENCE_CODEC_TYPED_V1,
};
use crate::device::PageDevice;
use crate::gc::{decode_typed_children, GcError, GcStoreError};
use crate::maintenance::{MaintenanceOperation, StoreMaintenance};
use crate::mark::{MarkRoot, RootClass};
use crate::pins::RootKey;
use crate::store::{
    read_checkpoint, read_pointer_payload, read_superblock, recover_state, scan_segment,
    validate_checkpoint_transition, CheckpointTransitionWitness, MountedState, SegmentStore,
    StoreError,
};

/// Version of the public, anonymous diagnostic schema.
pub const SCRUB_REPORT_VERSION: u16 = 1;

/// Small streaming workspace retained while canonical Blob content and tree
/// nodes are checked.  Manifest decode memory is accounted separately.
const SCRUB_STREAMING_WORKSPACE_BYTES: usize = PAGE_SIZE * 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScrubStatus {
    Healthy,
    Corrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScrubDeviceHealth {
    Readable,
}

/// Broad fault class only.  It is intentionally impossible to learn which
/// object, Blob, segment, pointer, or digest caused the failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScrubCorruptionDomain {
    Anchor,
    SegmentMetadata,
    AllocationOrMapping,
    BlobDataOrTree,
    AuthorityGraph,
}

/// Fixed-size aggregate health.  Adding objects cannot make this report
/// allocate or disclose their identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScrubReport {
    pub schema_version: u16,
    pub status: ScrubStatus,
    pub device_health: ScrubDeviceHealth,
    pub checkpoint_generation: u64,
    pub verified_checkpoint_copies: u8,
    pub checkpoint_fallback_verified: bool,
    pub admitted_segments: u64,
    pub allocated_segments: u64,
    pub retired_segments: u64,
    pub free_segments: u64,
    pub verified_segments: u64,
    pub verified_record_pairs: u64,
    pub verified_payload_bytes: u64,
    pub live_objects: u32,
    pub unique_blobs: u32,
    pub logical_live_bytes: u64,
    pub unique_blob_bytes: u64,
    pub deduplicated_bytes_saved: u64,
    pub physical_capacity_bytes: u64,
    pub physical_allocated_bytes: u64,
    pub physical_high_water_ppm: u32,
    pub gc_pressure_ppm: u32,
    pub device_io_failures: u32,
    pub quota_logical_high_water_bytes: u64,
    pub quota_physical_high_water_bytes: u64,
    pub scrub_memory_high_water_bytes: usize,
    pub corruption_signals: u32,
    pub corruption_domain: Option<ScrubCorruptionDomain>,
}

impl ScrubReport {
    fn from_state(state: &MountedState) -> Result<Self, ScrubError> {
        let counts = state
            .allocation
            .counts()
            .map_err(|_| ScrubError::MemoryLimit)?;
        let segment_bytes = SEGMENT_PAGES.saturating_mul(PAGE_SIZE as u64);
        let unavailable = counts.allocated.saturating_add(counts.retired);
        let physical_capacity_bytes = state.admitted_segments.saturating_mul(segment_bytes);
        let physical_allocated_bytes = unavailable.saturating_mul(segment_bytes);
        let physical_high_water_ppm = ratio_ppm(unavailable, state.admitted_segments);
        let reserve = u64::from(state.cleaner_reserve_segments);
        let gc_pressure_ppm = if counts.free <= reserve {
            1_000_000
        } else {
            ratio_ppm(reserve, counts.free)
        };
        let resident = state
            .resident_heap_bytes()
            .and_then(|bytes| bytes.checked_add(SCRUB_STREAMING_WORKSPACE_BYTES))
            .ok_or(ScrubError::MemoryLimit)?;
        Ok(Self {
            schema_version: SCRUB_REPORT_VERSION,
            status: ScrubStatus::Healthy,
            device_health: ScrubDeviceHealth::Readable,
            checkpoint_generation: state.generation,
            verified_checkpoint_copies: 0,
            checkpoint_fallback_verified: false,
            admitted_segments: state.admitted_segments,
            allocated_segments: counts.allocated,
            retired_segments: counts.retired,
            free_segments: counts.free,
            verified_segments: 0,
            verified_record_pairs: 0,
            verified_payload_bytes: 0,
            live_objects: 0,
            unique_blobs: 0,
            logical_live_bytes: 0,
            unique_blob_bytes: 0,
            deduplicated_bytes_saved: 0,
            physical_capacity_bytes,
            physical_allocated_bytes,
            physical_high_water_ppm,
            gc_pressure_ppm,
            device_io_failures: 0,
            quota_logical_high_water_bytes: 0,
            quota_physical_high_water_bytes: 0,
            scrub_memory_high_water_bytes: resident,
            corruption_signals: 0,
            corruption_domain: None,
        })
    }

    fn corrupt(mut self, domain: ScrubCorruptionDomain) -> Self {
        self.status = ScrubStatus::Corrupt;
        self.corruption_signals = self.corruption_signals.saturating_add(1);
        self.corruption_domain = Some(domain);
        self
    }

    fn observe_memory(&mut self, bytes: usize) {
        self.scrub_memory_high_water_bytes = self.scrub_memory_high_water_bytes.max(bytes);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScrubError {
    Unauthorized,
    StoreUnavailable,
    /// Scrub stopped at the first failed read.  Backend errors are deliberately
    /// erased because they may contain LBAs, paths, or driver-specific object
    /// context.  The fixed counter remains useful without becoming an oracle.
    DeviceUnavailable {
        failures: u32,
    },
    MemoryLimit,
}

impl fmt::Display for ScrubError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => formatter.write_str("Storage V2 scrub authority denied"),
            Self::StoreUnavailable => formatter.write_str("Storage V2 store is unavailable"),
            Self::DeviceUnavailable { .. } => {
                formatter.write_str("Storage V2 scrub device is unavailable")
            }
            Self::MemoryLimit => formatter.write_str("Storage V2 scrub memory ceiling exceeded"),
        }
    }
}

impl core::error::Error for ScrubError {}

enum StepError<E> {
    Device(E),
    MemoryLimit,
    Corrupt,
}

impl<E> StepError<E> {
    fn from_store(error: StoreError<E>) -> Self {
        match error {
            StoreError::Device(error) => Self::Device(error),
            StoreError::MemoryLimit => Self::MemoryLimit,
            _ => Self::Corrupt,
        }
    }
}

impl<D: PageDevice> SegmentStore<D> {
    /// Verify every authoritative layer without minting object authority and
    /// without mutating media.  Corruption is a successful diagnostic result;
    /// lack of authority, device I/O failure, and bounded-memory exhaustion are
    /// operational errors.
    pub async fn scrub(&self, maintenance: &StoreMaintenance) -> Result<ScrubReport, ScrubError> {
        let _maintenance_lease = self
            .acquire_maintenance(maintenance, MaintenanceOperation::Scrub)
            .ok_or(ScrubError::Unauthorized)?;
        let current = self
            .require_current_generation()
            .map_err(|_| ScrubError::StoreUnavailable)?;
        let current_resident = current
            .resident_heap_bytes()
            .ok_or(ScrubError::MemoryLimit)?;
        let mut report = ScrubReport::from_state(current)?;
        if let Some(quota) = self.quota_diagnostics() {
            report.quota_logical_high_water_bytes = quota.logical_high_water_bytes;
            report.quota_physical_high_water_bytes = quota.physical_high_water_bytes;
        }
        if report.scrub_memory_high_water_bytes > self.limits.recovery_memory_bytes {
            return Err(ScrubError::MemoryLimit);
        }

        if let Err(error) =
            Box::pin(verify_segment_set(&self.device, current, Some(&mut report))).await
        {
            return finish_step_error(report, ScrubCorruptionDomain::SegmentMetadata, error);
        }
        if current.authority_root != PhysicalPointer::Null {
            if let Err(error) = Box::pin(verify_pointer_payload_and_padding(
                &self.device,
                current,
                current.authority_root,
            ))
            .await
            {
                return finish_step_error(report, ScrubCorruptionDomain::AuthorityGraph, error);
            }
        }
        if let Err(error) = Box::pin(verify_state_contents(
            &self.device,
            current,
            self.limits.recovery_memory_bytes,
            0,
            Some(&mut report),
        ))
        .await
        {
            return finish_step_error(report, ScrubCorruptionDomain::BlobDataOrTree, error);
        }
        if let Err(error) = Box::pin(verify_durable_authority_closure(
            &self.device,
            current,
            self.limits,
            &self.typed_reference_kinds,
            0,
            Some(&mut report),
        ))
        .await
        {
            return finish_step_error(report, ScrubCorruptionDomain::AuthorityGraph, error);
        }

        let left_super = match Box::pin(read_superblock(&self.device, 0)).await {
            Ok(value) => value,
            Err(error) => {
                return finish_step_error(
                    report,
                    ScrubCorruptionDomain::Anchor,
                    StepError::from_store(error),
                )
            }
        };
        let right_super = match Box::pin(read_superblock(&self.device, 2)).await {
            Ok(value) => value,
            Err(error) => {
                return finish_step_error(
                    report,
                    ScrubCorruptionDomain::Anchor,
                    StepError::from_store(error),
                )
            }
        };
        // Superblocks are immutable redundant anchors, not alternating
        // publication slots.  Losing either copy is health-significant even
        // when the surviving copy remains sufficient for ordinary mount.
        if left_super.is_none() || right_super.is_none() {
            return Ok(report.corrupt(ScrubCorruptionDomain::Anchor));
        }
        let selected_super = match select_superblock(left_super, right_super) {
            Ok(Some(value)) if value.value() == &current.superblock => value,
            Ok(_) | Err(_) => return Ok(report.corrupt(ScrubCorruptionDomain::Anchor)),
        };
        let left = match Box::pin(read_checkpoint(&self.device, 4)).await {
            Ok(value) => value,
            Err(error) => {
                return finish_step_error(
                    report,
                    ScrubCorruptionDomain::Anchor,
                    StepError::from_store(error),
                )
            }
        };
        report.verified_checkpoint_copies = u8::from(left.is_some());
        let right = match Box::pin(read_checkpoint(&self.device, 6)).await {
            Ok(value) => value,
            Err(error) => {
                return finish_step_error(
                    report,
                    ScrubCorruptionDomain::Anchor,
                    StepError::from_store(error),
                )
            }
        };
        report.verified_checkpoint_copies = report
            .verified_checkpoint_copies
            .saturating_add(u8::from(right.is_some()));
        let selected = match select_checkpoint_for_superblock(
            selected_super,
            left,
            right,
            self.device.info().page_count,
        ) {
            Ok(Some(value)) if value.value().binding.generation == current.generation => value,
            Ok(_) | Err(_) => return Ok(report.corrupt(ScrubCorruptionDomain::Anchor)),
        };
        if let Err(error) = Box::pin(verify_checkpoint_payloads(
            &self.device,
            current,
            selected.value(),
        ))
        .await
        {
            return finish_step_error(report, ScrubCorruptionDomain::AllocationOrMapping, error);
        }

        let candidate_budget = self
            .limits
            .recovery_memory_bytes
            .checked_sub(current_resident)
            .ok_or(ScrubError::MemoryLimit)?;
        let candidate_limits = crate::store::StoreLimits {
            recovery_memory_bytes: candidate_budget,
            ..self.limits
        };

        match (left, right) {
            (Some(left), Some(right))
                if left.value().binding.generation != right.value().binding.generation =>
            {
                let (older, newer) =
                    if left.value().binding.generation < right.value().binding.generation {
                        (left, right)
                    } else {
                        (right, left)
                    };
                let older_state = match Box::pin(recover_state(
                    &self.device,
                    current.superblock,
                    older,
                    candidate_limits,
                ))
                .await
                {
                    Ok(state) => state,
                    Err(error) => {
                        return finish_step_error(
                            report,
                            ScrubCorruptionDomain::AllocationOrMapping,
                            StepError::from_store(error),
                        )
                    }
                };
                report.observe_memory(
                    current_resident
                        .checked_add(older_state.recovery_peak_bytes)
                        .ok_or(ScrubError::MemoryLimit)?,
                );
                if let Err(error) = Box::pin(verify_checkpoint_payloads(
                    &self.device,
                    &older_state,
                    older.value(),
                ))
                .await
                {
                    return finish_step_error(
                        report,
                        ScrubCorruptionDomain::AllocationOrMapping,
                        error,
                    );
                }
                if let Err(error) =
                    Box::pin(verify_segment_set(&self.device, &older_state, None)).await
                {
                    return finish_step_error(
                        report,
                        ScrubCorruptionDomain::SegmentMetadata,
                        error,
                    );
                }
                if let Err(error) = Box::pin(verify_state_contents(
                    &self.device,
                    &older_state,
                    self.limits.recovery_memory_bytes,
                    current_resident,
                    None,
                ))
                .await
                {
                    return finish_step_error(report, ScrubCorruptionDomain::BlobDataOrTree, error);
                }
                if let Err(error) = Box::pin(verify_durable_authority_closure(
                    &self.device,
                    &older_state,
                    self.limits,
                    &self.typed_reference_kinds,
                    current_resident,
                    Some(&mut report),
                ))
                .await
                {
                    return finish_step_error(report, ScrubCorruptionDomain::AuthorityGraph, error);
                }
                let witness = CheckpointTransitionWitness::from_mounted(older_state);
                let witness_bytes = witness.resident_bytes().ok_or(ScrubError::MemoryLimit)?;
                let newer_budget = candidate_budget
                    .checked_sub(witness_bytes)
                    .ok_or(ScrubError::MemoryLimit)?;
                let newer_state = match Box::pin(recover_state(
                    &self.device,
                    current.superblock,
                    newer,
                    crate::store::StoreLimits {
                        recovery_memory_bytes: newer_budget,
                        ..self.limits
                    },
                ))
                .await
                {
                    Ok(state) => state,
                    Err(error) => {
                        return finish_step_error(
                            report,
                            ScrubCorruptionDomain::AllocationOrMapping,
                            StepError::from_store(error),
                        )
                    }
                };
                let pair_peak = current_resident
                    .checked_add(witness_bytes)
                    .and_then(|bytes| bytes.checked_add(newer_state.recovery_peak_bytes))
                    .ok_or(ScrubError::MemoryLimit)?;
                report.observe_memory(pair_peak);
                if pair_peak > self.limits.recovery_memory_bytes {
                    return Err(ScrubError::MemoryLimit);
                }
                if validate_checkpoint_transition::<D::Error>(&witness, &newer_state).is_err()
                    || !same_publication(&newer_state, current)
                    || selected.value().binding.generation != newer_state.generation
                {
                    return Ok(report.corrupt(ScrubCorruptionDomain::AllocationOrMapping));
                }
                if let Err(error) = Box::pin(verify_state_contents(
                    &self.device,
                    &newer_state,
                    self.limits.recovery_memory_bytes,
                    current_resident.saturating_add(witness_bytes),
                    None,
                ))
                .await
                {
                    return finish_step_error(report, ScrubCorruptionDomain::BlobDataOrTree, error);
                }
                report.checkpoint_fallback_verified = true;
            }
            (Some(candidate), None) | (None, Some(candidate)) => {
                let recovered = match Box::pin(recover_state(
                    &self.device,
                    current.superblock,
                    candidate,
                    candidate_limits,
                ))
                .await
                {
                    Ok(state) => state,
                    Err(error) => {
                        return finish_step_error(
                            report,
                            ScrubCorruptionDomain::AllocationOrMapping,
                            StepError::from_store(error),
                        )
                    }
                };
                report.observe_memory(
                    current_resident
                        .checked_add(recovered.recovery_peak_bytes)
                        .ok_or(ScrubError::MemoryLimit)?,
                );
                if !same_publication(&recovered, current) {
                    return Ok(report.corrupt(ScrubCorruptionDomain::AllocationOrMapping));
                }
            }
            (Some(left), Some(right)) => {
                // Mount rejects two sealed copies of the same generation: the
                // alternating slots must form a strict predecessor pair.  Do
                // not report a state as healthy that cold recovery rejects.
                let _ = (left, right);
                return Ok(report.corrupt(ScrubCorruptionDomain::Anchor));
            }
            (None, None) => return Ok(report.corrupt(ScrubCorruptionDomain::Anchor)),
        }
        Ok(report)
    }
}

fn ratio_ppm(numerator: u64, denominator: u64) -> u32 {
    if denominator == 0 {
        return 0;
    }
    u32::try_from(
        numerator
            .saturating_mul(1_000_000)
            .checked_div(denominator)
            .unwrap_or(0)
            .min(1_000_000),
    )
    .unwrap_or(1_000_000)
}

fn finish_step_error<E>(
    report: ScrubReport,
    domain: ScrubCorruptionDomain,
    error: StepError<E>,
) -> Result<ScrubReport, ScrubError> {
    match error {
        StepError::Device(_) => Err(ScrubError::DeviceUnavailable { failures: 1 }),
        StepError::MemoryLimit => Err(ScrubError::MemoryLimit),
        StepError::Corrupt => Ok(report.corrupt(domain)),
    }
}

fn pointer_is_current(state: &MountedState, pointer: PhysicalPointer) -> bool {
    match pointer {
        PhysicalPointer::Null => true,
        PhysicalPointer::Value(pointer) => {
            pointer.store_uuid == state.superblock.binding.store_uuid
                && pointer.segment_no < state.admitted_segments
                && pointer.segment_generation > 0
                && pointer.segment_generation < state.next_segment_generation
                && state.allocation.segment_state(pointer.segment_no)
                    == Some(SegmentAllocation::Allocated)
        }
    }
}

async fn verify_checkpoint_payloads<D: PageDevice>(
    device: &D,
    state: &MountedState,
    checkpoint: &Checkpoint,
) -> Result<(), StepError<D::Error>> {
    if checkpoint.binding.generation != state.generation
        || checkpoint.admitted_segments != state.admitted_segments
        || checkpoint.next_segment_generation != state.next_segment_generation
        || checkpoint.catalog_root != state.catalog_root
        || checkpoint.authority_root != state.authority_root
        || checkpoint.replay_tail != state.replay_tail
    {
        return Err(StepError::Corrupt);
    }
    for pointer in [
        checkpoint.catalog_root,
        checkpoint.authority_root,
        checkpoint.allocation_root,
        checkpoint.replay_tail,
    ] {
        if !pointer_is_current(state, pointer) {
            return Err(StepError::Corrupt);
        }
        if pointer != PhysicalPointer::Null {
            verify_pointer_payload_and_padding(device, state, pointer).await?;
        }
    }
    Ok(())
}

async fn verify_durable_authority_closure<D: PageDevice>(
    device: &D,
    state: &MountedState,
    limits: crate::store::StoreLimits,
    typed_reference_kinds: &[u32],
    base_resident: usize,
    mut report: Option<&mut ScrubReport>,
) -> Result<(), StepError<D::Error>> {
    let Some(cas) = state.cas.as_ref() else {
        return if state.persistent_roots.is_none() {
            Ok(())
        } else {
            Err(StepError::Corrupt)
        };
    };
    let object_budget =
        usize::try_from(limits.max_catalog_entries).map_err(|_| StepError::MemoryLimit)?;
    let policy_entries = state
        .persistent_roots
        .as_ref()
        .map_or(&[][..], |policy| policy.entries());
    if object_budget == 0
        || cas.objects.len() > object_budget
        || policy_entries.len() > object_budget
    {
        return Err(StepError::Corrupt);
    }

    // A global semantic pass below validates every trusted typed edge.  Once
    // that graph is closed, proving each durable root resolves exactly is
    // sufficient to prove its complete transitive closure without allocating a
    // second root/mark graph.
    for entry in policy_entries {
        let key = RootKey::new(entry.object_id, entry.commit_generation, entry.object_kind)
            .map_err(|_| StepError::Corrupt)?;
        let object = cas
            .objects
            .binary_search_by_key(&key.object_id(), |object| object.object_id)
            .ok()
            .map(|index| cas.objects[index])
            .filter(|object| {
                object.commit_generation == key.commit_generation()
                    && object.blob_key.object_kind() == key.object_kind()
            })
            .ok_or(StepError::Corrupt)?;
        if cas
            .blobs
            .binary_search_by_key(&object.blob_key, |blob| blob.blob_key)
            .is_err()
        {
            return Err(StepError::Corrupt);
        }
    }

    let semantic_root_count = cas
        .objects
        .iter()
        .filter(|object| {
            object.reference_codec == REFERENCE_CODEC_TYPED_V1
                && typed_reference_kinds
                    .binary_search(&object.blob_key.object_kind())
                    .is_ok()
        })
        .count();
    let state_resident = state.resident_heap_bytes().ok_or(StepError::MemoryLimit)?;
    let requested_roots_bytes = semantic_root_count
        .checked_mul(core::mem::size_of::<MarkRoot>())
        .ok_or(StepError::MemoryLimit)?;
    let requested_retained = base_resident
        .checked_add(state_resident)
        .and_then(|bytes| bytes.checked_add(requested_roots_bytes))
        .ok_or(StepError::MemoryLimit)?;
    if requested_retained > limits.recovery_memory_bytes {
        return Err(StepError::MemoryLimit);
    }

    let mut roots = alloc::vec::Vec::new();
    roots
        .try_reserve_exact(semantic_root_count)
        .map_err(|_| StepError::MemoryLimit)?;
    for object in &cas.objects {
        if object.reference_codec != REFERENCE_CODEC_TYPED_V1
            || typed_reference_kinds
                .binary_search(&object.blob_key.object_kind())
                .is_err()
        {
            continue;
        }
        roots.push(MarkRoot {
            key: RootKey::new(
                object.object_id,
                object.commit_generation,
                object.blob_key.object_kind(),
            )
            .map_err(|_| StepError::Corrupt)?,
            class: RootClass::Runtime,
        });
    }
    let roots_bytes = roots
        .capacity()
        .checked_mul(core::mem::size_of::<MarkRoot>())
        .ok_or(StepError::MemoryLimit)?;
    let retained = base_resident
        .checked_add(state_resident)
        .and_then(|bytes| bytes.checked_add(roots_bytes))
        .ok_or(StepError::MemoryLimit)?;
    if retained > limits.recovery_memory_bytes {
        return Err(StepError::MemoryLimit);
    }
    if let Some(value) = report.as_deref_mut() {
        value.observe_memory(retained);
    }
    if roots.is_empty() {
        return Ok(());
    }

    let decode_budget = limits
        .recovery_memory_bytes
        .checked_sub(retained)
        .ok_or(StepError::MemoryLimit)?;
    let typed = decode_typed_children(
        device,
        state,
        crate::store::StoreLimits {
            recovery_memory_bytes: decode_budget,
            ..limits
        },
        &roots,
        typed_reference_kinds,
    )
    .await
    .map_err(map_gc_step_error)?;
    let decode_peak = retained
        .checked_add(typed.peak_bytes())
        .ok_or(StepError::MemoryLimit)?;
    if decode_peak > limits.recovery_memory_bytes {
        return Err(StepError::MemoryLimit);
    }
    let decoded_retained = retained
        .checked_add(typed.allocated_bytes())
        .ok_or(StepError::MemoryLimit)?;
    if decoded_retained > limits.recovery_memory_bytes {
        return Err(StepError::MemoryLimit);
    }
    if let Some(value) = report {
        value.observe_memory(decode_peak.max(decoded_retained));
    }
    Ok(())
}

fn map_gc_step_error<E>(error: GcStoreError<E>) -> StepError<E> {
    match error {
        GcStoreError::Store(error) => StepError::from_store(error),
        GcStoreError::Gc(GcError::MemoryLimit) => StepError::MemoryLimit,
        GcStoreError::Gc(_) => StepError::Corrupt,
    }
}

async fn verify_segment_set<D: PageDevice>(
    device: &D,
    state: &MountedState,
    mut report: Option<&mut ScrubReport>,
) -> Result<(), StepError<D::Error>> {
    for segment_no in 0..state.admitted_segments {
        if state.allocation.segment_state(segment_no) == Some(SegmentAllocation::Free) {
            continue;
        }
        let base = segment_base_page(segment_no).map_err(|_| StepError::Corrupt)?;
        let mut body = Box::new([0; PAGE_SIZE]);
        let mut seal = Box::new([0; PAGE_SIZE]);
        device
            .read_page(base, body.as_mut())
            .await
            .map_err(StepError::Device)?;
        device
            .read_page(base + 1, seal.as_mut())
            .await
            .map_err(StepError::Device)?;
        let header =
            match decode_segment_header_verified(&body, &seal).map_err(|_| StepError::Corrupt)? {
                DecodeStatus::Sealed(value) => value,
                DecodeStatus::Empty | DecodeStatus::Unsealed => return Err(StepError::Corrupt),
            };
        let value = header.value();
        if value.binding.store_uuid != state.superblock.binding.store_uuid
            || value.binding.segment_no != segment_no
            || value.binding.generation == 0
            || value.binding.generation >= state.next_segment_generation
            || value.binding.target_checkpoint_generation > state.generation
        {
            return Err(StepError::Corrupt);
        }
        let probe = PointerValue {
            store_uuid: state.superblock.binding.store_uuid,
            segment_no,
            segment_generation: value.binding.generation,
            descriptor_relative_page: 0,
            payload_relative_page: 0,
            payload_pages: 1,
            ordinal: 0,
            exact_byte_len: 1,
            extent_kind: ExtentKind::Blob,
            payload_sha256: [0; 32],
        };
        let scanned = scan_segment(
            device,
            state.superblock.binding.store_uuid,
            state.admitted_segments,
            state.next_segment_generation,
            state.generation,
            probe,
        )
        .await
        .map_err(StepError::from_store)?;
        verify_segment_payloads_and_padding(
            device,
            state,
            segment_no,
            value.binding.generation,
            scanned.record_count,
        )
        .await?;
        if let Some(value) = report.as_deref_mut() {
            value.verified_segments = value.verified_segments.saturating_add(1);
            value.verified_record_pairs = value
                .verified_record_pairs
                .saturating_add(u64::from(scanned.record_count).saturating_add(3));
            value.verified_payload_bytes = value
                .verified_payload_bytes
                .saturating_add(scanned.total_payload_bytes);
        }
    }
    Ok(())
}

async fn verify_state_contents<D: PageDevice>(
    device: &D,
    state: &MountedState,
    total_memory_limit: usize,
    base_resident: usize,
    mut report: Option<&mut ScrubReport>,
) -> Result<(), StepError<D::Error>> {
    let state_resident = state.resident_heap_bytes().ok_or(StepError::MemoryLimit)?;
    let resident = base_resident
        .checked_add(state_resident)
        .ok_or(StepError::MemoryLimit)?;
    if resident
        .checked_add(SCRUB_STREAMING_WORKSPACE_BYTES)
        .is_none_or(|peak| peak > total_memory_limit)
    {
        return Err(StepError::MemoryLimit);
    }

    for pointer in [state.catalog_root, state.authority_root, state.replay_tail] {
        if !pointer_is_current(state, pointer) {
            return Err(StepError::Corrupt);
        }
        if pointer != PhysicalPointer::Null {
            verify_pointer_payload_and_padding(device, state, pointer).await?;
        }
    }

    if let Some(cas) = &state.cas {
        if !cas_mappings_are_closed(&cas.objects, &cas.blobs) {
            return Err(StepError::Corrupt);
        }
        let context = CasCodecContext::new(
            state.superblock.binding.store_uuid,
            state.admitted_segments,
            state.next_segment_generation,
        )
        .map_err(|_| StepError::Corrupt)?;
        let mut unique_blob_bytes = 0_u64;
        for blob in &cas.blobs {
            if !pointer_is_current(state, blob.manifest) {
                return Err(StepError::Corrupt);
            }
            verify_pointer_payload_and_padding(device, state, blob.manifest).await?;
            let manifest_len = match blob.manifest {
                PhysicalPointer::Value(pointer) => {
                    usize::try_from(pointer.exact_byte_len).map_err(|_| StepError::MemoryLimit)?
                }
                PhysicalPointer::Null => return Err(StepError::Corrupt),
            };
            let peak = resident
                .checked_add(manifest_len.saturating_mul(2))
                .and_then(|bytes| bytes.checked_add(SCRUB_STREAMING_WORKSPACE_BYTES))
                .ok_or(StepError::MemoryLimit)?;
            if peak > total_memory_limit {
                return Err(StepError::MemoryLimit);
            }
            if let Some(value) = report.as_deref_mut() {
                value.observe_memory(peak);
            }
            let payload = read_pointer_payload(
                device,
                state.superblock.binding.store_uuid,
                state.admitted_segments,
                state.next_segment_generation,
                state.generation,
                blob.manifest,
                ExtentKind::Catalog,
                manifest_len,
            )
            .await
            .map_err(StepError::from_store)?;
            let manifest =
                decode_blob_manifest(&payload.bytes, context).map_err(|_| StepError::Corrupt)?;
            if manifest.blob_key != blob.blob_key
                || manifest
                    .extents
                    .iter()
                    .any(|extent| !pointer_is_current(state, extent.pointer))
            {
                return Err(StepError::Corrupt);
            }
            drop(payload);
            for extent in &manifest.extents {
                verify_pointer_payload_and_padding(device, state, extent.pointer).await?;
            }
            verify_manifest_blob(device, state, &manifest)
                .await
                .map_err(|error| match error {
                    crate::cas::CasStoreError::Store(error) => StepError::from_store(error),
                    _ => StepError::Corrupt,
                })?;
            unique_blob_bytes = unique_blob_bytes.saturating_add(blob.blob_key.exact_len());
        }
        if let Some(value) = report {
            value.live_objects = u32::try_from(cas.objects.len()).unwrap_or(u32::MAX);
            value.unique_blobs = u32::try_from(cas.blobs.len()).unwrap_or(u32::MAX);
            value.logical_live_bytes = cas.objects.iter().fold(0_u64, |total, object| {
                total.saturating_add(object.blob_key.exact_len())
            });
            value.unique_blob_bytes = unique_blob_bytes;
            value.deduplicated_bytes_saved =
                value.logical_live_bytes.saturating_sub(unique_blob_bytes);
        }
    } else {
        for entry in &state.catalog {
            if !pointer_is_current(state, entry.blob) {
                return Err(StepError::Corrupt);
            }
            if let PhysicalPointer::Value(_) = entry.blob {
                verify_pointer_payload_and_padding(device, state, entry.blob).await?;
                let resolved = read_pointer_payload(
                    device,
                    state.superblock.binding.store_uuid,
                    state.admitted_segments,
                    state.next_segment_generation,
                    state.generation,
                    entry.blob,
                    ExtentKind::Blob,
                    self_legacy_limit(state, total_memory_limit, resident)?,
                )
                .await
                .map_err(StepError::from_store)?;
                if resolved.bytes.len() as u64 != entry.exact_len
                    || resolved.extent.object_kind != entry.object_kind
                    || payload_sha256(&resolved.bytes) != entry.content_root
                {
                    return Err(StepError::Corrupt);
                }
            } else if entry.exact_len != 0 {
                return Err(StepError::Corrupt);
            }
        }
        if let Some(value) = report {
            value.live_objects = u32::try_from(state.catalog.len()).unwrap_or(u32::MAX);
            value.logical_live_bytes = state
                .catalog
                .iter()
                .fold(0_u64, |total, entry| total.saturating_add(entry.exact_len));
            value.unique_blob_bytes = value.logical_live_bytes;
        }
    }
    Ok(())
}

/// Authenticate exact payload bytes and require canonical zero padding with a
/// single page of stack workspace.  Semantic Blob-tree verification remains a
/// separate pass because a valid per-extent hash alone cannot bind the tree to
/// the Blob descriptor.
async fn verify_pointer_payload_and_padding<D: PageDevice>(
    device: &D,
    state: &MountedState,
    pointer: PhysicalPointer,
) -> Result<(), StepError<D::Error>> {
    let PhysicalPointer::Value(pointer) = pointer else {
        return Err(StepError::Corrupt);
    };
    if !pointer_is_current(state, PhysicalPointer::Value(pointer)) {
        return Err(StepError::Corrupt);
    }
    let first = segment_base_page(pointer.segment_no)
        .ok()
        .and_then(|base| base.checked_add(u64::from(pointer.payload_relative_page)))
        .ok_or(StepError::Corrupt)?;
    verify_exact_payload_and_padding(
        device,
        first,
        pointer.payload_pages,
        pointer.exact_byte_len,
        pointer.payload_sha256,
    )
    .await
}

async fn verify_segment_payloads_and_padding<D: PageDevice>(
    device: &D,
    state: &MountedState,
    segment_no: u64,
    segment_generation: u64,
    record_count: u32,
) -> Result<(), StepError<D::Error>> {
    let base = segment_base_page(segment_no).map_err(|_| StepError::Corrupt)?;
    let mut relative = DATA_FIRST_PAGE;
    for ordinal in 1..=record_count {
        let descriptor_page = base
            .checked_add(u64::from(relative))
            .ok_or(StepError::Corrupt)?;
        let mut body = Box::new([0; PAGE_SIZE]);
        let mut seal = Box::new([0; PAGE_SIZE]);
        device
            .read_page(descriptor_page, body.as_mut())
            .await
            .map_err(StepError::Device)?;
        device
            .read_page(
                descriptor_page.checked_add(1).ok_or(StepError::Corrupt)?,
                seal.as_mut(),
            )
            .await
            .map_err(StepError::Device)?;
        let extent = match decode_extent_verified(&body, &seal).map_err(|_| StepError::Corrupt)? {
            DecodeStatus::Sealed(extent) => *extent.value(),
            DecodeStatus::Empty | DecodeStatus::Unsealed => return Err(StepError::Corrupt),
        };
        if extent.binding.store_uuid != state.superblock.binding.store_uuid
            || extent.binding.segment_no != segment_no
            || extent.binding.generation != segment_generation
            || extent.binding.ordinal != ordinal
            || extent.binding.self_page != descriptor_page
            || extent.binding.target_checkpoint_generation > state.generation
            || extent.payload_first_relative_page != relative + 2
        {
            return Err(StepError::Corrupt);
        }
        verify_extent_payload_and_padding(device, base, extent).await?;
        relative = relative
            .checked_add(extent.record_span_pages)
            .ok_or(StepError::Corrupt)?;
    }
    Ok(())
}

async fn verify_extent_payload_and_padding<D: PageDevice>(
    device: &D,
    segment_base: u64,
    extent: ExtentRecord,
) -> Result<(), StepError<D::Error>> {
    let first = segment_base
        .checked_add(u64::from(extent.payload_first_relative_page))
        .ok_or(StepError::Corrupt)?;
    verify_exact_payload_and_padding(
        device,
        first,
        extent.payload_pages,
        extent.payload_byte_len,
        extent.payload_sha256,
    )
    .await
}

async fn verify_exact_payload_and_padding<D: PageDevice>(
    device: &D,
    first_page: u64,
    payload_pages: u32,
    exact_byte_len: u64,
    expected_sha256: [u8; 32],
) -> Result<(), StepError<D::Error>> {
    if exact_byte_len == 0 || u64::from(payload_pages) != exact_byte_len.div_ceil(PAGE_SIZE as u64)
    {
        return Err(StepError::Corrupt);
    }
    let mut remaining = exact_byte_len;
    let mut hasher = Sha256::new();
    for page_index in 0..u64::from(payload_pages) {
        let mut page = Box::new([0; PAGE_SIZE]);
        device
            .read_page(
                first_page
                    .checked_add(page_index)
                    .ok_or(StepError::Corrupt)?,
                page.as_mut(),
            )
            .await
            .map_err(StepError::Device)?;
        let take =
            usize::try_from(remaining.min(PAGE_SIZE as u64)).map_err(|_| StepError::Corrupt)?;
        hasher.update(&page[..take]);
        if page[take..].iter().any(|byte| *byte != 0) {
            return Err(StepError::Corrupt);
        }
        remaining -= take as u64;
    }
    let observed: [u8; 32] = hasher.finalize().into();
    if remaining != 0 || observed != expected_sha256 {
        return Err(StepError::Corrupt);
    }
    Ok(())
}

pub(crate) fn cas_mappings_are_closed(objects: &[ObjectMapping], blobs: &[BlobMapping]) -> bool {
    objects.iter().all(|object| {
        blobs
            .binary_search_by_key(&object.blob_key, |blob| blob.blob_key)
            .is_ok()
    }) && blobs.iter().all(|blob| {
        objects
            .iter()
            .any(|object| object.blob_key == blob.blob_key)
    })
}

fn self_legacy_limit<E>(
    _state: &MountedState,
    total_memory_limit: usize,
    resident: usize,
) -> Result<usize, StepError<E>> {
    total_memory_limit
        .checked_sub(resident)
        .ok_or(StepError::MemoryLimit)
}

fn same_publication(left: &MountedState, right: &MountedState) -> bool {
    let cas_equal = match (&left.cas, &right.cas) {
        (None, None) => true,
        (Some(left), Some(right)) => left.objects == right.objects && left.blobs == right.blobs,
        _ => false,
    };
    left.superblock == right.superblock
        && left.generation == right.generation
        && left.admitted_segments == right.admitted_segments
        && left.next_physical_segment == right.next_physical_segment
        && left.next_segment_generation == right.next_segment_generation
        && left.next_object_id == right.next_object_id
        && left.cleaner_reserve_segments == right.cleaner_reserve_segments
        && left.replay_count == right.replay_count
        && left.catalog_root == right.catalog_root
        && left.replay_tail == right.replay_tail
        && left.authority_root == right.authority_root
        && left.allocation == right.allocation
        && left.allocation_version == right.allocation_version
        && left.persistent_roots == right.persistent_roots
        && left.catalog == right.catalog
        && cas_equal
        && left.last_segment == right.last_segment
}
