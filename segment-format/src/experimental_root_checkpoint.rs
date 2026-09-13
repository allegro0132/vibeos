//! Experimental superblock admission and checkpoint codecs. No runtime mount path.
use super::*;

const TAG: u32 = 0x3152_4245; // EBR1, including for a separated fallback checkpoint.

/// Only constructed after both superblock copies have passed experimental decoding.
pub struct AdmittedFormat {
    superblock: VerifiedRecord<Superblock>,
}

/// Structurally selected under a matching admitted experimental superblock.
/// Store recovery must still validate allocation and referenced payloads.
pub struct SelectedCheckpoint {
    current: RecoveryCheckpoint,
    previous: Option<RecoveryCheckpoint>,
}

/// An integrity-checked candidate belonging to a structurally selected pair.
pub struct RecoveryCheckpoint {
    record: VerifiedRecord<BundleCheckpoint>,
}

impl SelectedCheckpoint {
    pub fn value(&self) -> &BundleCheckpoint { self.current.value() }
    pub fn current(&self) -> &RecoveryCheckpoint { &self.current }
    pub fn previous(&self) -> Option<&RecoveryCheckpoint> { self.previous.as_ref() }
}

impl RecoveryCheckpoint {
    pub fn value(&self) -> &BundleCheckpoint { self.record.value() }
}

pub fn encode_superblock(value: &Superblock, out: &mut Page) -> Result<BodyDigest, FormatError> {
    validate_superblock(value)?;
    write_superblock_fields(value, out)?;
    put_u32(out, 0xf4, TAG);
    Ok(finish_body(RecordKind::Superblock, 0x80, value.binding, out))
}

fn decode_superblock(body: &Page, seal: &Page) -> Result<DecodeStatus<VerifiedRecord<Superblock>>, FormatError> {
    let digest = match decode_common(body, seal, RecordKind::Superblock, 0x80)? {
        DecodeStatus::Empty => return Ok(DecodeStatus::Empty),
        DecodeStatus::Unsealed => return Ok(DecodeStatus::Unsealed),
        DecodeStatus::Sealed(digest) => digest,
    };
    if !is_zero(&body[0x81..0x88]) || get_u16(body, 0xb6) != 0 || get_u32(body, 0xf4) != TAG
        || get_u32(body, 0xfc) != 0 || get_u16(body, 0xb4) != HASH_ALGORITHM_SHA256
        || get_u64(body, 0xc0) != ANCHOR_PAGES {
        return Err(FormatError::NonZeroReserved);
    }
    let value = read_superblock_fields(body, digest)?;
    Ok(DecodeStatus::Sealed(VerifiedRecord { value, digest }))
}

fn candidate<T>(status: DecodeStatus<VerifiedRecord<T>>) -> Option<VerifiedRecord<T>> {
    match status { DecodeStatus::Sealed(value) => Some(value), _ => None }
}

/// Corrupt or legacy sealed copies are fatal even when the other copy is valid.
/// Empty/unsealed copies follow existing format rules; this is not an in-place upgrade.
pub fn admit(left: (&Page, &Page), right: (&Page, &Page)) -> Result<Option<AdmittedFormat>, FormatError> {
    let left = candidate(decode_superblock(left.0, left.1)?);
    let right = candidate(decode_superblock(right.0, right.1)?);
    Ok(select_superblock(left, right)?.map(|superblock| AdmittedFormat { superblock }))
}

impl AdmittedFormat {
    pub fn superblock(&self) -> &Superblock { self.superblock.value() }

    /// Structural selection only. Allocation transitions, referenced payloads,
    /// live roots and device binding still require store-level recovery checks.
    pub fn select_checkpoints(&self, left: (&Page, &Page), right: (&Page, &Page), maximum_pages: u64)
        -> Result<Option<SelectedCheckpoint>, FormatError>
    {
        let left = candidate(decode_verified(left.0, left.1)?);
        let right = candidate(decode_verified(right.0, right.1)?);
        for (slot, value) in [left.as_ref(), right.as_ref()].into_iter().enumerate() {
            if let Some(value) = value {
                if value.value.base.slot != slot as u8 { return Err(FormatError::WrongSlot); }
                checkpoints_match_superblock(self.superblock.value(), &value.value.metadata_only(), maximum_pages)?;
            }
        }
        match (left, right) {
            (None, None) => Ok(None),
            (Some(value), None) | (None, Some(value)) => Ok(Some(SelectedCheckpoint {
                current: RecoveryCheckpoint { record: value }, previous: None })),
            (Some(left), Some(right)) => {
                let (older, newer) = if left.value.base.binding.generation < right.value.base.binding.generation {
                    (left, right)
                } else { (right, left) };
                validate_checkpoint_transition(&older.value.base, &newer.value.base)?;
                Ok(Some(SelectedCheckpoint { current: RecoveryCheckpoint { record: newer },
                    previous: Some(RecoveryCheckpoint { record: older }) }))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundleCheckpoint {
    pub base: Checkpoint,
    /// Catalog, authority, allocation bits; replay_tail is never a bundle member.
    pub root_bundle_mask: u32,
}

impl BundleCheckpoint {
    fn metadata_only(self) -> Checkpoint {
        Checkpoint { catalog_root: PhysicalPointer::Null, authority_root: PhysicalPointer::Null,
            allocation_root: PhysicalPointer::Null, ..self.base }
    }

    pub fn validate(self) -> Result<(), FormatError> {
        if self.root_bundle_mask & !7 != 0 { return Err(FormatError::InvalidField); }
        // Reuse slot, generation, admission, replay and geometry validation.
        validate_checkpoint(&self.metadata_only())?;
        let roots = [self.base.catalog_root, self.base.authority_root,
            self.base.allocation_root, self.base.replay_tail];
        for (index, pointer) in roots.iter().copied().enumerate() {
            let bundled = self.root_bundle_mask & (1 << index) != 0;
            if bundled && pointer == PhysicalPointer::Null { return Err(FormatError::InvalidPointer); }
            let kind = if bundled { ExtentKind::Catalog } else {
                [ExtentKind::Catalog, ExtentKind::Authority, ExtentKind::Allocation, ExtentKind::CatalogDelta][index]
            };
            validate_pointer(pointer, self.base.binding.store_uuid, self.base.admitted_segments, kind)?;
            if let PhysicalPointer::Value(value) = pointer {
                if value.segment_generation >= self.base.next_segment_generation {
                    return Err(FormatError::InvalidPointer);
                }
            }
            for (previous_index, previous) in roots[..index].iter().copied().enumerate() {
                if let (PhysicalPointer::Value(left), PhysicalPointer::Value(right)) = (previous, pointer) {
                    if left.segment_no == right.segment_no && left.segment_generation != right.segment_generation {
                        return Err(FormatError::InvalidPointer);
                    }
                }
                if pointers_overlap(previous, pointer) {
                    let shared = bundled && self.root_bundle_mask & (1 << previous_index) != 0 && previous == pointer;
                    if !shared { return Err(FormatError::DuplicateOrOverlappingRecord); }
                }
            }
        }
        Ok(())
    }
}

pub fn encode_body(value: BundleCheckpoint, out: &mut Page) -> Result<BodyDigest, FormatError> {
    value.validate()?;
    // Existing common fields keep their established encoding and invariants.
    write_checkpoint_fields(&value.base, out)?;
    put_u32(out, 0xb4, value.root_bundle_mask);
    put_u32(out, 0xb8, TAG);
    Ok(finish_body(RecordKind::Checkpoint, 0x1c0, value.base.binding, out))
}

pub fn decode_verified(body: &Page, seal: &Page)
    -> Result<DecodeStatus<VerifiedRecord<BundleCheckpoint>>, FormatError>
{
    let digest = match decode_common(body, seal, RecordKind::Checkpoint, 0x1c0)? {
        DecodeStatus::Empty => return Ok(DecodeStatus::Empty),
        DecodeStatus::Unsealed => return Ok(DecodeStatus::Unsealed),
        DecodeStatus::Sealed(digest) => digest,
    };
    if !is_zero(&body[0x81..0x88]) || get_u32(body, 0xb8) != TAG || get_u32(body, 0xbc) != 0 {
        return Err(FormatError::NonZeroReserved);
    }
    let base = Checkpoint {
        binding: digest.binding, slot: body[0x80], previous_generation: get_u64(body, 0x88),
        admitted_range_pages: get_u64(body, 0x90), admitted_segments: get_u64(body, 0x98),
        next_segment_generation: get_u64(body, 0xa0), replay_count: get_u32(body, 0xa8),
        max_replay_records: get_u32(body, 0xac), cleaner_reserve_segments: get_u32(body, 0xb0),
        catalog_root: read_pointer(body, 0xc0)?, authority_root: read_pointer(body, 0x120)?,
        allocation_root: read_pointer(body, 0x180)?, replay_tail: read_pointer(body, 0x1e0)?,
    };
    let value = BundleCheckpoint { base, root_bundle_mask: get_u32(body, 0xb4) };
    value.validate()?;
    Ok(DecodeStatus::Sealed(VerifiedRecord { value, digest }))
}
