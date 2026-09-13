//! Experimental checkpoint codec, not an admitted storage format.
//! Requires incompatible superblock admission before selecting any checkpoint.
use super::*;

const TAG: u32 = 0x3152_4245; // EBR1, including for a separated fallback checkpoint.

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
