mod production_common;

use production_common::{checkpoint, extent, segment_header, segment_seal, summary};
use vibeos_segment_format::{
    admitted_pages, decode_checkpoint_verified, decode_extent_verified, decode_physical_pointer,
    decode_segment_header_verified, decode_segment_seal_verified, decode_segment_summary_verified,
    descriptor_chain_initial, descriptor_chain_next, encode_checkpoint_body, encode_extent_body,
    encode_physical_pointer, encode_record_seal, encode_segment_header_body,
    encode_segment_seal_body, encode_segment_summary_body, payload_chain_initial,
    payload_chain_next, payload_sha256, segment_base_page, select_checkpoint_for_superblock,
    select_superblock, DecodeStatus, ExtentKind, FormatError, Page, PhysicalPointer,
    SegmentVerifier, StoreUuid, VerifiedRecord, POINTER_SIZE,
};

fn seal(digest: vibeos_segment_format::BodyDigest) -> Page {
    let mut page = [0; 4096];
    encode_record_seal(digest, &mut page).unwrap();
    page
}

fn verified_checkpoint(
    value: &vibeos_segment_format::Checkpoint,
) -> VerifiedRecord<vibeos_segment_format::Checkpoint> {
    let mut body = [0; 4096];
    let digest = encode_checkpoint_body(value, &mut body).unwrap();
    match decode_checkpoint_verified(&body, &seal(digest)).unwrap() {
        DecodeStatus::Sealed(record) => record,
        _ => panic!("encoded checkpoint did not verify"),
    }
}

fn verified_superblock(
    value: &vibeos_segment_format::Superblock,
) -> VerifiedRecord<vibeos_segment_format::Superblock> {
    let mut body = [0; 4096];
    let digest = vibeos_segment_format::encode_superblock_body(value, &mut body).unwrap();
    match vibeos_segment_format::decode_superblock_verified(&body, &seal(digest)).unwrap() {
        DecodeStatus::Sealed(record) => record,
        _ => panic!("encoded superblock did not verify"),
    }
}

fn verified_header(
    value: &vibeos_segment_format::SegmentHeader,
) -> VerifiedRecord<vibeos_segment_format::SegmentHeader> {
    let mut body = [0; 4096];
    let digest = encode_segment_header_body(value, &mut body).unwrap();
    match decode_segment_header_verified(&body, &seal(digest)).unwrap() {
        DecodeStatus::Sealed(record) => record,
        _ => panic!("encoded header did not verify"),
    }
}

fn verified_extent(
    value: &vibeos_segment_format::ExtentRecord,
) -> VerifiedRecord<vibeos_segment_format::ExtentRecord> {
    let mut body = [0; 4096];
    let digest = encode_extent_body(value, &mut body).unwrap();
    match decode_extent_verified(&body, &seal(digest)).unwrap() {
        DecodeStatus::Sealed(record) => record,
        _ => panic!("encoded extent did not verify"),
    }
}

fn verified_summary(
    value: &vibeos_segment_format::SegmentSummary,
) -> VerifiedRecord<vibeos_segment_format::SegmentSummary> {
    let mut body = [0; 4096];
    let digest = encode_segment_summary_body(value, &mut body).unwrap();
    match decode_segment_summary_verified(&body, &seal(digest)).unwrap() {
        DecodeStatus::Sealed(record) => record,
        _ => panic!("encoded summary did not verify"),
    }
}

fn verified_segment_seal(
    value: &vibeos_segment_format::SegmentSeal,
) -> VerifiedRecord<vibeos_segment_format::SegmentSeal> {
    let mut body = [0; 4096];
    let digest = encode_segment_seal_body(value, &mut body).unwrap();
    match decode_segment_seal_verified(&body, &seal(digest)).unwrap() {
        DecodeStatus::Sealed(record) => record,
        _ => panic!("encoded segment seal did not verify"),
    }
}

#[test]
fn production_checkpoint_selection_is_strictly_contiguous_and_monotonic() {
    let super_a = verified_superblock(&production_common::superblock(0));
    let super_b = verified_superblock(&production_common::superblock(1));
    let selected_super = select_superblock(Some(super_a), Some(super_b))
        .unwrap()
        .unwrap();
    let maximum_pages = admitted_pages(4).unwrap();
    let first = verified_checkpoint(&checkpoint(1));
    let second = verified_checkpoint(&checkpoint(2));
    assert_eq!(
        select_checkpoint_for_superblock(selected_super, Some(first), Some(second), maximum_pages),
        Ok(Some(second))
    );

    let fourth = verified_checkpoint(&checkpoint(4));
    assert_eq!(
        select_checkpoint_for_superblock(selected_super, Some(first), Some(fourth), maximum_pages),
        Err(FormatError::BrokenGenerationChain)
    );

    let mut foreign = checkpoint(2);
    let foreign_uuid = StoreUuid::new(*b"foreign-v2-store").unwrap();
    foreign.binding.store_uuid = foreign_uuid;
    for pointer in [
        &mut foreign.catalog_root,
        &mut foreign.authority_root,
        &mut foreign.allocation_root,
        &mut foreign.replay_tail,
    ] {
        let PhysicalPointer::Value(mut value) = *pointer else {
            unreachable!();
        };
        value.store_uuid = foreign_uuid;
        *pointer = PhysicalPointer::Value(value);
    }
    let foreign = verified_checkpoint(&foreign);
    assert_eq!(
        select_checkpoint_for_superblock(selected_super, Some(first), Some(foreign), maximum_pages),
        Err(FormatError::BindingMismatch)
    );

    let mut rollback = checkpoint(2);
    rollback.admitted_segments = 3;
    rollback.admitted_range_pages = admitted_pages(3).unwrap();
    let rollback = verified_checkpoint(&rollback);
    assert_eq!(
        select_checkpoint_for_superblock(
            selected_super,
            Some(first),
            Some(rollback),
            maximum_pages
        ),
        Err(FormatError::AllocationAmplification)
    );
}

#[test]
fn extent_validation_is_checked_and_allows_empty_logical_content() {
    let mut empty = extent(0, 41, 1, 2, 1);
    empty.content_byte_len = 0;
    let mut page = [0; 4096];
    encode_extent_body(&empty, &mut page).unwrap();

    let mut overflowing = empty;
    overflowing.binding.self_page = segment_base_page(0).unwrap() + u64::from(u32::MAX);
    assert_eq!(
        encode_extent_body(&overflowing, &mut page),
        Err(FormatError::ArithmeticOverflow)
    );
}

#[test]
fn physical_pointer_codec_rejects_noncanonical_length_and_reserved_data() {
    let pointer = production_common::pointer(ExtentKind::Blob, 0, 41, 2, 2, 1);
    let mut encoded = [0; POINTER_SIZE];
    encode_physical_pointer(pointer, &mut encoded).unwrap();
    assert_eq!(decode_physical_pointer(&encoded), Ok(pointer));

    encoded[0x3c] = 1;
    assert_eq!(
        decode_physical_pointer(&encoded),
        Err(FormatError::InvalidPointer)
    );

    let PhysicalPointer::Value(mut value) = pointer else {
        unreachable!();
    };
    value.exact_byte_len -= 4096;
    assert_eq!(
        encode_physical_pointer(PhysicalPointer::Value(value), &mut encoded),
        Err(FormatError::InvalidPointer)
    );
}

#[test]
fn production_segment_verifier_binds_payload_cursor_counts_and_hash_chains() {
    let header = segment_header(0, 41);
    let verified_header = verified_header(&header);
    let header_body_sha256 = verified_header.digest().body_sha256();
    let mut verifier = SegmentVerifier::new(verified_header).unwrap();

    let first_payload = [0x51; 8192];
    let mut first = extent(0, 41, 1, 2, 2);
    first.payload_sha256 = payload_sha256(&first_payload);
    let verified_first = verified_extent(&first);
    verifier
        .append_extent(verified_first, &first_payload)
        .unwrap();

    let second_payload = [0x52; 8192];
    let mut second = extent(0, 41, 2, 6, 2);
    second.payload_sha256 = payload_sha256(&second_payload);
    let verified_second = verified_extent(&second);
    verifier
        .append_extent(verified_second, &second_payload)
        .unwrap();
    assert_eq!(verifier.next_ordinal(), 3);
    assert_eq!(verifier.next_relative_page(), 10);

    let mut descriptor_chain = descriptor_chain_initial(
        header.binding.store_uuid,
        header.binding.segment_no,
        header.binding.generation,
    );
    let mut payload_chain = payload_chain_initial(
        header.binding.store_uuid,
        header.binding.segment_no,
        header.binding.generation,
    );
    for (record, verified) in [(first, verified_first), (second, verified_second)] {
        descriptor_chain = descriptor_chain_next(
            header.binding.store_uuid,
            header.binding.segment_no,
            header.binding.generation,
            descriptor_chain,
            record.binding.ordinal,
            verified.digest().body_sha256(),
            record.payload_sha256,
        );
        payload_chain = payload_chain_next(
            header.binding.store_uuid,
            header.binding.segment_no,
            header.binding.generation,
            payload_chain,
            record.binding.ordinal,
            record.payload_byte_len,
            record.payload_sha256,
        );
    }

    let mut accepted_summary = summary(0, 41);
    accepted_summary.header_body_sha256 = header_body_sha256;
    accepted_summary.descriptor_chain_sha256 = descriptor_chain;
    accepted_summary.payload_chain_sha256 = payload_chain;
    let accepted_summary = verified_summary(&accepted_summary);
    verifier.verify_summary(accepted_summary).unwrap();

    let mut accepted_seal = segment_seal(0, 41);
    accepted_seal.header_body_sha256 = header_body_sha256;
    accepted_seal.summary_body_sha256 = accepted_summary.digest().body_sha256();
    accepted_seal.final_descriptor_chain_sha256 = descriptor_chain;
    accepted_seal.final_payload_chain_sha256 = payload_chain;
    let accepted_seal = verified_segment_seal(&accepted_seal);
    verifier
        .verify_seal(accepted_summary, accepted_seal)
        .unwrap();

    let mut mixed = *accepted_summary.value();
    mixed.descriptor_chain_sha256[0] ^= 1;
    assert_eq!(
        verifier.verify_summary(verified_summary(&mixed)),
        Err(FormatError::IncompleteSegment)
    );

    let mut skipped = extent(0, 41, 2, 10, 1);
    skipped.binding.ordinal = 4;
    let skipped_payload = [0x53; 4096];
    skipped.payload_sha256 = payload_sha256(&skipped_payload);
    assert_eq!(
        verifier.append_extent(verified_extent(&skipped), &skipped_payload),
        Err(FormatError::DuplicateOrOverlappingRecord)
    );

    assert_eq!(
        verifier.append_extent(verified_second, &[0; 8192]),
        Err(FormatError::DigestMismatch)
    );
}
