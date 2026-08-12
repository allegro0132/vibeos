mod common;
mod production_common;

use common::{flipped, get_u16, get_u32, get_u64, strict_prefix};
use production_common::{
    checkpoint, first_extent, segment_header, segment_seal, summary, superblock, uuid,
};
use vibeos_segment_format::{
    crc32c, decode_checkpoint, decode_extent, decode_segment_header, decode_segment_seal,
    decode_segment_summary, decode_superblock, encode_checkpoint_body, encode_extent_body,
    encode_record_seal, encode_segment_header_body, encode_segment_seal_body,
    encode_segment_summary_body, encode_superblock_body, DecodeStatus, Page, RecordKind,
    FORMAT_VERSION, PAGE_SIZE,
};

const BODY_MAGIC: &[u8; 8] = b"VIBESG2\0";
const SEAL_MAGIC: &[u8; 8] = b"VIBESL2\0";
const TERMINAL_MARKER: &[u8; 16] = b"VIBESG2-SEALED!!";
const BODY_CRC_OFFSET: usize = 0xfd0;
const BODY_CRC_COMPLEMENT_OFFSET: usize = 0xfd4;
const BODY_SELF_PAGE_COPY_OFFSET: usize = 0xfd8;
const BODY_GENERATION_COPY_OFFSET: usize = 0xfe0;
const BODY_SEGMENT_COPY_OFFSET: usize = 0xfe8;
const SEAL_BODY_SHA_OFFSET: usize = 0x50;
const SEAL_CRC_OFFSET: usize = 0xfd0;
const SEAL_CRC_COMPLEMENT_OFFSET: usize = 0xfd4;
const TERMINAL_MARKER_OFFSET: usize = 0xff0;

fn sealed(digest: &vibeos_segment_format::BodyDigest) -> Page {
    let mut seal = [0; PAGE_SIZE];
    encode_record_seal(digest, &mut seal).unwrap();
    seal
}

fn assert_common_body_layout(body: &Page, kind: RecordKind, payload_len: usize) {
    assert_eq!(&body[..8], BODY_MAGIC);
    assert_eq!(get_u16(body, 0x08), FORMAT_VERSION);
    assert_eq!(get_u16(body, 0x0a), 0x80);
    assert_eq!(get_u16(body, 0x0c), kind as u16);
    assert_eq!(get_u16(body, 0x0e), 0);
    assert_eq!(get_u32(body, 0x10) as usize, payload_len);
    assert_eq!(&body[0x18..0x28], uuid().as_bytes());
    assert!(body[0x50..0x80].iter().all(|byte| *byte == 0));
    let crc = get_u32(body, BODY_CRC_OFFSET);
    assert_eq!(crc, crc32c(&body[..BODY_CRC_OFFSET]));
    assert_eq!(get_u32(body, BODY_CRC_COMPLEMENT_OFFSET), !crc);
    assert_eq!(
        get_u64(body, BODY_SELF_PAGE_COPY_OFFSET),
        get_u64(body, 0x40)
    );
    assert_eq!(
        get_u64(body, BODY_GENERATION_COPY_OFFSET),
        get_u64(body, 0x28)
    );
    assert_eq!(get_u64(body, BODY_SEGMENT_COPY_OFFSET), get_u64(body, 0x30));
    assert!(body[0x80 + payload_len..BODY_CRC_OFFSET]
        .iter()
        .all(|byte| *byte == 0));
}

fn assert_common_seal_layout(seal: &Page, kind: RecordKind, body: &Page) {
    assert_eq!(&seal[..8], SEAL_MAGIC);
    assert_eq!(get_u16(seal, 0x08), FORMAT_VERSION);
    assert_eq!(get_u16(seal, 0x0a), kind as u16);
    assert_eq!(get_u16(seal, 0x0c), 0x80);
    assert_eq!(&seal[0x10..0x20], uuid().as_bytes());
    assert_eq!(get_u32(seal, 0x70), get_u32(body, 0x10));
    assert_eq!(get_u32(seal, 0x48), get_u32(body, BODY_CRC_OFFSET));
    assert!(seal[0x74..SEAL_CRC_OFFSET].iter().all(|byte| *byte == 0));
    assert_ne!(
        &seal[SEAL_BODY_SHA_OFFSET..SEAL_BODY_SHA_OFFSET + 32],
        &[0; 32]
    );
    let crc = get_u32(seal, SEAL_CRC_OFFSET);
    assert_eq!(crc, crc32c(&seal[..SEAL_CRC_OFFSET]));
    assert_eq!(get_u32(seal, SEAL_CRC_COMPLEMENT_OFFSET), !crc);
    assert!(seal[0xfd8..TERMINAL_MARKER_OFFSET]
        .iter()
        .any(|byte| *byte != 0));
    assert_eq!(&seal[TERMINAL_MARKER_OFFSET..], TERMINAL_MARKER);
}

#[test]
fn superblock_exact_bytes_and_roundtrip() {
    let value = superblock(1);
    let mut body = [0xcc; PAGE_SIZE];
    let digest = encode_superblock_body(&value, &mut body).unwrap();
    let seal = sealed(&digest);
    assert_common_body_layout(&body, RecordKind::Superblock, 0x80);
    assert_common_seal_layout(&seal, RecordKind::Superblock, &body);
    assert_eq!(body[0x80], 1);
    assert!(body[0x81..0x88].iter().all(|byte| *byte == 0));
    assert_eq!(get_u32(&body, 0x88), 4096);
    assert_eq!(get_u32(&body, 0x8c), 16);
    assert_eq!(get_u32(&body, 0x90), 1024);
    assert_eq!(get_u32(&body, 0x94), 2);
    assert_eq!(get_u32(&body, 0x98), 1020);
    assert_eq!(get_u32(&body, 0x9c), 1020);
    assert_eq!(get_u32(&body, 0xa0), 1021);
    assert_eq!(get_u32(&body, 0xa4), 1022);
    assert_eq!(get_u32(&body, 0xa8), 1023);
    assert_eq!(get_u32(&body, 0xac), 256);
    assert_eq!(get_u32(&body, 0xb0), 1);
    assert_eq!(get_u16(&body, 0xb4), 1);
    assert_eq!(get_u64(&body, 0xb8), value.initial_range_pages);
    assert_eq!(get_u64(&body, 0xc0), 16);
    assert_eq!(get_u64(&body, 0xc8), value.initial_segments);
    assert_eq!(&body[0xd0..0xe0], &value.device_id);
    assert_eq!(get_u64(&body, 0xe0), value.range_first_logical_block);
    assert_eq!(get_u64(&body, 0xe8), value.initial_block_count);
    assert_eq!(get_u32(&body, 0xf0), value.logical_block_size);
    assert_eq!(get_u32(&body, 0xf4), 0);
    assert_eq!(get_u32(&body, 0xf8), value.max_replay_records);
    assert_eq!(get_u32(&body, 0xfc), 0);
    assert_eq!(
        decode_superblock(&body, &seal),
        Ok(DecodeStatus::Sealed(value))
    );
}

#[test]
fn every_record_type_roundtrips() {
    let mut body = [0; PAGE_SIZE];

    let value = checkpoint(2);
    let digest = encode_checkpoint_body(&value, &mut body).unwrap();
    let seal = sealed(&digest);
    assert_common_body_layout(&body, RecordKind::Checkpoint, 0x1c0);
    assert_eq!(
        decode_checkpoint(&body, &seal),
        Ok(DecodeStatus::Sealed(value))
    );

    let value = segment_header(0, 41);
    let digest = encode_segment_header_body(&value, &mut body).unwrap();
    let seal = sealed(&digest);
    assert_common_body_layout(&body, RecordKind::SegmentHeader, 0x58);
    assert_eq!(
        decode_segment_header(&body, &seal),
        Ok(DecodeStatus::Sealed(value))
    );

    let value = first_extent();
    let digest = encode_extent_body(&value, &mut body).unwrap();
    let seal = sealed(&digest);
    assert_common_body_layout(&body, RecordKind::Extent, 0x80);
    assert_eq!(decode_extent(&body, &seal), Ok(DecodeStatus::Sealed(value)));

    let value = summary(0, 41);
    let digest = encode_segment_summary_body(&value, &mut body).unwrap();
    let seal = sealed(&digest);
    assert_common_body_layout(&body, RecordKind::SegmentSummary, 0xc8);
    assert_eq!(
        decode_segment_summary(&body, &seal),
        Ok(DecodeStatus::Sealed(value))
    );

    let value = segment_seal(0, 41);
    let digest = encode_segment_seal_body(&value, &mut body).unwrap();
    let seal = sealed(&digest);
    assert_common_body_layout(&body, RecordKind::SegmentSeal, 0xa0);
    assert_eq!(
        decode_segment_seal(&body, &seal),
        Ok(DecodeStatus::Sealed(value))
    );
}

#[test]
fn strict_seal_prefixes_are_unsealed_but_complete_corruption_fails_closed() {
    let value = checkpoint(2);
    let mut body = [0; PAGE_SIZE];
    let digest = encode_checkpoint_body(&value, &mut body).unwrap();
    let seal = sealed(&digest);
    for prefix_len in 0..PAGE_SIZE {
        let torn = strict_prefix(&seal, &[0; PAGE_SIZE], prefix_len);
        assert_eq!(decode_checkpoint(&body, &torn), Ok(DecodeStatus::Unsealed));
    }
    assert_eq!(
        decode_checkpoint(&body, &seal),
        Ok(DecodeStatus::Sealed(value))
    );

    for offset in [0, 0x50, 0xfd0] {
        let corrupt = flipped(&seal, offset);
        assert!(decode_checkpoint(&body, &corrupt).is_err());
    }
    for offset in [0xff0, PAGE_SIZE - 1] {
        let corrupt = flipped(&seal, offset);
        assert_eq!(
            decode_checkpoint(&body, &corrupt),
            Ok(DecodeStatus::Unsealed)
        );
    }
}

#[test]
fn sealed_body_corruption_always_fails_closed() {
    let value = checkpoint(2);
    let mut body = [0; PAGE_SIZE];
    let digest = encode_checkpoint_body(&value, &mut body).unwrap();
    let seal = sealed(&digest);
    for offset in 0..PAGE_SIZE {
        let corrupt = flipped(&body, offset);
        assert!(
            decode_checkpoint(&corrupt, &seal).is_err(),
            "accepted body byte {offset:#x}"
        );
    }
}

#[test]
fn empty_pair_is_empty_and_body_without_seal_is_unsealed() {
    assert_eq!(
        decode_checkpoint(&[0; PAGE_SIZE], &[0; PAGE_SIZE]),
        Ok(DecodeStatus::Empty)
    );
    let value = checkpoint(2);
    let mut body = [0; PAGE_SIZE];
    encode_checkpoint_body(&value, &mut body).unwrap();
    assert_eq!(
        decode_checkpoint(&body, &[0; PAGE_SIZE]),
        Ok(DecodeStatus::Unsealed)
    );
}
