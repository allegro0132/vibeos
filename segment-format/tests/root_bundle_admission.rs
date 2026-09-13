//! Proposed experimental fields must fail closed in the current decoder.
mod production_common;

use vibeos_segment_format::{
    crc32c, decode_checkpoint, decode_superblock, encode_checkpoint_body,
    encode_record_seal, encode_superblock_body, payload_sha256, DecodeStatus,
    FormatError, Page, PAGE_SIZE,
};

fn reseal(body: &mut Page, seal: &mut Page) {
    let crc = crc32c(&body[..0xfd0]);
    body[0xfd0..0xfd4].copy_from_slice(&crc.to_le_bytes());
    body[0xfd4..0xfd8].copy_from_slice(&(!crc).to_le_bytes());
    seal[0x48..0x4c].copy_from_slice(&crc.to_le_bytes());
    seal[0x4c..0x50].copy_from_slice(&(!crc).to_le_bytes());
    seal[0x50..0x70].copy_from_slice(&payload_sha256(body));
    let crc = crc32c(&seal[..0xfd0]);
    seal[0xfd0..0xfd4].copy_from_slice(&crc.to_le_bytes());
    seal[0xfd4..0xfd8].copy_from_slice(&(!crc).to_le_bytes());
}

#[test]
fn sealed_experimental_markers_are_errors_not_unsealed_candidates() {
    let mut super_body = [0; PAGE_SIZE];
    let mut super_seal = [0; PAGE_SIZE];
    let d = encode_superblock_body(&production_common::superblock(0), &mut super_body).unwrap();
    encode_record_seal(d, &mut super_seal).unwrap();
    assert!(matches!(decode_superblock(&super_body, &super_seal), Ok(DecodeStatus::Sealed(_))));
    let mut checkpoint_body = [0; PAGE_SIZE];
    let mut checkpoint_seal = [0; PAGE_SIZE];
    let d = encode_checkpoint_body(&production_common::checkpoint(2), &mut checkpoint_body).unwrap();
    encode_record_seal(d, &mut checkpoint_seal).unwrap();
    assert!(matches!(decode_checkpoint(&checkpoint_body, &checkpoint_seal), Ok(DecodeStatus::Sealed(_))));
    for bit in 0..32 {
        let mut body = super_body;
        let mut seal = super_seal;
        body[0xf4..0xf8].copy_from_slice(&(1_u32 << bit).to_le_bytes());
        reseal(&mut body, &mut seal);
        assert_eq!(decode_superblock(&body, &seal), Err(FormatError::NonZeroReserved));
        let mut body = checkpoint_body;
        let mut seal = checkpoint_seal;
        body[0xb4..0xb8].copy_from_slice(&(1_u32 << bit).to_le_bytes());
        reseal(&mut body, &mut seal);
        assert_eq!(decode_checkpoint(&body, &seal), Err(FormatError::NonZeroReserved));
    }
}
