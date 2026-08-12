mod common;

use common::{
    checkpoint_replacement_states, replacement_without_clear_states, strict_prefix, Slot, PAGE_SIZE,
};

const BODY_MAGIC: &[u8; 8] = b"VIBESG2\0";
const SEAL_MAGIC: &[u8; 8] = b"VIBESL2\0";
const TERMINAL_MARKER: &[u8; 16] = b"VIBESG2-SEALED!!";
const BODY_GENERATION_OFFSET: usize = 0x28;
const BODY_CRC_OFFSET: usize = 0xfd0;
const BODY_CRC_COMPLEMENT_OFFSET: usize = 0xfd4;
const BODY_COPY_A_OFFSET: usize = 0xfd8;
const BODY_COPY_B_OFFSET: usize = 0xfe8;
const SEAL_GENERATION_OFFSET: usize = 0x28;
const SEAL_BODY_DIGEST_OFFSET: usize = 0x50;
const SEAL_CRC_OFFSET: usize = 0xfd0;
const SEAL_MARKER_OFFSET: usize = 0xff0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OracleStatus {
    Empty,
    Unsealed,
    Sealed(u64),
    Malformed,
}

fn checksum(bytes: &[u8]) -> u32 {
    // This is deliberately independent from the production CRC. It only makes
    // the crash-state oracle sensitive to every byte in its local fixtures.
    bytes.iter().fold(0x811c_9dc5_u32, |state, byte| {
        state.wrapping_mul(16_777_619) ^ u32::from(*byte)
    })
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut result = [0_u8; 32];
    for (index, chunk) in bytes.chunks(128).enumerate() {
        let word = checksum(chunk).rotate_left((index % 31) as u32);
        let lane = index % 8;
        let old = u32::from_le_bytes(result[lane * 4..lane * 4 + 4].try_into().unwrap());
        result[lane * 4..lane * 4 + 4].copy_from_slice(&old.wrapping_add(word).to_le_bytes());
    }
    result
}

fn fixture(generation: u64, fill: u8) -> Slot {
    let mut body = [fill; PAGE_SIZE];
    body[..8].copy_from_slice(BODY_MAGIC);
    body[BODY_GENERATION_OFFSET..BODY_GENERATION_OFFSET + 8]
        .copy_from_slice(&generation.to_le_bytes());
    body[BODY_CRC_OFFSET..].fill(0);
    let body_crc = checksum(&body[..BODY_CRC_OFFSET]);
    body[BODY_CRC_OFFSET..BODY_CRC_OFFSET + 4].copy_from_slice(&body_crc.to_le_bytes());
    body[BODY_CRC_COMPLEMENT_OFFSET..BODY_CRC_COMPLEMENT_OFFSET + 4]
        .copy_from_slice(&(!body_crc).to_le_bytes());
    let copy = digest(&body[..BODY_CRC_OFFSET]);
    body[BODY_COPY_A_OFFSET..BODY_COPY_A_OFFSET + 16].copy_from_slice(&copy[..16]);
    body[BODY_COPY_B_OFFSET..BODY_COPY_B_OFFSET + 8].copy_from_slice(&copy[16..24]);

    let mut seal = [0_u8; PAGE_SIZE];
    seal[..8].copy_from_slice(SEAL_MAGIC);
    seal[SEAL_GENERATION_OFFSET..SEAL_GENERATION_OFFSET + 8]
        .copy_from_slice(&generation.to_le_bytes());
    seal[SEAL_BODY_DIGEST_OFFSET..SEAL_BODY_DIGEST_OFFSET + 32].copy_from_slice(&digest(&body));
    let seal_crc = checksum(&seal[..SEAL_CRC_OFFSET]);
    seal[SEAL_CRC_OFFSET..SEAL_CRC_OFFSET + 4].copy_from_slice(&seal_crc.to_le_bytes());
    seal[SEAL_MARKER_OFFSET..].copy_from_slice(TERMINAL_MARKER);
    Slot { body, seal }
}

fn classify(slot: Slot) -> OracleStatus {
    if slot.body.iter().all(|byte| *byte == 0) && slot.seal.iter().all(|byte| *byte == 0) {
        return OracleStatus::Empty;
    }
    if slot.seal[SEAL_MARKER_OFFSET..] != *TERMINAL_MARKER {
        return OracleStatus::Unsealed;
    }
    if slot.body[..8] != *BODY_MAGIC || slot.seal[..8] != *SEAL_MAGIC {
        return OracleStatus::Malformed;
    }
    let body_crc = u32::from_le_bytes(
        slot.body[BODY_CRC_OFFSET..BODY_CRC_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    let complement = u32::from_le_bytes(
        slot.body[BODY_CRC_COMPLEMENT_OFFSET..BODY_CRC_COMPLEMENT_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    if body_crc != checksum(&slot.body[..BODY_CRC_OFFSET]) || complement != !body_crc {
        return OracleStatus::Malformed;
    }
    let generation = u64::from_le_bytes(
        slot.body[BODY_GENERATION_OFFSET..BODY_GENERATION_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    let sealed_generation = u64::from_le_bytes(
        slot.seal[SEAL_GENERATION_OFFSET..SEAL_GENERATION_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    if generation != sealed_generation
        || slot.seal[SEAL_BODY_DIGEST_OFFSET..SEAL_BODY_DIGEST_OFFSET + 32] != digest(&slot.body)
    {
        return OracleStatus::Malformed;
    }
    OracleStatus::Sealed(generation)
}

fn selected_generation(other_slot: Slot, replacing_slot: Slot) -> Result<u64, ()> {
    let a = classify(other_slot);
    let b = classify(replacing_slot);
    if matches!(a, OracleStatus::Malformed) || matches!(b, OracleStatus::Malformed) {
        return Err(());
    }
    Ok(match (a, b) {
        (OracleStatus::Sealed(left), OracleStatus::Sealed(right)) => left.max(right),
        (OracleStatus::Sealed(generation), _) | (_, OracleStatus::Sealed(generation)) => generation,
        _ => 0,
    })
}

#[test]
fn terminal_marker_strict_prefix_is_never_published() {
    let new = fixture(2, 0x5a);
    for prefix_len in 0..PAGE_SIZE {
        let seal = strict_prefix(&new.seal, &[0; PAGE_SIZE], prefix_len);
        assert_ne!(&seal[SEAL_MARKER_OFFSET..], TERMINAL_MARKER);
        assert_eq!(
            classify(Slot {
                body: new.body,
                seal
            }),
            OracleStatus::Unsealed
        );
    }
    assert_eq!(classify(new), OracleStatus::Sealed(2));
}

#[test]
fn clear_body_flush_seal_flush_recovers_only_old_or_exact_new() {
    let other_slot = fixture(2, 0x22);
    let reused_old = fixture(1, 0x11);
    let new = fixture(3, 0x33);

    for state in checkpoint_replacement_states(reused_old, new) {
        match selected_generation(other_slot, state) {
            Ok(generation) => assert!(generation == 2 || generation == 3),
            // A torn seal-clear can retain a complete old terminal marker while
            // corrupting the old seal. Recovery fails closed and the writer is
            // forbidden to advance until an exact-zero reread succeeds.
            Err(()) => assert_ne!(state.seal, [0; PAGE_SIZE]),
        }
    }
}

#[test]
fn omitting_clear_gate_exposes_stale_seal_body_mixes() {
    let old = fixture(1, 0x11);
    let new = fixture(3, 0x33);
    let malformed = replacement_without_clear_states(old, new)
        .skip(1)
        .take(PAGE_SIZE - 1)
        .filter(|state| classify(*state) == OracleStatus::Malformed)
        .count();
    assert!(malformed > 0);
}
