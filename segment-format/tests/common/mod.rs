#![allow(dead_code)]

pub const PAGE_SIZE: usize = 4096;

pub fn strict_prefix(
    new_page: &[u8; PAGE_SIZE],
    old_page: &[u8; PAGE_SIZE],
    len: usize,
) -> [u8; PAGE_SIZE] {
    assert!(len < PAGE_SIZE);
    let mut result = *old_page;
    result[..len].copy_from_slice(&new_page[..len]);
    result
}

pub fn flipped(page: &[u8; PAGE_SIZE], offset: usize) -> [u8; PAGE_SIZE] {
    assert!(offset < PAGE_SIZE);
    let mut result = *page;
    result[offset] ^= 0x80;
    result
}

pub fn get_u16(page: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(page[offset..offset + 2].try_into().unwrap())
}

pub fn get_u32(page: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(page[offset..offset + 4].try_into().unwrap())
}

pub fn get_u64(page: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(page[offset..offset + 8].try_into().unwrap())
}

/// Enumerates every persistent state observable while replacing a page.
///
/// A device may expose the old page, any strict prefix of the new write joined
/// to the old suffix, or the exact completed new page until the following
/// flush establishes the new page as the durable baseline.
pub fn overwrite_crash_states<'a>(
    old_page: &'a [u8; PAGE_SIZE],
    new_page: &'a [u8; PAGE_SIZE],
) -> impl Iterator<Item = [u8; PAGE_SIZE]> + 'a {
    (0..=PAGE_SIZE).map(|prefix_len| {
        if prefix_len == PAGE_SIZE {
            *new_page
        } else {
            strict_prefix(new_page, old_page, prefix_len)
        }
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrashPoint {
    BeforeBodyWrite,
    DuringBodyWrite(usize),
    AfterBodyWrite,
    AfterBodyFlush,
    DuringSealWrite(usize),
    AfterSealWrite,
    AfterSealFlush,
}

/// All representative write/flush boundaries for a body-plus-seal commit.
/// Strict prefixes cover the byte-level tear cases separately.
pub const COMMIT_BOUNDARIES: &[CrashPoint] = &[
    CrashPoint::BeforeBodyWrite,
    CrashPoint::DuringBodyWrite(1),
    CrashPoint::DuringBodyWrite(PAGE_SIZE - 1),
    CrashPoint::AfterBodyWrite,
    CrashPoint::AfterBodyFlush,
    CrashPoint::DuringSealWrite(1),
    CrashPoint::DuringSealWrite(PAGE_SIZE - 1),
    CrashPoint::AfterSealWrite,
    CrashPoint::AfterSealFlush,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Slot {
    pub body: [u8; PAGE_SIZE],
    pub seal: [u8; PAGE_SIZE],
}

impl Slot {
    pub const ZERO: Self = Self {
        body: [0; PAGE_SIZE],
        seal: [0; PAGE_SIZE],
    };
}

/// Media states reachable by the required checkpoint-slot replacement
/// protocol. A replacement must first make the old seal durably empty, then
/// persist the new body, and only then publish its seal.
pub fn checkpoint_replacement_states(old: Slot, new: Slot) -> impl Iterator<Item = Slot> {
    let mut states = Vec::with_capacity(3 * (PAGE_SIZE + 1) + 4);
    states.push(old);

    // Clear the publication record before modifying a body that its digest
    // authenticates. Prefix tears retain an old-seal suffix and therefore may
    // be malformed; the writer cannot proceed until a successful flush and an
    // exact all-zero reread.
    for seal in overwrite_crash_states(&old.seal, &[0; PAGE_SIZE]) {
        states.push(Slot {
            body: old.body,
            seal,
        });
    }
    let cleared = Slot {
        body: old.body,
        seal: [0; PAGE_SIZE],
    };
    states.push(cleared);

    // With no complete seal, every torn body is unpublished.
    for body in overwrite_crash_states(&cleared.body, &new.body) {
        states.push(Slot {
            body,
            seal: cleared.seal,
        });
    }
    let body_durable = Slot {
        body: new.body,
        seal: [0; PAGE_SIZE],
    };
    states.push(body_durable);

    // A strict prefix of the non-zero terminal marker must remain unsealed.
    // Only the exact seal publishes the body.
    for seal in overwrite_crash_states(&body_durable.seal, &new.seal) {
        states.push(Slot {
            body: body_durable.body,
            seal,
        });
    }
    states.push(new);
    states.into_iter()
}

/// Unsafe shortcut used by a negative test: changing a published body without
/// first invalidating the old seal creates fail-closed mixed generations.
pub fn replacement_without_clear_states(old: Slot, new: Slot) -> impl Iterator<Item = Slot> {
    overwrite_crash_states(&old.body, &new.body)
        .map(|body| Slot {
            body,
            seal: old.seal,
        })
        .collect::<Vec<_>>()
        .into_iter()
}
