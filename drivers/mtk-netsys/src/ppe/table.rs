//! CPU-owned FOE storage. Public staging is INVALID-only; the control module
//! may prepare a TCP/UDP BIND entry while the device is disabled. The experimental
//! retirement primitive touches only an aligned IB1 word while published.
use super::{StagedEntry, ENTRY_BYTES};
pub const ENTRIES: usize = 16384;
pub const TABLE_BYTES: usize = ENTRIES * ENTRY_BYTES;
/// Deliberately table-size aligned; this is our allocation contract, not a claim
/// about the hardware's minimum alignment.
pub const ALIGNMENT: usize = TABLE_BYTES;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Alignment,
    Length,
    Address,
    Index,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    base: u32,
}
impl Region {
    pub fn new(base: u64, length: usize) -> Result<Self, Error> {
        if length != TABLE_BYTES {
            return Err(Error::Length);
        }
        if base == 0
            || base
                .checked_add(length as u64)
                .is_none_or(|end| end > 1u64 << 32)
        {
            return Err(Error::Address);
        }
        if base % ALIGNMENT as u64 != 0 {
            return Err(Error::Alignment);
        }
        Ok(Self { base: base as u32 })
    }
    pub fn base(self) -> u32 {
        self.base
    }
    pub fn end(self) -> u64 {
        u64::from(self.base) + TABLE_BYTES as u64
    }
}
/// Exclusive CPU borrow, with no Clone/Copy or raw mutable storage accessor.
/// Hardware publication is available only through the unsafe lifecycle API.
pub struct CpuTable<'a> {
    region: Region,
    bytes: &'a mut [u8],
    zero_proven: bool,
}
impl<'a> CpuTable<'a> {
    /// Physical address translation/disjoint allocation belongs to the caller.
    /// A failed validation does not modify the supplied storage.
    pub fn new(bytes: &'a mut [u8], physical: u64) -> Result<Self, Error> {
        let region = Region::new(physical, bytes.len())?;
        bytes.fill(0);
        Ok(Self { region, bytes, zero_proven: true })
    }
    #[cfg(test)]
    pub(super) fn bytes_for_test(&self) -> &[u8] {
        self.bytes
    }
    /// Whether this exclusive CPU borrow carries a complete-clear proof.
    /// Only construction or a complete CPU clear establishes it; staging,
    /// partial clearing and hardware publication consume it. No mutable storage
    /// accessor or Clone can bypass those transitions. This is a lifecycle
    /// invariant, not a fresh memory readback or a detector of hardware faults.
    /// Callers must still uphold the unsafe publication/physical-alias contract.
    pub fn has_zero_proof(&self) -> bool { self.zero_proven }
    pub(super) fn publish(&mut self) { self.zero_proven = false; }
    pub fn region(&self) -> Region {
        self.region
    }
    pub fn stage(&mut self, index: usize, entry: &StagedEntry) -> Result<(), Error> {
        if index >= ENTRIES {
            return Err(Error::Index);
        }
        self.zero_proven = false;
        self.bytes[index * ENTRY_BYTES..(index + 1) * ENTRY_BYTES].copy_from_slice(entry.bytes());
        Ok(())
    }
    // Only lifecycle code may prepare BIND while ingress/engine are disabled.
    pub(super) fn bind_napt(&mut self, index: usize, entry: &StagedEntry, timestamp: u8) {
        self.stage(index, entry)
            .expect("validated hardware hash slot");
        // Preserve only the validated L2 tag recipe; cache/static/type/state
        // bits remain lifecycle-owned rather than copied from staging.
        let tags = u32::from_le_bytes(entry.bytes()[..4].try_into().unwrap())
            & ((7 << 14) | (1 << 18));
        let protocol = u32::from_le_bytes(entry.bytes()[..4].try_into().unwrap()) & (1 << 30);
        let ib1 = protocol | (2 << 28) | (1 << 22) | tags | u32::from(timestamp);
        self.bytes[index * ENTRY_BYTES..index * ENTRY_BYTES + 4]
            .copy_from_slice(&ib1.to_le_bytes());
    }
    pub fn entry(&self, index: usize) -> Result<&[u8], Error> {
        if index >= ENTRIES {
            return Err(Error::Index);
        }
        Ok(&self.bytes[index * ENTRY_BYTES..(index + 1) * ENTRY_BYTES])
    }
    // Aligned volatile diagnostic word only; not a DMA ownership proof.
    pub(super) unsafe fn state_word(&self, index: usize) -> Option<u32> {
        if index >= ENTRIES { return None; }
        let word = unsafe { self.bytes.as_ptr().add(index * ENTRY_BYTES) }.cast::<u32>();
        if word.addr() % core::mem::align_of::<u32>() != 0 { return None; }
        Some(u32::from_le(unsafe { core::ptr::read_volatile(word) }))
    }
    // Lifecycle-only experimental live invalidation. Touch only the aligned
    // IB1 word; do not create a slice/reference into hardware-visible contents.
    // This does not establish DMA quiescence or permit reuse of the entry body.
    pub(super) unsafe fn retire_napt_state(&mut self, index: usize, protocol: super::Protocol) -> bool {
        if index >= ENTRIES { return false; }
        let word = unsafe { self.bytes.as_mut_ptr().add(index * ENTRY_BYTES) }.cast::<u32>();
        if word.addr() % core::mem::align_of::<u32>() != 0 { return false; }
        let ib1 = u32::from_le(unsafe { core::ptr::read_volatile(word) });
        let expected = if protocol == super::Protocol::Udp { 1 << 30 } else { 0 };
        let state = (ib1 >> 28) & 3;
        // TCP control traps can move a previously owned BIND installation to
        // the hardware FIN state before the owner sees FIN/RST. Both terminal
        // directions still need invalidation; UDP never owns a FIN state.
        if ib1 & (1 << 30) != expected
            || !(state == 2 || (protocol == super::Protocol::Tcp && state == 3)) { return false; }
        self.zero_proven = false;
        unsafe { core::ptr::write_volatile(word, (ib1 & !(3 << 28)).to_le()); }
        true
    }
    // Call only after retire_napt_state succeeded and a full DMA barrier.
    pub(super) unsafe fn retired_state_visible(&self, index: usize) -> bool {
        let word = unsafe { self.bytes.as_ptr().add(index * ENTRY_BYTES) }.cast::<u32>();
        u32::from_le(unsafe { core::ptr::read_volatile(word) }) & (3 << 28) == 0
    }
    // Lifecycle-only: all ingress drained and engine disabled.
    pub(super) fn clear_entry(&mut self, index: usize) {
        self.zero_proven = false;
        self.bytes[index * ENTRY_BYTES..(index + 1) * ENTRY_BYTES].fill(0);
    }
    pub fn clear(&mut self) {
        self.zero_proven = false;
        self.bytes.fill(0);
        self.zero_proven = true;
    }
    pub fn is_zero(&self) -> bool {
        // Normal-NC storage makes every load costly. Check full machine words
        // without weakening the full-table check or requiring virtual alignment.
        let mut words = self.bytes.chunks_exact(core::mem::size_of::<u64>());
        words.all(|word| u64::from_ne_bytes(word.try_into().unwrap()) == 0)
            && words.remainder().iter().all(|byte| *byte == 0)
    }
    pub fn nonzero_entries(&self) -> usize {
        self.bytes
            .chunks_exact(ENTRY_BYTES)
            .filter(|entry| entry.iter().any(|b| *b != 0))
            .count()
    }
    pub fn all_invalid(&self) -> bool {
        self.bytes
            .chunks_exact(ENTRY_BYTES)
            .all(|entry| entry[3] & 0x30 == 0)
    }
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::{
        ppe::{Protocol, Tuple},
        TxPort,
    };
    #[test]
    fn region_rejects_wrong_size_alignment_and_dma_address_overflow() {
        assert_eq!(
            Region::new(0x40c00000, TABLE_BYTES).unwrap().end(),
            0x40e00000
        );
        assert_eq!(
            Region::new(0xffe00000, TABLE_BYTES).unwrap().end(),
            1u64 << 32
        );
        assert_eq!(Region::new(0x40c01000, TABLE_BYTES), Err(Error::Alignment));
        assert_eq!(Region::new(0, TABLE_BYTES), Err(Error::Address));
        assert_eq!(Region::new(1u64 << 32, TABLE_BYTES), Err(Error::Address));
        assert_eq!(Region::new(u64::MAX - 1, TABLE_BYTES), Err(Error::Address));
        assert_eq!(Region::new(0x40c00000, TABLE_BYTES - 1), Err(Error::Length));
    }
    #[test]
    fn first_last_staging_preserves_neighbors_and_can_only_store_invalid_entries() {
        let mut bytes = std::vec![0xa5;TABLE_BYTES+2];
        let tuple = Tuple {
            source: [192, 168, 79, 100],
            destination: [192, 168, 78, 100],
            source_port: 1234,
            destination_port: 80,
        };
        let entry = StagedEntry::ipv4_napt(
            Protocol::Udp,
            tuple,
            tuple,
            TxPort::Wan,
            [2, 0, 0, 0, 0, 1],
            [2, 0, 0, 0, 0, 2],
        )
        .unwrap();
        {
            let mut table = CpuTable::new(&mut bytes[1..TABLE_BYTES + 1], 0x40c00000).unwrap();
            assert!(table.is_zero());
            assert!(table.has_zero_proof());
            for index in [0, ENTRIES - 1] {
                table.stage(index, &entry).unwrap();
                assert!(!table.has_zero_proof());
                assert_eq!(table.entry(index).unwrap(), entry.bytes());
            }
            assert!(!table.is_zero());
            assert!(table.all_invalid());
            assert!(table.entry(1).unwrap().iter().all(|b| *b == 0));
            assert!(table.entry(ENTRIES - 2).unwrap().iter().all(|b| *b == 0));
            assert_eq!(table.stage(ENTRIES, &entry), Err(Error::Index));
            assert_eq!(table.stage(usize::MAX, &entry), Err(Error::Index));
            table.clear();
            assert!(table.has_zero_proof());
            assert!(table.is_zero());
        }
        assert_eq!(bytes[0], 0xa5);
        assert_eq!(bytes[TABLE_BYTES + 1], 0xa5);
    }
    #[test]
    fn zero_scan_detects_every_byte_lane_at_unaligned_table_boundaries() {
        let mut backing = std::vec![0xa5; TABLE_BYTES + 2];
        {
            let table = CpuTable::new(&mut backing[1..TABLE_BYTES + 1], 0x40c00000).unwrap();
            assert!(table.is_zero());
            for base in [0, ENTRY_BYTES - 8, TABLE_BYTES - 8] {
                for lane in 0..8 {
                    table.bytes[base + lane] = 0x80;
                    assert!(!table.is_zero(), "missed byte {}", base + lane);
                    table.bytes[base + lane] = 0;
                }
            }
            assert!(table.is_zero());
        }
        assert_eq!(backing[0], 0xa5);
        assert_eq!(backing[TABLE_BYTES + 1], 0xa5);
    }
    #[test]
    fn live_state_write_rejects_unaligned_virtual_storage_and_invalid_indices() {
        let mut backing = std::vec![0; TABLE_BYTES + 4];
        let offset = (5 - backing.as_ptr().addr() % 4) % 4;
        let mut table = CpuTable::new(&mut backing[offset..offset + TABLE_BYTES], 0x40c00000).unwrap();
        assert_eq!(table.bytes.as_ptr().addr() % 4, 1);
        table.bytes[..4].copy_from_slice(&((1u32 << 30) | (2 << 28)).to_le_bytes());
        let before = table.bytes.to_vec();
        assert!(!unsafe { table.retire_napt_state(0, super::super::Protocol::Udp) });
        assert!(!unsafe { table.retire_napt_state(ENTRIES, super::super::Protocol::Udp) });
        assert!(!unsafe { table.retire_napt_state(usize::MAX, super::super::Protocol::Udp) });
        assert_eq!(table.bytes, before);
    }

    #[test]
    fn retirement_accepts_only_bound_or_owned_tcp_terminal_state() {
        use super::super::Protocol;
        let mut backing = std::vec![0; TABLE_BYTES + 4];
        let offset = (4 - backing.as_ptr().addr() % 4) % 4;
        let mut table = CpuTable::new(&mut backing[offset..offset + TABLE_BYTES], 0x40c00000).unwrap();
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            for state in 0..4u32 {
                let word = (if protocol == Protocol::Udp {1u32 << 30} else {0})
                    | (state << 28) | (1 << 22) | 0x44022;
                table.bytes[..ENTRY_BYTES].fill(0xa5);
                table.bytes[..4].copy_from_slice(&word.to_le_bytes());
                let before = table.bytes[..ENTRY_BYTES].to_vec();
                let expected = state == 2 || (state == 3 && protocol == Protocol::Tcp);
                assert_eq!(unsafe { table.retire_napt_state(0, protocol) }, expected);
                assert_eq!(&table.bytes[4..ENTRY_BYTES], &before[4..]);
                assert_eq!(&table.bytes[..4], &(if expected {word & !(3 << 28)} else {word}).to_le_bytes());
            }
        }
    }

    #[test]
    fn retirement_checks_expected_protocol_and_preserves_body() {
        use super::super::Protocol;
        let mut backing = std::vec![0; TABLE_BYTES + 4];
        let offset = (4 - backing.as_ptr().addr() % 4) % 4;
        let mut table = CpuTable::new(&mut backing[offset..offset + TABLE_BYTES], 0x40c00000).unwrap();
        for (protocol, wrong, bit) in [(Protocol::Tcp, Protocol::Udp, 0u32), (Protocol::Udp, Protocol::Tcp, 1u32 << 30)] {
            table.bytes[..ENTRY_BYTES].fill(0xa5);
            let word = bit | (2 << 28) | (1 << 22) | 0x5a;
            table.bytes[..4].copy_from_slice(&word.to_le_bytes());
            let before = table.bytes[..ENTRY_BYTES].to_vec();
            assert!(!unsafe { table.retire_napt_state(0, wrong) });
            assert_eq!(&table.bytes[..ENTRY_BYTES], before);
            assert!(unsafe { table.retire_napt_state(0, protocol) });
            assert_eq!(&table.bytes[4..ENTRY_BYTES], &before[4..]);
            assert_eq!(&table.bytes[..4], &(word & !(3 << 28)).to_le_bytes());
            assert!(!unsafe { table.retire_napt_state(0, protocol) });
        }
    }

    #[test]
    fn zero_proof_is_consumed_by_publication_and_not_rebuilt_by_partial_clear() {
        let mut bytes = std::vec![0xa5; TABLE_BYTES];
        let mut table = CpuTable::new(&mut bytes, 0x40c00000).unwrap();
        assert!(table.has_zero_proof());
        table.publish();
        assert!(!table.has_zero_proof());
        assert!(table.is_zero()); // A diagnostic read does not mint a proof.
        table.clear_entry(ENTRIES - 1);
        assert!(!table.has_zero_proof());
        table.clear();
        assert!(table.has_zero_proof());
        assert!(table.is_zero());
    }
    #[test]
    fn invalid_region_does_not_clear_callers_memory() {
        let mut bytes = [0xa5; ENTRY_BYTES];
        assert!(matches!(
            CpuTable::new(&mut bytes, 0x40c00000),
            Err(Error::Length)
        ));
        assert!(bytes.iter().all(|b| *b == 0xa5));
    }
}
