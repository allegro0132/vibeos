//! Ownership records for published FOE slots.
//!
//! The qualification geometry keeps its fixed sixteen-record budget. The
//! full-table geometry (`ppe-32k`) keeps one record per hardware slot, indexed
//! by that slot, so every lookup is bounded by the four ways of one bucket and
//! never by the number of installed rules. Storage is reserved once, before any
//! rule is published; later insertions cannot allocate.
use super::{Protocol, RuleTicket};
use crate::ppe::table::ENTRIES;

/// Rules one table may own. Overflow takes the software path, never eviction.
#[cfg(not(feature = "ppe-32k"))]
pub const MAX_RULES: usize = 16;
/// Every slot except the last: slot `ENTRIES - 1` was observed not to forward
/// on any engine of the qualified board, under either way ordering.
#[cfg(feature = "ppe-32k")]
pub const MAX_RULES: usize = ENTRIES - 1;

#[derive(Clone, Copy)]
pub(in crate::ppe) struct RuleRecord {
    pub ticket: RuleTicket,
    pub key: (Protocol, [u8; 12]),
    pub retiring: bool,
    /// Transient duplicate detection inside one batch validation.
    marked: bool,
}
impl RuleRecord {
    pub fn new(ticket: RuleTicket, key: (Protocol, [u8; 12])) -> Self {
        Self { ticket, key, retiring: false, marked: false }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ppe) enum BatchError {
    Stale,
    Duplicate,
    Capacity,
}

pub(in crate::ppe) struct Rules {
    #[cfg(not(feature = "ppe-32k"))]
    records: [Option<RuleRecord>; MAX_RULES],
    #[cfg(feature = "ppe-32k")]
    records: alloc::vec::Vec<Option<RuleRecord>>,
    count: usize,
    initial: Option<RuleTicket>,
}
impl Rules {
    pub fn new() -> Self {
        Self {
            #[cfg(not(feature = "ppe-32k"))]
            records: [None; MAX_RULES],
            #[cfg(feature = "ppe-32k")]
            records: alloc::vec![None; ENTRIES],
            count: 0,
            initial: None,
        }
    }
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.count
    }
    pub fn is_full(&self) -> bool {
        self.count >= MAX_RULES
    }
    /// The rule a session was prepared with, while that installation exists.
    pub fn initial(&self) -> Option<RuleTicket> {
        self.initial.filter(|ticket| self.get(*ticket).is_some())
    }
    fn position(&self, ticket: RuleTicket) -> Option<usize> {
        #[cfg(not(feature = "ppe-32k"))]
        {
            self.records.iter().position(|r| r.is_some_and(|r| r.ticket == ticket))
        }
        #[cfg(feature = "ppe-32k")]
        {
            self.records
                .get(ticket.index())
                .is_some_and(|r| r.is_some_and(|r| r.ticket == ticket))
                .then_some(ticket.index())
        }
    }
    /// Exact installation, never a successor that reuses its slot.
    pub fn get(&self, ticket: RuleTicket) -> Option<&RuleRecord> {
        self.position(ticket).and_then(|i| self.records[i].as_ref())
    }
    pub fn get_mut(&mut self, ticket: RuleTicket) -> Option<&mut RuleRecord> {
        self.position(ticket).and_then(|i| self.records[i].as_mut())
    }
    fn occupied(&self, slot: usize) -> bool {
        #[cfg(not(feature = "ppe-32k"))]
        {
            self.records.iter().flatten().any(|r| r.ticket.index() == slot)
        }
        #[cfg(feature = "ppe-32k")]
        {
            self.records[slot].is_some()
        }
    }
    /// A key always hashes to the same bucket, so its four ways are complete.
    pub fn contains_key(&self, bucket: usize, key: &(Protocol, [u8; 12])) -> bool {
        #[cfg(not(feature = "ppe-32k"))]
        {
            let _ = bucket;
            self.records.iter().flatten().any(|r| r.key == *key)
        }
        #[cfg(feature = "ppe-32k")]
        {
            self.records[bucket..bucket + 4].iter().flatten().any(|r| r.key == *key)
        }
    }
    /// First unowned way of a bucket (retiring installations still own theirs).
    pub fn free_way(&self, bucket: usize) -> Option<usize> {
        (bucket..bucket + 4).find(|slot| usable(*slot) && !self.occupied(*slot))
    }
    /// Caller has checked capacity, the key and that the slot is free.
    pub fn insert(&mut self, record: RuleRecord) {
        debug_assert!(!self.is_full() && !self.occupied(record.ticket.index()));
        #[cfg(not(feature = "ppe-32k"))]
        let slot = self.records.iter().position(Option::is_none).expect("checked rule capacity");
        #[cfg(feature = "ppe-32k")]
        let slot = record.ticket.index();
        if self.count == 0 && self.initial.is_none() {
            self.initial = Some(record.ticket);
        }
        self.records[slot] = Some(record);
        self.count += 1;
    }
    pub fn remove(&mut self, ticket: RuleTicket) -> bool {
        let Some(position) = self.position(ticket) else { return false };
        self.records[position] = None;
        self.count -= 1;
        true
    }
    /// Check that every ticket names a distinct live installation, without
    /// changing any record. Work is linear in the batch, not in the table.
    pub fn validate_batch(
        &mut self,
        tickets: impl Iterator<Item = RuleTicket> + Clone,
    ) -> Result<usize, BatchError> {
        let mut seen = 0;
        let mut result = Ok(());
        for ticket in tickets.clone() {
            if seen == MAX_RULES {
                result = Err(BatchError::Capacity);
                break;
            }
            match self.get_mut(ticket) {
                None => {
                    result = Err(BatchError::Stale);
                    break;
                }
                Some(record) if record.marked => {
                    result = Err(BatchError::Duplicate);
                    break;
                }
                Some(record) => record.marked = true,
            }
            seen += 1;
        }
        for ticket in tickets.take(seen) {
            if let Some(record) = self.get_mut(ticket) {
                record.marked = false;
            }
        }
        result.map(|()| seen)
    }
}

/// Slots this driver may publish in the current geometry.
pub(in crate::ppe) fn usable(slot: usize) -> bool {
    if cfg!(feature = "ppe-32k") {
        slot < ENTRIES - 1
    } else {
        slot < ENTRIES
    }
}
