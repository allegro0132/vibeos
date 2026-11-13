//! One engine drained for edits while the peer retains hardware admission.
//! No allocation escapes this owner; any failure closes both and retains both.
use super::*;

pub struct DirectionalPausedPair {
    pub(super) pair: Pair,
    pub(super) direction: Direction,
}
pub enum DirectionalPauseOutcome {
    Paused(DirectionalPausedPair),
    Failed(PairQuarantine),
}
pub enum DirectionalEditOutcome<T> {
    Updated(DirectionalPausedPair, T),
    Rejected(DirectionalPausedPair, EditError),
    Failed(PairQuarantine),
}
impl ActivePair {
    /// Close and drain only the selected engine. The peer may remain BUSY.
    /// # Safety
    /// Uphold the paired ownership and independent dual-input cutoff contracts.
    /// No other ingress may feed either table, and caches/automatic writers
    /// must remain disabled. All authorities for the peer must remain valid.
    pub unsafe fn pause_direction(
        self,
        io: &mut impl Registers,
        timeout: u64,
        direction: Direction,
    ) -> DirectionalPauseOutcome {
        let result = (|| {
            if timeout == 0 || timeout >= 1 << 63 || !self.0.valid(io, true) {
                return Err(Error::Preconditions);
            }
            let (reg, engine) = match direction {
                Direction::Inbound => (WAN, Engine::Ppe0),
                Direction::Outbound => (0x540, Engine::Ppe1),
            };
            write_checked(io, reg, 0x20710000)?;
            idle_on(io, engine, timeout)?;
            let paused = match direction {
                Direction::Inbound => self.0.valid_states(io, false, true),
                Direction::Outbound => self.0.valid_states(io, true, false),
            };
            if !paused {
                return Err(Error::Preconditions);
            }
            Ok(())
        })();
        match result {
            Ok(()) => DirectionalPauseOutcome::Paused(DirectionalPausedPair {
                pair: self.0,
                direction,
            }),
            Err(e) => DirectionalPauseOutcome::Failed(fail(io, self.0.tables(), e)),
        }
    }
}
impl DirectionalPausedPair {
    fn valid(&self, io: &mut impl Registers) -> bool {
        match self.direction {
            Direction::Inbound => self.pair.valid_states(io, false, true),
            Direction::Outbound => self.pair.valid_states(io, true, false),
        }
    }
    fn selected(&self) -> &Session {
        match self.direction {
            Direction::Inbound => &self.pair.wan,
            Direction::Outbound => &self.pair.lan,
        }
    }
    fn selected_mut(&mut self) -> &mut Session {
        match self.direction {
            Direction::Inbound => &mut self.pair.wan,
            Direction::Outbound => &mut self.pair.lan,
        }
    }
    fn edit<R: Registers, T>(
        mut self,
        io: &mut R,
        timeout: u64,
        operation: impl FnOnce(&mut Session, &mut R) -> T,
    ) -> DirectionalEditOutcome<T> {
        let result = (|| {
            if timeout == 0 || timeout >= 1 << 63 || !self.valid(io) {
                return Err(Error::Preconditions);
            }
            let s = self.selected();
            let (engine, original_global) = (s.engine, s.before.global);
            write_checked(io, ppe_reg(engine, GLOBAL), original_global & !ENABLE)?;
            idle_on(io, engine, timeout)?;
            let value = operation(self.selected_mut(), io);
            io.barrier();
            write_checked(io, ppe_reg(engine, GLOBAL), original_global | ENABLE)?;
            idle_on(io, engine, timeout)?;
            // An IRQ cutoff or foreign change during the edit must never let
            // this token reopen admission or return either allocation.
            if !self.valid(io) {
                return Err(Error::Preconditions);
            }
            Ok(value)
        })();
        match result {
            Ok(value) => DirectionalEditOutcome::Updated(self, value),
            Err(e) => DirectionalEditOutcome::Failed(fail(io, self.pair.tables(), e)),
        }
    }
    /// Install a fresh exact directional authority without changing the peer.
    /// # Safety
    /// Revalidate the new NAT/neighbor/route/MTU authority through cutoff and
    /// retain all paired authorities. The selected engine alone is drained.
    pub unsafe fn insert_napt(
        self,
        io: &mut impl Registers,
        timeout: u64,
        binding: &NaptBinding,
    ) -> DirectionalEditOutcome<RuleTicket> {
        if !self.valid(io) {
            return DirectionalEditOutcome::Failed(fail(
                io,
                self.pair.tables(),
                Error::Preconditions,
            ));
        }
        let s = self.selected();
        if binding.path != s.path {
            return DirectionalEditOutcome::Rejected(self, EditError::Egress);
        }
        if binding.mtu != s.mtu {
            return DirectionalEditOutcome::Rejected(self, EditError::Mtu);
        }
        let key = binding.key();
        if s.rules.iter().flatten().any(|r| r.key == key) {
            return DirectionalEditOutcome::Rejected(self, EditError::Duplicate);
        }
        let Some(record) = s.rules.iter().position(Option::is_none) else {
            return DirectionalEditOutcome::Rejected(self, EditError::Capacity);
        };
        let Some(index) = (binding.index..binding.index + 4)
            .find(|i| !s.rules.iter().flatten().any(|r| r.ticket.index == *i))
        else {
            return DirectionalEditOutcome::Rejected(self, EditError::BucketFull);
        };
        let Some(ticket) = ticket(index) else {
            return DirectionalEditOutcome::Rejected(self, EditError::IdentityExhausted);
        };
        self.edit(io, timeout, |s, io| {
            s.table.bind_napt(index, &binding.entry, io.read(0x10) as u8);
            s.rules[record] = Some(RuleRecord {
                ticket,
                key,
                retiring: false,
            });
            ticket
        })
    }
    /// Reclaim exactly one installation after this engine's admission/drain.
    /// # Safety
    /// Preserve exclusive paired ownership, disabled caches/automatic writers,
    /// and the independent cutoff. A stale ticket cannot remove a successor.
    pub unsafe fn remove_napt(
        self,
        io: &mut impl Registers,
        timeout: u64,
        ticket: RuleTicket,
    ) -> DirectionalEditOutcome<()> {
        if !self.valid(io) {
            return DirectionalEditOutcome::Failed(fail(
                io,
                self.pair.tables(),
                Error::Preconditions,
            ));
        }
        let Some(record) = self
            .selected()
            .rules
            .iter()
            .position(|r| r.is_some_and(|r| r.ticket == ticket))
        else {
            return DirectionalEditOutcome::Rejected(self, EditError::Stale);
        };
        self.edit(io, timeout, |s, _| {
            s.table.clear_entry(ticket.index);
            s.rules[record] = None;
        })
    }
    /// # Safety
    /// Revalidate selected authorities and serialize this admission write and
    /// its readbacks with the independent cutoff; recheck its deadline inside
    /// that same critical section. An expired lease must never reopen.
    pub unsafe fn resume(self, io: &mut impl Registers) -> ResumeOutcome {
        if !self.valid(io) {
            return ResumeOutcome::Failed(fail(io, self.pair.tables(), Error::Preconditions));
        }
        let (reg, value) = match self.direction {
            Direction::Inbound => (WAN, 0x20713000),
            Direction::Outbound => (0x540, 0x20714000),
        };
        let result = write_checked(io, reg, value).and_then(|_| {
            if self.pair.valid(io, true) {
                Ok(())
            } else {
                Err(Error::Preconditions)
            }
        });
        match result {
            Ok(()) => ResumeOutcome::Active(ActivePair(self.pair)),
            Err(e) => ResumeOutcome::Failed(fail(io, self.pair.tables(), e)),
        }
    }
    /// # Safety
    /// Uphold pair stop contracts; close/drain both before returning storage.
    pub unsafe fn stop(self, io: &mut impl Registers, timeout: u64) -> PairOutcome {
        unsafe { ActivePair(self.pair).stop(io, timeout) }
    }
}
