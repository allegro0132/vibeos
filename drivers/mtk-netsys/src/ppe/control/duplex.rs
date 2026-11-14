//! Two independently owned FOE tables. Experimental control plane only; no
//! automatic admission. WAN uses PPE0, MxL uses PPE1. Neither table is exposed
//! until both have been detached and restored successfully.
use super::*;
pub mod directional;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}
struct Pair {
    wan: Session,
    lan: Session,
    wan_mac: [u8; 6],
    /// The built-in switch's GDMA is a second ingress of the MxL table: it
    /// was handing every frame to PDMA and carried the MxL ingress address
    /// when the pair was prepared. Admitted and closed together with MxL.
    internal: bool,
}
pub struct PausedPair(Pair);
pub struct ActivePair(Pair);
pub struct PairQuarantine {
    _tables: [CpuTable<'static>; 2],
    pub error: Error,
    pub cutoff_error: Option<CutoffFailure>,
}
pub enum PairOutcome {
    Restored([CpuTable<'static>; 2]),
    Rejected([CpuTable<'static>; 2], Error),
    Quarantined(PairQuarantine),
}
pub enum PrepareOutcome {
    Paused(PausedPair),
    Failed(PairOutcome),
}
pub enum ResumeOutcome {
    Active(ActivePair),
    Failed(PairQuarantine),
}
pub enum PairPauseOutcome {
    Paused(PausedPair),
    Failed(PairQuarantine),
}
pub enum PairEditOutcome<T> {
    Updated(PausedPair, T),
    Rejected(PausedPair, EditError),
    Failed(PairQuarantine),
}
pub enum PairRetireOutcome {
    Pending(ActivePair),
    Rejected(ActivePair, RetireError),
    Failed(PairQuarantine),
}
fn cutoff() -> IngressCutoff {
    IngressCutoff::new(0x20710000, Some(0x20710000)).unwrap()
}
fn fail(io: &mut impl Registers, tables: [CpuTable<'static>; 2], error: Error) -> PairQuarantine {
    let cutoff_error = unsafe { cutoff().close(io) }.err();
    PairQuarantine {
        _tables: tables,
        error,
        cutoff_error,
    }
}
fn failed_table(outcome: Outcome) -> (CpuTable<'static>, Error) {
    match outcome {
        Outcome::Rejected(table, error) => (table, error),
        Outcome::Quarantined(q) => (q._table, q.error),
        Outcome::Restored(table) => (table, Error::Preconditions),
    }
}
fn mac_matches(io: &mut impl Registers, base: usize, mac: [u8; 6]) -> bool {
    mac != [0; 6]
        && mac[0] & 1 == 0
        && io.read(base + 8) == u32::from_be_bytes(mac[2..].try_into().unwrap())
        && io.read(base + 12) == u16::from_be_bytes(mac[..2].try_into().unwrap()) as u32
}
impl Pair {
    fn tables(self) -> [CpuTable<'static>; 2] {
        [self.wan.table, self.lan.table]
    }
    fn isolated(&self, io: &mut impl Registers) -> bool {
        let FlowPath::MxlToWan(mac) = self.lan.path else {
            return false;
        };
        let spare = Snapshot::read(Engine::Ppe2, |o| io.read(o));
        self.wan.engine == Engine::Ppe0
            && self.lan.engine == Engine::Ppe1
            && self.wan.path == FlowPath::WanToMxl
            && mac_matches(io, WAN, self.wan_mac)
            && mac_matches(io, 0x540, mac)
            && if self.internal {
                matches!(io.read(0x500), super::INTERNAL_CPU | super::INTERNAL_ADMIT) && mac_matches(io, 0x500, mac)
            } else {
                super::internal_bypasses(io.read(0x500))
            }
            && spare.table_base == 0
            && spare.cache == 0
            && !spare.busy()
    }
    fn valid(&self, io: &mut impl Registers, active: bool) -> bool {
        self.valid_states(io, active, active)
    }
    fn valid_states(&self, io: &mut impl Registers, wan_active: bool, lan_active: bool) -> bool {
        if !self.isolated(io) {
            return false;
        }
        let wan = io.read(WAN);
        let lan = io.read(0x540);
        if wan != if wan_active { 0x20713000 } else { 0x20710000 }
            || lan != if lan_active { 0x20714000 } else { 0x20710000 }
            || (self.internal && io.read(0x500) != if lan_active { super::INTERNAL_ADMIT } else { super::INTERNAL_CPU })
        {
            return false;
        }
        [(&self.wan, wan_active), (&self.lan, lan_active)]
            .into_iter()
            .all(|(s, active)| {
                let reg = |o| ppe_reg(s.engine, o);
                io.read(reg(TABLE_BASE)) == s.table.region().base()
                    && io.read(reg(GLOBAL)) & (if active { ENABLE } else { ENABLE | BUSY })
                        == ENABLE
                    && io.read(reg(0x2320)) == 0
                    && io.read(reg(TABLE_CONFIG)) == TABLE_CONFIG_VALUE
                    && io.read(reg(0x2204)) == 0x200e
            })
    }
}

/// Prepare both tables without opening either ingress. Table order is inbound,
/// outbound. A private owned-peer proof permits the second publication without
/// weakening public single-engine preconditions.
/// # Safety
/// Own both GDMA policies, both engine banks, both non-aliasing permanent DMA
/// allocations, WAN/LAN MAC configuration and the qualified MxL untagged-access
/// lease. Validate both directional NAT receipts, neighbors, MTUs and deadlines.
/// Keep an independent dual-input timer/owner cutoff armed whenever admission
/// is possible. No concurrent register owner or automatic table writer may run.
/// All single-session memory, barrier and failure/reset contracts apply.
/// TCP also requires explicit established-flow authority and qualified control
/// trapping; revoke hardware before processing SYN/FIN/RST or policy changes.
pub unsafe fn prepare(
    io: &mut impl Registers,
    tables: [CpuTable<'static>; 2],
    timeout: u64,
    inbound: &NaptBinding,
    outbound: &NaptBinding,
    wan_mac: [u8; 6],
) -> PrepareOutcome {
    let a = tables[0].region();
    let b = tables[1].region();
    if inbound.path != FlowPath::WanToMxl
        || !matches!(outbound.path, FlowPath::MxlToWan(_))
        || !(a.end() <= u64::from(b.base()) || b.end() <= u64::from(a.base()))
        || !tables.iter().all(CpuTable::has_zero_proof)
        || !mac_matches(io, WAN, wan_mac)
        || !inbound.path.ingress_matches(io)
        || !outbound.path.ingress_matches(io)
    {
        return PrepareOutcome::Failed(PairOutcome::Rejected(tables, Error::Preconditions));
    }
    let [wan_table, lan_table] = tables;
    let wan = match unsafe {
        start_table(
            io,
            wan_table,
            timeout,
            Some(inbound),
            false,
            Engine::Ppe0,
            None,
        )
    } {
        StartOutcome::Active(s) => PausedSession(s),
        StartOutcome::Failed(Outcome::Rejected(t, e)) => {
            return PrepareOutcome::Failed(PairOutcome::Rejected([t, lan_table], e))
        }
        StartOutcome::Failed(outcome) => {
            let (t, e) = failed_table(outcome);
            return PrepareOutcome::Failed(PairOutcome::Quarantined(fail(io, [t, lan_table], e)));
        }
    };
    match unsafe {
        start_table(
            io,
            lan_table,
            timeout,
            Some(outbound),
            false,
            Engine::Ppe1,
            Some(&wan),
        )
    } {
        StartOutcome::Active(lan) => {
            let internal = matches!(lan.path, FlowPath::MxlToWan(mac)
                if io.read(0x500) == super::INTERNAL_CPU && mac_matches(io, 0x500, mac));
            PrepareOutcome::Paused(PausedPair(Pair { wan: wan.0, lan, wan_mac, internal }))
        }
        StartOutcome::Failed(outcome) => {
            let (t, e) = failed_table(outcome);
            PrepareOutcome::Failed(PairOutcome::Quarantined(fail(io, [wan.0.table, t], e)))
        }
    }
}
impl PausedPair {
    /// Whether the built-in switch's GDMA is admitted with the MxL ingress.
    pub fn internal_joined(&self) -> bool { self.0.internal }
    pub fn initial_ticket(&self, direction: Direction) -> Option<RuleTicket> {
        match direction {
            Direction::Inbound => self.0.wan.initial_ticket(),
            Direction::Outbound => self.0.lan.initial_ticket(),
        }
    }
    /// # Safety
    /// Revalidate all retained authorities and arm the independent dual cutoff.
    /// Serialize both admission writes with asynchronous cutoff and recheck the
    /// deadline inside that same critical section; never reopen an expired lease.
    /// Both tables remain owned across either partial admission failure.
    pub unsafe fn resume(self, io: &mut impl Registers) -> ResumeOutcome {
        if !self.0.valid(io, false) {
            return ResumeOutcome::Failed(fail(io, self.0.tables(), Error::Preconditions));
        }
        let result = write_checked(io, WAN, 0x20713000)
            .and_then(|_| write_checked(io, 0x540, 0x20714000))
            .and_then(|_| if self.0.internal { write_checked(io, 0x500, super::INTERNAL_ADMIT) } else { Ok(()) })
            .and_then(|_| {
                if self.0.valid(io, true) {
                    Ok(())
                } else {
                    Err(Error::Preconditions)
                }
            });
        match result {
            Ok(()) => ResumeOutcome::Active(ActivePair(self.0)),
            Err(e) => ResumeOutcome::Failed(fail(io, self.0.tables(), e)),
        }
    }
    fn edit<R: Registers, T>(
        self,
        io: &mut R,
        direction: Direction,
        operation: impl FnOnce(PausedSession, &mut R) -> EditOutcome<T>,
    ) -> PairEditOutcome<T> {
        if !self.0.valid(io, false) {
            return PairEditOutcome::Failed(fail(io, self.0.tables(), Error::Preconditions));
        }
        let Pair { wan, lan, wan_mac, internal } = self.0;
        let (selected, peer) = match direction {
            Direction::Inbound => (wan, lan),
            Direction::Outbound => (lan, wan),
        };
        let assemble = |selected: Session, peer: Session| match direction {
            Direction::Inbound => Pair {
                wan: selected,
                lan: peer,
                wan_mac,
                internal,
            },
            Direction::Outbound => Pair {
                wan: peer,
                lan: selected,
                wan_mac,
                internal,
            },
        };
        match operation(PausedSession(selected), io) {
            EditOutcome::Updated(s, value) => {
                PairEditOutcome::Updated(PausedPair(assemble(s.0, peer)), value)
            }
            EditOutcome::Rejected(s, error) => {
                PairEditOutcome::Rejected(PausedPair(assemble(s.0, peer)), error)
            }
            EditOutcome::Failed(outcome) => {
                let (t, e) = failed_table(outcome);
                let tables = match direction {
                    Direction::Inbound => [t, peer.table],
                    Direction::Outbound => [peer.table, t],
                };
                PairEditOutcome::Failed(fail(io, tables, e))
            }
        }
    }
    /// # Safety
    /// Preserve the pair contract; validate this new directional authority.
    pub unsafe fn insert_napt(
        self,
        io: &mut impl Registers,
        timeout: u64,
        direction: Direction,
        binding: &NaptBinding,
    ) -> PairEditOutcome<RuleTicket> {
        self.edit(io, direction, |s, io| unsafe {
            s.insert_napt(io, timeout, binding)
        })
    }
    /// Publish both directional rules while paused. Rejection of the second
    /// insertion rolls the first back before returning; no half-connection may
    /// become admitted. Existing peer rules retain their tickets and bytes.
    /// # Safety
    /// Preserve the pair contract and validate both new directional authorities.
    pub unsafe fn insert_connection(
        self, io: &mut impl Registers, timeout: u64,
        inbound: &NaptBinding, outbound: &NaptBinding,
    ) -> PairEditOutcome<[RuleTicket; 2]> {
        let (paused, first) = match unsafe { self.insert_napt(io,timeout,Direction::Inbound,inbound) } {
            PairEditOutcome::Updated(p,t)=>(p,t),
            PairEditOutcome::Rejected(p,e)=>return PairEditOutcome::Rejected(p,e),
            PairEditOutcome::Failed(q)=>return PairEditOutcome::Failed(q),
        };
        match unsafe {paused.insert_napt(io,timeout,Direction::Outbound,outbound)} {
            PairEditOutcome::Updated(p,t)=>PairEditOutcome::Updated(p,[first,t]),
            PairEditOutcome::Failed(q)=>PairEditOutcome::Failed(q),
            PairEditOutcome::Rejected(p,e)=>match unsafe {p.remove_napt(io,timeout,Direction::Inbound,first)} {
                PairEditOutcome::Updated(p,())=>PairEditOutcome::Rejected(p,e),
                PairEditOutcome::Failed(q)=>PairEditOutcome::Failed(q),
                PairEditOutcome::Rejected(p,_)=>PairEditOutcome::Failed(fail(io,p.0.tables(),Error::Preconditions)),
            },
        }
    }
    /// Publish both rules of a connection routed between two inside hosts:
    /// both enter through the MxL-ingress table. As for `insert_connection`,
    /// rejection of the second rolls the first back.
    /// # Safety
    /// Preserve the pair contract and validate both new directional authorities.
    pub unsafe fn insert_inside_connection(
        self, io: &mut impl Registers, timeout: u64,
        one: &NaptBinding, other: &NaptBinding,
    ) -> PairEditOutcome<[RuleTicket; 2]> {
        let (paused, first) = match unsafe { self.insert_napt(io,timeout,Direction::Outbound,one) } {
            PairEditOutcome::Updated(p,t)=>(p,t),
            PairEditOutcome::Rejected(p,e)=>return PairEditOutcome::Rejected(p,e),
            PairEditOutcome::Failed(q)=>return PairEditOutcome::Failed(q),
        };
        match unsafe {paused.insert_napt(io,timeout,Direction::Outbound,other)} {
            PairEditOutcome::Updated(p,t)=>PairEditOutcome::Updated(p,[first,t]),
            PairEditOutcome::Failed(q)=>PairEditOutcome::Failed(q),
            PairEditOutcome::Rejected(p,e)=>match unsafe {p.remove_napt(io,timeout,Direction::Outbound,first)} {
                PairEditOutcome::Updated(p,())=>PairEditOutcome::Rejected(p,e),
                PairEditOutcome::Failed(q)=>PairEditOutcome::Failed(q),
                PairEditOutcome::Rejected(p,_)=>PairEditOutcome::Failed(fail(io,p.0.tables(),Error::Preconditions)),
            },
        }
    }
    /// Reclaim both rules of one routed inside connection after pause/drain.
    /// # Safety
    /// As for `remove_connections`.
    pub unsafe fn remove_inside_connection(
        self, io: &mut impl Registers, timeout: u64, tickets: [RuleTicket;2],
    ) -> PairEditOutcome<()> {
        match unsafe {self.remove_napt(io,timeout,Direction::Outbound,tickets[0])} {
            PairEditOutcome::Updated(p,())=>match unsafe {p.remove_napt(io,timeout,Direction::Outbound,tickets[1])} {
                // Half a connection must not stay published.
                PairEditOutcome::Rejected(p,_)=>PairEditOutcome::Failed(fail(io,p.0.tables(),Error::Preconditions)),
                other=>other,
            },
            other=>other,
        }
    }
    /// Reclaim a bounded batch of complete connections after pause/drain.
    /// Both ticket lists are checked before either table changes. An edit failure
    /// closes both inputs and quarantines both allocations, even after one edit.
    /// # Safety
    /// Preserve the pair contract (exclusive tables, no cache), confirmed drain,
    /// and closed inputs throughout the edit.
    pub unsafe fn remove_connections(
        mut self, io: &mut impl Registers, timeout: u64, tickets: &[[RuleTicket;2]],
    ) -> PairEditOutcome<()> {
        if tickets.len()>MAX_RULES {return PairEditOutcome::Rejected(self,EditError::Capacity);}
        if tickets.is_empty() {return PairEditOutcome::Updated(self,());}
        let incoming=tickets.iter().map(|pair|pair[0]);let outgoing=tickets.iter().map(|pair|pair[1]);
        if let Err(error)=removal_check(&mut self.0.wan,incoming.clone()).and_then(|_|removal_check(&mut self.0.lan,outgoing.clone())) {
            return PairEditOutcome::Rejected(self,error);
        }
        let paused=match self.edit(io,Direction::Inbound,|s,io|unsafe {s.remove_many(io,timeout,incoming)}) {
            PairEditOutcome::Updated(p,())=>p,
            other=>return other,
        };
        paused.edit(io,Direction::Outbound,|s,io|unsafe {s.remove_many(io,timeout,outgoing)})
    }
    /// # Safety
    /// Preserve the pair contract and keep both ingresses closed through edit.
    pub unsafe fn remove_napt(
        self,
        io: &mut impl Registers,
        timeout: u64,
        direction: Direction,
        ticket: RuleTicket,
    ) -> PairEditOutcome<()> {
        self.edit(io, direction, |s, io| unsafe {
            s.remove_napt(io, timeout, ticket)
        })
    }
    /// # Safety
    /// Retain exclusive ownership until both engines are detached/restored.
    /// On any failure neither allocation is returned, even if one detached.
    pub unsafe fn stop(self, io: &mut impl Registers, timeout: u64) -> PairOutcome {
        if !self.0.valid(io, false) {
            return PairOutcome::Quarantined(fail(io, self.0.tables(), Error::Preconditions));
        }
        let Pair { wan, lan, .. } = self.0;
        let wan = match unsafe { wan.stop(io, timeout) } {
            Outcome::Restored(t) => t,
            outcome => {
                let (t, e) = failed_table(outcome);
                return PairOutcome::Quarantined(fail(io, [t, lan.table], e));
            }
        };
        match unsafe { lan.stop(io, timeout) } {
            Outcome::Restored(t) => PairOutcome::Restored([wan, t]),
            outcome => {
                let (t, e) = failed_table(outcome);
                PairOutcome::Quarantined(fail(io, [wan, t], e))
            }
        }
    }
}
impl ActivePair {
    /// Read-only verification of both admitted engines and their isolation.
    pub fn admitted(&self, io: &mut impl Registers) -> bool { self.0.valid(io, true) }

    /// Close both inputs before waiting on either engine. BUSY/timeout never
    /// implies storage can be returned. Success retains both published tables.
    /// # Safety
    /// Preserve exclusive pair ownership; asynchronous cutoff may only close.
    pub unsafe fn pause(self, io: &mut impl Registers, timeout: u64) -> PairPauseOutcome {
        if let Err(first_failure) = unsafe { cutoff().close(io) } {
            let mut q = fail(io, self.0.tables(), Error::Preconditions);
            // Preserve the original failed close even if the final close retry
            // succeeds. Ownership remains quarantined in either case.
            q.cutoff_error = Some(first_failure);
            return PairPauseOutcome::Failed(q);
        }
        let result = (|| {
            if timeout == 0 || timeout >= 1 << 63 {
                return Err(Error::Preconditions);
            }
            idle_on(io, Engine::Ppe0, timeout)?;
            idle_on(io, Engine::Ppe1, timeout)?;
            if !self.0.valid(io, false) {
                return Err(Error::Preconditions);
            }
            Ok(())
        })();
        match result {
            Ok(()) => PairPauseOutcome::Paused(PausedPair(self.0)),
            Err(e) => PairPauseOutcome::Failed(fail(io, self.0.tables(), e)),
        }
    }
    /// # Safety
    /// Preserve the pause/stop contracts and independent cutoff until closure.
    pub unsafe fn stop(self, io: &mut impl Registers, timeout: u64) -> PairOutcome {
        match unsafe { self.pause(io, timeout) } {
            PairPauseOutcome::Paused(s) => unsafe { s.stop(io, timeout) },
            PairPauseOutcome::Failed(q) => PairOutcome::Quarantined(q),
        }
    }
    /// Diagnostic IB1 observations for two exact owned installations. Values
    /// can change immediately; they authorize neither mutation nor slot reuse.
    /// # Safety
    /// Retain the active pair's exclusive ownership and mapped DMA storage.
    pub unsafe fn retirement_words(&self, inbound: RuleTicket, outbound: RuleTicket) -> Option<[u32; 2]> {
        if self.0.wan.rules.get(inbound).is_none() || self.0.lan.rules.get(outbound).is_none() { return None; }
        Some([unsafe { self.0.wan.table.state_word(inbound.index)? },
              unsafe { self.0.lan.table.state_word(outbound.index)? }])
    }

    /// Retire both installations belonging to one connection before the owner
    /// changes its software state. Validate both tickets before touching either
    /// entry. Success changes only their IB1 state words, with a DMA barrier and
    /// readback; other flows remain admitted. This is not atomic DMA drainage:
    /// already-started lookups may finish, and neither key/slot is reusable.
    /// # Safety
    /// The owner must associate these exact directional tickets with the same
    /// authorized connection. Preserve all pair authorities and independent
    /// cutoff. Reuse requires pause/drain/removal, even after successful return.
    /// If either hardware state cannot be invalidated, both inputs close and
    /// both allocations remain quarantined; no partially-retired pair escapes.
    pub unsafe fn retire_connection(
        mut self,
        io: &mut impl Registers,
        inbound: RuleTicket,
        outbound: RuleTicket,
    ) -> PairRetireOutcome {
        let (Some(w), Some(l)) = (self.0.wan.rules.get(inbound).copied(), self.0.lan.rules.get(outbound).copied()) else {
            return PairRetireOutcome::Rejected(self, RetireError::Stale);
        };
        if w.retiring || l.retiring {
            return PairRetireOutcome::Rejected(self, RetireError::AlreadyPending);
        }
        if !self.0.valid(io, true) {
            return PairRetireOutcome::Failed(fail(io, self.0.tables(), Error::Preconditions));
        }
        let written = unsafe { self.0.wan.table.retire_napt_state(inbound.index, w.key.0) }
            && unsafe { self.0.lan.table.retire_napt_state(outbound.index, l.key.0) };
        io.barrier();
        if !written || !unsafe { self.0.wan.table.retired_state_visible(inbound.index) }
            || !unsafe { self.0.lan.table.retired_state_visible(outbound.index) }
            || !self.0.valid(io, true) {
            return PairRetireOutcome::Failed(fail(io, self.0.tables(), Error::Preconditions));
        }
        self.0.wan.rules.get_mut(inbound).expect("validated rule").retiring = true;
        self.0.lan.rules.get_mut(outbound).expect("validated rule").retiring = true;
        PairRetireOutcome::Pending(self)
    }

    /// Invalidate only one directional installation; no GDMA/PPE configuration
    /// writes, drain claim or slot reuse. The peer continues forwarding.
    /// # Safety
    /// Preserve all active-pair authorities and the independent cutoff. Reuse
    /// requires subsequent pause/drain and removal of this exact ticket.
    pub unsafe fn retire_napt(
        mut self,
        io: &mut impl Registers,
        direction: Direction,
        ticket: RuleTicket,
    ) -> PairRetireOutcome {
        let selected = match direction {
            Direction::Inbound => &self.0.wan,
            Direction::Outbound => &self.0.lan,
        };
        let Some(record) = selected.rules.get(ticket).copied() else {
            return PairRetireOutcome::Rejected(self, RetireError::Stale);
        };
        if record.retiring {
            return PairRetireOutcome::Rejected(self, RetireError::AlreadyPending);
        }
        if !self.0.valid(io, true) {
            return PairRetireOutcome::Failed(fail(io, self.0.tables(), Error::Preconditions));
        }
        let selected = match direction {
            Direction::Inbound => &mut self.0.wan,
            Direction::Outbound => &mut self.0.lan,
        };
        if !unsafe { selected.table.retire_napt_state(ticket.index, record.key.0) } {
            return PairRetireOutcome::Failed(fail(io, self.0.tables(), Error::Preconditions));
        }
        io.barrier();
        if !unsafe { selected.table.retired_state_visible(ticket.index) } || !self.0.valid(io, true) {
            return PairRetireOutcome::Failed(fail(io, self.0.tables(), Error::Preconditions));
        }
        let selected = match direction {
            Direction::Inbound => &mut self.0.wan,
            Direction::Outbound => &mut self.0.lan,
        };
        selected.rules.get_mut(ticket).expect("validated rule").retiring = true;
        PairRetireOutcome::Pending(self)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{boxed::Box, collections::BTreeMap, vec::Vec};
    const WAN_MAC: [u8; 6] = [2, 0x42, 0x70, 4, 0, 1];
    const LAN_MAC: [u8; 6] = [2, 0x42, 0x70, 4, 0, 2];
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Op {
        Read(usize),
        Write(usize, u32),
        Barrier,
    }
    struct Io {
        regs: BTreeMap<usize, u32>,
        ops: Vec<Op>,
        writes: usize,
        ignore: usize,
        busy: Option<Engine>,
        close_wan_on_lan_admit: bool,
        cutoff_on_edit_enable: Option<Engine>,
        cutoff_on_barrier: bool,
        clock: u64,
    }
    impl Io {
        fn new() -> Self {
            let mut regs = BTreeMap::new();
            for e in Engine::ALL {
                regs.insert(ppe_reg(e, GLOBAL), 0x6000020d);
                regs.insert(ppe_reg(e, 0x2204), 0xe);
                regs.insert(ppe_reg(e, TABLE_CONFIG), 0x16f000);
                for r in AUX {
                    regs.insert(ppe_reg(e, r), 0x51515151);
                }
            }
            for (r, v) in [
                (WAN, 0x20710000),
                (0x540, 0x20710000),
                (0x500, 0x20717777),
                (0x1508, 0x70040001),
                (0x150c, 0x0242),
                (0x548, 0x70040002),
                (0x54c, 0x0242),
            ] {
                regs.insert(r, v);
            }
            Self {
                regs,
                ops: Vec::new(),
                writes: 0,
                ignore: usize::MAX,
                busy: None,
                close_wan_on_lan_admit: false,
                cutoff_on_edit_enable: None,
                cutoff_on_barrier: false,
                clock: 0,
            }
        }
        fn closed(&self) {
            assert_eq!(self.regs[&WAN], 0x20710000);
            assert_eq!(self.regs[&0x540], 0x20710000);
        }
    }
    impl Registers for Io {
        fn read(&mut self, r: usize) -> u32 {
            self.ops.push(Op::Read(r));
            let v = *self.regs.get(&r).unwrap_or(&0);
            if self.busy.is_some_and(|e| r == ppe_reg(e, GLOBAL)) {
                v | BUSY
            } else {
                v
            }
        }
        fn write(&mut self, r: usize, v: u32) {
            assert!(configuration_register(r));
            self.writes += 1;
            self.ops.push(Op::Write(r, v));
            if self.writes != self.ignore {
                self.regs.insert(r, v);
            }
            if self
                .cutoff_on_edit_enable
                .is_some_and(|e| r == ppe_reg(e, GLOBAL))
                && v & ENABLE != 0
            {
                self.regs.insert(WAN, 0x20710000);
                self.regs.insert(0x540, 0x20710000);
            }
            if self.close_wan_on_lan_admit && r == 0x540 && v == 0x20714000 {
                self.regs.insert(WAN, 0x20710000);
            }
        }
        fn barrier(&mut self) {
            self.ops.push(Op::Barrier);
            if self.cutoff_on_barrier {
                self.regs.insert(WAN, 0x20710000);
                self.regs.insert(0x540, 0x20710000);
            }
        }
        fn now(&mut self) -> u64 {
            let n = self.clock;
            self.clock = n.wrapping_add(1);
            n
        }
    }
    fn tables(alias: bool) -> [CpuTable<'static>; 2] {
        tables_with_second(if alias { 0x40c00000 } else { 0x41000000 })
    }
    fn tables_with_second(second: u64) -> [CpuTable<'static>; 2] {
        [0x40c00000, second].map(|base| {
            CpuTable::new(
                Box::leak(std::vec![0; super::super::super::table::TABLE_BYTES].into_boxed_slice()),
                base,
            )
            .unwrap()
        })
    }
    fn bindings() -> [NaptBinding; 2] { bindings_offset(0) }
    fn bindings_offset(offset:u16) -> [NaptBinding; 2] {
        let out = Tuple {
            source: [192, 168, 79, 100],
            destination: [192, 168, 78, 100],
            source_port: 24567+offset,
            destination_port: 33445,
        };
        let incoming = Tuple {
            source: out.destination,
            destination: [192, 168, 78, 1],
            source_port: out.destination_port,
            destination_port: 49152+offset,
        };
        [
            NaptBinding::wan_to_mxl_lan(
                incoming,
                Tuple {
                    destination: out.source,
                    destination_port: out.source_port,
                    ..incoming
                },
                LAN_MAC,
                [2, 0, 0, 0, 0, 4],
            )
            .unwrap(),
            NaptBinding::mxl_lan_to_wan(
                out,
                Tuple {
                    source: incoming.destination,
                    source_port: incoming.destination_port,
                    ..out
                },
                LAN_MAC,
                WAN_MAC,
                [2, 0, 0, 0, 0, 3],
            )
            .unwrap(),
        ]
    }
    fn prepared(io: &mut Io) -> PausedPair {
        let b = bindings();
        let PrepareOutcome::Paused(p) =
            (unsafe { prepare(io, tables(false), 10, &b[0], &b[1], WAN_MAC) })
        else {
            panic!("prepare")
        };
        p
    }
    fn active(io: &mut Io) -> ActivePair {
        let ResumeOutcome::Active(a) = (unsafe { prepared(io).resume(io) }) else {
            panic!("resume")
        };
        a
    }
    fn three_connections(io:&mut Io)->(PausedPair,[[RuleTicket;2];3]) {
        let mut p=prepared(io);
        let first=[p.initial_ticket(Direction::Inbound).unwrap(),p.initial_ticket(Direction::Outbound).unwrap()];
        let mut tickets=[first;3];
        for offset in 1..3 {
            let b=bindings_offset(offset);
            let PairEditOutcome::Updated(next,t)=(unsafe {p.insert_connection(io,10,&b[0],&b[1])}) else {panic!("insert");};
            p=next;tickets[offset as usize]=t;
        }
        (p,tickets)
    }
    #[test]
    fn batch_removal_preserves_peer_bytes_and_uses_one_edit_per_engine() {
        let mut io=Io::new();let (p,t)=three_connections(&mut io);
        let peer=[p.0.wan.table.entry(t[1][0].index()).unwrap().to_vec(),p.0.lan.table.entry(t[1][1].index()).unwrap().to_vec()];
        let writes=io.writes;
        let PairEditOutcome::Updated(p,())=(unsafe {p.remove_connections(&mut io,10,&[t[0],t[2]])}) else {panic!("batch");};
        assert_eq!(io.writes-writes,4);io.closed();
        for (side,session) in [&p.0.wan,&p.0.lan].into_iter().enumerate() {
            assert_eq!(session.table.nonzero_entries(),1);
            assert_eq!(session.table.entry(t[1][side].index()).unwrap(),peer[side]);
            for n in [0,2] {assert!(session.table.entry(t[n][side].index()).unwrap().iter().all(|b|*b==0));}
        }
        let ResumeOutcome::Active(a)=(unsafe {p.resume(&mut io)}) else {panic!("resume peer");};
        assert!(a.admitted(&mut io));assert!(matches!(unsafe {a.stop(&mut io,10)},PairOutcome::Restored(_)));
    }
    #[test]
    fn batch_rejects_duplicate_and_stale_second_direction_before_mutation() {
        let mut io=Io::new();let (mut p,t)=three_connections(&mut io);
        for bad in [std::vec![t[0],t[0]],std::vec![t[0],[t[2][0],t[2][0]]],std::vec![t[0];MAX_RULES+1]] {
            let before=[p.0.wan.table.bytes_for_test().to_vec(),p.0.lan.table.bytes_for_test().to_vec()];let writes=io.writes;
            let PairEditOutcome::Rejected(next,_)=(unsafe {p.remove_connections(&mut io,10,&bad)}) else {panic!("reject");};p=next;
            assert_eq!(io.writes,writes);assert_eq!(p.0.wan.table.bytes_for_test(),before[0]);assert_eq!(p.0.lan.table.bytes_for_test(),before[1]);
        }
        let PairEditOutcome::Updated(p,())=(unsafe {p.remove_connections(&mut io,10,&[])}) else {panic!("empty");};
        assert!(matches!(unsafe {p.stop(&mut io,10)},PairOutcome::Restored(_)));
    }
    #[test]
    fn each_batch_edit_write_failure_quarantines_both_tables() {
        for failed in 1..=4 {
            let mut io=Io::new();let (p,t)=three_connections(&mut io);io.ignore=io.writes+failed;
            let PairEditOutcome::Failed(q)=(unsafe {p.remove_connections(&mut io,10,&[t[0],t[2]])}) else {panic!("write {failed}");};
            io.closed();assert_eq!(q._tables.len(),2);assert!(matches!(q.error,Error::Readback {..}));
        }
    }
    #[test]
    fn paired_insert_rolls_back_first_direction_when_second_rejects() {
        let mut io=Io::new();let p=prepared(&mut io);
        let before=[p.0.wan.table.bytes_for_test().to_vec(),p.0.lan.table.bytes_for_test().to_vec()];
        let old=[p.initial_ticket(Direction::Inbound).unwrap(),p.initial_ticket(Direction::Outbound).unwrap()];
        let tcp=bindings().map(|b|b.with_protocol(Protocol::Tcp));let udp=bindings();
        let PairEditOutcome::Rejected(p,EditError::Duplicate)=(unsafe {p.insert_connection(&mut io,10,&tcp[0],&udp[1])}) else {panic!("second duplicate");};
        io.closed();
        assert_eq!(p.0.wan.table.bytes_for_test(),before[0]);assert_eq!(p.0.lan.table.bytes_for_test(),before[1]);
        assert_eq!(p.initial_ticket(Direction::Inbound),Some(old[0]));assert_eq!(p.initial_ticket(Direction::Outbound),Some(old[1]));
        let PairEditOutcome::Updated(p,tickets)=(unsafe {p.insert_connection(&mut io,10,&tcp[0],&tcp[1])}) else {panic!("pair");};
        assert_ne!(tickets[0],tickets[1]);
        assert_eq!(p.0.wan.table.nonzero_entries(),2);assert_eq!(p.0.lan.table.nonzero_entries(),2);
        let ResumeOutcome::Active(a)=(unsafe {p.resume(&mut io)}) else {panic!("resume");};
        assert!(a.admitted(&mut io));
        assert!(matches!(unsafe {a.stop(&mut io,10)},PairOutcome::Restored(_)));
    }
    #[test]
    fn admission_snapshot_rejects_either_closed_input_or_changed_engine_without_writes() {
        let mut io=Io::new(); let a=active(&mut io); let writes=io.writes;
        assert!(a.admitted(&mut io));
        for (reg,bad) in [(WAN,0x20710000),(0x540,0x20710000),(0x1508,0),
            (0x548,0),(0x500,0), (ppe_reg(Engine::Ppe0,TABLE_BASE),0),
            (ppe_reg(Engine::Ppe1,TABLE_BASE),0),(ppe_reg(Engine::Ppe1,GLOBAL),0),
            (ppe_reg(Engine::Ppe2,TABLE_BASE),0x41400000)] {
            let old=io.regs.insert(reg,bad);
            assert!(!a.admitted(&mut io), "register {reg:x}");
            if let Some(old)=old {io.regs.insert(reg,old);} else {io.regs.remove(&reg);}
            assert!(a.admitted(&mut io));
        }
        // The built-in switch may be closed or software-only, never PPE-fed.
        for (value,ok) in [(0xc0700000,true),(0xc0703333,false),(0x20710000,false),(0x20717777,true)] {
            io.regs.insert(0x500,value);
            assert_eq!(a.admitted(&mut io),ok,"{value:x}");
        }
        assert_eq!(io.writes,writes);
        assert!(matches!(unsafe {a.stop(&mut io,10)},PairOutcome::Restored(_)));
    }
    #[test]
    fn connection_retirement_keeps_same_tuple_udp_peers_and_rejects_stale_pair() {
        let mut io = Io::new();
        let b = bindings().map(|b| b.with_protocol(Protocol::Tcp));
        let PrepareOutcome::Paused(p) = (unsafe { prepare(&mut io, tables(false), 10, &b[0], &b[1], WAN_MAC) }) else { panic!("prepare") };
        let incoming = p.initial_ticket(Direction::Inbound).unwrap();
        let outgoing = p.initial_ticket(Direction::Outbound).unwrap();
        let udp = bindings();
        let PairEditOutcome::Updated(p, up_in) = (unsafe { p.insert_napt(&mut io, 10, Direction::Inbound, &udp[0]) }) else { panic!("peer") };
        let PairEditOutcome::Updated(p, up_out) = (unsafe { p.insert_napt(&mut io, 10, Direction::Outbound, &udp[1]) }) else { panic!("peer") };
        let ResumeOutcome::Active(a) = (unsafe { p.resume(&mut io) }) else { panic!("resume") };
        let before = [a.0.wan.table.bytes_for_test().to_vec(), a.0.lan.table.bytes_for_test().to_vec()];
        let writes = io.writes;
        let PairRetireOutcome::Rejected(a, RetireError::Stale) = (unsafe { a.retire_connection(&mut io, incoming, incoming) }) else { panic!("wrong second direction") };
        assert_eq!(a.0.wan.table.bytes_for_test(), before[0]);
        assert_eq!(a.0.lan.table.bytes_for_test(), before[1]);
        io.busy = Some(Engine::Ppe1);
        io.ops.clear();
        let clock = io.clock;
        let PairRetireOutcome::Pending(a) = (unsafe { a.retire_connection(&mut io, incoming, outgoing) }) else { panic!("retire") };
        assert_eq!(io.writes, writes);
        assert_eq!(io.clock, clock);
        assert!(io.ops.contains(&Op::Barrier));
        assert_eq!(io.regs[&WAN], 0x20713000);
        assert_eq!(io.regs[&0x540], 0x20714000);
        for (side, (session, ticket, peer)) in [(&a.0.wan, incoming, up_in), (&a.0.lan, outgoing, up_out)].into_iter().enumerate() {
            let mut expected = before[side].clone();
            expected[ticket.index() * super::super::super::ENTRY_BYTES + 3] &= !0x30;
            assert_eq!(session.table.bytes_for_test(), expected);
            assert!(session.retirement_pending(ticket));
            assert!(!session.retirement_pending(peer));
        }
        let PairRetireOutcome::Rejected(a, RetireError::AlreadyPending) = (unsafe { a.retire_connection(&mut io, incoming, outgoing) }) else { panic!("duplicate") };
        io.busy = None;
        assert!(matches!(unsafe { a.stop(&mut io, 10) }, PairOutcome::Restored(_)));
    }

    #[test]
    fn connection_retirement_failure_never_returns_half_retired_active_pair() {
        for failure in 0..3 {
            let mut io = Io::new();
            let p = prepared(&mut io);
            let incoming = p.initial_ticket(Direction::Inbound).unwrap();
            let outgoing = p.initial_ticket(Direction::Outbound).unwrap();
            let ResumeOutcome::Active(mut a) = (unsafe { p.resume(&mut io) }) else { panic!("resume") };
            if failure < 2 {
                // Model a table whose hardware-visible state unexpectedly lost
                // BIND. No DMA exists in this mock; staging is deliberate fault injection.
                let b = bindings();
                let (s, t) = if failure == 0 { (&mut a.0.wan, incoming) } else { (&mut a.0.lan, outgoing) };
                s.table.stage(t.index(), &b[failure].entry).unwrap();
            } else { io.cutoff_on_barrier = true; }
            let PairRetireOutcome::Failed(q) = (unsafe { a.retire_connection(&mut io, incoming, outgoing) }) else { panic!("quarantine") };
            io.closed();
            assert_eq!(q.error, Error::Preconditions);
            assert!(q._tables.iter().all(|t| !t.has_zero_proof() && t.nonzero_entries() == 1));
        }
    }

    #[test]
    fn directional_retirement_observes_cutoff_at_visibility_barrier() {
        let mut io = Io::new();
        let p = prepared(&mut io);
        let ticket = p.initial_ticket(Direction::Inbound).unwrap();
        let ResumeOutcome::Active(a) = (unsafe { p.resume(&mut io) }) else { panic!("resume") };
        io.cutoff_on_barrier = true;
        assert!(matches!(unsafe { a.retire_napt(&mut io, Direction::Inbound, ticket) }, PairRetireOutcome::Failed(_)));
        io.closed();
    }

    #[test]
    fn pair_lifecycle_keeps_directional_tables_and_retires_without_global_pause() {
        let mut io = Io::new();
        let original = io.regs.clone();
        let p = prepared(&mut io);
        io.closed();
        let incoming = p.initial_ticket(Direction::Inbound).unwrap();
        let outgoing = p.initial_ticket(Direction::Outbound).unwrap();
        let peer_bytes = p.0.wan.table.entry(incoming.index()).unwrap().to_vec();
        assert_eq!(io.regs[&0x2220], 0x40c00000);
        assert_eq!(io.regs[&0x2620], 0x41000000);
        let ResumeOutcome::Active(a) = (unsafe { p.resume(&mut io) }) else {
            panic!("resume")
        };
        assert_eq!(io.regs[&WAN], 0x20713000);
        assert_eq!(io.regs[&0x540], 0x20714000);
        let writes = io.writes;
        let PairRetireOutcome::Rejected(a, RetireError::Stale) =
            (unsafe { a.retire_napt(&mut io, Direction::Inbound, outgoing) })
        else {
            panic!("wrong direction")
        };
        let PairRetireOutcome::Pending(a) =
            (unsafe { a.retire_napt(&mut io, Direction::Outbound, outgoing) })
        else {
            panic!("retire")
        };
        assert_eq!(io.writes, writes);
        // Mock has no DMA reader/writer: verify only the selected IB1 changed.
        assert_eq!(
            a.0.wan.table.entry(incoming.index()).unwrap(),
            peer_bytes.as_slice()
        );
        assert!(a.0.lan.retirement_pending(outgoing));
        let PairPauseOutcome::Paused(p) = (unsafe { a.pause(&mut io, 10) }) else {
            panic!("pause")
        };
        io.closed();
        let PairEditOutcome::Updated(p, ()) =
            (unsafe { p.remove_napt(&mut io, 10, Direction::Outbound, outgoing) })
        else {
            panic!("remove")
        };
        let PairEditOutcome::Updated(p, successor) =
            (unsafe { p.insert_napt(&mut io, 10, Direction::Outbound, &bindings()[1]) })
        else {
            panic!("insert")
        };
        assert_ne!(outgoing, successor);
        let ResumeOutcome::Active(a) = (unsafe { p.resume(&mut io) }) else {
            panic!("resume 2")
        };
        let PairRetireOutcome::Rejected(a, RetireError::Stale) =
            (unsafe { a.retire_napt(&mut io, Direction::Outbound, outgoing) })
        else {
            panic!("stale")
        };
        let PairOutcome::Restored(t) = (unsafe { a.stop(&mut io, 10) }) else {
            panic!("stop")
        };
        assert!(t.iter().all(CpuTable::is_zero));
        for (r, v) in &io.regs {
            assert_eq!(*v, *original.get(r).unwrap_or(&0), "register {r:#x}");
        }
    }
    #[test]
    fn aliases_foreign_tables_and_wrong_macs_reject_before_writes() {
        for case in 0..6 {
            let mut io = Io::new();
            let b = bindings();
            if case == 1 {
                io.regs.insert(0x2e20, 0x44000000);
            }
            if case == 2 {
                io.regs.insert(0x1508, 0x70040099);
            }
            let (incoming, outgoing) = if case == 3 {
                (&b[1], &b[0])
            } else {
                (&b[0], &b[1])
            };
            if case == 4 {
                io.regs.insert(0x2620, 0x41000000);
            }
            if case == 5 {
                io.regs.insert(0x548, 0x70040099);
            }
            assert!(matches!(
                unsafe { prepare(&mut io, tables(case == 0), 10, incoming, outgoing, WAN_MAC,) },
                PrepareOutcome::Failed(PairOutcome::Rejected(_, Error::Preconditions))
            ));
            assert_eq!(io.writes, 0);
        }
    }
    #[test]
    fn every_prepare_write_failure_closes_both_and_retains_both_allocations() {
        let mut reference = Io::new();
        let _ = prepared(&mut reference);
        let count = reference.writes;
        for failed in 1..=count {
            let mut io = Io::new();
            io.ignore = failed;
            let b = bindings();
            let PrepareOutcome::Failed(PairOutcome::Quarantined(q)) =
                (unsafe { prepare(&mut io, tables(false), 10, &b[0], &b[1], WAN_MAC) })
            else {
                panic!("write {failed}")
            };
            assert!(matches!(q.error, Error::Readback { .. }));
            assert!(q.cutoff_error.is_none());
            io.closed();
            assert_eq!(q._tables[0].region().base(), 0x40c00000);
            assert_eq!(q._tables[1].region().base(), 0x41000000);
        }
    }
    #[test]
    fn routed_inside_connection_lives_in_the_mxl_table_beside_translated_ones() {
        let mut io = Io::new();
        let p = prepared(&mut io);
        let tuple = Tuple { source: [192,168,79,100], destination: [192,168,20,50], source_port: 40000, destination_port: 53000 };
        let back = Tuple { source: tuple.destination, destination: tuple.source, source_port: tuple.destination_port, destination_port: tuple.source_port };
        let rules = [
            NaptBinding::mxl_lan_to_inside(tuple, LAN_MAC, LAN_MAC, [2,0,0,0,0,9]).unwrap().with_builtin_port(0).unwrap(),
            NaptBinding::mxl_lan_to_inside(back, LAN_MAC, LAN_MAC, [2,0,0,0,0,8]).unwrap().with_mxl_alias(0).unwrap(),
        ];
        let PairEditOutcome::Updated(p, tickets) = (unsafe { p.insert_inside_connection(&mut io, 10, &rules[0], &rules[1]) }) else { panic!("insert") };
        assert_ne!(tickets[0], tickets[1]);
        assert_eq!((p.0.wan.table.nonzero_entries(), p.0.lan.table.nonzero_entries()), (1, 3));
        // The same tuple twice is refused whole, leaving nothing behind.
        let PairEditOutcome::Rejected(p, _) = (unsafe { p.insert_inside_connection(&mut io, 10, &rules[1], &rules[0]) }) else { panic!("duplicate") };
        assert_eq!(p.0.lan.table.nonzero_entries(), 3);
        let ResumeOutcome::Active(a) = (unsafe { p.resume(&mut io) }) else { panic!("resume") };
        assert!(a.admitted(&mut io));
        let PairPauseOutcome::Paused(p) = (unsafe { a.pause(&mut io, 10) }) else { panic!("pause") };
        let PairEditOutcome::Updated(p, ()) = (unsafe { p.remove_inside_connection(&mut io, 10, tickets) }) else { panic!("remove") };
        assert_eq!((p.0.wan.table.nonzero_entries(), p.0.lan.table.nonzero_entries()), (1, 1));
        // Stale tickets are refused before anything changes.
        let PairEditOutcome::Rejected(p, _) = (unsafe { p.remove_inside_connection(&mut io, 10, tickets) }) else { panic!("stale") };
        assert!(matches!(unsafe { p.stop(&mut io, 10) }, PairOutcome::Restored(_)));
    }
    #[test]
    fn builtin_switch_joins_the_mxl_ingress_only_with_its_address_and_follows_admission() {
        // Open to software without the MxL ingress address: left alone.
        let mut io = Io::new();
        io.regs.insert(0x500, 0xc0700000);
        let p = prepared(&mut io);
        assert!(!p.internal_joined());
        let ResumeOutcome::Active(a) = (unsafe { p.resume(&mut io) }) else { panic!("resume") };
        assert!(a.admitted(&mut io));
        assert_eq!(io.regs[&0x500], 0xc0700000);
        assert!(!io.ops.iter().any(|op| matches!(op, Op::Write(0x500, _))));
        assert!(matches!(unsafe { a.stop(&mut io, 10) }, PairOutcome::Restored(_)));
        // With it: admitted to PPE1 beside the MxL, closed with it, and any
        // other value while the pair lives is a lost precondition.
        let mut io = Io::new();
        for (r, v) in [(0x500, 0xc0700000), (0x508, 0x70040002), (0x50c, 0x0242)] { io.regs.insert(r, v); }
        let p = prepared(&mut io);
        assert!(p.internal_joined());
        assert_eq!(io.regs[&0x500], 0xc0700000);
        let ResumeOutcome::Active(a) = (unsafe { p.resume(&mut io) }) else { panic!("resume") };
        assert_eq!((io.regs[&0x500], io.regs[&0x540], io.regs[&WAN]), (0xc1704000, 0x20714000, 0x20713000));
        assert!(a.admitted(&mut io));
        for bad in [0xc0700000, 0x20717777, 0xc0703000] {
            io.regs.insert(0x500, bad);
            assert!(!a.admitted(&mut io), "{bad:x}");
        }
        io.regs.insert(0x500, 0xc1704000);
        let PairPauseOutcome::Paused(p) = (unsafe { a.pause(&mut io, 10) }) else { panic!("pause") };
        assert_eq!((io.regs[&0x500], io.regs[&0x540], io.regs[&WAN]), (0xc0700000, 0x20710000, 0x20710000));
        let ResumeOutcome::Active(a) = (unsafe { p.resume(&mut io) }) else { panic!("resume again") };
        assert_eq!(io.regs[&0x500], 0xc1704000);
        assert!(matches!(unsafe { a.stop(&mut io, 10) }, PairOutcome::Restored(_)));
        assert_eq!(io.regs[&0x500], 0xc0700000);
        // A changed address after preparation is a lost precondition too.
        let p = prepared(&mut io);
        io.regs.insert(0x508, 0);
        assert!(matches!(unsafe { p.resume(&mut io) }, ResumeOutcome::Failed(_)));
    }
    #[test]
    fn partial_resume_failure_closes_both_before_readbacks() {
        for failed in [1, 2] {
            let mut io = Io::new();
            let p = prepared(&mut io);
            io.ignore = io.writes + failed;
            let ResumeOutcome::Failed(q) = (unsafe { p.resume(&mut io) }) else {
                panic!("admit {failed}")
            };
            io.closed();
            assert!(q.cutoff_error.is_none());
            assert_eq!(
                &io.ops[io.ops.len() - 6..],
                &[
                    Op::Write(WAN, 0x20710000),
                    Op::Write(0x540, 0x20710000),
                    Op::Read(0x500),
                    Op::Barrier,
                    Op::Read(WAN),
                    Op::Read(0x540)
                ]
            );
            assert_eq!(io.regs[&0x2220], 0x40c00000);
            assert_eq!(io.regs[&0x2620], 0x41000000);
        }
    }
    #[test]
    fn failed_second_detachment_never_returns_the_already_restored_first_table() {
        let mut reference = Io::new();
        let a = active(&mut reference);
        assert!(matches!(
            unsafe { a.stop(&mut reference, 10) },
            PairOutcome::Restored(_)
        ));
        let detach = reference
            .ops
            .iter()
            .filter(|o| matches!(o, Op::Write(..)))
            .position(|o| *o == Op::Write(0x2620, 0))
            .unwrap()
            + 1;
        let mut io = Io::new();
        let a = active(&mut io);
        io.ignore = detach;
        let PairOutcome::Quarantined(q) = (unsafe { a.stop(&mut io, 10) }) else {
            panic!("returned tables")
        };
        assert_eq!(q.error, Error::Readback { offset: 0x2620 });
        io.closed();
        assert_eq!(io.regs[&0x2220], 0);
        assert_eq!(io.regs[&0x2620], 0x41000000);
        assert!(q._tables[0].is_zero());
        assert_eq!(q._tables[1].nonzero_entries(), 1);
    }
    #[test]
    fn busy_peer_and_changed_mac_fail_closed_without_freeing_or_reusing_entries() {
        for busy in [false, true] {
            let mut io = Io::new();
            let a = active(&mut io);
            let ticket = a.0.lan.initial_ticket().unwrap();
            let begin = io.ops.len();
            let q = if busy {
                io.busy = Some(Engine::Ppe1);
                io.clock = u64::MAX - 2;
                let PairPauseOutcome::Failed(q) = (unsafe { a.pause(&mut io, 10) }) else {
                    panic!("busy")
                };
                q
            } else {
                io.regs.insert(0x1508, 0x70040099);
                let PairRetireOutcome::Failed(q) =
                    (unsafe { a.retire_napt(&mut io, Direction::Outbound, ticket) })
                else {
                    panic!("MAC")
                };
                q
            };
            io.closed();
            assert!(q._tables.iter().all(|t| t.nonzero_entries() == 1));
            assert!(!io.ops[begin..]
                .iter()
                .any(|o| matches!(o, Op::Write(0x2220, _) | Op::Write(0x2620, _))));
            assert!(io.ops.len() - begin < 100);
        }
    }
    #[test]
    fn inbound_retirement_and_edit_preserve_outbound_peer() {
        let mut io = Io::new();
        let p = prepared(&mut io);
        let ticket = p.initial_ticket(Direction::Inbound).unwrap();
        let other = p.initial_ticket(Direction::Outbound).unwrap();
        let peer = p.0.lan.table.entry(other.index()).unwrap().to_vec();
        let ResumeOutcome::Active(a) = (unsafe { p.resume(&mut io) }) else {
            panic!("resume")
        };
        let writes = io.writes;
        let PairRetireOutcome::Pending(a) =
            (unsafe { a.retire_napt(&mut io, Direction::Inbound, ticket) })
        else {
            panic!("retire")
        };
        assert_eq!(io.writes, writes);
        assert_eq!(a.0.lan.table.entry(other.index()).unwrap(), peer.as_slice());
        let PairPauseOutcome::Paused(p) = (unsafe { a.pause(&mut io, 10) }) else {
            panic!("pause")
        };
        let writes = io.writes;
        let PairEditOutcome::Rejected(p, EditError::Egress) =
            (unsafe { p.insert_napt(&mut io, 10, Direction::Inbound, &bindings()[1]) })
        else {
            panic!("direction")
        };
        assert_eq!(io.writes, writes);
        let PairEditOutcome::Updated(p, ()) =
            (unsafe { p.remove_napt(&mut io, 10, Direction::Inbound, ticket) })
        else {
            panic!("remove")
        };
        let PairEditOutcome::Updated(p, _) =
            (unsafe { p.insert_napt(&mut io, 10, Direction::Inbound, &bindings()[0]) })
        else {
            panic!("insert")
        };
        assert!(matches!(
            unsafe { p.stop(&mut io, 10) },
            PairOutcome::Restored(_)
        ));
    }
    #[test]
    fn either_cutoff_write_failure_still_attempts_peer_and_preserves_failure() {
        for failed in [1, 2] {
            let mut io = Io::new();
            let a = active(&mut io);
            io.ignore = io.writes + failed;
            let begin = io.ops.len();
            let PairPauseOutcome::Failed(q) = (unsafe { a.pause(&mut io, 10) }) else {
                panic!("cutoff")
            };
            assert_eq!(
                q.cutoff_error,
                Some(CutoffFailure {
                    wan: failed == 1,
                    mxl: failed == 2
                })
            );
            assert_eq!(
                &io.ops[begin..begin + 4],
                &[
                    Op::Write(WAN, 0x20710000),
                    Op::Write(0x540, 0x20710000),
                    Op::Read(0x500),
                    Op::Barrier
                ]
            );
            io.closed(); // Final close retry succeeded; ownership stays quarantined.
            assert!(q._tables.iter().all(|t| t.nonzero_entries() == 1));
        }
    }
    #[test]
    fn adjacent_non_overlapping_tables_are_supported() {
        let mut io = Io::new();
        let b = bindings();
        let PrepareOutcome::Paused(p) = (unsafe {
            prepare(
                &mut io,
                tables_with_second(0x40c00000 + super::super::super::table::TABLE_BYTES as u64),
                10,
                &b[0],
                &b[1],
                WAN_MAC,
            )
        }) else {
            panic!("adjacent")
        };
        assert_eq!(io.regs[&0x2620], 0x40c00000 + super::super::super::table::TABLE_BYTES as u32);
        let PairOutcome::Restored(t) = (unsafe { p.stop(&mut io, 10) }) else {
            panic!("restore")
        };
        assert_eq!(t[0].region().end(), u64::from(t[1].region().base()));
        assert!(t.iter().all(CpuTable::is_zero));
    }
    #[test]
    fn resume_rechecks_first_ingress_after_second_admission() {
        let mut io = Io::new();
        let p = prepared(&mut io);
        io.close_wan_on_lan_admit = true;
        let ResumeOutcome::Failed(q) = (unsafe { p.resume(&mut io) }) else {
            panic!("lost first admission")
        };
        assert_eq!(q.error, Error::Preconditions);
        io.closed();
        assert!(q._tables.iter().all(|t| t.nonzero_entries() == 1));
    }
    #[test]
    fn directional_edit_recycles_selected_slot_while_busy_peer_remains_admitted() {
        use directional::{DirectionalEditOutcome as E, DirectionalPauseOutcome as P};
        for protocol in [Protocol::Udp, Protocol::Tcp] {
        for direction in [Direction::Inbound, Direction::Outbound] {
            let mut io = Io::new();
            let b = bindings().map(|b| b.with_protocol(protocol));
            let PrepareOutcome::Paused(p) = (unsafe { prepare(&mut io, tables(false), 10, &b[0], &b[1], WAN_MAC) }) else { panic!("prepare") };
            let old = p.initial_ticket(direction).unwrap();
            let peer_direction = if direction == Direction::Inbound {
                Direction::Outbound
            } else {
                Direction::Inbound
            };
            let peer_ticket = p.initial_ticket(peer_direction).unwrap();
            let (
                selected_engine,
                peer_engine,
                selected_reg,
                peer_reg,
                peer_admission,
                binding_index,
            ) = match direction {
                Direction::Inbound => (Engine::Ppe0, Engine::Ppe1, WAN, 0x540, 0x20714000, 0),
                Direction::Outbound => (Engine::Ppe1, Engine::Ppe0, 0x540, WAN, 0x20713000, 1),
            };
            let peer_bytes = match direction {
                Direction::Inbound => p.0.lan.table.entry(peer_ticket.index()).unwrap().to_vec(),
                Direction::Outbound => p.0.wan.table.entry(peer_ticket.index()).unwrap().to_vec(),
            };
            let ResumeOutcome::Active(a) = (unsafe { p.resume(&mut io) }) else {
                panic!("resume")
            };
            let PairRetireOutcome::Pending(a) = (unsafe { a.retire_napt(&mut io, direction, old) })
            else {
                panic!("retire")
            };
            io.busy = Some(peer_engine);
            let start = io.ops.len();
            let P::Paused(p) = (unsafe { a.pause_direction(&mut io, 10, direction) }) else {
                panic!("pause selected")
            };
            assert_eq!(io.regs[&peer_reg], peer_admission);
            let writes = io.writes;
            let E::Rejected(p, EditError::Stale) =
                (unsafe { p.remove_napt(&mut io, 10, peer_ticket) })
            else {
                panic!("peer ticket")
            };
            assert_eq!(io.writes, writes);
            let E::Updated(p, ()) = (unsafe { p.remove_napt(&mut io, 10, old) }) else {
                panic!("remove")
            };
            let E::Updated(p, new) =
                (unsafe { p.insert_napt(&mut io, 10, &b[binding_index]) })
            else {
                panic!("insert")
            };
            assert_eq!(old.index(), new.index());
            assert_ne!(old, new);
            let writes = io.writes;
            let E::Rejected(p, EditError::Stale) = (unsafe { p.remove_napt(&mut io, 10, old) })
            else {
                panic!("stale successor")
            };
            assert_eq!(io.writes, writes);
            let peer = match direction {
                Direction::Inbound => &p.pair.lan,
                Direction::Outbound => &p.pair.wan,
            };
            assert_eq!(
                peer.table.entry(peer_ticket.index()).unwrap(),
                peer_bytes.as_slice()
            );
            let ResumeOutcome::Active(a) = (unsafe { p.resume(&mut io) }) else {
                panic!("resume selected")
            };
            for op in &io.ops[start..] {
                if let Op::Write(reg, _) = op {
                    assert!(
                        *reg == selected_reg || *reg == ppe_reg(selected_engine, GLOBAL),
                        "peer/config write: {op:?}"
                    );
                }
            }
            assert_eq!(io.regs[&peer_reg], peer_admission);
            io.busy = None;
            let PairOutcome::Restored(t) = (unsafe { a.stop(&mut io, 10) }) else {
                panic!("stop")
            };
            assert!(t.iter().all(CpuTable::is_zero));
        }
        }
    }
    #[test]
    fn directional_failures_close_both_and_never_return_storage() {
        use directional::{DirectionalEditOutcome as E, DirectionalPauseOutcome as P};
        // First admission close, selected disable, selected re-enable, resume.
        for direction in [Direction::Inbound, Direction::Outbound] {
            for step in 0..4 {
                let mut io = Io::new();
                let p = prepared(&mut io);
                let ticket = p.initial_ticket(direction).unwrap();
                let ResumeOutcome::Active(a) = (unsafe { p.resume(&mut io) }) else {
                    panic!("resume")
                };
                if step == 0 {
                    io.ignore = io.writes + 1;
                }
                let paused = unsafe { a.pause_direction(&mut io, 10, direction) };
                let q = match paused {
                    P::Failed(q) => {
                        assert_eq!(step, 0);
                        q
                    }
                    P::Paused(p) => {
                        if step == 1 || step == 2 {
                            io.ignore = io.writes + step;
                        }
                        match unsafe { p.remove_napt(&mut io, 10, ticket) } {
                            E::Failed(q) => {
                                assert!(step == 1 || step == 2);
                                q
                            }
                            E::Updated(p, ()) => {
                                assert_eq!(step, 3);
                                io.ignore = io.writes + 1;
                                let ResumeOutcome::Failed(q) = (unsafe { p.resume(&mut io) })
                                else {
                                    panic!("resume readback")
                                };
                                q
                            }
                            E::Rejected(_, _) => panic!("unexpected rejection"),
                        }
                    }
                };
                io.closed();
                assert_eq!(q._tables.len(), 2);
                assert_ne!(q._tables[0].region().base(), q._tables[1].region().base());
            }
        }
    }
    #[test]
    fn directional_busy_timeout_wrap_and_peer_cutoff_fail_closed() {
        use directional::DirectionalPauseOutcome as P;
        for direction in [Direction::Inbound, Direction::Outbound] {
            let mut io = Io::new();
            let a = active(&mut io);
            io.clock = u64::MAX - 3;
            io.busy = Some(if direction == Direction::Inbound {
                Engine::Ppe0
            } else {
                Engine::Ppe1
            });
            let P::Failed(q) = (unsafe { a.pause_direction(&mut io, 10, direction) }) else {
                panic!("busy")
            };
            assert_eq!(q.error, Error::Timeout);
            io.closed();
            let mut io = Io::new();
            let a = active(&mut io);
            let P::Paused(p) = (unsafe { a.pause_direction(&mut io, 10, direction) }) else {
                panic!("pause")
            };
            unsafe { cutoff().close(&mut io) }.unwrap();
            let ResumeOutcome::Failed(q) = (unsafe { p.resume(&mut io) }) else {
                panic!("expired peer")
            };
            assert_eq!(q.error, Error::Preconditions);
            io.closed();
            assert!(q._tables.iter().all(|t| t.nonzero_entries() == 1));
        }
    }

    #[test]
    fn directional_edit_rechecks_cutoff_before_returning_paused_owner() {
        use directional::{DirectionalEditOutcome as E, DirectionalPauseOutcome as P};
        for direction in [Direction::Inbound, Direction::Outbound] {
            let mut io = Io::new();
            let p = prepared(&mut io);
            let ticket = p.initial_ticket(direction).unwrap();
            let ResumeOutcome::Active(a) = (unsafe { p.resume(&mut io) }) else {
                panic!("resume")
            };
            let P::Paused(p) = (unsafe { a.pause_direction(&mut io, 10, direction) }) else {
                panic!("pause")
            };
            io.cutoff_on_edit_enable = Some(if direction == Direction::Inbound {
                Engine::Ppe0
            } else {
                Engine::Ppe1
            });
            let E::Failed(q) = (unsafe { p.remove_napt(&mut io, 10, ticket) }) else {
                panic!("cutoff during edit")
            };
            io.closed();
            assert_eq!(q.error, Error::Preconditions);
            let selected = if direction == Direction::Inbound {
                0
            } else {
                1
            };
            assert_eq!(q._tables[selected].nonzero_entries(), 0);
            assert_eq!(q._tables[1 - selected].nonzero_entries(), 1);
        }
    }
    #[test]
    fn directional_rejections_preserve_state_and_half_paused_stop_restores_both() {
        use directional::{DirectionalEditOutcome as E, DirectionalPauseOutcome as P};
        for direction in [Direction::Inbound, Direction::Outbound] {
            let mut io = Io::new();
            let a = active(&mut io);
            let P::Paused(p) = (unsafe { a.pause_direction(&mut io, 10, direction) }) else {
                panic!("pause")
            };
            let selected = if direction == Direction::Inbound {
                0
            } else {
                1
            };
            let b = bindings();
            let writes = io.writes;
            let E::Rejected(p, EditError::Egress) =
                (unsafe { p.insert_napt(&mut io, 10, &b[1 - selected]) })
            else {
                panic!("path")
            };
            let E::Rejected(p, EditError::Duplicate) =
                (unsafe { p.insert_napt(&mut io, 10, &b[selected]) })
            else {
                panic!("duplicate")
            };
            let [incoming, outgoing] = bindings();
            let different_mtu = if selected == 0 { incoming } else { outgoing }
                .with_mtu(1200)
                .unwrap();
            let E::Rejected(p, EditError::Mtu) =
                (unsafe { p.insert_napt(&mut io, 10, &different_mtu) })
            else {
                panic!("mtu")
            };
            assert_eq!(io.writes, writes);
            let PairOutcome::Restored(t) = (unsafe { p.stop(&mut io, 10) }) else {
                panic!("half paused stop")
            };
            io.closed();
            assert!(t.iter().all(CpuTable::is_zero));
        }
    }
}
