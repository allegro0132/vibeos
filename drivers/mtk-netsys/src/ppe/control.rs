//! Reversible PPE0 base-register probe, with the engine disabled throughout
//! publication. The empty-session interface also qualifies enabled miss-to-CPU
//! lookup with WAN-only ingress. A separate unsafe entry point permits one
//! authorized TCP/UDP diagnostic rule with mandatory caller-owned revocation.
//! Engine-selected diagnostics additionally qualify isolated PPE1 outbound use.
use super::{table::CpuTable, EncodeError, Engine, Protocol, Snapshot, StagedEntry, Tuple};
use core::{
    num::NonZeroU64,
    sync::atomic::{AtomicU64, Ordering},
};

pub mod duplex;
mod rules;
pub use rules::MAX_RULES;
use rules::{BatchError, RuleRecord, Rules};

const GLOBAL: usize = 0x2200;
const TABLE_CONFIG: usize = 0x221c;
const TABLE_BASE: usize = 0x2220;
const ENABLE: u32 = 1;
const BUSY: u32 = 1 << 31;
// Disable periodic aging, keepalive and scan work before waiting for idle.
const BACKGROUND: u32 = (0x1f << 7) | (3 << 12) | (3 << 16);

/// Writable FE-relative registers used by the reversible diagnostic sessions.
/// Shared with the physical backend and the mock so new writes cannot silently
/// escape the board's MMIO allowlist.
pub fn configuration_register(offset: usize) -> bool {
    let offset = if (0x2600..0x2800).contains(&offset) { offset - 0x400 } else { offset };
    matches!(
        offset,
        0x1500
            | 0x500
            | 0x540
            | 0x2200
            | 0x2204
            | 0x2208
            | 0x221c
            | 0x2220
            | 0x2248
            | 0x224c
            | 0x2308
            | 0x230c
            | 0x2310
            | 0x2374
    )
}

/// Minimal configuration-register backend. Offsets are FE-relative.
pub trait Registers {
    fn read(&mut self, offset: usize) -> u32;
    fn write(&mut self, offset: usize, value: u32);
    /// Full DMA-memory and device-register ordering/completion barrier.
    fn barrier(&mut self);
    /// Monotonic wrapping ticks; must advance while polling.
    fn now(&mut self) -> u64;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Preconditions,
    Readback { offset: usize },
    Timeout,
}

/// Fixed board ingress closure policy, independent of FOE/table ownership.
/// This only represents qualified CPU-return register values; it cannot open
/// admission, grant NAT permission or establish completion of prior DMA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IngressCutoff {
    wan: u32,
    mxl: Option<u32>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CutoffFailure {
    pub wan: bool,
    pub mxl: bool,
}
impl IngressCutoff {
    pub fn new(wan: u32, mxl: Option<u32>) -> Result<Self, Error> {
        // Exact policies qualified by this board port: every traffic class
        // returns to PDMA. Never preserve an accidentally admitted nibble.
        if wan != 0x20710000 || mxl.is_some_and(|value| value != 0x20710000) {
            return Err(Error::Preconditions);
        }
        Ok(Self { wan, mxl })
    }
    pub fn wan_restore(self) -> u32 { self.wan }
    pub fn mxl_restore(self) -> Option<u32> { self.mxl }
    /// Close every selected ingress before inspecting any readback. Failure on
    /// one port must not leave another selected port admitting new lookups.
    /// Bounded: no locks, allocation, polling or table/cache accesses.
    ///
    /// # Safety
    /// Caller owns both selected GDMA policies and a real ordered MMIO backend.
    /// No backend call may panic/unwind. On error the caller must reset or
    /// otherwise establish closure; success is NOT a DMA-drain proof.
    pub unsafe fn close(self, io: &mut impl Registers) -> Result<(), CutoffFailure> {
        io.write(0x1500, self.wan);
        if let Some(value) = self.mxl { io.write(0x540, value); }
        // A built-in switch that joined the MxL table returns to PDMA with
        // it. Any other policy there is not this cutoff's to touch.
        let internal = self.mxl.is_some() && io.read(0x500) == INTERNAL_ADMIT;
        if internal { io.write(0x500, INTERNAL_CPU); }
        io.barrier();
        let wan = io.read(0x1500) != self.wan;
        let mxl = self.mxl.is_some_and(|value| io.read(0x540) != value)
            || (internal && io.read(0x500) != INTERNAL_CPU);
        if wan || mxl { Err(CutoffFailure { wan, mxl }) } else { Ok(()) }
    }
    /// Observe both selected CPU policies, without touching FOE memory.
    pub fn closed(self, io: &mut impl Registers) -> bool {
        let wan = io.read(0x1500) == self.wan;
        let mxl = self.mxl.is_none_or(|value| {
            let (mxl, internal) = (io.read(0x540), io.read(0x500));
            mxl == value && internal != INTERNAL_ADMIT
        });
        wan && mxl
    }
}
/// Built-in switch GDMA policy: every class to PDMA, and the same with the
/// router's own unicast admitted to PPE1 beside the MxL ingress.
pub(super) const INTERNAL_CPU: u32 = 0xc0700000;
pub(super) const INTERNAL_ADMIT: u32 = 0xc1704000;

/// Retains a permanent allocation after uncertain device state. There is no
/// CPU storage accessor or recovery operation. Recovery requires a device
/// reset and a separately established ownership proof, not merely a retry.
pub struct Quarantine {
    _table: CpuTable<'static>,
    pub error: Error,
}
pub enum Outcome {
    Restored(CpuTable<'static>),
    /// No registers were written; CPU ownership never changed.
    Rejected(CpuTable<'static>, Error),
    /// At least one write was attempted. Storage must not be recycled.
    Quarantined(Quarantine),
}

fn write_checked(io: &mut impl Registers, offset: usize, value: u32) -> Result<(), Error> {
    io.write(offset, value);
    io.barrier();
    // BUSY is read-only and can change independently of writable configuration.
    let mask = if matches!(offset, GLOBAL | 0x2600) { !BUSY } else { u32::MAX };
    if io.read(offset) & mask != value & mask {
        return Err(Error::Readback { offset });
    }
    Ok(())
}
fn ppe_reg(engine: Engine, offset: usize) -> usize {
    engine.offset() + offset - Engine::Ppe0.offset()
}
fn idle(io: &mut impl Registers, timeout: u64) -> Result<(), Error> {
    idle_on(io, Engine::Ppe0, timeout)
}
fn idle_on(io: &mut impl Registers, engine: Engine, timeout: u64) -> Result<(), Error> {
    let start = io.now();
    loop {
        if io.read(ppe_reg(engine, GLOBAL)) & BUSY == 0 {
            io.barrier();
            return Ok(());
        }
        if io.now().wrapping_sub(start) >= timeout {
            return Err(Error::Timeout);
        }
        core::hint::spin_loop();
    }
}

/// Temporarily publish an all-zero table address while PPE0 is disabled,
/// detach it, then restore the inherited empty-table configuration.
///
/// # Safety
/// Caller must exclusively own PPE configuration for the entire operation and
/// ensure no ingress path feeds any PPE engine. `table` must describe its exact
/// physical, permanent, normal non-cacheable DMA allocation. No other engine
/// or device may reference that allocation. The backend must implement real
/// ordered MMIO, a running clock and a full system barrier. No register call
/// may panic/unwind after a write. `timeout` is in backend ticks, nonzero and
/// less than half the wrapping clock range. This probe must never be used to
/// stop or replace an existing active table.
///
/// A static borrow is intentional: even dropping a quarantine cannot release
/// a caller's stack/heap buffer for reuse while DMA ownership is uncertain.
pub unsafe fn probe(io: &mut impl Registers, mut table: CpuTable<'static>, timeout: u64) -> Outcome {
    let before = Snapshot::read(Engine::Ppe0, |offset| io.read(offset));
    let inherited_empty = Engine::ALL.into_iter().all(|engine| {
        let state = Snapshot::read(engine, |offset| io.read(offset));
        state.table_base == 0 && !state.busy() && state.cache == 0
    });
    if timeout == 0
        || timeout >= 1 << 63
        || !inherited_empty
        || before.flow & ((1 << 12) | (1 << 13)) != 0
        || !table.is_zero()
    {
        return Outcome::Rejected(table, Error::Preconditions);
    }
    let result = (|| {
        write_checked(io, TABLE_CONFIG, before.table_config & !BACKGROUND)?;
        idle(io, timeout)?;
        write_checked(io, GLOBAL, before.global & !ENABLE)?;
        idle(io, timeout)?;
        // Barrier also makes the zeroed NC allocation visible before its base.
        io.barrier();
        table.publish();
        write_checked(io, TABLE_BASE, table.region().base())?;
        idle(io, timeout)?;
        write_checked(io, TABLE_BASE, 0)?;
        idle(io, timeout)?;
        write_checked(io, TABLE_CONFIG, before.table_config)?;
        // Re-enabling the inherited empty engine is last: base==0 was read
        // back, then idle and the completion barrier established detachment.
        write_checked(io, GLOBAL, before.global)?;
        let after = Snapshot::read(Engine::Ppe0, |offset| io.read(offset));
        if before != after {
            return Err(Error::Preconditions);
        }
        Ok(())
    })();
    match result {
        Ok(()) => { table.clear(); Outcome::Restored(table) },
        Err(error) => Outcome::Quarantined(Quarantine {
            _table: table,
            error,
        }),
    }
}

/// An enabled table, fed only by the selected WAN or MxL GDMA. No storage accessor:
/// general diagnostic reads must wait for `stop` to return CPU ownership.
/// Only the explicit retirement operation may access a live IB1 state word.
pub struct Session {
    engine: Engine,
    table: CpuTable<'static>,
    before: Snapshot,
    auxiliary: [u32; 7],
    ingress_cpu: u32,
    mtu: u16,
    path: FlowPath,
    rules: Rules,
}
/// Size field 4 selects 16K entries, 5 selects 32K; hash mode 1, v2/v3 entry
/// format, search miss to CPU. No scan, keepalive, auto-build or age writers.
pub(super) const TABLE_CONFIG_VALUE: u32 = 0x0010_4020 | if cfg!(feature = "ppe-32k") { 5 } else { 4 };
static RULE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleTicket {
    id: NonZeroU64,
    index: usize,
}
impl RuleTicket {
    pub fn index(self) -> usize {
        self.index
    }
}
fn ticket(index: usize) -> Option<RuleTicket> {
    let id = RULE_SEQUENCE
        .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
        .ok()?
        + 1;
    Some(RuleTicket {
        id: NonZeroU64::new(id)?,
        index,
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditError {
    Capacity,
    BucketFull,
    Duplicate,
    Mtu,
    Stale,
    IdentityExhausted,
    Egress,
}
pub enum EditOutcome<T> {
    Updated(PausedSession, T),
    /// Metadata rejection; hardware and table bytes have not changed.
    Rejected(PausedSession, EditError),
    Failed(Outcome),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetireError { Stale, AlreadyPending }
pub enum RetireOutcome {
    /// IB1 invalidation is visible; in-flight work is NOT proven drained.
    /// The installation's slot/key remain reserved until a paused removal.
    Pending(Session),
    Rejected(Session, RetireError),
    /// Caller must fail closed; no table storage becomes CPU-owned.
    Failed(Outcome),
}
pub enum StartOutcome {
    Active(Session),
    Failed(Outcome),
}
const WAN: usize = 0x1500;
const AUX: [usize; 7] = [0x2208, 0x2248, 0x224c, 0x2374, 0x2308, 0x230c, 0x2310];

/// Enable a zero table with miss-to-CPU (no automatic entry creation), no cache,
/// no aging/keepalive, and only WAN ingress. This is a fallback qualification
/// session, not a binding API.
///
/// # Safety
/// All `probe` memory/MMIO/exclusive-owner requirements apply until `stop`
/// finishes. No other code may change GDMA/PPE policy during the session. PDMA
/// TX must never target PPE. The allocation stays permanently reserved even
/// if a session is dropped. Clock/timeout requirements are as for `probe`.
pub unsafe fn start_empty(
    io: &mut impl Registers,
    table: CpuTable<'static>,
    timeout: u64,
) -> StartOutcome {
    unsafe { start_table(io, table, timeout, None, true, Engine::Ppe0, None) }
}

/// One owned topology and ingress direction per table. MxL uses its qualified bridge alias,
/// never an arbitrary customer VLAN or a physical-port selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlowPath { WanToInternal, WanToMxl, MxlToWan([u8; 6]) }
impl FlowPath {
    fn admission_register(self) -> usize {
        match self { Self::MxlToWan(_) => 0x540, _ => WAN }
    }
    fn admission_value(self, cpu: u32, engine: Engine) -> u32 {
        // GDMA MYMAC is bits 15:12; broadcast/multicast/other unicast stay
        // with PDMA for the bounded outbound diagnostic. v3 ports: PPE0=3, PPE1=4.
        let port = match engine { Engine::Ppe0 => 3, Engine::Ppe1 => 4, Engine::Ppe2 => 12 };
        (cpu & !0xffff) | if matches!(self, Self::MxlToWan(_)) { port << 12 } else { port * 0x1111 }
    }
    fn ingress_matches(self, io: &mut impl Registers) -> bool {
        if let Self::MxlToWan(mac) = self {
            if io.read(0x548) != u32::from_be_bytes(mac[2..].try_into().unwrap())
                || io.read(0x54c) != u16::from_be_bytes(mac[..2].try_into().unwrap()) as u32 {
                return false;
            }
        }
        let (peer_register, peer_value) = match self {
            Self::WanToInternal => return io.read(0x500) == 0xc0700000 && io.read(0x540) == 0x20717777,
            Self::WanToMxl => (0x540, 0x20710000),
            Self::MxlToWan(_) => (WAN, 0x20710000),
        };
        internal_bypasses(io.read(0x500)) && io.read(peer_register) == peer_value
    }
}
/// The built-in switch's GDMA stays out of an MxL session's tables: closed, or
/// handing every frame to PDMA. Its hosts are then software-forwarded only;
/// the routing owner must never publish a rule whose LAN host is behind it.
pub(super) fn internal_bypasses(policy: u32) -> bool {
    matches!(policy, 0x20717777 | 0xc0700000)
}
fn napt_bucket(original: Tuple) -> usize {
    // Hash-mode 1 chooses destination/source bits using the port word,
    // rotates that choice by a byte, XOR-folds all tuple words, then
    // selects a 4-way-aligned bucket in the 16K or 32K NETSYS-v3 table.
    let ports = (u32::from(original.source_port) << 16) | u32::from(original.destination_port);
    let dst = u32::from_be_bytes(original.destination);
    let src = u32::from_be_bytes(original.source);
    let choice = (ports & dst) | (!ports & src);
    let mixed = choice.rotate_left(8) ^ ports ^ dst ^ src;
    let index = (((mixed ^ (mixed >> 16)) as usize) & (super::table::ENTRIES / 4 - 1)) << 2;
    index
}
/// An exact direction-specific TCP/UDP translation. Constructors default to UDP;
/// select TCP explicitly with `with_protocol`. Construction validates format,
/// NOT NAT authorization; publication still requires the unsafe owner contract.
pub struct NaptBinding {
    entry: StagedEntry,
    index: usize,
    mtu: u16,
    path: FlowPath,
}
impl NaptBinding {
    /// Select the transport encoding without changing the validated NAT tuple,
    /// L2 recipe or hash bucket. This is format only, not permission to forward.
    /// TCP publication requires established connection authority and verified
    /// SYN/FIN/RST trapping; software must retire the rule before control changes.
    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        let mut ib1 = u32::from_le_bytes(self.entry.0[..4].try_into().unwrap());
        ib1 &= !(1 << 30);
        if protocol == Protocol::Udp { ib1 |= 1 << 30; }
        self.entry.0[..4].copy_from_slice(&ib1.to_le_bytes());
        self
    }
    pub fn protocol(&self) -> Protocol {
        if self.entry.0[3] & 0x40 != 0 { Protocol::Udp } else { Protocol::Tcp }
    }
    fn key(&self) -> (Protocol, [u8; 12]) {
        (self.protocol(), self.entry.bytes()[4..16].try_into().unwrap())
    }

    pub fn wan_to_lan(
        original: Tuple,
        translated: Tuple,
        source_mac: [u8; 6],
        destination_mac: [u8; 6],
    ) -> Result<Self, EncodeError> {
        if original.source != translated.source || original.source_port != translated.source_port {
            return Err(EncodeError::Address);
        }
        let entry = StagedEntry::ipv4_napt(
            Protocol::Udp,
            original,
            translated,
            crate::TxPort::Internal,
            source_mac,
            destination_mac,
        )?;
        Ok(Self {
            entry,
            index: napt_bucket(original),
            mtu: 1500,
            path: FlowPath::WanToInternal,
        })
    }
    /// Format only: publication additionally requires the caller to own the
    /// MxL bridge lease and validate tagged egress, neighbor and NAT authority.
    pub fn wan_to_mxl_lan(
        original: Tuple,
        translated: Tuple,
        source_mac: [u8; 6],
        destination_mac: [u8; 6],
    ) -> Result<Self, EncodeError> {
        let mut binding = Self::wan_to_lan(original, translated, source_mac, destination_mac)?;
        binding.entry = StagedEntry::ipv4_napt_mxl_bridge(
            Protocol::Udp, original, translated, source_mac, destination_mac)?;
        binding.path = FlowPath::WanToMxl;
        Ok(binding)
    }
    /// Experimental outbound SNAT format. Only source address/port may change.
    /// This does not authorize opening MxL ingress. Publication requires owned
    /// bridge/tag policy, validated outbound receipt and WAN next-hop authority.
    /// `ingress_mac` must be the authorized LAN router address; the configured
    /// GDMA MYMAC registers are checked before admission and ownership changes.
    pub fn mxl_lan_to_wan(
        original: Tuple,
        translated: Tuple,
        ingress_mac: [u8; 6],
        source_mac: [u8; 6],
        destination_mac: [u8; 6],
    ) -> Result<Self, EncodeError> {
        if ingress_mac == [0; 6] || ingress_mac[0] & 1 != 0
            || original.destination != translated.destination
            || original.destination_port != translated.destination_port {
            return Err(EncodeError::Address);
        }
        let entry = StagedEntry::ipv4_napt(Protocol::Udp, original, translated,
            crate::TxPort::Wan, source_mac, destination_mac)?;
        Ok(Self { entry, index: napt_bucket(original), mtu: 1500, path: FlowPath::MxlToWan(ingress_mac) })
    }
    /// Plain routing between two hosts that are both behind the switches:
    /// a rule of the MxL-ingress table (which a joined built-in switch feeds
    /// too) that leaves towards a switch again. Nothing is translated. It is
    /// staged with the MxL bridge tag; select the real egress with
    /// `with_mxl_alias` or `with_builtin_port`. Format only: the caller owns
    /// both hosts' location, the policy between their networks, and the
    /// fact that every network feeding this table may reach the destination.
    pub fn mxl_lan_to_inside(
        original: Tuple,
        ingress_mac: [u8; 6],
        source_mac: [u8; 6],
        destination_mac: [u8; 6],
    ) -> Result<Self, EncodeError> {
        Self::switch_ingress(original, original, ingress_mac, source_mac, destination_mac)
    }
    /// A rule of the table the SoC's own port feeds, whatever it does to the
    /// addresses: translate the source, the destination, or nothing. Which
    /// network is behind that port is the caller's business. Staged with
    /// the MxL bridge tag; select the real egress with `with_mxl_alias` or
    /// `with_builtin_port`. Format only, as for every constructor here.
    pub fn direct_ingress(
        original: Tuple,
        translated: Tuple,
        source_mac: [u8; 6],
        destination_mac: [u8; 6],
    ) -> Result<Self, EncodeError> {
        let entry = StagedEntry::ipv4_napt_mxl_bridge(Protocol::Udp, original, translated, source_mac, destination_mac)?;
        Ok(Self { entry, index: napt_bucket(original), mtu: 1500, path: FlowPath::WanToMxl })
    }
    /// A rule of the table the switches feed (frames for `ingress_mac`),
    /// whatever it does to the addresses. Staged with the MxL bridge tag;
    /// select the real egress with `with_mxl_alias`, `with_builtin_port` or
    /// `with_direct_egress`.
    pub fn switch_ingress(
        original: Tuple,
        translated: Tuple,
        ingress_mac: [u8; 6],
        source_mac: [u8; 6],
        destination_mac: [u8; 6],
    ) -> Result<Self, EncodeError> {
        if ingress_mac == [0; 6] || ingress_mac[0] & 1 != 0 {
            return Err(EncodeError::Address);
        }
        let entry = StagedEntry::ipv4_napt_mxl_bridge(Protocol::Udp, original, translated, source_mac, destination_mac)?;
        Ok(Self { entry, index: napt_bucket(original), mtu: 1500, path: FlowPath::MxlToWan(ingress_mac) })
    }
    /// Send a switch-ingress rule's frames out of the SoC's own port,
    /// untagged. A rule entering through that port cannot leave by it.
    pub fn with_direct_egress(mut self) -> Result<Self, EncodeError> {
        if !matches!(self.path, FlowPath::MxlToWan(_)) {
            return Err(EncodeError::UnsupportedEgress);
        }
        let ib1 = u32::from_le_bytes(self.entry.0[..4].try_into().unwrap());
        self.entry.0[..4].copy_from_slice(&(ib1 & !(7 << 14 | 1 << 18)).to_le_bytes());
        self.entry.0[16..20].copy_from_slice(&((2u32 << 9) | (0xf << 20)).to_le_bytes());
        self.entry.0[44..46].copy_from_slice(&0u16.to_le_bytes());
        self.entry.0[46..48].copy_from_slice(&0x0800u16.to_le_bytes());
        Ok(self)
    }
    /// Stands for a table's ingress and MTU where no rule exists yet.
    fn template(path: FlowPath, mtu: u16) -> Result<Self, EncodeError> {
        let tuple = Tuple { source: [192, 0, 2, 1], destination: [192, 0, 2, 2], source_port: 1, destination_port: 1 };
        let rule = match path {
            FlowPath::MxlToWan(mac) => Self::switch_ingress(tuple, tuple, mac, mac, mac)?,
            _ => Self::direct_ingress(tuple, tuple, [2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])?,
        };
        rule.with_mtu(mtu)
    }
    /// Whether this rule leaves towards a switch (PSE port GDM3 or GDM1 with
    /// a tag), as opposed to the untagged WAN port or the legacy fixture.
    fn inside_egress(&self) -> bool {
        let port = u32::from_le_bytes(self.entry.0[16..20].try_into().unwrap()) >> 9 & 0xf;
        self.path == FlowPath::WanToMxl || (matches!(self.path, FlowPath::MxlToWan(_)) && port != 2)
    }
    /// Select which copper index's CPU tag carries MxL egress: the one the
    /// switch owner reports as entering its LAN bridge (index 0 unless that
    /// port is outside the bridge). Format only; the caller owns that policy.
    pub fn with_mxl_alias(mut self, copper: u8) -> Result<Self, EncodeError> {
        if !self.inside_egress() || copper > 3 {
            return Err(EncodeError::UnsupportedEgress);
        }
        self.entry.0[44..46].copy_from_slice(&(0x0c00 | u16::from(copper)).to_le_bytes());
        Ok(self)
    }
    /// Send this rule's frames to one port of the built-in switch instead of
    /// the MxL: PSE port GDM1, with the switch's four-byte port tag (port
    /// bitmap where the type would be, one tag layer, no 802.1Q insertion).
    /// Format only; the caller owns the switch's CPU-port tag policy.
    pub fn with_builtin_port(mut self, port: u8) -> Result<Self, EncodeError> {
        if !self.inside_egress() || port > 5 {
            return Err(EncodeError::UnsupportedEgress);
        }
        let ib1 = u32::from_le_bytes(self.entry.0[..4].try_into().unwrap());
        self.entry.0[..4].copy_from_slice(&((ib1 | 1 << 14) & !(1 << 18)).to_le_bytes());
        self.entry.0[16..20].copy_from_slice(&((1u32 << 9) | (0xf << 20)).to_le_bytes());
        self.entry.0[44..46].copy_from_slice(&0u16.to_le_bytes());
        self.entry.0[46..48].copy_from_slice(&(1u16 << port).to_le_bytes());
        Ok(self)
    }
    /// Match the single rule's validated egress IP MTU. Hardware limits include
    /// Ethernet/VLAN headers; oversized packets must take the CPU slow path.
    pub fn with_mtu(mut self, mtu: u16) -> Result<Self, EncodeError> {
        if !(576..=1500).contains(&mtu) {
            return Err(EncodeError::Mtu);
        }
        self.mtu = mtu;
        Ok(self)
    }
    pub fn index(&self) -> usize {
        self.index
    }
}

/// Publish one pre-authorized TCP/UDP rule with cache disabled and one ingress.
/// # Safety
/// All `start_empty` requirements apply. Additionally, the routing owner must
/// revalidate the exact transport mapping, remote permission, direction, MACs and MTU
/// immediately before calling; ensure no policy/neighbor/lease changes while
/// active; and withdraw admission before that authority expires. A failure
/// requires fail-closed ingress withdrawal or board reset, not just leaking the
/// table. TCP additionally requires explicit established-flow handoff and verified
/// SYN/FIN/RST traps; retire hardware before processing those control events.
/// This diagnostic does not implement a production expiry scheduler.
/// For MxL egress, retain the owned four-copper bridge lease, fixed 0xc00 alias
/// and CPU-port VLAN policy throughout publication. GDMA checks alone cannot
/// prove switch ownership; revoke the session before releasing that lease.
/// MxL ingress is currently for isolated, bounded hardware qualification only:
/// MYMAC-only classification and ingress MAC readback do not prove customer
/// VLAN admission; retain a separately qualified switch ingress policy. Production
/// use additionally requires matching the software input policy, CPU-tag
/// parsing/removal, exceptions and untagged WAN egress on this exact board.
/// Retain the bridge lease and arm a cutoff covering MxL before publication;
/// the previous WAN-only IRQ/owner guard is insufficient. A single session
/// accepts only one direction; mixing outgoing and return rules is rejected.
pub unsafe fn start_single_napt(
    io: &mut impl Registers,
    table: CpuTable<'static>,
    timeout: u64,
    binding: &NaptBinding,
) -> StartOutcome {
    unsafe { start_table(io, table, timeout, Some(binding), true, Engine::Ppe0, None) }
}
/// Prepare a hardware-owned rule while keeping selected admission on the CPU.
/// # Safety
/// The same authority and exclusive ownership requirements as start_single_napt
/// apply. Drain preceding software work and revalidate before resume.
pub unsafe fn prepare_single_napt(
    io: &mut impl Registers,
    table: CpuTable<'static>,
    timeout: u64,
    binding: &NaptBinding,
) -> PauseOutcome {
    match unsafe { start_table(io, table, timeout, Some(binding), false, Engine::Ppe0, None) } {
        StartOutcome::Active(session) => PauseOutcome::Paused(PausedSession(session)),
        StartOutcome::Failed(outcome) => PauseOutcome::Failed(outcome),
    }
}
/// Qualify a selected engine with all other tables detached. PPE1 is currently
/// restricted to the bounded MxL-to-WAN diagnostic; this does not authorize
/// simultaneous engines or shared FOE tables.
/// # Safety
/// All start_single_napt requirements apply to the selected engine and ingress.
pub unsafe fn start_single_napt_on(
    io: &mut impl Registers, table: CpuTable<'static>, timeout: u64,
    binding: &NaptBinding, engine: Engine,
) -> StartOutcome {
    unsafe { start_table(io, table, timeout, Some(binding), true, engine, None) }
}
/// Prepare the selected diagnostic engine with ingress still CPU-owned.
/// # Safety
/// All prepare_single_napt and start_single_napt_on requirements apply.
pub unsafe fn prepare_single_napt_on(
    io: &mut impl Registers, table: CpuTable<'static>, timeout: u64,
    binding: &NaptBinding, engine: Engine,
) -> PauseOutcome {
    match unsafe { start_table(io, table, timeout, Some(binding), false, engine, None) } {
        StartOutcome::Active(session) => PauseOutcome::Paused(PausedSession(session)),
        StartOutcome::Failed(outcome) => PauseOutcome::Failed(outcome),
    }
}
unsafe fn start_table(
    io: &mut impl Registers,
    mut table: CpuTable<'static>,
    timeout: u64,
    binding: Option<&NaptBinding>,
    admit: bool,
    engine: Engine,
    peer: Option<&PausedSession>,
) -> StartOutcome {
    unsafe { start_table_with(io, table, timeout, binding, true, admit, engine, peer) }
}
/// `start_table`; with `publish` false the binding only names the table's
/// ingress and MTU and the table starts without a rule.
unsafe fn start_table_with(
    io: &mut impl Registers,
    mut table: CpuTable<'static>,
    timeout: u64,
    binding: Option<&NaptBinding>,
    publish: bool,
    admit: bool,
    engine: Engine,
    peer: Option<&PausedSession>,
) -> StartOutcome {
    let before = Snapshot::read(engine, |o| io.read(o));
    let path = binding.map_or(FlowPath::WanToInternal, |b| b.path);
    let ingress_cpu = io.read(path.admission_register());
    // Only the private duplex coordinator can supply an owned paused peer.
    // Public single-engine entry points always require every table detached.
    let peer_valid = peer.is_none_or(|p| p.0.engine != engine && p.edit_check(io).is_ok());
    let empty = Engine::ALL.into_iter().all(|engine| {
        let s = Snapshot::read(engine, |o| io.read(o));
        let expected = peer.filter(|p| p.0.engine == engine)
            .map_or(0, |p| p.0.table.region().base());
        s.table_base == expected && s.cache == 0 && !s.busy()
    });
    if engine == Engine::Ppe2
        || (engine == Engine::Ppe1 && !matches!(path, FlowPath::MxlToWan(_)))
        || !peer_valid
        || !empty
        || timeout == 0
        || timeout >= 1 << 63
        || !table.has_zero_proof()
        || before.flow & ((1 << 12) | (1 << 13)) != 0
        || ingress_cpu != 0x20710000
        || !path.ingress_matches(io)
    {
        return StartOutcome::Failed(Outcome::Rejected(table, Error::Preconditions));
    }
    // Reserve all ownership metadata before any register write.
    let mut rules = Rules::new();
    let mut initial = None;
    if let Some(binding) = binding.filter(|_| publish) {
        let slot = rules.free_way(binding.index);
        let Some(ticket) = slot.and_then(ticket) else {
            return StartOutcome::Failed(Outcome::Rejected(table, Error::Preconditions));
        };
        rules.insert(RuleRecord::new(ticket, binding.key()));
        initial = Some(ticket);
    }
    let auxiliary = AUX.map(|o| io.read(ppe_reg(engine, o)));
    let result = (|| {
        write_checked(io, ppe_reg(engine, TABLE_CONFIG), before.table_config & !BACKGROUND)?;
        idle_on(io, engine, timeout)?;
        write_checked(io, ppe_reg(engine, GLOBAL), before.global & !ENABLE)?;
        idle_on(io, engine, timeout)?;
        if let (Some(binding), Some(ticket)) = (binding, initial) {
            table.bind_napt(ticket.index(), &binding.entry, io.read(0x10) as u8);
        }
        write_checked(io, ppe_reg(engine, TABLE_CONFIG), TABLE_CONFIG_VALUE)?;
        io.barrier();
        table.publish();
        write_checked(io, ppe_reg(engine, TABLE_BASE), table.region().base())?;
        // Same framing convention as Linux mtk_ppe_update_mtu: IP MTU +
        // 14-byte Ethernet header, then 0..3 VLAN headers. Do not inherit a
        // bootloader jumbo limit or MTU-drop policy. Exceptions go to CPU.
        let base = u32::from(binding.map_or(1500, |b| b.mtu)) + 14;
        let limits = [
            u32::MAX,
            0,
            0xcb777,
            0x7f,
            0,
            base | ((base + 4) << 16),
            (base + 8) | ((base + 12) << 16),
        ];
        for (offset, value) in AUX.into_iter().zip(limits) {
            write_checked(io, ppe_reg(engine, offset), value)?;
        }
        write_checked(io, ppe_reg(engine, 0x2204), 0x200e)?;
        write_checked(io, ppe_reg(engine, GLOBAL), before.global | ENABLE)?;
        // NETSYS-v3 PPE0 port is 3, not the v1 port 4. Ingress is last.
        if admit { write_checked(io, path.admission_register(), path.admission_value(ingress_cpu, engine))?; }
        else { idle_on(io, engine, timeout)?; }
        Ok(())
    })();
    match result {
        Ok(()) => StartOutcome::Active(Session {
            table,
            engine,
            before,
            auxiliary,
            ingress_cpu,
            mtu: binding.map_or(1500, |b| b.mtu),
            path,
            rules,
        }),
        Err(error) => StartOutcome::Failed(Outcome::Quarantined(Quarantine {
            _table: table,
            error,
        })),
    }
}
/// Selected admission is closed and all preceding lookups completed. The FOE
/// allocation remains hardware-owned; software may revalidate its authority,
/// but may not access/recycle table storage through this token.
pub struct PausedSession(Session);
pub enum PauseOutcome {
    Paused(PausedSession),
    Failed(Outcome),
}
/// Every ticket must name a distinct live installation of this session.
fn removal_check(session: &mut Session, tickets: impl Iterator<Item = RuleTicket> + Clone) -> Result<usize, EditError> {
    session.rules.validate_batch(tickets).map_err(|error| match error {
        BatchError::Stale => EditError::Stale,
        BatchError::Duplicate => EditError::Duplicate,
        BatchError::Capacity => EditError::Capacity,
    })
}

impl PausedSession {
    pub fn initial_ticket(&self) -> Option<RuleTicket> { self.0.initial_ticket() }
    fn edit_check(&self, io: &mut impl Registers) -> Result<(), Error> {
        let engine = self.0.engine;
        if !self.0.path.ingress_matches(io)
            || io.read(self.0.path.admission_register()) != self.0.ingress_cpu
            || io.read(ppe_reg(engine, TABLE_BASE)) != self.0.table.region().base()
            || io.read(ppe_reg(engine, GLOBAL)) & (ENABLE | BUSY) != ENABLE
            || io.read(ppe_reg(engine, 0x2320)) != 0
            || io.read(ppe_reg(engine, TABLE_CONFIG)) != TABLE_CONFIG_VALUE
            || io.read(ppe_reg(engine, 0x2204)) != 0x200e
        {
            return Err(Error::Preconditions);
        }
        Ok(())
    }
    fn edit_begin(&self, io: &mut impl Registers, timeout: u64) -> Result<(), Error> {
        let engine = self.0.engine;
        if timeout == 0 || timeout >= 1 << 63 {
            return Err(Error::Preconditions);
        }
        self.edit_check(io)?;
        write_checked(io, ppe_reg(engine, GLOBAL), self.0.before.global & !ENABLE)?;
        idle_on(io, engine, timeout)
    }
    fn edit_end(&self, io: &mut impl Registers, timeout: u64) -> Result<(), Error> {
        let engine = self.0.engine;
        io.barrier();
        write_checked(io, ppe_reg(engine, GLOBAL), self.0.before.global | ENABLE)?;
        idle_on(io, engine, timeout)
    }
    /// Insert into one of the four hardware ways without replacing a peer.
    /// # Safety
    /// Revalidate NAT/remote/route/neighbor/MTU authority before installation.
    /// Keep all pause/session ownership contracts, cache disabled, and every
    /// ingress closed through the edit. Authority must survive until cutoff.
    pub unsafe fn insert_napt(
        mut self,
        io: &mut impl Registers,
        timeout: u64,
        binding: &NaptBinding,
    ) -> EditOutcome<RuleTicket> {
        if binding.path != self.0.path {
            return EditOutcome::Rejected(self, EditError::Egress);
        }
        if binding.mtu != self.0.mtu {
            return EditOutcome::Rejected(self, EditError::Mtu);
        }
        let key = binding.key();
        if self.0.rules.contains_key(binding.index, &key) {
            return EditOutcome::Rejected(self, EditError::Duplicate);
        }
        if self.0.rules.is_full() {
            return EditOutcome::Rejected(self, EditError::Capacity);
        }
        let Some(index) = self.0.rules.free_way(binding.index) else {
            return EditOutcome::Rejected(self, EditError::BucketFull);
        };
        let Some(ticket) = ticket(index) else {
            return EditOutcome::Rejected(self, EditError::IdentityExhausted);
        };
        let result = (|| {
            self.edit_begin(io, timeout)?;
            self.0
                .table
                .bind_napt(index, &binding.entry, io.read(0x10) as u8);
            self.edit_end(io, timeout)
        })();
        match result {
            Ok(()) => {
                self.0.rules.insert(RuleRecord::new(ticket, key));
                EditOutcome::Updated(self, ticket)
            }
            Err(error) => EditOutcome::Failed(Outcome::Quarantined(Quarantine {
                _table: self.0.table,
                error,
            })),
        }
    }
    /// Remove exact installations in one disabled-engine edit, preserving peers.
    /// Validate the entire bounded batch before modifying any table byte.
    /// # Safety
    /// Uphold the same exclusive, paused, no-cache contract as insert_napt.
    pub unsafe fn remove_many(
        mut self, io: &mut impl Registers, timeout: u64,
        tickets: impl Iterator<Item = RuleTicket> + Clone,
    ) -> EditOutcome<()> {
        let count=match removal_check(&mut self.0,tickets.clone()) {
            Ok(count)=>count,Err(error)=>return EditOutcome::Rejected(self,error),
        };
        if count==0 {return EditOutcome::Updated(self,());}
        let result=(|| {
            self.edit_begin(io,timeout)?;
            for ticket in tickets.clone() {self.0.table.clear_entry(ticket.index);}
            self.edit_end(io,timeout)
        })();
        match result {
            Ok(())=>{
                for ticket in tickets {self.0.rules.remove(ticket);}
                EditOutcome::Updated(self,())
            },
            Err(error)=>EditOutcome::Failed(Outcome::Quarantined(Quarantine {_table:self.0.table,error})),
        }
    }
    /// Remove exactly this installation, not a successor reusing its slot.
    /// # Safety
    /// Uphold the same exclusive, paused, no-cache contract as insert_napt.
    pub unsafe fn remove_napt(
        self, io: &mut impl Registers, timeout: u64, ticket: RuleTicket,
    ) -> EditOutcome<()> {
        unsafe {self.remove_many(io,timeout,core::iter::once(ticket))}
    }
    /// # Safety
    /// Revalidate the exact rule's authority, route, neighbor and deadline
    /// before resuming. Serialize publication with any asynchronous cutoff;
    /// no other ingress or register owner may feed/change this PPE session.
    pub unsafe fn resume(self, io: &mut impl Registers) -> StartOutcome {
        let session = self.0;
        let engine = session.engine;
        let result = (|| {
            if !session.path.ingress_matches(io)
                || io.read(session.path.admission_register()) != session.ingress_cpu
                || io.read(ppe_reg(engine, TABLE_BASE)) != session.table.region().base()
                || io.read(ppe_reg(engine, GLOBAL)) & (ENABLE | BUSY) != ENABLE
            {
                return Err(Error::Preconditions);
            }
            write_checked(io, session.path.admission_register(), session.path.admission_value(session.ingress_cpu, engine))
        })();
        match result {
            Ok(()) => StartOutcome::Active(session),
            Err(error) => StartOutcome::Failed(Outcome::Quarantined(Quarantine {
                _table: session.table,
                error,
            })),
        }
    }
    /// # Safety
    /// Uphold Session::stop's exclusive restoration contract.
    pub unsafe fn stop(self, io: &mut impl Registers, timeout: u64) -> Outcome {
        unsafe { self.0.stop(io, timeout) }
    }
}

impl Session {
    /// Whether this exact installation is awaiting drain and final removal.
    pub fn retirement_pending(&self, ticket: RuleTicket) -> bool {
        self.rules.get(ticket).is_some_and(|r| r.retiring)
    }
    /// Experimental per-entry invalidation without changing ingress or PPE
    /// enable registers. No body clear, slot release or timer renewal occurs.
    ///
    /// # Safety
    /// Keep the exclusive Session ownership, cache-off and permanent Normal-NC
    /// DMA contracts. The target and all peer rules must retain valid authority
    /// through a separately enforced cutoff/drain. A visible invalid state is
    /// not proof that prior lookups or hardware writebacks have completed.
    /// Keep the independent IRQ cutoff armed; never reuse the target slot/key
    /// until pause/drain plus remove_napt, or stop, has completed. On Failed,
    /// close ingress or reset even if no MMIO write was performed here.
    pub unsafe fn retire_napt(mut self, io: &mut impl Registers, ticket: RuleTicket) -> RetireOutcome {
        let engine = self.engine;
        let Some(record) = self.rules.get(ticket).copied() else {
            return RetireOutcome::Rejected(self, RetireError::Stale);
        };
        if record.retiring {
            return RetireOutcome::Rejected(self, RetireError::AlreadyPending);
        }
        let valid = self.path.ingress_matches(io)
            && io.read(self.path.admission_register()) == self.path.admission_value(self.ingress_cpu, engine)
            && io.read(ppe_reg(engine, TABLE_BASE)) == self.table.region().base()
            && io.read(ppe_reg(engine, GLOBAL)) & ENABLE != 0
            && io.read(ppe_reg(engine, 0x2320)) == 0
            && io.read(ppe_reg(engine, TABLE_CONFIG)) == TABLE_CONFIG_VALUE
            && io.read(ppe_reg(engine, 0x2204)) == 0x200e;
        if !valid || !unsafe { self.table.retire_napt_state(ticket.index, record.key.0) } {
            return RetireOutcome::Failed(Outcome::Quarantined(Quarantine {
                _table: self.table, error: Error::Preconditions,
            }));
        }
        io.barrier();
        if !unsafe { self.table.retired_state_visible(ticket.index) } {
            return RetireOutcome::Failed(Outcome::Quarantined(Quarantine {
                _table: self.table, error: Error::Preconditions,
            }));
        }
        self.rules.get_mut(ticket).expect("validated rule").retiring = true;
        RetireOutcome::Pending(self)
    }
    pub fn initial_ticket(&self) -> Option<RuleTicket> {
        self.rules.initial()
    }
    /// Close new admission and drain preceding lookups without detaching or
    /// rescanning the 2 MiB table. A failure retains the allocation.
    /// # Safety
    /// Keep the original session's exclusive ownership contract. An IRQ may
    /// only restore the same selected-ingress-to-CPU value; it must not reopen admission.
    pub unsafe fn pause(self, io: &mut impl Registers, timeout: u64) -> PauseOutcome {
        let engine = self.engine;
        let result = (|| {
            if timeout == 0 || timeout >= 1 << 63 {
                return Err(Error::Preconditions);
            }
            write_checked(io, self.path.admission_register(), self.ingress_cpu)?;
            if !self.path.ingress_matches(io) { return Err(Error::Preconditions); }
            idle_on(io, engine, timeout)
        })();
        match result {
            Ok(()) => PauseOutcome::Paused(PausedSession(self)),
            Err(error) => PauseOutcome::Failed(Outcome::Quarantined(Quarantine {
                _table: self.table,
                error,
            })),
        }
    }
    /// # Safety
    /// Continue to uphold the `start_empty` ownership/backend contract. No
    /// asynchronous owner may alter ingress or PPE while detaching/restoring.
    pub unsafe fn stop(mut self, io: &mut impl Registers, timeout: u64) -> Outcome {
        let engine = self.engine;
        let result = (|| {
            if timeout == 0 || timeout >= 1 << 63 {
                return Err(Error::Preconditions);
            }
            // Stop new selected admission before stopping lookup or touching base.
            write_checked(io, self.path.admission_register(), self.ingress_cpu)?;
            if !self.path.ingress_matches(io) { return Err(Error::Preconditions); }
            idle_on(io, engine, timeout)?;
            write_checked(io, ppe_reg(engine, GLOBAL), self.before.global & !ENABLE)?;
            idle_on(io, engine, timeout)?;
            write_checked(io, ppe_reg(engine, 0x2204), self.before.flow)?;
            write_checked(io, ppe_reg(engine, TABLE_BASE), 0)?;
            idle_on(io, engine, timeout)?;
            for (offset, value) in AUX.into_iter().zip(self.auxiliary) {
                write_checked(io, ppe_reg(engine, offset), value)?;
            }
            write_checked(io, ppe_reg(engine, TABLE_CONFIG), self.before.table_config)?;
            write_checked(io, ppe_reg(engine, GLOBAL), self.before.global)?;
            if Snapshot::read(engine, |o| io.read(o)) != self.before
                || io.read(self.path.admission_register()) != self.ingress_cpu
                || !self.path.ingress_matches(io)
            {
                return Err(Error::Preconditions);
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                // Detached ownership permits a full clear, renewing the proof
                // even for an empty table that was exposed to hardware.
                self.table.clear();
                Outcome::Restored(self.table)
            }
            Err(error) => Outcome::Quarantined(Quarantine {
                _table: self.table,
                error,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::ppe::table::TABLE_BYTES;
    use std::{boxed::Box, collections::BTreeMap, vec::Vec};
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Op {
        Read(usize),
        Write(usize, u32),
        Barrier,
    }
    struct Mock {
        registers: BTreeMap<usize, u32>,
        ops: Vec<Op>,
        writes: usize,
        ignore_write: Option<usize>,
        busy_after: Option<usize>,
        clock: u64,
    }
    impl Mock {
        fn new() -> Self {
            let mut registers = BTreeMap::new();
            for engine in Engine::ALL {
                registers.insert(engine.offset() + 0x200, 0x6000020d);
                registers.insert(engine.offset() + 0x204, 0xe);
                registers.insert(engine.offset() + 0x21c, 0x16f000);
            }
            Self {
                registers,
                ops: Vec::new(),
                writes: 0,
                ignore_write: None,
                busy_after: None,
                clock: 0,
            }
        }
    }
    impl Registers for Mock {
        fn read(&mut self, offset: usize) -> u32 {
            self.ops.push(Op::Read(offset));
            let value = *self.registers.get(&offset).unwrap_or(&0);
            if matches!(offset, GLOBAL | 0x2600) && self.busy_after.is_some_and(|w| self.writes >= w) {
                value | BUSY
            } else {
                value
            }
        }
        fn write(&mut self, offset: usize, value: u32) {
            assert!(configuration_register(offset));
            self.writes += 1;
            self.ops.push(Op::Write(offset, value));
            if self.ignore_write != Some(self.writes) {
                self.registers.insert(offset, value);
            }
        }
        fn barrier(&mut self) {
            self.ops.push(Op::Barrier);
        }
        fn now(&mut self) -> u64 {
            let t = self.clock;
            self.clock = t.wrapping_add(1);
            t
        }
    }
    fn table() -> CpuTable<'static> {
        CpuTable::new(
            Box::leak(std::vec![0; TABLE_BYTES].into_boxed_slice()),
            0x40c00000,
        )
        .unwrap()
    }
    #[test]
    fn publication_is_disabled_and_detachment_precedes_restore() {
        let mut io = Mock::new();
        let original = io.registers.clone();
        let result = unsafe { probe(&mut io, table(), 10) };
        let Outcome::Restored(table) = result else {
            panic!("not restored")
        };
        assert!(table.is_zero());
        let writes: Vec<_> = io
            .ops
            .iter()
            .filter_map(|op| {
                if let Op::Write(o, v) = op {
                    Some((*o, *v))
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            writes,
            std::vec![
                (TABLE_CONFIG, 0x16f000 & !BACKGROUND),
                (GLOBAL, 0x6000020c),
                (TABLE_BASE, 0x40c00000),
                (TABLE_BASE, 0),
                (TABLE_CONFIG, 0x16f000),
                (GLOBAL, 0x6000020d)
            ]
        );
        for (i, op) in io.ops.iter().enumerate() {
            if let Op::Write(offset, _) = op {
                assert_eq!(io.ops[i + 1], Op::Barrier);
                assert_eq!(io.ops[i + 2], Op::Read(*offset));
            }
        }
        for (offset, value) in original {
            assert_eq!(io.registers[&offset], value);
        }
        assert_eq!(io.registers[&TABLE_BASE], 0);
    }
    #[test]
    fn each_write_failure_retains_allocation_and_stops_later_writes() {
        for failed in 1..=6 {
            let mut io = Mock::new();
            io.ignore_write = Some(failed);
            let result = unsafe { probe(&mut io, table(), 10) };
            let Outcome::Quarantined(fault) = result else {
                panic!("failure {failed} returned CPU owner")
            };
            assert!(matches!(fault.error, Error::Readback { .. }));
            assert_eq!(io.writes, failed);
        }
    }
    #[test]
    fn busy_timeout_before_and_after_publication_never_returns_cpu_storage() {
        for busy_after in 1..=4 {
            let mut io = Mock::new();
            io.busy_after = Some(busy_after);
            io.clock = u64::MAX - 2; // timeout remains bounded across wrap
            let result = unsafe { probe(&mut io, table(), 10) };
            let Outcome::Quarantined(fault) = result else {
                panic!("busy returned owner")
            };
            assert_eq!(fault.error, Error::Timeout);
            assert_eq!(io.writes, busy_after);
            assert!(io.ops.len() < 100);
        }
    }
    #[test]
    fn nonzero_invalid_entries_are_rejected_without_register_writes() {
        use crate::ppe::{Protocol, StagedEntry, Tuple};
        let tuple = Tuple {
            source: [192, 168, 79, 100],
            destination: [192, 168, 78, 100],
            source_port: 12345,
            destination_port: 33445,
        };
        let entry = StagedEntry::ipv4_napt(
            Protocol::Udp,
            tuple,
            tuple,
            crate::TxPort::Wan,
            [2, 0, 0, 0, 0, 1],
            [2, 0, 0, 0, 0, 2],
        )
        .unwrap();
        let mut storage = table();
        storage.stage(0, &entry).unwrap();
        assert!(storage.all_invalid());
        let mut io = Mock::new();
        let Outcome::Rejected(storage, Error::Preconditions) =
            (unsafe { probe(&mut io, storage, 10) })
        else {
            panic!("nonzero table accepted")
        };
        assert_eq!(storage.entry(0).unwrap(), entry.bytes());
        assert_eq!(io.writes, 0);
    }
    #[test]
    fn existing_tables_caches_busy_and_nat_are_rejected_without_writes() {
        for engine in Engine::ALL {
            for (reg, value) in [(0x220, 0x40000000), (0x320, 1), (0x200, BUSY | 1)] {
                let mut io = Mock::new();
                io.registers.insert(engine.offset() + reg, value);
                assert!(matches!(
                    unsafe { probe(&mut io, table(), 10) },
                    Outcome::Rejected(_, Error::Preconditions)
                ));
                assert_eq!(io.writes, 0);
            }
        }
        for (offset, value) in [(0x2204, 1 << 12), (0x2204, 1 << 13), (0x2320, 1 << 8)] {
            let mut io = Mock::new();
            io.registers.insert(offset, value);
            assert!(matches!(
                unsafe { probe(&mut io, table(), 10) },
                Outcome::Rejected(_, Error::Preconditions)
            ));
            assert_eq!(io.writes, 0);
        }
        for timeout in [0, 1 << 63, u64::MAX] {
            let mut io = Mock::new();
            assert!(matches!(
                unsafe { probe(&mut io, table(), timeout) },
                Outcome::Rejected(_, Error::Preconditions)
            ));
            assert_eq!(io.writes, 0);
        }
    }
    #[test]
    fn dual_ingress_cutoff_closes_all_before_readback_without_drain_claim() {
        let cutoff = IngressCutoff::new(0x20710000, Some(0x20710000)).unwrap();
        let mut io = Mock::new();
        io.registers.insert(WAN, 0x20713333);
        io.registers.insert(0x540, 0x20713333);
        io.registers.insert(GLOBAL, BUSY | ENABLE);
        let before = io.registers.clone();
        assert_eq!(unsafe { cutoff.close(&mut io) }, Ok(()));
        assert_eq!(io.ops, std::vec![Op::Write(WAN, 0x20710000),
            Op::Write(0x540, 0x20710000), Op::Read(0x500), Op::Barrier,
            Op::Read(WAN), Op::Read(0x540)]);
        for (offset, value) in before {
            if offset != WAN && offset != 0x540 { assert_eq!(io.registers[&offset], value); }
        }
        assert!(cutoff.closed(&mut io));
        assert_eq!(io.clock, 0); // No idle wait: BUSY is not ownership proof.
        assert_eq!(unsafe { cutoff.close(&mut io) }, Ok(())); // Idempotent.
    }
    #[test]
    fn cutoff_attempts_other_ingress_even_if_one_write_fails() {
        for failed_write in [1, 2] {
            let cutoff = IngressCutoff::new(0x20710000, Some(0x20710000)).unwrap();
            let mut io = Mock::new();
            io.registers.insert(WAN, 0x20713333);
            io.registers.insert(0x540, 0x20713333);
            io.ignore_write = Some(failed_write);
            assert_eq!(unsafe { cutoff.close(&mut io) }, Err(CutoffFailure {
                wan: failed_write == 1, mxl: failed_write == 2,
            }));
            assert_eq!(io.writes, 2);
            assert_eq!(io.registers[&if failed_write == 1 { 0x540 } else { WAN }], 0x20710000);
            assert!(!cutoff.closed(&mut io));
            assert_eq!(io.ops.iter().filter(|op| matches!(op, Op::Read(_))).count(), 6);
        }
    }
    #[test]
    fn wan_cutoff_does_not_touch_foreign_mxl_policy() {
        let cutoff = IngressCutoff::new(0x20710000, None).unwrap();
        let mut io = Mock::new();
        io.registers.insert(WAN, 0x20713333);
        io.registers.insert(0x540, 0xdeadbeef);
        assert_eq!(unsafe { cutoff.close(&mut io) }, Ok(()));
        assert!(cutoff.closed(&mut io));
        assert_eq!(io.registers[&0x540], 0xdeadbeef);
        assert!(!io.ops.iter().any(|op| matches!(op, Op::Read(0x540) | Op::Write(0x540, _))));
    }
    #[test]
    fn cutoff_rejects_open_or_unqualified_restore_values() {
        for bad in [0, 0x20713333, 0x20710003, 0x20717777, 0xc0700000, u32::MAX] {
            assert_eq!(IngressCutoff::new(bad, None), Err(Error::Preconditions));
            assert_eq!(IngressCutoff::new(0x20710000, Some(bad)), Err(Error::Preconditions));
        }
    }
    fn router_mock() -> Mock {
        let mut io = Mock::new();
        for (o, v) in [(WAN, 0x20710000), (0x500, 0xc0700000), (0x540, 0x20717777)] {
            io.registers.insert(o, v);
        }
        io
    }
    #[test]
    fn empty_session_admits_wan_last_and_restores_ingress_before_detach() {
        let mut io = router_mock();
        let initial = io.registers.clone();
        let StartOutcome::Active(active) = (unsafe { start_empty(&mut io, table(), 10) }) else {
            panic!("start")
        };
        assert_eq!(
            io.ops
                .iter()
                .filter_map(|op| if let Op::Write(o, v) = op {
                    Some((*o, *v))
                } else {
                    None
                })
                .last(),
            Some((WAN, 0x20713333))
        );
        assert_eq!(io.registers[&TABLE_CONFIG], TABLE_CONFIG_VALUE);
        assert_eq!(io.registers[&0x2204], 0x200e);
        let first_stop = io.ops.len();
        let Outcome::Restored(table) = (unsafe { active.stop(&mut io, 10) }) else {
            panic!("stop")
        };
        assert!(table.is_zero());
        assert_eq!(io.ops[first_stop], Op::Write(WAN, 0x20710000));
        for (o, v) in initial {
            assert_eq!(io.registers[&o], v);
        }
        assert_eq!(io.registers[&TABLE_BASE], 0);
        for (i, op) in io.ops.iter().enumerate() {
            if let Op::Write(o, _) = op {
                assert_eq!(io.ops[i + 1], Op::Barrier);
                assert_eq!(io.ops[i + 2], Op::Read(*o));
            }
        }
    }
    #[test]
    fn empty_session_failures_never_return_storage_after_a_write() {
        // Some writes can be no-ops in inherited state. Force distinct initial
        // auxiliary values so every ignored write is observable.
        for failed in 1..=27 {
            let mut io = router_mock();
            for o in AUX {
                io.registers.insert(o, 0x12345678);
            }
            io.ignore_write = Some(failed);
            let result = unsafe { start_empty(&mut io, table(), 10) };
            let outcome = match result {
                StartOutcome::Active(active) => unsafe { active.stop(&mut io, 10) },
                StartOutcome::Failed(outcome) => outcome,
            };
            assert!(
                matches!(outcome, Outcome::Quarantined(_)),
                "write {failed} not quarantined"
            );
            assert_eq!(io.writes, failed);
        }
    }
    #[test]
    fn empty_session_rejects_foreign_ingress_and_existing_tables_before_writing() {
        for (offset, value) in [
            (WAN, 0x20714444),
            (0x500, 0xc0703333),
            (0x540, 0x20713333),
            (0x2620, 0x40c00000),
            (0x2f20, 1),
        ] {
            let mut io = router_mock();
            io.registers.insert(offset, value);
            assert!(matches!(
                unsafe { start_empty(&mut io, table(), 10) },
                StartOutcome::Failed(Outcome::Rejected(_, Error::Preconditions))
            ));
            assert_eq!(io.writes, 0);
        }
    }
    #[test]
    fn empty_session_busy_timeout_retains_table_and_keeps_ingress_closed() {
        let mut io = router_mock();
        let StartOutcome::Active(active) = (unsafe { start_empty(&mut io, table(), 10) }) else {
            panic!("start")
        };
        io.busy_after = Some(io.writes + 1);
        let Outcome::Quarantined(fault) = (unsafe { active.stop(&mut io, 10) }) else {
            panic!("returned table")
        };
        assert_eq!(fault.error, Error::Timeout);
        assert_eq!(io.registers[&WAN], 0x20710000);
        assert_ne!(io.registers[&TABLE_BASE], 0);
    }
    #[test]
    fn udp_binding_hash_vectors_and_disabled_staging_then_clear() {
        for (source, destination, source_port, destination_port, index) in [
            ([192, 168, 78, 100], [192, 168, 78, 1], 33445, 49152, 0x3938),
            ([8, 8, 8, 8], [203, 0, 113, 9], 53, 49279, 0x2c0c),
            ([1, 2, 3, 4], [198, 51, 100, 9], 65535, 1, 0x241c),
        ] {
            let original = Tuple {
                source,
                destination,
                source_port,
                destination_port,
            };
            let translated = Tuple {
                destination: [192, 168, 79, 100],
                destination_port: 12345,
                ..original
            };
            let binding = NaptBinding::wan_to_lan(
                original,
                translated,
                [2, 0, 0, 0, 0, 1],
                [2, 0, 0, 0, 0, 2],
            )
            .unwrap();
            assert_eq!(binding.index() & 0x3ffc, index);
            assert!(binding.index() < crate::ppe::table::ENTRIES && binding.index() % 4 == 0);
            let mut io = router_mock();
            io.registers.insert(0x10, 0x1234);
            let StartOutcome::Active(active) =
                (unsafe { start_single_napt(&mut io, table(), 10, &binding) })
            else {
                panic!("start")
            };
            // Mock only: no DMA is running; physical code has no such accessor.
            assert_eq!(active.table.nonzero_entries(), 1);
            let bytes = active.table.entry(binding.index()).unwrap();
            assert_eq!(&bytes[..4], &0x60400034u32.to_le_bytes());
            assert_eq!(&bytes[4..], &binding.entry.bytes()[4..]);
            assert!(!active.table.all_invalid());
            let Outcome::Restored(table) = (unsafe { active.stop(&mut io, 10) }) else {
                panic!("stop")
            };
            assert!(table.is_zero());
        }
    }
    fn polling_binding() -> NaptBinding {
        let original = Tuple {
            source: [192, 168, 78, 100],
            destination: [192, 168, 78, 1],
            source_port: 33445,
            destination_port: 49152,
        };
        NaptBinding::wan_to_lan(
            original,
            Tuple {
                destination: [192, 168, 79, 100],
                destination_port: 24567,
                ..original
            },
            [2, 0, 0, 0, 0, 1],
            [2, 0, 0, 0, 0, 2],
        )
        .unwrap()
    }
    fn mxl_binding() -> NaptBinding {
        let original = Tuple { source: [192,168,78,100], destination: [192,168,78,1],
            source_port: 33445, destination_port: 49152 };
        NaptBinding::wan_to_mxl_lan(original,
            Tuple { destination: [192,168,79,100], destination_port: 24567, ..original },
            [2,0,0,0,0,1], [2,0,0,0,0,2]).unwrap()
    }
    fn mxl_mock() -> Mock {
        let mut io = router_mock();
        io.registers.insert(0x500, 0x20717777);
        io.registers.insert(0x540, 0x20710000);
        io.registers.insert(0x548, 0x70040002);
        io.registers.insert(0x54c, 0x0242);
        io
    }
    fn outbound_binding() -> NaptBinding {
        let original = Tuple { source: [192,168,79,100], destination: [192,168,78,100],
            source_port: 24567, destination_port: 33445 };
        NaptBinding::mxl_lan_to_wan(original,
            Tuple { source: [192,168,78,1], source_port: 49152, ..original },
            [2,0x42,0x70,4,0,2], [2,0,0,0,0,1], [2,0,0,0,0,2]).unwrap()
    }
    #[test]
    fn outbound_snat_format_preserves_remote_and_selects_untagged_wan() {
        let binding = outbound_binding();
        assert_eq!(binding.index() & 0x3ffc, 0x374);
        let bytes = binding.entry.bytes();
        assert_eq!(&bytes[0..4], &0x40500000u32.to_le_bytes()); // INVALID UDP, TTL/cache staging.
        assert_eq!(&bytes[4..16], &[0x64,0x4f,0xa8,0xc0, 0x64,0x4e,0xa8,0xc0, 0xa5,0x82,0xf7,0x5f]);
        assert_eq!(&bytes[20..32], &[1,0x4e,0xa8,0xc0, 0x64,0x4e,0xa8,0xc0, 0xa5,0x82,0,0xc0]);
        assert_eq!(&bytes[16..20], &0x00f00400u32.to_le_bytes()); // PSE WAN=2.
        assert_eq!(&bytes[44..48], &[0,0,0,8]); // No output VLAN.
        let original = Tuple { source: [192,168,79,100], destination: [192,168,78,100],
            source_port: 24567, destination_port: 33445 };
        for translated in [Tuple { destination: [192,168,78,99], ..original },
            Tuple { destination_port: 53, ..original }] {
            assert!(matches!(NaptBinding::mxl_lan_to_wan(original, translated,
                [2,0x42,0x70,4,0,2], [2,0,0,0,0,1], [2,0,0,0,0,2]), Err(EncodeError::Address)));
        }
    }
    #[test]
    fn outbound_prepare_resume_retire_edit_stop_owns_only_mxl_admission() {
        let mut io = mxl_mock();
        io.registers.insert(0x10, 0x34);
        let inherited = io.registers.clone();
        let binding = outbound_binding().with_mtu(1200).unwrap();
        let PauseOutcome::Paused(paused) = (unsafe { prepare_single_napt(&mut io, table(), 10, &binding) })
            else { panic!("prepare") };
        assert_eq!(io.registers[&0x540], 0x20710000);
        assert_eq!(io.registers[&0x230c], 1214 | (1218 << 16));
        let ticket = paused.initial_ticket().unwrap();
        let bytes = paused.0.table.entry(ticket.index()).unwrap();
        assert_eq!(&bytes[..4], &0x60400034u32.to_le_bytes());
        assert_eq!(&bytes[4..], &binding.entry.bytes()[4..]);
        let StartOutcome::Active(active) = (unsafe { paused.resume(&mut io) }) else { panic!("resume") };
        assert_eq!(io.registers[&0x540], 0x20713000);
        assert_eq!(io.registers[&WAN], 0x20710000);
        let RetireOutcome::Pending(active) = (unsafe { active.retire_napt(&mut io, ticket) }) else { panic!("retire") };
        assert!(active.retirement_pending(ticket));
        let PauseOutcome::Paused(paused) = (unsafe { active.pause(&mut io, 10) }) else { panic!("pause") };
        assert_eq!(io.registers[&0x540], 0x20710000);
        let EditOutcome::Updated(paused, ()) = (unsafe { paused.remove_napt(&mut io, 10, ticket) }) else { panic!("remove") };
        let EditOutcome::Updated(paused, fresh) = (unsafe { paused.insert_napt(&mut io, 10, &binding) }) else { panic!("insert") };
        assert_ne!(fresh, ticket);
        let StartOutcome::Active(active) = (unsafe { paused.resume(&mut io) }) else { panic!("resume") };
        let begin = io.ops.len();
        let Outcome::Restored(table) = (unsafe { active.stop(&mut io, 10) }) else { panic!("stop") };
        assert!(table.is_zero());
        assert_eq!(io.ops[begin], Op::Write(0x540, 0x20710000));
        for (offset,value) in &io.registers { assert_eq!(*value,*inherited.get(offset).unwrap_or(&0)); }
        assert!(!io.ops.iter().any(|op| matches!(op, Op::Write(WAN, _))));
    }
    #[test]
    fn mxl_sessions_accept_the_builtin_switch_handed_to_software_only() {
        for binding in [mxl_binding(), outbound_binding()] {
            let mut io = mxl_mock(); io.registers.insert(0x500, 0xc0700000);
            let StartOutcome::Active(active) = (unsafe { start_single_napt(&mut io, table(), 10, &binding) }) else { panic!("start") };
            assert!(matches!(unsafe { active.stop(&mut io, 10) }, Outcome::Restored(_)));
            assert_eq!(io.registers[&0x500], 0xc0700000);
            assert!(!io.ops.iter().any(|op| matches!(op, Op::Write(0x500, _))));
        }
        assert!(internal_bypasses(0x20717777) && !internal_bypasses(0x20710000) && !internal_bypasses(0xc0703333));
    }
    #[test]
    fn routed_inside_rule_keeps_the_tuple_and_takes_either_switch_egress() {
        let tuple = Tuple { source: [192,168,79,100], destination: [192,168,20,50], source_port: 40000, destination_port: 53000 };
        let ingress = [2,0x42,0x70,4,0,2];
        let rule = NaptBinding::mxl_lan_to_inside(tuple, ingress, ingress, [2,0,0,0,0,9]).unwrap();
        // Untranslated, in the MxL-ingress table, leaving through GDM3 tagged.
        assert_eq!(rule.path, FlowPath::MxlToWan(ingress));
        assert_eq!(rule.entry.bytes()[4..16], rule.entry.bytes()[20..32]);
        assert_eq!(rule.index(), napt_bucket(tuple));
        let word = |b: &NaptBinding, at: usize| u32::from_le_bytes(b.entry.bytes()[at..at + 4].try_into().unwrap());
        assert_eq!((word(&rule, 16), &rule.entry.bytes()[44..46]), ((15 << 9) | (0xf << 20), &0x0c00u16.to_le_bytes()[..]));
        let tagged = NaptBinding::mxl_lan_to_inside(tuple, ingress, ingress, [2,0,0,0,0,9]).unwrap().with_mxl_alias(3).unwrap();
        assert_eq!(tagged.entry.bytes()[44..46], 0x0c03u16.to_le_bytes());
        let builtin = NaptBinding::mxl_lan_to_inside(tuple, ingress, ingress, [2,0,0,0,0,9]).unwrap().with_builtin_port(0).unwrap();
        assert_eq!((word(&builtin, 16), &builtin.entry.bytes()[44..48]), ((1 << 9) | (0xf << 20), &[0u8, 0, 1, 0][..]));
        assert!(matches!(builtin.path, FlowPath::MxlToWan(_)));
        assert!(matches!(NaptBinding::mxl_lan_to_inside(tuple, [0; 6], ingress, [2,0,0,0,0,9]), Err(EncodeError::Address)));
        // The rule towards the WAN port still takes no switch egress.
        assert!(matches!(outbound_binding().with_mxl_alias(1), Err(EncodeError::UnsupportedEgress)));
    }
    #[test]
    fn rules_of_either_table_take_any_translation_and_every_other_egress() {
        let inside = Tuple { source: [192,168,79,100], destination: [203,0,113,5], source_port: 40000, destination_port: 443 };
        let snat = Tuple { source: [198,51,100,7], source_port: 50001, ..inside };
        let reply = Tuple { source: inside.destination, destination: snat.source, source_port: 443, destination_port: 50001 };
        let dnat = Tuple { destination: inside.source, destination_port: 40000, ..reply };
        let mac = [2,0x42,0x70,4,0,2];
        let word = |b: &NaptBinding, at: usize| u32::from_le_bytes(b.entry.bytes()[at..at + 4].try_into().unwrap());
        // The SoC's port as an inside port: source translation on the way
        // to an uplink behind a switch, which the old shapes refused.
        let out = NaptBinding::direct_ingress(inside, snat, mac, [2,0,0,0,0,9]).unwrap().with_builtin_port(0).unwrap();
        assert_eq!((out.path, out.index()), (FlowPath::WanToMxl, napt_bucket(inside)));
        assert_ne!(out.entry.bytes()[4..16], out.entry.bytes()[20..32]);
        assert!(matches!(NaptBinding::wan_to_mxl_lan(inside, snat, mac, [2,0,0,0,0,9]), Err(EncodeError::Address)));
        assert!(matches!(NaptBinding::direct_ingress(inside, snat, mac, [2,0,0,0,0,9]).unwrap().with_direct_egress(), Err(EncodeError::UnsupportedEgress)));
        // The answer arrives through the switch and leaves untagged by the
        // SoC's port, with the destination translated back.
        let back = NaptBinding::switch_ingress(reply, dnat, mac, mac, [2,0,0,0,0,8]).unwrap().with_direct_egress().unwrap();
        assert_eq!(back.path, FlowPath::MxlToWan(mac));
        assert_eq!(word(&back, 0) & (7 << 14 | 1 << 18), 0);
        assert_eq!((word(&back, 16), &back.entry.bytes()[44..48]), ((2 << 9) | (0xf << 20), &[0u8, 0, 0, 8][..]));
        // Identical to the qualified outbound format when nothing else differs.
        let old = NaptBinding::mxl_lan_to_wan(inside, snat, mac, mac, [2,0,0,0,0,8]).unwrap();
        let new = NaptBinding::switch_ingress(inside, snat, mac, mac, [2,0,0,0,0,8]).unwrap().with_direct_egress().unwrap();
        assert_eq!(old.entry, new.entry);
        // Once it leaves by the SoC's port it takes no switch tag.
        assert!(matches!(new.with_mxl_alias(0), Err(EncodeError::UnsupportedEgress)));
        // Both ends behind switches, translated: the uplink on one of them.
        let both = NaptBinding::switch_ingress(reply, dnat, mac, mac, [2,0,0,0,0,8]).unwrap().with_mxl_alias(2).unwrap();
        assert_eq!(both.entry.bytes()[44..46], 0x0c02u16.to_le_bytes());
        let template = NaptBinding::template(FlowPath::MxlToWan(mac), 1492).unwrap();
        assert_eq!((template.path, template.mtu), (FlowPath::MxlToWan(mac), 1492));
    }
    #[test]
    fn builtin_port_egress_carries_the_switch_port_tag_through_gdm1() {
        let plain = mxl_binding();
        let moved = mxl_binding().with_builtin_port(2).unwrap();
        let word = |b: &NaptBinding, at: usize| u32::from_le_bytes(b.entry.bytes()[at..at + 4].try_into().unwrap());
        // One tag layer, no 802.1Q insertion; PSE port 1; port bitmap as type.
        assert_eq!(word(&moved, 0) & (7 << 14 | 1 << 18), 1 << 14);
        assert_eq!(word(&moved, 0) & !(1 << 18), word(&plain, 0) & !(1 << 18));
        assert_eq!(word(&moved, 16), (1 << 9) | (0xf << 20));
        assert_eq!(moved.entry.bytes()[44..48], [0, 0, 4, 0]);
        assert_eq!((&plain.entry.bytes()[4..16], &plain.entry.bytes()[20..44], &plain.entry.bytes()[48..]),
            (&moved.entry.bytes()[4..16], &moved.entry.bytes()[20..44], &moved.entry.bytes()[48..]));
        assert_eq!((moved.index(), moved.path), (plain.index(), FlowPath::WanToMxl));
        assert!(matches!(mxl_binding().with_builtin_port(6), Err(EncodeError::UnsupportedEgress)));
        assert!(matches!(outbound_binding().with_builtin_port(0), Err(EncodeError::UnsupportedEgress)));
    }
    #[test]
    fn cutoff_returns_a_joined_builtin_switch_to_software_and_leaves_any_other_policy() {
        let cutoff = IngressCutoff::new(0x20710000, Some(0x20710000)).unwrap();
        for (before, after) in [(INTERNAL_ADMIT, INTERNAL_CPU), (INTERNAL_CPU, INTERNAL_CPU), (0x20717777, 0x20717777)] {
            let mut io = Mock::new();
            for (o, v) in [(WAN, 0x20713000), (0x540, 0x20714000), (0x500, before)] { io.registers.insert(o, v); }
            assert!(!cutoff.closed(&mut io));
            assert_eq!(unsafe { cutoff.close(&mut io) }, Ok(()));
            assert_eq!((io.registers[&WAN], io.registers[&0x540], io.registers[&0x500]), (0x20710000, 0x20710000, after));
            assert!(cutoff.closed(&mut io));
            assert_eq!(io.ops.iter().filter(|op| matches!(op, Op::Write(0x500, _))).count(), usize::from(before != after));
        }
        // The WAN-only cutoff never looks at it.
        let mut io = Mock::new();
        io.registers.insert(0x500, INTERNAL_ADMIT);
        assert_eq!(unsafe { IngressCutoff::new(0x20710000, None).unwrap().close(&mut io) }, Ok(()));
        assert_eq!(io.registers[&0x500], INTERNAL_ADMIT);
    }
    #[test]
    fn mxl_alias_selects_only_the_bridge_tag_of_mxl_egress() {
        let plain = mxl_binding();
        let moved = mxl_binding().with_mxl_alias(2).unwrap();
        assert_eq!(moved.entry.bytes()[44..46], 0x0c02u16.to_le_bytes());
        assert_eq!((&plain.entry.bytes()[..44], &plain.entry.bytes()[46..]), (&moved.entry.bytes()[..44], &moved.entry.bytes()[46..]));
        assert_eq!(mxl_binding().with_mxl_alias(0).unwrap().entry, plain.entry);
        assert!(matches!(mxl_binding().with_mxl_alias(4), Err(EncodeError::UnsupportedEgress)));
        assert!(matches!(outbound_binding().with_mxl_alias(0), Err(EncodeError::UnsupportedEgress)));
    }
    #[test]
    fn outbound_rejects_foreign_ingress_and_mixed_direction_without_writes() {
        for (offset, value) in [(WAN,0x20713333),(0x500,0xc0703333),(0x500,0x20710000),(0x540,0x20713333),(0x540,0x20717777),(0x548,0x70040099),(0x54c,0x0342)] {
            let mut io = mxl_mock(); io.registers.insert(offset,value);
            assert!(matches!(unsafe { start_single_napt(&mut io,table(),10,&outbound_binding()) },
                StartOutcome::Failed(Outcome::Rejected(_,Error::Preconditions))));
            assert_eq!(io.writes,0);
        }
        for (first,other) in [(outbound_binding(),mxl_binding()),(mxl_binding(),outbound_binding())] {
            let mut io=mxl_mock();
            let PauseOutcome::Paused(paused)=(unsafe { prepare_single_napt(&mut io,table(),10,&first) }) else {panic!("prepare")};
            let before=io.ops.len();
            let EditOutcome::Rejected(paused,EditError::Egress)=(unsafe {paused.insert_napt(&mut io,10,&other)}) else {panic!("mixed direction")};
            assert_eq!(before,io.ops.len());
            assert!(matches!(unsafe {paused.stop(&mut io,10)},Outcome::Restored(_)));
        }
    }
    #[test]
    fn outbound_resume_and_edit_reject_a_new_foreign_ingress() {
        for edit in [false,true] {
            let mut io=mxl_mock();
            let PauseOutcome::Paused(paused)=(unsafe {prepare_single_napt(&mut io,table(),10,&outbound_binding())}) else {panic!("prepare")};
            let ticket=paused.initial_ticket().unwrap();
            io.registers.insert(WAN,0x20713333);
            let writes=io.writes;
            if edit {assert!(matches!(unsafe {paused.remove_napt(&mut io,10,ticket)},EditOutcome::Failed(Outcome::Quarantined(_))));}
            else {assert!(matches!(unsafe {paused.resume(&mut io)},StartOutcome::Failed(Outcome::Quarantined(_))));}
            assert_eq!(io.writes,writes);
            assert_eq!(io.registers[&0x540],0x20710000);
        }
    }
    #[test]
    fn outbound_mac_change_cannot_resume_or_retire_a_rule() {
        for register in [0x548, 0x54c] {
            for resume in [false, true] {
                let mut io = mxl_mock();
                let PauseOutcome::Paused(paused) = (unsafe {
                    prepare_single_napt(&mut io, table(), 10, &outbound_binding())
                }) else { panic!("prepare") };
                let ticket = paused.initial_ticket().unwrap();
                if resume {
                    *io.registers.get_mut(&register).unwrap() ^= 1;
                    let writes = io.writes;
                    assert!(matches!(unsafe { paused.resume(&mut io) },
                        StartOutcome::Failed(Outcome::Quarantined(_))));
                    assert_eq!(io.writes, writes);
                } else {
                    let StartOutcome::Active(active) = (unsafe { paused.resume(&mut io) })
                        else { panic!("resume") };
                    *io.registers.get_mut(&register).unwrap() ^= 1;
                    let writes = io.writes;
                    assert!(matches!(unsafe { active.retire_napt(&mut io, ticket) },
                        RetireOutcome::Failed(Outcome::Quarantined(_))));
                    assert_eq!(io.writes, writes);
                }
                // Failed ownership never clears/recycles the published table.
                assert_eq!(io.registers[&TABLE_BASE], 0x40c00000);
                assert_eq!(unsafe { IngressCutoff::new(0x20710000, Some(0x20710000))
                    .unwrap().close(&mut io) }, Ok(()));
                assert_eq!(io.registers[&0x540], 0x20710000);
            }
        }
    }
    #[test]
    fn outbound_pause_and_stop_failure_retain_allocation_without_detachment() {
        for stop in [false,true] {
            let mut io=mxl_mock();
            let StartOutcome::Active(active)=(unsafe {start_single_napt(&mut io,table(),10,&outbound_binding())}) else {panic!("start")};
            io.ignore_write=Some(io.writes+1);
            let begin=io.ops.len();
            if stop {assert!(matches!(unsafe {active.stop(&mut io,10)},Outcome::Quarantined(_)));}
            else {assert!(matches!(unsafe {active.pause(&mut io,10)},PauseOutcome::Failed(Outcome::Quarantined(_))));}
            assert_eq!(io.registers[&TABLE_BASE],0x40c00000);
            assert_eq!(io.registers[&0x540],0x20713000);
            assert!(!io.ops[begin..].iter().any(|op| matches!(op,Op::Write(TABLE_BASE,_)|Op::Write(WAN,_))));
            // Caller retains its independent dual cutoff even on failed ownership transition.
            io.ignore_write=None;
            assert_eq!(unsafe {IngressCutoff::new(0x20710000,Some(0x20710000)).unwrap().close(&mut io)},Ok(()));
            assert_eq!(io.registers[&0x540],0x20710000);
        }
    }
    #[test]
    fn mxl_topology_is_required_and_mixed_rules_are_rejected_before_writes() {
        for (mut io, binding) in [(router_mock(), mxl_binding()), (mxl_mock(), polling_binding())] {
            assert!(matches!(unsafe { start_single_napt(&mut io, table(), 10, &binding) },
                StartOutcome::Failed(Outcome::Rejected(_, Error::Preconditions))));
            assert_eq!(io.writes, 0);
        }
        for (mut io, first, other) in [(mxl_mock(), mxl_binding(), polling_binding()),
            (router_mock(), polling_binding(), mxl_binding())] {
            let PauseOutcome::Paused(paused) = (unsafe { prepare_single_napt(&mut io, table(), 10, &first) })
                else { panic!("prepare") };
            let writes = io.writes;
            let EditOutcome::Rejected(paused, EditError::Egress) =
                (unsafe { paused.insert_napt(&mut io, 10, &other) }) else { panic!("mixed LAN") };
            assert_eq!(io.writes, writes);
            assert!(matches!(unsafe { paused.stop(&mut io, 10) }, Outcome::Restored(_)));
        }
    }
    #[test]
    fn mxl_bound_tag_mtu_pause_resume_and_restore() {
        let mut io = mxl_mock();
        let inherited = io.registers.clone();
        io.registers.insert(0x10, 0x34);
        let binding = mxl_binding().with_mtu(1200).unwrap();
        assert_eq!(binding.index(), polling_binding().index());
        let PauseOutcome::Paused(paused) = (unsafe { prepare_single_napt(&mut io, table(), 10, &binding) })
            else { panic!("prepare") };
        assert_eq!(io.registers[&WAN], 0x20710000);
        // Mock has no DMA; verify actual published bytes, not just staging.
        let bytes = paused.0.table.entry(binding.index()).unwrap();
        assert_eq!(&bytes[..4], &0x60444034u32.to_le_bytes());
        assert_eq!(&bytes[16..20], &0x00f01e00u32.to_le_bytes());
        assert_eq!(&bytes[44..48], &0x08000c00u32.to_le_bytes());
        assert_eq!(io.registers[&0x230c], 0x04c204be);
        assert_eq!(io.registers[&0x2308], 0);
        let StartOutcome::Active(active) = (unsafe { paused.resume(&mut io) }) else { panic!("resume") };
        assert_eq!(io.registers[&WAN], 0x20713333);
        let PauseOutcome::Paused(paused) = (unsafe { active.pause(&mut io, 10) }) else { panic!("pause") };
        let Outcome::Restored(storage) = (unsafe { paused.stop(&mut io, 10) }) else { panic!("stop") };
        assert!(storage.is_zero());
        for offset in [WAN, 0x500, 0x540, TABLE_BASE, 0x2308, 0x230c, 0x2310] {
            assert_eq!(io.registers.get(&offset).copied().unwrap_or(0), inherited.get(&offset).copied().unwrap_or(0));
        }
    }
    #[test]
    fn changed_lan_topology_cannot_resume_hardware() {
        for mxl in [false, true] {
            let mut io = if mxl {mxl_mock()} else {router_mock()};
            let binding = if mxl {mxl_binding()} else {polling_binding()};
            let PauseOutcome::Paused(paused) = (unsafe { prepare_single_napt(&mut io, table(), 10, &binding) })
                else { panic!("prepare") };
            io.registers.insert(0x540, 0x20713333);
            let writes = io.writes;
            assert!(matches!(unsafe { paused.resume(&mut io) },
                StartOutcome::Failed(Outcome::Quarantined(_))));
            assert_eq!(io.writes, writes);
            assert_eq!(io.registers[&WAN], 0x20710000);
        }
    }
    fn collision_bindings(count: usize) -> Vec<NaptBinding> {
        let mut found = Vec::new();
        let bucket = polling_binding().index();
        for port in 1..=u16::MAX {
            let original = Tuple {
                source: [192, 168, 78, 100],
                destination: [192, 168, 78, 1],
                source_port: port,
                destination_port: 49152,
            };
            let b = NaptBinding::wan_to_lan(
                original,
                Tuple {
                    destination: [192, 168, 79, 100],
                    destination_port: 24567,
                    ..original
                },
                [2, 0, 0, 0, 0, 1],
                [2, 0, 0, 0, 0, 2],
            )
            .unwrap();
            if b.index() == bucket {
                found.push(b);
                if found.len() == count {
                    return found;
                }
            }
        }
        panic!("insufficient collision vectors")
    }
    #[test]
    fn cleared_ownership_proof_survives_empty_probe_and_bound_lifecycles() {
        let mut io = router_mock();
        let mut table = table();
        for bound in [false, true, false, true] {
            assert!(table.has_zero_proof());
            let result = if bound {
                unsafe { start_single_napt(&mut io, table, 10, &polling_binding()) }
            } else { unsafe { start_empty(&mut io, table, 10) } };
            let StartOutcome::Active(active) = result else { panic!("start") };
            assert!(!active.table.has_zero_proof());
            let Outcome::Restored(restored) = (unsafe { active.stop(&mut io, 10) })
            else { panic!("stop") };
            assert!(restored.has_zero_proof());
            assert!(restored.is_zero());
            table = restored;
        }
        let Outcome::Restored(table) = (unsafe { probe(&mut io, table, 10) })
        else { panic!("probe") };
        assert!(table.has_zero_proof());
        assert!(table.is_zero());
    }

    #[test]
    fn zero_bytes_without_ownership_proof_are_rejected_before_mmio_writes() {
        let mut io = router_mock();
        let mut table = table();
        table.publish(); // Exercise conservative rejection of unknown history.
        assert!(table.is_zero());
        assert!(matches!(unsafe { start_empty(&mut io, table, 10) },
            StartOutcome::Failed(Outcome::Rejected(_, Error::Preconditions))));
        assert_eq!(io.writes, 0);
    }
    #[test]
    fn prepared_rule_never_opens_wan_before_explicit_resume() {
        let mut io = router_mock();
        let binding = polling_binding();
        let PauseOutcome::Paused(paused) =
            (unsafe { prepare_single_napt(&mut io, table(), 10, &binding) })
        else { panic!("prepare") };
        assert_eq!(io.read(WAN), 0x20710000);
        assert_eq!(io.read(TABLE_BASE), 0x40c00000);
        assert!(paused.initial_ticket().is_some());
        assert!(!io.ops.iter().any(|op| matches!(op, Op::Write(WAN, _))));
        let StartOutcome::Active(active) = (unsafe { paused.resume(&mut io) })
        else { panic!("resume") };
        assert_eq!(io.read(WAN), 0x20713333);
        let Outcome::Restored(table) = (unsafe { active.stop(&mut io, 10) })
        else { panic!("stop") };
        assert!(table.is_zero());
    }
    #[test]
    fn preparation_enable_failures_quarantine_without_opening_ingress() {
        let binding = polling_binding();
        let mut reference = router_mock();
        assert!(matches!(unsafe { prepare_single_napt(&mut reference, table(), 10, &binding) }, PauseOutcome::Paused(_)));
        let final_write = reference.writes;
        for busy in [false, true] {
            let mut io = router_mock();
            if busy { io.busy_after = Some(final_write); }
            else { io.ignore_write = Some(final_write); }
            assert!(matches!(unsafe { prepare_single_napt(&mut io, table(), 10, &binding) },
                PauseOutcome::Failed(Outcome::Quarantined(_))));
            assert_eq!(io.read(WAN), 0x20710000);
            assert_eq!(io.read(TABLE_BASE), 0x40c00000);
            assert!(!io.ops.iter().any(|op| matches!(op, Op::Write(WAN, _))));
        }
    }
    #[test]
    fn live_retirement_preserves_peers_and_reserves_slot_until_drained_removal() {
        let mut io = router_mock();
        let bindings = collision_bindings(2);
        let StartOutcome::Active(active) = (unsafe { start_single_napt(&mut io, table(), 10, &bindings[0]) }) else { panic!("start") };
        let first = active.initial_ticket().unwrap();
        let PauseOutcome::Paused(paused) = (unsafe { active.pause(&mut io, 10) }) else { panic!("pause") };
        let EditOutcome::Updated(paused, peer) = (unsafe { paused.insert_napt(&mut io, 10, &bindings[1]) }) else { panic!("insert") };
        let StartOutcome::Active(active) = (unsafe { paused.resume(&mut io) }) else { panic!("resume") };
        let before = active.table.bytes_for_test().to_vec();
        let registers = io.registers.clone();
        io.ops.clear();
        let clock = io.clock;
        // Unrelated traffic may keep BUSY asserted. Retirement must neither
        // wait for global idle nor close/reopen any configuration register.
        io.busy_after = Some(io.writes);
        let RetireOutcome::Pending(active) = (unsafe { active.retire_napt(&mut io, first) }) else { panic!("retire") };
        assert!(active.retirement_pending(first));
        assert!(!active.retirement_pending(peer));
        assert_eq!(io.clock, clock);
        assert_eq!(io.registers, registers);
        assert!(!io.ops.iter().any(|op| matches!(op, Op::Write(..))));
        assert!(io.ops.contains(&Op::Barrier));
        let mut expected = before;
        expected[first.index * super::super::ENTRY_BYTES + 3] &= !0x30;
        assert_eq!(active.table.bytes_for_test(), expected);
        let begin = io.ops.len();
        let RetireOutcome::Rejected(active, RetireError::AlreadyPending) = (unsafe { active.retire_napt(&mut io, first) }) else { panic!("duplicate retirement") };
        assert_eq!(io.ops.len(), begin);
        io.busy_after = None;
        let PauseOutcome::Paused(paused) = (unsafe { active.pause(&mut io, 10) }) else { panic!("drain") };
        let EditOutcome::Rejected(paused, EditError::Duplicate) = (unsafe { paused.insert_napt(&mut io, 10, &bindings[0]) }) else { panic!("retiring key reused") };
        let EditOutcome::Updated(paused, ()) = (unsafe { paused.remove_napt(&mut io, 10, first) }) else { panic!("remove") };
        let EditOutcome::Updated(paused, successor) = (unsafe { paused.insert_napt(&mut io, 10, &bindings[0]) }) else { panic!("reuse after drain") };
        assert_eq!(first.index(), successor.index());
        assert_ne!(first, successor);
        let StartOutcome::Active(active) = (unsafe { paused.resume(&mut io) }) else { panic!("resume") };
        let before = active.table.bytes_for_test().to_vec();
        let begin = io.ops.len();
        let RetireOutcome::Rejected(active, RetireError::Stale) = (unsafe { active.retire_napt(&mut io, first) }) else { panic!("stale ticket") };
        assert_eq!(io.ops.len(), begin);
        assert_eq!(active.table.bytes_for_test(), before);
        assert!(!active.retirement_pending(successor));
        assert!(matches!(unsafe { active.stop(&mut io, 10) }, Outcome::Restored(_)));
    }

    #[test]
    fn tcp_and_udp_same_tuple_have_independent_slots_and_retirement() {
        let mut io = router_mock();
        let udp = polling_binding();
        let tcp = polling_binding().with_protocol(Protocol::Tcp);
        assert_eq!(udp.index(), tcp.index());
        assert_ne!(udp.key(), tcp.key());
        let PauseOutcome::Paused(p) = (unsafe { prepare_single_napt(&mut io, table(), 10, &udp) }) else { panic!("prepare") };
        let udp_ticket = p.initial_ticket().unwrap();
        let EditOutcome::Updated(p, tcp_ticket) = (unsafe { p.insert_napt(&mut io, 10, &tcp) }) else { panic!("insert tcp") };
        assert_ne!(udp_ticket.index(), tcp_ticket.index());
        let EditOutcome::Rejected(p, EditError::Duplicate) = (unsafe { p.insert_napt(&mut io, 10, &tcp) }) else { panic!("duplicate tcp") };
        let StartOutcome::Active(a) = (unsafe { p.resume(&mut io) }) else { panic!("resume") };
        let udp_before = a.table.entry(udp_ticket.index()).unwrap().to_vec();
        let tcp_before = a.table.entry(tcp_ticket.index()).unwrap().to_vec();
        assert_eq!(udp_before[3] & 0x70, 0x60);
        assert_eq!(tcp_before[3] & 0x70, 0x20);
        let RetireOutcome::Pending(a) = (unsafe { a.retire_napt(&mut io, tcp_ticket) }) else { panic!("retire tcp") };
        assert_eq!(a.table.entry(udp_ticket.index()).unwrap(), udp_before);
        let mut expected = tcp_before;
        expected[3] &= !0x30;
        assert_eq!(a.table.entry(tcp_ticket.index()).unwrap(), expected);
        let PauseOutcome::Paused(p) = (unsafe { a.pause(&mut io, 10) }) else { panic!("pause") };
        let EditOutcome::Updated(p, ()) = (unsafe { p.remove_napt(&mut io, 10, tcp_ticket) }) else { panic!("remove") };
        let EditOutcome::Updated(p, new) = (unsafe { p.insert_napt(&mut io, 10, &tcp) }) else { panic!("replace") };
        assert_eq!(new.index(), tcp_ticket.index());
        assert_ne!(new, tcp_ticket);
        let StartOutcome::Active(a) = (unsafe { p.resume(&mut io) }) else { panic!("resume") };
        let RetireOutcome::Rejected(a, RetireError::Stale) = (unsafe { a.retire_napt(&mut io, tcp_ticket) }) else { panic!("stale") };
        assert!(matches!(unsafe { a.stop(&mut io, 10) }, Outcome::Restored(_)));
    }

    #[test]
    fn live_retirement_quarantines_changed_cache_policy_without_writes() {
        let mut io = router_mock();
        let binding = collision_bindings(1).remove(0);
        let StartOutcome::Active(active) = (unsafe { start_single_napt(&mut io, table(), 10, &binding) }) else { panic!("start") };
        let ticket = active.initial_ticket().unwrap();
        let before = active.table.bytes_for_test().to_vec();
        io.registers.insert(0x2320, 1);
        io.ops.clear();
        let RetireOutcome::Failed(Outcome::Quarantined(q)) = (unsafe { active.retire_napt(&mut io, ticket) }) else { panic!("unsafe cache policy") };
        assert_eq!(q._table.bytes_for_test(), before);
        assert!(!io.ops.iter().any(|op| matches!(op, Op::Write(..))));
    }

    #[test]
    fn incremental_four_way_collision_and_ticket_reuse_are_isolated() {
        let mut io = router_mock();
        let bindings = collision_bindings(5);
        let StartOutcome::Active(active) =
            (unsafe { start_single_napt(&mut io, table(), 10, &bindings[0]) })
        else {
            panic!("start")
        };
        let first = active.initial_ticket().unwrap();
        let PauseOutcome::Paused(mut paused) = (unsafe { active.pause(&mut io, 10) }) else {
            panic!("pause")
        };
        let mut tickets = std::vec![first];
        for binding in &bindings[1..4] {
            let begin = io.ops.len();
            let EditOutcome::Updated(next, ticket) =
                (unsafe { paused.insert_napt(&mut io, 10, binding) })
            else {
                panic!("insert")
            };
            paused = next;
            tickets.push(ticket);
            let writes: Vec<_> = io.ops[begin..]
                .iter()
                .filter_map(|op| {
                    if let Op::Write(o, _) = op {
                        Some(*o)
                    } else {
                        None
                    }
                })
                .collect();
            assert_eq!(
                writes,
                [GLOBAL, GLOBAL],
                "incremental edit must not republish base or ingress"
            );
            assert_eq!(io.registers[&WAN], 0x20710000);
        }
        assert_eq!(
            tickets.iter().map(|t| t.index()).collect::<Vec<_>>(),
            (bindings[0].index()..bindings[0].index() + 4).collect::<Vec<_>>()
        );
        let before = paused.0.table.bytes_for_test().to_vec();
        let writes = io.writes;
        let EditOutcome::Rejected(next, EditError::Duplicate) =
            (unsafe { paused.insert_napt(&mut io, 10, &bindings[1]) })
        else {
            panic!("duplicate")
        };
        paused = next;
        let EditOutcome::Rejected(next, EditError::BucketFull) =
            (unsafe { paused.insert_napt(&mut io, 10, &bindings[4]) })
        else {
            panic!("bucket")
        };
        paused = next;
        assert_eq!(io.writes, writes);
        assert_eq!(paused.0.table.bytes_for_test(), before);
        let EditOutcome::Updated(next, ()) =
            (unsafe { paused.remove_napt(&mut io, 10, tickets[1]) })
        else {
            panic!("remove")
        };
        paused = next;
        assert!(paused
            .0
            .table
            .entry(tickets[1].index())
            .unwrap()
            .iter()
            .all(|b| *b == 0));
        for t in [tickets[0], tickets[2], tickets[3]] {
            assert_eq!(
                paused.0.table.entry(t.index()).unwrap(),
                &before[t.index() * 128..(t.index() + 1) * 128]
            );
        }
        let EditOutcome::Updated(next, reused) =
            (unsafe { paused.insert_napt(&mut io, 10, &bindings[4]) })
        else {
            panic!("reuse")
        };
        paused = next;
        assert_eq!(reused.index(), tickets[1].index());
        assert_ne!(reused, tickets[1]);
        let writes = io.writes;
        let EditOutcome::Rejected(next, EditError::Stale) =
            (unsafe { paused.remove_napt(&mut io, 10, tickets[1]) })
        else {
            panic!("stale")
        };
        paused = next;
        assert_eq!(io.writes, writes);
        assert_eq!(paused.0.table.nonzero_entries(), 4);
        let Outcome::Restored(storage) = (unsafe { paused.stop(&mut io, 10) }) else {
            panic!("stop")
        };
        assert!(storage.is_zero());
    }
    // The full-table geometry has no budget below its bucket ways; see
    // full_table_fills_every_usable_slot_and_never_the_last.
    #[cfg(not(feature = "ppe-32k"))]
    #[test]
    fn incremental_budget_mtu_and_foreign_ticket_reject_without_mutation() {
        let mut bindings = Vec::new();
        for port in 1..=u16::MAX {
            let original = Tuple {
                source: [192, 168, 78, 100],
                destination: [192, 168, 78, 1],
                source_port: port,
                destination_port: 49152,
            };
            let b = NaptBinding::wan_to_lan(
                original,
                Tuple {
                    destination: [192, 168, 79, 100],
                    destination_port: 24567,
                    ..original
                },
                [2, 0, 0, 0, 0, 1],
                [2, 0, 0, 0, 0, 2],
            )
            .unwrap();
            if !bindings
                .iter()
                .any(|old: &NaptBinding| old.index() == b.index())
            {
                bindings.push(b);
            }
            if bindings.len() == MAX_RULES + 1 {
                break;
            }
        }
        assert_eq!(bindings.len(), MAX_RULES + 1);
        let mut old_io = router_mock();
        let StartOutcome::Active(old) =
            (unsafe { start_single_napt(&mut old_io, table(), 10, &bindings[0]) })
        else {
            panic!("old start")
        };
        let old_ticket = old.initial_ticket().unwrap();
        assert!(matches!(
            unsafe { old.stop(&mut old_io, 10) },
            Outcome::Restored(_)
        ));
        let mut io = router_mock();
        let StartOutcome::Active(active) =
            (unsafe { start_single_napt(&mut io, table(), 10, &bindings[0]) })
        else {
            panic!("start")
        };
        let current = active.initial_ticket().unwrap();
        assert_ne!(current, old_ticket);
        let PauseOutcome::Paused(mut paused) = (unsafe { active.pause(&mut io, 10) }) else {
            panic!("pause")
        };
        for b in &bindings[1..MAX_RULES] {
            let EditOutcome::Updated(next, _) = (unsafe { paused.insert_napt(&mut io, 10, b) })
            else {
                panic!("insert")
            };
            paused = next;
        }
        let writes = io.writes;
        let before = paused.0.table.bytes_for_test().to_vec();
        let mut different_mtu = polling_binding();
        different_mtu.mtu = 1200;
        let EditOutcome::Rejected(next, EditError::Mtu) =
            (unsafe { paused.insert_napt(&mut io, 10, &different_mtu) })
        else {
            panic!("mtu")
        };
        paused = next;
        let EditOutcome::Rejected(next, EditError::Capacity) =
            (unsafe { paused.insert_napt(&mut io, 10, &bindings[MAX_RULES]) })
        else {
            panic!("quota")
        };
        paused = next;
        let EditOutcome::Rejected(next, EditError::Stale) =
            (unsafe { paused.remove_napt(&mut io, 10, old_ticket) })
        else {
            panic!("foreign")
        };
        paused = next;
        assert_eq!(io.writes, writes);
        assert_eq!(paused.0.table.bytes_for_test(), before);
        let EditOutcome::Updated(next, ()) = (unsafe { paused.remove_napt(&mut io, 10, current) })
        else {
            panic!("remove")
        };
        paused = next;
        let EditOutcome::Updated(next, _) =
            (unsafe { paused.insert_napt(&mut io, 10, &bindings[MAX_RULES]) })
        else {
            panic!("freed budget")
        };
        paused = next;
        assert_eq!(paused.0.table.nonzero_entries(), MAX_RULES);
        assert!(matches!(
            unsafe { paused.stop(&mut io, 10) },
            Outcome::Restored(_)
        ));
    }
    #[test]
    fn incremental_edit_faults_retain_allocation_with_ingress_closed() {
        for removal in [false, true] {
            for failure in 0..4 {
                let mut io = router_mock();
                let bindings = collision_bindings(2);
                let StartOutcome::Active(active) =
                    (unsafe { start_single_napt(&mut io, table(), 10, &bindings[0]) })
                else {
                    panic!("start")
                };
                let ticket = active.initial_ticket().unwrap();
                let PauseOutcome::Paused(paused) = (unsafe { active.pause(&mut io, 10) }) else {
                    panic!("pause")
                };
                match failure {
                    0 => io.ignore_write = Some(io.writes + 1),
                    1 => io.ignore_write = Some(io.writes + 2),
                    2 => io.busy_after = Some(io.writes + 1),
                    _ => {
                        io.registers.insert(0x2320, 1);
                    }
                }
                let outcome = if removal {
                    match unsafe { paused.remove_napt(&mut io, 10, ticket) } {
                        EditOutcome::Failed(o) => o,
                        _ => panic!("remove accepted"),
                    }
                } else {
                    match unsafe { paused.insert_napt(&mut io, 10, &bindings[1]) } {
                        EditOutcome::Failed(o) => o,
                        _ => panic!("insert accepted"),
                    }
                };
                assert!(matches!(outcome, Outcome::Quarantined(_)));
                assert_eq!(io.registers[&WAN], 0x20710000);
                assert_ne!(io.registers[&TABLE_BASE], 0);
            }
        }
    }
    #[test]
    fn pause_drains_before_software_mutation_and_resume_preserves_bound_storage() {
        let mut io = router_mock();
        let binding = polling_binding();
        let StartOutcome::Active(mut active) =
            (unsafe { start_single_napt(&mut io, table(), 10, &binding) })
        else {
            panic!("start");
        };
        let base = io.registers[&TABLE_BASE];
        let entry = active.table.entry(binding.index()).unwrap().to_vec();
        for _ in 0..4 {
            let begin = io.ops.len();
            let PauseOutcome::Paused(paused) = (unsafe { active.pause(&mut io, 10) }) else {
                panic!("pause");
            };
            assert_eq!(io.ops[begin], Op::Write(WAN, 0x20710000));
            assert_eq!(io.ops.last(), Some(&Op::Barrier));
            assert_eq!(paused.0.table.nonzero_entries(), 1);
            assert_eq!(paused.0.table.entry(binding.index()).unwrap(), entry);
            assert_eq!(io.registers[&TABLE_BASE], base);
            let StartOutcome::Active(resumed) = (unsafe { paused.resume(&mut io) }) else {
                panic!("resume");
            };
            active = resumed;
            let writes: Vec<_> = io.ops[begin..]
                .iter()
                .filter_map(|op| {
                    if let Op::Write(o, v) = op {
                        Some((*o, *v))
                    } else {
                        None
                    }
                })
                .collect();
            assert_eq!(writes, [(WAN, 0x20710000), (WAN, 0x20713333)]);
        }
        let PauseOutcome::Paused(paused) = (unsafe { active.pause(&mut io, 10) }) else {
            panic!("pause");
        };
        let Outcome::Restored(storage) = (unsafe { paused.stop(&mut io, 10) }) else {
            panic!("stop");
        };
        assert!(storage.is_zero());
        assert_eq!(io.registers[&TABLE_BASE], 0);
    }
    #[test]
    fn pause_resume_failure_never_recycles_published_rule() {
        for failure in 0..5 {
            let mut io = router_mock();
            let StartOutcome::Active(active) =
                (unsafe { start_single_napt(&mut io, table(), 10, &polling_binding()) })
            else {
                panic!("start");
            };
            if failure == 0 {
                io.ignore_write = Some(io.writes + 1);
            }
            if failure == 1 {
                io.busy_after = Some(io.writes + 1);
            }
            let outcome = match unsafe { active.pause(&mut io, if failure == 4 { 0 } else { 10 }) }
            {
                PauseOutcome::Failed(outcome) => outcome,
                PauseOutcome::Paused(paused) => {
                    if failure == 2 {
                        io.ignore_write = Some(io.writes + 1);
                    }
                    if failure == 3 {
                        io.registers.insert(WAN, 0x20714444);
                    }
                    match unsafe { paused.resume(&mut io) } {
                        StartOutcome::Failed(outcome) => outcome,
                        StartOutcome::Active(_) => panic!("failure {failure} accepted"),
                    }
                }
            };
            let Outcome::Quarantined(fault) = outcome else {
                panic!("returned allocation");
            };
            assert_eq!(fault._table.nonzero_entries(), 1);
            assert_ne!(io.registers[&TABLE_BASE], 0);
        }
    }
    #[test]
    fn binding_mtu_limits_punt_oversize_and_restore_inherited_registers() {
        let original = Tuple {
            source: [192, 168, 78, 100],
            destination: [192, 168, 78, 1],
            source_port: 33445,
            destination_port: 49152,
        };
        let binding = || {
            NaptBinding::wan_to_lan(
                original,
                Tuple {
                    destination: [192, 168, 79, 100],
                    destination_port: 12345,
                    ..original
                },
                [2, 0, 0, 0, 0, 1],
                [2, 0, 0, 0, 0, 2],
            )
            .unwrap()
        };
        for mtu in [0, 575, 1501, u16::MAX] {
            assert!(matches!(binding().with_mtu(mtu), Err(EncodeError::Mtu)));
        }
        for (mtu, zero_one_tags, two_three_tags) in [
            (576, 0x0252024e, 0x025a0256),
            (1200, 0x04c204be, 0x04ca04c6),
            (1500, 0x05ee05ea, 0x05f605f2),
        ] {
            let mut io = router_mock();
            let inherited = [
                (0x2308, 0xffffffff),
                (0x230c, 0x24002400),
                (0x2310, 0x24082404),
            ];
            for (offset, value) in inherited {
                io.registers.insert(offset, value);
            }
            let configured = binding().with_mtu(mtu).unwrap();
            let StartOutcome::Active(active) =
                (unsafe { start_single_napt(&mut io, table(), 10, &configured) })
            else {
                panic!("start");
            };
            assert_eq!(
                io.registers[&0x2308], 0,
                "oversize must punt instead of drop"
            );
            assert_eq!(io.registers[&0x230c], zero_one_tags);
            assert_eq!(io.registers[&0x2310], two_three_tags);
            assert!(matches!(
                unsafe { active.stop(&mut io, 10) },
                Outcome::Restored(_)
            ));
            for (offset, value) in inherited {
                assert_eq!(io.registers[&offset], value);
            }
        }
    }
    #[test]
    fn bound_entry_is_retained_on_failed_withdrawal_and_cannot_change_remote() {
        let original = Tuple {
            source: [192, 168, 78, 100],
            destination: [192, 168, 78, 1],
            source_port: 33445,
            destination_port: 49152,
        };
        let translated = Tuple {
            destination: [192, 168, 79, 100],
            destination_port: 12345,
            ..original
        };
        assert!(NaptBinding::wan_to_lan(
            original,
            Tuple {
                source_port: 1,
                ..translated
            },
            [2, 0, 0, 0, 0, 1],
            [2, 0, 0, 0, 0, 2]
        )
        .is_err());
        let binding =
            NaptBinding::wan_to_lan(original, translated, [2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
                .unwrap();
        let mut io = router_mock();
        let StartOutcome::Active(active) =
            (unsafe { start_single_napt(&mut io, table(), 10, &binding) })
        else {
            panic!("start")
        };
        io.ignore_write = Some(io.writes + 1);
        let Outcome::Quarantined(fault) = (unsafe { active.stop(&mut io, 10) }) else {
            panic!("returned CPU storage")
        };
        assert!(matches!(fault.error, Error::Readback { offset: WAN }));
        assert_eq!(fault._table.nonzero_entries(), 1);
        assert!(!fault._table.all_invalid());
    }
    #[test]
    fn ppe1_outbound_lifecycle_keeps_other_engines_untouched() {
        let mut io = mxl_mock();
        let original = io.registers.clone();
        let binding = outbound_binding();
        let PauseOutcome::Paused(paused) = (unsafe {
            prepare_single_napt_on(&mut io, table(), 10, &binding, Engine::Ppe1)
        }) else { panic!("prepare PPE1") };
        assert_eq!(io.registers[&0x2620], 0x40c00000);
        assert_eq!(io.registers[&0x540], 0x20710000);
        let ticket = paused.initial_ticket().unwrap();
        let StartOutcome::Active(active) = (unsafe { paused.resume(&mut io) }) else { panic!("resume") };
        assert_eq!(io.registers[&0x540], 0x20714000);
        let writes = io.writes;
        let RetireOutcome::Pending(active) = (unsafe { active.retire_napt(&mut io, ticket) }) else { panic!("retire") };
        assert_eq!(io.writes, writes);
        let PauseOutcome::Paused(paused) = (unsafe { active.pause(&mut io, 10) }) else { panic!("pause") };
        let EditOutcome::Updated(paused, ()) = (unsafe { paused.remove_napt(&mut io, 10, ticket) }) else { panic!("remove") };
        let EditOutcome::Updated(paused, _) = (unsafe { paused.insert_napt(&mut io, 10, &binding) }) else { panic!("insert") };
        let StartOutcome::Active(active) = (unsafe { paused.resume(&mut io) }) else { panic!("resume 2") };
        let Outcome::Restored(table) = (unsafe { active.stop(&mut io, 10) }) else { panic!("stop") };
        assert!(table.is_zero());
        for (offset, value) in &io.registers { assert_eq!(*value, *original.get(offset).unwrap_or(&0)); }
        assert!(io.ops.iter().all(|op| match op {
            Op::Write(offset, _) => *offset == 0x540 || (0x2600..0x2800).contains(offset),
            _ => true,
        }));
    }
    #[test]
    fn ppe1_rejects_foreign_tables_and_unsupported_direction_before_writes() {
        for engine in Engine::ALL {
            let mut io = mxl_mock();
            io.registers.insert(engine.offset() + 0x220, 0x42000000);
            assert!(matches!(unsafe { start_single_napt_on(&mut io, table(), 10, &outbound_binding(), Engine::Ppe1) },
                StartOutcome::Failed(Outcome::Rejected(_, Error::Preconditions))));
            assert_eq!(io.writes, 0);
        }
        for (engine, binding) in [(Engine::Ppe1, mxl_binding()), (Engine::Ppe2, outbound_binding())] {
            let mut io = mxl_mock();
            assert!(matches!(unsafe { start_single_napt_on(&mut io, table(), 10, &binding, engine) },
                StartOutcome::Failed(Outcome::Rejected(_, Error::Preconditions))));
            assert_eq!(io.writes, 0);
        }
    }
    #[test]
    fn ppe1_failed_detach_retains_storage_and_uses_physical_error_offset() {
        let mut io = mxl_mock();
        let StartOutcome::Active(active) = (unsafe { start_single_napt_on(&mut io, table(), 10, &outbound_binding(), Engine::Ppe1) }) else { panic!("start") };
        // stop: close ingress, disable, restore flow, detach.
        io.ignore_write = Some(io.writes + 4);
        let Outcome::Quarantined(q) = (unsafe { active.stop(&mut io, 10) }) else { panic!("detached") };
        assert_eq!(q.error, Error::Readback { offset: 0x2620 });
        assert_eq!(io.registers[&0x540], 0x20710000);
        assert_eq!(io.registers[&0x2620], 0x40c00000);
        assert_eq!(q._table.nonzero_entries(), 1);
    }

    #[test]
    fn ppe1_busy_pause_closes_ingress_and_never_detaches() {
        let mut io = mxl_mock();
        let StartOutcome::Active(active) = (unsafe { start_single_napt_on(&mut io, table(), 10, &outbound_binding(), Engine::Ppe1) }) else { panic!("start") };
        io.busy_after = Some(io.writes + 1);
        io.clock = u64::MAX - 2;
        let begin = io.ops.len();
        let PauseOutcome::Failed(Outcome::Quarantined(q)) = (unsafe { active.pause(&mut io, 10) }) else { panic!("busy") };
        assert_eq!(q.error, Error::Timeout);
        assert_eq!(io.registers[&0x540], 0x20710000);
        assert_eq!(io.registers[&0x2620], 0x40c00000);
        assert!(io.ops.len() - begin < 100);
        assert!(io.ops[begin..].iter().all(|op| !matches!(op, Op::Write(0x2620, _))));
    }

    #[cfg(feature = "ppe-32k")]
    fn spread_binding(n: u32) -> NaptBinding {
        let mixed = n.wrapping_mul(0x9e37_79b1) ^ (n >> 7);
        let original = Tuple {
            source: [198, (mixed >> 16) as u8, (mixed >> 8) as u8, mixed as u8 | 1],
            destination: [192, 168, 78, 1],
            source_port: (n.wrapping_mul(40503) >> 3) as u16 | 1,
            destination_port: 49152 + (mixed >> 18) as u16,
        };
        NaptBinding::wan_to_lan(
            original,
            Tuple { destination: [192, 168, 79, 100], destination_port: 24567, ..original },
            [2, 0, 0, 0, 0, 1],
            [2, 0, 0, 0, 0, 2],
        )
        .unwrap()
    }
    // The capacity fixture's bucket function forwarded on the board in every
    // slot but the last; the session's hash must select the same buckets.
    #[cfg(all(feature = "ppe-32k", feature = "ppe-capacity-test"))]
    #[test]
    fn full_table_hash_matches_the_hardware_qualified_fixture() {
        use crate::ppe::capacity;
        for port in capacity::FIRST_PORT..capacity::FIRST_PORT + capacity::ENTRIES as u16 {
            for outbound in [false, true] {
                let (tuple, _) = capacity::recipe(outbound, port);
                assert_eq!(napt_bucket(tuple), capacity::bucket(tuple));
            }
        }
        for n in 0..100_000 {
            let binding = spread_binding(n);
            let bytes = binding.entry.bytes();
            let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            let tuple = Tuple {
                source: word(4).to_be_bytes(),
                destination: word(8).to_be_bytes(),
                source_port: (word(12) >> 16) as u16,
                destination_port: word(12) as u16,
            };
            assert_eq!(binding.index(), capacity::bucket(tuple));
        }
    }
    #[cfg(feature = "ppe-32k")]
    #[test]
    fn full_table_fills_every_usable_slot_and_never_the_last() {
        use crate::ppe::table::ENTRIES;
        assert_eq!((ENTRIES, MAX_RULES, TABLE_CONFIG_VALUE), (32768, 32767, 0x0010_4025));
        let mut io = router_mock();
        let first = spread_binding(0);
        let StartOutcome::Active(active) = (unsafe { start_single_napt(&mut io, table(), 10, &first) })
        else { panic!("start") };
        assert_eq!(io.registers[&TABLE_CONFIG], 0x0010_4025);
        let PauseOutcome::Paused(mut paused) = (unsafe { active.pause(&mut io, 10) }) else { panic!("pause") };
        let mut tickets = std::vec![paused.initial_ticket().unwrap()];
        let mut full = 0usize;
        for n in 1..2_000_000u32 {
            io.ops.clear();
            let binding = spread_binding(n);
            paused = match unsafe { paused.insert_napt(&mut io, 10, &binding) } {
                EditOutcome::Updated(p, ticket) => {
                    assert!(ticket.index() >= binding.index() && ticket.index() < binding.index() + 4);
                    assert_ne!(ticket.index(), ENTRIES - 1);
                    tickets.push(ticket);
                    p
                }
                EditOutcome::Rejected(p, EditError::BucketFull) => { full += 1; p }
                EditOutcome::Rejected(p, EditError::Duplicate) => p,
                EditOutcome::Rejected(_, error) => panic!("unexpected rejection {error:?}"),
                EditOutcome::Failed(_) => panic!("edit"),
            };
            if tickets.len() == MAX_RULES { break; }
        }
        assert_eq!(tickets.len(), MAX_RULES);
        assert!(full > 0);
        assert_eq!(paused.0.rules.len(), MAX_RULES);
        assert_eq!(paused.0.table.nonzero_entries(), MAX_RULES);
        assert!(paused.0.table.entry(ENTRIES - 1).unwrap().iter().all(|b| *b == 0));
        let mut slots: Vec<usize> = tickets.iter().map(|t| t.index()).collect();
        slots.sort_unstable();
        slots.dedup();
        assert_eq!(slots.len(), MAX_RULES);
        // A full table rejects further rules without touching hardware.
        io.ops.clear();
        let writes = io.writes;
        let mut rejected = false;
        for n in 2_000_000..2_000_064u32 {
            paused = match unsafe { paused.insert_napt(&mut io, 10, &spread_binding(n)) } {
                EditOutcome::Rejected(p, EditError::Capacity | EditError::BucketFull | EditError::Duplicate) => { rejected = true; p }
                _ => panic!("full table accepted a rule"),
            };
        }
        assert!(rejected && io.writes == writes);
        // Batch validation is all-or-nothing: duplicates and stale tickets
        // leave every record and byte in place.
        let mut bad = tickets[..1000].to_vec();
        bad.push(tickets[3]);
        paused = match unsafe { paused.remove_many(&mut io, 10, bad.iter().copied()) } {
            EditOutcome::Rejected(p, EditError::Duplicate) => p,
            _ => panic!("duplicate batch"),
        };
        assert_eq!((paused.0.rules.len(), io.writes), (MAX_RULES, writes));
        paused = match unsafe { paused.remove_many(&mut io, 10, tickets[..20_000].iter().copied()) } {
            EditOutcome::Updated(p, ()) => p,
            _ => panic!("batch removal"),
        };
        assert_eq!(paused.0.rules.len(), MAX_RULES - 20_000);
        assert_eq!(paused.0.table.nonzero_entries(), MAX_RULES - 20_000);
        paused = match unsafe { paused.remove_many(&mut io, 10, tickets[19_999..20_001].iter().copied()) } {
            EditOutcome::Rejected(p, EditError::Stale) => p,
            _ => panic!("stale batch"),
        };
        assert_eq!(paused.0.rules.len(), MAX_RULES - 20_000);
        // A freed slot is reusable under a fresh identity only.
        let again = spread_binding(0);
        paused = match unsafe { paused.insert_napt(&mut io, 10, &again) } {
            EditOutcome::Updated(p, ticket) => { assert_ne!(ticket, tickets[0]); assert_eq!(ticket.index(), tickets[0].index()); p }
            _ => panic!("reuse"),
        };
        assert!(matches!(unsafe { paused.stop(&mut io, 10) }, Outcome::Restored(t) if t.is_zero()));
    }
}
