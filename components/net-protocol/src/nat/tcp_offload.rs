//! Explicit connection-level TCP offload authority. Default NAT stays strict.
use super::*;

/// Exact TCP address/port tuple; protocol is carried by TcpPermit.
pub type TcpTuple = UdpTuple;

/// A committed established TCP packet, not independent hardware authority.
/// Copies have fixed lifetimes and a connection incarnation distinct from the
/// endpoint-independent mapping generation. Closing/reopening the same tuple
/// cannot revive an earlier permit. Hardware hits cannot renew this receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpPermit {
    receipt: UdpPermit,
    incarnation: u64,
}
impl TcpPermit {
    pub fn direction(self) -> Direction {
        self.receipt.direction()
    }
    pub fn original(self) -> TcpTuple {
        self.receipt.original()
    }
    pub fn translated(self) -> TcpTuple {
        self.receipt.translated()
    }
    pub fn expires_at(self) -> u64 {
        self.receipt.expires_at()
    }
}
/// Bounded committed TCP hints. Every lookup still requires live NAT handoff,
/// connection incarnation, route, neighbor and MTU validation by the caller.
/// Remembering a receipt never enables offload or extends its deadline.
pub struct TcpForwardCache<const N: usize> {
    entries: [Option<(TcpPermit,Egress)>;N],
    next: usize,
}
impl<const N: usize> TcpForwardCache<N> {
    pub const fn new()->Self {Self {entries:[None;N],next:0}}
    /// Heap construction for capacities too large to build on a kernel stack.
    pub fn new_boxed()->alloc::boxed::Box<Self> {
        let mut cache=alloc::boxed::Box::<Self>::new_uninit();
        let raw=cache.as_mut_ptr();
        // Safety: exclusively owned, aligned storage; every field and every
        // array element is written exactly once before `assume_init`.
        unsafe {
            let entries=core::ptr::addr_of_mut!((*raw).entries).cast::<Option<(TcpPermit,Egress)>>();
            for i in 0..N {entries.add(i).write(None);}
            core::ptr::addr_of_mut!((*raw).next).write(0);
            cache.assume_init()
        }
    }
    pub const fn capacity(&self)->usize {N}
    pub fn clear(&mut self) {self.entries.fill(None);self.next=0;}
    pub fn forget(&mut self,direction:Direction,tuple:TcpTuple) {
        for entry in &mut self.entries[cache_set::<N>(direction,tuple)] {
            if entry.as_ref().is_some_and(|(p,_)|p.direction()==direction&&p.original()==tuple) {*entry=None;}
        }
    }
    pub fn remember(&mut self,permit:TcpPermit,link:Egress) {
        let set=cache_set::<N>(permit.direction(),permit.original());
        let (base,ways)=(set.start,set.len());
        let mut vacant=None;
        for (index,entry) in self.entries[set].iter_mut().enumerate() {
            if entry.as_ref().is_some_and(|(p,_)|p.direction()==permit.direction()&&p.original()==permit.original()) {
                *entry=Some((permit,link));return;
            }
            if entry.is_none()&&vacant.is_none() {vacant=Some(index);}
        }
        if ways!=0 {
            let index=vacant.unwrap_or(self.next%ways);
            self.entries[base+index]=Some((permit,link));self.next=(index+1)%ways;
        }
    }
    /// Replace only an already-retained instance after a committed software
    /// forward. Never admit an evicted/new peer, reuse an old incarnation, or
    /// move the replacement cursor. This remains a hint, not new authority.
    pub fn refresh(&mut self,permit:TcpPermit,link:Egress)->bool {
        for entry in &mut self.entries[cache_set::<N>(permit.direction(),permit.original())] {
            if let Some((old,_))=entry {
                if old.direction()==permit.direction() && old.original()==permit.original()
                    && old.receipt.identity==permit.receipt.identity
                    && old.receipt.mapping==permit.receipt.mapping
                    && old.receipt.flow==permit.receipt.flow
                    && old.receipt.generation==permit.receipt.generation
                    && old.incarnation==permit.incarnation
                    && permit.receipt.issued>=old.receipt.issued {
                    *entry=Some((permit,link));return true;
                }
            }
        }
        false
    }
    pub fn lookup(&self,direction:Direction,tuple:TcpTuple)->Option<(TcpPermit,Egress)> {
        self.entries[cache_set::<N>(direction,tuple)].iter().flatten().find(|(p,_)|p.direction()==direction&&p.original()==tuple).copied()
    }
}

/// Reciprocal committed receipts for one established connection incarnation.
/// This snapshot neither enables relaxed windows nor installs hardware rules.
/// Revalidate through its original NAT owner before every hardware handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpPermitPair {
    incoming: TcpPermit,
    outgoing: TcpPermit,
}
impl TcpPermitPair {
    pub fn permits(self) -> [TcpPermit; 2] { [self.incoming, self.outgoing] }
    pub fn expires_at(self) -> u64 { self.incoming.expires_at().min(self.outgoing.expires_at()) }
}

/// Read-only software permission for an already handed-off established flow.
/// This is deliberately not a committed-packet TcpPermit and cannot be used
/// for hardware admission. Revalidate it through the original NAT owner.
#[derive(Clone, Copy, Debug)]
pub struct TcpSoftwareFallback { permit: TcpPermit }
impl TcpSoftwareFallback {
    pub fn destination(self)->[u8;4] {self.permit.translated().destination}
    pub fn expires_at(self)->u64 {self.permit.expires_at()}
}

impl<const M: usize, const F: usize> Table<M, F> {
    /// Recover software permission on a hint-cache miss without allocation,
    /// state changes or lifetime renewal. Reuses the bounded mapping/flow hash
    /// probes (at most eight each); never scans or creates an established flow.
    pub fn tcp_software_fallback(&self,direction:Direction,tuple:TcpTuple,now:u64)->Option<TcpSoftwareFallback> {
        if now<self.last_now {return None;}
        let (mapping,remote)=match direction {
            Direction::LanToWan=>{
                if !self.config.lan_host(tuple.source)||!self.config.remote(tuple.destination) {return None;}
                let key=Internal {ip:tuple.source,port:tuple.source_port,protocol:6};
                let (slot,fresh)=self.mapping_slot(key,now).ok()?;
                if fresh {return None;}
                (slot,Remote {ip:tuple.destination,port:tuple.destination_port})
            },
            Direction::WanToLan=>{
                if tuple.destination!=self.config.wan_ip||!self.config.remote(tuple.source) {return None;}
                (usize::from(tuple.destination_port.checked_sub(PORT_BASE)?),Remote {ip:tuple.source,port:tuple.source_port})
            },
        };
        let m=self.mappings.get(mapping).copied().flatten()?;
        if m.until<=now||m.key.protocol!=6 {return None;}
        let (flow,fresh)=self.flow_slot(mapping,m.generation,remote,now).ok()?;
        if fresh {return None;}
        let f=self.flows[flow]?;
        if !f.tcp_offloaded||!matches!(f.state,State::Established {..})||f.tcp_incarnation==0 {return None;}
        let permit=TcpPermit {receipt:UdpPermit {
            identity:self.identity,direction,mapping,flow,generation:m.generation,
            internal:m.key,remote,wan:self.config.wan_ip,issued:now,until:f.until.min(m.until),
        },incarnation:f.tcp_incarnation};
        if permit.original()!=tuple||!self.tcp_offload_enabled(&permit,direction,now) {return None;}
        Some(TcpSoftwareFallback {permit})
    }
    /// Software only: the opaque lookup cannot be converted to a hardware
    /// receipt. The caller still establishes ingress, route, neighbor and MTU.
    pub fn forward_tcp_software_fallback(&self,grant:&TcpSoftwareFallback,direction:Direction,packet:Packet<'_>,egress:Egress,now:u64)->Result<usize,Error> {
        self.forward_permitted_tcp(&grant.permit,direction,packet,egress,now)
    }
    /// Build a read-only pair only from opposite directions of the exact same
    /// live flow slot, mapping generation and TCP incarnation. Distinct peers
    /// sharing an endpoint-independent mapping cannot be joined.
    pub fn tcp_permit_pair(&self, incoming: TcpPermit, outgoing: TcpPermit, now: u64) -> Option<TcpPermitPair> {
        let pair=TcpPermitPair {incoming,outgoing};
        self.validate_tcp_pair(&pair,now).then_some(pair)
    }
    pub fn validate_tcp_pair(&self, pair: &TcpPermitPair, now: u64) -> bool {
        let a=&pair.incoming;let b=&pair.outgoing;
        self.validate_tcp_permit(a,Direction::WanToLan,now)
            && self.validate_tcp_permit(b,Direction::LanToWan,now)
            && a.receipt.mapping==b.receipt.mapping
            && a.receipt.flow==b.receipt.flow
            && a.receipt.generation==b.receipt.generation
            && a.incarnation==b.incarnation
    }
    /// Same explicit connection-level policy contract as enable_tcp_offload.
    /// Validate both receipts before changing the one shared flow; rejection
    /// leaves windows, clocks and lifetimes untouched. Hardware/route authority
    /// and control trapping remain the routing owner's responsibility.
    pub fn enable_tcp_pair(&mut self, pair: &TcpPermitPair, now: u64) -> bool {
        if !self.validate_tcp_pair(pair,now) { return false; }
        let flow=self.flows[pair.incoming.receipt.flow].as_mut().unwrap();
        flow.tcp_offloaded=true;flow.window=None;self.last_now=now;true
    }

    /// Read-only constant-work receipt check; no window relaxation or refresh.
    pub fn validate_tcp_permit(&self, permit: &TcpPermit, direction: Direction, now: u64) -> bool {
        let p = &permit.receipt;
        if p.identity != self.identity
            || p.direction != direction
            || now < self.last_now
            || now < p.issued
            || now >= p.until
            || self.config.wan_ip != p.wan
        {
            return false;
        }
        let Some(mapping) = self.mappings.get(p.mapping).copied().flatten() else {
            return false;
        };
        let Some(flow) = self.flows.get(p.flow).copied().flatten() else {
            return false;
        };
        mapping.key.protocol == 6
            && mapping.key == p.internal
            && mapping.generation == p.generation
            && mapping.until >= p.until
            && flow.mapping == p.mapping
            && flow.generation == p.generation
            && flow.remote == p.remote
            && flow.until >= p.until
            && flow.tcp_incarnation == permit.incarnation
            && permit.incarnation != 0
            && matches!(flow.state, State::Established { .. })
    }
    /// A receipt alone cannot bypass strict TCP windows. This also checks that
    /// the connection has explicitly entered connection-level policy.
    pub fn tcp_offload_enabled(&self, permit: &TcpPermit, direction: Direction, now: u64) -> bool {
        self.validate_tcp_permit(permit, direction, now)
            && self.flows[permit.receipt.flow].unwrap().tcp_offloaded
    }

    /// Forward an exact established data packet after explicit handoff, without
    /// probing mappings/flows or refreshing state. Caller validates the physical
    /// ingress, route, neighbor and MTU authority and reserves TX beforehand.
    /// Control packets must take the normal owner path after hardware retirement.
    /// Parsing still verifies Ethernet/IP/TCP checksums and lengths; this method
    /// additionally checks TCP options and flags before any rewrite. Authority
    /// expiry requires a new slow-path receipt, never extension by cache hits.
    pub fn forward_permitted_tcp(
        &self,
        permit: &TcpPermit,
        direction: Direction,
        packet: Packet<'_>,
        egress: Egress,
        now: u64,
    ) -> Result<usize, Error> {
        if !self.tcp_offload_enabled(permit, direction, now)
        {
            return Err(Error::Denied);
        }
        let original = permit.original();
        let Transport::Tcp { source, destination, flags } = packet.transport() else {
            return Err(Error::Denied);
        };
        if packet.source() != original.source || packet.destination() != original.destination
            || source != original.source_port || destination != original.destination_port
            || flags & 0x17 != 0x10
        {
            return Err(Error::Denied);
        }
        // Packet::parse checks data offset and checksum; tcp_details also
        // rejects malformed option encodings, even after window handoff.
        packet.tcp_details().map_err(Error::Packet)?;
        let translated = permit.translated();
        packet.forward(egress, Some(Translation {
            source: translated.source,
            destination: translated.destination,
            ports: PortRewrite::Ports {
                source: translated.source_port,
                destination: translated.destination_port,
            },
        })).map_err(Error::Packet)
    }

    /// Explicitly adopt connection-level policy for this established connection.
    /// This must precede any hardware forwarding. It is sticky until closure /
    /// expiry / reconfiguration: software cannot reconstruct sequence windows
    /// from packets it did not observe. A later SYN starts strict tracking again.
    ///
    /// The routing owner must keep hardware bounded by the original receipt,
    /// route/neighbor/MTU and configuration authority. It must revoke hardware
    /// before processing control events (including FIN/RST) and before reusing
    /// any expired connection. SYN/FIN/RST and malformed packets must trap to
    /// software. This method neither installs a rule nor supplies those checks.
    pub fn enable_tcp_offload(
        &mut self,
        permit: &TcpPermit,
        direction: Direction,
        now: u64,
    ) -> bool {
        if !self.validate_tcp_permit(permit, direction, now) {
            return false;
        }
        let flow = self.flows[permit.receipt.flow].as_mut().unwrap();
        flow.tcp_offloaded = true;
        flow.window = None;
        self.last_now = now;
        true
    }
}
impl<const M: usize, const F: usize> Prepared<'_, '_, M, F> {
    /// Commit normally and optionally issue an exact established TCP receipt.
    /// SYN/FIN/RST never issue one; obtaining it does not enable offload policy.
    /// Reserve TX first, as for forward(). Failed rewrite commits nothing.
    pub fn forward_with_tcp_permit(
        self,
        egress: Egress,
    ) -> Result<(usize, Option<TcpPermit>), Error> {
        let eligible = matches!(self.packet.transport(),Transport::Tcp {flags,..} if flags & 7 == 0 && flags & 16 != 0)
            && matches!(self.flow.state, State::Established { .. });
        let permit = eligible.then(|| TcpPermit {
            receipt: UdpPermit {
                identity: self.table.identity,
                direction: self.direction,
                mapping: self.mapping_slot,
                flow: self.flow_slot,
                generation: self.mapping.generation,
                internal: self.mapping.key,
                remote: self.flow.remote,
                wan: self.table.config.wan_ip,
                issued: self.now,
                until: self.flow.until.min(self.mapping.until),
            },
            incarnation: self.flow.tcp_incarnation,
        });
        let length = self.forward(egress)?;
        Ok((length, permit))
    }
}
