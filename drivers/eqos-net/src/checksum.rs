//! TX checksum preparation and RX verification for complete Ethernet/IPv4 packets.
//! The caller supplies writable CPU-owned bytes before DMA publication.
//! Fragmented IPv4 cannot request transport completion without reassembly.
use crate::descriptor::TxChecksum;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error { Truncated, Malformed, Fragmented, Checksum }

fn word(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}
fn sum(bytes: &[u8]) -> u32 {
    let mut n = 0;
    for pair in bytes.chunks(2) {
        n += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
    }
    n
}
fn finish(mut n: u32) -> u16 {
    while n >> 16 != 0 { n = (n & 0xffff) + (n >> 16); }
    !(n as u16)
}
fn put(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_be_bytes());
}

/// Complete a TX checksum request. Non-IPv4 frames are left unchanged.
/// Normal untagged IPv4 TCP/UDP may use CIC Full when hardware is admitted;
/// VLAN, IPv4 options and UDP/IP length differences use software instead.
/// ICMP errors complete their quoted IPv4 header and ICMP checksum; other
/// transports retain their existing payload checksum.
/// An error never modifies the packet. This API does not accept IP fragments;
/// callers sending already-checksummed raw fragments should use ordinary TX.
pub fn prepare(frame: &mut [u8], hardware: bool) -> Result<TxChecksum, Error> {
    match parse(frame)? {
        Some(plan) => apply(frame, plan, hardware),
        None => Ok(TxChecksum::None),
    }
}

#[derive(Clone, Copy)]
struct Plan {
    ip: usize,
    ihl: usize,
    transport: usize,
    length: usize,
    protocol: u8,
    payload: Option<(usize, usize)>,
}

/// Validated complete packet, borrowed until synchronous DMA submission ends.
/// Its private plan cannot be reused with different or modified packet bytes.
pub struct Request<'a> { frame: &'a [u8], plan: Option<Plan> }
impl<'a> Request<'a> {
    pub fn new(frame: &'a [u8]) -> Result<Self, Error> {
        Ok(Self { frame, plan: parse(frame)? })
    }
    pub(crate) fn len(&self) -> usize { self.frame.len() }
    pub(crate) fn with_prepared<T>(self, hardware: bool,
        submit: impl FnOnce(&[u8], TxChecksum) -> T) -> Result<T, Error> {
        let Some(plan) = self.plan else {
            return Ok(submit(self.frame, TxChecksum::None));
        };
        if let Some((check, n)) = plan.payload {
            if hardware && plan.ip == 14 && plan.ihl == 20 && n == plan.length
                && word(self.frame, plan.ip + 10) == 0 && word(self.frame, check) == 0 {
                return Ok(submit(self.frame, TxChecksum::Full));
            }
        }
        self.with_copy(plan, hardware, submit)
    }
    // Keep scratch allocation and initialization out of the normal TX path.
    #[inline(never)]
    fn with_copy<T>(self, plan: Plan, hardware: bool,
        submit: impl FnOnce(&[u8], TxChecksum) -> T) -> Result<T, Error> {
        if self.frame.len() > crate::ring::BUFFER { return Err(Error::Malformed); }
        let mut copy = [0u8; crate::ring::BUFFER];
        let copy = &mut copy[..self.frame.len()];
        copy.copy_from_slice(self.frame);
        let mode = apply(copy, plan, hardware)?;
        Ok(submit(copy, mode))
    }
}
fn parse(frame: &[u8]) -> Result<Option<Plan>, Error> {
    if frame.len() < 14 { return Err(Error::Truncated); }
    let mut ip = 14;
    let mut ether = word(frame, 12);
    // One or two VLAN tags, with explicit bounds and no unbounded parsing.
    for _ in 0..2 {
        if !matches!(ether, 0x8100 | 0x88a8) { break; }
        if frame.len() < ip + 4 { return Err(Error::Truncated); }
        ether = word(frame, ip + 2);
        ip += 4;
    }
    if matches!(ether, 0x8100 | 0x88a8) { return Err(Error::Malformed); }
    if ether != 0x0800 { return Ok(None); }
    if frame.len() < ip + 20 { return Err(Error::Truncated); }
    let ihl = usize::from(frame[ip] & 15) * 4;
    let total = usize::from(word(frame, ip + 2));
    if frame[ip] >> 4 != 4 || ihl < 20 || total < ihl { return Err(Error::Malformed); }
    if frame.len() < ip + total { return Err(Error::Truncated); }
    let fragments = word(frame, ip + 6);
    if fragments & 0x8000 != 0 { return Err(Error::Malformed); }
    if fragments & 0x3fff != 0 { return Err(Error::Fragmented); }
    let transport = ip + ihl;
    let length = total - ihl;
    let protocol = frame[ip + 9];
    let payload = match protocol {
        6 => {
            if length < 20 { return Err(Error::Truncated); }
            let tcp_header = usize::from(frame[transport + 12] >> 4) * 4;
            if tcp_header < 20 || tcp_header > length { return Err(Error::Malformed); }
            Some((transport + 16, length))
        }
        17 => {
            if length < 8 { return Err(Error::Truncated); }
            let udp_length = usize::from(word(frame, transport + 4));
            if udp_length < 8 || udp_length > length { return Err(Error::Malformed); }
            Some((transport + 6, udp_length))
        }
        _ => None,
    };
    Ok(Some(Plan { ip, ihl, transport, length, protocol, payload }))
}
fn apply(frame: &mut [u8], plan: Plan, hardware: bool) -> Result<TxChecksum, Error> {
    let Plan { ip, ihl, transport, length, protocol, payload } = plan;
    // All validation precedes mutation. Ethernet padding is not checksum data.
    put(frame, ip + 10, 0);
    if let Some((check, transport_length)) = payload {
        put(frame, check, 0);
        if hardware && ip == 14 && ihl == 20 && transport_length == length {
            return Ok(TxChecksum::Full);
        }
        let pseudo = sum(&frame[ip + 12..ip + 20])
            + u32::from(protocol) + transport_length as u32;
        let mut checksum = finish(pseudo + sum(&frame[transport..transport + transport_length]));
        // UDP encodes a computed zero as all ones (RFC 768).
        if protocol == 17 && checksum == 0 { checksum = 0xffff; }
        put(frame, check, checksum);
    }
    // smoltcp's TX offload capability also reaches the quoted IPv4 header
    // in ICMP errors. Hardware cannot complete that inner header checksum.
    if protocol == 1 && length >= 28 && matches!(frame[transport], 3 | 4 | 5 | 11 | 12) {
        let quoted = transport + 8;
        let qihl = usize::from(frame[quoted] & 15) * 4;
        if frame[quoted] >> 4 == 4 && qihl >= 20 && qihl <= length - 8
            && usize::from(word(frame, quoted + 2)) >= qihl {
            put(frame, quoted + 10, 0);
            let inner = finish(sum(&frame[quoted..quoted + qihl]));
            put(frame, quoted + 10, inner);
            put(frame, transport + 2, 0);
            let icmp = finish(sum(&frame[transport..transport + length]));
            put(frame, transport + 2, icmp);
        }
    }
    let header = finish(sum(&frame[ip..ip + ihl]));
    put(frame, ip + 10, header);
    Ok(TxChecksum::None)
}

/// Scope of successful RX verification. NonIpv4 is not checksum validation;
/// its consumer must retain the checks required by that frame's protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RxVerified { Hardware, Software, NonIpv4 }

/// Verify a complete IPv4 packet without mutation or a payload copy.
/// `status` must belong to this packet from a capability-admitted, enabled IPC
/// engine; use Unavailable otherwise. Only ordinary IPv4 TCP/UDP with matching
/// hardware payload type can bypass sums. Every other IPv4 format uses software.
/// ICMP/unknown transports get IP-header verification only; their own protocol
/// layer still verifies payload checksums. Fragments require reassembly and are
/// explicitly rejected rather than declared transport-verified. NonIpv4 never
/// permits a caller to disable transport checksum checks for other IP versions.
pub fn verify_rx_ipv4(frame: &[u8], status: crate::descriptor::RxChecksum)
    -> Result<RxVerified, Error> {
    use crate::descriptor::RxChecksum as C;
    if status == C::Error { return Err(Error::Checksum); }
    let Some(plan) = parse(frame)? else { return Ok(RxVerified::NonIpv4); };
    let Plan { ip, ihl, transport, length, protocol, payload } = plan;
    if let Some((_, n)) = payload {
        let expected = match protocol { 6 => 2, 17 => 1, _ => unreachable!() };
        if status == (C::Ipv4 { payload_type: expected })
            && ip == 14 && ihl == 20 && n == length {
            return Ok(RxVerified::Hardware);
        }
    }
    if finish(sum(&frame[ip..ip + ihl])) != 0 { return Err(Error::Checksum); }
    if let Some((check, n)) = payload {
        // RFC 768 permits an omitted UDP checksum for IPv4 only.
        if !(protocol == 17 && word(frame, check) == 0) {
            let pseudo = sum(&frame[ip + 12..ip + 20]) + u32::from(protocol) + n as u32;
            if finish(pseudo + sum(&frame[transport..transport + n])) != 0 {
                return Err(Error::Checksum);
            }
        }
    }
    Ok(RxVerified::Software)
}
