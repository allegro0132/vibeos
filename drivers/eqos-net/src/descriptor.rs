//! Basic 16-byte EQoS descriptors; default TX has no checksum insertion.
//! Values are CPU-order snapshots. Live access must be volatile, little-endian,
//! cache synchronized and publish OWN last before the DMA tail pointer.
pub const OWN: u32 = 1 << 31;
const CONTEXT: u32 = 1 << 30;
const FIRST: u32 = 1 << 29;
const LAST: u32 = 1 << 28;
const ERROR: u32 = 1 << 15;
pub const MAX_FRAME: usize = 1518; // Ethernet + optional VLAN, excluding FCS.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLength,
    AddressTooWide,
    InvalidLayout,
    Hardware,
    Fragmented,
    TxWriteback(u32),
    Context,
}

fn address32(address: u64, bytes: usize) -> Result<u32, Error> {
    if bytes == 0
        || address
            .checked_add(bytes as u64 - 1)
            .is_none_or(|last| last > u32::MAX as u64)
    {
        return Err(Error::AddressTooWide);
    }
    Ok(address as u32)
}

/// Prepared descriptor without OWN. The runtime must sync packet data and all
/// words, publish OWN in word 3, sync the descriptor, then ring the DMA doorbell.
pub fn tx(address: u64, bytes: usize) -> Result<[u32; 4], Error> {
    tx_with_checksum(address, bytes, TxChecksum::None)
}

/// EQoS CIC encodings (Linux dwmac4_descs.h / descs.h). Full includes the
/// IP header and transport pseudoheader. This does not enable MAC capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TxChecksum {
    None = 0,
    Ipv4Header = 1,
    Full = 3,
}

/// The caller must admit the hardware capability, MAC mode and packet format
/// before selecting insertion. OWN remains clear; publication is unchanged.
pub fn tx_with_checksum(address: u64, bytes: usize, checksum: TxChecksum) -> Result<[u32; 4], Error> {
    if !(14..=MAX_FRAME).contains(&bytes) {
        return Err(Error::InvalidLength);
    }
    Ok([
        address32(address, bytes)?,
        0,
        bytes as u32,
        FIRST | LAST | ((checksum as u32) << 16) | bytes as u32,
    ])
}

pub fn rx(address: u64, buffer_bytes: usize) -> Result<[u32; 4], Error> {
    if !(MAX_FRAME + 4..=0x3fff).contains(&buffer_bytes) {
        return Err(Error::InvalidLength);
    }
    Ok([address32(address, buffer_bytes)?, 0, 0, 1 << 24])
}

pub fn tx_complete(words: [u32; 4]) -> Result<bool, Error> {
    let status = words[3];
    if status & OWN != 0 {
        return Ok(false);
    }
    if status & CONTEXT != 0 {
        return Err(Error::Context);
    }
    if status & ERROR != 0 {
        return Err(Error::Hardware);
    }
    // TX read and write-back formats differ. FIRST is a submission flag,
    // not required by completion (Linux dwmac4_wrback_get_tx_status).
    // This ring submits one descriptor per frame, so LAST must be present.
    if status & LAST == 0 {
        return Err(Error::TxWriteback(status));
    }
    Ok(true)
}

/// This profile leaves FCS in RX buffers (MAC ACS/CST disabled). The returned
/// length excludes the four-byte FCS. Never interpret the write-back address
/// words as an RX buffer pointer; the runtime owns a separate slot-to-buffer map.
pub fn rx_complete(words: [u32; 4], buffer_bytes: usize) -> Result<Option<usize>, Error> {
    let status = words[3];
    if status & OWN != 0 {
        return Ok(None);
    }
    if status & CONTEXT != 0 {
        return Err(Error::Context);
    }
    if status & ERROR != 0 {
        return Err(Error::Hardware);
    }
    if status & (FIRST | LAST) != FIRST | LAST {
        return Err(Error::Fragmented);
    }
    let bytes = (status & 0x7fff) as usize;
    if !(18..=MAX_FRAME + 4).contains(&bytes) || bytes > buffer_bytes {
        return Err(Error::InvalidLength);
    }
    Ok(Some(bytes - 4))
}

/// Isolate descriptors on cache lines without confusing descriptor stride with
/// hardware descriptor size. DSL units are the controller's AXI bus width.
pub fn skip_length(stride: usize, axi_bytes: usize) -> Result<u32, Error> {
    if !matches!(axi_bytes, 4 | 8 | 16)
        || stride < 16
        || !stride.is_power_of_two()
        || (stride - 16) % axi_bytes != 0
        || (stride - 16) / axi_bytes > 7
    {
        return Err(Error::InvalidLayout);
    }
    Ok((((stride - 16) / axi_bytes) as u32) << 18)
}

/// RX checksum observation, not permission to skip software verification.
/// The caller must additionally qualify the enabled MAC mode and match packet
/// headers to the reported IP version/payload type before trusting this status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RxChecksum {
    Unavailable,
    Bypassed,
    Error,
    Ipv4 { payload_type: u8 },
    Ipv6 { payload_type: u8 },
}
/// Decode only a complete, CPU-owned normal descriptor with valid word 1.
/// A descriptor without protocol metadata can never mean checksum success.
pub fn rx_checksum(words: [u32; 4]) -> RxChecksum {
    if !matches!(rx_complete(words, MAX_FRAME + 4), Ok(Some(_)))
        || words[3] & (1 << 26) == 0 {
        return RxChecksum::Unavailable;
    }
    let flags = words[1];
    if flags & ((1 << 3) | (1 << 7)) != 0 { return RxChecksum::Error; }
    if flags & (1 << 6) != 0 { return RxChecksum::Bypassed; }
    let payload_type = (flags & 7) as u8;
    match (flags >> 4) & 3 {
        1 => RxChecksum::Ipv4 { payload_type },
        2 => RxChecksum::Ipv6 { payload_type },
        _ => RxChecksum::Unavailable,
    }
}

/// Header-only first TSO descriptor. Word 1 stays zero, compatible with
/// controllers implementing extended DMA address widths even for low addresses.
/// Runtime must reserve context, header and all payload descriptors before OWN.
pub fn tso_ipv4_first(
    header_address: u64,
    tcp_header_bytes: usize,
    total_payload_bytes: usize,
) -> Result<[u32; 4], Error> {
    if !(20..=60).contains(&tcp_header_bytes)
        || tcp_header_bytes % 4 != 0
        || !(1..=0x3ffff).contains(&total_payload_bytes) {
        return Err(Error::InvalidLength);
    }
    let header_bytes = 14 + 20 + tcp_header_bytes;
    Ok([
        address32(header_address, header_bytes)?, 0, header_bytes as u32,
        FIRST | (1 << 18) | (((tcp_header_bytes / 4) as u32) << 19)
            | total_payload_bytes as u32,
    ])
}

/// Continuation of an already prepared TSO packet. Context and total length
/// belong only to the first descriptor. Payload storage remains owned until
/// the final descriptor of the entire logical packet completes.
pub fn tso_continuation(address: u64, bytes: usize, last: bool) -> Result<[u32; 4], Error> {
    if !(1..=0x3fff).contains(&bytes) { return Err(Error::InvalidLength); }
    Ok([address32(address, bytes)?, 0, bytes as u32, if last { LAST } else { 0 }])
}

/// MSS context for IP MTU 1500, IPv4 without options. A TCP option changes the
/// maximum MSS, not the wire MTU. No cached MSS state is retained by this codec.
pub fn tso_mss(mss: usize, tcp_header_bytes: usize) -> Result<[u32; 4], Error> {
    if !(20..=60).contains(&tcp_header_bytes) || tcp_header_bytes % 4 != 0
        || mss < 64 || mss > 1500 - 20 - tcp_header_bytes {
        return Err(Error::InvalidLength);
    }
    Ok([0, 0, mss as u32, CONTEXT | (1 << 26)])
}
