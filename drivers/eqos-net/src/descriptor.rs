//! Basic 16-byte EQoS descriptors, with checksum/TSO/context features disabled.
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
    if !(14..=MAX_FRAME).contains(&bytes) {
        return Err(Error::InvalidLength);
    }
    Ok([
        address32(address, bytes)?,
        0,
        bytes as u32,
        FIRST | LAST | bytes as u32,
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
    if status & (FIRST | LAST) != FIRST | LAST {
        return Err(Error::Fragmented);
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
