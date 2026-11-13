//! Static gateway-MAC ownership support; no table-wide flush or live-entry
//! eviction. The mailbox/table iterator must remain exclusively owned.
use super::{Error, Io, Mailbox};

const MAX_RECORDS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdbEntry {
    pub fid: u16,
    pub port: u32,
    pub map: [u16; 8],
    pub mac: [u8; 6],
    pub static_entry: bool,
    pub sub_interface: u16,
    pub filter: u8,
    pub igmp: bool,
    pub associated: [u8; 6],
    pub tci: u16,
}
impl FdbEntry {
    // Qualified firmware expands the single port 9 ADD into bitmap bit 9
    // on readback. Require that exact singleton, not merely a matching port.
    pub(super) fn gateway(self, fid: u16, mac: [u8; 6]) -> bool {
        self.fid == fid
            && self.mac == mac
            && self.static_entry
            && self.port == 9
            && self.map == [0x200, 0, 0, 0, 0, 0, 0, 0]
            && self.sub_interface == 0
            && self.filter == 0
            && !self.igmp
            && self.associated == [0; 6]
            && self.tci == 0
    }
    fn decode(b: &[u8; 53]) -> Result<Self, Error> {
        if b[30] > 1 || b[40] > 1 || b[39] > 3 {
            return Err(Error::InvalidResponse);
        }
        let word = |o| u16::from_le_bytes([b[o], b[o + 1]]);
        let mut map = [0; 8];
        for (i, value) in map.iter_mut().enumerate() {
            *value = word(8 + i * 2);
        }
        Ok(Self {
            fid: word(2),
            port: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            map,
            mac: b[33..39].try_into().unwrap(),
            static_entry: b[30] != 0,
            sub_interface: word(31),
            filter: b[39],
            igmp: b[40] != 0,
            associated: b[42..48].try_into().unwrap(),
            tci: word(49),
        })
    }
}

fn add_request(fid: u16, mac: [u8; 6]) -> [u8; 48] {
    let mut b = [0; 48];
    b[..2].copy_from_slice(&fid.to_le_bytes());
    b[2..6].copy_from_slice(&9u32.to_le_bytes());
    b[30] = 1;
    b[32..38].copy_from_slice(&mac);
    b
}
fn remove_request(fid: u16, mac: [u8; 6]) -> [u8; 11] {
    let mut b = [0; 11];
    b[..2].copy_from_slice(&fid.to_le_bytes());
    b[2..8].copy_from_slice(&mac);
    b
}

impl<I: Io> Mailbox<'_, I> {
    /// Bounded full walk because this qualified ABI exposes an iterator. A
    /// missing terminator, duplicate MAC/FID variants or malformed record is
    /// an error, NEVER proof of absence. No persistent global cursor is retained.
    pub fn find_fdb(&mut self, fid: u16, mac: [u8; 6]) -> Result<Option<FdbEntry>, Error> {
        let mut found = None;
        for index in 0..=MAX_RECORDS {
            let mut b = [0; 53];
            b[0] = u8::from(index == 0);
            self.query(0x0a03, &mut b)?;
            if b[1] > 1 {
                return Err(Error::InvalidResponse);
            }
            if b[1] == 1 {
                return Ok(found);
            }
            if index == MAX_RECORDS {
                break;
            }
            let entry = FdbEntry::decode(&b)?;
            if entry.fid == fid && entry.mac == mac {
                if found.is_some() {
                    return Err(Error::InvalidResponse);
                }
                found = Some(entry);
            }
        }
        Err(Error::InvalidResponse)
    }
    /// Only the fresh-domain lease calls this after proving the key absent.
    pub(super) fn add_gateway_fdb(&mut self, fid: u16, mac: [u8; 6]) -> Result<(), Error> {
        self.execute(0x0a02, &mut add_request(fid, mac), false)?;
        if !self
            .find_fdb(fid, mac)?
            .is_some_and(|e| e.gateway(fid, mac))
        {
            return Err(Error::ReadbackMismatch);
        }
        Ok(())
    }
    /// Caller has checked the entry still matches its owned static CPU route.
    pub(super) fn remove_gateway_fdb(&mut self, fid: u16, mac: [u8; 6]) -> Result<(), Error> {
        self.execute(0x0a05, &mut remove_request(fid, mac), false)?;
        if self.find_fdb(fid, mac)?.is_some() {
            return Err(Error::ReadbackMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
