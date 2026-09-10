//! Shared PHY discovery and Motorcomm YT8531 support. No board addresses,
//! clocks, kernel policy or packet queues belong here. All operations on the
//! owned MDIO port must be serialized with MAC stop/reconfiguration by firmware.
use crate::{read, status, write, Error as MdioError, MdioPort};

pub const YT8531_ID: u32 = 0x4f51_e91b;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Mdio(MdioError),
    NoDevice,
    Ambiguous,
    Unsupported,
    InvalidConfig,
    ResetTimedOut,
    Readback,
    NotReady,
}
impl From<MdioError> for Error {
    fn from(e: MdioError) -> Self {
        Self::Mdio(e)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub address: u8,
    pub id: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Speed {
    Mbps10,
    Mbps100,
    Mbps1000,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Link {
    pub speed: Speed,
    pub full_duplex: bool,
}

/// Read-only scan of explicitly allowed addresses. More than one responding
/// PHY is ambiguous, even if only one has a supported ID. No address-zero guess.
pub fn discover(port: &mut impl MdioPort, addresses: u32, polls: u32) -> Result<Identity, Error> {
    if addresses == 0 || polls == 0 || polls > 1_000_000 {
        return Err(Error::InvalidConfig);
    }
    let mut found = None;
    for address in 0..32 {
        if addresses & (1 << address) == 0 {
            continue;
        }
        let id = (u32::from(read(port, address, 2, polls)?) << 16)
            | u32::from(read(port, address, 3, polls)?);
        if id == 0 || id == u32::MAX {
            continue;
        }
        if found.replace(Identity { address, id }).is_some() {
            return Err(Error::Ambiguous);
        }
    }
    found.ok_or(Error::NoDevice)
}

/// Raw vendor delay/drive encodings supplied by a board description.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tuning {
    pub drive: [u8; 3], // extra drive bit, data drive, RX clock drive
    pub rxc_delay_enabled: bool,
    pub rx_delay: u8,
    pub tx_delay_fe: u8,
    pub tx_delay: u8,
    pub tx_inverted: [bool; 3], // 10, 100, 1000 Mbps
}
impl Tuning {
    fn valid(self) -> bool {
        self.drive[0] <= 1
            && self.drive[1] <= 3
            && self.drive[2] <= 7
            && self.rx_delay <= 15
            && self.tx_delay_fe <= 15
            && self.tx_delay <= 15
    }
}
pub struct Yt8531<P> {
    port: P,
    identity: Identity,
    polls: u32,
    tuning: Option<Tuning>,
    last_link: Option<Link>,
}
impl<P: MdioPort> Yt8531<P> {
    pub fn probe(mut port: P, addresses: u32, polls: u32) -> Result<Self, Error> {
        let identity = discover(&mut port, addresses, polls)?;
        if identity.id != YT8531_ID {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            port,
            identity,
            polls,
            tuning: None,
            last_link: None,
        })
    }
    pub fn identity(&self) -> Identity {
        self.identity
    }
    /// Consumes the PHY state. Reconstruct/probe after transport recovery.
    pub fn into_port(self) -> P {
        self.port
    }
    fn read(&mut self, reg: u8) -> Result<u16, Error> {
        let value = read(&mut self.port, self.identity.address, reg, self.polls)?;
        if value == u16::MAX {
            return Err(Error::Mdio(MdioError::InvalidResponse));
        }
        Ok(value)
    }
    fn write(&mut self, reg: u8, value: u16) -> Result<(), Error> {
        Ok(write(
            &mut self.port,
            self.identity.address,
            reg,
            value,
            self.polls,
        )?)
    }
    fn ext_update(&mut self, reg: u16, mask: u16, value: u16) -> Result<(), Error> {
        self.write(30, reg)?;
        let old = self.read(31)?;
        self.write(31, (old & !mask) | (value & mask))?;
        // Verify masked configuration before publishing a usable PHY state.
        if self.read(31)? & mask != value & mask {
            return Err(Error::Readback);
        }
        Ok(())
    }
    /// MAC must be stopped. Soft reset is published once and polled with a
    /// finite budget. No timed-out write is replayed; failure leaves NotReady.
    /// Subsequent initialize begins with identity validation and a fresh reset.
    /// Advertise full-duplex 10/100/1000 only, with pause disabled to match the
    /// first EQoS datapath. Negotiation is asynchronous, observed by poll_link.
    pub fn initialize(&mut self, tuning: Tuning, reset_reads: u32) -> Result<(), Error> {
        if !tuning.valid() || reset_reads == 0 || reset_reads > 10_000 {
            return Err(Error::InvalidConfig);
        }
        self.tuning = None;
        self.last_link = None;
        let id = (u32::from(self.read(2)?) << 16) | u32::from(self.read(3)?);
        if id != self.identity.id {
            return Err(Error::Unsupported);
        }
        self.write(0, 1 << 15)?;
        let mut reset_done = false;
        for _ in 0..reset_reads {
            if self.read(0)? & (1 << 15) == 0 {
                reset_done = true;
                break;
            }
        }
        if !reset_done {
            return Err(Error::ResetTimedOut);
        }
        self.ext_update(0xa001, 1 << 8, u16::from(tuning.rxc_delay_enabled) << 8)?;
        self.ext_update(
            0xa010,
            0xf030,
            u16::from(tuning.drive[0]) << 12
                | u16::from(tuning.drive[1]) << 4
                | u16::from(tuning.drive[2]) << 13,
        )?;
        self.ext_update(
            0xa003,
            0x3cff,
            u16::from(tuning.rx_delay) << 10
                | u16::from(tuning.tx_delay_fe) << 4
                | u16::from(tuning.tx_delay),
        )?;
        self.write(4, 0x0141)?;
        self.write(9, 0x0200)?;
        if self.read(4)? != 0x0141 || self.read(9)? != 0x0200 {
            return Err(Error::Readback);
        }
        self.write(0, 0x1200)?;
        self.tuning = Some(tuning);
        Ok(())
    }
    /// Read-only observation of resolved vendor status. Call configure_link
    /// with the MAC stopped before starting traffic at a newly observed speed.
    /// Any I/O/configuration error invalidates state until initialize succeeds.
    /// None means cable down or negotiation in progress; it does not reset PHY.
    pub fn poll_link(&mut self) -> Result<Option<Link>, Error> {
        self.tuning.ok_or(Error::NotReady)?;
        let result = self.link_inner();
        if result.is_err() {
            self.tuning = None;
            self.last_link = None;
        }
        result
    }
    /// MAC/DMA must be stopped by the caller. Confirm the candidate still holds,
    /// program the speed-specific TX inversion, then recheck before returning
    /// true. This separation keeps ordinary link polling free of PHY writes.
    pub fn configure_link(&mut self, link: Link) -> Result<bool, Error> {
        let tuning = self.tuning.ok_or(Error::NotReady)?;
        if !link.full_duplex {
            return Err(Error::Unsupported);
        }
        if self.poll_link()? != Some(link) {
            return Ok(false);
        }
        let index = match link.speed {
            Speed::Mbps10 => 0,
            Speed::Mbps100 => 1,
            Speed::Mbps1000 => 2,
        };
        if self.last_link != Some(link) {
            if let Err(e) =
                self.ext_update(0xa003, 1 << 14, u16::from(tuning.tx_inverted[index]) << 14)
            {
                self.tuning = None;
                self.last_link = None;
                return Err(e);
            }
        }
        if self.poll_link()? != Some(link) {
            self.last_link = None;
            return Ok(false);
        }
        self.last_link = Some(link);
        Ok(true)
    }
    fn link_inner(&mut self) -> Result<Option<Link>, Error> {
        let basic = status(&mut self.port, self.identity.address, self.polls)?;
        if !basic.link_up() || !basic.autoneg_complete() || basic.0 & (1 << 4) != 0 {
            self.last_link = None;
            return Ok(None);
        }
        let value = self.read(17)?;
        if value & 0x0c00 != 0x0c00 {
            self.last_link = None;
            return Ok(None);
        }
        let speed = match value & 0xc200 {
            0 => Speed::Mbps10,
            0x4000 => Speed::Mbps100,
            0x8000 => Speed::Mbps1000,
            _ => return Err(Error::Unsupported),
        };
        if value & (1 << 13) == 0 {
            return Err(Error::Unsupported);
        }
        let link = Link {
            speed,
            full_duplex: true,
        };
        // A speed/link transition during the multi-command sample is not an
        // established link. Next poll retries observation, not packet writes.
        let after = self.read(17)?;
        let basic = status(&mut self.port, self.identity.address, self.polls)?;
        if after & 0xee00 != value & 0xee00
            || !basic.link_up()
            || !basic.autoneg_complete()
            || basic.0 & (1 << 4) != 0
        {
            self.last_link = None;
            return Ok(None);
        }
        Ok(Some(link))
    }
}
