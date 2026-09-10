#![no_std]
//! Shared IEEE Clause 22 transactions. Register encodings belong to controllers.
//! Poll bounds do not prove a wall-clock timeout; consumers provide the budget.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidAddress,
    InvalidBudget,
    InvalidResponse,
    TimedOut,
}

pub trait MdioPort {
    fn busy(&mut self) -> bool;
    fn start_read(&mut self, phy: u8, register: u8);
    fn start_write(&mut self, phy: u8, register: u8, value: u16);
    fn data(&mut self) -> u16;
    fn relax(&mut self) {
        core::hint::spin_loop();
    }
}

fn idle(port: &mut impl MdioPort, polls: u32) -> Result<(), Error> {
    for _ in 0..polls {
        if !port.busy() {
            return Ok(());
        }
        port.relax();
    }
    Err(Error::TimedOut)
}

fn validate(phy: u8, register: u8, polls: u32) -> Result<(), Error> {
    if phy >= 32 || register >= 32 {
        return Err(Error::InvalidAddress);
    }
    if polls == 0 {
        return Err(Error::InvalidBudget);
    }
    Ok(())
}

pub fn read(port: &mut impl MdioPort, phy: u8, register: u8, polls: u32) -> Result<u16, Error> {
    validate(phy, register, polls)?;
    idle(port, polls)?;
    port.start_read(phy, register);
    idle(port, polls)?;
    Ok(port.data())
}

/// A completion timeout after publication leaves write outcome unknown. This
/// function never retries. The controller/consumer must recover before retrying.
pub fn write(
    port: &mut impl MdioPort,
    phy: u8,
    register: u8,
    value: u16,
    polls: u32,
) -> Result<(), Error> {
    validate(phy, register, polls)?;
    idle(port, polls)?;
    port.start_write(phy, register, value);
    idle(port, polls)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BasicStatus(pub u16);
impl BasicStatus {
    pub fn link_up(self) -> bool {
        self.0 & (1 << 2) != 0
    }
    pub fn autoneg_complete(self) -> bool {
        self.0 & (1 << 5) != 0
    }
}

/// BMSR link status is latched low. The first read clears history; only the
/// second read describes the current link. Either transaction can fail.
pub fn status(port: &mut impl MdioPort, phy: u8, polls: u32) -> Result<BasicStatus, Error> {
    read(port, phy, 1, polls)?;
    match read(port, phy, 1, polls)? {
        0xffff => Err(Error::InvalidResponse),
        value => Ok(BasicStatus(value)),
    }
}
