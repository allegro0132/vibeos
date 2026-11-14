//! Unattached bridge-port allocation authority for cold CPU alias setup.
//! ALLOC's two-byte ID is an output, not a requested fixed alias number.
use super::{Error, Io, Mailbox};
#[derive(Debug, Default)]
pub struct BridgePortLease {
    attempted: bool,
    id: Option<u16>,
    release_attempted: bool,
    released: bool,
}
impl BridgePortLease {
    pub const fn new() -> Self {
        Self {
            attempted: false,
            id: None,
            release_attempted: false,
            released: false,
        }
    }
    pub fn id(&self) -> Option<u16> {
        self.id
    }
    pub fn released(&self) -> bool {
        self.released
    }
}
impl<I: Io> Mailbox<'_, I> {
    /// Caller exclusively owns switch configuration and must not publish this
    /// ID through a CTP, VLAN reassignment or any bridge map while probing.
    /// An ambiguous allocation burns this lease; it is never retried.
    pub fn allocate_bridge_port(&mut self, lease: &mut BridgePortLease) -> Result<u16, Error> {
        if lease.attempted {
            return Err(Error::InvalidState);
        }
        let v = self.version()?;
        if (v.major, v.minor, v.revision, v.build) != (1, 0, 70, 70) {
            return Err(Error::UnsupportedFirmware);
        }
        lease.attempted = true;
        let mut bytes = [0; 2];
        self.query(0x0401, &mut bytes)?;
        let id = u16::from_le_bytes(bytes);
        // Physical port IDs are preallocated; never claim/free them on a
        // corrupt reply. Forwarding maps contain 128 bridge-port bits.
        if !(16..128).contains(&id) {
            return Err(Error::InvalidResponse);
        }
        lease.id = Some(id);
        self.quarantine_bridge_port(lease)?;
        Ok(id)
    }
    fn quarantine_bridge_port(&mut self, lease: &BridgePortLease) -> Result<(), Error> {
        let id = lease.id.ok_or(Error::InvalidState)?;
        if lease.release_attempted {
            return Err(Error::InvalidState);
        }
        let mut bytes = [0; 186];
        bytes[..2].copy_from_slice(&id.to_le_bytes());
        bytes[2..6].copy_from_slice(&0x100u32.to_le_bytes());
        self.execute(0x0402, &mut bytes, false)?;
        self.query(0x0403, &mut bytes)?;
        if bytes[..2] != id.to_le_bytes() || bytes[131..147].iter().any(|b| *b != 0) {
            return Err(Error::ReadbackMismatch);
        }
        Ok(())
    }
    /// Only for an unattached allocation, or after the owner has detached all
    /// incoming references. A failed FREE is ambiguous and must not be retried.
    pub fn release_bridge_port(&mut self, lease: &mut BridgePortLease) -> Result<(), Error> {
        if lease.release_attempted {
            return Err(Error::InvalidState);
        }
        self.quarantine_bridge_port(lease)?;
        let id = lease.id.ok_or(Error::InvalidState)?;
        lease.release_attempted = true;
        self.execute(0x0404, &mut id.to_le_bytes(), false)?;
        lease.released = true;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    struct Mock {
        regs: [u16; 96],
        id: u16,
        commands: std::vec::Vec<u16>,
        fail: Option<u16>,
        bad_map: bool,
    }
    impl Mock {
        fn new(id: u16) -> Self {
            Self {
                regs: [0; 96],
                id,
                commands: std::vec::Vec::new(),
                fail: None,
                bad_map: false,
            }
        }
    }
    impl Io for Mock {
        fn now(&self) -> u64 {
            0
        }
        fn read(&mut self, r: u16) -> Result<u16, crate::mdio::Error> {
            Ok(self.regs[r as usize])
        }
        fn write(&mut self, r: u16, v: u16) -> Result<(), crate::mdio::Error> {
            self.regs[r as usize] = v;
            if r == 0 && v & 0x8000 != 0 {
                let cmd = v & 0x7fff;
                self.commands.push(cmd);
                self.regs[0] = cmd;
                self.regs[1] = 0;
                if self.fail == Some(cmd) {
                    self.regs[1] = (-1i16) as u16;
                    return Ok(());
                }
                match cmd {
                    0x1902 => {
                        self.regs[2] = 1;
                        self.regs[3] = 70;
                        self.regs[4] = 70;
                        self.regs[5] = 0;
                    }
                    0x0401 => {
                        assert_eq!(self.regs[2], 0);
                        self.regs[2] = self.id;
                    }
                    0x0402 => {
                        assert_eq!(self.regs[2], self.id);
                        assert_eq!(self.regs[3], 0x100);
                        assert_eq!(self.regs[4], 0);
                        assert!(self.regs[5..95].iter().all(|v| *v == 0));
                    }
                    0x0403 => {
                        if self.bad_map {
                            self.regs[67] = 0x100;
                        }
                    }
                    0x0404 => {
                        assert_eq!(self.regs[2], self.id);
                    }
                    _ => panic!("unexpected command {cmd:x}"),
                }
            }
            Ok(())
        }
    }
    #[test]
    fn returned_id_owns_all_writes_and_one_release() {
        let mut io = Mock::new(23);
        let mut lease = BridgePortLease::new();
        assert_eq!(
            Mailbox::new(&mut io, 10).allocate_bridge_port(&mut lease),
            Ok(23)
        );
        assert_eq!(lease.id(), Some(23));
        assert_eq!(
            Mailbox::new(&mut io, 10).allocate_bridge_port(&mut lease),
            Err(Error::InvalidState)
        );
        Mailbox::new(&mut io, 10)
            .release_bridge_port(&mut lease)
            .unwrap();
        assert!(lease.released());
        assert_eq!(
            Mailbox::new(&mut io, 10).release_bridge_port(&mut lease),
            Err(Error::InvalidState)
        );
        assert_eq!(io.commands.iter().filter(|c| **c == 0x404).count(), 1);
    }
    #[test]
    fn invalid_ids_never_authorize_writes_or_free() {
        for id in [0, 1, 9, 13, 15, 128, 65535] {
            let mut io = Mock::new(id);
            let mut lease = BridgePortLease::new();
            assert_eq!(
                Mailbox::new(&mut io, 10).allocate_bridge_port(&mut lease),
                Err(Error::InvalidResponse)
            );
            assert_eq!(lease.id(), None);
            assert_eq!(
                Mailbox::new(&mut io, 10).release_bridge_port(&mut lease),
                Err(Error::InvalidState)
            );
            assert_eq!(io.commands, [0x1902, 0x401]);
        }
    }
    #[test]
    fn failed_commands_retain_authority_without_retrying_allocation_or_free() {
        for cmd in [0x401, 0x402, 0x403, 0x404] {
            let mut io = Mock::new(17);
            let mut lease = BridgePortLease::new();
            io.fail = Some(cmd);
            let allocated = Mailbox::new(&mut io, 10).allocate_bridge_port(&mut lease);
            if cmd == 0x404 {
                allocated.unwrap();
                assert_eq!(
                    Mailbox::new(&mut io, 10).release_bridge_port(&mut lease),
                    Err(Error::Firmware(-1))
                );
            } else {
                assert_eq!(allocated, Err(Error::Firmware(-1)));
            }
            assert!(!lease.released());
            assert_eq!(
                Mailbox::new(&mut io, 10).allocate_bridge_port(&mut lease),
                Err(Error::InvalidState)
            );
            if cmd == 0x404 {
                assert_eq!(
                    Mailbox::new(&mut io, 10).release_bridge_port(&mut lease),
                    Err(Error::InvalidState)
                );
            }
        }
    }
    #[test]
    fn quarantine_readback_mismatch_prevents_release() {
        let mut io = Mock::new(17);
        io.bad_map = true;
        let mut lease = BridgePortLease::new();
        assert_eq!(
            Mailbox::new(&mut io, 10).allocate_bridge_port(&mut lease),
            Err(Error::ReadbackMismatch)
        );
        assert_eq!(lease.id(), Some(17));
        assert_eq!(
            Mailbox::new(&mut io, 10).release_bridge_port(&mut lease),
            Err(Error::ReadbackMismatch)
        );
        assert!(!io.commands.contains(&0x404));
    }
}
