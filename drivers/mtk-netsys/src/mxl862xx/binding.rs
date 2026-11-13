//! Reversible ownership of one user port's ingress/egress VLAN rules.
//! Existing CPU/CTP mappings are preserved; this is not cold-start initialization.
use super::{Bridge, Error, Io, Mailbox};
use crate::{mxl_tag::Port, mxl_vlan::Rule};

#[derive(Debug)]
pub struct PortVlanLease {
    port: Port,
    previous: Option<Bridge>,
    allocation: Option<[u8; 4]>,
    egress_allocation: Option<[u8; 4]>,
    started: bool,
    map_may_change: bool,
    binding_may_change: bool,
    free_attempted: bool,
    active: bool,
    released: bool,
}
impl PortVlanLease {
    pub fn new(port: Port) -> Self {
        Self {
            port,
            previous: None,
            allocation: None,
            egress_allocation: None,
            started: false,
            map_may_change: false,
            binding_may_change: false,
            free_attempted: false,
            active: false,
            released: false,
        }
    }
    pub fn port(&self) -> Port {
        self.port
    }
    pub fn block(&self) -> Option<u16> {
        self.allocation.map(|a| u16::from_le_bytes([a[2], a[3]]))
    }
    pub fn egress_block(&self) -> Option<u16> {
        self.egress_allocation
            .map(|a| u16::from_le_bytes([a[2], a[3]]))
    }
    pub fn active(&self) -> bool {
        self.active
    }
    pub fn released(&self) -> bool {
        self.released
    }
}
impl<I: Io> Mailbox<'_, I> {
    /// Keep the lease even on failure, then call restore_port_vlans. A failure
    /// before an allocation ID is returned may leak an unknown unbound block.
    /// The caller must exclude other switch configuration/reset for this lease.
    pub fn own_port_vlans(&mut self, lease: &mut PortVlanLease) -> Result<(), Error> {
        if lease.started {
            return Err(Error::InvalidState);
        }
        lease.started = true;
        let v = self.version()?;
        if (v.major, v.minor, v.revision, v.build) != (1, 0, 70, 70) {
            return Err(Error::UnsupportedFirmware);
        }
        let port = lease.port.dt_index() as u16 + 1;
        let previous = self.bridge(port)?;
        if previous.destination != port as u8
            || previous.map != [0x200, 0, 0, 0, 0, 0, 0, 0]
            || !previous.ingress_vlan.0
            || previous.ingress_vlan.2 == 0
        {
            return Err(Error::InvalidResponse);
        }
        lease.previous = Some(previous);
        let mut allocation = [3, 0, 0, 0];
        self.query(0x0b01, &mut allocation)?;
        let block = u16::from_le_bytes([allocation[2], allocation[3]]);
        if block == u16::MAX {
            return Err(Error::InvalidResponse);
        }
        lease.allocation = Some(allocation);
        if u16::from_le_bytes([allocation[0], allocation[1]]) < 3 {
            return Err(Error::InvalidResponse);
        }
        for (index, rule) in [
            Rule::PushUntagged(lease.port),
            Rule::PushSingleTagged(lease.port),
            Rule::PushDoubleTagged(lease.port),
        ]
        .into_iter()
        .enumerate()
        {
            self.execute(0x0b02, &mut rule.encode(block, index as u16), false)?;
            if !rule.matches(&self.vlan_rule(block, index as u16)?) {
                return Err(Error::ReadbackMismatch);
            }
        }
        let mut egress_allocation = [4, 0, 0, 0];
        self.query(0x0b01, &mut egress_allocation)?;
        let egress_block = u16::from_le_bytes([egress_allocation[2], egress_allocation[3]]);
        if egress_block == u16::MAX {
            return Err(Error::InvalidResponse);
        }
        lease.egress_allocation = Some(egress_allocation);
        if u16::from_le_bytes([egress_allocation[0], egress_allocation[1]]) < 4 {
            return Err(Error::InvalidResponse);
        }
        for (index, rule) in [
            Rule::PopOuter(lease.port),
            Rule::PopOuterTagged(lease.port),
            Rule::DropDoubleTagged,
            Rule::DropSingleTagged,
        ]
        .into_iter()
        .enumerate()
        {
            self.execute(0x0b02, &mut rule.encode(egress_block, index as u16), false)?;
            if !rule.matches(&self.vlan_rule(egress_block, index as u16)?) {
                return Err(Error::ReadbackMismatch);
            }
        }
        // Prepare all rules before touching live forwarding. Mark possible
        // changes before submission, since a timeout does not undo a write.
        lease.map_may_change = true;
        self.set_user_map(port, false)?;
        lease.binding_may_change = true;
        self.set_binding(port, true, (true, block, 3))?;
        self.set_binding(port, false, (true, egress_block, 4))?;
        let current = self.bridge(port)?;
        if current.id != previous.id
            || current.destination != previous.destination
            || current.map != [0; 8]
        {
            return Err(Error::ReadbackMismatch);
        }
        self.set_user_map(port, true)?;
        lease.active = true;
        Ok(())
    }
    /// Stop forwarding, restore and verify the old binding, restore the map,
    /// then free. If restoration fails, retain the block: never free a resource
    /// which hardware may still reference. A failed FREE is not retried.
    pub fn restore_port_vlans(&mut self, lease: &mut PortVlanLease) -> Result<(), Error> {
        if !lease.started || lease.released || lease.free_attempted {
            return Err(Error::InvalidState);
        }
        let port = lease.port.dt_index() as u16 + 1;
        if lease.map_may_change {
            self.set_user_map(port, false)?;
            lease.active = false;
            if lease.binding_may_change {
                let previous = lease.previous.ok_or(Error::InvalidState)?;
                self.set_binding(port, true, previous.ingress_vlan)?;
                self.set_binding(port, false, previous.egress_vlan)?;
                lease.binding_may_change = false;
            }
            self.set_user_map(port, true)?;
            lease.map_may_change = false;
        }
        for mut allocation in [lease.allocation, lease.egress_allocation]
            .into_iter()
            .flatten()
        {
            lease.free_attempted = true;
            self.execute(0x0b04, &mut allocation, false)?;
        }
        lease.released = true;
        Ok(())
    }
    pub(super) fn set_binding(
        &mut self,
        port: u16,
        ingress: bool,
        binding: (bool, u16, u16),
    ) -> Result<(), Error> {
        let mut bytes = [0; 186];
        bytes[..2].copy_from_slice(&port.to_le_bytes());
        bytes[2..6].copy_from_slice(&(if ingress { 2u32 } else { 4u32 }).to_le_bytes());
        let off = if ingress { 8 } else { 13 };
        bytes[off] = u8::from(binding.0);
        bytes[off + 1..off + 3].copy_from_slice(&binding.1.to_le_bytes());
        bytes[off + 3..off + 5].copy_from_slice(&binding.2.to_le_bytes());
        self.execute(0x0402, &mut bytes, false)?;
        let got = self.bridge(port)?;
        if (if ingress {
            got.ingress_vlan
        } else {
            got.egress_vlan
        }) != binding
        {
            return Err(Error::ReadbackMismatch);
        }
        Ok(())
    }
}
