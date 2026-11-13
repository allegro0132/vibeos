//! Qualified bridge-domain ABI. Probes never attach a domain to a port.
use super::{Error, Io, Mailbox};

const PORTS: [u16; 11] = [1, 2, 3, 4, 9, 13, 17, 18, 19, 20, 29];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloodMode {
    Members,
    Discard,
    Cpu,
}
impl FloodMode {
    fn wire(self) -> u32 {
        match self {
            Self::Members => 0,
            Self::Discard => 1,
            Self::Cpu => 2,
        }
    }
    fn decode(v: u32) -> Result<Self, Error> {
        match v {
            0 => Ok(Self::Members),
            1 => Ok(Self::Discard),
            2 => Ok(Self::Cpu),
            _ => Err(Error::InvalidResponse),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainPolicy {
    pub learning_limit: Option<u16>,
    /// Broadcast, unknown IP multicast, unknown non-IP multicast, unknown UC.
    pub flood: [FloodMode; 4],
}
impl DomainPolicy {
    pub(super) fn request(self, id: u16) -> Result<[u8; 49], Error> {
        // Qualified firmware keeps only eight bits: 1022 reads back as
        // 254, 1024 as zero, and low byte 255 means unlimited.
        if self.learning_limit.is_some_and(|limit| limit > 254) {
            return Err(Error::InvalidState);
        }
        let mut b = [0; 49];
        b[..2].copy_from_slice(&id.to_le_bytes());
        // Only learning limit and forwarding mode, never meters or counters.
        b[2..6].copy_from_slice(&0x11u32.to_le_bytes());
        if let Some(limit) = self.learning_limit {
            b[6] = 1;
            b[7..9].copy_from_slice(&limit.to_le_bytes());
        }
        for (i, mode) in self.flood.into_iter().enumerate() {
            b[33 + i * 4..37 + i * 4].copy_from_slice(&mode.wire().to_le_bytes());
        }
        Ok(b)
    }
    fn decode(id: u16, b: &[u8; 49]) -> Result<Self, Error> {
        if b[..2] != id.to_le_bytes() || b[6] > 1 {
            return Err(Error::InvalidResponse);
        }
        let mut flood = [FloodMode::Discard; 4];
        for (i, mode) in flood.iter_mut().enumerate() {
            *mode = FloodMode::decode(u32::from_le_bytes(
                b[33 + i * 4..37 + i * 4].try_into().unwrap(),
            ))?;
        }
        Ok(Self {
            learning_limit: (b[6] != 0).then(|| u16::from_le_bytes([b[7], b[8]])),
            flood,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Learning {
    pub destination_lookup_disabled: bool,
    pub source_learning_disabled: bool,
    pub limit: Option<u16>,
    pub learned: u16,
}

#[derive(Debug)]
pub struct DomainProbe {
    pub id: u16,
    pub verified: u8,
    pub observed: Option<DomainPolicy>,
    pub failure: Option<Error>,
    pub cleanup_error: Option<Error>,
}

impl<I: Io> Mailbox<'_, I> {
    /// Read-only port policy, separate from the legacy path-identity query.
    pub fn port_learning(&mut self, port: u16) -> Result<Learning, Error> {
        if !PORTS.contains(&port) {
            return Err(Error::InvalidPort);
        }
        let mut b = [0; 186];
        b[..2].copy_from_slice(&port.to_le_bytes());
        b[2..6].copy_from_slice(&0x19800u32.to_le_bytes());
        self.query(0x0403, &mut b)?;
        if b[..2] != port.to_le_bytes() || [149, 150, 153].iter().any(|i| b[*i] > 1) {
            return Err(Error::InvalidResponse);
        }
        Ok(Learning {
            destination_lookup_disabled: b[149] != 0,
            source_learning_disabled: b[150] != 0,
            limit: (b[153] != 0).then(|| u16::from_le_bytes([b[154], b[155]])),
            learned: u16::from_le_bytes([b[158], b[159]]),
        })
    }

    pub(super) fn domain_policy(&mut self, id: u16) -> Result<DomainPolicy, Error> {
        let mut b = DomainPolicy {
            learning_limit: None,
            flood: [FloodMode::Members; 4],
        }
        .request(id)?;
        self.query(0x0303, &mut b)?;
        DomainPolicy::decode(id, &b)
    }

    /// Requires exclusive switch configuration ownership. Allocation and FREE
    /// are submitted once only. A lost allocation response can leak an unknown
    /// unbound domain; a lost FREE response is reported and never retried.
    /// Inherited/active domains are never written or freed by this probe.
    pub fn probe_bridge_domain(&mut self) -> Result<DomainProbe, Error> {
        let v = self.version()?;
        if (v.major, v.minor, v.revision, v.build) != (1, 0, 70, 70) {
            return Err(Error::UnsupportedFirmware);
        }
        let mut inherited = [0; PORTS.len()];
        for (i, port) in PORTS.into_iter().enumerate() {
            inherited[i] = self.bridge(port)?.id;
        }
        let mut allocation = [0; 2];
        self.query(0x0301, &mut allocation)?;
        let id = u16::from_le_bytes(allocation);
        if id == 0 || id == u16::MAX || inherited.contains(&id) {
            // A corrupt allocation response is not authority to touch this ID.
            return Err(Error::InvalidResponse);
        }
        let mut report = DomainProbe {
            id,
            verified: 0,
            observed: None,
            failure: None,
            cleanup_error: None,
        };
        let exercise = (|| {
            self.domain_policy(id)?;
            for policy in [
                DomainPolicy {
                    learning_limit: Some(64),
                    flood: [FloodMode::Discard; 4],
                },
                DomainPolicy {
                    learning_limit: Some(254),
                    flood: [FloodMode::Members; 4],
                },
            ] {
                self.execute(0x0302, &mut policy.request(id)?, false)?;
                let observed = self.domain_policy(id)?;
                report.observed = Some(observed);
                if observed != policy {
                    return Err(Error::ReadbackMismatch);
                }
                report.verified += 1;
            }
            Ok(())
        })();
        report.failure = exercise.err();
        // No port has been attached by this API, including on failure.
        report.cleanup_error = self.execute(0x0304, &mut allocation, false).err();
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
