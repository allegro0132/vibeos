//! Firmware coordination of independent PHY and DMA engines. No capability,
//! session-generation, queue scheduling or automatic retry policy lives here.
use vibeos_eqos_net::{
    backend::{Backend, Memory},
    controller::Io,
    ring::{self, Layout, Ring},
};
use vibeos_ethernet::{
    phy::{self, Link, Yt8531},
    MdioPort,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Phy(phy::Error),
    Ring(ring::Error),
    Faulted,
}
impl From<phy::Error> for Error {
    fn from(e: phy::Error) -> Self {
        Self::Phy(e)
    }
}
impl From<ring::Error> for Error {
    fn from(e: ring::Error) -> Self {
        Self::Ring(e)
    }
}

pub struct Engine<R: Io + 'static, M: Memory, P: MdioPort> {
    ring: Ring<Backend<R, M>>,
    phy: Yt8531<P>,
    link: Option<Link>,
    faulted: bool,
    pub tx_packets: u64,
    pub rx_packets: u64,
    /// Unavailable, bypassed, error, IPv4, IPv6 observations; never skip checks.
    pub rx_checksum_status: [u64; 5],
    /// Hardware verified, software verified, verification/profile drops.
    pub rx_verified: [u64; 3],
}
impl<R: Io + 'static, M: Memory, P: MdioPort> Engine<R, M, P> {
    /// PHY must have completed initialize. No DMA starts until poll_link sees
    /// a resolved link and has configured PHY phase with the MAC stopped.
    pub fn new(
        backend: &'static mut Backend<R, M>,
        layout: Layout,
        phy: Yt8531<P>,
    ) -> Result<Self, Error> {
        Ok(Self {
            ring: Ring::new(backend, layout)?,
            phy,
            link: None,
            faulted: false,
            tx_packets: 0,
            rx_packets: 0,
            rx_checksum_status: [0; 5],
            rx_verified: [0; 3],
        })
    }
    pub fn link(&self) -> Option<Link> {
        self.link
    }
    fn ring(&mut self) -> &mut Ring<Backend<R, M>> {
        &mut self.ring
    }
    fn fail(&mut self) {
        self.faulted = true;
        self.link = None;
        self.ring().fault();
    }
    /// Link changes abandon prior in-flight packets only after a proven stop.
    /// A failed stop/configuration never reuses that ring or retries its packets.
    pub fn poll_link(&mut self) -> Result<(), Error> {
        if self.faulted {
            return Err(Error::Faulted);
        }
        let result = self.update_link();
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn update_link(&mut self) -> Result<(), Error> {
        let observed = self.phy.poll_link()?;
        if observed == self.link {
            return Ok(());
        }
        if !self.ring().shutdown() {
            return Err(Error::Ring(ring::Error::Controller));
        }
        self.link = None;
        let Some(link) = observed else {
            return Ok(());
        };
        if !self.phy.configure_link(link)? {
            return Ok(());
        }
        self.ring()
            .set_link(link.speed, link.full_duplex)
            .map_err(|_| Error::Ring(ring::Error::Controller))?;
        self.ring().initialize()?;
        self.link = Some(link);
        Ok(())
    }
    pub fn tx_owned(&mut self) -> Result<bool, Error> {
        if self.faulted {
            return Err(Error::Faulted);
        }
        if self.link.is_none() {
            return Ok(false);
        }
        match self.ring().reap() {
            Ok(_) => Ok(self.ring().pending() != 0),
            Err(e) => {
                self.fail();
                Err(e.into())
            }
        }
    }
    pub fn transmit(&mut self, packet: &[u8]) -> Result<(), Error> {
        if self.faulted {
            return Err(Error::Faulted);
        }
        if self.link.is_none() {
            return Err(Error::Ring(ring::Error::Full));
        }
        match self.ring().transmit(packet) {
            Ok(()) => {
                self.tx_packets = self.tx_packets.saturating_add(1);
                Ok(())
            }
            Err(e @ (ring::Error::Full | ring::Error::Packet)) => Err(e.into()),
            Err(e) => {
                self.fail();
                Err(e.into())
            }
        }
    }
    /// Experimental complete-packet TX checksum path; raw TX is unchanged.
    pub fn transmit_checksum(&mut self, packet: &[u8]) -> Result<(), Error> {
        if self.faulted { return Err(Error::Faulted); }
        if self.link.is_none() { return Err(Error::Ring(ring::Error::Full)); }
        let request = match vibeos_eqos_net::checksum::Request::new(packet) {
            Ok(request) => request,
            // The raw HAL preserves already-checksummed fragments. The composed
            // smoltcp image emits complete packets (fragmentation is disabled).
            Err(vibeos_eqos_net::checksum::Error::Fragmented) => return self.transmit(packet),
            Err(_) => return Err(Error::Ring(ring::Error::Packet)),
        };
        match self.ring().transmit_request(request) {
            Ok(()) => { self.tx_packets = self.tx_packets.saturating_add(1); Ok(()) }
            Err(e @ (ring::Error::Full | ring::Error::Packet)) => Err(e.into()),
            Err(e) => { self.fail(); Err(e.into()) }
        }
    }
    /// A malformed/oversized RX frame has already been dropped and rearmed by
    /// the ring. Hardware/controller failures instead quarantine this instance.
    pub fn receive(&mut self, out: &mut [u8]) -> Result<Option<usize>, Error> {
        if self.faulted {
            return Err(Error::Faulted);
        }
        if self.link.is_none() {
            return Ok(None);
        }
        #[cfg(not(feature = "rx-status-experiment"))]
        let result = self.ring().receive(out);
        #[cfg(feature = "rx-status-experiment")]
        let result = self.ring().receive_with_status(out).map(|frame| frame.and_then(|f| {
            use vibeos_eqos_net::descriptor::RxChecksum as C;
            let index = match f.checksum {
                C::Unavailable => 0, C::Bypassed => 1, C::Error => 2,
                C::Ipv4 { .. } => 3, C::Ipv6 { .. } => 4,
            };
            self.rx_checksum_status[index] = self.rx_checksum_status[index].saturating_add(1);
            // IPC errors need not set the descriptor error-summary bit.
            // Count the observation, but never enqueue this frame to a client.
            if matches!(f.checksum, C::Error) {
                #[cfg(feature = "rx-ipv4-checksum-experiment")]
                { self.rx_verified[2] = self.rx_verified[2].saturating_add(1); }
                return None;
            }
            #[cfg(feature = "rx-ipv4-checksum-experiment")]
            {
                use vibeos_eqos_net::checksum::{verify_rx_ipv4, RxVerified as V};
                match verify_rx_ipv4(&out[..f.bytes], f.checksum) {
                    Ok(V::Hardware) => self.rx_verified[0] = self.rx_verified[0].saturating_add(1),
                    Ok(V::Software) => self.rx_verified[1] = self.rx_verified[1].saturating_add(1),
                    // This experiment is for the current IPv4-only stack. ARP
                    // has no IP/transport checksum. Never pass unchecked IPv6
                    // while advertising global transport checksum completion.
                    Ok(V::NonIpv4) if out.get(12..14) == Some(&[0x08, 0x06]) => {},
                    _ => {
                        self.rx_verified[2] = self.rx_verified[2].saturating_add(1);
                        return None;
                    }
                }
            }
            Some(f.bytes)
        }));
        match result {
            Ok(n) => {
                if n.is_some() {
                    self.rx_packets = self.rx_packets.saturating_add(1);
                }
                Ok(n)
            }
            Err(ring::Error::Descriptor(_) | ring::Error::OutputTooSmall) => Ok(None),
            Err(e) => {
                self.fail();
                Err(e.into())
            }
        }
    }
    pub fn dma_diagnostics(&mut self) -> Option<vibeos_eqos_net::controller::DmaDiagnostics> {
        self.ring.diagnostics()
    }
    pub fn rx_diagnostics(&self) -> ring::RxDiagnostics { self.ring.rx_diagnostics() }
    pub fn shutdown(&mut self) -> bool {
        self.link = None;
        let stopped = self.ring().shutdown();
        // Retired instances cannot resume, even after a successful stop.
        self.faulted = true;
        stopped
    }
}
