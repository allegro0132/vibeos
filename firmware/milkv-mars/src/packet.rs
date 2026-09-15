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
    #[cfg(feature = "rx-pool-experiment")]
    rx_initializer: Option<fn(&mut Ring<Backend<R, M>>) -> Result<(), ring::Error>>,
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
        let mut ring = Ring::new(backend, layout)?;
        ring.set_single_tx_sync(cfg!(feature = "tx-single-sync-experiment"))?;
        Ok(Self {
            ring,
            #[cfg(feature = "rx-pool-experiment")]
            rx_initializer: None,
            phy,
            link: None,
            faulted: false,
            tx_packets: 0,
            rx_packets: 0,
            rx_checksum_status: [0; 5],
            rx_verified: [0; 3],
        })
    }
    #[cfg(feature = "rx-pool-experiment")]
    pub fn set_rx_initializer(&mut self, init: fn(&mut Ring<Backend<R, M>>) -> Result<(), ring::Error>) {
        assert!(self.link.is_none() && !self.faulted);
        self.rx_initializer = Some(init);
    }
    #[cfg(feature = "rx-pool-experiment")]
    pub fn receive_detached<const D: usize, const N: usize>(&mut self,
        buffers: &mut impl vibeos_eqos_net::rx_buffers::Access<D, N>,
    ) -> Result<Option<ring::Detached>, Error> {
        if self.faulted { return Err(Error::Faulted); }
        if self.link.is_none() { return Ok(None); }
        match self.ring.receive_detached_scoped(buffers) {
            Ok(frame) => Ok(frame),
            Err(ring::Error::Full) => Err(ring::Error::Full.into()),
            Err(ring::Error::Descriptor(_)) => Ok(None),
            Err(error) => { self.fail(); Err(error.into()) }
        }
    }
    #[cfg(feature = "rx-batch-experiment")]
    pub fn receive_detached_batch<const D: usize, const N: usize>(&mut self,
        buffers: &mut impl vibeos_eqos_net::rx_buffers::Access<D, N>,
    ) -> Result<[Option<ring::Detached>; ring::RX_BATCH], Error> {
        if self.faulted { return Err(Error::Faulted); }
        if self.link.is_none() { return Ok([None; ring::RX_BATCH]); }
        match self.ring.receive_detached_batch(buffers) {
            Ok(frames) => Ok(frames),
            Err(ring::Error::Full) => Err(ring::Error::Full.into()),
            Err(ring::Error::Descriptor(_)) => Ok([None; ring::RX_BATCH]),
            Err(error) => { self.fail(); Err(error.into()) }
        }
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
        #[cfg(feature = "symmetric-pause-experiment")]
        {
            let (local, partner) = self.phy.advertisements()?;
            let pause = link.full_duplex && local & partner & (1 << 10) != 0;
            self.ring().set_symmetric_pause(pause)
                .map_err(|_| Error::Ring(ring::Error::Controller))?;
        }
        #[cfg(feature = "tso-experiment")]
        self.ring().set_tso(true).map_err(|_| Error::Ring(ring::Error::Controller))?;
        #[cfg(feature = "rx-pool-experiment")]
        if let Some(init) = self.rx_initializer { init(self.ring())?; }
        else { self.ring().initialize()?; }
        #[cfg(not(feature = "rx-pool-experiment"))]
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
    #[cfg(feature = "tso-experiment")]
    pub fn transmit_segments(&mut self, segments: vibeos_hal::tcp_segmentation::TcpSegments<'_>) -> Result<(),Error> {
        if self.faulted {return Err(Error::Faulted);}
        if self.link.is_none() {return Err(Error::Ring(ring::Error::Full));}
        let request=vibeos_eqos_net::tso::Request::from_segments(segments)
            .map_err(|_|Error::Ring(ring::Error::Packet))?;
        match self.ring().transmit_tso(request) {
            Ok(())=>{self.tx_packets=self.tx_packets.saturating_add(segments.wire_segments() as u64);Ok(())},
            Err(e @ (ring::Error::Full | ring::Error::Packet))=>Err(e.into()),
            Err(e)=>{self.fail();Err(e.into())}
        }
    }
    /// A malformed/oversized RX frame has already been dropped and rearmed by
    /// the ring. Hardware/controller failures instead quarantine this instance.
    pub fn receive_pending(&mut self) -> bool {
        self.faulted || (self.link.is_some() && self.ring().receive_pending().unwrap_or(true))
    }
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
            self.validate_rx_frame(&out[..f.bytes], f.checksum).then_some(f.bytes)
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
    /// Same checksum admission for copied and detached receive paths.
    pub fn validate_rx_frame(&mut self, bytes: &[u8], checksum: vibeos_eqos_net::descriptor::RxChecksum) -> bool {
        #[cfg(not(feature = "rx-status-experiment"))]
        { let _ = (bytes, checksum); }
        #[cfg(feature = "rx-status-experiment")]
        {
            use vibeos_eqos_net::descriptor::RxChecksum as C;
            let index = match checksum {
                C::Unavailable => 0, C::Bypassed => 1, C::Error => 2,
                C::Ipv4 { .. } => 3, C::Ipv6 { .. } => 4,
            };
            self.rx_checksum_status[index] = self.rx_checksum_status[index].saturating_add(1);
            // IPC errors need not set the descriptor error-summary bit.
            // Count the observation, but never enqueue this frame to a client.
            if matches!(checksum, C::Error) {
                #[cfg(feature = "rx-ipv4-checksum-experiment")]
                { self.rx_verified[2] = self.rx_verified[2].saturating_add(1); }
                return false;
            }
            #[cfg(feature = "rx-ipv4-checksum-experiment")]
            {
                use vibeos_eqos_net::checksum::{verify_rx_ipv4, RxVerified as V};
                match verify_rx_ipv4(bytes, checksum) {
                    Ok(V::Hardware) => self.rx_verified[0] = self.rx_verified[0].saturating_add(1),
                    Ok(V::Software) => self.rx_verified[1] = self.rx_verified[1].saturating_add(1),
                    // This experiment is for the current IPv4-only stack. ARP
                    // has no IP/transport checksum. Never pass unchecked IPv6
                    // while advertising global transport checksum completion.
                    Ok(V::NonIpv4) if bytes.get(12..14) == Some(&[0x08, 0x06]) => {},
                    _ => {
                        self.rx_verified[2] = self.rx_verified[2].saturating_add(1);
                        return false;
                    }
                }
            }
        }
        true
    }
    pub fn dma_diagnostics(&mut self) -> Option<vibeos_eqos_net::controller::DmaDiagnostics> {
        self.ring.diagnostics()
    }
    pub fn rx_diagnostics(&self) -> ring::RxDiagnostics { self.ring.rx_diagnostics() }
    pub fn flow_diagnostics(&mut self) -> Option<[u32; 4]> { self.ring.flow_diagnostics() }
    pub fn pending_tx(&self) -> usize { self.ring.pending() }
    pub fn advertisements(&mut self) -> Result<(u16, u16), Error> {
        self.phy.advertisements().map_err(Error::Phy)
    }
    pub fn mmc_tx_counters(&mut self) -> Option<vibeos_eqos_net::controller::MmcTxCounters> {
        self.ring.mmc_tx_counters()
    }
    pub fn shutdown(&mut self) -> bool {
        self.link = None;
        let stopped = self.ring().shutdown();
        // Retired instances cannot resume, even after a successful stop.
        self.faulted = true;
        stopped
    }
}
