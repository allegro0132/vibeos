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
    /// A malformed/oversized RX frame has already been dropped and rearmed by
    /// the ring. Hardware/controller failures instead quarantine this instance.
    pub fn receive(&mut self, out: &mut [u8]) -> Result<Option<usize>, Error> {
        if self.faulted {
            return Err(Error::Faulted);
        }
        if self.link.is_none() {
            return Ok(None);
        }
        match self.ring().receive(out) {
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
    pub fn shutdown(&mut self) -> bool {
        self.link = None;
        let stopped = self.ring().shutdown();
        // Retired instances cannot resume, even after a successful stop.
        self.faulted = true;
        stopped
    }
}
