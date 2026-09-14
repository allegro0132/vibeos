//! Compatible raw transport plus the opt-in ordered pooled transmit resource.
use vibeos_core::{cap::{CapError, Revocable}, chan::Endpoint, net::StampedPacket};
#[cfg(feature = "native-tcp-segmentation")]
use vibeos_core::{net::PacketStamp, heap::AllocationDomain, net_segment_pool::{Error, Ticket}, net_transmit::{Transmit, TransmitEndpoint}};

#[derive(Clone)]
pub enum PacketTransmit {
    Raw(Revocable<Endpoint<StampedPacket>>),
    #[cfg(feature = "native-tcp-segmentation")]
    /// The supervisor supplies its executor-derived allocation domain; it is
    /// used to retire abandoned reservations before arena reuse/rebinding.
    Pooled { authority: Revocable<TransmitEndpoint>, domain: AllocationDomain },
}
impl From<Revocable<Endpoint<StampedPacket>>> for PacketTransmit {
    fn from(value: Revocable<Endpoint<StampedPacket>>) -> Self { Self::Raw(value) }
}
impl PacketTransmit {
    pub(crate) fn revalidate(&self) -> Result<(),CapError> {
        match self {
            Self::Raw(q) => q.try_with(|_|()),
            #[cfg(feature = "native-tcp-segmentation")]
            Self::Pooled { authority, .. } => authority.try_with(|_|()),
        }
    }
    pub(crate) fn send_frame(&self, frame: StampedPacket) -> Result<Result<(),StampedPacket>,CapError> {
        match self {
            Self::Raw(q) => q.try_with(|q|q.try_send(frame)),
            #[cfg(feature = "native-tcp-segmentation")]
            Self::Pooled { authority, .. } => authority.try_with(|q| match q.try_send(Transmit::Frame(frame)) {
                Ok(()) => Ok(()), Err(Transmit::Frame(frame)) => Err(frame), _ => unreachable!(),
            }),
        }
    }
    #[cfg(feature = "native-tcp-segmentation")]
    pub(crate) fn reserve(&self, stamp: PacketStamp) -> Result<Option<Reservation>,ReserveError> {
        match self {
            Self::Raw(_) => Ok(None),
            Self::Pooled { authority, domain } => {
                let ticket = authority.try_with(|q|q.pool().reserve(stamp,*domain))
                    .map_err(|_|ReserveError::Revoked)?.map_err(ReserveError::Pool)?;
                Ok(Some(Reservation { authority: authority.clone(), ticket: Some(ticket), stamp, frames: 0 }))
            }
        }
    }
}
#[cfg(feature = "native-tcp-segmentation")]
pub(crate) enum ReserveError { Revoked, Pool(Error) }
#[cfg(feature = "native-tcp-segmentation")]
pub(crate) struct Reservation {
    pub(crate) authority: Revocable<TransmitEndpoint>,
    pub(crate) ticket: Option<Ticket>,
    pub(crate) stamp: PacketStamp,
    pub(crate) frames: u64,
}
#[cfg(feature = "native-tcp-segmentation")]
impl Reservation {
    pub(crate) fn publish(&mut self) -> Result<bool,ReserveError> {
        let ticket=self.ticket.expect("live reservation");
        let result=self.authority.try_with(|q|q.publish(ticket,self.stamp))
            .map_err(|_|ReserveError::Revoked)?.map_err(ReserveError::Pool)?;
        if result.is_ok() { self.ticket=None; Ok(true) } else { Ok(false) }
    }
}
#[cfg(feature = "native-tcp-segmentation")]
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(ticket)=self.ticket.take() {
            // A revoked/faulted owner is retired by the supervisor's pool hook;
            // local cleanup never bypasses revoked authority.
            let _=self.authority.try_with(|q|q.pool().cancel(ticket,self.stamp));
        }
    }
}
