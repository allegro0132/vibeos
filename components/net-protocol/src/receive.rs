//! Directional receive authority, preserving the legacy packet endpoint.
use vibeos_core::{cap::{CapError, Revocable}, chan::Endpoint, net::StampedPacket};
#[cfg(feature = "pooled-rx")]
use vibeos_core::{heap::AllocationDomain, net::PacketStamp,
    net_receive::{ReceiveEndpoint, Loan, Error as ReceiveError}};
#[derive(Clone)]
pub enum PacketReceive {
    Raw(Revocable<Endpoint<StampedPacket>>),
    #[cfg(feature = "pooled-rx")]
    Pooled { authority: Revocable<ReceiveEndpoint>, domain: AllocationDomain },
}
impl From<Revocable<Endpoint<StampedPacket>>> for PacketReceive {
    fn from(authority: Revocable<Endpoint<StampedPacket>>) -> Self { Self::Raw(authority) }
}
impl PacketReceive {
    #[cfg(feature = "rx-admission-batch")]
    pub(crate) fn receive_batch_into(&self, stamp: PacketStamp, limit: usize,
        batch: &mut vibeos_core::net_receive::LoanBatch) -> Option<Result<Result<usize, ReceiveError>, CapError>> {
        match self {
            Self::Raw(_) => None,
            Self::Pooled { authority, domain } => Some(authority.try_with(|q| q.try_receive_batch_into(stamp, *domain, limit, batch))),
        }
    }
    /// Notification only; callers must revalidate all device/session authority.
    pub fn message_event(&self) -> Result<vibeos_core::chan::MessageEvent, CapError> {
        match self {
            Self::Raw(q) => q.try_with(|q| q.message_event()),
            #[cfg(feature = "pooled-rx")]
            Self::Pooled { authority, .. } => authority.try_with(|q| q.message_event()),
        }
    }

    pub(crate) fn revalidate(&self) -> Result<(), CapError> {
        match self {
            Self::Raw(q) => q.try_with(|_| ()),
            #[cfg(feature = "pooled-rx")]
            Self::Pooled { authority, .. } => authority.try_with(|_| ()),
        }
    }
    pub(crate) fn has_message(&self) -> Result<bool, CapError> {
        match self {
            Self::Raw(q) => q.try_with(|q| q.has_message()),
            #[cfg(feature = "pooled-rx")]
            Self::Pooled { authority, .. } => authority.try_with(|q| q.has_message()),
        }
    }
    pub(crate) fn raw_receive(&self) -> Result<Option<StampedPacket>, CapError> {
        match self {
            Self::Raw(q) => q.try_with(|q| q.try_recv()),
            #[cfg(feature = "pooled-rx")]
            Self::Pooled { .. } => unreachable!("pooled receive is admitted separately"),
        }
    }
    #[cfg(feature = "pooled-rx")]
    pub(crate) fn receive_loan(&self, stamp: PacketStamp) -> Option<Result<Result<Option<Loan>, ReceiveError>, CapError>> {
        match self {
            Self::Raw(_) => None,
            Self::Pooled { authority, domain } => Some(authority.try_with(|q| q.try_receive(stamp, *domain))),
        }
    }
}
