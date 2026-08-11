//! Typed network messages and directional views over the kernel channel.
//!
//! [`Packet`] is the pure Ethernet frame. Driver/stack boundaries carry it only
//! inside [`StampedPacket`], whose immutable [`PacketStamp`] prevents queued
//! traffic from crossing a device or stack restart. The channel itself remains
//! the capability-addressed [`Endpoint<T>`]; [`SendEndpoint`] and
//! [`RecvEndpoint`] are deliberately narrow views for code that should use only
//! one direction.

extern crate alloc;

use alloc::sync::Arc;
use core::fmt;
use core::num::NonZeroU64;

pub use crate::chan::Endpoint;
pub use vibeos_hal::{MAX_ETHERNET_FRAME_LEN, MAX_PACKET_LEN};

/// The bidirectional typed endpoint object before its interface is narrowed.
pub type DuplexEndpoint<T> = Endpoint<T>;

/// An owned Ethernet frame with fixed, allocation-free storage.
///
/// Construction always copies exactly the logical frame bytes and
/// zero-initializes the unused tail.  The private `u16` length keeps the
/// representation to the fixed 1,514-byte payload plus its two-byte length.
#[repr(C)]
#[derive(Clone, PartialEq, Eq)]
pub struct Packet {
    bytes: [u8; MAX_PACKET_LEN],
    len: u16,
}

/// Exact identity of one device/stack packet session.
///
/// Both halves are non-zero and immutable. A device incarnation owns the
/// epoch while each stack binding advances the generation; comparing the
/// complete value prevents queued packets from crossing either restart.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PacketStamp {
    device_epoch: NonZeroU64,
    stack_generation: NonZeroU64,
}

/// Why a packet-session stamp could not be constructed or advanced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketStampError {
    ZeroDeviceEpoch,
    ZeroStackGeneration,
    DeviceEpochExhausted,
    StackGenerationExhausted,
}

impl fmt::Display for PacketStampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDeviceEpoch => f.write_str("packet device epoch must be non-zero"),
            Self::ZeroStackGeneration => f.write_str("packet stack generation must be non-zero"),
            Self::DeviceEpochExhausted => f.write_str("packet device epoch space exhausted"),
            Self::StackGenerationExhausted => {
                f.write_str("packet stack generation space exhausted")
            }
        }
    }
}

impl PacketStamp {
    pub fn new(device_epoch: u64, stack_generation: u64) -> Result<Self, PacketStampError> {
        let device_epoch =
            NonZeroU64::new(device_epoch).ok_or(PacketStampError::ZeroDeviceEpoch)?;
        let stack_generation =
            NonZeroU64::new(stack_generation).ok_or(PacketStampError::ZeroStackGeneration)?;
        Ok(Self {
            device_epoch,
            stack_generation,
        })
    }

    pub const fn device_epoch(self) -> u64 {
        self.device_epoch.get()
    }

    pub const fn stack_generation(self) -> u64 {
        self.stack_generation.get()
    }

    /// Return the next device incarnation without changing this value.
    pub fn next_device_epoch(self) -> Result<Self, PacketStampError> {
        let device_epoch = self
            .device_epoch()
            .checked_add(1)
            .ok_or(PacketStampError::DeviceEpochExhausted)?;
        Self::new(device_epoch, self.stack_generation())
    }

    /// Return the next stack incarnation without wrapping the generation.
    pub fn next_stack_generation(self) -> Result<Self, PacketStampError> {
        let stack_generation = self
            .stack_generation()
            .checked_add(1)
            .ok_or(PacketStampError::StackGenerationExhausted)?;
        Self::new(self.device_epoch(), stack_generation)
    }
}

/// A complete Ethernet frame sealed to one exact packet session.
///
/// There is intentionally no mutable stamp setter and no direct byte-slice
/// implementation. A receiver must successfully call [`Self::into_packet`]
/// with its expected stamp before the raw frame becomes available.
#[repr(C)]
#[derive(Clone, PartialEq, Eq)]
pub struct StampedPacket {
    stamp: PacketStamp,
    packet: Packet,
}

/// Evidence that a queued packet belongs to a different session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketStampMismatch {
    pub expected: PacketStamp,
    pub observed: PacketStamp,
}

impl PacketStampMismatch {
    pub const fn device_epoch_changed(self) -> bool {
        self.expected.device_epoch() != self.observed.device_epoch()
    }

    pub const fn stack_generation_changed(self) -> bool {
        self.expected.stack_generation() != self.observed.stack_generation()
    }
}

impl fmt::Display for PacketStampMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "packet stamp mismatch: expected device epoch {} / stack generation {}, observed {} / {}",
            self.expected.device_epoch(),
            self.expected.stack_generation(),
            self.observed.device_epoch(),
            self.observed.stack_generation()
        )
    }
}

impl StampedPacket {
    pub const fn new(packet: Packet, stamp: PacketStamp) -> Self {
        Self { stamp, packet }
    }

    pub fn copy_from(frame: &[u8], stamp: PacketStamp) -> Result<Self, PacketError> {
        Packet::copy_from(frame).map(|packet| Self::new(packet, stamp))
    }

    pub const fn stamp(&self) -> PacketStamp {
        self.stamp
    }

    /// Open a frame only when both session coordinates match exactly.
    ///
    /// A mismatch consumes and drops the frame rather than returning a payload
    /// which a caller could accidentally process after observing the error.
    pub fn into_packet(self, expected: PacketStamp) -> Result<Packet, PacketStampMismatch> {
        if self.stamp == expected {
            Ok(self.packet)
        } else {
            Err(PacketStampMismatch {
                expected,
                observed: self.stamp,
            })
        }
    }
}

impl fmt::Debug for StampedPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StampedPacket")
            .field("stamp", &self.stamp)
            .field("len", &self.packet.len())
            .finish()
    }
}

/// Fail-closed driver-side session state shared by hardware backends.
///
/// Historical counters survive detach. `attach_device` and `bind_stack`
/// advance them with checked arithmetic; every failed rebind leaves the fence
/// inactive. The driver may then stamp received frames and admit transmitted
/// frames only through the active exact session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacketSessionFence {
    device_epoch: u64,
    stack_generation: u64,
    device_attached: bool,
    active: Option<PacketStamp>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketSessionError {
    DeviceEpochExhausted,
    StackGenerationExhausted,
    TransmitBusy { in_flight: usize },
    Inactive,
    StampMismatch(PacketStampMismatch),
}

impl fmt::Display for PacketSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceEpochExhausted => f.write_str("packet device epoch space exhausted"),
            Self::StackGenerationExhausted => {
                f.write_str("packet stack generation space exhausted")
            }
            Self::TransmitBusy { in_flight } => {
                write!(
                    f,
                    "cannot bind packet stack with {in_flight} transmit frames in flight"
                )
            }
            Self::Inactive => f.write_str("packet session fence is inactive"),
            Self::StampMismatch(error) => error.fmt(f),
        }
    }
}

impl PacketSessionFence {
    pub const fn new() -> Self {
        Self {
            device_epoch: 0,
            stack_generation: 0,
            device_attached: false,
            active: None,
        }
    }

    /// Restore monotonic history without restoring a live binding.
    pub const fn from_history(device_epoch: u64, stack_generation: u64) -> Self {
        Self {
            device_epoch,
            stack_generation,
            device_attached: false,
            active: None,
        }
    }

    pub const fn device_epoch(&self) -> u64 {
        self.device_epoch
    }

    pub const fn stack_generation(&self) -> u64 {
        self.stack_generation
    }

    pub const fn active_stamp(&self) -> Option<PacketStamp> {
        self.active
    }

    pub const fn device_attached(&self) -> bool {
        self.device_attached
    }

    /// Attach a fresh device incarnation and invalidate every stack binding.
    pub fn attach_device(&mut self) -> Result<u64, PacketSessionError> {
        self.active = None;
        self.device_attached = false;
        self.device_epoch = self
            .device_epoch
            .checked_add(1)
            .ok_or(PacketSessionError::DeviceEpochExhausted)?;
        self.device_attached = true;
        Ok(self.device_epoch)
    }

    pub fn detach_device(&mut self) {
        self.active = None;
        self.device_attached = false;
    }

    /// Bind a fresh stack only after all previously admitted TX work is gone.
    pub fn bind_stack(&mut self, tx_inflight: usize) -> Result<PacketStamp, PacketSessionError> {
        self.active = None;
        if tx_inflight != 0 {
            return Err(PacketSessionError::TransmitBusy {
                in_flight: tx_inflight,
            });
        }
        if !self.device_attached {
            return Err(PacketSessionError::Inactive);
        }
        self.stack_generation = self
            .stack_generation
            .checked_add(1)
            .ok_or(PacketSessionError::StackGenerationExhausted)?;
        let stamp = PacketStamp::new(self.device_epoch, self.stack_generation)
            .expect("checked packet session counters are non-zero");
        self.active = Some(stamp);
        Ok(stamp)
    }

    pub fn unbind_stack(&mut self) {
        self.active = None;
    }

    /// Seal one device-received frame for the currently bound stack.
    pub fn stamp_ingress(&self, packet: Packet) -> Result<StampedPacket, PacketSessionError> {
        let stamp = self.active.ok_or(PacketSessionError::Inactive)?;
        Ok(StampedPacket::new(packet, stamp))
    }

    /// Admit one stack-produced frame only for the current exact binding.
    pub fn accept_egress(&self, packet: StampedPacket) -> Result<Packet, PacketSessionError> {
        let stamp = self.active.ok_or(PacketSessionError::Inactive)?;
        packet
            .into_packet(stamp)
            .map_err(PacketSessionError::StampMismatch)
    }
}

/// Why bytes could not be converted into a [`Packet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    /// An empty byte slice is not an Ethernet frame.
    Empty,
    /// The frame would not fit in the fixed packet representation.
    TooLong { len: usize, max: usize },
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("an Ethernet packet cannot be empty"),
            Self::TooLong { len, max } => {
                write!(f, "Ethernet packet length {len} exceeds maximum {max}")
            }
        }
    }
}

/// Why a packet could not be copied into a caller's buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketBufferTooSmall {
    pub required: usize,
    pub provided: usize,
}

impl fmt::Display for PacketBufferTooSmall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "packet requires {} bytes but destination provides {}",
            self.required, self.provided
        )
    }
}

impl Packet {
    pub const MAX_LEN: usize = MAX_PACKET_LEN;

    /// Copy one complete Ethernet frame into owned, fixed-size storage.
    pub fn copy_from(frame: &[u8]) -> Result<Self, PacketError> {
        if frame.is_empty() {
            return Err(PacketError::Empty);
        }
        if frame.len() > Self::MAX_LEN {
            return Err(PacketError::TooLong {
                len: frame.len(),
                max: Self::MAX_LEN,
            });
        }

        let mut bytes = [0; MAX_PACKET_LEN];
        bytes[..frame.len()].copy_from_slice(frame);
        Ok(Self {
            bytes,
            // Safe because MAX_LEN is 1,514, well below u16::MAX.
            len: frame.len() as u16,
        })
    }

    /// Number of meaningful frame bytes.
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Packet construction rejects empty frames, so this is always false for
    /// every safely constructed value.  It is provided with the usual slice
    /// access vocabulary.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Borrow only the meaningful frame bytes; the zero-filled tail is never
    /// exposed as protocol data.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }

    /// Copy the complete logical frame to `destination`.
    ///
    /// A short destination is rejected before any byte is written.  On
    /// success, bytes beyond the returned length are left untouched.
    pub fn copy_to(&self, destination: &mut [u8]) -> Result<usize, PacketBufferTooSmall> {
        let required = self.len();
        if destination.len() < required {
            return Err(PacketBufferTooSmall {
                required,
                provided: destination.len(),
            });
        }
        destination[..required].copy_from_slice(self.as_bytes());
        Ok(required)
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet")
            .field("len", &self.len())
            .field("bytes", &self.as_bytes())
            .finish()
    }
}

impl AsRef<[u8]> for Packet {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl TryFrom<&[u8]> for Packet {
    type Error = PacketError;

    fn try_from(frame: &[u8]) -> Result<Self, Self::Error> {
        Self::copy_from(frame)
    }
}

/// A send-only typed view of an [`Endpoint<T>`].
///
/// This view narrows an already-resolved endpoint for protocol code.  The
/// capability lookup which produced the endpoint remains the authority
/// boundary and must require `Rights::SEND`.
///
/// ```compile_fail
/// # use std::sync::Arc;
/// # use vibeos_core::net::{directional, Endpoint, Packet};
/// # let endpoint: Arc<Endpoint<Packet>> = Endpoint::new("net", 1);
/// let (sender, _) = directional(endpoint);
/// sender.try_recv();
/// ```
pub struct SendEndpoint<T: Send + 'static> {
    endpoint: Arc<Endpoint<T>>,
}

impl<T: Send + 'static> Clone for SendEndpoint<T> {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
        }
    }
}

impl<T: Send + 'static> SendEndpoint<T> {
    pub fn try_send(&self, message: T) -> Result<(), T> {
        self.endpoint.try_send(message)
    }

    pub async fn send(&self, message: T) {
        self.endpoint.send(message).await;
    }

    pub fn stats(&self) -> (u64, u64, usize) {
        self.endpoint.stats()
    }
}

/// A receive-only typed view of an [`Endpoint<T>`].
///
/// The capability lookup which produced the endpoint must require
/// `Rights::RECV`; this type then prevents accidental sends in the receiving
/// component's protocol implementation.
///
/// ```compile_fail
/// # use std::sync::Arc;
/// # use vibeos_core::net::{directional, Endpoint, Packet};
/// # let endpoint: Arc<Endpoint<Packet>> = Endpoint::new("net", 1);
/// let (_, receiver) = directional(endpoint);
/// # let packet = Packet::copy_from(&[1]).unwrap();
/// receiver.try_send(packet);
/// ```
pub struct RecvEndpoint<T: Send + 'static> {
    endpoint: Arc<Endpoint<T>>,
}

impl<T: Send + 'static> Clone for RecvEndpoint<T> {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
        }
    }
}

impl<T: Send + 'static> RecvEndpoint<T> {
    pub fn try_recv(&self) -> Option<T> {
        self.endpoint.try_recv()
    }

    pub async fn recv(&self) -> T {
        self.endpoint.recv().await
    }

    pub fn stats(&self) -> (u64, u64, usize) {
        self.endpoint.stats()
    }
}

/// Narrow one bidirectional typed endpoint into send-only and receive-only
/// views over the same bounded queue.
pub fn directional<T: Send + 'static>(
    endpoint: Arc<Endpoint<T>>,
) -> (SendEndpoint<T>, RecvEndpoint<T>) {
    (
        SendEndpoint {
            endpoint: endpoint.clone(),
        },
        RecvEndpoint { endpoint },
    )
}

/// Narrow an endpoint to its send interface only.
pub fn send_only<T: Send + 'static>(endpoint: Arc<Endpoint<T>>) -> SendEndpoint<T> {
    SendEndpoint { endpoint }
}

/// Narrow an endpoint to its receive interface only.
pub fn recv_only<T: Send + 'static>(endpoint: Arc<Endpoint<T>>) -> RecvEndpoint<T> {
    RecvEndpoint { endpoint }
}

/// A raw-frame endpoint for diagnostics which do not cross a session fence.
pub type RawPacketEndpoint = DuplexEndpoint<Packet>;

/// The driver/stack transport: stamped packets, never an unframed byte stream.
pub type PacketEndpoint = DuplexEndpoint<StampedPacket>;
