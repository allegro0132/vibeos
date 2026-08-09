//! Typed network messages and directional views over the kernel channel.
//!
//! Ethernet frames cross the component boundary as [`Packet`] values.  The
//! logical length is carried with a fixed-size backing array, so neither a
//! caller-provided length nor a growable byte stream becomes part of the
//! protocol.  The channel itself remains the capability-addressed
//! [`Endpoint<T>`]; [`SendEndpoint`] and [`RecvEndpoint`] are deliberately
//! narrow views for code that should use only one direction.

extern crate alloc;

use alloc::sync::Arc;
use core::fmt;

pub use crate::chan::Endpoint;

/// The bidirectional typed endpoint object before its interface is narrowed.
pub type DuplexEndpoint<T> = Endpoint<T>;

/// Largest Ethernet frame handled by the M4.4 network interface, excluding
/// the four-byte frame check sequence supplied and consumed by the device.
pub const MAX_PACKET_LEN: usize = 1_514;

/// Descriptive alias for [`MAX_PACKET_LEN`].
pub const MAX_ETHERNET_FRAME_LEN: usize = MAX_PACKET_LEN;

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

/// The concrete M4.4 socket transport: packets, never an unframed byte stream.
pub type PacketEndpoint = DuplexEndpoint<Packet>;
