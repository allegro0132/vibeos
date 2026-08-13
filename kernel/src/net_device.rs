//! Board-selected network-device frontend.
//!
//! Kernel components depend on this module rather than a concrete transport.
//! The firmware's board selection remains a compile-time choice, so the
//! re-export has no dynamic-dispatch or runtime probing cost.

// This private binary-crate module intentionally exposes the complete stable
// frontend even when a particular firmware image consumes only a subset.
#![allow(unused_imports)]

use alloc::{format, string::String};
use core::fmt::Write as _;

/// Capacity of the stable packet channels between a device driver and its
/// clients. This frontend resource policy is intentionally unrelated to any
/// backend's hardware descriptor-ring depth.
pub const FRONTEND_QUEUE_DEPTH: usize = crate::platform::NETWORK_FRONTEND.queue_depth;

/// Stable physical attachment identity used only to order discovered NICs.
/// Interface names are assigned after sorting these keys; no `netN` value is
/// coupled to a driver kind or discovery order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkLocation {
    Mmio {
        base: usize,
    },
    Usb {
        controller: usize,
        ports: [u8; 8],
        depth: u8,
    },
}

impl Ord for NetworkLocation {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.anchor()
            .cmp(&other.anchor())
            .then_with(|| match (self, other) {
                (Self::Mmio { .. }, Self::Mmio { .. }) => core::cmp::Ordering::Equal,
                (Self::Mmio { .. }, Self::Usb { .. }) => core::cmp::Ordering::Less,
                (Self::Usb { .. }, Self::Mmio { .. }) => core::cmp::Ordering::Greater,
                (
                    Self::Usb {
                        ports: left_ports,
                        depth: left_depth,
                        ..
                    },
                    Self::Usb {
                        ports: right_ports,
                        depth: right_depth,
                        ..
                    },
                ) => left_ports
                    .cmp(right_ports)
                    .then_with(|| left_depth.cmp(right_depth)),
            })
    }
}

impl PartialOrd for NetworkLocation {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl NetworkLocation {
    const fn anchor(self) -> usize {
        match self {
            Self::Mmio { base } => base,
            Self::Usb { controller, .. } => controller,
        }
    }

    pub fn describe(self) -> String {
        match self {
            Self::Mmio { base } => format!("mmio@{base:#x}"),
            Self::Usb {
                controller,
                ports,
                depth,
            } => {
                let mut output = format!("usb@{controller:#x}");
                for port in ports.into_iter().take(usize::from(depth)) {
                    let _ = write!(output, "/{port}");
                }
                output
            }
        }
    }
}

#[cfg(feature = "milkv-duo")]
#[allow(unused_imports)]
pub use crate::dwmac_net::{
    ack_packet, bind_stack_with, challenge_packet, debug_waiter_count, discover, driver_task,
    hello_packet, info_with, inject_fault_with, is_challenge, recover_faulted_domain, DmaRegion,
    MmioWindow, NetDevice, NetError, NetInfo, NetResources, GUEST_MAC, HANDSHAKE_ETHERTYPE,
    HANDSHAKE_FRAME_LEN, PEER_MAC,
};

#[cfg(feature = "qemu-virt")]
#[allow(unused_imports)]
pub use crate::virtio_net::{
    ack_packet, bind_stack_with, challenge_packet, debug_waiter_count, discover, driver_task,
    hello_packet, info_with, inject_fault_with, is_challenge, recover_faulted_domain, DmaRegion,
    MmioWindow, NetDevice, NetError, NetInfo, NetResources, GUEST_MAC, HANDSHAKE_ETHERTYPE,
    HANDSHAKE_FRAME_LEN, PEER_MAC,
};

#[cfg(feature = "tcp-echo-recovery-test")]
pub(crate) use crate::virtio_net::{
    packet_session_test_info, release_stale_packets_for_test, request_driver_fault_for_test,
    stage_stale_packets_for_test,
};

/// Report whether the selected device's physical carrier is usable.
///
/// VirtIO does not expose a separate PHY signal in the supported transport,
/// while DWMAC publishes the actual PHY state. Keeping that distinction here
/// prevents service adapters from depending on a board-specific `NetInfo`
/// layout.
#[cfg(feature = "qemu-virt")]
#[allow(dead_code)]
pub const fn carrier_up(_info: &NetInfo) -> bool {
    true
}

#[cfg(feature = "milkv-duo")]
#[allow(dead_code)]
pub const fn carrier_up(info: &NetInfo) -> bool {
    info.phy_link_up
}
