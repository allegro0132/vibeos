//! Kernel adapters for the separately compiled IPv4 stack component.

#[cfg(feature = "tcp-echo-recovery-test")]
extern crate alloc;

#[cfg(feature = "tcp-echo-recovery-test")]
use alloc::{format, string::String};

use vibeos_core::cap::{Cap, Rights};
use vibeos_core::chan::Endpoint;
use vibeos_core::net::StampedPacket;
use vibeos_netstack::{NetworkBindError, NetworkInfo, Platform};

use crate::world::Space;

pub use vibeos_netstack::config::{vsh_dhclient, vsh_ip};
pub use vibeos_netstack::COMPONENT_NAME;

struct NetstackPlatform {
    space: &'static Space,
}

impl NetstackPlatform {
    const fn new(space: &'static Space) -> Self {
        Self { space }
    }
}

impl Platform for NetstackPlatform {
    fn packet_endpoints(
        &self,
        outbound: Cap,
        inbound: Cap,
    ) -> Option<(
        vibeos_core::cap::Revocable<Endpoint<StampedPacket>>,
        vibeos_core::cap::Revocable<Endpoint<StampedPacket>>,
    )> {
        let cspace = self.space.0.lock();
        let outbound = cspace
            .lookup_revocable::<Endpoint<StampedPacket>>(outbound, Rights::SEND)
            .ok()?;
        let inbound = cspace
            .lookup_revocable::<Endpoint<StampedPacket>>(inbound, Rights::RECV)
            .ok()?;
        Some((outbound, inbound))
    }

    fn bind_stack(&self, control: Cap) -> Result<vibeos_core::net::PacketStamp, NetworkBindError> {
        let lease = self
            .space
            .0
            .lock()
            .lookup_lease::<crate::virtio_net::NetDevice>(control, Rights::INVOKE)
            .map_err(|_| NetworkBindError::Denied)?;
        crate::virtio_net::bind_stack_with(&lease).map_err(|error| match error {
            crate::virtio_net::NetError::Offline => NetworkBindError::Offline,
            crate::virtio_net::NetError::SessionBusy => NetworkBindError::SessionBusy,
            crate::virtio_net::NetError::AuthorityRevoked
            | crate::virtio_net::NetError::PermissionDenied => NetworkBindError::Denied,
            _ => NetworkBindError::Failed,
        })
    }

    fn network_info(&self, control: Cap) -> Option<NetworkInfo> {
        let lease = self
            .space
            .0
            .lock()
            .lookup_lease::<crate::virtio_net::NetDevice>(control, Rights::READ)
            .ok()?;
        let info = crate::virtio_net::info_with(&lease).ok()?;
        Some(NetworkInfo {
            online: info.online,
            quarantined: info.quarantined,
            session_epoch: info.session_epoch,
            #[cfg(feature = "qemu-virt")]
            phy_link_up: true,
            #[cfg(feature = "milkv-duo")]
            phy_link_up: info.phy_link_up,
        })
    }
}

pub async fn task(space: &'static Space, outbound: Cap, inbound: Cap, control: Cap) {
    let platform = NetstackPlatform::new(space);
    vibeos_netstack::task(&platform, outbound, inbound, control).await;
}

/// Test-image-only stack fault trigger. Hardware staging remains kernel-only.
#[cfg(feature = "tcp-echo-recovery-test")]
pub(crate) fn vsh_inject_fault(_args: &[String]) -> Result<String, crate::vsh::Status> {
    if let Err(error) = crate::virtio_net::stage_stale_packets_for_test() {
        return Ok(format!("tcp-echo fault staging failed: {error}"));
    }
    vibeos_netstack::request_fault_for_test();
    Ok(String::from("tcp-echo fault requested"))
}

/// Test-image-only driver fault trigger. It is absent from production images.
#[cfg(feature = "tcp-echo-recovery-test")]
pub(crate) fn vsh_inject_driver_fault(_args: &[String]) -> Result<String, crate::vsh::Status> {
    if let Err(error) = crate::virtio_net::stage_stale_packets_for_test() {
        return Ok(format!("tcp-echo driver fault staging failed: {error}"));
    }
    crate::virtio_net::request_driver_fault_for_test();
    Ok(String::from("tcp-echo driver fault requested"))
}

#[cfg(feature = "tcp-echo-recovery-test")]
pub(crate) fn vsh_release_stale(_args: &[String]) -> Result<String, crate::vsh::Status> {
    match crate::virtio_net::release_stale_packets_for_test() {
        Ok(true) => Ok(String::from("tcp-echo stale release complete")),
        Ok(false) => Ok(String::from("tcp-echo stale release partial")),
        Err(error) => Ok(format!("tcp-echo stale release failed: {error}")),
    }
}

#[cfg(feature = "tcp-echo-recovery-test")]
pub(crate) fn vsh_session_info(_args: &[String]) -> Result<String, crate::vsh::Status> {
    let (epoch, generation, egress_device, egress_stack) =
        crate::virtio_net::packet_session_test_info();
    let (ingress_device, ingress_stack) = vibeos_netstack::rejected_ingress_for_test();
    let world = crate::world::world();
    let stack_component = world
        .component_named(COMPONENT_NAME)
        .map_or(0, |component| component.snapshot().generation);
    let driver_component = world
        .component_named("virtio-net")
        .map_or(0, |component| component.snapshot().generation);
    Ok(format!(
        "tcp-session epoch={epoch} generation={generation} ingress-device={ingress_device} ingress-stack={ingress_stack} egress-device={egress_device} egress-stack={egress_stack} stack-component={stack_component} driver-component={driver_component}"
    ))
}
