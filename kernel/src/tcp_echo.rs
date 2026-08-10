//! N1 acceptance service: one configurable IPv4 interface and one TCP echo socket.
//!
//! This module is compiled only for the dedicated `tcp-echo` image. It keeps
//! the protocol stack behind attenuated packet/control capabilities and is not
//! part of the eventual SSH security boundary.

#[cfg(feature = "tcp-echo-recovery-test")]
extern crate alloc;

#[cfg(feature = "tcp-echo-recovery-test")]
use alloc::{format, string::String};
#[cfg(feature = "tcp-echo-recovery-test")]
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::cap::{Cap, Rights};
use crate::chan::Endpoint;
use crate::net::{PacketStamp, StampedPacket};
use crate::world::Space;
use vibeos_core::net_stack::{StackError, StaticIpv4Config, StaticIpv4EchoStack};

const GUEST_MAC: [u8; 6] = crate::net_config::DEFAULT_MAC;
const GUEST_IPV4: [u8; 4] = crate::net_config::DEFAULT_IPV4;
const GATEWAY_IPV4: [u8; 4] = crate::net_config::DEFAULT_GATEWAY;
const PREFIX_LEN: u8 = crate::net_config::DEFAULT_PREFIX_LEN;
const LISTEN_PORT: u16 = 2222;
const TCP_TEST_SEED: u64 = 0x5649_4245_4f53_4e31;
const IDLE_POLL_CEILING_MS: u64 = 10;

#[cfg(feature = "tcp-echo-recovery-test")]
static FAULT_REQUESTED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "tcp-echo-recovery-test")]
static REJECTED_DEVICE_EPOCH_INGRESS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "tcp-echo-recovery-test")]
static REJECTED_STACK_GENERATION_INGRESS: AtomicU64 = AtomicU64::new(0);

/// Test-image-only fault trigger. Production TCP/SSH images do not compile
/// this ambient hook; the recovery acceptance image drives it through vsh.
#[cfg(feature = "tcp-echo-recovery-test")]
pub(crate) fn vsh_inject_fault(_args: &[String]) -> Result<String, crate::vsh::Status> {
    if let Err(error) = crate::virtio_net::stage_stale_packets_for_test() {
        return Ok(format!("tcp-echo fault staging failed: {error}"));
    }
    FAULT_REQUESTED.store(true, Ordering::Release);
    Ok(String::from("tcp-echo fault requested"))
}

/// Test-image-only driver fault trigger. It deliberately bypasses production
/// authority and is absent from every normal TCP or future SSH image.
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
    let ingress_device = REJECTED_DEVICE_EPOCH_INGRESS.load(Ordering::Acquire);
    let ingress_stack = REJECTED_STACK_GENERATION_INGRESS.load(Ordering::Acquire);
    let world = crate::world::world();
    let stack_component = world
        .component_named("tcp-echo")
        .map_or(0, |component| component.snapshot().generation);
    let driver_component = world
        .component_named("virtio-net")
        .map_or(0, |component| component.snapshot().generation);
    Ok(format!(
        "tcp-session epoch={epoch} generation={generation} ingress-device={ingress_device} ingress-stack={ingress_stack} egress-device={egress_device} egress-stack={egress_stack} stack-component={stack_component} driver-component={driver_component}"
    ))
}

/// Run the feature-gated transport proof with SEND/RECV plus control READ and
/// the narrow INVOKE operation required to mint a fresh packet-session stamp.
pub async fn task(space: &'static Space, outbound_cap: Cap, inbound_cap: Cap, control_cap: Cap) {
    let (outbound, inbound) = {
        let cspace = space.0.lock();
        let Ok(outbound) =
            cspace.lookup_revocable::<Endpoint<StampedPacket>>(outbound_cap, Rights::SEND)
        else {
            return;
        };
        let Ok(inbound) =
            cspace.lookup_revocable::<Endpoint<StampedPacket>>(inbound_cap, Rights::RECV)
        else {
            return;
        };
        (outbound, inbound)
    };

    let mut observed_epoch = None;
    let mut observed_config_revision = 0;
    let mut stack = None;
    loop {
        #[cfg(feature = "tcp-echo-recovery-test")]
        if FAULT_REQUESTED.swap(false, Ordering::AcqRel) {
            panic!("injected TCP stack fault");
        }

        let Some(info) = device_info(space, control_cap) else {
            return;
        };
        if info.quarantined {
            return;
        }
        if !info.online {
            crate::exec::sleep_ms(1).await;
            continue;
        }

        if observed_epoch != Some(info.session_epoch) {
            let stamp = match bind_stack(space, control_cap) {
                Ok(stamp) => stamp,
                Err(
                    crate::virtio_net::NetError::SessionBusy | crate::virtio_net::NetError::Offline,
                ) => {
                    crate::exec::sleep_ms(1).await;
                    continue;
                }
                Err(_) => return,
            };
            let config = StaticIpv4Config::new(
                GUEST_MAC,
                GUEST_IPV4,
                PREFIX_LEN,
                LISTEN_PORT,
                TCP_TEST_SEED ^ stamp.device_epoch(),
            )
            .with_default_gateway(GATEWAY_IPV4);
            let next =
                match StaticIpv4EchoStack::new(config, stamp, inbound.clone(), outbound.clone()) {
                    Ok(stack) => stack,
                    Err(_) => return,
                };
            stack = Some(next);
            observed_epoch = Some(stamp.device_epoch());
            observed_config_revision = 0;
        }

        let active_stack = stack
            .as_mut()
            .expect("an observed network epoch has a protocol stack");
        if crate::net_config::reconcile(active_stack, &mut observed_config_revision).is_err() {
            return;
        }
        let now_ms = monotonic_ms();
        let report = match active_stack.poll(now_ms) {
            Ok(report) => report,
            Err(StackError::AuthorityRevoked) => return,
            Err(_) => return,
        };
        crate::net_config::publish_stack_status(
            observed_config_revision,
            active_stack.ipv4_status(),
        );
        #[cfg(feature = "tcp-echo-recovery-test")]
        {
            let device_stats = stack
                .as_ref()
                .expect("a polled network epoch has a protocol stack")
                .device_stats();
            REJECTED_DEVICE_EPOCH_INGRESS
                .store(device_stats.rejected_device_epoch_frames, Ordering::Release);
            REJECTED_STACK_GENERATION_INGRESS.store(
                device_stats.rejected_stack_generation_frames,
                Ordering::Release,
            );
        }

        if report.more_work {
            crate::exec::yield_now().await;
        } else {
            let delay = report
                .next_poll_delay_ms
                .unwrap_or(IDLE_POLL_CEILING_MS)
                .clamp(1, IDLE_POLL_CEILING_MS);
            crate::exec::sleep_ms(delay).await;
        }
    }
}

fn bind_stack(space: &Space, control_cap: Cap) -> Result<PacketStamp, crate::virtio_net::NetError> {
    let lease = space
        .0
        .lock()
        .lookup_lease::<crate::virtio_net::NetDevice>(control_cap, Rights::INVOKE)
        .map_err(|_| crate::virtio_net::NetError::AuthorityRevoked)?;
    crate::virtio_net::bind_stack_with(&lease)
}

fn device_info(space: &Space, control_cap: Cap) -> Option<crate::virtio_net::NetInfo> {
    let lease = space
        .0
        .lock()
        .lookup_lease::<crate::virtio_net::NetDevice>(control_cap, Rights::READ)
        .ok()?;
    crate::virtio_net::info_with(&lease).ok()
}

fn monotonic_ms() -> u64 {
    let hz = crate::exec::timebase_hz();
    crate::sbi::time().saturating_mul(1_000) / hz
}
