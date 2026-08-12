//! Capability-confined shared IPv4 stack service.
//!
//! The image selects a static or DHCP address policy and grants a bounded set
//! of TCP listener frontends. Applications remain separate components and
//! never receive this service's packet endpoints or smoltcp objects.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

#[cfg(all(feature = "static-service", feature = "dhcp-service"))]
compile_error!("select exactly one netstack address policy");
#[cfg(not(any(feature = "static-service", feature = "dhcp-service")))]
compile_error!("select a netstack address policy");

#[cfg(feature = "tcp-echo-recovery-test")]
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use vibeos_core::cap::{Cap, Revocable};
use vibeos_core::chan::Endpoint;
use vibeos_core::net::{PacketStamp, StampedPacket};
use vibeos_net_api::TcpListener;
use vibeos_net_protocol::{
    Ipv4StackConfig, SharedIpv4TcpStack, StackError, TcpListenerHandle, MAX_TCP_LISTENERS,
};

pub mod command;
pub mod config;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkInfo {
    pub online: bool,
    pub quarantined: bool,
    pub session_epoch: u64,
    pub phy_link_up: bool,
    pub ethernet_address: [u8; 6],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkBindError {
    Offline,
    SessionBusy,
    Denied,
    Failed,
}

/// Privileged packet and network-control operations consumed by this component.
pub trait Platform: Sync {
    fn packet_endpoints(
        &self,
        outbound: Cap,
        inbound: Cap,
    ) -> Option<(
        Revocable<Endpoint<StampedPacket>>,
        Revocable<Endpoint<StampedPacket>>,
    )>;
    fn bind_stack(&self, control: Cap) -> Result<PacketStamp, NetworkBindError>;
    fn network_info(&self, control: Cap) -> Option<NetworkInfo>;
    fn tcp_listener(&self, listener: Cap) -> Option<Revocable<TcpListener>>;
}

type Space = dyn Platform;

const GUEST_IPV4: [u8; 4] = config::DEFAULT_IPV4;
const GATEWAY_IPV4: [u8; 4] = config::DEFAULT_GATEWAY;
const PREFIX_LEN: u8 = config::DEFAULT_PREFIX_LEN;
const TCP_TEST_SEED: u64 = 0x5649_4245_4f53_4e31;
const IDLE_POLL_CEILING_MS: u64 = 10;

pub const COMPONENT_NAME: &str = "net-stack";
pub const MAX_SERVICE_LISTENERS: usize = MAX_TCP_LISTENERS;
pub type TcpListenerCapabilities = [Option<Cap>; MAX_SERVICE_LISTENERS];

pub const fn one_tcp_listener(listener: Cap) -> TcpListenerCapabilities {
    let mut listeners = [None; MAX_SERVICE_LISTENERS];
    listeners[0] = Some(listener);
    listeners
}

#[cfg(feature = "tcp-echo-recovery-test")]
static FAULT_REQUESTED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "tcp-echo-recovery-test")]
static REJECTED_DEVICE_EPOCH_INGRESS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "tcp-echo-recovery-test")]
static REJECTED_STACK_GENERATION_INGRESS: AtomicU64 = AtomicU64::new(0);

/// Request one component-local injected fault after the kernel has staged the
/// recovery fixture. This symbol does not exist in production images.
#[cfg(feature = "tcp-echo-recovery-test")]
pub fn request_fault_for_test() {
    FAULT_REQUESTED.store(true, Ordering::Release);
}

/// Return the component-side stale-ingress rejection counters used by N2.
#[cfg(feature = "tcp-echo-recovery-test")]
pub fn rejected_ingress_for_test() -> (u64, u64) {
    (
        REJECTED_DEVICE_EPOCH_INGRESS.load(Ordering::Acquire),
        REJECTED_STACK_GENERATION_INGRESS.load(Ordering::Acquire),
    )
}

/// Run the feature-gated transport proof with SEND/RECV plus control READ and
/// the narrow INVOKE operation required to mint a fresh packet-session stamp.
pub async fn task(
    space: &Space,
    outbound_cap: Cap,
    inbound_cap: Cap,
    control_cap: Cap,
    listener_caps: TcpListenerCapabilities,
) {
    let (outbound, inbound) = match space.packet_endpoints(outbound_cap, inbound_cap) {
        Some(endpoints) => endpoints,
        None => return,
    };
    let mut listeners = Vec::new();
    if listeners.try_reserve_exact(MAX_SERVICE_LISTENERS).is_err() {
        return;
    }
    for listener_cap in listener_caps.into_iter().flatten() {
        let Some(listener) = space.tcp_listener(listener_cap) else {
            return;
        };
        listeners.push(listener);
    }
    if listeners.is_empty() {
        return;
    }

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
        config::publish_carrier(info.online && info.phy_link_up);
        config::publish_ethernet_address(info.ethernet_address);
        if info.quarantined {
            return;
        }
        if !info.online {
            vibeos_core::exec::sleep_ms(1).await;
            continue;
        }

        if observed_epoch != Some(info.session_epoch) {
            let stamp = match bind_stack(space, control_cap) {
                Ok(stamp) => stamp,
                Err(NetworkBindError::SessionBusy | NetworkBindError::Offline) => {
                    vibeos_core::exec::sleep_ms(1).await;
                    continue;
                }
                Err(_) => return,
            };
            let config = Ipv4StackConfig::new(
                info.ethernet_address,
                GUEST_IPV4,
                PREFIX_LEN,
                TCP_TEST_SEED ^ stamp.device_epoch(),
            )
            .with_default_gateway(GATEWAY_IPV4);
            let mut next =
                match SharedIpv4TcpStack::new(config, stamp, inbound.clone(), outbound.clone()) {
                    Ok(stack) => stack,
                    Err(_) => return,
                };
            let mut bound_listeners = Vec::new();
            if bound_listeners.try_reserve_exact(listeners.len()).is_err() {
                return;
            }
            for listener in &listeners {
                let port = match listener.try_with(TcpListener::port) {
                    Ok(port) => port,
                    Err(_) => return,
                };
                let socket = match next.add_tcp_listener(port) {
                    Ok(socket) => socket,
                    Err(_) => return,
                };
                bound_listeners.push(BoundListener {
                    frontend: listener.clone(),
                    socket,
                });
            }
            stack = Some(BoundStack {
                core: next,
                listeners: bound_listeners,
            });
            observed_epoch = Some(stamp.device_epoch());
            observed_config_revision = 0;
        }

        let active_stack = stack
            .as_mut()
            .expect("an observed network epoch has a protocol stack");
        if config::reconcile(&mut active_stack.core, &mut observed_config_revision).is_err() {
            return;
        }
        let now_ms = monotonic_ms();
        let mut frontend_work = match drive_frontends(active_stack) {
            Ok(worked) => worked,
            Err(DriveError::AuthorityRevoked) => return,
            Err(DriveError::Failed) => return,
        };
        let report = match active_stack.core.poll_network(now_ms) {
            Ok(report) => report,
            Err(StackError::AuthorityRevoked) => return,
            Err(_) => return,
        };
        frontend_work |= match drive_frontends(active_stack) {
            Ok(worked) => worked,
            Err(DriveError::AuthorityRevoked) => return,
            Err(DriveError::Failed) => return,
        };
        config::publish_stack_status(observed_config_revision, active_stack.core.ipv4_status());
        #[cfg(feature = "tcp-echo-recovery-test")]
        {
            let device_stats = active_stack.core.device_stats();
            REJECTED_DEVICE_EPOCH_INGRESS
                .store(device_stats.rejected_device_epoch_frames, Ordering::Release);
            REJECTED_STACK_GENERATION_INGRESS.store(
                device_stats.rejected_stack_generation_frames,
                Ordering::Release,
            );
        }

        if report.more_work || frontend_work {
            vibeos_core::exec::yield_now().await;
        } else {
            let delay = report
                .next_poll_delay_ms
                .unwrap_or(IDLE_POLL_CEILING_MS)
                .clamp(1, IDLE_POLL_CEILING_MS);
            vibeos_core::exec::sleep_ms(delay).await;
        }
    }
}

struct BoundStack {
    core: SharedIpv4TcpStack,
    listeners: Vec<BoundListener>,
}

struct BoundListener {
    frontend: Revocable<TcpListener>,
    socket: TcpListenerHandle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DriveError {
    AuthorityRevoked,
    Failed,
}

fn drive_frontends(stack: &mut BoundStack) -> Result<bool, DriveError> {
    let mut worked = false;
    for listener in &stack.listeners {
        match listener
            .frontend
            .try_with(|frontend| stack.core.drive_tcp_frontend(listener.socket, frontend))
        {
            Ok(Ok(report)) => {
                worked |= report.received_bytes != 0
                    || report.transmitted_bytes != 0
                    || report.close_applied.is_some();
            }
            Ok(Err(_)) => return Err(DriveError::Failed),
            Err(_) => return Err(DriveError::AuthorityRevoked),
        }
    }
    Ok(worked)
}

fn bind_stack(space: &Space, control_cap: Cap) -> Result<PacketStamp, NetworkBindError> {
    space.bind_stack(control_cap)
}

fn device_info(space: &Space, control_cap: Cap) -> Option<NetworkInfo> {
    space.network_info(control_cap)
}

fn monotonic_ms() -> u64 {
    let hz = vibeos_core::exec::timebase_hz();
    vibeos_core::arch::time().saturating_mul(1_000) / hz
}
