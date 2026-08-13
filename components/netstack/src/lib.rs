//! Capability-confined multi-interface IPv4 stack service.
//!
//! The image grants a boot-discovered list of independent NIC capability
//! bundles. Each bundle owns its own smoltcp interface, address policy, routes,
//! DHCP client, packet session, and bounded set of TCP listener frontends.
//! Applications remain separate components and never receive packet endpoints
//! or smoltcp objects.

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
    Ipv4StackConfig, SharedIpv4TcpStack, TcpListenerHandle, MAX_TCP_LISTENERS,
};

pub use vibeos_net_protocol::command::NetworkInterfaceId;

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

pub type PacketEndpoints = (
    Revocable<Endpoint<StampedPacket>>,
    Revocable<Endpoint<StampedPacket>>,
);

/// Privileged packet and network-control operations consumed by this component.
pub trait Platform: Sync {
    fn packet_endpoints(&self, outbound: Cap, inbound: Cap) -> Option<PacketEndpoints>;
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

/// Complete authority bundle for one independently configured IP interface.
/// A second NIC must arrive with a distinct bundle; sharing packet endpoints,
/// control capabilities, or listener frontends is never inferred by index.
#[derive(Clone, Copy, Debug)]
pub struct NetworkInterfaceCapabilities {
    pub interface: NetworkInterfaceId,
    pub outbound: Cap,
    pub inbound: Cap,
    pub control: Cap,
    pub listeners: TcpListenerCapabilities,
}

impl NetworkInterfaceCapabilities {
    pub const fn new(
        interface: NetworkInterfaceId,
        outbound: Cap,
        inbound: Cap,
        control: Cap,
        listeners: TcpListenerCapabilities,
    ) -> Self {
        Self {
            interface,
            outbound,
            inbound,
            control,
            listeners,
        }
    }
}

pub const fn no_tcp_listeners() -> TcpListenerCapabilities {
    [None; MAX_SERVICE_LISTENERS]
}

pub const fn one_tcp_listener(listener: Cap) -> TcpListenerCapabilities {
    let mut listeners = no_tcp_listeners();
    listeners[0] = Some(listener);
    listeners
}

pub const fn two_tcp_listeners(first: Cap, second: Cap) -> TcpListenerCapabilities {
    let mut listeners = no_tcp_listeners();
    listeners[0] = Some(first);
    listeners[1] = Some(second);
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
    let interfaces = [NetworkInterfaceCapabilities::new(
        NetworkInterfaceId::FIRST,
        outbound_cap,
        inbound_cap,
        control_cap,
        listener_caps,
    )];
    task_with_interfaces(space, &interfaces).await;
}

/// Run a fair, bounded protocol loop over every explicitly admitted NIC.
///
/// Each entry owns a separate smoltcp interface, address/route/DHCP state,
/// packet-session generation, and listener set. A revoked or quarantined NIC
/// is retired without taking healthy interfaces down with it.
pub async fn task_with_interfaces(space: &Space, interface_caps: &[NetworkInterfaceCapabilities]) {
    let mut interfaces = Vec::new();
    if interfaces.try_reserve_exact(interface_caps.len()).is_err() {
        return;
    }
    let mut seen = Vec::new();
    if seen.try_reserve_exact(interface_caps.len()).is_err() {
        return;
    }
    for caps in interface_caps.iter().copied() {
        if seen.contains(&caps.interface) {
            continue;
        }
        seen.push(caps.interface);
        let Some((outbound, inbound)) = space.packet_endpoints(caps.outbound, caps.inbound) else {
            continue;
        };
        let mut listeners = Vec::new();
        if listeners.try_reserve_exact(MAX_SERVICE_LISTENERS).is_err() {
            continue;
        }
        let mut valid = true;
        for listener_cap in caps.listeners.into_iter().flatten() {
            let Some(listener) = space.tcp_listener(listener_cap) else {
                valid = false;
                break;
            };
            let listener_id = match listener.try_with(TcpListener::id) {
                Ok(listener_id) => listener_id.get(),
                Err(_) => {
                    valid = false;
                    break;
                }
            };
            if !config::register_listener(caps.interface, listener_id) {
                valid = false;
                break;
            }
            listeners.push(listener);
        }
        if !valid {
            continue;
        }
        if !config::register_interface(caps.interface, !listeners.is_empty()) {
            continue;
        }
        interfaces.push(InterfaceTask {
            interface: caps.interface,
            outbound,
            inbound,
            control: caps.control,
            listeners,
            observed_epoch: None,
            observed_ethernet_address: None,
            observed_config_revision: 0,
            stack: None,
            retired: false,
        });
    }
    if interfaces.is_empty() {
        return;
    }

    loop {
        #[cfg(feature = "tcp-echo-recovery-test")]
        if FAULT_REQUESTED.swap(false, Ordering::AcqRel) {
            panic!("injected TCP stack fault");
        }

        let now_ms = monotonic_ms();
        let mut live_interfaces = 0usize;
        let mut more_work = false;
        let mut next_poll_delay_ms = IDLE_POLL_CEILING_MS;
        #[cfg(feature = "tcp-echo-recovery-test")]
        let mut rejected_device_epoch_ingress = 0u64;
        #[cfg(feature = "tcp-echo-recovery-test")]
        let mut rejected_stack_generation_ingress = 0u64;

        for interface in &mut interfaces {
            if interface.retired {
                continue;
            }
            live_interfaces += 1;
            match interface.poll(space, now_ms) {
                Ok(report) => {
                    more_work |= report.more_work;
                    next_poll_delay_ms = next_poll_delay_ms.min(report.next_poll_delay_ms);
                }
                Err(InterfaceError::Retired) => {
                    interface.retired = true;
                    config::publish_link_down(interface.interface);
                    live_interfaces -= 1;
                }
            }

            #[cfg(feature = "tcp-echo-recovery-test")]
            if let Some(active_stack) = interface.stack.as_ref() {
                let device_stats = active_stack.core.device_stats();
                rejected_device_epoch_ingress = rejected_device_epoch_ingress
                    .saturating_add(device_stats.rejected_device_epoch_frames);
                rejected_stack_generation_ingress = rejected_stack_generation_ingress
                    .saturating_add(device_stats.rejected_stack_generation_frames);
            }
        }

        #[cfg(feature = "tcp-echo-recovery-test")]
        {
            REJECTED_DEVICE_EPOCH_INGRESS.store(rejected_device_epoch_ingress, Ordering::Release);
            REJECTED_STACK_GENERATION_INGRESS
                .store(rejected_stack_generation_ingress, Ordering::Release);
        }

        if live_interfaces == 0 {
            return;
        }
        if more_work {
            vibeos_core::exec::yield_now().await;
        } else {
            let delay = next_poll_delay_ms.clamp(1, IDLE_POLL_CEILING_MS);
            vibeos_core::exec::sleep_ms(delay).await;
        }
    }
}

struct InterfaceTask {
    interface: NetworkInterfaceId,
    outbound: Revocable<Endpoint<StampedPacket>>,
    inbound: Revocable<Endpoint<StampedPacket>>,
    control: Cap,
    listeners: Vec<Revocable<TcpListener>>,
    observed_epoch: Option<u64>,
    observed_ethernet_address: Option<[u8; 6]>,
    observed_config_revision: u64,
    stack: Option<BoundStack>,
    retired: bool,
}

impl InterfaceTask {
    fn poll(&mut self, space: &Space, now_ms: u64) -> Result<InterfacePollReport, InterfaceError> {
        let Some(info) = device_info(space, self.control) else {
            return Err(InterfaceError::Retired);
        };
        config::publish_ethernet_address(self.interface, info.ethernet_address);
        if info.quarantined {
            return Err(InterfaceError::Retired);
        }
        if !info.online || !info.phy_link_up {
            self.drop_carrier();
            return Ok(InterfacePollReport::idle(1));
        }
        config::publish_carrier(self.interface, true);

        if self.observed_epoch != Some(info.session_epoch)
            || self.observed_ethernet_address != Some(info.ethernet_address)
        {
            let stamp = match bind_stack(space, self.control) {
                Ok(stamp) => stamp,
                Err(NetworkBindError::SessionBusy | NetworkBindError::Offline) => {
                    return Ok(InterfacePollReport::idle(1));
                }
                Err(_) => return Err(InterfaceError::Retired),
            };
            let stack_config = Ipv4StackConfig::new(
                info.ethernet_address,
                GUEST_IPV4,
                PREFIX_LEN,
                TCP_TEST_SEED ^ stamp.device_epoch() ^ ((self.interface.index() as u64) << 32),
            )
            .with_default_gateway(GATEWAY_IPV4);
            let mut next = SharedIpv4TcpStack::new(
                stack_config,
                stamp,
                self.inbound.clone(),
                self.outbound.clone(),
            )
            .map_err(|_| InterfaceError::Retired)?;
            let mut bound_listeners = Vec::new();
            if bound_listeners
                .try_reserve_exact(self.listeners.len())
                .is_err()
            {
                return Err(InterfaceError::Retired);
            }
            for listener in &self.listeners {
                let port = listener
                    .try_with(TcpListener::port)
                    .map_err(|_| InterfaceError::Retired)?;
                let port_group = listener
                    .try_with(TcpListener::port_group)
                    .map_err(|_| InterfaceError::Retired)?;
                let socket = match port_group {
                    Some(group) => next.add_shared_tcp_listener(port, group.get()),
                    None => next.add_tcp_listener(port),
                }
                .map_err(|_| InterfaceError::Retired)?;
                bound_listeners.push(BoundListener {
                    frontend: listener.clone(),
                    socket,
                });
            }
            self.stack = Some(BoundStack {
                core: next,
                listeners: bound_listeners,
            });
            self.observed_epoch = Some(stamp.device_epoch());
            self.observed_ethernet_address = Some(info.ethernet_address);
            self.observed_config_revision = 0;
        }

        let active_stack = self
            .stack
            .as_mut()
            .expect("an observed network epoch has a protocol stack");
        config::reconcile(
            self.interface,
            &mut active_stack.core,
            &mut self.observed_config_revision,
        )
        .map_err(|_| InterfaceError::Retired)?;
        let mut frontend_work =
            drive_frontends(active_stack).map_err(|_| InterfaceError::Retired)?;
        let report = active_stack
            .core
            .poll_network(now_ms)
            .map_err(|_| InterfaceError::Retired)?;
        frontend_work |= drive_frontends(active_stack).map_err(|_| InterfaceError::Retired)?;
        config::publish_stack_status(
            self.interface,
            self.observed_config_revision,
            active_stack.core.ipv4_status(),
        );
        Ok(InterfacePollReport {
            more_work: report.more_work || frontend_work,
            next_poll_delay_ms: report
                .next_poll_delay_ms
                .unwrap_or(IDLE_POLL_CEILING_MS)
                .clamp(1, IDLE_POLL_CEILING_MS),
        })
    }

    fn drop_carrier(&mut self) {
        config::publish_link_down(self.interface);
        self.stack = None;
        self.observed_epoch = None;
        self.observed_ethernet_address = None;
        self.observed_config_revision = 0;
    }
}

#[derive(Clone, Copy)]
struct InterfacePollReport {
    more_work: bool,
    next_poll_delay_ms: u64,
}

impl InterfacePollReport {
    const fn idle(next_poll_delay_ms: u64) -> Self {
        Self {
            more_work: false,
            next_poll_delay_ms,
        }
    }
}

#[derive(Clone, Copy)]
enum InterfaceError {
    Retired,
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
