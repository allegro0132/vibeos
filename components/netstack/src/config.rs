//! Capability-admitted control plane for the bounded set of IPv4 interfaces.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use vibeos_core::sync::SpinLock;
use vibeos_net_protocol::command::{
    parse_dhclient_command, parse_ip_command, DhclientCommand, IpCommand, Ipv4Method,
    NetworkConfiguration, NetworkInterfaceId,
};
use vibeos_net_protocol::{Ipv4RuntimeStatus, SharedIpv4TcpStack, StackError, StaticIpv4Address};
use vibeos_vsh::Status;

pub const DEFAULT_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
pub const DEFAULT_IPV4: [u8; 4] = [10, 0, 2, 15];
pub const DEFAULT_GATEWAY: [u8; 4] = [10, 0, 2, 2];
pub const DEFAULT_PREFIX_LEN: u8 = 24;

#[cfg(feature = "static-service")]
const DEFAULT_STATIC: StaticIpv4Address =
    StaticIpv4Address::new(DEFAULT_IPV4, DEFAULT_PREFIX_LEN).with_default_gateway(DEFAULT_GATEWAY);

#[derive(Clone, Copy)]
struct ControlState {
    present: bool,
    revision: u64,
    desired: NetworkConfiguration,
    applied_revision: u64,
    runtime: Ipv4RuntimeStatus,
    carrier_up: bool,
    ethernet_address: [u8; 6],
}

/// The deterministic acceptance image assigns its historical address to the
/// interface carrying the explicitly granted service listener. DHCP images
/// may safely discover a lease independently on every admitted link.
#[cfg(feature = "static-service")]
const SERVICE_BOOT_CONFIGURATION: NetworkConfiguration = NetworkConfiguration {
    link_up: true,
    method: Ipv4Method::Static(DEFAULT_STATIC),
};
#[cfg(feature = "static-service")]
const DEFAULT_BOOT_CONFIGURATION: NetworkConfiguration = NetworkConfiguration {
    link_up: true,
    method: Ipv4Method::None,
};

#[cfg(feature = "dhcp-service")]
const SERVICE_BOOT_CONFIGURATION: NetworkConfiguration = NetworkConfiguration {
    link_up: true,
    method: Ipv4Method::Dhcp,
};
#[cfg(feature = "dhcp-service")]
const DEFAULT_BOOT_CONFIGURATION: NetworkConfiguration = SERVICE_BOOT_CONFIGURATION;

const fn initial_control(desired: NetworkConfiguration) -> ControlState {
    ControlState {
        present: false,
        revision: 1,
        desired,
        applied_revision: 0,
        runtime: Ipv4RuntimeStatus::Unconfigured,
        carrier_up: false,
        ethernet_address: DEFAULT_MAC,
    }
}

const fn boot_configuration(has_service_listener: bool) -> NetworkConfiguration {
    if has_service_listener {
        SERVICE_BOOT_CONFIGURATION
    } else {
        DEFAULT_BOOT_CONFIGURATION
    }
}

static CONTROL: SpinLock<Vec<ControlState>> = SpinLock::new(Vec::new());
static LISTENER_INTERFACES: SpinLock<Vec<(u64, NetworkInterfaceId)>> = SpinLock::new(Vec::new());

pub fn vsh_ip(args: &[String]) -> Result<String, Status> {
    let command = parse_ip_command(args).map_err(|_| Status::Usage)?;
    match command {
        IpCommand::ShowLink { interface } => show_links(interface),
        IpCommand::ShowAddress { interface } => show_addresses(interface),
        IpCommand::ShowRoute { interface } => show_routes(interface),
        IpCommand::SetLink { interface, up } => {
            update(interface, |configuration| configuration.link_up = up)?;
            Ok(String::new())
        }
        IpCommand::ReplaceAddress {
            interface,
            address,
            prefix_len,
        } => {
            update(interface, |configuration| {
                let default_gateway = match configuration.method {
                    Ipv4Method::Static(current) => current.default_gateway,
                    Ipv4Method::None | Ipv4Method::Dhcp => None,
                };
                configuration.method = Ipv4Method::Static(StaticIpv4Address {
                    address,
                    prefix_len,
                    default_gateway,
                });
            })?;
            Ok(String::new())
        }
        IpCommand::FlushAddress { interface } => {
            update(interface, |configuration| {
                configuration.method = Ipv4Method::None
            })?;
            Ok(String::new())
        }
        IpCommand::ReplaceDefaultRoute { interface, gateway } => {
            let mut control = CONTROL.lock();
            let Some(state) = control
                .get_mut(interface.index())
                .filter(|state| state.present)
            else {
                return Err(Status::Usage);
            };
            let Ipv4Method::Static(mut address) = state.desired.method else {
                return Err(Status::Usage);
            };
            address.default_gateway = Some(gateway);
            state.desired.method = Ipv4Method::Static(address);
            state.revision = state.revision.wrapping_add(1).max(1);
            Ok(String::new())
        }
    }
}

pub fn vsh_dhclient(args: &[String]) -> Result<String, Status> {
    match parse_dhclient_command(args).map_err(|_| Status::Usage)? {
        DhclientCommand::Acquire { interface } => {
            update(interface, |configuration| {
                configuration.link_up = true;
                configuration.method = Ipv4Method::Dhcp;
            })?;
            Ok(format!(
                "DHCP discovery started on {}; use `ip -4 addr show dev {}` to inspect the lease\n",
                interface_name(interface),
                interface_name(interface),
            ))
        }
        DhclientCommand::Release { interface } => {
            update(interface, |configuration| {
                configuration.method = Ipv4Method::None
            })?;
            Ok(format!(
                "DHCP client stopped and IPv4 configuration cleared on {}\n",
                interface_name(interface),
            ))
        }
    }
}

/// Admit one capability-backed interface into the operator-visible table.
/// Merely parsing `netN` never marks it present.
pub fn register_interface(interface: NetworkInterfaceId, has_service_listener: bool) -> bool {
    let mut control = CONTROL.lock();
    let index = interface.index();
    if index >= control.len() {
        let additional = index + 1 - control.len();
        if control.try_reserve_exact(additional).is_err() {
            return false;
        }
        while control.len() <= index {
            control.push(initial_control(DEFAULT_BOOT_CONFIGURATION));
        }
    }
    if has_service_listener && !control[index].present {
        control[index].desired = boot_configuration(true);
    }
    control[index].present = true;
    true
}

pub fn register_listener(interface: NetworkInterfaceId, listener_id: u64) -> bool {
    let mut listeners = LISTENER_INTERFACES.lock();
    if let Some((_, registered)) = listeners
        .iter()
        .find(|(candidate, _)| *candidate == listener_id)
    {
        return *registered == interface;
    }
    if listeners.try_reserve_exact(1).is_err() {
        return false;
    }
    listeners.push((listener_id, interface));
    true
}

pub fn reconcile(
    interface: NetworkInterfaceId,
    stack: &mut SharedIpv4TcpStack,
    observed_revision: &mut u64,
) -> Result<(), StackError> {
    let (revision, desired) = {
        let control = CONTROL.lock();
        let state = *control
            .get(interface.index())
            .expect("registered interface retains control state");
        (state.revision, state.desired)
    };
    if revision == *observed_revision {
        publish_runtime(interface, revision, stack.ipv4_status());
        return Ok(());
    }

    if !desired.link_up {
        stack.clear_ipv4()?;
    } else {
        match desired.method {
            Ipv4Method::None => stack.clear_ipv4()?,
            Ipv4Method::Static(address) => stack.configure_static_ipv4(address)?,
            Ipv4Method::Dhcp => stack.start_dhcp()?,
        }
    }
    *observed_revision = revision;
    publish_runtime(interface, revision, stack.ipv4_status());
    Ok(())
}

pub fn publish_stack_status(
    interface: NetworkInterfaceId,
    observed_revision: u64,
    status: Ipv4RuntimeStatus,
) {
    publish_runtime(interface, observed_revision, status);
}

pub fn publish_carrier(interface: NetworkInterfaceId, carrier_up: bool) {
    let mut control = CONTROL.lock();
    if let Some(state) = control.get_mut(interface.index()) {
        state.present = true;
        state.carrier_up = carrier_up;
    }
}

pub fn publish_ethernet_address(interface: NetworkInterfaceId, ethernet_address: [u8; 6]) {
    let mut control = CONTROL.lock();
    if let Some(state) = control.get_mut(interface.index()) {
        state.present = true;
        state.ethernet_address = ethernet_address;
    }
}

pub fn runtime_status_on(interface: NetworkInterfaceId) -> Option<Ipv4RuntimeStatus> {
    let control = CONTROL.lock();
    control
        .get(interface.index())
        .filter(|state| state.present)
        .map(|state| state.runtime)
}

pub fn runtime_status_for_listener(listener_id: u64) -> Option<Ipv4RuntimeStatus> {
    let interface = LISTENER_INTERFACES
        .lock()
        .iter()
        .find_map(|(candidate, interface)| (*candidate == listener_id).then_some(*interface))?;
    runtime_status_on(interface)
}

fn update(
    interface: NetworkInterfaceId,
    change: impl FnOnce(&mut NetworkConfiguration),
) -> Result<(), Status> {
    let mut control = CONTROL.lock();
    let Some(state) = control
        .get_mut(interface.index())
        .filter(|state| state.present)
    else {
        return Err(Status::Usage);
    };
    change(&mut state.desired);
    state.revision = state.revision.wrapping_add(1).max(1);
    Ok(())
}

fn publish_runtime(interface: NetworkInterfaceId, revision: u64, status: Ipv4RuntimeStatus) {
    let mut control = CONTROL.lock();
    if let Some(state) = control.get_mut(interface.index()) {
        if revision == state.revision {
            state.applied_revision = revision;
            state.runtime = status;
        }
    }
}

fn show_links(interface: Option<NetworkInterfaceId>) -> Result<String, Status> {
    let control = CONTROL.lock().clone();
    render_selected(&control, interface, |id, state, output| {
        output.push_str(&format_link(id, state));
    })
}

fn show_addresses(interface: Option<NetworkInterfaceId>) -> Result<String, Status> {
    let control = CONTROL.lock().clone();
    render_selected(&control, interface, |id, state, output| {
        output.push_str(&format_link(id, state));
        match state.runtime {
            Ipv4RuntimeStatus::Static(address) => {
                output.push_str(&format_address(id, address, ""));
            }
            Ipv4RuntimeStatus::DhcpBound(address) => {
                output.push_str(&format_address(id, address, " dynamic"));
            }
            Ipv4RuntimeStatus::DhcpDiscovering => output.push_str(&format!(
                "    inet dhcp pending scope global dynamic {}\n",
                interface_name(id),
            )),
            Ipv4RuntimeStatus::Unconfigured => {}
        }
    })
}

fn show_routes(interface: Option<NetworkInterfaceId>) -> Result<String, Status> {
    let control = CONTROL.lock().clone();
    render_selected(&control, interface, |id, state, output| {
        match state.runtime {
            Ipv4RuntimeStatus::Static(address) => {
                output.push_str(&format_route(id, address, "static"));
            }
            Ipv4RuntimeStatus::DhcpBound(address) => {
                output.push_str(&format_route(id, address, "dhcp"));
            }
            Ipv4RuntimeStatus::Unconfigured | Ipv4RuntimeStatus::DhcpDiscovering => {}
        }
    })
}

fn render_selected(
    control: &[ControlState],
    interface: Option<NetworkInterfaceId>,
    mut render: impl FnMut(NetworkInterfaceId, ControlState, &mut String),
) -> Result<String, Status> {
    let mut output = String::new();
    if let Some(interface) = interface {
        let Some(state) = control
            .get(interface.index())
            .copied()
            .filter(|state| state.present)
        else {
            return Err(Status::Usage);
        };
        render(interface, state, &mut output);
        return Ok(output);
    }

    for (index, state) in control.iter().copied().enumerate() {
        if state.present {
            let interface = NetworkInterfaceId::new(
                u16::try_from(index).expect("registered interface index fits its identity"),
            );
            render(interface, state, &mut output);
        }
    }
    Ok(output)
}

fn format_link(interface: NetworkInterfaceId, control: ControlState) -> String {
    let (flags, state) = if control.desired.link_up {
        if control.applied_revision == control.revision && control.carrier_up {
            ("UP,LOWER_UP", "UP")
        } else {
            ("UP", "UNKNOWN")
        }
    } else {
        ("", "DOWN")
    };
    format!(
        "{}: {}: <{flags}> mtu 1500 state {state}\n    link/ether {} brd ff:ff:ff:ff:ff:ff\n",
        interface.index() + 1,
        interface_name(interface),
        format_mac(control.ethernet_address),
    )
}

fn format_address(
    interface: NetworkInterfaceId,
    address: StaticIpv4Address,
    suffix: &str,
) -> String {
    format!(
        "    inet {}/{} scope global{suffix} {}\n",
        format_ipv4(address.address),
        address.prefix_len,
        interface_name(interface),
    )
}

fn format_route(
    interface: NetworkInterfaceId,
    address: StaticIpv4Address,
    protocol: &str,
) -> String {
    address.default_gateway.map_or_else(String::new, |gateway| {
        format!(
            "default via {} dev {} proto {protocol}\n",
            format_ipv4(gateway),
            interface_name(interface),
        )
    })
}

fn interface_name(interface: NetworkInterfaceId) -> String {
    format!("net{}", interface.index())
}

fn format_ipv4(address: [u8; 4]) -> String {
    format!(
        "{}.{}.{}.{}",
        address[0], address[1], address[2], address[3]
    )
}

fn format_mac(address: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        address[0], address[1], address[2], address[3], address[4], address[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> alloc::vec::Vec<String> {
        values.iter().map(|value| String::from(*value)).collect()
    }

    #[test]
    fn dynamically_sized_interface_configuration_is_isolated() {
        let first = NetworkInterfaceId::FIRST;
        let second = NetworkInterfaceId::new(1);
        let distant = NetworkInterfaceId::new(17);
        assert!(register_interface(first, true));
        assert!(register_interface(second, false));
        assert!(register_interface(distant, false));
        publish_ethernet_address(first, [0x02, 0, 0, 0, 0, 1]);
        publish_ethernet_address(second, [0x02, 0, 0, 0, 1, 1]);
        publish_carrier(first, true);
        publish_carrier(second, true);

        let first_before = CONTROL.lock()[first.index()].desired;
        vsh_ip(&args(&[
            "addr",
            "replace",
            "192.168.8.20/24",
            "dev",
            "net1",
        ]))
        .unwrap();
        vsh_ip(&args(&[
            "route",
            "replace",
            "default",
            "via",
            "192.168.8.1",
            "dev",
            "net1",
        ]))
        .unwrap();

        let control = CONTROL.lock();
        assert_eq!(control[first.index()].desired, first_before);
        assert_eq!(
            control[second.index()].desired.method,
            Ipv4Method::Static(
                StaticIpv4Address::new([192, 168, 8, 20], 24)
                    .with_default_gateway([192, 168, 8, 1])
            )
        );
        drop(control);

        let links = vsh_ip(&args(&["link", "show"])).unwrap();
        assert!(links.contains("net0"));
        assert!(links.contains("net1"));
        assert!(links.contains("net17"));
        assert!(links.contains("02:00:00:00:01:01"));
        assert!(vsh_ip(&args(&["link", "show", "dev", "net2"])).is_err());
    }
}
