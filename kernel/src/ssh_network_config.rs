//! Runtime control plane for the production SSH component's exclusively owned IPv4 stack.

extern crate alloc;

use alloc::{format, string::String};

use vibeos_core::sync::SpinLock;
use vibeos_sshd::{
    DhclientCommand, IpCommand, Ipv4Method, Ipv4Policy, Ipv4RuntimeStatus, NetworkConfiguration,
    PRIMARY_INTERFACE, StaticIpv4Address, parse_dhclient_command, parse_ip_command,
};
use vibeos_vsh::Status;

#[derive(Clone, Copy)]
struct ControlState {
    initialized: bool,
    revision: u64,
    applied_revision: u64,
    desired: NetworkConfiguration,
    runtime: Ipv4RuntimeStatus,
    carrier_up: bool,
    ethernet_address: [u8; 6],
}

static CONTROL: SpinLock<ControlState> = SpinLock::new(ControlState {
    initialized: false,
    revision: 0,
    applied_revision: 0,
    desired: NetworkConfiguration {
        link_up: true,
        method: Ipv4Method::Dhcp,
    },
    runtime: Ipv4RuntimeStatus::Unconfigured,
    carrier_up: false,
    ethernet_address: [0; 6],
});

fn policy_configuration(policy: Ipv4Policy) -> NetworkConfiguration {
    NetworkConfiguration {
        link_up: true,
        method: match policy {
            Ipv4Policy::Static(address) => Ipv4Method::Static(address),
            Ipv4Policy::Dhcp { .. } => Ipv4Method::Dhcp,
        },
    }
}

pub fn initialize(policy: Ipv4Policy, ethernet_address: [u8; 6]) {
    let mut control = CONTROL.lock();
    if control.initialized {
        return;
    }
    control.initialized = true;
    control.revision = 1;
    control.applied_revision = 0;
    control.desired = policy_configuration(policy);
    control.runtime = Ipv4RuntimeStatus::Unconfigured;
    control.carrier_up = false;
    control.ethernet_address = ethernet_address;
}

pub fn snapshot(fallback: Ipv4Policy) -> (u64, NetworkConfiguration) {
    let control = *CONTROL.lock();
    if control.initialized {
        (control.revision, control.desired)
    } else {
        (0, policy_configuration(fallback))
    }
}

pub fn acknowledge(revision: u64, status: Ipv4RuntimeStatus) {
    let mut control = CONTROL.lock();
    if control.revision == revision {
        control.applied_revision = revision;
        control.runtime = status;
    }
}

pub fn publish_status(status: Ipv4RuntimeStatus) {
    CONTROL.lock().runtime = status;
}

pub fn publish_carrier(carrier_up: bool) {
    CONTROL.lock().carrier_up = carrier_up;
}

pub fn changed() -> bool {
    let control = CONTROL.lock();
    control.initialized && control.revision != control.applied_revision
}

fn update(change: impl FnOnce(&mut NetworkConfiguration)) {
    let mut control = CONTROL.lock();
    change(&mut control.desired);
    control.revision = control.revision.wrapping_add(1).max(1);
}

pub fn vsh_ip(args: &[String]) -> Result<String, Status> {
    match parse_ip_command(args).map_err(|_| Status::Usage)? {
        IpCommand::ShowLink => Ok(show_link()),
        IpCommand::ShowAddress => Ok(show_address()),
        IpCommand::ShowRoute => Ok(show_route()),
        IpCommand::SetLink { up } => {
            update(|configuration| configuration.link_up = up);
            Ok(String::new())
        }
        IpCommand::ReplaceAddress {
            address,
            prefix_len,
        } => {
            update(|configuration| {
                let default_gateway = match configuration.method {
                    Ipv4Method::Static(current) => current.default_gateway,
                    Ipv4Method::None | Ipv4Method::Dhcp => None,
                };
                configuration.method = Ipv4Method::Static(StaticIpv4Address {
                    address,
                    prefix_len,
                    default_gateway,
                });
            });
            Ok(String::new())
        }
        IpCommand::FlushAddress => {
            update(|configuration| configuration.method = Ipv4Method::None);
            Ok(String::new())
        }
        IpCommand::ReplaceDefaultRoute { gateway } => {
            let mut control = CONTROL.lock();
            let Ipv4Method::Static(mut address) = control.desired.method else {
                return Err(Status::Usage);
            };
            address.default_gateway = Some(gateway);
            control.desired.method = Ipv4Method::Static(address);
            control.revision = control.revision.wrapping_add(1).max(1);
            Ok(String::new())
        }
    }
}

pub fn vsh_dhclient(args: &[String]) -> Result<String, Status> {
    match parse_dhclient_command(args).map_err(|_| Status::Usage)? {
        DhclientCommand::Acquire => {
            update(|configuration| {
                configuration.link_up = true;
                configuration.method = Ipv4Method::Dhcp;
            });
            Ok(String::from(
                "DHCP discovery started; the SSH listener will rebind when a lease is available\n",
            ))
        }
        DhclientCommand::Release => {
            update(|configuration| configuration.method = Ipv4Method::None);
            Ok(String::from(
                "DHCP client stopped and IPv4 configuration cleared\n",
            ))
        }
    }
}

fn show_link() -> String {
    let control = *CONTROL.lock();
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
        "1: {PRIMARY_INTERFACE}: <{flags}> mtu 1500 state {state}\n    link/ether {} brd ff:ff:ff:ff:ff:ff\n",
        format_mac(control.ethernet_address)
    )
}

fn show_address() -> String {
    let control = *CONTROL.lock();
    let mut output = show_link();
    match control.runtime {
        Ipv4RuntimeStatus::Static(address) => output.push_str(&format_address(address, "")),
        Ipv4RuntimeStatus::DhcpBound(address) => {
            output.push_str(&format_address(address, " dynamic"));
        }
        Ipv4RuntimeStatus::DhcpDiscovering => {
            output.push_str("    inet dhcp pending scope global dynamic net0\n");
        }
        Ipv4RuntimeStatus::Unconfigured => {}
    }
    output
}

fn show_route() -> String {
    let control = *CONTROL.lock();
    match control.runtime {
        Ipv4RuntimeStatus::Static(address) => format_route(address, "static"),
        Ipv4RuntimeStatus::DhcpBound(address) => format_route(address, "dhcp"),
        Ipv4RuntimeStatus::Unconfigured | Ipv4RuntimeStatus::DhcpDiscovering => String::new(),
    }
}

fn format_address(address: StaticIpv4Address, suffix: &str) -> String {
    format!(
        "    inet {}/{} scope global{suffix} {PRIMARY_INTERFACE}\n",
        format_ipv4(address.address),
        address.prefix_len,
    )
}

fn format_route(address: StaticIpv4Address, protocol: &str) -> String {
    address.default_gateway.map_or_else(String::new, |gateway| {
        format!(
            "default via {} dev {PRIMARY_INTERFACE} proto {protocol}\n",
            format_ipv4(gateway)
        )
    })
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
