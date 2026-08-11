//! Capability-admitted control plane for the single IPv4 stack.

extern crate alloc;

use alloc::format;
use alloc::string::String;

use vibeos_net_protocol::{Ipv4RuntimeStatus, StackError, StaticIpv4Address, StaticIpv4EchoStack};

use crate::command::{
    parse_dhclient_command, parse_ip_command, DhclientCommand, IpCommand, Ipv4Method,
    NetworkConfiguration, PRIMARY_INTERFACE,
};
use vibeos_core::sync::SpinLock;
use vibeos_vsh::Status;

pub const DEFAULT_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
pub const DEFAULT_IPV4: [u8; 4] = [10, 0, 2, 15];
pub const DEFAULT_GATEWAY: [u8; 4] = [10, 0, 2, 2];
pub const DEFAULT_PREFIX_LEN: u8 = 24;

#[cfg(feature = "tcp-echo")]
const DEFAULT_STATIC: StaticIpv4Address =
    StaticIpv4Address::new(DEFAULT_IPV4, DEFAULT_PREFIX_LEN).with_default_gateway(DEFAULT_GATEWAY);

#[derive(Clone, Copy)]
struct ControlState {
    revision: u64,
    desired: NetworkConfiguration,
    applied_revision: u64,
    runtime: Ipv4RuntimeStatus,
    carrier_up: bool,
}

/// Image-selected boot policy for the network service.
///
/// The echo acceptance image uses the deterministic SLIRP address expected by
/// its test harness. The interactive shell image starts DHCP and is free to run
/// on any board whose platform adapter implements the packet contract.
#[cfg(feature = "tcp-echo")]
const BOOT_CONFIGURATION: NetworkConfiguration = NetworkConfiguration {
    link_up: true,
    method: Ipv4Method::Static(DEFAULT_STATIC),
};

#[cfg(feature = "net-shell")]
const BOOT_CONFIGURATION: NetworkConfiguration = NetworkConfiguration {
    link_up: true,
    method: Ipv4Method::Dhcp,
};

static CONTROL: SpinLock<ControlState> = SpinLock::new(ControlState {
    revision: 1,
    desired: BOOT_CONFIGURATION,
    applied_revision: 0,
    runtime: Ipv4RuntimeStatus::Unconfigured,
    carrier_up: false,
});

pub fn vsh_ip(args: &[String]) -> Result<String, Status> {
    let command = parse_ip_command(args).map_err(|_| Status::Usage)?;
    match command {
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
                "DHCP discovery started; use `ip -4 addr show dev net0` to inspect the lease\n",
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

pub fn reconcile(
    stack: &mut StaticIpv4EchoStack,
    observed_revision: &mut u64,
) -> Result<(), StackError> {
    let (revision, desired) = {
        let control = CONTROL.lock();
        (control.revision, control.desired)
    };
    if revision == *observed_revision {
        publish_runtime(revision, stack.ipv4_status());
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
    publish_runtime(revision, stack.ipv4_status());
    Ok(())
}

pub fn publish_stack_status(observed_revision: u64, status: Ipv4RuntimeStatus) {
    publish_runtime(observed_revision, status);
}

pub fn publish_carrier(carrier_up: bool) {
    CONTROL.lock().carrier_up = carrier_up;
}

fn update(change: impl FnOnce(&mut NetworkConfiguration)) {
    let mut control = CONTROL.lock();
    change(&mut control.desired);
    control.revision = control.revision.wrapping_add(1).max(1);
}

fn publish_runtime(revision: u64, status: Ipv4RuntimeStatus) {
    let mut control = CONTROL.lock();
    if revision == control.revision {
        control.applied_revision = revision;
        control.runtime = status;
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
        format_mac(DEFAULT_MAC)
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
