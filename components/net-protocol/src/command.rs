//! Pure parsing for the operator-controlled IPv4 command surface.

extern crate alloc;

use alloc::string::String;
use core::net::Ipv4Addr;
use core::str::FromStr;

use crate::StaticIpv4Address;

/// Compatibility spelling for the first topology-sorted interface.
/// This does not identify a driver class.
pub const PRIMARY_INTERFACE: &str = "net0";
pub const COMPAT_INTERFACE: &str = "eth0";

/// Stable, boot-local index used to join an interface's packet capabilities,
/// control state, and human-readable `netN` name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetworkInterfaceId(u16);

impl NetworkInterfaceId {
    /// First entry after the image policy sorts physical topology keys.
    pub const FIRST: Self = Self(0);
    /// Compatibility alias; the first entry is not bound to a driver class.
    pub const PRIMARY: Self = Self::FIRST;

    pub const fn new(index: u16) -> Self {
        Self(index)
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv4Method {
    None,
    Static(StaticIpv4Address),
    Dhcp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkConfiguration {
    pub link_up: bool,
    pub method: Ipv4Method,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpCommand {
    ShowLink {
        interface: Option<NetworkInterfaceId>,
    },
    ShowAddress {
        interface: Option<NetworkInterfaceId>,
    },
    ShowRoute {
        interface: Option<NetworkInterfaceId>,
    },
    SetLink {
        interface: NetworkInterfaceId,
        up: bool,
    },
    ReplaceAddress {
        interface: NetworkInterfaceId,
        address: [u8; 4],
        prefix_len: u8,
    },
    FlushAddress {
        interface: NetworkInterfaceId,
    },
    ReplaceDefaultRoute {
        interface: NetworkInterfaceId,
        gateway: [u8; 4],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhclientCommand {
    Acquire { interface: NetworkInterfaceId },
    Release { interface: NetworkInterfaceId },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandParseError(pub &'static str);

pub fn parse_ip_command(args: &[String]) -> Result<IpCommand, CommandParseError> {
    let args = strip_ipv4_flag(args);
    match string_args(args).as_slice() {
        ["link", "show"] => Ok(IpCommand::ShowLink { interface: None }),
        ["link", "show", "dev", device] => Ok(IpCommand::ShowLink {
            interface: Some(parse_interface(device)?),
        }),
        ["link", "set", "dev", device, state] | ["link", "set", device, state]
            if matches!(*state, "up" | "down") =>
        {
            Ok(IpCommand::SetLink {
                interface: parse_interface(device)?,
                up: *state == "up",
            })
        }
        ["addr", "show"] | ["address", "show"] => {
            Ok(IpCommand::ShowAddress { interface: None })
        }
        ["addr", "show", "dev", device] | ["address", "show", "dev", device] => {
            Ok(IpCommand::ShowAddress {
                interface: Some(parse_interface(device)?),
            })
        }
        ["addr" | "address", "replace" | "add", cidr, "dev", device] => {
            let (address, prefix_len) = parse_cidr(cidr)?;
            Ok(IpCommand::ReplaceAddress {
                interface: parse_interface(device)?,
                address,
                prefix_len,
            })
        }
        ["addr" | "address", "flush", "dev", device] => Ok(IpCommand::FlushAddress {
            interface: parse_interface(device)?,
        }),
        ["route", "show"] => Ok(IpCommand::ShowRoute { interface: None }),
        ["route", "show", "dev", device] => Ok(IpCommand::ShowRoute {
            interface: Some(parse_interface(device)?),
        }),
        ["route", "replace" | "add", "default", "via", gateway] => {
            Ok(IpCommand::ReplaceDefaultRoute {
                interface: NetworkInterfaceId::FIRST,
                gateway: parse_unicast_ipv4(gateway)?,
            })
        }
        [
            "route",
            "replace" | "add",
            "default",
            "via",
            gateway,
            "dev",
            device,
        ] => Ok(IpCommand::ReplaceDefaultRoute {
            interface: parse_interface(device)?,
            gateway: parse_unicast_ipv4(gateway)?,
        }),
        _ => Err(CommandParseError(
            "usage: ip [-4] link show [dev netN]|link set dev netN up|down|addr show [dev netN]|addr replace ADDRESS/PREFIX dev netN|addr flush dev netN|route show [dev netN]|route replace default via GATEWAY [dev netN]",
        )),
    }
}

pub fn parse_dhclient_command(args: &[String]) -> Result<DhclientCommand, CommandParseError> {
    match string_args(args).as_slice() {
        [] => Ok(DhclientCommand::Acquire {
            interface: NetworkInterfaceId::FIRST,
        }),
        ["-r"] => Ok(DhclientCommand::Release {
            interface: NetworkInterfaceId::FIRST,
        }),
        ["-r", device] => Ok(DhclientCommand::Release {
            interface: parse_interface(device)?,
        }),
        [device] => Ok(DhclientCommand::Acquire {
            interface: parse_interface(device)?,
        }),
        _ => Err(CommandParseError("usage: dhclient [-r] [netN]")),
    }
}

fn strip_ipv4_flag(args: &[String]) -> &[String] {
    if args.first().is_some_and(|argument| argument == "-4") {
        &args[1..]
    } else {
        args
    }
}

fn string_args(args: &[String]) -> alloc::vec::Vec<&str> {
    args.iter().map(String::as_str).collect()
}

fn parse_interface(device: &str) -> Result<NetworkInterfaceId, CommandParseError> {
    let index = device
        .strip_prefix("net")
        .or_else(|| device.strip_prefix("eth"))
        .ok_or(CommandParseError("network interface must be named netN"))?;
    if index.is_empty() || (index.len() > 1 && index.starts_with('0')) {
        return Err(CommandParseError(
            "network interface index is not canonical",
        ));
    }
    let index = index
        .parse::<u16>()
        .map_err(|_| CommandParseError("invalid network interface index"))?;
    Ok(NetworkInterfaceId::new(index))
}

fn parse_cidr(value: &str) -> Result<([u8; 4], u8), CommandParseError> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or(CommandParseError("IPv4 address requires a /PREFIX"))?;
    let address = parse_unicast_ipv4(address)?;
    let prefix_len = prefix
        .parse::<u8>()
        .map_err(|_| CommandParseError("IPv4 prefix is not a number"))?;
    if prefix_len > 32 {
        return Err(CommandParseError("IPv4 prefix exceeds 32"));
    }
    Ok((address, prefix_len))
}

fn parse_unicast_ipv4(value: &str) -> Result<[u8; 4], CommandParseError> {
    let address =
        Ipv4Addr::from_str(value).map_err(|_| CommandParseError("invalid IPv4 address"))?;
    let octets = address.octets();
    if address.is_unspecified() || address.is_multicast() || octets == [255; 4] || octets[0] == 0 {
        return Err(CommandParseError("IPv4 address must be unicast"));
    }
    Ok(octets)
}
