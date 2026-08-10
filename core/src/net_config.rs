//! Pure command parsing and value types for operator-controlled IPv4 setup.
//!
//! The parser intentionally implements a small, documented subset of the
//! iproute2 and ISC dhclient command surfaces. It never resolves authority or
//! mutates a device; the kernel-side network configuration service performs
//! those operations after the command capability has been admitted by vsh.

extern crate alloc;

use alloc::string::String;
use core::net::Ipv4Addr;
use core::str::FromStr;

pub const PRIMARY_INTERFACE: &str = "net0";
pub const COMPAT_INTERFACE: &str = "eth0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticIpv4Address {
    pub address: [u8; 4],
    pub prefix_len: u8,
    pub default_gateway: Option<[u8; 4]>,
}

impl StaticIpv4Address {
    pub const fn new(address: [u8; 4], prefix_len: u8) -> Self {
        Self {
            address,
            prefix_len,
            default_gateway: None,
        }
    }

    pub const fn with_default_gateway(mut self, gateway: [u8; 4]) -> Self {
        self.default_gateway = Some(gateway);
        self
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
pub enum Ipv4RuntimeStatus {
    Unconfigured,
    Static(StaticIpv4Address),
    DhcpDiscovering,
    DhcpBound(StaticIpv4Address),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpCommand {
    ShowLink,
    ShowAddress,
    ShowRoute,
    SetLink { up: bool },
    ReplaceAddress { address: [u8; 4], prefix_len: u8 },
    FlushAddress,
    ReplaceDefaultRoute { gateway: [u8; 4] },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhclientCommand {
    Acquire,
    Release,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandParseError(pub &'static str);

pub fn parse_ip_command(args: &[String]) -> Result<IpCommand, CommandParseError> {
    let args = strip_ipv4_flag(args);
    match string_args(args).as_slice() {
        ["link", "show"] => Ok(IpCommand::ShowLink),
        ["link", "show", "dev", device] if valid_device(device) => Ok(IpCommand::ShowLink),
        ["link", "set", "dev", device, state] | ["link", "set", device, state]
            if valid_device(device) && matches!(*state, "up" | "down") =>
        {
            Ok(IpCommand::SetLink { up: *state == "up" })
        }
        ["addr", "show"] | ["address", "show"] => Ok(IpCommand::ShowAddress),
        ["addr", "show", "dev", device] | ["address", "show", "dev", device]
            if valid_device(device) =>
        {
            Ok(IpCommand::ShowAddress)
        }
        [operation @ ("addr" | "address"), action @ ("replace" | "add"), cidr, "dev", device]
            if valid_device(device) =>
        {
            let _ = (operation, action);
            let (address, prefix_len) = parse_cidr(cidr)?;
            Ok(IpCommand::ReplaceAddress {
                address,
                prefix_len,
            })
        }
        ["addr" | "address", "flush", "dev", device] if valid_device(device) => {
            Ok(IpCommand::FlushAddress)
        }
        ["route", "show"] => Ok(IpCommand::ShowRoute),
        ["route", "replace" | "add", "default", "via", gateway]
        | ["route", "replace" | "add", "default", "via", gateway, "dev", PRIMARY_INTERFACE]
        | ["route", "replace" | "add", "default", "via", gateway, "dev", COMPAT_INTERFACE] => {
            Ok(IpCommand::ReplaceDefaultRoute {
                gateway: parse_unicast_ipv4(gateway)?,
            })
        }
        _ => Err(CommandParseError(
            "usage: ip [-4] link show|link set dev net0 up|down|addr show|addr replace ADDRESS/PREFIX dev net0|addr flush dev net0|route show|route replace default via GATEWAY [dev net0]",
        )),
    }
}

pub fn parse_dhclient_command(args: &[String]) -> Result<DhclientCommand, CommandParseError> {
    match string_args(args).as_slice() {
        [] | [PRIMARY_INTERFACE] | [COMPAT_INTERFACE] => Ok(DhclientCommand::Acquire),
        ["-r"] | ["-r", PRIMARY_INTERFACE] | ["-r", COMPAT_INTERFACE] => {
            Ok(DhclientCommand::Release)
        }
        _ => Err(CommandParseError("usage: dhclient [-r] [net0]")),
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

fn valid_device(device: &str) -> bool {
    matches!(device, PRIMARY_INTERFACE | COMPAT_INTERFACE)
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
