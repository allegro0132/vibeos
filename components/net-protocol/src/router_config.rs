//! Validated two-interface router configuration, shared by serial and future
//! lease-driven control. No packet state is changed during validation.
use crate::{nat, neighbor};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub interfaces: [neighbor::Interface; 2], // WAN, LAN
}
impl Config {
    pub fn new(interfaces: [neighbor::Interface; 2]) -> Result<Self, &'static str> {
        let [wan, lan] = interfaces;
        // Reuse neighbor policy without allocating a neighbor table.
        if wan.next_hop(wan.ip) != Err(neighbor::Error::Local)
            || lan.next_hop(lan.ip) != Err(neighbor::Error::Local)
        {
            return Err("invalid interface address, prefix, MAC or gateway");
        }
        if wan.mac == lan.mac || lan.gateway.is_some() {
            return Err("distinct MACs and no LAN default gateway required");
        }
        let mask = u32::MAX << (32 - wan.prefix.min(lan.prefix));
        if u32::from_be_bytes(wan.ip) & mask == u32::from_be_bytes(lan.ip) & mask {
            return Err("WAN and LAN networks overlap");
        }
        Ok(Self { interfaces })
    }
    pub fn nat(self) -> nat::Config {
        nat::Config {
            wan_ip: self.interfaces[0].ip,
            lan_ip: self.interfaces[1].ip,
            lan_prefix: self.interfaces[1].prefix,
        }
    }
    /// WAN CIDR, WAN gateway (or "none"), LAN CIDR. Strict dotted decimal.
    pub fn parse(args: &[&str], macs: [[u8; 6]; 2]) -> Result<Self, &'static str> {
        if args.len() != 3 { return Err("expected WAN_CIDR GATEWAY|none LAN_CIDR"); }
        fn cidr(text: &str) -> Result<([u8; 4], u8), &'static str> {
            let (ip, prefix) = text.split_once('/').ok_or("missing prefix")?;
            Ok((ip.parse::<core::net::Ipv4Addr>().map_err(|_| "invalid IPv4")?.octets(),
                prefix.parse::<u8>().map_err(|_| "invalid prefix")?))
        }
        let (wan_ip, wan_prefix) = cidr(args[0])?;
        let (lan_ip, lan_prefix) = cidr(args[2])?;
        let gateway = if args[1] == "none" { None } else {
            Some(args[1].parse::<core::net::Ipv4Addr>().map_err(|_| "invalid gateway")?.octets())
        };
        Self::new([
            neighbor::Interface { mac: macs[0], ip: wan_ip, prefix: wan_prefix, gateway },
            neighbor::Interface { mac: macs[1], ip: lan_ip, prefix: lan_prefix, gateway: None },
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MACS: [[u8; 6]; 2] = [[2,0,0,0,0,1],[2,0,0,0,0,2]];
    #[test]
    fn valid_config_composes_with_nat_and_neighbors() {
        for gateway in ["192.168.78.2", "none"] {
            let c = Config::parse(&["192.168.78.1/24", gateway, "192.168.79.1/24"], MACS).unwrap();
            assert!(nat::Table::<4, 8>::new(c.nat(), 1).is_ok());
            for i in c.interfaces { assert!(neighbor::Table::<4>::new(i).is_ok()); }
        }
    }
    #[test]
    fn rejects_unsafe_and_ambiguous_address_sets() {
        for args in [
            ["192.168.78.1/0", "none", "192.168.79.1/24"],
            ["192.168.78.1/31", "none", "192.168.79.1/24"],
            ["192.168.78.0/24", "none", "192.168.79.1/24"],
            ["192.168.78.255/24", "none", "192.168.79.1/24"],
            ["192.168.78.1/24", "192.168.78.1", "192.168.79.1/24"],
            ["192.168.78.1/24", "192.168.79.2", "192.168.79.1/24"],
            ["192.168.78.1/24", "192.168.78.255", "192.168.79.1/24"],
            ["192.168.78.1/16", "none", "192.168.79.1/24"],
            ["192.168.78.1/24", "none", "192.168.79.1/16"],
            ["127.0.0.1/24", "none", "192.168.79.1/24"],
            ["224.1.2.3/24", "none", "192.168.79.1/24"],
            ["192.168.078.1/24", "none", "192.168.79.1/24"],
            ["192.168.78.1/24/24", "none", "192.168.79.1/24"],
        ] { assert!(Config::parse(&args, MACS).is_err(), "{args:?}"); }
        assert!(Config::parse(&[], MACS).is_err());
        assert!(Config::parse(&["192.168.78.1/24", "none", "192.168.79.1/24"], [MACS[0]; 2]).is_err());
    }
}


/// Ethernet fixture MTU policy. The lower bound also accommodates generated
/// ICMP quotes without requiring local fragmentation; jumbo frames are excluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mtus([u16; 2]);
impl Mtus {
    pub const DEFAULT: Self = Self([1500; 2]);
    pub fn new(wan: u16, lan: u16) -> Result<Self, &'static str> {
        if !(576..=1500).contains(&wan) || !(576..=1500).contains(&lan) {
            return Err("MTU must be 576..1500");
        }
        Ok(Self([wan, lan]))
    }
    pub fn parse(args: &[&str]) -> Result<Self, &'static str> {
        if args.len() != 2 { return Err("expected WAN_MTU LAN_MTU"); }
        Self::new(args[0].parse().map_err(|_| "invalid WAN MTU")?,
                  args[1].parse().map_err(|_| "invalid LAN MTU")?)
    }
    pub fn get(self, interface: usize) -> u16 { self.0[interface] }
}

#[cfg(test)]
mod mtu_tests {
    use super::*;
    #[test]
    fn interface_mtu_policy_is_bounded_and_independent() {
        let m = Mtus::parse(&["1492", "576"]).unwrap();
        assert_eq!(m.get(0), 1492);
        assert_eq!(m.get(1), 576);
        assert_eq!(Mtus::DEFAULT, Mtus::new(1500, 1500).unwrap());
        for args in [["575", "1500"], ["1500", "1501"], ["65536", "1500"], ["-1", "1500"], ["1400x", "1500"]] {
            assert!(Mtus::parse(&args).is_err());
        }
        assert!(Mtus::parse(&[]).is_err());
    }
}
