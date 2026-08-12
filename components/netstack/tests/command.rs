use vibeos_netstack::command::{
    parse_dhclient_command, parse_ip_command, DhclientCommand, IpCommand, NetworkInterfaceId,
};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn parses_linux_style_show_and_static_ipv4_commands() {
    assert_eq!(
        parse_ip_command(&args(&["link", "show"])),
        Ok(IpCommand::ShowLink { interface: None })
    );
    assert_eq!(
        parse_ip_command(&args(&["-4", "addr", "show", "dev", "eth0"])),
        Ok(IpCommand::ShowAddress {
            interface: Some(NetworkInterfaceId::PRIMARY),
        })
    );
    assert_eq!(
        parse_ip_command(&args(&[
            "addr",
            "replace",
            "192.168.7.20/24",
            "dev",
            "net0"
        ])),
        Ok(IpCommand::ReplaceAddress {
            interface: NetworkInterfaceId::PRIMARY,
            address: [192, 168, 7, 20],
            prefix_len: 24,
        })
    );
    assert_eq!(
        parse_ip_command(&args(&[
            "route",
            "replace",
            "default",
            "via",
            "192.168.7.1",
            "dev",
            "net0"
        ])),
        Ok(IpCommand::ReplaceDefaultRoute {
            interface: NetworkInterfaceId::PRIMARY,
            gateway: [192, 168, 7, 1],
        })
    );
}

#[test]
fn parses_link_and_dhcp_commands_with_eth0_alias() {
    assert_eq!(
        parse_ip_command(&args(&["link", "set", "dev", "eth0", "down"])),
        Ok(IpCommand::SetLink {
            interface: NetworkInterfaceId::PRIMARY,
            up: false,
        })
    );
    assert_eq!(
        parse_dhclient_command(&[]),
        Ok(DhclientCommand::Acquire {
            interface: NetworkInterfaceId::PRIMARY,
        })
    );
    assert_eq!(
        parse_dhclient_command(&args(&["-r", "eth0"])),
        Ok(DhclientCommand::Release {
            interface: NetworkInterfaceId::PRIMARY,
        })
    );
}

#[test]
fn carries_secondary_interface_identity_through_every_command() {
    let net1 = NetworkInterfaceId::new(1).unwrap();
    assert_eq!(
        parse_ip_command(&args(&["link", "show", "dev", "net1"])),
        Ok(IpCommand::ShowLink {
            interface: Some(net1),
        })
    );
    assert_eq!(
        parse_ip_command(&args(&["addr", "flush", "dev", "eth1"])),
        Ok(IpCommand::FlushAddress { interface: net1 })
    );
    assert_eq!(
        parse_ip_command(&args(&[
            "route",
            "replace",
            "default",
            "via",
            "192.168.8.1",
            "dev",
            "net1",
        ])),
        Ok(IpCommand::ReplaceDefaultRoute {
            interface: net1,
            gateway: [192, 168, 8, 1],
        })
    );
    assert_eq!(
        parse_dhclient_command(&args(&["net1"])),
        Ok(DhclientCommand::Acquire { interface: net1 })
    );
}

#[test]
fn rejects_out_of_scope_devices_and_invalid_addresses() {
    assert!(
        parse_ip_command(&args(&["addr", "replace", "192.168.1.8/33", "dev", "net0"])).is_err()
    );
    assert!(parse_ip_command(&args(&["route", "replace", "default", "via", "224.0.0.1"])).is_err());
    assert!(parse_ip_command(&args(&["link", "show", "dev", "wlan0"])).is_err());
    assert!(parse_ip_command(&args(&["link", "show", "dev", "net4"])).is_err());
    assert!(parse_ip_command(&args(&["link", "show", "dev", "net01"])).is_err());
    assert!(parse_dhclient_command(&args(&["-1", "net0"])).is_err());
}
