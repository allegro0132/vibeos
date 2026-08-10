use vibeos_core::net_config::{
    parse_dhclient_command, parse_ip_command, DhclientCommand, IpCommand,
};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn parses_linux_style_show_and_static_ipv4_commands() {
    assert_eq!(
        parse_ip_command(&args(&["link", "show"])),
        Ok(IpCommand::ShowLink)
    );
    assert_eq!(
        parse_ip_command(&args(&["-4", "addr", "show", "dev", "eth0"])),
        Ok(IpCommand::ShowAddress)
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
            gateway: [192, 168, 7, 1],
        })
    );
}

#[test]
fn parses_link_and_dhcp_commands_with_eth0_alias() {
    assert_eq!(
        parse_ip_command(&args(&["link", "set", "dev", "eth0", "down"])),
        Ok(IpCommand::SetLink { up: false })
    );
    assert_eq!(parse_dhclient_command(&[]), Ok(DhclientCommand::Acquire));
    assert_eq!(
        parse_dhclient_command(&args(&["-r", "eth0"])),
        Ok(DhclientCommand::Release)
    );
}

#[test]
fn rejects_out_of_scope_devices_and_invalid_addresses() {
    assert!(
        parse_ip_command(&args(&["addr", "replace", "192.168.1.8/33", "dev", "net0"])).is_err()
    );
    assert!(parse_ip_command(&args(&["route", "replace", "default", "via", "224.0.0.1"])).is_err());
    assert!(parse_ip_command(&args(&["link", "show", "dev", "wlan0"])).is_err());
    assert!(parse_dhclient_command(&args(&["-1", "net0"])).is_err());
}
