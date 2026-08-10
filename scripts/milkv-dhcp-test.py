#!/usr/bin/env python3
"""One-address DHCPv4 peer for an isolated Milk-V acceptance link.

This is deliberately not a general DHCP server. It binds one named interface,
answers one exact client MAC, offers one caller-selected IPv4 address, and
supplies neither a router nor DNS. It keeps no files or lease database.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import signal
import socket
import struct
import sys


BOOTREQUEST = 1
BOOTREPLY = 2
ETHERNET_HTYPE = 1
DHCP_COOKIE = b"\x63\x82\x53\x63"
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5
OPT_SUBNET_MASK = 1
OPT_BROADCAST = 28
OPT_REQUESTED_IP = 50
OPT_LEASE_TIME = 51
OPT_MESSAGE_TYPE = 53
OPT_SERVER_ID = 54
OPT_RENEWAL_TIME = 58
OPT_REBIND_TIME = 59
OPT_END = 255
IP_BOUND_IF_DARWIN = 25
SO_BINDTODEVICE_LINUX = 25
BOOTP = struct.Struct("!BBBBIHH4s4s4s4s16s64s128s")
MIN_DHCP_BYTES = BOOTP.size + len(DHCP_COOKIE)


class DhcpError(ValueError):
    pass


@dataclass(frozen=True)
class Request:
    xid: int
    flags: int
    ciaddr: ipaddress.IPv4Address
    client_mac: bytes
    options: dict[int, bytes]

    @property
    def message_type(self) -> int:
        value = self.options.get(OPT_MESSAGE_TYPE, b"")
        if len(value) != 1:
            raise DhcpError("missing or malformed DHCP message type")
        return value[0]


@dataclass(frozen=True)
class Config:
    server_ip: ipaddress.IPv4Address
    client_ip: ipaddress.IPv4Address
    client_mac: bytes
    network: ipaddress.IPv4Network
    lease_seconds: int


def parse_mac(value: str) -> bytes:
    parts = value.split(":")
    if len(parts) != 6:
        raise argparse.ArgumentTypeError("MAC must contain six colon-separated octets")
    try:
        result = bytes(int(part, 16) for part in parts)
    except ValueError as error:
        raise argparse.ArgumentTypeError("MAC octets must be hexadecimal") from error
    if any(len(part) != 2 for part in parts) or result == b"\x00" * 6 or result[0] & 1:
        raise argparse.ArgumentTypeError("MAC must be a non-zero unicast address")
    return result


def parse_options(data: bytes) -> dict[int, bytes]:
    options: dict[int, bytes] = {}
    offset = 0
    while offset < len(data):
        code = data[offset]
        offset += 1
        if code == 0:
            continue
        if code == OPT_END:
            return options
        if offset >= len(data):
            raise DhcpError("truncated DHCP option length")
        length = data[offset]
        offset += 1
        end = offset + length
        if end > len(data):
            raise DhcpError("truncated DHCP option value")
        if code in options:
            raise DhcpError("duplicate DHCP option")
        options[code] = data[offset:end]
        offset = end
    raise DhcpError("DHCP options are missing END")


def parse_request(packet: bytes) -> Request:
    if len(packet) < MIN_DHCP_BYTES:
        raise DhcpError("packet is shorter than BOOTP plus DHCP cookie")
    (
        op,
        htype,
        hlen,
        hops,
        xid,
        _secs,
        flags,
        ciaddr,
        _yiaddr,
        _siaddr,
        giaddr,
        chaddr,
        _sname,
        _bootfile,
    ) = BOOTP.unpack_from(packet)
    if op != BOOTREQUEST or htype != ETHERNET_HTYPE or hlen != 6:
        raise DhcpError("request is not Ethernet BOOTP")
    if hops != 0 or giaddr != b"\x00" * 4:
        raise DhcpError("relayed DHCP is outside this direct-link peer")
    if packet[BOOTP.size:MIN_DHCP_BYTES] != DHCP_COOKIE:
        raise DhcpError("invalid DHCP cookie")
    request = Request(
        xid=xid,
        flags=flags,
        ciaddr=ipaddress.IPv4Address(ciaddr),
        client_mac=chaddr[:6],
        options=parse_options(packet[MIN_DHCP_BYTES:]),
    )
    _ = request.message_type
    return request


def option(code: int, value: bytes) -> bytes:
    if not 0 < code < OPT_END or len(value) > 255:
        raise DhcpError("invalid encoded DHCP option")
    return bytes((code, len(value))) + value


def build_reply(request: Request, config: Config, message_type: int) -> bytes:
    if message_type not in (DHCP_OFFER, DHCP_ACK):
        raise DhcpError("unsupported DHCP reply type")
    header = BOOTP.pack(
        BOOTREPLY,
        ETHERNET_HTYPE,
        6,
        0,
        request.xid,
        0,
        request.flags | 0x8000,
        b"\x00" * 4,
        config.client_ip.packed,
        b"\x00" * 4,
        b"\x00" * 4,
        request.client_mac + b"\x00" * 10,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    renewal = max(1, config.lease_seconds // 2)
    rebind = max(renewal + 1, config.lease_seconds * 7 // 8)
    options = b"".join(
        (
            option(OPT_MESSAGE_TYPE, bytes((message_type,))),
            option(OPT_SERVER_ID, config.server_ip.packed),
            option(OPT_LEASE_TIME, struct.pack("!I", config.lease_seconds)),
            option(OPT_SUBNET_MASK, config.network.netmask.packed),
            option(OPT_BROADCAST, config.network.broadcast_address.packed),
            option(OPT_RENEWAL_TIME, struct.pack("!I", renewal)),
            option(OPT_REBIND_TIME, struct.pack("!I", rebind)),
            bytes((OPT_END,)),
        )
    )
    packet = header + DHCP_COOKIE + options
    return packet + b"\x00" * max(0, 300 - len(packet))


def reply_for(request: Request, config: Config) -> tuple[int, bytes] | None:
    if request.client_mac != config.client_mac:
        return None
    if request.message_type == DHCP_DISCOVER:
        return DHCP_OFFER, build_reply(request, config, DHCP_OFFER)
    if request.message_type != DHCP_REQUEST:
        return None

    server_id = request.options.get(OPT_SERVER_ID)
    requested = request.options.get(OPT_REQUESTED_IP)
    if server_id is not None:
        if (
            server_id != config.server_ip.packed
            or requested != config.client_ip.packed
            or int(request.ciaddr) != 0
        ):
            return None
    elif requested is not None:
        if requested != config.client_ip.packed or int(request.ciaddr) != 0:
            return None
    elif request.ciaddr != config.client_ip:
        return None
    return DHCP_ACK, build_reply(request, config, DHCP_ACK)


def request_packet(
    message_type: int,
    mac: bytes,
    *,
    xid: int = 0x12345678,
    requested_ip: ipaddress.IPv4Address | None = None,
    server_id: ipaddress.IPv4Address | None = None,
    ciaddr: ipaddress.IPv4Address | None = None,
) -> bytes:
    header = BOOTP.pack(
        BOOTREQUEST,
        ETHERNET_HTYPE,
        6,
        0,
        xid,
        0,
        0x8000,
        (ciaddr or ipaddress.IPv4Address("0.0.0.0")).packed,
        b"\x00" * 4,
        b"\x00" * 4,
        b"\x00" * 4,
        mac + b"\x00" * 10,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    options = option(OPT_MESSAGE_TYPE, bytes((message_type,)))
    if requested_ip is not None:
        options += option(OPT_REQUESTED_IP, requested_ip.packed)
    if server_id is not None:
        options += option(OPT_SERVER_ID, server_id.packed)
    return header + DHCP_COOKIE + options + bytes((OPT_END,))


def selftest() -> None:
    server = ipaddress.IPv4Address("169.254.184.74")
    client = ipaddress.IPv4Address("169.254.184.75")
    mac = bytes.fromhex("020000000001")
    config = Config(server, client, mac, ipaddress.IPv4Network("169.254.0.0/16"), 3600)

    discover = parse_request(request_packet(DHCP_DISCOVER, mac))
    offer_type, offer = reply_for(discover, config) or (0, b"")
    assert offer_type == DHCP_OFFER
    assert len(offer) >= 300
    assert offer[16:20] == client.packed
    offer_options = parse_options(offer[MIN_DHCP_BYTES:])
    assert offer_options[OPT_MESSAGE_TYPE] == bytes((DHCP_OFFER,))
    assert offer_options[OPT_SERVER_ID] == server.packed
    assert OPT_SUBNET_MASK in offer_options
    assert 3 not in offer_options and 6 not in offer_options

    selecting = parse_request(
        request_packet(DHCP_REQUEST, mac, requested_ip=client, server_id=server)
    )
    ack_type, ack = reply_for(selecting, config) or (0, b"")
    assert ack_type == DHCP_ACK
    assert parse_options(ack[MIN_DHCP_BYTES:])[OPT_MESSAGE_TYPE] == bytes((DHCP_ACK,))
    assert reply_for(parse_request(request_packet(DHCP_REQUEST, mac)), config) is None
    assert (
        reply_for(
            parse_request(request_packet(DHCP_REQUEST, mac, server_id=server, ciaddr=client)),
            config,
        )
        is None
    )
    init_reboot = parse_request(request_packet(DHCP_REQUEST, mac, requested_ip=client))
    assert (reply_for(init_reboot, config) or (0, b""))[0] == DHCP_ACK
    renewal = parse_request(request_packet(DHCP_REQUEST, mac, ciaddr=client))
    assert (reply_for(renewal, config) or (0, b""))[0] == DHCP_ACK
    wrong_mac = bytes.fromhex("020000000002")
    assert reply_for(parse_request(request_packet(DHCP_DISCOVER, wrong_mac)), config) is None
    wrong_server = ipaddress.IPv4Address("169.254.184.73")
    assert (
        reply_for(
            parse_request(
                request_packet(DHCP_REQUEST, mac, requested_ip=client, server_id=wrong_server)
            ),
            config,
        )
        is None
    )
    try:
        parse_request(request_packet(DHCP_DISCOVER, mac)[: BOOTP.size] + b"bad!")
    except DhcpError:
        pass
    else:
        raise AssertionError("invalid DHCP cookie was accepted")
    print("milkv-dhcp-test selftest: ok")


def bind_socket(interface: str, server_port: int) -> socket.socket:
    ifindex = socket.if_nametoindex(interface)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    if sys.platform == "darwin":
        sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF_DARWIN, ifindex)
    elif sys.platform.startswith("linux"):
        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE_LINUX, interface.encode() + b"\x00")
    else:
        sock.close()
        raise RuntimeError("interface-bound DHCP is supported only on Darwin and Linux")
    sock.bind(("", server_port))
    sock.settimeout(1.0)
    return sock


def serve(arguments: argparse.Namespace) -> int:
    server_ip = ipaddress.IPv4Address(arguments.server_ip)
    client_ip = ipaddress.IPv4Address(arguments.client_ip)
    if any(
        address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_reserved
        for address in (server_ip, client_ip)
    ):
        raise DhcpError("server and client must be non-loopback unicast IPv4 addresses")
    network = ipaddress.IPv4Network(f"{server_ip}/{arguments.prefix_len}", strict=False)
    if server_ip in (network.network_address, network.broadcast_address):
        raise DhcpError("server IP must be a usable address in its subnet")
    if client_ip not in network or client_ip in (network.network_address, network.broadcast_address):
        raise DhcpError("client IP must be a usable address in the server subnet")
    if client_ip == server_ip:
        raise DhcpError("server and client IP addresses must differ")
    config = Config(server_ip, client_ip, arguments.client_mac, network, arguments.lease_seconds)

    stop = False

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    sock = bind_socket(arguments.interface, arguments.server_port)
    print(
        f"milkv-dhcp-test: {arguments.interface} {server_ip}/{arguments.prefix_len} "
        f"offers {client_ip} only to {arguments.client_mac.hex(':')}",
        flush=True,
    )
    try:
        while not stop:
            try:
                packet, _peer = sock.recvfrom(2048)
            except socket.timeout:
                continue
            try:
                request = parse_request(packet)
                reply = reply_for(request, config)
            except DhcpError:
                continue
            if reply is None:
                continue
            message_type, encoded = reply
            sock.sendto(encoded, ("255.255.255.255", arguments.client_port))
            label = "OFFER" if message_type == DHCP_OFFER else "ACK"
            print(
                f"milkv-dhcp-test: sent {label} xid=0x{request.xid:08x} "
                f"to {config.client_mac.hex(':')} for {config.client_ip}",
                flush=True,
            )
    finally:
        sock.close()
    print("milkv-dhcp-test: stopped", flush=True)
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--interface", default="en7")
    result.add_argument("--server-ip", default="169.254.184.74")
    result.add_argument("--client-ip", default="169.254.184.75")
    result.add_argument("--client-mac", type=parse_mac, default=parse_mac("02:00:00:00:00:01"))
    result.add_argument("--prefix-len", type=int, default=16, choices=range(8, 31))
    result.add_argument("--lease-seconds", type=int, default=3600)
    result.add_argument("--server-port", type=int, default=67)
    result.add_argument("--client-port", type=int, default=68)
    result.add_argument("--selftest", action="store_true")
    return result


def main() -> int:
    arguments = parser().parse_args()
    if arguments.selftest:
        selftest()
        return 0
    if not 60 <= arguments.lease_seconds <= 86_400:
        parser().error("--lease-seconds must be in 60..86400")
    if not 1 <= arguments.server_port <= 65535 or not 1 <= arguments.client_port <= 65535:
        parser().error("DHCP ports must be in 1..65535")
    try:
        return serve(arguments)
    except (DhcpError, OSError, RuntimeError) as error:
        print(f"FAIL milkv-dhcp-test: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
