# Supervised virtio-net contract

M4.4 adds one modern virtio-mmio network device as a supervised component and
connects it to bounded `Endpoint<Packet>` resources. This document fixes the
implementation and acceptance boundary. Both focused QEMU cases, their
independent host evidence, and the complete regression suite now pass.

## Protocol surface

The driver accepts only transport version 2 and network device ID 1. It uses a
split ring of eight descriptors for each of the two mandatory queues:

| Queue | Role | Descriptor direction |
|---:|---|---|
| 0 | receive | one device-writable contiguous buffer |
| 1 | transmit | one device-readable contiguous buffer |

Only `VIRTIO_F_VERSION_1` is acknowledged. Checksum and segmentation offload,
mergeable receive buffers, control queues, multiqueue/RSS, packed rings,
indirect descriptors, event indices, and device-provided MAC configuration are
not dependencies. A device may offer those bits; the driver leaves them clear.

Every DMA buffer is one contiguous 1,526-byte allocation: a 12-byte modern
`virtio_net_hdr` followed by at most 1,514 bytes of Ethernet frame without the
four-byte FCS. TX writes a zeroed no-offload header with `num_buffers = 0`.
Because mergeable receive buffers are not negotiated, RX accepts only
`flags = 0`, `gso_type = NONE`, and `num_buffers = 1`.

QEMU 11 retains the modern 12-byte prefix but its non-mergeable receive path
overwrites only the first 10 metadata bytes. Before publishing an RX
descriptor, the driver therefore clears the complete buffer and seeds the
architected single-buffer value (`num_buffers = 1`). QEMU may leave that value
untouched; the core model still observes exactly the canonical value, and the
unnegotiated mergeable-buffer feature plus one-descriptor layout prevents it
from authorizing a second buffer.

RX consumes only the prefix certified by `used.len`. Values below 12 leave the
header incompletely initialized; values above 1,526 exceed the descriptor. Both
are protocol faults. The frame length is `used.len - 12`. TX has no
device-writable descriptor, so its used length is reserved and ignored rather
than required to be zero.

## Typed packet boundary

`Packet` is an owned Ethernet frame of 1 through 1,514 bytes. It is not a byte
stream and it does not borrow the DMA slab. The driver copies a validated RX
prefix into a `Packet` before recycling that descriptor, then sends the value
through a bounded `Endpoint<Packet>`. TX similarly copies a packet into stable
DMA; client memory is never published to the device.

The endpoint capability carries direction in its rights: clients receive only
through `RECV` and transmit only through `SEND`. There is no fd, pathname,
ambient NIC lookup, or ioctl. M4.4 is raw Ethernet transport only; it does not
claim an ARP, IP, UDP, TCP, DNS, or POSIX-socket implementation.

The configurable ARP/IPv4/TCP consumer now lives in the independent
`components/netstack` `no_std` crate. Its protocol loop and `ip`/`dhclient`
control state can name only packet and network-control capabilities passed to
the component. `kernel/src/netstack_platform.rs` is the thin adapter which
resolves those handles against the component CSpace; direct driver fault and
stale-packet controls remain compiled only into the N2 recovery image. This is
a source/dependency boundary inside the shared S-mode image, not hardware
isolation from the kernel or driver.

## Queue lifecycle and DMA safety

RX and TX have independent wrapping `u16` available/used indices but share one
non-zero device epoch. Each exposed descriptor has an exact token containing
the epoch, queue direction, head, and non-wrapping serial. This prevents an old
completion or cancellation token from aliasing a recycled head after the ring
index wraps.

Used entries may complete active heads out of publication order. An out-of-range,
duplicate, or inactive head, an impossible used-index advance, or a malformed RX
header/length is a device-wide protocol fault. Local wrong or stale tokens are
rejected without stealing another active slot.

Timeout, cancellation after publication, `DEVICE_NEEDS_RESET`, or a component
fault quarantines every exposed RX and TX buffer until the whole device has been
reset. Status must read back as zero before either queue is cleared or any DMA is
reused. A successful reset advances the shared epoch and reinitializes both
queues. A failed bounded reset leaves the fixed SYSTEM DMA slab quarantined; it
does not pretend that reclaiming the driver arena stopped device access.

## Host acceptance protocol

The two QEMU cases use `-netdev socket` connected to an unprivileged Python peer
bound to an ephemeral `127.0.0.1` TCP port. Existing cases receive no NIC, so
their device discovery and goldens do not change. The socket stream carries each
raw frame behind QEMU's four-byte big-endian length prefix; no TAP interface,
root privilege, host routing, or Internet access is involved.

The deterministic test frames are exactly 60 bytes without FCS:

- guest MAC `02:00:00:00:00:01`;
- peer MAC `02:00:00:00:00:02`;
- EtherType `0x88B5` in network byte order;
- ASCII `VIBEOS-NET-HELLO-v1`, `VIBEOS-NET-CHALLENGE-v1`, or
  `VIBEOS-NET-ACK-v1` immediately after the Ethernet header, followed by zero
  padding.

The normal case requires exact `HELLO -> CHALLENGE -> ACK` bytes. The recovery
case first receives the HELLO exposed by the incarnation that faults after
QueueNotify and deliberately sends no response. It then requires a second exact
HELLO from the fresh epoch before completing `CHALLENGE -> ACK`. This prevents a
challenge from the abandoned session from satisfying the restarted session.

`scripts/net-peer.py` writes a canonical evidence file containing the complete
hexadecimal frames only after the sequence succeeds. The harness independently
re-reads that file with `--check-evidence`; a matching shell transcript cannot
hide a missing, reordered, truncated, or fabricated L2 exchange.

Run the focused evidence with:

```sh
python3 scripts/net-peer.py --selftest
./scripts/qemu-test.sh net
./scripts/qemu-test.sh net_recovery
```
