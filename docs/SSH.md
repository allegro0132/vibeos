# Capability-native SSH plan

This document defines the staged path from VibeOS's raw Ethernet transport to a
minimal SSH server.  It is an implementation plan, not a claim that SSH is
already available.

## Target

The first usable target is deliberately smaller than a Unix `sshd`:

- QEMU `virt`, static IPv4, one TCP listener and one concurrent connection;
- public-key authentication only;
- `curve25519-sha256`, `ssh-ed25519`, and
  `chacha20-poly1305@openssh.com`, with strict key exchange required;
- one SSH `session` channel carrying an `exec` request;
- command execution through a separately constructed, least-authority
  `vsh::Session`;
- no password authentication, PTY, interactive shell, SFTP/SCP, forwarding,
  agent/X11 requests, environment mutation, or compression.

An interactive terminal is a later stage.  It must use per-connection line
discipline and channel-backed output rather than the global UART TTY.

## Component and authority topology

```text
NIC driver
  <-> bounded Endpoint<Packet>
net-stack component
  <-> bounded TcpListener/TcpConnection resources
sshd component
  <-> authenticated principal policy
restricted vsh session component
```

The network stack is the sole normal consumer of raw inbound packets.  It owns
no shell, store, key, or console authority.  The SSH server owns only its TCP
listener, an entropy capability, a host signing capability, the read-only
authentication policy, and authority to ask the session factory for one of the
predeclared command profiles.  A username is a display label; possession and
validation of an authorized public key select the capability profile.

The host private key should eventually remain behind a signer service: the SSH
component receives `INVOKE`, not `READ`, and never obtains the key bytes.  A
test-only QEMU image may use provisioned deterministic keys, but that image is
not a secure deployment.

## Milestones and acceptance gates

### N1: IPv4/TCP proof

- Adapt the existing owned Ethernet `Packet` endpoints to `smoltcp`.
- Use a fixed QEMU MAC and `10.0.2.15/24`; listen on TCP port 2222.
- Support ARP, IPv4, and a bounded TCP byte stream.  DHCP, DNS, IPv6, and IP
  fragmentation are out of scope.
- Run QEMU with user networking and localhost-only host forwarding.  A host
  client must exchange exact bytes with the guest TCP echo service.
- On a network-device epoch change, drain stale packets and abort every TCP
  connection before accepting traffic from the new epoch.

The N1 echo service is behind the `tcp-echo` kernel feature.  Normal images and
the existing raw-L2 acceptance cases do not enable it.

The base N1 transport is now implemented as a capability-revocable, bounded
`smoltcp` adapter and a QEMU-only `tcp-echo` component. Its host tests cover ARP
plus a 3,000-byte TCP exchange, endpoint backpressure, monotonic time, and
revocation. The end-to-end byte-stream gate is:

```sh
./scripts/qemu-tcp-test.sh
```

That command builds the dedicated image, binds an ephemeral localhost port,
forwards it to `10.0.2.15:2222`, and requires an exact binary echo. This proves
the byte-stream transport only; its TCP seed is explicitly non-cryptographic
and the image is not an SSH server.

One N1 hardening gate remains before the transport can be called SSH-ready:
packets must carry both the network-device epoch and stack generation end to
end, the driver must reject stale egress, and QEMU must exercise driver and
stack faults during a live TCP stream. The current component observes device
epoch changes, drains queued ingress, and rebuilds all TCP state, but that
snapshot is not an atomic cross-hart barrier. A stack fault is therefore
reclaimed but deliberately left terminal instead of automatically mixing a
new stack generation with queued old egress.

### N2: entropy and identity

- Add a bounded `RandomSource` capability.  QEMU uses virtio-rng; the Milk-V
  Duo backend must use a documented and validated hardware source or fail
  closed.
- Provision one unique Ed25519 host identity per device and keep its public
  fingerprint stable across reboot.
- Store authorized public keys as exact binary keys mapped to immutable
  capability profiles; do not parse an ambient `authorized_keys` pathname.
- Define a fixed persistent `ssh-policy` graph and its update/revocation flow.
  The current CRC-protected journal alone is not protection against malicious
  media replacement or rollback.

### N3: minimal SSH exec

- Pin and audit a `no_std` SSH implementation before admitting it to the trusted
  build.
- Reject every algorithm and channel/request type outside the target profile.
- Apply banner, KEX, authentication, idle, and rekey deadlines.
- Execute one foreground command through `vsh::Session::execute_cancellable`,
  stream bounded stdout/stderr, return `exit-status`, and propagate disconnect
  as cancellation.
- On teardown: cancel work, join tasks, revoke the session CSpace, release TCP
  buffers, and remove the component allocation owner.

### N4: hostile-input evidence

- Host tests and fuzz targets cover packet/string/name-list lengths, malformed
  key exchange, authentication failures, channel windows, and disconnect races.
- QEMU uses a real OpenSSH client and tests the authorized key, a rejected key,
  stable host fingerprint, strict KEX, timeout, reset, and resource exhaustion.
- Live connection, authentication-attempt, Job, stage, packet, channel, and
  memory limits are enforced in code rather than existing only in manifests or
  prose.
- CPU-heavy cryptographic work has a bounded cooperative-work policy so a
  single connection cannot starve network polling on the one-hart Duo target.

### N5: interactive terminal and hardware

- Add per-session terminal input, output, history, Ctrl-C/EOF, window changes,
  and channel backpressure.  Do not reuse the singleton UART TTY.
- Fix and stress the native DWMAC queue/backpressure path, then complete raw-L2,
  TCP, and SSH acceptance on a physical Milk-V Duo Ethernet IO Board.

SFTP/SCP remains out of scope until VibeOS has a capability-native file or
directory service whose semantics can be exposed without inventing a POSIX path
namespace inside the SSH component.
