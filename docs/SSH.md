# Capability-native SSH plan

This document defines the staged path from VibeOS's raw Ethernet transport to a
minimal SSH server. Completed transport/security-foundation gates are called
out explicitly; no section claims the SSH wire protocol before N4 passes.

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
  <-> bounded Endpoint<StampedPacket>
net-stack component
  <-> bounded TcpListener/TcpConnection resources
sshd component
  <-> authenticated principal policy
restricted vsh session component
```

The network stack is the sole normal consumer of raw inbound packets.  The
implemented driver boundary carries each `Packet` inside a `StampedPacket`
bound to one boot-local `(device epoch, stack generation)` pair.  The planned
`TcpListener` and `TcpConnection` resources shown above do not exist yet; the
N1 acceptance component owns one smoltcp socket directly.  The stack owns no
shell, store, key, or console authority.  The future SSH server owns only its
TCP listener, an entropy capability, a host signing capability, the read-only
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
the byte-stream transport only; its fixed TCP seed is explicitly
non-cryptographic and the image is not an SSH server.

### N2: packet-session generations and live recovery

The implementation now gives every driver/stack session an exact
`PacketStamp` containing a non-zero device epoch and stack generation. Device
attach advances the epoch, stack bind advances the generation, and checked
counter exhaustion fails closed. A bind first makes the fence inactive and
cannot succeed while previously admitted transmit descriptors remain in
flight. The drivers serialize binding with ingress publication and with exact
stamp validation plus egress DMA publication. The smoltcp adapter independently
rejects mismatched ingress. These coordinates are restart identities, not
random values, cryptographic authenticators, or identities that survive boot.

Fault recovery unbinds a session only when the faulted allocation domain owns
that binding. The `tcp-echo` supervisor may then restart a faulted stack and let
the replacement bind a fresh generation; cancellation and normal exit remain
operator decisions. The N2 QEMU gate is:

```sh
./scripts/qemu-tcp-test.sh recovery
```

That one gate is designed to exercise two live-stream transitions in order:

1. Fault the TCP-stack component. The device epoch must stay equal and the
   stack generation must advance. The retired stream must not echo after the
   transition, a fresh stream must exchange exact bytes, and old-coordinate
   ingress and egress packets must increment their separate rejection counts.
2. Fault the virtio-net driver. Both the device epoch and stack generation must
   advance after driver and stack recovery. The same retired-stream,
   fresh-stream, and coordinate-specific stale-ingress/stale-egress assertions
   apply to the second retired pair.

This paragraph defines the acceptance gate; it does not claim that a particular
run passed. The deterministic stale-packet and fault controls are compiled only
by `tcp-echo-recovery-test`. They add the ambient `tcp-fault`, `tcp-release`,
`tcp-session`, and `tcp-device-fault` controls to that test image; normal
`tcp-echo`, default, and future SSH images do not contain them. The staged
packets exercise the two typed-endpoint rejection paths, not a real delayed DMA
completion or a late IRQ. The gate is QEMU/virtio-only. The analogous native
DWMAC fence exists in source but has not been exercised by this TCP image or
validated on Milk-V Duo hardware. N2 is therefore not a production-readiness,
exhaustive cross-hart-interleaving, or physical-device claim.

### N3: entropy and identity

The QEMU security foundation is now implemented:

- A modern virtio-rng driver exposes only a bounded, fallible `RandomSource`
  capability. Its fixed SYSTEM DMA slab never contains a client pointer;
  short completions accumulate to an exact result, and malformed completion,
  timeout, reset, cancellation, attach-fault, and restart paths either confirm
  device reset before reuse or permanently quarantine the slab.
- Portable consumers use a pinned RustCrypto ChaCha20 RNG with independent
  non-zero stream domains, request/reseed ceilings, repeated-seed detection,
  terminal fail-closed state, and zeroizing Drop. Raw fault recovery scrubs
  complete tracked-arena blocks before they enter the allocator free list.
- The host seed remains inside an opaque Ed25519 signer. Public-key READ and
  fixed 32-byte exchange-hash INVOKE are separate capabilities. Authorized
  client keys are exact validated 32-byte values mapped through an immutable,
  bounded capability-profile table.
- The `ssh-security-test` feature is QEMU-only and visibly embeds fixed host and
  client fixtures. Its component receives only random READ, signer READ or
  signer INVOKE through separate handles, and policy READ. The two-boot gate is:

```sh
./scripts/qemu-ssh-security-test.sh
```

The gate requires a stable test host key and a different signed virtio-rng
transport-sample marker on each boot. This is wiring/freshness evidence, not a
statistical proof of entropy quality or a secure deployment.

Before any production SSH image is treated as secure, the remaining platform
provisioning work is:

- Use a documented and validated Milk-V Duo hardware source or leave SSH
  disabled on that platform. Compiling a vendor RNG API or driver is not
  hardware validation.
- Provision one unique Ed25519 host identity per device, keep its public
  fingerprint stable across reboot, and leave the private seed behind a signer
  service. The SSH component receives invocation authority, not readable key
  bytes. A fixed test host key must never enter a production image.
- Store authorized public keys as exact binary keys mapped to immutable
  capability profiles; do not parse an ambient `authorized_keys` pathname.
- Define a fixed persistent `ssh-policy` graph and its update/revocation flow.
  The current CRC-protected journal detects accidental corruption but does not
  provide private-key confidentiality, malicious-media authentication, or
  rollback resistance.

### N4: minimal SSH exec

- Pin and audit a `no_std` SSH implementation before admitting it to the trusted
  build.
- Reject every algorithm and channel/request type outside the target profile.
- Apply banner, KEX, authentication, idle, and rekey deadlines.
- Execute one foreground command through `vsh::Session::execute_cancellable`,
  stream bounded stdout/stderr, return `exit-status`, and propagate disconnect
  as cancellation.
- On teardown: cancel work, join tasks, revoke the session CSpace, release TCP
  buffers, and remove the component allocation owner.

### N5: hostile-input evidence

- Host tests and fuzz targets cover packet/string/name-list lengths, malformed
  key exchange, authentication failures, channel windows, and disconnect races.
- QEMU uses a real OpenSSH client and tests the authorized key, a rejected key,
  stable host fingerprint, strict KEX, timeout, reset, and resource exhaustion.
- Live connection, authentication-attempt, Job, stage, packet, channel, and
  memory limits are enforced in code rather than existing only in manifests or
  prose.
- CPU-heavy cryptographic work has a bounded cooperative-work policy so a
  single connection cannot starve network polling on the one-hart Duo target.

### N6: interactive terminal and hardware

- Add per-session terminal input, output, history, Ctrl-C/EOF, window changes,
  and channel backpressure.  Do not reuse the singleton UART TTY.
- Fix and stress the native DWMAC queue/backpressure path, then complete raw-L2,
  TCP, and SSH acceptance on a physical Milk-V Duo Ethernet IO Board.

SFTP/SCP remains out of scope until VibeOS has a capability-native file or
directory service whose semantics can be exposed without inventing a POSIX path
namespace inside the SSH component.
