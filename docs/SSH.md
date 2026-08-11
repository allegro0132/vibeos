# Capability-native SSH plan

This document defines the staged path from VibeOS's raw Ethernet transport to a
minimal SSH server. Completed transport/security-foundation gates are called
out explicitly; no section claims the SSH wire protocol before N4 passes.

## Target

The current acceptance target is deliberately smaller than a Unix `sshd`:

- QEMU `virt`, static IPv4, one TCP listener and one concurrent connection;
- public-key authentication only;
- `curve25519-sha256`, `ssh-ed25519`, and
  `chacha20-poly1305@openssh.com`, with strict key exchange required;
- one SSH `session` channel carrying either a no-PTY `exec` request or a
  PTY-backed interactive shell;
- command execution through a separately constructed, profile-specific
  `vsh::Session`, with a fresh capability space and terminal frontend for every
  interactive connection;
- no password authentication, SFTP/SCP, forwarding, agent/X11 requests,
  environment mutation, or compression. Shell without PTY and exec with PTY
  are rejected.

The interactive path now uses per-connection line discipline and
channel-backed output rather than the global UART TTY. QEMU validates this
securely wired test boundary. A separate, visibly insecure Milk-V image now
makes the same protocol path available for physical bring-up, but remote login
to the board has not yet been completed or validated.

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
bound to one boot-local `(device epoch, stack generation)` pair. The planned
general `TcpListener` and `TcpConnection` resources shown above do not exist
yet; the N1 and N4 acceptance components each own one smoltcp socket directly.
The stack owns no shell, store, key, or console authority. The acceptance SSH
component owns only its network grants, entropy capability, separate host-key
read/sign grants, read-only authentication policy, and a fresh restricted VSH
session with the appropriate exec or interactive profile per connection. A
username is a display label; possession and
validation of an authorized public key select the capability profile.

The acceptance boundary keeps the host private key behind a signer service:
the SSH component receives separate public-key `READ` and signing `INVOKE`
grants and never obtains the key bytes. Its provisioned deterministic key is a
public test fixture, not a secure deployment. Production still requires a
unique device identity and authenticated provisioning.

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
  hardware validation. The isolated upstream Jitterentropy port and its
  required physical runtime/restart gate are documented in
  [JITTERENTROPY.md](JITTERENTROPY.md); it is not yet admitted here.
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

### N4: minimal SSH exec and interactive VSH

The QEMU-only `ssh-test` image is the executable acceptance boundary for this
milestone. It is intentionally separate from normal images and from N3's
self-terminating security test. The server admits only the algorithm and
session profiles in the Target section. A no-PTY `exec` executes one bounded
foreground command through `vsh::Session::execute_ssh_cancellable`. A PTY plus
`shell` request creates a fresh interactive `vsh::Session`, capability space,
and terminal frontend with prompt editing, backspace, Ctrl-C, Ctrl-D,
connection-local typeahead, and bounded channel backpressure. Both paths return
an `exit-status`; shell without PTY, exec with PTY, environment, subsystem, and
additional-channel requests are rejected. Disconnect tears down and joins the
per-connection command/session state; a component fault is handled by the
ordinary generation supervisor and capability-space reset path.

The end-to-end gate is:

```sh
./scripts/qemu-ssh-test.sh
```

It requires `qemu-system-riscv64`, Python 3, `rustup`, and the OpenSSH `ssh`
and `ssh-keygen` programs. By default it selects a free `127.0.0.1` port and
forwards it to `10.0.2.15:2222`; an explicit
`SSH_HOST_PORT` override remains available while the guest port stays fixed.
QEMU user networking uses `restrict=on`, disables
IPv6, and attaches a modern `/dev/urandom`-backed virtio-rng device. Every
process has a bounded timeout, and the exit trap terminates and joins both QEMU
and its timeout guard before removing the mode-0600 key files.

`scripts/openssh-test-key.py --fixture accepted` and `--fixture rejected`
produce deterministic, unencrypted OpenSSH Ed25519 client keys matching the
binary QEMU policy. They are deliberately public test identities. The host
peer starts with `-F /dev/null`, pins the exact expected test host key, disables
password and keyboard-interactive fallbacks, and forces:

- KEX: `curve25519-sha256` with OpenSSH strict ordering;
- host and client key type: `ssh-ed25519`;
- cipher: `chacha20-poly1305@openssh.com` in both directions.

Readiness requires a successful, authenticated `true` through this strict
profile; the verbose OpenSSH transcript must contain the exact negotiated
algorithms and expected host fingerprint. The first boot must then return exact
output for `echo vibeos-ssh-acceptance`, status 0 for `true`, and status 1 for
`false`. A real forced-PTY OpenSSH shell sends editing, Ctrl-C, backspace,
command, and Ctrl-D bytes and must receive the exact prompt/echo/output stream;
the gate then executes another no-PTY `true` to prove listener rearm after the
clean shell exit. The rejected key must fail public-key auth; shell without
PTY, exec with PTY, and the `sftp` subsystem must each produce OpenSSH's
request-rejected diagnostic. A second complete boot must pass the same
authenticated readiness probe with the same exact host key, whose fixture
fingerprint is
`SHA256:Tpigy/2zLGErAlymNq6E6LHkGOIA5S1+gJsEi5VteN8`.

The guest log contract checked independently from OpenSSH is:

```text
ssh-test listening on 10.0.2.15:2222
ssh-test exec complete: status <n>
ssh-test shell complete: status <n>
FAIL ssh-test: <fatal reason>
```

`ssh-test connection reset: <reason>` is intentionally not a global failure:
rejected or hostile connections may reset one connection while the single
listener remains healthy.

#### Explicit Milk-V hardware bring-up gate

`milkv-ssh-acceptance` compiles the same bounded Sunset/session/VSH path for the
native DWMAC backend and DHCP. It is intentionally mutually exclusive with the
production `net-shell` image and every QEMU acceptance feature. Its component
still receives only packet SEND/RECV, network READ/INVOKE, random READ, separate
host-key READ/sign INVOKE, and immutable authorization-policy READ grants; init
does not receive the raw packet endpoints.

This image is deliberately cryptographically unsafe. It reuses the public test
host and client identities and substitutes a deterministic capability-scoped
random provider whose sequence repeats after reboot. The feature name, boot
warning, output directory, and documentation all preserve that distinction.
It may be used only on an isolated bring-up link with non-secret traffic, and a
successful run must never be cited as entropy, identity-provisioning, or
production-SSH evidence.

Build/package it and run the physical OpenSSH peer with:

```sh
./scripts/build-milkv-duo.sh --ssh-acceptance
./scripts/package-milkv-duo-sdk.sh --ssh-acceptance /path/to/duo-buildroot-sdk
./scripts/milkv-ssh-test.sh ADDRESS
```

The board waits for carrier and DHCP rather than exiting if the cable is late,
publishes `milkv-ssh-acceptance listening on ADDRESS:2222` over UART, rebinds
after recoverable device/link changes, and republishes lease changes. The host
gate reuses the same exact host fingerprint, forced algorithms, authorized and
rejected fixture keys, exec statuses, negative request policy, and real
interactive PTY/VSH sequence as the QEMU gate.

On 2026-08-11, a physical CV1800B Duo running the acceptance image built from
commit `be3d790` acquired `169.254.184.75` and passed 11 complete gates without
a reboot. One gate creates at least ten independent, non-multiplexed OpenSSH
connections, so the run covered at least 110 sessions, including 11 forced-PTY
VSH sessions, 11 rejected keys, and 33 denied invalid requests. The UART log
showed 44 status-0 exec completions, 11 intentional status-1 completions, 11
successful interactive shells, and no completion-drain timeout, DWMAC timeout,
panic, or driver fault. The pinned host fingerprint was
`SHA256:Tpigy/2zLGErAlymNq6E6LHkGOIA5S1+gJsEi5VteN8`. This is physical SSH/VSH
acceptance evidence for the explicitly insecure image only; it is not entropy,
identity-provisioning, or production-SSH evidence.

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

The OpenSSH gate above supplies the authorized/rejected-key, exact exec and
interactive-terminal output/status, request-denial, strict-algorithm, and
stable-host-key portion of N5. It does not by itself claim malformed transport
fuzzing, deadline/reset coverage, resource exhaustion, disconnect-race
coverage, or Milk-V hardware evidence; those remain separate acceptance work.

### N6: interactive terminal and hardware

The QEMU per-session terminal covers input, output, history, Ctrl-C/EOF,
window-change metadata, and channel backpressure without reusing the singleton
UART TTY. A physical Duo has passed carrier, DHCP, eight fresh exact-echo TCP
streams, and the explicit acceptance-image SSH/VSH run recorded above.
Driver-reset, delayed-DMA/late-IRQ stress, hardware entropy, and production
identity provisioning remain open. The explicit acceptance result must not be
reported as production SSH readiness.

SFTP/SCP remains out of scope until VibeOS has a capability-native file or
directory service whose semantics can be exposed without inventing a POSIX path
namespace inside the SSH component.
