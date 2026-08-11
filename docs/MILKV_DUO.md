# Milk-V Duo (CV1800B)

VibeOS provides **single-core board support for the Milk-V Duo C906B**. Current
support includes a fixed memory layout, Sv39 mappings, UART0, the PLIC, a 25 MHz
timebase, native microSD/DWMAC backends, and a FIT/SD image packaging flow based
on the official Buildroot SDK.

The separate `--jitterentropy-probe` image loads the exactly pinned
`jitterentropy-rs` 0.1.1 crate against `rdtime` and exposes conditioned smoke
testing on UART. The crate currently exposes no raw-noise qualification API.
The rewrite is not a certified or behaviorally equivalent replacement for
upstream Jitterentropy. It is a qualification artifact, not a production
entropy source. See
[JITTERENTROPY.md](JITTERENTROPY.md) before making any SSH security claim.

> **Base-port and explicit SSH/VSH hardware validation status (2026-08-11):
> passed within the documented boundaries.** A CV1800B board booted
> successfully and entered the interactive shell. Sv39, the 25 MHz timer,
> UART0/PLIC IRQ 44, and component scheduling all worked correctly, and the
> earlier hardware `selftest` reported `388 passed, 0 failed`. The native
> Ethernet IO Board path acquired DHCP and passed eight fresh physical TCP
> streams. The deliberately insecure SSH acceptance image subsequently passed
> 11 complete OpenSSH/VSH gates, representing at least 110 independent SSH
> sessions. Native microSD data I/O in the new two-partition image remains
> unchecked below. The C906L and dual-core SMP are not supported.

The DWMAC software path gives its normal RX and TX descriptors separate 64-byte
non-coherent cache lines and observes device-written state with the C906
invalidate operation rather than clean-plus-invalidate, preventing stale CPU
`OWN` state from overwriting a DMA completion. It also retains a dequeued packet
while its sole TX descriptor is busy, faults after a bounded two-second stall,
revalidates all device capabilities around each synchronous hardware turn, and
resets MAC/DMA on normal teardown. The physical DHCP/TCP and SSH baselines below
exercise ordinary bidirectional traffic through that path. They do not yet
cover driver restart coordinates, deliberately delayed DMA completion, late
IRQs, or long-duration link stress.

The production image enables the `net-shell` feature. Its supervised IPv4 stack
exclusively owns the DWMAC packet endpoints, starts DHCPv4 automatically, and
admits `ip`/`dhclient` only through vsh command capabilities. The DWMAC source
uses the same boot-local device-epoch/stack-generation packet fence as
virtio-net. These are source-level implementation facts, not a Milk-V hardware
result. The N2 `qemu-tcp-test.sh recovery` gate still exercises only the virtio
backend; it neither validates DWMAC restart coordinates nor injects a real
delayed descriptor completion or late Ethernet IRQ on the board.

## CPU model and support boundaries

The official SDK does not expose the two cores as symmetric OpenSBI harts:

- The C906B (hart 0) is the application core that OpenSBI exposes to the main
  system. It is the only core currently used by VibeOS.
- The FSBL releases the C906L separately, and the stock SDK runs FreeRTOS on it
  by default. It is the RTOS core in an AMP/mailbox communication model, not a
  regular SMP hart that can be started through SBI HSM.
- VibeOS neither probes nor starts the C906L and does not claim dual-core SMP
  support. Future support for this core should introduce an explicit
  AMP/mailbox design rather than adding it to the existing HSM hart list.

Milk-V's [official RTOS core documentation](https://milkv.io/docs/duo/getting-started/rtoscore)
likewise describes the two cores as a main-system "big core" and a FreeRTOS
"small core" communicating through a mailbox.

## Board parameters

All address ranges below are physical addresses and use an exclusive upper
bound.

| Item | Milk-V Duo configuration |
|---|---|
| Main core | C906B, hart 0, single core |
| VibeOS RAM | `0x8020_0000..0x83e0_0000` (60 MiB) |
| Start of FreeRTOS reserved region | `0x83f4_0000` |
| UART0 | `0x0414_0000`, IRQ 44 |
| UART registers | shift 2, 32-bit MMIO (width 4) |
| UART clock and baud rate | 25 MHz, 115200 baud |
| PLIC | `0x7000_0000`, hart 0 S-mode context 1 |
| RISC-V timebase | 25 MHz |
| virtio-mmio | 0 slots; native SDIO0 and DWMAC backends are selected instead |
| microSD / SDIO0 | `0x0431_0000`, IRQ 36; 1-bit 25 MHz PIO baseline |
| Ethernet / DWMAC | `0x0407_0000`, IRQ 31; RMII, Ethernet IO Board |
| Blue status LED | active-high GPIOC24; `drivers/milkv-duo-led` configures and verifies it after enabling Sv39 |

The Duo USB & Ethernet IO Board V1.11 does not route the RJ45 LED terminals to
the SoC: `J11` pins 11 through 14 are explicitly left unconnected in the
official schematic. VibeOS still selects the integrated EPHY link/speed LED
functions internally, but software cannot light the jack LEDs on this board
revision. The blue GPIOC24 LED is therefore the board-level boot indicator.
See the
[official IO Board V1.11 schematic](https://github.com/milkv-duo/accessories/blob/master/Duo_USB%26Ethernet_IOB/duo_iob_v1.11.pdf)
and the
[official Duo product brief](https://github.com/milkv-duo/duo-files/blob/main/duo/hardware/duo-datasheet-v1.2.pdf).

UART0 and the PLIC occupy Sv39 root VPN2 entries 0 and 1, respectively, so they
must use separate level-1 device page tables. The C906 also requires T-Head
C9xx extended PTE memory attributes: normal RAM uses `SHARE|BUFFER|CACHE`, while
MMIO uses `SHARE|STRONG_ORDER`. The QEMU platform does not set these reserved
high bits.

UART0 is a DesignWare APB UART, not an entirely unextended 16550. After taking
over from U-Boot, the kernel must wait for `LSR.TEMT` before rewriting the LCR
and must clear interrupts according to their IIR reason. Busy Detect `0x07` is
cleared by reading the USR (logical register `0x1f`), while an RX timeout `0x0c`
with an empty FIFO is cleared by one dummy RBR read. Otherwise, level-high IRQ
44 continuously retriggers in the PLIC claim/complete loop, causing the shell
never to be scheduled after it prints `sched`.

VibeOS deliberately stops at `0x83e0_0000` and does not occupy the FreeRTOS
region beginning at `0x83f4_0000`. Do not move the linker's upper bound directly
to the end of the 64 MiB DRAM merely to enlarge the heap.

The stock board memory map also declares an approximately 26.8 MiB ION region
for Linux multimedia drivers, but `FREERTOS_RESERVED_ION_SIZE` is 0 in this
configuration. VibeOS does not run those Linux drivers, so the current port uses
the ION region as normal RAM. If custom C906L firmware accesses ION, `RAM_END`
must be reduced accordingly; otherwise, cross-core memory corruption will
occur.

The upstream sources for these hardware parameters can be cross-checked here:

- [Official duo-buildroot-sdk](https://github.com/milkv-duo/duo-buildroot-sdk)
- [CPU, PLIC, and CLINT DTS](https://github.com/milkv-duo/duo-buildroot-sdk/blob/23eb84fecb29585dbb5728d6b7e2475ff273baac/build/boards/default/dts/cv180x_riscv/cv180x_base_riscv.dtsi#L30-L85)
- [UART0 DTS](https://github.com/milkv-duo/duo-buildroot-sdk/blob/23eb84fecb29585dbb5728d6b7e2475ff273baac/build/boards/default/dts/cv180x/cv180x_base.dtsi#L251-L258)
- [CV1800B Milk-V Duo memory layout](https://github.com/milkv-duo/duo-buildroot-sdk/blob/23eb84fecb29585dbb5728d6b7e2475ff273baac/build/boards/cv180x/cv1800b_milkv_duo_sd/memmap.py#L12-L80)

## Building and packaging

[`scripts/build-milkv-duo.sh`](../scripts/build-milkv-duo.sh) builds VibeOS.
[`scripts/package-milkv-duo-sdk.sh`](../scripts/package-milkv-duo-sdk.sh)
generates the FIT and packages the full-card image in the SDK's Linux/amd64
environment. Packaging reuses the FIP, Linux runtime DTB, `mkimage`, `dumpimage`,
and `genimage` produced by the SDK. You must therefore complete one full stock
SDK build first. The final image itself does not contain a Linux kernel or
rootfs.

The official SDK supports Ubuntu 22.04 amd64. On macOS/Apple Silicon, the
official amd64 Docker image can build it through architecture translation, but
this host combination is not officially supported upstream. The Docker commands
below specify the platform explicitly to avoid silently using the wrong
architecture.

Replace `/path/to/duo-buildroot-sdk` in the examples below with the actual
absolute path to the SDK. The validated flashable image was built with SDK commit
`23eb84fecb29585dbb5728d6b7e2475ff273baac` and official container digest
`sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679`.
Both `develop` and `latest` are mutable references. Use the commit and digest
above to pin the source and tool inputs. FIT and FAT tooling can record build
timestamps, so this flow does not claim byte-for-byte reproducible output;
record the final image checksum when distributing an artifact.

### 1. Build the stock SDK first

Run the following directly on a native Ubuntu 22.04 amd64 host:

```sh
cd /path/to/duo-buildroot-sdk
./build.sh milkv-duo-sd
```

On macOS/Apple Silicon, keep the source tree on a case-sensitive Linux file
system. Do not build the Linux sources directly from a default,
case-insensitive APFS working tree. When the SDK resides on a case-sensitive
volume, use:

```sh
SDK=/absolute/path/to/duo-buildroot-sdk
DUO_IMAGE=milkvtech/milkv-duo@sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679
docker pull --platform linux/amd64 "$DUO_IMAGE"
docker run --rm --platform linux/amd64 \
  -v "$SDK:/home/work" \
  "$DUO_IMAGE" \
  /bin/bash -lc 'cd /home/work && ./build.sh milkv-duo-sd'
```

`milkv-duo-sd` is the CV1800B SD target registered on the current `develop`
branch. Some `milkv-duo` examples in the upstream README are outdated. If a
different revision does not recognize this target name, consult its `device/`
directory and the target list printed by `./build.sh` with no arguments.

### 2. Native Ubuntu amd64: build and package

In the same Ubuntu amd64 environment as the SDK host tools, build the bare
kernel first and then run the packaging script with complete error checking:

```sh
SDK=/absolute/path/to/duo-buildroot-sdk
VIBEOS=/absolute/path/to/vibeos
cd "$VIBEOS"
./scripts/build-milkv-duo.sh "$SDK"
./scripts/package-milkv-duo-sdk.sh "$SDK"
```

The packaging script combines the stock FIP and VibeOS FIT in an isolated
temporary directory, invokes the SDK's `genimage` directly, and verifies the
partition table, FAT file system, FIP, and FIT payload before publishing. It
does not modify the SDK working tree or call the SDK's `pack_sd_image`, whose
layout is hard-coded for two partitions. The final full-card image is
`target/milkv-duo/vibeos-milkv-duo-sd.img`.

### 3. Docker/macOS: build the kernel on the host, package in a container

First generate the bare kernel from the VibeOS repository root, without an SDK
argument:

```sh
cd /path/to/vibeos
./scripts/build-milkv-duo.sh
```

Then mount both the SDK and VibeOS into the official container. The SDK may be
mounted read-only during packaging. The container script generates and checks
the FIT, runs `genimage` in isolated staging, and publishes the new image to
VibeOS's `target/` only after the partition table and all payloads pass
validation:

```sh
SDK=/absolute/path/to/duo-buildroot-sdk
VIBEOS=/absolute/path/to/vibeos
DUO_IMAGE=milkvtech/milkv-duo@sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679
docker run --rm --platform linux/amd64 \
  -v "$SDK:/home/work:ro" \
  -v "$VIBEOS:/home/vibeos" \
  "$DUO_IMAGE" \
  /home/vibeos/scripts/package-milkv-duo-sdk.sh /home/work
```

The final flashable image is `target/milkv-duo/vibeos-milkv-duo-sd.img`.

On first boot with the Ethernet IO Board connected, the production image starts
DHCP automatically. The bounded operator surface is:

```text
ip link show
ip -4 addr show dev net0
ip addr replace 192.168.1.20/24 dev net0
ip route replace default via 192.168.1.1 dev net0
dhclient net0
dhclient -r net0
```

`eth0` is accepted as an alias for `net0`. `dhclient -r` stops the client and
clears the local IPv4 configuration; smoltcp does not currently emit a DHCP
RELEASE packet.

### Explicit SSH/VSH hardware acceptance image (insecure)

The physical remote-login gate uses a deliberately separate
`milkv-ssh-acceptance` image. It proves DWMAC, DHCP, the SSH wire protocol, and
interactive per-session VSH on the board, but it is **not a secure deployment**:
the image embeds public fixed host/client identities and a deterministic random
provider whose sequence repeats after every reboot. Never expose it to an
untrusted network, send secrets through it, or distribute it as a production
image. The normal `milkv-duo,net-shell` image remains SSH-disabled until real
hardware entropy and per-device identity provisioning exist.

Build its bare kernel on the host:

```sh
./scripts/build-milkv-duo.sh --ssh-acceptance
```

Package it in the same validated SDK environment described above:

```sh
./scripts/package-milkv-duo-sdk.sh --ssh-acceptance /path/to/duo-buildroot-sdk
```

For the macOS/container flow, pass `--ssh-acceptance` before `/home/work` in
the existing `docker run` command. The final flashable artifact is:

```text
target/milkv-duo-ssh-acceptance/vibeos-milkv-duo-ssh-acceptance-sd.img
```

After boot, the serial console prints an unmistakable insecurity warning and
then publishes the current lease as:

```text
milkv-ssh-acceptance listening on A.B.C.D:2222
```

The service waits indefinitely for late carrier or DHCP, rebinds after a
carrier/device-generation change, and republishes the address when a lease is
lost or changed. From another machine on the same isolated link, run the exact
OpenSSH gate against the announced address:

If that isolated link has no DHCP server, the host can provide one ephemeral,
single-address lease without changing its persistent network configuration.
The following example assumes `en7` already owns `169.254.184.74/16` and serves
only VibeOS's fixed acceptance MAC:

```sh
python3 -B scripts/milkv-dhcp-test.py \
  --interface en7 \
  --server-ip 169.254.184.74 \
  --client-ip 169.254.184.75 \
  --client-mac 02:00:00:00:00:01
```

The helper binds the named interface, keeps no lease file, ignores every other
MAC, and advertises neither a router nor DNS. Stop it with Ctrl-C after the SSH
gate. On a network that already supplies DHCP, do not run a second server.

Then use the address printed by the board:

```sh
SSH_BIND_ADDRESS=169.254.184.74 \
  ./scripts/milkv-ssh-test.sh 169.254.184.75
```

`SSH_BIND_ADDRESS` prevents a multi-homed host from selecting an unrelated
source address for this direct link. Leave it unset on an ordinary LAN where
the host route already selects the intended interface address.

The script generates mode-0600 accepted and rejected fixture keys in a private
temporary directory, pins the exact public test host fingerprint and algorithm
suite, checks exec status and denial paths, and drives a real forced-PTY VSH
session including editing, Ctrl-C, backspace, Ctrl-D, and listener rearm. A
pass combined with the matching warning and address from that board boot is
physical remote-login evidence for this explicit test image only.

#### Physical SSH/VSH result (2026-08-11)

The acceptance artifact built from commit `be3d790` had SHA-256
`cfcf0f789ea460f1dcd362115103371eeccf69fba3e8d14ed75b76515e349837`.
U-Boot loaded its 693848-byte FIT and reported `Decompressing 672352 bytes` for
the kernel. The same UART boot then printed the explicit insecurity warning and
announced `milkv-ssh-acceptance listening on 169.254.184.75:2222` after the
interface-bound DHCP peer assigned the lease.

The physical host ran the complete gate 11 times without rebooting the board.
Each gate creates at least ten non-multiplexed OpenSSH processes: six valid
authenticated sessions, one rejected-key session, and three authenticated
sessions whose invalid request is denied. This supplied at least 110 independent
TCP/SSH sessions, including 11 real forced-PTY interactive VSH sessions. Every
gate pinned host fingerprint
`SHA256:Tpigy/2zLGErAlymNq6E6LHkGOIA5S1+gJsEi5VteN8`, forced the documented
algorithm suite, and printed its final PASS marker.

The matching UART log contained 44 successful status-0 exec completions, 11
intentional status-1 exec completions, and 11 status-0 interactive shell
completions. It contained no SSH completion-drain timeout, DWMAC TX timeout,
kernel panic, or driver fault. A concurrent packet capture reported 5503 packets
captured with zero kernel drops. This closes the explicit insecure
remote-login gate; it does not satisfy the hardware-entropy, unique-identity,
production SSH, driver-restart, or deliberately delayed-DMA requirements.

### Diagnostic image

Hardware acceptance uses a separate `legacy-shell` image. The production vsh
receives only the `ip` and `dhclient` command capabilities; it does not receive
raw packet, block, fault-injection, or self-test authority. The diagnostic image
instead retains the raw-L2 test surface and does not start the DHCP/IP stack.
Build the diagnostic kernel on the host with:

```sh
./scripts/build-milkv-duo.sh --diagnostic
```

Then package it in the same SDK environment used above:

```sh
./scripts/package-milkv-duo-sdk.sh --diagnostic /path/to/duo-buildroot-sdk
```

The flashable result is
`target/milkv-duo-diagnostic/vibeos-milkv-duo-diagnostic-sd.img`. It boots to
the `vibe>` diagnostic prompt. Enter `vsh` for an interactive
capability-native session and press Ctrl-C at an empty `vsh>` prompt to return;
`vsh <list>` continues to execute one command list without changing prompts.
The interactive diagnostic session installs the same standard host commands as
the production vsh (`help`, `ps`, `caps`, `mem`, `quiet`, `verbose`, and
`poweroff`) alongside the language applets and its private output capability.
Hardware diagnostics remain in the outer `vibe>` shell.

For the raw-L2 Ethernet test, connect the Ethernet IO Board directly to a host
interface or through one switch, then start the hardware peer before entering
`net test` on the serial console:

```sh
sudo python3 scripts/milkv-net-peer.py --interface en7
```

Replace `en7` with the actual host interface. The Milk-V acceptance image sends
its bounded HELLO and ACK frames to the Ethernet broadcast destination so an
ordinary host NIC can receive them, while the CHALLENGE still has the exact
fixed peer source and guest destination checked by VibeOS. The QEMU socket peer
and its unicast frame contract are unchanged.

The image contains a bootable, type `0x0c`, 128 MiB FAT partition followed by a
4 MiB type `0xda` raw VibeOS data partition. It has no Linux partition or ext4
rootfs. The native block backend translates the data partition's first LBA to
logical sector zero, so shell block tests and the persistent journal cannot
overwrite FAT, `fip.bin`, or `boot.sd`. You can use read-only mounts to validate
the MBR layout, payloads, FIT metadata, and CRC32 values:

```sh
DUO_IMAGE=milkvtech/milkv-duo@sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679
docker run --rm --platform linux/amd64 \
  -v "$SDK:/home/work:ro" \
  -v "$VIBEOS:/home/vibeos:ro" \
  "$DUO_IMAGE" \
  /home/vibeos/scripts/verify-milkv-duo-image.sh /home/work
```

Keep the following layers distinct:

- The SDK's `fip.bin` still provides the FSBL, OpenSBI, and U-Boot. It is not a
  Linux rootfs.
- `target/milkv-duo/boot.sd` is the FIT containing the VibeOS bare kernel and
  board DTB. It is not the full-card image.
- The packaging script only reads SDK artifacts. It does not replace the SDK's
  `rawimages/boot.sd` or generate `rootfs.ext4`.

Do not replace the FIP's `LOADER_2ND` directly with the VibeOS ELF or bare binary.
That path uses the SDK's private BL33 header and a different jump convention.
The supported path loads the VibeOS payload at `0x8020_0000` from the raw
`boot.sd` FIT through U-Boot.

Only the `*.img` file above is the final flashable image. Do not write the
intermediate `boot.sd` across the entire microSD card.

## Flashing and serial console

Flashing overwrites the target card. Back up its data and check the selected
device again before proceeding. This document does not execute any disk-writing
commands automatically. Follow Milk-V's
[official microSD flashing guide](https://milkv.io/docs/duo/getting-started/boot)
and use a tool such as balenaEtcher or Rufus to write the final `*.img` generated
by the packaging script. Do not use raw `dd` when the device identifier cannot
be confirmed.

Before powering on the board, connect a 3.3 V USB-to-TTL serial adapter with TX
and RX crossed and a shared ground. Do not connect 5 V to the UART signal pins.
Use these serial parameters:

```text
115200 baud, 8 data bits, no parity, 1 stop bit, no flow control
```

In short: **115200 8N1**.

### Physical IPv4/TCP gate

On the serial `vsh>` prompt, obtain the address assigned to the production
image and confirm that carrier is present:

```text
ip link show
ip -4 addr show dev net0
```

From another machine on the same link, pass that address to the bounded host
peer. The peer opens a fresh TCP stream for every round and requires the exact
binary payload back from port 2222:

```sh
python3 -B scripts/milkv-tcp-test.py ADDRESS
```

The address is intentionally not hard-coded: DHCP may assign a different one
after a reboot or on another network. On 2026-08-10, a physical Duo connected
through host interface `en7` reported `UP,LOWER_UP` and the dynamic address
`169.254.184.75/16`; eight consecutive fresh streams passed the exact-echo
gate. This is DWMAC/IPv4/TCP evidence only and does not claim SSH availability.

## Hardware validation checklist

For the first hardware boot, preserve the full serial log and verify each item:

- [x] `scripts/build-milkv-duo.sh` successfully generates the bare kernel. The
      native flow or `scripts/package-milkv-duo-sdk.sh` then successfully
      generates `target/milkv-duo/boot.sd`, with no FIT validation errors.
- [x] The final `*.img` contains a 128 MiB FAT boot partition and a 4 MiB raw
      VibeOS data partition. Its `fip.bin` and `boot.sd` are byte-for-byte
      identical to this build, and no Linux/rootfs partition exists.
- [x] The serial console displays the FSBL, OpenSBI, U-Boot, and VibeOS banners.
      The VibeOS platform name is Milk-V Duo/CV1800B.
- [x] The kernel reports only one online hart and makes no attempt to probe or
      start the C906L through HSM.
- [x] UART input and output are stable, and the `vibe>` shell is accessible and
      usable at 115200 8N1.
- [x] `uptime` increases normally, and sleep/timer self-tests pass, demonstrating
      that the 25 MHz timebase and SBI TIME path agree.
- [x] PLIC context 1 receives UART0 IRQ 44, and continuous input neither loses
      data nor triggers an interrupt storm.
- [x] MMU diagnostics show the kernel in
      `0x8020_0000..0x83e0_0000`, with no mapping or use of the FreeRTOS reserved
      region beginning at `0x83f4_0000`.
- [ ] `blk info` reports the SD data partition online; `blk test` survives a
      reboot without changing either boot payload.
- [ ] With the Ethernet IO Board attached, `net info` reports the CV1800B
      DWMAC online and the raw-L2 HELLO/CHALLENGE/ACK exchange succeeds.
- [x] The production image reports `LOWER_UP`, acquires a DHCP lease, and
      `ip addr` displays the applied configuration. Eight fresh TCP streams
      reached the bounded listener through the assigned address and returned
      exact binary echoes. Lease renewal still belongs to the longer-duration
      network stress gate.
- [ ] A live DWMAC reset/restart advances the device epoch and stack generation;
      packets from each retired coordinate are rejected in both directions,
      and the retired TCP stream does not resume in the replacement stack.
- [ ] Delayed DWMAC DMA completion and late-IRQ cases are exercised on physical
      hardware; the synthetic QEMU endpoint injection is not evidence for
      either case.
- [ ] Before enabling SSH, a documented hardware entropy source is validated
      on the board and a unique per-device Ed25519 identity is provisioned
      behind non-readable signing authority. Until then the Duo SSH path fails
      closed in production; the explicitly insecure `milkv-ssh-acceptance`
      image, a deterministic test key, and the CRC journal do not satisfy this
      item.
- [x] Flash the explicit SSH acceptance image on an isolated link and run
      `scripts/milkv-ssh-test.sh ADDRESS`. Preserve the serial warning,
      announced address, OpenSSH transcript, interactive VSH result, and final
      PASS marker. The 2026-08-11 run passed 11 complete gates (at least 110
      independent sessions) with the evidence recorded above. This item must
      not be reported as production SSH readiness.
- [x] Run the self-tests appropriate for a single-core board configuration.
      Preserve the full serial log before analyzing any trap, panic, or OpenSBI
      extension error.

Checked base-port items include the earlier hardware acceptance run and the
explicit 2026-08-11 SSH/VSH run. Unchecked storage, raw-network, recovery, and
fault-injection items still require dedicated fresh board evidence. Neither
status is a claim of production readiness or dual-core SMP support.
