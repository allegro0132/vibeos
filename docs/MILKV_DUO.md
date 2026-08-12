# Milk-V Duo (CV1800B)

VibeOS provides **single-core board support for the Milk-V Duo C906B**. Current
support includes a fixed memory layout, Sv39 mappings, UART0, the PLIC, a 25 MHz
timebase, native microSD/DWMAC backends, DWC2 USB host with HID and CDC-ECM
classes, and a FIT/SD image packaging flow based on the official Buildroot SDK.

The separate `--jitterentropy-probe` image loads the exactly pinned
`jitterentropy-rs` 0.1.1 crate against `rdtime` and exposes conditioned smoke
testing plus timer-boundary raw-delta qualification on UART. The crate itself
did not expose a raw-noise API; the reviewable VibeOS patch adds a
qualification-only export after the collector's private timing window closes.
The rewrite is not a certified or behaviorally equivalent replacement for
upstream Jitterentropy. It is a qualification artifact, not a production
entropy source. See
[JITTERENTROPY.md](JITTERENTROPY.md) before making any SSH security claim.
The additional `--jitterentropy-ssh-probe` image combines that collector with
the deliberately insecure fixed-key SSH acceptance transport and streams a
strictly framed binary dataset on port 2222. It is a separate network/load
qualification condition, not production SSH.

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

The production image enables `milkv-ssh`. One independent `net-stack` component
fairly drives the interfaces discovered at boot. The image policy sorts each
NIC's stable physical location (`mmio@...` or the DWC2 controller plus USB port
path) and assigns the boot-local `netN` ordinals from that order; no ordinal is
reserved for DWMAC, CDC-ECM, or RTL815x. Each admitted NIC has its own packet
endpoints, device epoch, MAC identity, ARP cache, route table, DHCPv4 client and
fault boundary. SSH receives only the port-22 listener capability attached to
the DWMAC policy root and observes that interface's lease before announcing
readiness; another NIC does not acquire SSH authority merely by appearing. The image contains
no fixed host or client private key. It uses the accepted
OSR=3 jitterentropy-rs source to seed a ChaCha20 DRBG, and refuses to listen
until a device host key and an authorized client key have both been persisted
and verified. This is a project deployment decision based on the recorded
board evidence, not a claim of NIST/CMVP certification. The dual-interface
composition builds, but its simultaneous physical gate remains unchecked until
the UART procedure below is run with both links attached.

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
| USB 2.0 OTG / DWC2 | `0x0434_0000..0x0435_0000`, PHY `0x0300_6000..0x0300_6058`, IRQ 30; host bring-up, EP0 enumeration, HID and CDC-ECM |
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

## USB host bring-up status

The Milk-V image now maps the CV1800B DWC2 core, enables its AXI/APB/125 MHz/
33 kHz/12 MHz clocks, selects host role through TOP register `0x0300_0048`,
validates the Synopsys core ID, performs a bounded core reset, and powers the
single root port. A successful boot prints a line like:

```text
usb       DWC2 0xNNNN @ 0x4340000, IRQ 30, N channel(s), port powered/waiting
```

CV1800B's DWC2 revision uses the 4.20a-or-newer reset protocol: hardware raises
`GRSTCTL.CSRST_DONE` instead of clearing `CSRST` itself, after which software
clears `CSRST` and acknowledges `CSRST_DONE`. The driver selects this handshake
from `GSNPSID` and only forces host mode after the core reset, matching the
official SDK sequence.

The driver now also enables buffer DMA with explicit C906 cache maintenance,
resets an attached root-port device, runs endpoint-zero SETUP/DATA/STATUS
transactions, assigns address 1, and reads the complete device descriptor. It
then scans the configuration tree for HID interfaces. Boot keyboards are
switched to the fixed boot protocol; report-protocol keyboards expose their HID
report descriptor so supported array and NKRO layouts can be selected. The
driver polls the chosen interrupt-IN endpoint at its advertised interval.
Newly pressed keys use the same ASCII, control-key and ANSI-arrow translation
as the QEMU xHCI console and feed the kernel console input queue. The boot log
prints speed, VID:PID, USB version, endpoint-zero packet size, keyboard protocol,
and the selected HID interface/endpoint. A resident polling task
detects root-port disconnect and reconnect transitions, clears stale device
state, and repeats enumeration and HID configuration after reinsertion.

SCSI transparent-command-set, Bulk-Only USB storage is also supported on LUN
zero. The driver discovers the bulk-IN and bulk-OUT endpoints, issues TEST UNIT
READY, REQUEST SENSE and READ CAPACITY(10), and accepts 512-byte logical blocks.
READ(10) and WRITE(10) transfer one raw sector at a time; failed BOT transport
or phase transactions perform the required Mass Storage Reset followed by
CLEAR_FEATURE(ENDPOINT_HALT) on both bulk endpoints. VibeOS does not yet mount a
FAT or other filesystem from USB, so this is raw block access rather than a
file-oriented `mount`, `cp`, or directory interface. The official SDK describes
the same core/PHY ranges and IRQ in
[`cv180x_base.dtsi`](https://github.com/milkv-duo/duo-buildroot-sdk/blob/develop/build/boards/default/dts/cv180x/cv180x_base.dtsi)
and
[`cv180x_base_riscv.dtsi`](https://github.com/milkv-duo/duo-buildroot-sdk/blob/develop/build/boards/default/dts/cv180x_riscv/cv180x_base_riscv.dtsi).

The physical UART VSH exposes `lsusb` for live diagnosis. It reports the DWC2
release, IRQ, channel count, root-port state and raw `HPRT`, followed by the
addressed device's VID:PID, speed, USB version and endpoint-zero packet size.
Authenticated SSH sessions install the same shared VSH command profile, so
`lsusb` and other read-only platform diagnostics are available over either
transport. The default-password onboarding profile remains deliberately
restricted until a public key is authorized.
For an attached disk, `usb info` prints endpoint packet sizes and capacity, and
`usb read N` dumps one 512-byte sector. The hardware acceptance image also
provides `usb write-test CONFIRM`, locked to the explicitly reserved LBA
4,000,000. It saves that sector, writes a deterministic pattern, reads it back,
restores the original bytes, and verifies the restoration. It must only be run
on media where that LBA is known to be disposable, and power and USB must remain
stable until the restoration message appears.
For a usable keyboard it also prints `HID keyboard protocol=Boot` or
`protocol=Report` with the selected interface and interrupt-IN endpoint. It
also reports each interface class tuple and the HID report-descriptor length.
`connected, not enumerated` distinguishes
an electrical connection from successful USB protocol enumeration.
For a directly attached high-speed hub it also configures hub power, resets the
connected downstream ports, assigns each child a unique address, and reports
each child's negotiated speed and raw port status. HID and Mass Storage keep
independent address, endpoint-toggle and split-transaction state, so their
transfers can be interleaved through the same hub. This provides the topology
needed to select native high-speed transactions or USB 2.0 split transactions
before assigning each child address.
On 2026-08-12, UART and an authenticated SSH PTY returned the same physical
topology: hub `05e3:0610`, four ports, with a connected, enabled and powered
Full-Speed child on port 1 (`wPortStatus = 0x0103`).
Full/Low-Speed children behind a high-speed hub use bounded DWC2 start-split
and complete-split transactions. Endpoint-zero traffic is divided into one
max-packet transaction at a time with software PID toggling, while NYET causes
a bounded complete-split retry. The first child receives address 2 and appears
as a separate `lsusb` row with its parent hub and port.

On 2026-08-12, the physical report-protocol gate enumerated an Apple
`05ac:0220` Full-Speed keyboard behind the `05e3:0610` high-speed hub. `lsusb`
reported interface 2, interrupt-IN endpoint `0x83`, maximum packet size 32 and
a 1 ms interval, and retrieved all 238 report-descriptor bytes. The descriptor
advertised both Report ID 1's five-key array and Report ID 2's 104-key NKRO
bitmap. Typing `hidtest123` on that keyboard produced the exact ten-byte VSH
command and the expected `unknown command at bytes 0..10` response, with no
missing, duplicated or reordered key.

The multi-device gate on the same date simultaneously enumerated that keyboard
as address 2 on hub port 1 and a high-speed `1f75:0903` SCSI/BOT disk as address
3 on port 3. `echo hidusbcombo` entered through HID exactly, followed by a
successful 512-byte `usb read 0` from the disk with the `55 aa` MBR signature.
Removing the keyboard caused a bounded re-enumeration that left the disk online
at address 2 and READ(10) working. Reinserting it restored both functions;
removing only the disk then left the keyboard online, where `echo hidok7`
arrived exactly. The hub polling task checks port membership every 250 ms and
rebuilds function bindings when it changes.

The recursive-hub gate on 2026-08-12 placed a high-speed `1a40:0101` hub on
root-hub address 1 / port 1, then the Full-Speed Apple keyboard on the nested
hub's address 2 / port 3. `lsusb` reported the keyboard at address 3 with the
complete parent chain, and `echo nestedhidok` arrived exactly through split
transactions targeting the nearest high-speed hub. Removing only the keyboard
reduced the descendant count from two to one while preserving both hubs.
Reinsertion restored Report HID without reboot, and `echo n2ok` arrived exactly.
Traversal is bounded to four hub levels and fifteen non-root devices; nested
hubs must currently negotiate High Speed.

The CV1800B adapter also reproduces the vendor FSBL's UTMI wrapper reset pulse
(`USB20_PHY_WRAP + 0x14 = 0x18b`, restore, then wait 100 microseconds) after
enabling all five USB clocks. Host role selection powers VBUS before the DWC2
core reset; omitting the UTMI pulse leaves `GRSTCTL.CSFTRST` stuck on physical
hardware even though the APB register window and Synopsys core ID are readable.

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

On first boot, VibeOS obtains a fresh Ed25519 host seed from jitterentropy-rs,
commits the SSH configuration as an immutable object-store version, and starts
SSH after read-back verification. Existing sector-16/17 provisioning records
are migrated once into the object store. Connect with the one-time onboarding
credential:

```sh
ssh vibe@BOARD_ADDRESS
# password: vibeos
```

The password-authenticated VSH exposes only key provisioning commands. Generate
an Ed25519 client key on the administrator's computer and authorize its public
half in standard OpenSSH form:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/vibeos_duo
ssh-authorize add ssh-ed25519 AAAA...comment
```

After the authorized-key update is flushed and read back, VibeOS atomically
disables the default password, disables password authentication, and resets the
onboarding connection. Subsequent connections are public-key-only. Up to eight
exact Ed25519 client keys may be added; adding the same key again is idempotent
and exceeding the bound is rejected. The legacy 64-hex public-key form remains
accepted on UART.

The board-side `ssh-keygen` command instead creates an independent client key
pair and never authorizes it. `cat ssh-client-key.pub` prints its OpenSSH public
key and `cat ssh-client-key` prints its unencrypted OpenSSH private key. Each
`cat` invocation asynchronously reads and validates the latest SSH object-store
version; these two names are an explicit allowlist, not a general object-ID or
path namespace. Anyone who can read that private-key output can use the key, so
transfer it over an authenticated session and protect it immediately.

The host seed, authorized public keys, onboarding-complete state, and optional
device-generated client key pair are stored on the microSD without encryption;
physical access to the card can recover private material or roll back policy.
The object journal detects corruption and torn writes but does not provide
confidentiality or rollback protection.

After provisioning, connect with:

```sh
ssh -i ~/.ssh/vibeos_duo root@BOARD_ADDRESS
```

The same shared Netstack control plane is exposed to the local production VSH
and to an authenticated production SSH profile. The legacy `net-shell` image
remains available as a network-only diagnostic. First list the admitted
interfaces, then substitute the chosen name for `netN`:

```text
ip link show
ip -4 addr show dev netN
ip addr replace 192.168.1.20/24 dev netN
ip route replace default via 192.168.1.1 dev netN
dhclient netN
dhclient -r netN
```

`ethN` is accepted as an alias for the corresponding `netN`. `dhclient -r` stops the client and
clears the local IPv4 configuration; smoltcp does not currently emit a DHCP
RELEASE packet.

### Explicit SSH/VSH hardware acceptance image (insecure)

The physical remote-login gate uses a deliberately separate
`milkv-ssh-acceptance` image. It proves DWMAC, DHCP, the SSH wire protocol, and
interactive per-session VSH on the board, but it is **not a secure deployment**:
the image embeds public fixed host/client identities and a deterministic random
provider whose sequence repeats after every reboot. Never expose it to an
untrusted network, send secrets through it, or distribute it as a production
image. The normal production image does not link these acceptance fixtures.

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

On the serial `vsh>` prompt, read the boot line
`net map netN <- mmio@0x4070000 (dwmac)`, substitute that name for
`<DWMAC_NET>`, obtain its address, and confirm that carrier is present:

```text
ip link show
ip -4 addr show dev <DWMAC_NET>
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

### Simultaneous DWMAC + USB CDC-ECM gate

Build a DHCP-enabled image, attach both the Ethernet IO Board and a supported
USB CDC-ECM function, and connect the two links to DHCP-capable networks. They
may share one LAN, but the DHCP server must issue distinct addresses for their
distinct MAC identities. Read the two boot-time `net map` lines and substitute
the names mapped from `mmio@0x4070000` and `usb@0x4340000/...` below. The
ordinals come from sorted physical topology, not the driver kind.

Capture UART0 from boot, wait for both leases, then run:

```text
ip link show
ip -4 addr show dev <DWMAC_NET>
ip -4 addr show dev <USB_NET>
ip route show dev <DWMAC_NET>
ip route show dev <USB_NET>
```

The gate requires both links to report `UP,LOWER_UP` at the same time and both
interfaces to show different dynamic IPv4 leases. Re-run the two address
commands after unplugging and reconnecting the USB NIC: `<DWMAC_NET>` must
retain its lease, while `<USB_NET>` must return with a higher device epoch and
reacquire its own lease. The first simultaneous-online portion of the preserved log is
machine-checkable with:

```sh
./scripts/check-milkv-dual-net-log.sh path/to/uart.log
```

Independent DHCP discovery on both interfaces exercises RX and TX on both data
paths without sharing a packet session. The production and diagnostic service
listener remains attached to the DWMAC policy root regardless of its `netN`
ordinal; the dual-network log gate therefore does not claim that SSH or TCP echo
is exposed through the USB interface.

## Hardware validation checklist

For the first hardware boot, preserve the full serial log and verify each item.
For the USB HID gate, build `./scripts/build-milkv-duo.sh --diagnostic`, capture
UART0 at 115200 8N1 to a file, and boot with the USB keyboard disconnected.
After the `vsh>` prompt appears, attach the keyboard and run `lsusb` through
UART first. Continue only if it reports the device ID and `HID keyboard
protocol=Boot` or `protocol=Report`.
Then type `uptime` on the USB keyboard, unplug it, wait for the disconnect
diagnostic, reconnect it, confirm `lsusb` again through UART, and type `uptime`
again on the USB keyboard. The two echoed `uptime` commands are the evidence
that HID reached the console input queue. Analyze the preserved log with:

```sh
./scripts/check-milkv-usb-hid-log.sh path/to/uart.log
```

The gate passes only when the log contains two successful enumerations, two HID
configurations, the intervening disconnect transition, and two successful
keyboard-entered `uptime` commands, with no panic or USB failure marker.

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
- [x] The physical boot on 2026-08-12 reports DWC2 release `0x420a`, IRQ 30,
      14 host channels and a powered, connected root port. `lsusb` enumerates
      the attached Genesys Logic high-speed hub as `05e3:0610` without a
      reset/host-mode timeout; Hub downstream traversal remains part of the
      HID gate below.
- [x] A Full-Speed USB HID device behind the high-speed hub completes address,
      configuration and report-descriptor enumeration on the physical OTG port.
      The Apple `05ac:0220` report keyboard is configured on interface 2 / endpoint
      `0x83`, and `hidtest123` reaches `vsh>` exactly through USB input.
- [x] A high-speed `1f75:0903` SCSI/BOT disk behind hub port 3 reports
      123,469,824 sectors of 512 bytes. READ(10) returned the complete protective
      MBR including its `55 aa` signature. On 2026-08-12, the guarded WRITE(10)
      test on reserved LBA 4,000,000 passed its pattern readback and restoration
      checks; an independent subsequent READ(10) matched the original 512 bytes.
- [x] Hub multi-device enumeration runs HID and Mass Storage simultaneously.
      Removing and reinserting the keyboard preserves disk READ(10); removing
      the disk preserves exact HID input. Each topology transition reassigns
      addresses and restores the remaining functions without a reboot.
- [x] Recursive enumeration traverses the physical `05e3:0610` -> `1a40:0101`
      -> `05ac:0220` topology. The Full-Speed keyboard works at depth two through
      the nested high-speed hub's transaction translator, and nested-port
      removal/reinsertion clears and restores HID without removing either hub.
- [ ] `blk info` reports the SD data partition online; `blk test` survives a
      reboot without changing either boot payload.
- [ ] With the Ethernet IO Board attached, `net info` reports the CV1800B
      DWMAC online and the raw-L2 HELLO/CHALLENGE/ACK exchange succeeds.
- [x] The production image reports `LOWER_UP`, acquires a DHCP lease, and
      `ip addr` displays the applied configuration. Eight fresh TCP streams
      reached the bounded listener through the assigned address and returned
      exact binary echoes. Lease renewal still belongs to the longer-duration
      network stress gate.
- [ ] With DWMAC and USB CDC-ECM attached together, both topology-mapped `netN`
      interfaces report `UP,LOWER_UP`, acquire distinct DHCP leases, and pass
      `scripts/check-milkv-dual-net-log.sh`. USB unplug/reconnect retires and
      rebinds only the USB-mapped interface; fresh-board UART evidence is still
      required.
- [ ] A live DWMAC reset/restart advances the device epoch and stack generation;
      packets from each retired coordinate are rejected in both directions,
      and the retired TCP stream does not resume in the replacement stack.
- [ ] Delayed DWMAC DMA completion and late-IRQ cases are exercised on physical
      hardware; the synthetic QEMU endpoint injection is not evidence for
      either case.
- [x] Production SSH uses the board-evaluated OSR=3 jitterentropy-rs source and
      locally provisions a unique Ed25519 host key behind non-readable signing
      authority. It fails closed until both host and client records pass
      CRC/readback validation. This project gate is not NIST/CMVP certification;
      microSD confidentiality and authenticated rollback protection remain open.
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
