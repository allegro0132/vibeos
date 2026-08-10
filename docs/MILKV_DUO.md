# Milk-V Duo (CV1800B)

VibeOS provides **single-core board support for the Milk-V Duo C906B**. Current
support includes a fixed memory layout, Sv39 mappings, UART0, the PLIC, a 25 MHz
timebase, native microSD/DWMAC backends, and a FIT/SD image packaging flow based
on the official Buildroot SDK.

> **Base-port hardware validation status (2026-08-10): passed.** A CV1800B board booted
> successfully from the earlier single-FAT image and entered the
> interactive shell. Sv39, the 25 MHz timer, UART0/PLIC IRQ 44, and component
> scheduling all worked correctly, and the hardware `selftest` reported
> `388 passed, 0 failed`. Native microSD data I/O and Ethernet IO Board support
> compile successfully but remain unchecked below until the new two-partition
> image is exercised on hardware. The C906L and dual-core SMP are not supported.

The DWMAC software path now retains a dequeued packet while its sole TX
descriptor is busy, faults after a bounded two-second stall, revalidates all
device capabilities around each synchronous hardware turn, and resets MAC/DMA
on normal teardown. This closes the known software drop/stall path; it does not
replace the unchecked physical Ethernet acceptance item below.

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
| Blue status LED | active-high GPIOC24; VibeOS turns it on after enabling Sv39 |

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

## Hardware validation checklist

For the first hardware boot, preserve the full serial log and verify each item:

- [x] `scripts/build-milkv-duo.sh` successfully generates the bare kernel. The
      native flow or `scripts/package-milkv-duo-sdk.sh` then successfully
      generates `target/milkv-duo/boot.sd`, with no FIT validation errors.
- [ ] The final `*.img` contains a 128 MiB FAT boot partition and a 4 MiB raw
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
- [ ] The production image reports `LOWER_UP`, acquires and renews a DHCP lease,
      `ip addr`/`ip route` display the applied configuration, and a fresh TCP
      stream reaches the bounded listener through the assigned address.
- [ ] A live DWMAC reset/restart advances the device epoch and stack generation;
      packets from each retired coordinate are rejected in both directions,
      and the retired TCP stream does not resume in the replacement stack.
- [ ] Delayed DWMAC DMA completion and late-IRQ cases are exercised on physical
      hardware; the synthetic QEMU endpoint injection is not evidence for
      either case.
- [ ] Before enabling SSH, a documented hardware entropy source is validated
      on the board and a unique per-device Ed25519 identity is provisioned
      behind non-readable signing authority. Until then the Duo SSH path fails
      closed; neither a deterministic test key nor the CRC journal satisfies
      this item.
- [x] Run the self-tests appropriate for a single-core board configuration.
      Preserve the full serial log before analyzing any trap, panic, or OpenSBI
      extension error.

Checked base-port items above record the earlier hardware acceptance run;
unchecked storage/network items apply to this new implementation and require a
fresh board log. Neither status is a claim of production readiness or dual-core
SMP support.
