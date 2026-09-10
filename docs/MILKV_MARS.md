# Milk-V Mars port status

Target: standard Milk-V Mars with 4 GiB RAM, microSD boot, serial and SSH
acceptance. This is an **incomplete port**. A 641 MiB serial/SD test image now
builds with paired SPL/OpenSBI/U-Boot. Hardware qualification, EQoS and SSH
remain outstanding. See [image instructions](../firmware/milkv-mars/bootchain/README.md).

## Implemented foundation

- Firmware-owned UART/PLIC instances and immutable HAL operation tables are
  used by the existing QEMU and Duo firmware. The kernel console adapter keeps
  its locks, ring buffers, record framing and wakeups; the interrupt adapter
  keeps its atomic handler registry and enable lock. Neither adapter imports a
  BSP or accesses registers. All kernel adapters now obtain physical resource
  descriptions from firmware. The dependency guard rejects concrete drivers
  and BSPs in the kernel dependency graph; legacy feature aliases remain.
- `drivers/uart16550` implements 16550/DW APB register IO and preserves the DW
  busy-detect and phantom-timeout acknowledgements. `drivers/plic` implements
  context initialization, source masking, claim and completion.
- `drivers/sd-protocol` shares SD CSD normalization/capacity and sector address
  encoding with the existing Duo SDHCI driver and the new DW-MSHC engine.
- `drivers/dw-mshc` implements SD initialization, four-bit negotiation, bounded
  clock changes, 512-byte PIO reads/writes, card-ready checking and write
  publication tracking. IO failures quarantine the instance. It requires the
  caller to prepare clocks, reset, pinmux and card power. It has not been tested
  against a real controller. The Mars firmware now binds it to the kernel PIO
  service through a firmware-enforced data partition.
- `hal::fdt` validates bounded FDT v17 byte slices and extracts RAM and fixed
  reservations without allocation. `hal::memory` subtracts reservations
  transactionally and validates complete DMA spans and cache-line isolation.
  DTB admission now publishes reservation-subtracted heap ranges in the QEMU
  acceptance composition and Mars serial/SD composition. The MMU consumes
  the firmware boot contract and its RAM table arena, supports multiple GiB
  windows and 2 MiB RAM leaves, and pre-splits permission-changing pools.
- `boards/milkv-mars` describes the target and admits DTB memory within its
  physical RAM range. The caller must still reserve the kernel image, page
  tables and permanent DMA before using that memory for allocation.

## Reference baseline

SDK: `milkv-mars/mars-buildroot-sdk`, `dev` commit
`1fd6bac9f2efde47fbb8afd28d2903c49f893e3f`.

Relevant files in that revision:

- `linux/arch/riscv/boot/dts/starfive/jh7110-milkv-mars.dts` and `.dtsi`
- `linux/arch/riscv/boot/dts/starfive/jh7110.dtsi` and `jh7110-clk.dtsi`
- `u-boot/drivers/clk/starfive/clk-jh7110.c`
- `u-boot/include/dwmmc.h`

Source URL base:
[fixed SDK revision](https://github.com/milkv-mars/mars-buildroot-sdk/tree/1fd6bac9f2efde47fbb8afd28d2903c49f893e3f).
The local reference manifest records inspected file hashes; it is not a
bootloader build or an image manifest.

| Resource | SDK description |
|---|---|
| RAM | `0x40000000..0x140000000` (4 GiB, extending above physical 4 GiB) |
| OpenSBI/kernel boundary | kernel load at `0x40200000`; reserve the preceding 2 MiB |
| Application harts | 1, 2, 3, 4; hart 0 is the disabled S7 monitor core |
| Supervisor PLIC contexts | 2, 4, 6, 8 respectively, not QEMU's `2 * hart + 1` |
| PLIC | `0x0c000000`, 136 interrupt sources |
| UART0 | `0x10000000`, IRQ 32, 32-bit registers, register shift 2 |
| UART0 clock | gate from the 24 MHz oscillator in the SDK clock tree |
| Timebase | 4 MHz |
| microSD | DW-MSHC SDIO1 at `0x16020000`, IRQ 75, 32-word FIFO at offset `0x200` |
| SD clock profile | 50 MHz source, initial clock no greater than 400 kHz, data clock 25 MHz |
| GMAC0 | `0x16030000`, MAC IRQ 7; GMAC5 register/descriptor engine remains unimplemented |

Treat clock rates above as the pinned SDK profile, not evidence that arbitrary
pre-existing firmware leaves the same configuration. Platform initialization
must establish them before attaching the relevant controller.

## Remaining implementation

1. Implement JH7110 clock/reset/pinmux preparation and verify DMA coherence for
   the GMAC path. Add the GMAC5/EQoS engine and PHY setup using the Mars wiring.
2. Qualify DW-MSHC data-only IO, persistence, timeout/reset behavior and protection
   of boot partitions on the board.
3. Qualify the paired SPL/OpenSBI/U-Boot image, four-core HSM startup, IPI,
   fences, timer, DTB reservations and guarded mappings on physical Mars.
   Confirm board revision/SD boot selector; do not update SPI in this workflow.
4. Provision a separate Mars identity,
   qualify the entropy source, and enable SSH/WASM/Wasmtime only after these
   prerequisites work on the board.
5. Capture three cold boots and an hour of simultaneous storage, networking and
   WASM activity. Supply the serial device, SSH address/user/key and test-card
   device explicitly; never infer these from the existing Duo setup.

## Reproducing foundation checks

```sh
cargo test --locked --offline \
  -p vibeos-hal -p vibeos-bsp-milkv-mars \
  -p vibeos-driver-uart16550 -p vibeos-driver-plic \
  -p vibeos-sd-protocol -p vibeos-driver-sdhci-blk -p vibeos-driver-dw-mshc
(cd firmware/qemu-virt && cargo build --locked --offline --release --features legacy-shell)
(cd firmware/milkv-duo && cargo build --locked --offline --release)
scripts/qemu-test.sh mmu
scripts/qemu-test.sh selftest
python3 scripts/qemu-large-ram-test.py
```

Recreate the independent DTB fixture with:

```sh
dtc -I dts -O dtb -o boards/milkv-mars/tests/fixtures/memory.dtb \
  boards/milkv-mars/tests/fixtures/memory.dts
```

Host register models validate sequencing, response handling and error paths;
they do not emulate electrical timing, clock/reset hardware, interrupt delivery
or cache coherence. QEMU acceptance validates the existing QEMU platform only.
Actual run results and remaining gaps are recorded in the
[foundation evidence](../boards/milkv-mars/foundation-evidence.json).

## Firmware boot contract and large-RAM stage

The kernel imports `VIBEOS_BOOT_PLATFORM` from its final firmware. The table
contains board facts, hart topology, MMU layout, optional RTC/reset operations
and a callback returning permanent page-table storage. QEMU and Duo use this
path; Cargo feature forwarding that affects QEMU RAM now belongs to firmware.

The dedicated `mmu-large-memory` QEMU firmware profile maps four GiB while
keeping its heap below 128 MiB. On-target checks write distinct patterns through
five unused high pages, including all four root windows and addresses above
physical 4 GiB, verify that the pages do not alias, and restore their contents.
The same image runs the normal selftest including stack guards and W^X. It is
an acceptance profile, not the default QEMU image or a Mars hardware emulator.

The storage bootstrap exposed a stack-overflow regression during this change:
returning the 1024-root pin registry by value produced multiple large stack
copies. Production initialization now constructs it directly in its Arc, with
a separate 64 KiB-stack host regression. Ordinary VirtIO-block boot and the
on-target selftest exercise the actual bootstrap path.

OpenSBI's `Platform HSM Device: ---` line does **not** prove that the SBI HSM
extension is absent (QEMU's current firmware prints this and advertises HSM).
Bootloader qualification must probe the extension and start secondary harts;
it must not infer capability from that label alone.

### PIO block composition stage

The Duo firmware now owns the SDHCI card instance and publishes the HAL
`PioBlockDevice` operation table. The kernel holds an exclusive invocation token
and retains capability checks, incarnation/epoch handling, fault policy and
partition translation. CMD18 fallback, CMD25 mode probing, adaptive blind PIO
and verification now live in `drivers/sdhci-blk/src/adaptive.rs`. Existing Duo
resource identifiers, image-policy sector ranges and diagnostic commands remain
compatible. The explicit raw diagnostic read is still separate from ordinary
partition-limited I/O.

`BlockWindow` validates the complete logical run before translating it into
physical sectors. The HAL callback contract records mutation publication even
when the card subsequently fails. The actual kernel invocation adapter is tested
against synthetic firmware, including duplicate-notification suppression,
pre-publication rejection and post-publication timeout. Driver tests exercise
invalid-range rejection and the failed SDHCI protocol fallback ladder with plain
memory registers; these do not emulate successful SD transfers or hardware timing.

Evidence: `boards/milkv-mars/pio-composition-evidence.json`. This stage removes
the SDHCI dependency from the kernel; VirtIO, Ethernet, USB and LED migration,
Duo SoC setup separation, Mars platform setup and DW-MSHC firmware composition
are still pending. No new physical SD qualification or Mars image is claimed.

### Asynchronous entropy composition stage

QEMU firmware now owns the VirtIO RNG engine and publishes a HAL entropy
operation table. The kernel retains its capability leases, DMA claim barrier,
request deadlines, interrupt routing, revocation, epoch allocation and quarantine
policy. The firmware's IRQ acknowledgement path does not borrow mutable engine
state. Completion queries use shared state; submission and reset require the
exclusive invocation token.

HAL submission tokens contain an epoch and a checked serial number. The serial
survives device resets, and the provider retains the actual hardware completion
record. This prevents stale waiters from matching a reused hardware ring index.
Host tests cover stale epochs, reset, active-request rejection and serial
exhaustion. A mutation that ignores the epoch is caught. QEMU N3's two-boot
acceptance exercises real VirtIO RNG, distinct signed samples, stable test
identity and binary authentication policy. This is QEMU transport validation,
not Mars entropy qualification or a new physical fault/recovery qualification.

The kernel no longer depends on `vibeos-driver-virtio-rng`. Its shared VirtIO
transport and other DMA engines still require migration. Mars production SSH
remains gated on an independently configured identity and qualified entropy.

### SoC/SDHCI resource separation

`vibeos-platform-cv1800b` now owns SDIO0 source clocks, pad mux/pulls and
slot supply switching. The SDHCI description no longer grants access to the
TOP block. Firmware constructs the platform resources and passes the HAL
`SdPlatform` hooks to card initialization. Controller POWER_CONTROL, controller
reset, command/response and FIFO operations remain in the SDHCI driver.

The prior order is preserved: platform clocks, controller power off, pad/supply
off with 30 ms settling, host reset and initial controller clock/power, then
slot supply on with 1 ms and 5 ms settling. Host tests check unrelated bits,
pad modes, power sequencing and failure to reset stopping before power-on.
The monotonic delay also handles counter wrap. Fake registers cannot validate
physical voltage, pad timing or a particular card's power requirements.

This is the SD portion of the platform split. Ethernet and USB still contain
CV1800B platform code, and shared clock-register ownership must remain serialized
when those resources are migrated. JH7110 requires its own implementation.

### Queued block composition stage

QEMU firmware now owns the VirtIO block engine and its fixed DMA slab. The HAL
queued-block table carries read/write/flush requests, publication notifications,
completion records and reset operations. Kernel policy retains capability checks,
queue scheduling, epoch validation, cancellation, revocation and fault recovery.
Firmware retains the actual driver submission, matching an epoch/serial token
before completing or timing out a request. IRQ acknowledgement never borrows
mutable firmware engine state. Reset failure continues to quarantine DMA.

The actual kernel invocation adapter is host-tested against synthetic firmware.
This covers multi-sector marshaling, publication notification, completion data,
timeout/reset and recovery dispatch. A mutation truncating multi-sector requests
to one sector fails. QEMU `block` verifies the physical backing file contents;
`block_recovery` covers timeout, cancellation, revocation and a fault after DMA
publication, followed by a fresh online generation. These tests do not emulate
Mars DW-MSHC or physical SD behavior.

The kernel no longer depends on `vibeos-driver-virtio-blk`; shared VirtIO
transport/protocol helpers, network and USB engines still require migration.

### Packet-device composition stage

The Duo firmware now owns the DWMAC engine, instance state and DMA slab, and
publishes HAL packet-device operations. The kernel retains packet endpoints,
network generations, capability admission and fault/recovery policy. Driver
telemetry and the old device identifiers remain compatible; controller/platform
register diagnostic words are transitional fields for those existing tools.
The controller engine no longer appears in the kernel's dependency graph.

Firmware preserves the `.dma` placement and serializes instance claim/release.
Fault recovery abandons the old engine metadata without running its destructor:
DWMAC's destructor can reset hardware, and the driver's recovery contract forbids
an old instance from being dropped after recovery. Explicit recovery owns reset;
a failed reset keeps the firmware claim fenced. Ordinary shutdown still consumes
the engine normally. Host tests cover packet marshaling, error propagation,
claim/shutdown dispatch and non-execution of the abandoned destructor. A mutation
that drops the old instance is caught. No new physical Ethernet or DMA timing
qualification is claimed; QEMU tests exercise the existing QEMU path.

The DWMAC engine still contains CV1800B platform setup and cache operations.
Those must be split before sharing its MDIO/PHY support with JH7110 GMAC5;
Mars must not inherit CV1800B/T-Head cache instructions.

### QEMU queued-network composition stage

QEMU firmware now owns the VirtIO network engine and supplies HAL queued packet
operations. The kernel keeps endpoint publication, packet generation fences,
capability admission, timeout policy and IRQ routing. Received frames have a
bounded HAL representation; ring validation remains in the hardware driver.
Shared queries never borrow mutable firmware state, and fault recovery abandons
old engine metadata before the explicit hardware reset.

The kernel invocation token remembers release/quarantine locally. An explicit
shutdown followed by task destruction cannot touch a replacement engine. Host
regression tests exercise this sequence, including a replacement attached between
the two shutdown calls; removing the local release guard fails the test. The same
adapter tests cover receive bounds, frame contents, deadlines, reset and error
propagation. QEMU `net` and `net_recovery` validate the real ring path against a
localhost peer; the latter injects a fault after DMA publication and checks a
fresh generation handshake. This is not physical Mars GMAC/DMA qualification.

The kernel no longer depends on `vibeos-driver-virtio-net`. Shared VirtIO
transport/protocol helpers, PCI, USB and the Duo LED still require migration.

### Firmware platform boot hooks

BootPlatform now exposes boot-hart-only initialization and diagnostic callbacks.
The kernel invokes them after identity mappings exist, before heap services or
secondary harts. Duo supplies LED initialization and its existing exact diagnostic
text; QEMU supplies no-op hooks. The kernel's LED crate dependency and Duo-only
LED startup branches are removed. Other platform/device migration is still pending.

Host tests execute the actual Duo hook helpers against plain-memory register
apertures, checking GPIO/mux preservation and the distinction between asserted
output and unconfirmed input. Mutating that distinction fails the diagnostic
regression. These tests do not prove electrical LED behavior on a physical board.

### PCI host composition stage

QEMU firmware owns the ECAM host, BAR allocator and enumerated inventory. HAL
contains immutable function/BAR records and the host operation table. The kernel
retains serialization and collects inventory into its own caller-facing vector;
firmware enumeration callbacks do not allocate or retain callback references.
Enabling bus mastering now goes through the host operation after checking the
complete function against the current initialized inventory. The snapshot itself
contains no configuration-space mapping or hardware access method.

Host tests check that absent or forged inventory cannot modify the command
register and that valid activation preserves status and unrelated command bits.
Removing the inventory check fails the regression. QEMU USB acceptance exercises
PCI BAR/INTx, XHCI, HID input/hotplug and BOT/SCSI backing I/O. The kernel no longer
depends on the PCI driver. USB controllers and shared VirtIO helpers remain to
be migrated; no Mars PCIe support is implied or included in this port's scope.

### XHCI firmware composition stage

QEMU firmware now owns the XHCI controller and its permanent page-aligned `.dma`
storage. HAL carries USB inventory, bounded HID input and host operations. The
kernel retains PCI resource admission, controller serialization, PLIC routing,
wait-queue ordering and terminal injection; it has no XHCI driver dependency.
The firmware IRQ callback reconstructs only the validated MMIO token and never
borrows mutable controller state.

On IRQ-install failure the kernel masks controller interrupts and leaves its
published flag false. Firmware retains the already initialized instance, so a
retry with the same resources does not manufacture another mutable DMA borrow.
Different resources are rejected. Host tests execute the actual kernel adapter
with failed registration and failed enable, then successful retry, sector I/O,
HID injection and wakeup. Removing IRQ masking fails the regression. QEMU USB
acceptance covers the real XHCI/HID/hotplug/BOT path; ELF inspection verifies the
moved DMA slab's section and page alignment. This does not add Mars USB support.

### Duo polling USB composition stage

The Duo firmware owns DWC2, its instance claim and its permanent DMA slab.
The kernel consumes the HAL polling USB table for HID, BOT storage and CDC-ECM,
retaining the same hotplug configuration order, polling intervals, terminal
injection and network-session policy. Descriptor/input bounds are represented
in HAL without register-access methods. Existing driver type imports remain
compatible through re-exports. The Duo kernel's normal dependency graph no
longer includes BSP or concrete drivers; QEMU's shared VirtIO transport/types
and the remaining SoC-resource split still need migration.

Host tests exercise the actual kernel adapter: failed initialization followed
by retry, idempotent publication, class configuration order, HID injection,
sector I/O and network error propagation. Removing the idempotence guard fails
the regression. The Duo release image retains the USB slab in `.dma`; QEMU
selftest passes 390 checks. These are composition checks, not physical Duo USB
or Mars validation. Mars firmware, GMAC5, boot firmware, the flashable SD image
and the planned physical acceptance remain outstanding.

### VirtIO transport and contract separation stage

QEMU firmware now supplies device discovery and transport lifecycle operations.
Kernel tokens preserve slot/base/IRQ/vendor diagnostics but cannot read or write
registers. Firmware reprobes only trusted windows, rejects mismatched descriptor
identity, and reports failed reset on an invalid descriptor. DMA release and
quarantine remain kernel policy. The MMIO-free VirtIO protocol implementation
and its 44 existing regressions moved to `contracts/virtio`, with the old driver
crate retained as a compatible re-export.

The dependency gate checks all declared workspace production edges, including
optional features and build dependencies. Kernel/HAL/contracts cannot depend on
concrete drivers or BSPs; drivers cannot depend on kernel or BSPs. QEMU and Duo
now pass this gate. This establishes the crate dependency boundary, while
board-feature/service decoupling and the remaining CV1800B SoC resource split
remain work in the architecture phase. Mars hardware and SD-image acceptance
are still outstanding.

### Ethernet SoC and DMA separation stage

CV1800B Ethernet clocks, PHY calibration and C906 cache instructions now reside
in the platform crate. Firmware selects the platform callbacks; DWMAC receives
only MAC resources, PHY address, DMA limits and those callbacks. SoC/eFuse
apertures were removed from its resource description. Existing diagnostic words
and PHY tuning are preserved. An early platform error leaves the controller
untouched and permits retry. DMA spans are checked against the platform's
32-bit address limit and 64-byte cache isolation before controller setup.

The golden sequence in `platform/cv1800b/tests/ethernet-sequence.txt` was captured
from commit `e831630` with mocked MMIO and delays: 226 entries cover the complete
write/delay sequences for fallback and calibrated eFuse cases. Mutating the PHY
link-removal tuning fails the regression. Host tests also cover callback span
and direction, failed setup rollback and DMA address boundaries. These checks
plus Duo compilation and QEMU regression do not validate physical Ethernet,
cache coherence, or Mars entropy. DWC2 still needs its remaining SoC split;
shared MDIO/PHY helpers and Mars EQoS/SD integration remain pending.

### USB SoC and cache separation stage

DWC2 no longer receives TOP/PHY apertures or embeds C906 cache instructions.
Firmware selects CV1800B platform preparation, rollback, diagnostics and the
shared DMA operation table. The original clock/host-role/UTMI pulse/100-us delay
sequence and reverse-order clock rollback are preserved. Initialization errors
before platform success do not invoke core accesses or rollback; core errors
after successful preparation consume the platform token and release the claim.
The fixed DMA pool is checked for controller reach and cache isolation.

Host tests cover the exact preparation/rollback event sequence, retry after
both failure classes, minimum delay/timer wrap and DMA ownership directions.
Removing rollback fails the driver regression. QEMU regression and Duo builds
remain software evidence only; no Duo UTMI timing or Mars DMA/entropy validation
is claimed. Board-feature/service decoupling, shared PHY support, Mars firmware,
boot components and the flashable SD image still remain to be implemented.

### Reusable provisioned services stage

The kernel now exposes `provisioned-ssh`, `provisioned-command`,
`provisioned-wasmtime`, and `dhcp-iperf3-server`. The old `milkv-ssh`,
`milkv-command`, `milkv-wasmtime`, and `milkv-iperf3-server` aliases remain.
The command entry includes its WASI dependencies directly, so it can be built
without relying on a board wrapper to add them. Firmware chooses entropy
separately: Duo's new service entries explicitly select the existing jitter
provider; QEMU's provisioned entry uses VirtIO RNG. New platforms do not
implicitly inherit Duo entropy or acceptance identities.

Build examples (run inside the corresponding firmware directory):

- QEMU: `cargo build --release --features provisioned-command`
- Duo SSH: `cargo build --release --no-default-features --features provisioned-ssh`
- Duo Wasmtime: `cargo build --release --target riscv64gc-unknown-none-elf --no-default-features --features provisioned-wasmtime`

Wasmtime still requires LP64D; adding floating-point instructions to the IMAC
LP64 target does not satisfy its ABI. The reusable production service also
requires an explicitly selected entropy provider. Mars must add and qualify
its own provider before enabling formal SSH.

`scripts/qemu-provisioned-service-test.py` exercises a freshly built QEMU
`provisioned-command` ELF using a temporary 128 MiB data disk matching the
file-tree image policy, real VirtIO entropy, four harts and two boots. It checks
identity persistence, VSH `ssh-keygen`/`ssh-keycat`, matching persisted/public
client keys and absence of automatic authorization. It forwards no SSH port
and deletes the identity-bearing disk afterwards. This does not claim SSH/WASM
transport or physical entropy qualification. The VSSHKEY1 encoding is unchanged.

### CPU admission and live DTB probe stage

`vibeos-hal::fdt::Fdt::cpus` reads a bounded CPU inventory without allocation.
It validates the unique `/cpus` node, cell widths, hart IDs, scalar strings,
compatible lists and nonzero timebase. Duplicate IDs, duplicate consumed
properties and insufficient inventory capacity reject the handoff. Disabled
CPU entries remain available to board policy; nested interrupt-controller and
CPU-map nodes do not become harts. Both one-cell and two-cell hart IDs retain
their full value.

`vibeos_bsp_milkv_mars::harts::admit` accepts only enabled U74-MC harts 1–4,
Sv39, the 4 MHz timebase and the image's RV64IMAC/optional FD requirements.
It accepts the pinned Linux and U-Boot ISA spellings; letters inside named
extensions cannot supply missing base capabilities. The actual boot hart is
logical slot zero, followed by the remaining admitted physical IDs in order.
A bad boot hart fails; an incompatible secondary produces a reduced inventory
with `is_four_core() == false`. Even an enabled S7 is excluded.

The synthetic fixtures under `hal/tests/fixtures/cpus*.dts` project CPU facts
from the SDK revision in `boards/milkv-mars/sdk-reference.json`; they are not
complete boot device trees. Regenerate each with `dtc -I dts -O dtb -o NAME.dtb
NAME.dts`. Host tests cover every U74 boot choice, disabled/incompatible CPUs,
FP requirements, 64-bit IDs, malformed declarations and bounded bit mutations.
Deliberately removing disabled-hart filtering or duplicate-ID rejection fails
the corresponding regression.

For a live software check, build in `firmware/qemu-virt` with
`cargo build --release --features boot-dtb-probe,legacy-shell`, then run from
the repository root:

```sh
python3 scripts/qemu-boot-dtb-test.py \
  --kernel target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt \
  --output target/boot-dtb-evidence
```

This opt-in probe captures CPU/timebase facts before heap initialization and
keeps no references into the DTB. QEMU's highest advertised mode is Sv57;
Sv48/Sv57 also support Sv39 under the
[RISC-V privileged specification](https://docs.riscv.org/reference/isa/priv/supervisor.html).
The probe verifies firmware-selected harts and timebase, then runs the existing
390 target selftests. A DTB with a changed timebase is rejected before services.
`--dtb PATH --expect-rejection` exercises a deliberately invalid handoff.

These checks do not yet wire Mars admission into a production Mars boot entry.
SBI extension probing, live Mars resource/memory publication, four physical
hart completion, SD/EQoS integration and the flashable image remain pending.
The opt-in QEMU probe is acceptance instrumentation, not a replacement for
those production checks or physical acceptance.

### Storage/network frontend selection stage

The Mars composition can now select `pio-block` and `packet-network` without
implicitly enabling Duo USB or its entropy provider. The four combinations of
PIO/queued block and packet/queued network frontends compile with generic
network/WASI/legacy-shell services and no kernel board profile. Conflicting
frontend selections fail compilation. Firmware owns the stable block device
identity and NIC driver label; existing QEMU/Duo identity values are preserved.

A real QEMU composition image with no kernel board profile passes live DTB and
390 selftests, block read/write and network handshake tests; recovery results
are recorded in `boards/milkv-mars/frontend-selection-evidence.json`.
This establishes the composition boundary, not JH7110 controller behavior.
Mars still requires its firmware entry, live admission/resource publication,
DW-MSHC/EQoS integration, boot components and the flashable SD image.

### DW-MSHC PIO service contract stage

The DW-MSHC engine now exposes bounded `read_blocks`,
`write_blocks_tracked`, `flush_tracked` and HAL-compatible diagnostics/errors.
Each request is validated in full before touching the controller, including
capacity, sector-address encoding, arithmetic overflow and the HAL's 256-sector
limit. Batches deliberately use single-sector CMD17/CMD24 transactions.
Optional write verification compares each completed sector before advancing.

The submission callback now runs immediately before the command-register
store. Previously it ran after the store, leaving a fault window in which a
possibly executed write could still appear unsubmitted. Batch writes invoke
it exactly once, and a failing command or mismatched readback makes the card
unavailable until firmware reconstructs it. Flush tracks only the first CMD13
and waits for ready-for-data in transfer state, including repeated status polls.

Fourteen driver model tests plus two SD protocol tests pass. Mutations moving
publication after the command store, validating only the first sector, or
ignoring verification mismatch each fail their regressions. The driver also
checks for the bare-metal RV64 target. The existing QEMU block-recovery test
passes, but exercises VirtIO and the shared kernel policy, not DW-MSHC hardware.
The register model does not prove JH7110 register layout, pin/clock sequencing,
FIFO timing or real media durability. Mars platform preparation, firmware-owned
instance registration and SD image integration remain outstanding.

### JH7110 SD platform preparation stage

`platform/jh7110` supplies SDIO1 clock/reset/pad preparation independently of
BSP wiring and the DW-MSHC controller engine. Mars supplies CLK/CMD/DAT0..3
GPIOs `[10,9,11,12,7,8]` and the 200 ms settling interval. The source files and
hashes are pinned in `boards/milkv-mars/jh7110-sd-reference.json`, including the
[official SDK board DTS](https://github.com/milkv-mars/mars-buildroot-sdk/blob/1fd6bac9f2efde47fbb8afd28d2903c49f893e3f/linux/arch/riscv/boot/dts/starfive/jh7110-milkv-mars.dts).

Preparation reads the running bus/AXI divider and integer PLL2 configuration.
For PLL2 at 1188 MHz and AXI_CFG0 divide-by-three, a divide-by-eight SDIO1 clock
is 49.5 MHz. The returned actual source rate must be passed to the BSP's
`sd_controller(source_hz)`. There is no ready-to-use nominal 50 MHz controller
description. The subsequent MSHC divider keeps the data clock at or below
25 MHz. Fractional/powered-down PLLs, disabled shared parents, zero dividers,
invalid resources and unsupported GPIO wiring are rejected before writes.
The paired boot firmware must establish the supported parent clock tree.

The platform enables the slot AHB clock, requests and checks reset, disables
and configures the card clock, installs the six pin routes, then enables the
clock and releases reset. It waits for the board-supplied settling interval.
Shared PLL/bus settings, SDIO0 and unowned register bits are preserved. Polling
has both elapsed-time and iteration bounds. A post-write failure requests reset
and disables the card clock; missing reset acknowledgment does not establish
hardware quiescence, so the controller engine must not be registered afterwards.
Firmware must exclude concurrent access and explicitly prepare again to retry.

Host tests cover clock decoding, route fields and reserved bits, sequence,
resource validation, timer wrap, reset timeout cleanup and retry. The optional
`jh7110-sd-model-test` feature of `firmware/qemu-hal-test` executes the same
platform code under RV64 QEMU using an explicit register model. It reports
`JH7110_SD_MODEL PASS` and is followed by the existing 390 kernel selftests.
This is not JH7110 MMIO, pad timing or real card testing. Mutations substituting
a nominal clock, dropping timeout cleanup or overwriting reserved pad bits
fail the host regressions.

The Mars firmware entry, live DTB resource publication and registration of the
prepared DW-MSHC instance remain to be connected. EQoS, paired boot components,
the flashable SD image and physical acceptance are still outstanding.

### Pre-MMU firmware admission stage

The optional `BootPlatform::admit_boot` callback runs once on the boot hart,
prior to timebase configuration, page tables, heap initialization and secondary
release. Its `BootRequest` carries the physical hart, DTB pointer, RAM envelope,
static image/stacks/pools span and heap envelope. `BootRequest::dtb` bounds the
aligned header and complete blob (at most 1 MiB) before parsing. Physical
readability is still an obligation of the boot handoff; pointer arithmetic alone
cannot establish it. Rejection initializes the UART for a diagnostic and asks
SBI to shut down, without publishing device services.

Hart IDs and timebase are now firmware callbacks, allowing a composition root
to publish copied, immutable metadata after admission. QEMU and Duo production
images retain their existing static topology/timebase through these callbacks.
The optional `boot-admission-test` image in `firmware/qemu-hal-test` validates
its four CPUs, Sv39 support, timebase and static memory against a live DTB,
then publishes boot-hart-first IDs and timebase with release/acquire ordering.
No borrowed DTB pointers survive. Repeated publication fails.

```sh
(cd firmware/qemu-hal-test && cargo build --offline --locked --release --features boot-admission-test)
python3 scripts/qemu-boot-dtb-test.py \
  --kernel target/riscv64imac-unknown-none-elf/release/vibeos-qemu-hal-test \
  --output target/mars-reference/admission-run --require-admission
```

The live QEMU run verifies one publication, four harts and 390 passing kernel
selftests. A wrong-timebase DTB is rejected before the kernel banner/heap.
Host tests exercise bounded DTB access, invalid CPU/memory/timebase rejection,
nonzero boot-hart ordering and repeated publication. Mutations that remove
memory or timebase rejection or permit republishing are detected. Python
ordering guards cover placement before MMU/heap/SMP. Host tests cannot prove
physical address decoding, RV64 cache visibility or hardware fault behavior;
QEMU does not qualify Mars hardware.

This is an admission interface and a QEMU acceptance composition, not production
Mars admission. The subsequent disjoint-heap stage below connects reservation-aware
allocation. Mars resource validation and SBI qualification remain required before
registering Mars devices or producing the SD image.


### Reservation-aware heap stage

`Heap::init_regions` accepts up to 16 sorted, disjoint RAM ranges without
allocating metadata. Initialization validates and trims alignment before changing
allocator state. Adjacent ranges merge; a reserved gap never merges. Each extent
has its own bump cursor. Free-list reuse, pressure coalescing and tail rewind
work across the admitted extents while preserving gaps. Fault-domain recovery
checks that both headers and complete allocation blocks belong to a used prefix
of one extent before dereferencing them. Live-byte accounting and persistent
formats are unchanged. The existing single-range initializer remains available.

`BootRequest::usable_heap` clips a reservation-subtracted `BootMemory` to the
linker heap envelope, validates the static image span and discards partial pages
around reservations. Its host test covers the Mars 4 GiB range, including RAM
above physical address 4 GiB. `BootPlatform::heap_regions` publishes the immutable
result; the kernel checks the linker envelope and initializes these ranges.
QEMU and Duo production compositions retain their existing single-range policy.
The QEMU admission composition now uses the real DTB memory/reservations and
publishes two heap ranges in the 128 MiB live boot test. The reported usable
capacity agrees with the kernel allocator's initial capacity.

The updated `--require-admission` test requires the heap metadata/capacity check
and 395 successful selftests. Five additional on-target checks allocate from
both sides of a canary-filled hole, exhaust them, recycle allocations and verify
that a larger request cannot merge across the hole. Host regressions also reclaim
one fault domain spanning both ranges, verify transactional initialization errors,
merge adjacent ranges and exercise the live-byte telemetry feature. Mutations
merging a reserved gap, suppressing per-extent tail rewind and rounding a
reservation inward are detected.

This stage does not remove reserved RAM from every identity mapping, qualify
Mars DMA/cache behavior or establish the device/firmware reservations for a Mars
image. Those must be supplied by the production Mars composition. SBI probing,
DW-MSHC registration, EQoS, paired boot firmware and an SD image remain pending.

### Console/SD DTB resources and Mars BSP composition

`boards/milkv-mars::resources::admit` now validates the pinned SDK console/SD
resources before returning their actual DTB apertures: UART0, PLIC, SDIO1,
SYS CRG, SYS SYSCON and SYS pin controller. The SYSCON aperture is 4 KiB in
this DTB, despite the broader static mapping envelope. The runtime platform
binding should use the returned aperture. UART register shift/width, SD FIFO
and bus width, IRQ numbers, enabled state, parent controller and PLIC source
count must match the supported board configuration. Only the first clock
controller register window is consumed; its additional STG/AON windows are not
implicitly admitted for access by this API.

The parser requires an enabled root `/soc` simple bus with two address and size
cells and empty identity `ranges`. It does not guess unsupported translations.
It resolves CPU interrupt-controller phandles, verifies the nine PLIC context
slots (S7 M, followed by four U74 M/S pairs), and detects ambiguous related
phandles anywhere in the DTB, including matching legacy aliases. Global phandle
inspection is bounded to 32 node levels. Machine contexts may retain IRQ 11 or
be masked as `0xffffffff`, as in the official
[OpenSBI v1.6 fixup](https://github.com/riscv-software-src/opensbi/blob/v1.6/lib/utils/fdt/fdt_fixup.c).
Supervisor slots must remain IRQ 9 for the matching physical hart. This reference
does not select the eventual paired OpenSBI version.

The Mars BSP now implements the static firmware composition contract with
standard PTE attributes, 2 MiB RAM leaves and six sparse device page-table
windows. It reserves 2051 RAM page-table pages for `0x40200000..0x140000000`.
No SDHCI or legacy DWMAC description is supplied. This description establishes
mapping requirements, not readiness of a controller, DMA pool or PHY.

`resource-reference.json` records all 16 fetched DTS/include source hashes,
SDK commit, preprocessing tools and the complete compiled 52,701-byte official
Mars DTB hash. It passes memory, resource and four-hart admission with boot
hart 4. Vendor DTS warnings are retained in the evidence log. The focused
checked-in fixture is a separate model, not the official or production boot DTB.

```sh
cargo run --offline --locked -p vibeos-bsp-milkv-mars --example inspect_dtb -- \
  path/to/mars.dtb 0x48000000 4
(cd firmware/qemu-hal-test && cargo build --offline --locked --release \
  --features boot-admission-test,mars-resources-test)
python3 scripts/qemu-boot-dtb-test.py \
  --kernel target/riscv64imac-unknown-none-elf/release/vibeos-qemu-hal-test \
  --output target/mars-reference/resource-run --require-admission
```

The physical DTB address and boot hart in the inspection command are explicit
inputs; they are not a bootloader configuration. The optional RV64 image runs
the focused Mars parser fixture and prints `MARS_RESOURCES_MODEL PASS`, then
runs the QEMU boot/heap admission and 395 selftests. Host mutations removing
UART-width checks, supervisor IRQ validation, duplicate-handle rejection or
identity-bus restrictions fail their regressions. Neither this model nor host
inspection exercises Mars MMIO, SBI HSM, clock preparation or physical boot.
The production Mars entry, SD instance/data partition binding, GMAC/PHY/DMA
resource validation and engine, paired boot firmware, SD image and physical
acceptance remain outstanding.


### Mars serial/SD bring-up firmware

`firmware/milkv-mars` now supplies the final entry, boot description, early
UART/PLIC tables and a firmware-owned DW-MSHC instance. Boot admission requires
four DTB-admitted application harts and SBI HSM, IPI, RFENCE and TIME extension
probes. It publishes only copied resource/hart/heap metadata. A missing extension
or invalid handoff fails before MMU/heap/service initialization. Extension probes
are not proof that all harts subsequently start or that remote fences work on
Mars; those remain physical acceptance requirements.

The linker loads at `0x40200000`, reserves four guarded stacks and maps the
4 GiB RAM envelope ending at `0x140000000`. The kernel now reads the heap ceiling
as a firmware value, avoiding a PC-relative address of a linker symbol more than
2 GiB away under RISC-V medany. QEMU's large-memory profile intentionally retains
its original 128 MiB heap ceiling. QEMU and Duo production layouts are unchanged.

The SD binding uses the admitted SYS CRG/SYSCON/pin apertures, prepares SDIO1,
passes the decoded source rate to MSHC and publishes a data-only device.
Its fixed image-layout contract is **physical LBA 262144, 1048576 sectors**
(128 MiB offset, 512 MiB data, 512-byte sectors). The boot image packer must reserve
all boot components/partitions below that boundary. This image is not a general
partition-table autodetector and must be paired with the matching test SD layout.
Media too small for the complete data range is rejected. Every read/write checks
the full logical run before translating it; no raw probe operation is exported.
`bounded-device` is a generic zero-based image policy, with compile-time agreement
between its capacity and the firmware data boundary. Other firmware retains its
existing policy and data format. Standard RISC-V I/O fences surround MSHC MMIO;
model tests cannot qualify the real interconnect ordering or SD durability.

The packet-device contract now distinguishes an absent firmware slot. Discovery
publishes no NIC/MMIO/DMA capability for that slot, and the engine rejects claims
before calling hardware operations. Mars currently uses this state: EQoS, network
and SSH are explicitly unavailable in this bring-up image. No entropy provider
or provisional SSH identity has been enabled. This is a temporary bring-up
composition; it does not satisfy the planned network/SSH acceptance.

Build the payload and inspect its layout with:

```sh
scripts/build-milkv-mars.sh
# target/milkv-mars/bringup/{vibeos.elf,vibeos.bin,elf-check.json,manifest.json}
```

The ELF checker requires the correct architecture/entry, non-overlapping identity
loads outside firmware-reserved RAM, no writable executable load, the full 64-bit
heap ceiling, writable BSS and four guarded stack reservations. It checks layout,
not boot instructions or hardware behavior. The manifest records hashes, source
revision/dirty state, compiler, SDK revision and the data layout. These artifacts
are **not an SD image** and do not yet bundle SPL, OpenSBI, U-Boot, a FIT handoff
or a qualified production DTB. Do not treat the raw payload as a disk image.

Host tests cover SBI admission failure, reserved DTB pages, complete partition
bounds, write-publication timing/error forwarding and absent NIC rejection.
`firmware/qemu-hal-test` can run the same Mars admission and partition logic
under RV64 with `boot-admission-test,mars-composition-test`, followed by 395
kernel selftests. Its hardware resources are models. The 4 GiB QEMU profile
passes 393 tests, including the existing high-memory probes, and the ordinary
QEMU profile and Duo build are retained. Mutations removing the HSM requirement,
partition offset enforcement, absent-NIC claim guard or ELF heap-ceiling check
are detected. Physical Mars serial, SD, four-core and fence behavior, EQoS/DMA,
entropy, SSH/WASM acceptance and the bootable SD packaging are still pending.

### Paired boot firmware and test SD image

The stage above's missing boot packaging is now implemented. Run
`sh scripts/build-mars-sd.sh` to produce
`target/mars-boot/out/mars-serial-sd.img`, a 641 MiB regular disk image with
official SPL/DDR initialization, OpenSBI 1.2, U-Boot 2021.10, VibeOS FIT and
the exact previously admitted SDK Mars DTB. The pinned Ubuntu tools container
builds on this host's Linux/aarch64 Docker environment with GCC 11.4/binutils
2.38; the output contains complete tool/package versions and configs.

The SPL/firmware partitions retain SDK offsets/types. The FAT boot partition
ends at 128 MiB; the 512 MiB VibeOS data partition begins there, matching the
firmware's enforced block window. The data partition is initially blank. The
packer only creates a new regular file and refuses existing paths, including
device nodes and symlinks. It does not write an SD card or change SPI.

The paired U-Boot uses no persistent SPI environment, runs without S-mode SMP,
and loads `vibeos.itb` from SD partition 3 at `0x46000000`. The FIT requests the
RISC-V Linux `bootm` calling convention at `0x40200000`. SPL SMP is retained;
the compiled OpenSBI ELF contains HSM, IPI, RFENCE and TIME extensions. Those
static facts do not prove actual secondary-hart startup or handoff behavior.

Five host image tests include CRC corruption, a rechecksummed partition-boundary
mutation, payload tampering, nonblank data and overwrite rejection. Two tests
in the tools container inspect actual boot artifacts and detect SPL CRC, HSM,
SPI environment and FIT payload mutations. Independent GPT/FAT checks pass.
The compiled DTB hash matches `resource-reference.json`; the VibeOS payload
hash matches the stage-24 ELF build. No new real-Mars or emulator boot of this
Mars boot chain has been performed. Evidence is recorded in
`boards/milkv-mars/bootchain-image-evidence.json`.

See [boot instructions](../firmware/milkv-mars/bootchain/README.md) for hardware
revision and SD-selector requirements. The image is suitable for writing to
the selected test card, but **the Mars port remains incomplete**: physical
serial/four-core/SD qualification, EQoS/DMA, entropy, SSH/WASM, three cold boots
and the one-hour concurrent stability run remain required.
