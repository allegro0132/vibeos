# Milk-V Mars port status

Target: standard Milk-V Mars with 4 GiB RAM, microSD boot, serial and SSH
acceptance. This is an **incomplete port**. Separate 641 MiB serial/SD and
EQoS DHCP/iperf3 test images build with paired SPL/OpenSBI/U-Boot. Physical
qualification, qualified entropy and SSH remain outstanding.
See [image instructions](../firmware/milkv-mars/bootchain/README.md).

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

### Shared MDIO and EQoS controller encodings

`drivers/ethernet` now owns bounded Clause 22 read/write sequencing and the
double BMSR read needed for current link status. `drivers/dwmac-net` uses this
code with its legacy register transport; a register-array test checks the old
offsets and command words. An all-ones PHY response is treated as unavailable.
Packet/client contracts and persistent data formats are unchanged.

`drivers/eqos-net` adds a separate transport for GMAC4/5 PA/RDA/GOC fields and
CSR-clock selection, plus single-buffer TX/RX descriptors. It validates the
entire 32-bit DMA span, leaves OWN unpublished in prepared descriptors, rejects
error/context/fragmented completions, bounds lengths, strips retained FCS from
the reported RX length and computes DSL using AXI width. The pinned reference
manifest is `boards/milkv-mars/eqos-reference.json`.

Twenty-two host tests pass across shared Ethernet, EQoS and legacy DWMAC. The
RV64 register/descriptor model reports `EQOS_MODEL PASS`, followed by 395
kernel selftests. The Duo release build and dependency boundary check pass.
Mutations dropping the latch-clearing read, changing the EQoS PHY address
shift to the Duo value, and changing OWN from bit 31 are detected and restored.
Evidence is in `boards/milkv-mars/eqos-codec-evidence.json`.

This is still **not a working Mars NIC**. Ordered live ring publication and
reclamation, reset/quarantine behavior, JH7110 clocks/pins/cache maintenance,
PHY/RGMII setup, resource admission and the firmware packet instance remain
to be implemented and qualified. The stage-25 SD image continues to identify
itself as serial/SD-only; no unqualified SSH or entropy provider is enabled.

### EQoS ring ownership and recovery

The EQoS driver now implements a serialized TX/RX ring state machine with four
separately validated DMA spans, fixed 64-byte descriptor isolation and 1536-byte
buffers. TX preserves a spare slot, reaps in FIFO order, synchronizes packet
and descriptor data, publishes OWN last, and only then advances the tail. RX
uses the driver's private buffer map, copies a validated frame without FCS,
and returns the slot to DMA; malformed frames and undersized destinations are
dropped without copying. Processing loops are bounded by the ring count.

Start/stop failures, TX descriptor errors and explicit timeout faults quarantine
the ring. A successful reset must prove hardware quiescent before descriptors
or buffers are initialized again. Abandoned TX packets are not retried. The
backend/pool has permanent storage and remains exclusively borrowed; dropping
the ring does not free DMA storage. Arithmetic validation is supplemented by
the backend's required admission against the actual dedicated pool.

Ten ring host tests plus the existing 22 Ethernet tests pass. The RV64 model
reports `EQOS_RING_MODEL PASS`, followed by 395 kernel selftests. Mutations
skipping reset, omitting OWN publication and filling the reserved TX slot are
detected. Evidence is in `boards/milkv-mars/eqos-ring-evidence.json`.

The concrete MMIO/cache backend, JH7110 platform/PHY preparation and firmware
packet instance are still pending. Neither host traces nor the RV64 DMA model
proves actual DMA ordering, cache maintenance, network connectivity or shutdown
on Mars. The test SD image remains serial/SD-only.

### EQoS register controller and ring adapter

The driver now has an ordered MMIO register implementation and a single-queue
GMAC4/5 controller. Configuration validates actual FIFO size encodings, programs
MAC speed/duplex, store-and-forward queues, conservative DMA bursts, descriptor
bases/lengths and DSL, and retains FCS to match the RX codec. It keeps checksum,
TSO, extended DMA addressing, promiscuous filtering and unnegotiated pause off.
The polled frontend does not enable DMA interrupts.

Reset uses one SWR publication, a counter deadline plus a finite poll cap, and
disabled channel/MAC readback. Stop follows the same reset handshake so old
packets are abandoned rather than retried. Reset/start readback failures keep
the ring quarantined. `backend::Backend` connects the controller to the ring
and a separately admitted permanent DMA memory provider. Actual memory/cache
implementation remains a platform responsibility.

Twelve controller/adapter/MMIO host tests plus the prior 32 Ethernet tests pass.
The RV64 ring model now executes this controller's configuration and failed
reset path, reports `EQOS_CONTROLLER_MODEL PASS`, and runs 395 kernel selftests.
Mutations skipping reset completion, changing TX descriptor base, enabling FCS
stripping and bypassing pool admission are detected. Evidence is recorded in
`boards/milkv-mars/eqos-controller-evidence.json`.

These checks do not qualify JH7110 bus-reset completion, cache visibility or
physical link behavior. The next required integration is the SoC's clock/reset,
PHY/pinmux and DMA/cache provider, followed by firmware registration and physical
network/SSH acceptance. The SD image is still the serial/SD bring-up profile.

### JH7110 cache service and permanent EQoS DMA pool

HAL now has an instance-owned `DmaCache` visibility contract in addition to the
existing static callback table. `platform/jh7110/cache.rs` implements the pinned
SDK's SiFive L2 FLUSH64 sequence, including hardware line-size/way checks,
complete physical-address writes and per-line barriers. It rejects partial
lines and invalid RAM ranges and does not use the uncached alias or T-Head ISA.
The source manifest is `boards/milkv-mars/jh7110-cache-reference.json`.

The independent EQoS `Pool` provides aligned permanent storage and explicit CPU
versus physical views. Construction validates the whole 32-bit-addressable pool
and each cache operation span; callbacks enforce descriptor/packet slot types,
directions and bounds. Host tests use deliberately different CPU/physical
addresses to catch identity-mapping assumptions. A QEMU composition test now
combines the real pool, ring, controller and JH7110 cache service, with only
hardware register/DMA effects modeled, and reports `EQOS_POOL_MODEL PASS`.

Five cache and five pool tests, the relevant HAL/controller/SD tests, and 395
QEMU kernel selftests pass. The Duo release build and dependency guard pass.
Mutations truncating FLUSH64 addresses, removing per-line barriers, accepting
wrong cache geometry and shifting CPU offsets are detected. Evidence is in
`boards/milkv-mars/eqos-cache-pool-evidence.json`.

No actual JH7110 cache operation or GMAC DMA transaction has run on Mars. DTB
admission of GMAC/cache resources, clock/reset/pinmux and PHY preparation,
production pool reservation/registration, network/SSH and physical stability
qualification remain required. This stage does not change the serial-only
network status of the previously generated test SD image.

### GMAC0 and cache resource admission

`network_resources::admit` now validates the pinned GMAC0 register window, PLIC
interrupts, ordered clock/reset references and provider geometry, AON SYSCON,
cache geometry, and vendor PHY tuning. It rejects provider aliases, duplicate
properties, changed resources and alternative PHY bindings. The admission is
separate from console/SD admission so an old serial-only fixture cannot silently
enable networking. AON CRG/SYSCON now has a page-granular mapping and its own
reserved level-zero page table.

The official SDK's `ethernet-phy@0` has neither `reg` nor `phy-handle`. Admission
therefore returns tuning values without inventing a PHY address or identity;
MDIO discovery and supported-ID validation remain required before enabling the
link. Likewise, the DTB's `dma-coherent` hint does not replace the cache service
or actual multicore DMA qualification.

The complete pinned SDK DTB passes `inspect_network`. Five network admission
tests plus 18 prior BSP tests pass, including resource substitution and malformed
binding cases. The RV64 firmware reports `MARS_NETWORK_RESOURCES PASS` and runs
395 kernel selftests. Mutations removing cache-line validation, provider handle
uniqueness, and duplicate-property rejection are detected. Source hashes and
validation evidence are in `boards/milkv-mars/network-resource-reference.json`
and `boards/milkv-mars/network-resource-evidence.json`.

This stage admits descriptions only: JH7110 Ethernet clock/reset programming,
PHY discovery/configuration and production device registration remain pending.
The existing SD image continues to be the serial/SD bring-up profile.

### Shared PHY discovery and YT8531 configuration

`drivers/ethernet::phy` now provides read-only Clause 22 discovery across an
explicit address mask. The YT8531 frontend requires the exact supported ID,
owns its MDIO port, validates board tuning before I/O, and revalidates identity
before soft reset. Reset and all transactions have finite poll budgets; a
failed configuration remains unavailable. Extended-register writes preserve
unrelated fields and verify readback. The initial advertisement supports full
duplex at 10/100/1000 Mbps without pause, matching the EQoS datapath.

Ordinary link polling performs reads only. It requires completed negotiation,
resolved vendor status, and a stable second sample. The caller must stop MAC/DMA
before invoking the separate speed-dependent TX inversion configuration. Any
configuration or MDIO error invalidates the initialized state; no failed write
is replayed. EQoS re-exports the shared speed type, preserving its existing API.

Eight new PHY tests cover discovery ambiguity, register preservation, reset and
readback failures, every initialization transaction failing in turn, link
changes, and timeout recovery. Together with existing Ethernet/EQoS/Duo tests,
57 host tests pass. The RV64 model composes the real EQoS MDIO transport and PHY
frontend and reports `YT8531_MODEL PASS`; 395 kernel selftests pass. Four mutations
removing reset proof, preserving the wrong drive bits, bypassing readback and
failing to quarantine are detected. Sources and evidence are in
`boards/milkv-mars/phy-reference.json` and `boards/milkv-mars/phy-evidence.json`.

Actual PHY identity, electrical timing and Ethernet clock/reset programming are
not qualified by these models. Mars firmware device registration and network,
SSH/entropy and physical acceptance still remain; the SD image is unchanged.

### JH7110 GMAC0 clocks, reset and pads

The platform module now prepares GMAC0 using actual integer PLL and bus-divider
readback. It derives the CSR clock from STG_AXI/AHB separately from GTX, sets an
exact 125 MHz GTX rate through the local divider, and leaves shared PLLs and bus
dividers unchanged. The Mars external RGMII TX parent is corroborated by the
upstream v6.12 Mars DTS; it follows the PHY's negotiated speed without changing
shared clocks. The pinned vendor SDK remains the register/reset/pad reference.

Preparation requires boot firmware to have released the shared AON pin block.
It asserts the two MAC resets, checks acknowledgment, programs the MAC-owned
clocks/RGMII selection and board-supplied TX drive, then releases reset with a
bounded acknowledgment wait. Masked configuration writes require readback.
Failures request reset and disable TX clocks; this cleanup is explicitly not
DMA quiescence proof and cannot permit memory reuse. Existing MAC/DMA must have
been stopped before preparation. The BSP now admits/maps the AON pin aperture.

Eight platform tests plus the prior BSP/cache/SD tests pass (42 total). The RV64
model passes its decoded 198 MHz CSR rate to the real EQoS MDIO/YT8531 frontend,
checks reset failure, and reports `JH7110_ETHERNET_MODEL PASS` alongside 395
kernel selftests. Mutations dropping reset acknowledgment, substituting GTX for
CSR rate, broadening the pad mask, and omitting failure TX gating are detected.
Sources and evidence are recorded in `boards/milkv-mars/ethernet-platform-reference.json`
and `boards/milkv-mars/jh7110-ethernet-platform-evidence.json`.

Actual clocks, reset synchronizers, pad electrical behavior and PHY/carrier are
still unqualified. Production Mars packet-device assembly and physical network,
SSH and stability acceptance remain required. The existing SD image remains
the serial/SD bring-up profile.

### Packet link lifecycle prerequisites

EQoS now permits changing the next MAC speed/duplex only while stopped and
invalidates the previous controller configuration. A ring can return its owned
backend before first start or after successful shutdown; running or quarantined
rings retain ownership. This allows firmware to coordinate PHY phase changes
and MAC configuration without reaching through live DMA references.

The kernel packet adapter now polls PHY by elapsed time before processing the
packet batch. Previously, only idle iterations advanced its PHY poll counter;
an outbound DHCP packet waiting for the first link could keep the task busy and
prevent it from observing that link. A pending packet with no DMA-owned TX now
uses the normal sleep/retry path, while active descriptors retain fast polling.
Capability/session admission and hardware timeout policy remain in the kernel.

Two controller/ownership tests and two cadence tests pass along with the prior
related tests (41 total). The RV64 model exercises stopped backend reuse and
the real cadence helper, reports `PACKET_LINK_MODEL PASS`, and runs 395 kernel
selftests. Mutations removing the running-state guard, releasing a live backend,
keeping stale configuration and shifting the poll deadline are detected.
Evidence is in `boards/milkv-mars/eqos-link-lifecycle-evidence.json`.

The QEMU model does not exercise actual Mars carrier changes or the complete
packet-task/DHCP path. Firmware packet-device assembly and physical tests are
still required before claiming Mars Ethernet or SSH support.

### Static Mars packet-device assembly (test profile)

`sh scripts/build-milkv-mars.sh --ethernet` composes the admitted JH7110
clock/reset/pad service, YT8531 PHY, EQoS controller, permanent DMA pool and HAL
packet operations. The optional payload includes DHCP and the existing TCP 5201
iperf3 service; it does not enable SSH. The default build remains serial/SD.
Network payloads and their ELF checks/manifests are placed separately under
`target/milkv-mars/ethernet`. The current generic test MAC is
`02:00:00:00:00:01`; use only one such test image per network. Independent identity
configuration remains required for the formal image.

Firmware retains the ring throughout link transitions and fault recovery. It
proves DMA stopped before changing PHY phase or MAC speed, and publishes a link
only after configuration/start succeeds. Failed stop keeps the permanent pool
quarantined; retirement cannot resume the old engine. Kernel capability,
session, scheduling and recovery policies remain outside the hardware drivers.
The NOLOAD DMA slab is explicitly initialized, 64-byte aligned, 102400 bytes,
below 4 GiB and outside the heap; artifact checks enforce these properties.

This integration found two boot defects. LTO could reorder the cold entry after
other `.text.boot` objects; Mars now keeps a distinct entry section first and
asserts its address equals the FIT load address. Also, the network-resource
mapping additions in stages 30–33 required seven device level-0 tables while
the kernel reserved six, causing an unconditional MMU startup failure. The HAL
now declares a shared capacity of eight, and firmware checks board requirements
at compile time. Earlier ELF-only reports did not detect that startup failure
and must not be interpreted as boot evidence. The earlier stage-25 SD file is
unchanged and predates those mapping additions.

Eleven host firmware tests and four ELF checker tests pass. The RV64 acceptance
image uses the real kernel mapper with seven device windows, then exercises the
real pool/cache/controller/PHY/coordinator with modeled device effects: initial
link down, gigabit TX, disconnect, 100 Mbps reconnect and retirement. Its
`MARS_PACKET_ENGINE_MODEL PASS` marker accompanies 395 kernel selftests. Mutations
removing stop proof, candidate verification and retirement are detected by host
tests; reducing MMU capacity back to six fails at compile time. Evidence is in
`boards/milkv-mars/packet-composition-evidence.json`.

These tests do not execute the full DHCP packet task against real Mars hardware,
qualify PHY electrical timing, or prove multicore DMA/cache coherence. They also
do not qualify entropy, SSH, WASM over SSH, or the required cold-boot/stability
acceptance. Payload composition is not physical Ethernet acceptance.

### Network test SD image

`sh scripts/build-mars-sd.sh --ethernet` now builds and checks an independent
641 MiB image under `target/mars-boot-ethernet/out`. The first checked image is
`mars-ethernet-sd.img`, SHA-256
`8008a8780286ad90242f7e95d2025e1930c27801c24f0c97da505afee8da9e92`.
Its four partitions retain the existing data offset/capacity and persistence
format. The build checks both GPT copies, FAT, embedded FIT payload hashes,
SPL CRC, actual SBI extension symbols and U-Boot configuration. Five host SD
tests and two actual-artifact bootchain tests (including corruption mutations)
pass. Both profile scripts refuse existing image files before fetching sources.
The earlier serial/SD image was verified byte-for-byte unchanged.

Evidence is in `boards/milkv-mars/network-sd-image-evidence.json`; the image
directory holds its manifest, checksums, tool versions and component files.
No physical SD card was written and no SPI change was made. This is a DHCP/iperf3
bring-up image, with SSH disabled. Real cold boots, persistence, link recovery,
multicore cache/DMA, entropy and SSH/WASM stability remain unqualified.

### Passive serial acceptance collector

`scripts/mars-serial-accept.py` requires an explicit serial port, operator-reported
board revision and new evidence directory. It preserves raw bytes and a hash,
checks ordered Mars boot/four-hart/Sv39 markers, and waits the whole requested
interval so a late panic cannot be hidden by early boot success. Reboots,
truncated markers, interrupted captures and size limits cannot pass. It does
not send commands, select an SD device, verify a power cycle or grant physical
acceptance based on strings. See the bootchain README for its invocation.

Eleven tests include actual host PTYs for fragmented reads, no transmitted
bytes, TTY restoration, late panic, empty input, interruption and byte limits.
Mutations disabling late-panic rejection, repeated-boot detection or capture
failure status are detected. These are host capture-tool tests, not new kernel
or Mars runs. `boards/milkv-mars/serial-collector-evidence.json` records results;
all physical acceptance and stability gates remain outstanding.

### JH7110 TRNG command transport

`drivers/starfive-trng` is an independent `no_std` register-protocol crate. It
has no kernel, board or other crate dependency. Firmware must own the clocks,
shared SEC reset and PLIC mask; the driver never resets the SEC subsystem or
assumes that a disabled interrupt proves hardware stopped. It requires mission
mode with nonce mode off, verifies configuration readback, disables automatic
reseed counters and explicitly reseeds before each conditioned 256-bit block.

Both elapsed-time and poll-count limits bound waits. Stale completions are
acknowledged before issuing a command; the expected completion, idle state and
seeded/mode bits must agree before reading. Lockup during the copy invalidates
the whole block. Zero, all-one or consecutive repeated blocks are rejected.
Errors disable TRNG interrupts and permanently fault the instance; no automatic
reseed retry hides a failure. These checks are not statistical health tests,
an entropy estimate or permission to enable production SSH.

The final pinned Mars DTB has TRNG enabled at `/soc/trng@1600C000`, IRQ 30,
with vendor clock IDs 205/206 and shared reset ID 131. The base SoC file says
`disabled`, but the Mars board include overrides it to `okay`; the compiled
DTB is the authority. Crypto and security DMA also reference reset 131, so a
platform reset policy must account for all users. Exact references are recorded
in `boards/milkv-mars/trng-reference.json`.

Ten host tests cover commands, configuration, output publication and failure
paths. An RV64/QEMU model executes this same crate, including lockup during
copy and wrapped-clock timeout, with `JH7110_TRNG_MODEL PASS` and 395 kernel
selftests. Mutations disabling the deadline, duplicate detection, quarantine
or lockup handling are detected. Evidence is in
`boards/milkv-mars/trng-protocol-evidence.json`.

Production Mars firmware does not yet map, initialize or register this source.
Clock/shared-reset preparation, HAL service integration, physical behavior and
entropy qualification remain required. The existing test SD image and its
disabled SSH state are unchanged.

### TRNG resource admission and shared provider parsing

The BSP now admits the final Mars TRNG DTB node and exposes its exact register
window, IRQ, clock IDs and shared-security reset scope. A matching node is
required; a serial/network-only fixture cannot silently provide entropy.
Provider substitution, reversed clock ordering, interrupt-parent rerouting,
duplicate nodes/properties and any partially overlapping direct `/soc` register
alias are rejected. Adjacent crypto/security-DMA windows remain valid.
This description grants no exclusive ownership of the shared reset.

Clock/reset provider and strict node parsing are shared internally between
Ethernet and TRNG, preserving existing network admission behavior. Both
`inspect_trng` and `inspect_network` accept the actual pinned 52701-byte Mars
DTB. Seven new TRNG tests bring BSP host coverage to 30 passing tests. RV64
acceptance emits `MARS_TRNG_RESOURCES PASS` alongside the TRNG protocol model
and 395 kernel selftests. Four mutations weakening clock binding, overlap
rejection, IRQ-parent checking and duplicate-node detection are caught.

Evidence is in `boards/milkv-mars/trng-resource-evidence.json`. The new TRNG
resource description is not yet used by production firmware: its MMIO mapping,
platform clock/shared-reset lifecycle, HAL integration and physical entropy
qualification remain work before SSH can be enabled. No physical port was
opened or board state changed by this stage.

### Shared SEC_TOP platform lifecycle

`platform/jh7110/src/security.rs` now owns the two SEC clock gates and the
shared reset sequence. The vendor IDs 205/206 select STG CRG offsets `0x3c`
and `0x40`; reset ID 131 selects bit 3 of STG `0x74`, with acknowledgement at
`0x78`. The BSP resource description now supplies STG CRG at `0x10230000` in
addition to SYS CRG. These controls must not be addressed through SYS CRG.

Creating the domain requires explicit exclusive ownership of every SEC_TOP
client (TRNG, crypto and security DMA), a retained parent STG bus clock and
serialized CRG access. Preparation enables only the two child gates, asserts
and verifies reset, then releases and verifies it. Stop requires child
invocations to have ceased, asserts reset and waits before disabling clocks.
Readback errors or a bounded timeout retain a faulted owner; no Drop handler or
automatic retry resets hardware. Unrelated register bits are preserved.

Seven new platform tests cover ordering, partial writes, both reset directions,
wrapped timers, a frozen timer's poll limit, idempotent stop and invalid MMIO
apertures. Together with the existing platform/BSP tests, 56 host tests pass.
RV64 executes the same lifecycle with modeled STG registers and reports
`JH7110_SEC_MODEL PASS`, alongside the TRNG/resource models and 395 kernel
selftests. Mutations removing reset acknowledgement, gating before reset,
broadening the reset mask and removing the deadline are detected. Source and
evidence records are `boards/milkv-mars/security-platform-reference.json` and
`boards/milkv-mars/security-platform-evidence.json`.

These are protocol models, not physical stop/clock proofs. Production firmware
still needs to map STG/TRNG, establish this exclusive ownership and the parent
clock prerequisite, register the entropy service and collect physical entropy
evidence. The domain does not reprogram parent clocks or infer entropy quality.
SSH remains disabled in the existing test SD image.

### Security MMIO mapping coverage

The Mars BSP now maps the exact TRNG (`0x1600c000..0x16010000`) and STG CRG
(`0x10230000..0x10240000`) apertures with 4 KiB pages. Their neighboring crypto
and security-DMA windows remain unmapped. TRNG shares the SD/GMAC level-0 table;
STG needs an additional table, bringing the declared device window count to
eight. The static HAL capacity already reserves eight; no kernel board branch
or concrete driver dependency was added.

Two new host tests enumerate every device page and all four PLIC supervisor
contexts, verify exact table counts and ensure no overlap or accidental
neighbor mapping. BSP host tests total 32. The QEMU acceptance composition now
builds eight device windows through the real kernel mapper and reports
`DEVICE_WINDOW_CAPACITY PASS level0=8` with 395 kernel selftests. Removing either
security mapping or reducing declared capacity is detected by mutation tests.
Evidence is in `boards/milkv-mars/security-mapping-evidence.json`.

Mapping alone does not register or run a driver and does not prove physical
MMIO decoding. The shared-domain ownership, parent-clock preparation, firmware
entropy service and physical entropy/SSH qualification remain outstanding.

### TRNG native register lane

`vibeos-starfive-trng::Mmio` now supplies the ordered volatile 32-bit lane for
the existing polling protocol. Firmware passes a mapped aperture and timer;
the driver has no board address, kernel dependency, clock/reset policy or
entropy estimate. Construction checks alignment, minimum extent and address
overflow without IO. Register allowlists exclude reserved offsets and writes
to status, mission-mode and random-output words. Firmware must exclusively own
ISTAT, mask the PLIC source on every hart and keep the shared SEC domain alive.

Three new host tests verify aperture rejection, exact word access and untouched
neighbors, and rejection of forbidden reads/writes; all 13 driver tests pass.
RV64 executes the same native lane against RAM, reports `JH7110_TRNG_MMIO PASS`
and passes 395 kernel selftests. The generated lane contains RV64 IO fences.
Mutations weakening the aperture bound, allowing status writes and redirecting
word addresses are detected. Evidence is recorded in
`boards/milkv-mars/trng-mmio-evidence.json`.

The RAM access test does not emulate hardware register side effects or verify
the Mars MMIO bus. No production TRNG instance or random capability is published
by this change. Parent-clock lifetime, shared-domain composition and physical
entropy/SSH qualification remain required; existing SD images are unchanged.

### Shared STG parent-clock decoding

`vibeos-platform-jh7110::clock::stg_axiahb_hz` decodes the read-only
BUS_ROOT/AXI_CFG0/STG_AXIAHB path independently of GMAC. Ethernet now uses the
same decoder and the extracted PLL helper, preserving its previous rate and
preflight rejection rules. Security-domain composition can query the parent
without accessing GMAC GTX/PTP or requiring PLL0. The supported initial rate
envelope remains 20–300 MHz; fractional, powered-down, malformed or non-integral
configurations are rejected. The oscillator path does not read PLL registers.

Three new host tests cover independent register access, both parent paths,
post-dividers and invalid configurations. All 29 platform tests pass; QEMU
executes the decoder and reports `JH7110_STG_CLOCK PASS` with 395 kernel selftests.
Removing the divider limit, ignoring post-division or forcing the oscillator
parent is detected by mutation tests. Evidence and pinned SDK source details
are in `boards/milkv-mars/shared-clock-evidence.json`.

The returned frequency is a configuration snapshot, not proof of a running
physical clock or a lifetime lease. Firmware must serialize shared clock access
and keep the parent stable while security clients are active. This change does
not yet instantiate the SEC/TRNG owner or publish a qualified entropy service.

### Explicit TRNG boot diagnostic composition

`sh scripts/build-milkv-mars.sh --trng-probe` builds an independent diagnostic
payload; add `--ethernet` to retain DHCP/iperf3. The diagnostic feature requires
TRNG DTB admission and runs after device mappings, before secondary harts and
services. It sets only the TRNG PLIC priority to zero with readback, decodes
the STG parent, constructs the shared-domain and native TRNG owners, reads two
conditioned blocks and explicitly stops the domain. A failure reports prepare,
read and stop results and shuts down; no later service is started on failure.
An atomic claim prevents repeated invocation. No raw block bytes are logged.

This composition requires a quiescent SEC handoff from boot firmware and stable
shared roots during the diagnostic. It never registers an entropy capability,
never enables SSH and never labels the output cryptographically qualified.
`protocol-observed` is only a hardware control-path diagnostic, even when a
future physical run obtains that message. Real source qualification is still
required. Failed stop does not permit owner reuse; the image halts.

Payload directories are `target/milkv-mars/bringup-trng-probe` and
`target/milkv-mars/ethernet-trng-probe`. Their manifests explicitly mark the
diagnostic and unqualified entropy. The SD packer does not yet accept this
profile; neither existing test SD image was replaced. Software evidence is in
`boards/milkv-mars/trng-composition-evidence.json`. QEMU continues to exercise
the driver/platform models and normal boot regression, not the physical Mars
diagnostic entry. No physical SEC handoff or TRNG result has been observed.

### Diagnostic SD packaging

The SD builder, container packer and manifest checker now accept `--trng-probe`
alongside optional `--ethernet`. All four profiles have separate image names,
payload directories and bootchain output directories. The manifest checker
rejects mismatched TRNG/network metadata and any claim of qualified entropy in
these test images. The existing GPT geometry and boot/data separation remain
unchanged. Output overwrite is rejected before fetching/building.

The combined Ethernet/TRNG diagnostic image was built with the paired pinned
SPL/OpenSBI/U-Boot chain and checked as a 641 MiB image. Bootchain corruption
tests, SD geometry tests and three manifest profile mutations pass. Build and
hash evidence is in `boards/milkv-mars/trng-sd-evidence.json`; the artifact and
usage are documented in `firmware/milkv-mars/bootchain/README.md`.
This supersedes the earlier diagnostic-payload-only packaging limitation.
The image is suitable for the planned test SD card, but no physical boot,
SEC handoff, entropy, SSH or full stability qualification is claimed.
