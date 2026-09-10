# Hardware architecture

VibeOS selects a board and image policy when the final firmware image is
compiled. The Cargo composition and downward dependency direction are:

```text
firmware/<board>  (selects features, owns entry point and final linking)
        ├── boards/<board> + UART/PLIC engines
        ├── immutable HAL boot/device operation tables
        └── kernel archive
              ├── policy/image   (logical resources)
              ├── hal            (firmware-supplied physical resources)
              └── kernel adapters (capabilities, IRQs, supervision)
                       └── drivers/* (register/protocol engines)
                                  └── hal + core
```

The final firmware uses its `boards/<board>` BSP to construct the immutable
`vibeos_hal::boot::BootPlatform` consumed by the kernel. The kernel archive
has no BSP dependency or board-selection facade. The contract includes: RAM and MMIO
ranges, MMU mappings, hart and interrupt-controller facts, UART details, and
optional per-device descriptions. Drivers receive only the description they
need; they do not import a BSP or select a board themselves. Consequently,
physical addresses, IRQ numbers, clocks, bus widths, and DMA/cache constraints
belong in the BSP rather than in `kernel` or a generic driver.

Logical image choices are separate from physical board facts. The final
firmware explicitly enables one `policy/image` feature, selecting block slices
and backend-neutral frontend limits. For example, the Milk-V image exposes
only its packaged data sectors; the SDHCI driver still discovers and validates
the capacity of the complete card.

## Compile-time composition

Each firmware crate enables exactly one mutually exclusive kernel board
feature:

| Firmware crate | Kernel composition features | BSP and hardware drivers |
|---|---|---|
| `firmware/qemu-virt` | `qemu-virt`, `qemu-default-image` | `boards/qemu-virt`, PCI, VirtIO MMIO, VirtIO block/network/RNG, XHCI |
| `firmware/milkv-duo` | `milkv-duo`, `milkv-duo-sd-image` | `boards/milkv-duo`, DWMAC + DWC2/CDC-ECM network, SDHCI block |

Firmware image features such as `legacy-shell`, `tcp-echo`, `ssh-test`, and
`net-shell` are exposed by the firmware crates and forwarded to the kernel.
Final entry symbols and linking also remain in those crates. Build from one
firmware directory at a time so Cargo uses `firmware/.cargo/config.toml` and
does not combine both board features into one kernel archive.

## Firmware-owned early devices

UART and PLIC instances are now composed directly by the final firmware via
`firmware/early_devices.rs`. The immutable `VIBEOS_EARLY_DEVICES` Rust static
contains HAL descriptions and operation tables; it needs no heap or mutable
registration before the first console write. This is an internal static-link
contract, not a stable module ABI. Firmware supplies the mapping and lifetime
obligations; the kernel serializes TX, config and PLIC enable updates.

The kernel UART/PLIC adapters contain queues, IRQ-handler publication and
policy only. They neither access registers nor import a board/driver crate.
The MMU and other device adapters obtain physical descriptions through
`VIBEOS_BOOT_PLATFORM`. RAM page tables are allocated statically by firmware
and borrowed under the kernel page-table ownership protocol. Multiple GiB
windows and 2 MiB RAM leaves are supported; all runtime permission-changing
pools are split before publishing the address space. Other hardware engines
still have direct kernel dependencies pending the remaining driver migration.
See `MILKV_MARS.md` for the remaining port work.

## Driver crates

| Crate | Owns | Deliberately left to the kernel adapter |
|---|---|---|
| `drivers/uart16550` | 16550/DW APB register access and interrupt acknowledgement | Console buffering, locks, framing and wakeups |
| `drivers/plic` | PLIC register access, context reset, enable/claim/complete | Context selection, locking and atomic handler registry |
| `drivers/sd-protocol` | SD CSD capacity and block/byte address encoding | Controller transport and managed storage policy |
| `drivers/dw-mshc` | DW-MSHC PIO SD engine; currently unattached | SoC preparation and generic block-service integration remain pending |
| `drivers/pci` | Generic PCI ECAM discovery, type-0 BAR sizing/assignment, bus-master enablement | Serialized host access, device policy, INTx routing |
| `drivers/virtio-core` | VirtIO 1.2 wire constants, feature/status machines, descriptors and split-queue lifecycle models | MMIO access, DMA storage, interrupts and device policy |
| `drivers/virtio-mmio` | Modern VirtIO MMIO probing, register transport, feature and queue setup primitives | Device-specific queues, DMA allocation, interrupts and recovery |
| `drivers/virtio-blk` | Block split queue, fixed DMA slab, request/completion validation, reset and quarantine state | Block capabilities, request scheduling, IRQ publication, supervision and logical media policy |
| `drivers/virtio-net` | RX/TX split queues, fixed DMA slab, feature handshake, completion validation and reset boundary | Packet sessions, network identity, IRQ routing, scheduling and supervisor policy |
| `drivers/virtio-rng` | Synchronous entropy queue, fixed DMA slab and completion validation | Random capability policy, deadlines, scheduling, interrupts and restart policy |
| `drivers/xhci` | XHCI and USB protocol state using caller-provided permanent DMA storage | PCI discovery, bus mastering, PLIC routing, synchronization and input/storage publication |
| `drivers/dwc2-host` | CV1800B USB clocks/role wiring, DWC2 reset/root-port power, buffer-DMA host channels using caller-supplied instance storage, hub split transactions, EP0 enumeration, USB class transactions, and CDC-ECM carrier notification decoding | PLIC routing and class capability publication; the kernel adapter owns polling, carrier publication, and hotplug recovery policy |
| `drivers/rtl815x` | Realtek USB product/personality classification, the bounded RTL8151 virtual-CD mode-switch protocol, and authoritative PLA PHY carrier decoding | DWC2 topology/endpoints/DMA, vendor control transport, CDC-ECM traffic and network policy |
| `drivers/dwmac-net` | CV1800B DWMAC registers, clock/ePHY/MDIO setup, cache maintenance, and caller-supplied instance-owned RX/TX DMA plus telemetry state | Network capabilities and sessions, MAC policy, supervision and interrupt policy |
| `drivers/milkv-duo-led` | CV1800B pad mux, GPIO output sequencing and status readback for the board LED | Boot-status policy and diagnostic reporting |
| `drivers/sdhci-blk` | CV1800B clock/pad/power setup, SD discovery and 512-byte PIO sector I/O | Block capabilities, locking, supervision and logical partition mapping |

Driver crates are `no_std` hardware engines. They may depend on `vibeos-hal`
for typed descriptions, on `drivers/virtio-core` for the VirtIO wire model,
and on board-neutral data types in `vibeos-core`, but never on `vibeos-kernel`,
a BSP, or a firmware crate. Unsafe
MMIO/DMA entry points state the mapping, exclusivity, lifetime, and coherence
obligations that the embedding kernel adapter must uphold.

This separation does not create a privilege boundary: all layers currently
share one address space. It makes ownership and review boundaries explicit and
allows driver protocol tests to run on the host without selecting a board.

The Milk-V DWMAC and DWC2 engines are polling drivers today: their BSP IRQ
numbers live in each `Engine`/`Controller` description, but no shared IRQ wait
queue or interrupt-cause state is active. Each adapter supplies two distinct
objects: device-visible bytes in the linker `NOLOAD` `.dma` section, and
CPU-only claim/telemetry state in normally initialized `.bss`. The latter must
never be embedded in `.dma`, whose boot contents are unspecified. If a future
policy enables IRQ delivery, its wait queue, pending causes and counters must be
added to the CPU-only per-instance state rather than reintroduced as crate
globals.

Network interface ordinals are also policy results rather than driver names.
The boot world collects every admitted NIC capability bundle, sorts stable
locations (MMIO base or USB controller plus physical port path), and only then
assigns the boot-local `netN` sequence. The netstack allocates state for that
runtime list; it has no fixed interface-count table. A service listener stays
attached to the policy root that minted it, even if another topology changes
that root's ordinal on a later boot.

The synchronous PIO block boundary is now firmware-owned as well. The HAL
operation table carries device metadata and serialized initialization, read,
write, flush and diagnostic callbacks. It cannot retain caller buffers or
publication callbacks. Kernel partition admission uses the reusable HAL
`BlockWindow`; card protocol probing lives in the SDHCI crate. This boundary
is ready for a DW-MSHC provider without importing SDHCI types into the kernel.
Asynchronous DMA backends still need their completion and ownership migration.

The HAL entropy operation table separates asynchronous RNG hardware ownership
from kernel request policy. Firmware retains the driver engine, DMA slab and
hardware completion records; kernel requests use epoch/serial tokens. Read-only
completion queries can cross scheduler awaits, while state mutation requires
exclusive invocation ownership. The minimal IRQ acknowledgement callback never
borrows firmware engine state. Confirmed reset remains the prerequisite for
releasing the kernel's DMA claim; failed resets retain quarantine.

SD slot clock/pad/supply operations are supplied by a platform crate through
HAL `SdPlatform` hooks. SDHCI receives only its own controller aperture and
clock rates; it no longer receives a SoC control aperture. Firmware composes
the controller and platform implementations, preserving power/reset ordering.

Queued block devices are also composed by firmware. The kernel sends HAL
operations and keeps scheduling, request publication accounting and capability
policy; firmware owns the engine and DMA state. Operation tokens identify a
specific epoch and serial. Driver completion validation precedes copying data
back to kernel request buffers. Existing timeout, cancel, revoke and fault
recovery paths retain their reset-before-reuse ordering across this boundary.

The HAL packet-device boundary now composes the Duo DWMAC instance in firmware.
Packet endpoints, stack generations and capability/fault policy remain kernel
services. Firmware retains a fixed `.dma` slab and an instance claim. Ordinary
shutdown consumes the engine; fault recovery explicitly abandons old metadata
without a destructor and does not release the claim until reset succeeds.

QEMU queued networking is now assembled by firmware as well. Kernel invocation
tokens record release locally so repeated cleanup cannot dispatch a shutdown to
a replacement firmware instance. Network frame bounds are checked before the
HAL frame exposes a byte slice; controller ring/header validation stays in the
driver. Packet-session policy and endpoint scheduling remain in the kernel.

BootPlatform provides boot-only platform initialization and reporting callbacks,
invoked after MMIO mapping and before SMP/services. Board-specific LED setup and
its diagnostic formatting now belong to Duo firmware. The kernel has no LED
hardware dependency or board-selection branch for that startup operation.

PCI host enumeration and BAR allocation are now firmware-owned. HAL function
snapshots describe resources without embedding ECAM access. Kernel callers
serialize host operations and request bus-master activation through the host,
which validates membership in its current inventory before writing configuration
space. USB controller ownership is a subsequent boundary migration.

XHCI controller and DMA storage are now firmware-owned. Kernel USB policy keeps
resource admission, locking, IRQ registration and TTY injection. A failed IRQ
route is masked and remains unpublished; firmware retains its controller for a
same-resource retry, preventing a second live mutable DMA borrow. The IRQ token
contains only live MMIO context and bypasses controller-state borrowing.

Duo's polling USB host is now composed by firmware. HAL `usb_polling::Host`
provides serialized operations and bounded descriptor/HID snapshots; the kernel
keeps initialization publication, hotplug/class-selection policy, TTY delivery,
and CDC network sessions. Firmware owns DWC2's controller, instance claim and
permanent `.dma` storage. Failed initialization leaves no published kernel token;
successful initialization is idempotent. The Duo kernel production dependency
graph now contains no BSP or concrete driver crate. CV1800B USB clock/PHY access
still lives in the DWC2 implementation and needs the later SoC-resource split.

Fixed VirtIO discovery, status reads, reset confirmation and task-context IRQ
acknowledgement now cross a firmware transport table. Kernel transport tokens
contain only copied resource identity. Firmware resolves them against its own
MMIO description and checks the complete descriptor before use; a supplied base
is never dereferenced. Missing/mismatched resources report reset-required or
failed reset, preserving quarantine. IRQ top halves retain the existing stateless
firmware acknowledgement callbacks and never borrow an engine.

Pure VirtIO wire types and state machines now live in `contracts/virtio`.
`drivers/virtio-core` is a source-compatible re-export for existing driver users.
The contract performs no MMIO and owns no DMA. Its existing 44 protocol tests
moved with it. Neither QEMU nor Duo kernel production graphs contain concrete
drivers or BSPs. `python3 scripts/check-driver-boundaries.py` enforces declared
workspace normal/build/optional edges, excludes test-only fixtures, and checks
that drivers also cannot reach the kernel or a BSP. This dependency gate does
not prove the remaining board-feature or SoC-register-policy separation.
