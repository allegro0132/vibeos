# Hardware architecture

VibeOS selects a board and image policy when the final firmware image is
compiled. The Cargo composition and downward dependency direction are:

```text
firmware/<board>  (selects features, owns entry point and final linking)
        └── kernel archive
              ├── policy/image   (logical resources)
              ├── boards/<board> (typed physical descriptions)
              └── kernel adapters (capabilities, IRQs, supervision)
                       └── drivers/* (register/protocol engines)
                                  └── hal + core
```

The selected `boards/<board>` BSP constructs the
typed `vibeos_hal::BoardInfo` consumed by the kernel adapters: RAM and MMIO
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
| `firmware/milkv-duo` | `milkv-duo`, `milkv-duo-sd-image` | `boards/milkv-duo`, DWMAC network, SDHCI block |

Firmware image features such as `legacy-shell`, `tcp-echo`, `ssh-test`, and
`net-shell` are exposed by the firmware crates and forwarded to the kernel.
Final entry symbols and linking also remain in those crates. Build from one
firmware directory at a time so Cargo uses `firmware/.cargo/config.toml` and
does not combine both board features into one kernel archive.

## Driver crates

| Crate | Owns | Deliberately left to the kernel adapter |
|---|---|---|
| `drivers/pci` | Generic PCI ECAM discovery, type-0 BAR sizing/assignment, bus-master enablement | Serialized host access, device policy, INTx routing |
| `drivers/virtio-core` | VirtIO 1.2 wire constants, feature/status machines, descriptors and split-queue lifecycle models | MMIO access, DMA storage, interrupts and device policy |
| `drivers/virtio-mmio` | Modern VirtIO MMIO probing, register transport, feature and queue setup primitives | Device-specific queues, DMA allocation, interrupts and recovery |
| `drivers/virtio-blk` | Block split queue, fixed DMA slab, request/completion validation, reset and quarantine state | Block capabilities, request scheduling, IRQ publication, supervision and logical media policy |
| `drivers/virtio-net` | RX/TX split queues, fixed DMA slab, feature handshake, completion validation and reset boundary | Packet sessions, network identity, IRQ routing, scheduling and supervisor policy |
| `drivers/virtio-rng` | Synchronous entropy queue, fixed DMA slab and completion validation | Random capability policy, deadlines, scheduling, interrupts and restart policy |
| `drivers/xhci` | XHCI and USB protocol state using caller-provided permanent DMA storage | PCI discovery, bus mastering, PLIC routing, synchronization and input/storage publication |
| `drivers/dwc2-host` | CV1800B USB clocks/role wiring, DWC2 reset/root-port power, buffer-DMA host channels, EP0 control transfers and device enumeration | PLIC routing, hotplug, class configuration and HID capability publication |
| `drivers/dwmac-net` | CV1800B DWMAC registers, clock/ePHY/MDIO setup, cache maintenance and fixed RX/TX DMA storage | Network capabilities and sessions, MAC policy, supervision and interrupt policy |
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
