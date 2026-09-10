# Milk-V Mars port status

Target: standard Milk-V Mars with 4 GiB RAM, microSD boot, serial and SSH
acceptance. This is an **incomplete port**. There is no Mars firmware image or
claim of hardware qualification in this change.

## Implemented foundation

- Firmware-owned UART/PLIC instances and immutable HAL operation tables are
  used by the existing QEMU and Duo firmware. The kernel console adapter keeps
  its locks, ring buffers, record framing and wakeups; the interrupt adapter
  keeps its atomic handler registry and enable lock. Neither adapter imports a
  BSP or accesses registers. Other kernel adapters still depend on concrete
  hardware drivers and board features.
- `drivers/uart16550` implements 16550/DW APB register IO and preserves the DW
  busy-detect and phantom-timeout acknowledgements. `drivers/plic` implements
  context initialization, source masking, claim and completion.
- `drivers/sd-protocol` shares SD CSD normalization/capacity and sector address
  encoding with the existing Duo SDHCI driver and the new DW-MSHC engine.
- `drivers/dw-mshc` implements SD initialization, four-bit negotiation, bounded
  clock changes, 512-byte PIO reads/writes, card-ready checking and write
  publication tracking. IO failures quarantine the instance. It requires the
  caller to prepare clocks, reset, pinmux and card power. It is not yet wired
  into a kernel block service or exercised against a real controller.
- `hal::fdt` validates bounded FDT v17 byte slices and extracts RAM and fixed
  reservations without allocation. `hal::memory` subtracts reservations
  transactionally and validates complete DMA spans and cache-line isolation.
  These helpers do not yet replace the kernel's existing MMU/allocator boot.
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

1. Introduce the complete firmware boot/device registration contract. Move
   remaining BSP and driver dependencies out of the kernel, preserving device
   capability lifetimes, DMA quarantine, queue cancellation and recovery.
2. Implement JH7110 clock/reset/pinmux preparation and verify DMA coherence for
   the GMAC path. Add the GMAC5/EQoS engine and PHY setup using the Mars wiring.
3. Connect the DW-MSHC engine to the generic block service. Preserve the existing
   managed-range and write-certainty contracts; reserve separate boot/data
   partitions in image policy. Add device timeout and recovery acceptance.
4. Integrate the boot DTB parser with hart, timebase, resource and image
   validation. Extend the live MMU beyond its current single-gigapage RAM
   hierarchy, with large-page RAM mappings and fine mappings for protection
   boundaries. Connect the admitted free ranges to allocation.
5. Add `firmware/milkv-mars`, a linker layout and reproducible SD packaging.
   Qualify a matching SPL/OpenSBI/U-Boot configuration with HSM/IPI/RFENCE/TIME.
   Do not update SPI as part of this test-card workflow.
6. Generalize service image features, provision a separate Mars identity,
   qualify the entropy source, and enable SSH/WASM/Wasmtime only after these
   prerequisites work on the board.
7. Capture three cold boots and an hour of simultaneous storage, networking and
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
