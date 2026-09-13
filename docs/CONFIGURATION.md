# Configuring and building VibeOS

The configurator selects boards, drivers and built-in components before compilation.
It produces one position-independent kernel containing the union of the selected
board drivers. The bootloader passes the physical hart ID in `a0` and a readable
DTB in `a1`; the kernel admits the board, memory and CPU description before MMIO.
QEMU virt, Milk-V Duo CV1800B and Milk-V Mars JH7110 4 GiB use the **same raw
`vibeos.bin` bytes**. Their bootloader, DTB and FIT packaging can differ.

## Quick start

Use the repository's pinned Rust toolchain, including `rust-src` and
`llvm-tools-preview`. The terminal UI uses Ratatui/Crossterm. Python 3 is required
for image verification; QEMU is required only for running or smoke tests.

```sh
./configure.sh
./build.sh
./run.sh --config vibeos.toml
```

The UI has three columns: categories, selectable items, and dependencies plus
availability on each selected board. It uses English ASCII text and borders.

| Key | Action |
| --- | --- |
| Tab / Left / Right | Change category |
| Up / Down / j / k | Select an item |
| Space / Enter | Toggle a board/component; cycle a driver; choose a preset |
| / | Search names, identifiers and descriptions |
| PageUp / PageDown | Scroll dependency details or preview |
| Ctrl-S | Validate and save |
| q / Escape | Exit, confirming if there are unsaved changes |
| ? | Show key help |

Drivers have `auto`, `on` and `off` states. `auto` allows dependency resolution
to select a provider. `on` requires the driver on compatible selected boards.
`off` forbids it, including as a transitive dependency. Boot requirements cannot
be turned off. VSH is always included. A failed dependency attempt does not leak
partially selected drivers into the result.

```sh
# Reproducible, noninteractive defaults; also works in CI.
./configure.sh --preset default --non-interactive
./configure.sh check --config vibeos.toml
./configure.sh resolve --config vibeos.toml
./build.sh --config vibeos.toml --dry-run

# Keep several independent selections.
./configure.sh --preset minimal --non-interactive --output target/minimal.toml
./build.sh --config target/minimal.toml
```

Checked-in presets are in `configs/presets/`: `default`, `minimal`, `qemu-virt`,
`milkv-duo`, and `milkv-mars`. Default includes all three boards, their native
storage/Ethernet drivers, VSH, file services and DHCP networking. Minimal includes
all three boards and only their boot requirements plus VSH. Single-board presets
include native storage and Ethernet. None installs external WASM programs.

## Selection and dependency model

`vibeos.toml` records user intent and is ignored by Git. For example:

```toml
version = 1
boards = ["qemu-virt", "milkv-duo", "milkv-mars"]
components = ["vsh", "file-tree", "network", "ssh"]

[drivers]
virtio-rng = "auto"
jitter-entropy = "auto"
xhci = "off"
```

`configs/catalog.toml` defines supported boards, mandatory drivers, feature
mappings, capability providers and conflicts. Extend the catalog and firmware
implementation together. Unknown fields, unknown identifiers, cycles, missing
providers and mismatched Cargo features are errors.

Resolution computes each board's dependency closure first, then the union of
Cargo features. A requested component may be unavailable on some boards; its
reason is displayed and it is not activated there. If it cannot run on any
selected board, saving/building fails. Global library conflicts are errors even
when components would run on different boards. Current conflicts are Python
with Wasmtime, and SSH with the dedicated iperf3 service profile.

| Component | Dependencies / behavior |
| --- | --- |
| VSH | Required console shell |
| File services | Native or VirtIO managed block storage |
| Networking | Native, VirtIO or Duo USB CDC-ECM network; DHCP |
| SSH | Networking, file services and entropy; locally provisioned identities |
| WASI | File services; built-in WASI Preview 1 command runtime |
| Wasmtime | WASI and RV64GC; existing runtime ISA and memory admission |
| Python support | WASI/Wasmi with the bounded small-board limits; install Python separately |
| iperf3 | Networking; dedicated DHCP TCP server profile |

QEMU prefers virtio-rng. Boards without a dedicated approved source, including
Duo and Mars, can use jitterentropy with OSR 3 and a 256 KiB collector. Explicitly
disabling virtio-rng also permits QEMU to resolve to jitterentropy. Collector
initialization/health failures return errors; they never substitute deterministic
bytes. Actual entropy health and performance must be checked on each physical
board. StarFive TRNG remains a separate diagnostic driver and does not satisfy
SSH's entropy dependency.

The kernel retains the existing capability leases, rights checks, driver epochs,
revocation and managed storage boundaries. Runtime tables select implementations;
they do not grant authority. On Mars, the existing DTB/SBI admission and SD data
partition validation still run. Kernel startup prints its board, configuration
digest, enabled components and reasons for unavailable components.

## Build artifacts and checks

Outputs are isolated under `target/universal/<configuration-digest>/`:

- `resolved.toml`: input selection, board closures, reasons, target and features.
- `cargo/`: this selection's Cargo artifacts, including the universal ELF.
- `vibeos.bin`: the single raw kernel.
- `layout.json`: verified ELF layout, relocations and board memory budgets.
- `manifest.json`: image/configuration checksums, features, compiler and Git
  provenance, and the embedded layout record.

The configuration digest covers the normalized selection and catalog, not source
code. The raw image checksum identifies the built bytes. Rebuilding the same
selection after a source change updates its artifacts. Git provenance records
HEAD and the tracked diff digest; it is not a complete source archive.

The firmware build script recomputes the selection to reject stale or edited
resolved files. The post-link verifier requires a RISC-V ELF64 PIE with entry zero,
non-overlapping W^X segments and symbol-free `R_RISCV_RELATIVE` relocations. It
checks relocation bounds, static image footprint, page-table/heap budgets, Duo's
FIT source overlap, and byte-for-byte agreement between ELF load segments and the
raw image. Artifact consumers reject changed images or resolved configurations.

`./run.sh --config FILE` builds and runs the configured QEMU target. It attaches
only selected QEMU devices and creates a persistent 128 MiB data disk inside the
build output when block storage is enabled. Exit QEMU with Ctrl-A, then X.
The original `./run.sh` without `--config` retains the existing Core-WASM demo.

## Physical-board packaging

Packaging consumes the verified manifest and never recompiles or patches the raw
kernel. Supply the board's vendor DTB. `fdtget`/`fdtput` from dtc validate the root
identity and add `vibeos,board-id`; all other vendor resources are retained.
Use a fresh output directory for each package.

```sh
python3 scripts/package-universal.py \
  --manifest target/universal/DIGEST/manifest.json \
  --board milkv-duo --dtb /path/to/cv1800b_milkv_duo_sd.dtb \
  --output target/packages/duo --mkimage /path/to/sdk/mkimage

python3 scripts/package-universal.py \
  --manifest target/universal/DIGEST/manifest.json \
  --board milkv-mars --dtb /path/to/jh7110-milkv-mars.dtb \
  --output target/packages/mars --mkimage /path/to/mkimage
```

`--prepare-only` emits the raw kernel, marked DTB, ITS and package checksums when
mkimage is unavailable. A prepared package is not a bootable FIT until mkimage
has successfully processed it. Duo uses LZMA and its existing 7 MiB safe FIT window
at `0x81400000`, expanding to `0x80200000`. Mars uses `0x40200000`. Both packages
retain an identical, uncompressed `vibeos.bin` and record its checksum. Packaging
does not flash media, replace a bootloader, or certify a vendor DTB's resources.

## Validation

```sh
cargo test -p vibeos-config --features tui
cargo test -p vibeos-firmware-universal --lib --test admission
python3 -B -m unittest discover -s scripts/tests -p test_universal_image.py
python3 -B scripts/test-universal.py --image target/universal/DIGEST/vibeos.bin
# For the minimal preset, add --minimal to the smoke test.
```

The QEMU smoke test boots an unchanged raw image at `0x80200000` and `0x80400000`,
checks four online harts, console output, DHCP and file persistence across both
boots, and records the same SHA-256. It creates only disposable test storage.
The second-address jump shim belongs to the test harness, not the kernel image.

Physical Duo/Mars acceptance remains a separate hardware step. Check the same
kernel hash on both packages, board identification, admitted harts/RAM, serial,
native storage, Ethernet and selected entropy/SSH services. Build and package
records explicitly report `physical_acceptance: false` until such evidence exists.
