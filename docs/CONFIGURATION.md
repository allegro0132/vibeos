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

`./configure.sh` opens the setup UI. Five sections run across the top: Boards,
Drivers, Components, Presets and Review. Each section is a list beside a detail
pane; Review is one scrollable summary of the resolved build. A first run (no
`vibeos.toml` yet) opens on Presets so you start from a working selection.

Every row shows the *resolved* outcome rather than only the stored choice. A
driver left on `auto` that a component pulled in is drawn as included and
labelled `auto, in use`. The detail pane lists, per selected board, whether the
item is included and why. The status line always shows the first unresolved
problem, and Review lists them all.

| Symbol | ASCII | Meaning |
| --- | --- | --- |
| `●` | `[x]` | Included in the build |
| `○` | `[ ]` | Not included |
| `◆` | `[#]` | Required; cannot be turned off |
| `●` (yellow) | `[~]` | Selected, but missing on some boards |
| `×` | `[-]` | Driver forced off, even as a dependency |
| `!` | `[!]` | Selected, but cannot be satisfied (or conflicts) |
| `·` | ` . ` | Applies to no selected board |

| Key | Action |
| --- | --- |
| Tab / Shift-Tab / Left / Right / 1-5 | Change section |
| Up / Down / j / k / Home / End | Select an item |
| Space / Enter | Toggle a board/component; cycle a driver; load a preset |
| / | Filter by name, identifier or description; Escape clears it |
| PageUp / PageDown | Scroll the detail pane or Review |
| s / Ctrl-S | Validate and save (Enter also saves on Review) |
| q / Escape | Quit; with unsaved changes, choose save, discard or keep editing |
| ? | Keys and symbols |

A failed save jumps to Review. Loading a preset asks first only when it would
discard unsaved changes, and nothing is written until you save.

The UI draws with Unicode and the terminal's own ANSI palette. It falls back to
pure ASCII when the locale is not UTF-8, on the Linux console, or with `--ascii`
or `VIBECONFIG_ASCII=1`, which suits serial terminals. `NO_COLOR` disables
colour; weight then carries the hierarchy. The minimum size is 50 x 12, and
below 84 columns the detail pane moves under the list.

## Architecture

Every board in the catalog has an architecture, `riscv64` or `aarch64` (shown as
arm64). A kernel image has exactly one, so a configuration does too: it is
derived from the selected boards and never stored in `vibeos.toml`. The resolver
rejects a selection that mixes architectures and picks the Rust target from it.

| Architecture | Boards | Image |
| --- | --- | --- |
| riscv64 | QEMU virt, Milk-V Duo, Milk-V Mars | One shared universal image, built here |
| arm64 | BPI-R4 Pro 4E | Built by [VibeWrt](https://github.com/allegro0132/vibewrt), configured alone |

In the UI the Boards list shows each board's architecture. RISC-V boards combine
freely. Selecting a board from the other architecture asks before replacing the
selection with that board and its default drivers; cancelling changes nothing.
Drivers and components that do not exist for the current architecture are shown
as not applicable.

This workspace holds the arm64 runtime, the BPI board definitions and the
MediaTek drivers as libraries, but no arm64 firmware. For BPI-R4 Pro,
`./configure.sh` records and validates the selection, Review shows where the
image is built, and `./build.sh` stops with that pointer instead of compiling.
A board with an external image always resolves to an empty feature set.

## Drivers and presets

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
`milkv-duo`, `milkv-mars` and `bpi-r4pro-4e`. Default and minimal cover the boards
that share the universal image. Default includes all three RISC-V boards, their native
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

`configs/catalog.toml` defines supported boards, their architecture and who builds
their image (`image = "external"` plus a `build_hint`), mandatory drivers, feature
mappings, capability providers and conflicts. Extend the catalog and firmware
implementation together. Unknown fields, unknown identifiers, cycles, missing
providers and mismatched Cargo features are errors.

Resolution computes each board's dependency closure first, then the union of
Cargo features. A requested component may be unavailable on some boards; its
reason is displayed and it is not activated there. If it cannot run on any
selected board, saving/building fails. Global library conflicts are errors even
when components would run on different boards. The current conflict is Python
with Wasmtime. SSH and iperf3 can share an image: each has its own listeners.

| Component | Dependencies / behavior |
| --- | --- |
| VSH | Required console shell |
| File services | Native or VirtIO managed block storage |
| Networking | Native, VirtIO or Duo USB CDC-ECM network; DHCP |
| SSH | Networking, file services and entropy; locally provisioned identities |
| WASI | File services; built-in WASI Preview 1 command runtime |
| Wasmtime | WASI and RV64GC; existing runtime ISA and memory admission |
| Python support | WASI/Wasmi with the bounded small-board limits; install Python separately |
| iperf3 | Networking; DHCP TCP benchmark server, alone or beside SSH |

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

For an SSH/XHCI configuration, add `--ssh --usb` to verify a real credential-free
OpenSSH handshake, identical public host keys across boots, client key persistence
and USB keyboard enumeration. The SSH test binds a localhost-only forwarded port.
`--jitter` tests SSH without a VirtIO RNG. On a virtual timer where collector
initialization returns `Offline`, use `--jitter --entropy-unavailable` to verify
that key generation fails closed instead. This environment's QEMU timer took that
rejection path; no claim of Mars entropy qualification follows from it.

The QEMU smoke test boots an unchanged raw image at `0x80200000` and `0x80400000`,
checks four online harts, console output, DHCP and file persistence across both
boots, and records the same SHA-256. It creates only disposable test storage.
The second-address jump shim belongs to the test harness, not the kernel image.

Physical Duo/Mars acceptance remains a separate hardware step. Check the same
kernel hash on both packages, board identification, admitted harts/RAM, serial,
native storage, Ethernet and selected entropy/SSH services. Build and package
records explicitly report `physical_acceptance: false` until such evidence exists.
