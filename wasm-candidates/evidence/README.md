# C0.7 candidate baselines

`baseline-v1.json` is the reviewed C0.7 evidence record. It replaces the old
CSV snapshot, which mixed inline Rust object sizes, debug-heavy `.rlib` file
sizes, validator timing, and ordinary call timing without covering the
roadmap's required measurements.

The closed applicability matrix distinguishes two Core candidates from the
shared Component frontend. Canonical ABI lift/lower is measured once against
the in-tree frontend and is explicitly not applicable to either Core engine;
Core fuel and empty Core instances are correspondingly not attributed to the
frontend.

## Measurement contract

- Code/static size comes from four independently linked
  `riscv64imac-unknown-none-elf` ELF probes. The Wasmi and DLR probes validate,
  instantiate, fuel, and execute the same `burn` guest, so LTO cannot discard
  the interpreter hot path. The frontend probe validates the typed Component
  and WIT world and executes the same Canonical ABI roundtrip used by the host
  collector. Pinned `llvm-readobj` classifies only `SHF_ALLOC` sections; debug
  sections are excluded. A fixed 256 KiB probe heap is reported and removed
  from static-RAM totals. CI performs a fresh cross-build and requires the
  complete allocated-section, heap-symbol, and aggregate record to match.
- Validator memory records requested allocation bytes through a single-threaded
  tracking global allocator. Accepted and truncated hostile inputs are separate
  windows. Every transient window must finish with `heap_after == heap_before`.
- Empty-instance cost excludes the already-built Engine/Module and includes a
  fresh Store plus empty Instance. Both retained and peak bytes are recorded,
  followed by a mandatory return to baseline after drop.
- Core cold startup begins with compiled Wasm bytes and includes a fresh engine,
  validation/compilation, Store, instantiation, export lookup, and first guest
  return. WAT parsing is outside the window. Frontend startup is named
  `frontend-prepare` because this layer validates and plans but does not own a
  Core Store.
- Fuel throughput runs `burn(32768)`, records raw elapsed samples and exact
  per-call fuel, and recomputes both operations/s and fuel/s. Wasmi and DLR fuel
  schedules use different units, so their fuel counts are not directly
  comparable.
- Canonical lift/lower uses the C8.3 workload shape: a 256-byte UTF-8 string,
  64 `u32` values, `CanonicalMachine`, and successful post-return cleanup.

There are no performance thresholds in C0. Updating a baseline is an explicit
review action and never a normal test side effect.

Both build modes use a fresh temporary target directory, an isolated Cargo
home that exposes only the existing registry/git caches, offline resolution,
the pinned absolute Cargo/Rust compiler paths, empty Rust flags/wrappers, and
the workspace release profile. The recorded tool binary hashes identify the
collection host; cross-platform CI instead checks the pinned rustc commit and
rebuilds every measured program and fixture.

## Commands

Collect to stdout without changing the repository:

```sh
python3 -B scripts/collect-c0-baseline.py
```

The pinned toolchain and RISC-V target must already be installed, and the
locked crates must already exist in the local Cargo cache:

```sh
rustup target add --toolchain nightly-2026-08-01 riscv64imac-unknown-none-elf
python3 -B scripts/collect-c0-baseline.py --check-build
```

Explicitly replace the checked-in baseline:

```sh
python3 -B scripts/collect-c0-baseline.py --update
```

Verify the checked-in record, all source/fixture pins, derived statistics,
heap cleanup, static-section arithmetic, and representative negative
mutations without recollecting timings:

```sh
python3 -B scripts/verify-c0-baseline.py --selftest --check-toolchain
```

Collection and verification use absolute `RUSTC`/`RUSTDOC` paths resolved from
the repository's pinned rustup toolchain. Neither command requires or accesses
Milk-V Duo hardware.
