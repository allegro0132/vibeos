# Milk-V Duo Jitterentropy qualification

VibeOS loads `jitterentropy-rs` 0.1.1 directly from crates.io for the
Milk-V Duo. The dependency is pinned exactly in `kernel/Cargo.toml` and its
registry checksum is recorded in `Cargo.lock`; no vendored source tree or Git
submodule is required.

The crate describes itself as a Rust rewrite scaffold, not a certified or
behaviorally equivalent replacement for the upstream C implementation. VibeOS
therefore confines it to a UART-only qualification image. It is **not a
production entropy capability and does not enable production SSH**.

## Integration

- The crate is built as ordinary `no_std` Rust with its `alloc` feature.
- A small `Timer` implementation reads SBI `rdtime`, backed by the Duo's
  25 MHz timebase. This measures variations in CPU execution time; it is not a
  claim that the board exposes a dedicated hardware RNG or that `rdtime` is a
  CPU-cycle counter.
- The crate's platform timer is disabled in favor of that callback,
  forced-FIPS handling is selected, OSR is 3, and the memory-access region is
  capped at 256 KiB.
- `jent smoke` constructs the collector through the safe Rust API, requests
  two successive 256-bit results, verifies that both reads completed and are
  unequal, then explicitly zeroizes both buffers without printing their
  contents.
- The former C submodule, freestanding adapter, Clang invocation, and static
  archive are gone.

## Build and boot

Build the isolated image:

```sh
./scripts/build-milkv-duo.sh --jitterentropy-probe
```

The ELF and raw binary are written to
`target/milkv-duo-jitterentropy-probe/`. To produce the full SD image in the
same pinned SDK environment used by the normal Duo image:

```sh
./scripts/package-milkv-duo-sdk.sh --jitterentropy-probe /path/to/duo-buildroot-sdk
```

At the UART shell, exercise the admission path:

```text
vibe> jent smoke
VIBE_JENT_SMOKE PASS source=jitterentropy-rs version=3070100 ... osr=3 fips=forced timer=sbi-rdtime ...
```

Any `FAIL`, short read, startup error, or hang is a rejection. Two unequal
outputs are only a smoke test, not statistical or cryptographic validation.

## Raw-noise assessment is unavailable

`jitterentropy-rs` 0.1.1 declares a `raw-noise` feature but does not expose
a public raw-sample API. VibeOS deliberately does not patch registry source, so
the probe currently has no `jent raw` command.

The existing `scripts/jitterentropy-extract.py` utility is retained only for
previously captured UART logs. It cannot be used to obtain new evidence from
this probe.

Raw runtime and restart assessment must be restored before this collector can
be considered for production. The acceptable paths are:

1. consume a future crates.io release with a reviewed raw-noise API; or
2. maintain the extension in a reachable fork, commit it there, and load that
   fork as a clean Git submodule.

An uncommitted or locally patched submodule is not acceptable because CI and
other developers could not reproduce the exact source.

## Admission gate for production SSH

Production admission remains blocked until all of the following are completed:

1. `jent smoke` passes across representative boards and the supported
   voltage, clock, temperature, firmware, and workload envelope.
2. A reviewed raw recorder captures runtime and independent-restart samples
   through the same timing path used by the collector.
3. SP800-90B non-IID analysis passes with a documented entropy rationale for
   this exact Rust implementation, compiler, and target.
4. Startup tests, runtime health tests, conditioning, error behavior, generated
   RISC-V code, and unsafe boundaries receive independent review.
5. The open items in the upstream validation plan are resolved, including a
   faithful conditioner if exact 3.7.x behavior is required.
6. The collector seeds or reseeds a bounded DRBG; SSH never consumes raw timing
   samples directly. Device-unique identity and authenticated,
   rollback-resistant authorization policy remain separate requirements.

Passing these engineering gates supports a VibeOS platform claim; it is not by
itself a formal NIST/CMVP entropy-source validation.

## Primary references

- [jitterentropy-rs](https://github.com/qnfm/jitterentropy-rs)
- [Upstream jitterentropy-library](https://github.com/smuellerDD/jitterentropy-library)
- [NIST SP 800-90B](https://csrc.nist.gov/pubs/sp/800/90/b/final)
- [NIST SP800-90B EntropyAssessment](https://github.com/usnistgov/SP800-90B_EntropyAssessment)
