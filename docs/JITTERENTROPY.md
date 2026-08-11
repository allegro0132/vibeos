# Milk-V Duo Jitterentropy qualification

VibeOS carries a pinned port of upstream `jitterentropy-library` 3.7.0 for the
Milk-V Duo. The port builds and links, but it is deliberately confined to a
UART-only qualification image. It is **not yet a production entropy capability
and does not enable production SSH**. That boundary moves only after raw data
from real boards passes the runtime and restart assessments below.

## What was ported

- The upstream C core is loaded as the `vendor/jitterentropy` Git submodule and
  the superproject gitlink pins commit
  `e783cf1c450bce4d72f95c9f9c84546a6094976a` (`v3.7.0`). Its selected BSD
  license remains upstream at `vendor/jitterentropy/LICENSE.bsd`; VibeOS does
  not modify the submodule sources.
- A freestanding adapter supplies allocation, explicit zeroization, and a timer.
  The timer is RISC-V `rdtime`, backed by the Duo's 25 MHz timebase. This
  measures variations in CPU execution time; it is not a claim that the board
  exposes a dedicated hardware RNG or that `rdtime` is a CPU-cycle counter.
- The thread-based upstream internal timer is compiled out and explicitly
  disabled at runtime. FIPS/SP800-90B startup and continuous health handling is
  forced, OSR is 3, and the memory-access region is capped at 256 KiB.
- The C translation unit is built with the upstream-required `-O0 -fwrapv` plus
  freestanding RISC-V LP64 flags. The Rust kernel may remain optimized; the
  Jitterentropy C core does not.
- `jent smoke` uses the public production API. It performs initialization,
  creates a collector, requests two successive 256-bit results, checks that
  both reads completed and are unequal, then zeroizes them without printing
  secret material.
- `jent raw N` follows upstream's `jitterentropy-hashtime` test semantics: it
  bypasses the production startup rejection so a bad platform still yields
  diagnosable raw timing data. Its output is evidence only and must never be
  used as keys, seeds, or protocol randomness.

This mirrors the important Linux pattern: initialization is a gate, collector
access is serialized, output is conditioned, and health-test errors are
propagated. Linux exposes its implementation as the Crypto API
`jitterentropy_rng` and treats intermittent/permanent health failures as errors;
it is separate from the general `drivers/char/random.c` pool.

## Build and boot the probe

Build the isolated image:

```sh
git submodule update --init --recursive
./scripts/build-milkv-duo.sh --jitterentropy-probe
```

The ELF and raw binary are written to
`target/milkv-duo-jitterentropy-probe/`. To produce the full SD image in the
same pinned SDK environment used by the normal Duo image:

```sh
./scripts/package-milkv-duo-sdk.sh --jitterentropy-probe /path/to/duo-buildroot-sdk
```

This creates
`target/milkv-duo-jitterentropy-probe/vibeos-milkv-duo-jitterentropy-probe-sd.img`.
Use the flashing procedure in `docs/MILKV_DUO.md`. Keep this image off untrusted
networks; it has no network stack, but its serial output intentionally reveals
raw noise-source samples.

At the UART shell, first exercise the real admission path:

```text
vibe> jent smoke
VIBE_JENT_SMOKE PASS version=3070000 ... osr=3 fips=forced internal_timer=disabled ...
```

Any `FAIL`, short read, startup error, or hang is a rejection. Two unequal
outputs are only a smoke test, not statistical validation.

## Raw runtime assessment

Capture one uninterrupted block of at least 1,000,000 deltas on each relevant
board/clock/voltage/temperature/load condition. Boot fresh and issue only:

```text
vibe> jent raw 1000000
```

At 115200 baud this is intentionally slow. Capture the complete UART transcript,
then extract the decimal one-sample-per-line format expected by the upstream
tools:

```sh
python3 -B scripts/jitterentropy-extract.py \
  --mode runtime \
  --expect-blocks 1 \
  --expect-samples 1000000 \
  --output evidence/runtime/jent-raw-noise.data \
  evidence/runtime/uart.log
```

The extractor rejects missing, duplicated, reordered, or unterminated markers.
It also reports stuck samples and blocks whose online health tests failed; do
not discard those failures.

Analyze the result with the `tests/raw-entropy/validation-runtime` flow from the
same upstream 3.7.0 tree and NIST's
`SP800-90B_EntropyAssessment` tool. Follow upstream's LSB-mask exploration;
testing the 64-bit deltas as if all bits formed a valid alphabet is not the
required analysis.

## Restart assessment

The upstream common profile uses 1,000 independent restarts with 1,000 samples
per restart. For every row, perform a real power cycle or reset that recreates
the entropy-source state, capture one `jent raw 1000` block, and preserve board
identity plus environmental metadata. Concatenate the UART logs only after
collection:

```sh
python3 -B scripts/jitterentropy-extract.py \
  --mode restart \
  --expect-blocks 1000 \
  --expect-samples 1000 \
  --output evidence/restart/data \
  evidence/restart/uart-*.log
```

This emits `jent-raw-noise-restart.000000.data` and so on, one restart per
file, ready for upstream `tests/raw-entropy/validation-restart/processdata.sh`.
A software loop that merely reallocates a collector is not a restart test.

## Admission gate for production SSH

The port can be promoted into a production `RandomSource` only when all of the
following are reviewed and recorded:

1. `jent smoke` passes on every boot across representative boards and the
   supported voltage, clock, temperature, and workload envelope.
2. Runtime and restart SP800-90B non-IID analyses pass on real-device raw data.
   For this common Jitterentropy profile at OSR 3, upstream's acceptance
   rationale requires more than `1 / OSR`, i.e. more than one third bit of
   min-entropy per accepted time delta. Retain the full reports and masks used.
3. No unexplained startup, RCT, APT, lag-predictor, intermittent, or permanent
   health failure is hidden. Production reads must fail closed on such errors.
4. The exact compiler, C flags, upstream commit, board revision, firmware,
   operating conditions, raw logs, extracted data, and analysis-tool revisions
   are archived. Changing timer, memory size, loop counts, compiler semantics,
   firmware, or SoC operating envelope invalidates the evidence until retested.
5. Jitterentropy is used to seed/reseed a bounded DRBG; SSH never consumes raw
   deltas directly. Device-unique host-key provisioning and authenticated,
   rollback-resistant authorization policy remain separate requirements.

Passing these engineering gates supports a VibeOS platform claim; it is not by
itself a formal NIST/CMVP entropy-source validation.

## Primary references

- [Upstream jitterentropy-library](https://github.com/smuellerDD/jitterentropy-library)
- [Linux Jitterentropy core](https://github.com/torvalds/linux/blob/master/crypto/jitterentropy.c)
- [Linux Crypto API adapter](https://github.com/torvalds/linux/blob/master/crypto/jitterentropy-kcapi.c)
- [NIST SP 800-90B](https://csrc.nist.gov/pubs/sp/800/90/b/final)
- [NIST SP800-90B EntropyAssessment](https://github.com/usnistgov/SP800-90B_EntropyAssessment)
