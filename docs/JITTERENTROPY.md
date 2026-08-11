# Milk-V Duo Jitterentropy qualification

VibeOS pins `jitterentropy-rs` 0.1.1 as a Git submodule at upstream commit
`c5bd2e17194fe3a04d17f74027bb67622579405f`. The upstream tree and license stay
unmodified in Git; `patches/jitterentropy-rs/0001-vibeos-qualification.patch`
adds one qualification-only API behind the crate's `raw-noise` feature plus a
no-std warning fix. `scripts/prepare-jitterentropy-rs.sh` verifies the exact,
clean submodule, exports it to `target/vendor/jitterentropy-rs`, and applies the
patch only to that generated build copy.

The crate describes itself as a Rust rewrite scaffold, not a certified or
behaviorally equivalent replacement for the upstream C implementation. VibeOS
therefore confines it to qualification images. The base probe is UART-only; a
second high-throughput image reuses the visibly insecure fixed-key SSH
acceptance fixtures solely to transport raw evidence. Neither is a production
entropy capability and neither enables production SSH.

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
- `jent raw N` calls the qualification-only `raw_block` API. The delta is
  calculated inside the same private `sample_with_delta()` function used by
  conditioned output. No probe executes in the `before..after` timing window;
  the evidence write occurs only after that window closes. Normal conditioner,
  memory-disturbance, variable-work, and health-test paths still execute, while
  conditioned output is discarded and zeroized. The command is compiled only
  into this qualification image.
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

### High-throughput SSH evidence image

Build and package the separate network qualification image:

```sh
./scripts/build-milkv-duo.sh --jitterentropy-ssh-probe
./scripts/package-milkv-duo-sdk.sh --jitterentropy-ssh-probe /path/to/duo-buildroot-sdk
```

This image starts the same DHCP/port-2222 service as
`milkv-ssh-acceptance`. It deliberately embeds fixed public test identities
and deterministic SSH protocol randomness. Those weaknesses do not alter the
raw timing deltas, but they make the endpoint unsuitable for secrets or any
production network. Preserve the UART warning and announced lease from every
boot as evidence that the intended board/image was addressed.

The exact SSH exec command `jent raw N` bypasses VSH's normal 64 KiB capture
limit. Acquisition still runs the same collector and static raw buffer; it
yields to the TCP stack after every 128 deltas. After acquisition, stdout is a
framed binary stream containing an ASCII header, exactly `N` little-endian
`u64` deltas, and an ASCII health trailer. The host wrapper pins the test host
key and crypto profile, archives the original frame and SSH diagnostics,
strictly validates all counts and health fields, and emits the decimal input
expected by the upstream tools:

```sh
./scripts/jitterentropy-ssh-capture.sh BOARD_IPV4 1000000 \
  evidence/board-01/runtime/jent-raw-noise-0001.data
```

The outputs are the decimal `.data` file, `.ssh-frame`, `.ssh.log`, and `.json`
hash/metadata record. Because network polling changes the execution environment
between 128-sample blocks, record this as the SSH-stream image/load condition;
do not merge it with samples from the UART-only image.

## Raw runtime assessment

The original upstream commit's declared `raw-noise` feature has no public API.
The reviewable VibeOS patch adds only `raw_block`, after the private sampling
function has calculated each delta. This validates the Rust
implementation and its deployed timer path; it does **not** make the rewrite
equivalent to upstream C Jitterentropy.

For every board and operating condition, boot fresh, run `jent smoke`, then
capture one uninterrupted block of at least 1,000,000 consecutive deltas:

```text
vibe> jent raw 1000000
```

At 115200 baud the UART transcript is tens of megabytes and takes roughly an
hour. Use the SSH evidence image above when that distinct qualification
condition is acceptable. For UART capture, disable terminal line wrapping and
preserve the complete binary-clean log. Extract it with strict marker, order,
and count checks:

```sh
python3 -B scripts/jitterentropy-extract.py \
  --mode runtime \
  --expect-blocks 1 \
  --expect-samples 1000000 \
  --output evidence/runtime/jent-raw-noise-0001.data \
  evidence/runtime/uart.log
```

The Rust crate does not expose upstream's internal `jent_stuck` counter, so the
UART marker honestly reports `stuck=not-exposed`. Zero, repeated, or otherwise
pathological deltas remain in the raw dataset and are visible to the NIST
estimators. Any startup or runtime health failure rejects the run; do not join
partial captures or remove failed samples.

## Restart assessment

Collect 1,000 independent restarts with exactly 1,000 deltas each. Every row
must begin after a real board reset or power cycle that recreates collector and
boot state; reallocating a collector in one boot is not a restart test.

```text
vibe> jent raw 1000
```

Preserve one UART log and one metadata record per restart, then extract all
rows in reset order:

```sh
python3 -B scripts/jitterentropy-extract.py \
  --mode restart \
  --expect-blocks 1000 \
  --expect-samples 1000 \
  --output evidence/restart/data \
  evidence/restart/uart-*.log
```

This creates `jent-raw-noise-restart.000000.data` through
`jent-raw-noise-restart.000999.data`. The six-digit sequence is checked again
before analysis, preventing a missing or reordered restart from being silently
accepted.

## Upstream and NIST analysis

Pin the analysis inputs used for this qualification:

- upstream `jitterentropy-library` v3.7.0 commit
  `e783cf1c450bce4d72f95c9f9c84546a6094976a`;
- a reviewed commit of NIST `SP800-90B_EntropyAssessment` (the assessment
  report records the exact commit automatically).

The official Makefiles require Linux, GCC/OpenMP, and the NIST development
libraries. In the same pinned Ubuntu 22.04/amd64 container used for Duo
packaging, install `libbz2-dev libdivsufsort-dev libjsoncpp-dev libssl-dev
libmpfr-dev`, mount both tool repositories and the evidence directory, then
run:

```sh
python3 -B scripts/jitterentropy-assess.py \
  --mode runtime \
  --input evidence/runtime/jent-raw-noise-0001.data \
  --output evidence/runtime/assessment \
  --upstream /tools/jitterentropy-library \
  --nist /tools/SP800-90B_EntropyAssessment \
  --osr 3

python3 -B scripts/jitterentropy-assess.py \
  --mode restart \
  --input evidence/restart/data \
  --output evidence/restart/assessment \
  --upstream /tools/jitterentropy-library \
  --nist /tools/SP800-90B_EntropyAssessment \
  --osr 3
```

The script validates all input counts, builds upstream `extractlsb`, applies
the requested LSB mask (default `FF:8`), builds and invokes NIST `ea_non_iid`
or `ea_restart`, retains full logs and SHA-256 hashes, and writes a JSON result.
Additional reviewed masks can be supplied as `--mask 0F:4`; every requested
mask must pass. For OSR 3 the gate is strict: runtime
`min(H_original, bits * H_bitstring) > 1/3`, and restart both `H_r > 1/3` and
`H_c > 1/3` per effective delta. Equality is not accepted.

## Hardware and operating-condition matrix

Define the supported voltage, clock, and temperature envelope before testing.
Cover multiple boards (preferably different production lots) and at minimum
nominal plus each supported corner, with idle and worst-case CPU/memory/I/O
loads. Include warm/cold transitions and any dynamic-frequency mode that can
occur in production. Each matrix cell needs its own runtime dataset; distribute
the 1,000 restart rows across the matrix only under an approved sampling plan,
or run a complete restart assessment per cell for the strongest claim.

For every capture archive: board model/revision/serial/lot, reset mechanism,
measured temperature and supply voltage, configured and measured CPU/timebase
frequency, load generator, firmware/FIT/image SHA-256, VibeOS commit and dirty
state, rustc commit and flags, `jitterentropy-rs` crate checksum, OSR/memory
size, UART adapter/settings, timestamps, operator, tool commits, raw-log/data
hashes, health outcomes, mask rationale, NIST logs, and final decision.

## Admission gate for production SSH

Production admission remains blocked until all of the following are completed:

1. `jent smoke` passes across representative boards and the supported
   voltage, clock, temperature, firmware, and workload envelope.
2. The crate-local `raw_block` extension captures the required runtime and
   independent-restart samples after the same measurement window used by the
   Rust collector.
3. SP800-90B non-IID analysis passes strictly above `1 / OSR` with a
   documented entropy rationale for this exact Rust implementation, compiler,
   and target.
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
