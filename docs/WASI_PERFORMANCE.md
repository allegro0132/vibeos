# WASI interpreter performance investigation

The release build inherited `opt-level = "z"` for both the Wasmi interpreter
and shared kernel primitives. Optimizing these hot paths for size substantially
reduced CPU throughput. The fix selects `opt-level = 3` for
`vibeos-wasmi-softfloat` and `vibeos-core`, while preserving the size-oriented
profile for other packages and the existing storage overrides.

## Controlled measurements

Same unmodified CoreMark WASI module, wasi-sdk 33, single-hart QEMU 11.0.3
`virt/rv64`, 1 GiB, single-thread TCG, real virtual clock, no `icount`.
Every reported performance or validation run lasted at least 10 seconds and
passed the upstream CRC checks. Each number below is the median of three
performance runs. Compilation and the two VMs were kept out of timed runs.

| Build | CoreMark iterations/s | Relative to original |
| --- | ---: | ---: |
| Original size-optimized runtime | 26.393402 | 1.00× |
| Wasmi optimized for speed | 77.662722 | 2.94× |
| Wasmi optimized, with poll instrumentation | 77.349433 | 2.93× |
| Wasmi + kernel core optimized, with instrumentation | **105.579898** | **4.00×** |

The final performance samples were 105.618927, 105.579898 and 105.462982.
They ran 2,000 iterations in 18.936, 18.943 and 18.964 seconds. The validation
seed set ran 2,000 iterations in 18.942 seconds and also passed.

The earlier Debian native median of 9523.896871 is still about 90.21× faster
than the optimized interpreter. This is a comparison of whole execution stacks,
including Wasmi interpretation inside QEMU, compilers and standard libraries.
The changes fix measured build-configuration overhead; they do not turn the
interpreter into native or AOT execution.

## Where the time goes

The benchmark-only `WASI profile` record contains poll count, consumed fuel,
time inside `WasiInvocation::poll`, invocation wall time, and timer frequency.
`profiles.json` associates these records with requests. Timing starts after
module instantiation and stops before terminal logging and resource teardown.
Poll time includes interpreter execution, fuel resumption, host work and any
interrupt time inside the call. Outside-poll time includes scheduler work,
authority checks and waits; this is elapsed-time attribution, not a CPU profiler
or a claim that all outside time belongs to one function.

For the second performance sample, the Wasmi-only instrumented image spent
15.704472 seconds inside runtime polls and 4.521701 seconds outside (22.36%).
After optimizing the shared core, these were 16.830258 and 2.123530 seconds
(11.20%), while completing 2,000 rather than 1,563 iterations. Outside-poll
cost per iteration fell from about 2.893 ms to 1.062 ms. Core allocation and
capability primitives can also be used from inside a runtime poll.

The interpreter remains the dominant measured cost. No change to guest
algorithms, fuel quantum, output bounds or security checks contributed to the
reported improvement.

## Compatibility and footprint

- Wasmi `extra-checks`, validation, memory bounds and fuel accounting remain on.
- Default total fuel stays 10 million; only the explicit benchmark image uses
  10 billion. Both still yield every 10,000 fuel.
- Cancellation, authority checks, private capabilities, allocation domains and
  the single-instance limit are retained.
- Profiling counters and timer reads compile only with `wasi-benchmark`.
- QEMU benchmark boot heap availability changed from 116,784 to 116,412 KiB:
  372 KiB additional linked code/data/reserved-layout footprint (about 0.32%
  of the previous free heap). This is not an ELF file-size measurement.
- The shared Wasmi release change passed 454 Core/Component/WASI tests.
  After the core optimization, 396 core/WASI/service tests passed. The latter
  suite leaves the existing stdlib fixture and IRQ-probe documentation example
  opt-in. These counts overlap and must not be added as unique tests.
- The final target run completed all six WASI invocations, with clean allocation
  reclamation, zero guest capabilities and zero I/O waiters.

The package overrides affect all firmware using these shared crates. Archived
performance/cost baselines should retain their original build identity;
semantic tests passing does not preserve old timing values.

## Reproduce and inspect

Follow [CoreMark setup](COREMARK_WASI.md), then run:

```sh
scripts/benchmark-coremark-wasi.py --work target/coremark-performance/repeated
cargo test --release --locked --offline -p vibeos-core -p vibeos-wasi-runtime -p vibeos-wasi-command
cargo test --release --locked --offline -p vibeos-wasm-runtime -p vibeos-component-runtime
```

Evidence from this investigation is under `target/coremark-performance/`:
`wasmi-o3/`, `profiled/`, and `core-o3/` contain complete outputs, environment
hashes, UART logs and per-run results. `optimization.json` summarizes before,
after and final poll measurements. `regression.log` and `core-regression.log`
contain test outcomes. The original baseline remains unchanged under
`target/coremark-benchmark/vibeos-single/`.

## Follow-up: inline checked scalar memory helpers

A subsequent investigation found out-of-line calls in the scalar memory path.
For example, the previous RISC-V `memory::access::load::<u32>` included a stack
frame, return-address/frame-pointer saves and restores, in addition to the actual
bounds check and load. Nine small address/load/store composition helpers now use
`#[inline(always)]`. This removes avoidable call boundaries in the instruction
handlers while leaving overflow checks, range checks, byte order, unaligned
access and trap behavior unchanged. No unsafe access or alignment assumption was
introduced.

The two broader compiler experiments were rejected: final-firmware `-O3` gave
99.253470 iterations/s, and compiling the entire Wasmi numeric helper crate at
`-O3` gave approximately 95 iterations/s. Neither override is retained. The
previous Wasmi and kernel-core package overrides remain the only new package
speed overrides from this investigation.

The same saved pre-change ELF was rerun after the candidate on the same host,
using the new `--kernel` option. This distinguishes a code improvement from a
change in host conditions. Explicit-ELF runs imply `--skip-build`, and their
metadata records the actual ELF hash separately from the current workspace.

| Single-hart run | Performance samples (iterations/s) | Median |
| --- | --- | ---: |
| Previous ELF, contemporaneous rerun | 103.625046, 103.327770, 103.441074 | 103.441074 |
| Checked memory helpers inlined | 133.490905, 133.312808, 133.497765 | **133.490905** |

This is **1.2905×** the contemporaneous baseline, and **5.0577×** the original
26.393402 result. Each candidate performance run completed 2,598 iterations in
19.462, 19.488 and 19.461 seconds; validation completed in 19.451 seconds. All
passed CRC validation. Both measured images reported 116,412 KiB of free boot
heap, so there was no increase in this linked-memory footprint measure.

Median runtime-poll time per iteration fell from 8.578 ms to 6.528 ms. The
outside-poll fraction rose from about 11.3% to 12.9% because the inner work became
faster; the fuel quantum and authority checks were not relaxed. The unchanged
Debian native result is still approximately 71.34× faster, so this remains an
interpreter-stack comparison rather than native execution parity.

A new runtime test exercises 160 combinations of scalar widths, signed/unsigned
extension, unaligned addresses, final valid accesses, out-of-bounds stores and
independent out-of-bounds loads. The real interpreter executes these Wasm cases.
Results, profile records and ELF identities are in
`target/coremark-performance/memory-inline/` and `previous-recheck/`;
`memory-optimization.json` retains the comparison and rejected experiments.

Follow-up validation passed 36 host tests (one optional stdlib fixture test
ignored), including the 160 interpreter cases above. The ordinary four-hart
QEMU image also passed the end-to-end suite: 44 SSH requests, Rust/C commands,
binary stdin and separate stderr, upload rejection, containment, cancellation,
disconnect recovery, post-boot compilation/upload, and execution after reboot.
This follow-up used five repeated invocations, not another 100-cycle run. All
33 logged invocation lifecycles across both boots reported clean reclamation,
zero guest capabilities and zero I/O waiters. Evidence is in
`memory-regression.log`, `memory-acceptance-2.log` and `memory-acceptance-2/`.
The acceptance script now checks the pinned SDK before booting QEMU.

```sh
# Run an immutable saved image rather than the mutable build output path.
scripts/benchmark-coremark-wasi.py --kernel target/coremark-performance/memory-inline.elf \
  --work target/coremark-performance/memory-inline-repeat
cargo test --release --locked --offline -p vibeos-wasmi-core-softfloat \
  -p vibeos-wasi-runtime -p vibeos-wasi-command
```
