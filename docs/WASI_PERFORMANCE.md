# WASI runtime performance investigation

## Pthread runtime optimization (2026-09-10)

The final four-hart VibeOS image reaches the goal of **at least 90% of Debian
Wasmtime with fuel at every worker count**, using three interleaved performance
samples and an independent validation-seed sample per count. M1/M2/M3 are one,
two or three actual pthread workers plus the waiting main thread.

The final paired Debian M3 run was substantially slower than the preceding
reference. To avoid crediting that fluctuation as a runtime advantage, the
conservative comparison below uses the **higher median at each worker count**
from the two adjacent Debian runs. This is a sensitivity check, not an additional
physical run. Every raw sample, including low scores, remains in the reports.
Values are aggregate iterations/second.

| Measurement | M1 | M2 | M3 |
| --- | ---: | ---: | ---: |
| Final VibeOS Wasmtime | 2248.13 | 4526.90 | 7013.31 |
| Immediately paired Debian Wasmtime, fuel | 2430.80 | 4691.72 | 6353.14 |
| Preceding Debian Wasmtime, fuel | 2421.85 | 4891.33 | 7335.88 |
| VibeOS / conservative reference | **92.5%** | **92.6%** | **95.6%** |

VibeOS ranges were 2228.19–2257.62 (M1), 4030.38–4535.20 (M2), and
6916.96–7057.53 (M3). The paired Debian M3 range was 5850.45–6678.70;
the preceding reference range was 7284.26–7338.88. The apparent paired M3
advantage is not evidence of a stable advantage over Linux. VibeOS M3/M1 is
3.12×; slightly superlinear scaling can reflect fixed costs and host variation.
These are median throughput results, not a lower bound for individual runs.

All runs use QEMU 11.0.3, `virt`, `rv64`, four harts, 1 GiB, MTTCG, VM-clock RTC,
no `icount`, the same Wasmtime 48/compiler correctness patches, and the identical
46,489-byte threaded Wasm (SHA-256
`3a6b9af26c55b962a79c5fd6a3e52f850b39d1ca373178a436379970a013017f`).
The 36 retained samples across these three runs pass per-worker CRC validation
and last at least 18.993 seconds. All 15 final VibeOS invocations, including
calibration, report clean reclamation and the expected distinct worker harts.
Builds completed before the serial VM runs. Five-second process snapshots found
no overlapping QEMU or compiler during the final pair; editor/desktop background
load remained. Measurements ran on an Apple M3 Max (14 CPU cores, 36 GiB RAM).

The optimized image is based on `8717c4c40e46f9ad964186849a749ecaa3cce674`
plus the recorded working-tree changes; that Git revision alone does not identify
the measured source. Benchmark ELF SHA-256:
`1bc44062f4ad91e7f01da33bf958ee5dcac23aa037d12537754807f6fceee8d3`.
The [verified comparison](../benchmarks/wasm-runtime/results/coremark-threads-goal90.json)
contains exact medians, ranges, configuration and executable hashes; the
[acceptance record](../benchmarks/wasm-runtime/results/coremark-threads-goal90-acceptance.json)
binds source-file hashes, regressions and conservative ratios to this image.

Profiling found repeated invariant private capability lookups and shared writes
in the fuel path. Same-image measurements also correlated slower runs with worker
placement on the boot hart. The changes remove invariant private-slot lookups
from each in-fiber continuation, remove a shared aggregate fuel counter whose
bound is already enforced by the fixed Store count, separate worker counter
cache lines, and record each pinned worker's hart once. Four-hart placement leaves
the boot hart for I/O and supervision; smaller topologies retain all online harts.
The 10 ms SYSTEM reaper is also pinned to the boot hart: previously workers could
steal it, reintroducing periodic scheduling contention. After this change, M1
fuel continuations follow the expected 31-of-32 batch pattern and its measured
range narrows. This evidence does not isolate each kernel service's time cost.

Per-Store fuel remains 100 billion in the benchmark and 10 million in the ordinary
image, with a 10,000-fuel quantum and maximum batch of 32. Live cancellation,
caller authority, memory/compiler checks and allocation-domain reclamation are
unchanged. The [ownership proof](../benchmarks/wasm-runtime/coremark-threads.md#fuel-policy-ownership-invariants)
explains why private-slot checks and the aggregate counter are redundant.
No experimental synchronous-fuel vendor patch or function optimization attribute
is retained; neither improved fixed-work instruction-count diagnostics.

The final ordinary image passes 57 thread/atomic/trap/fuel/reuse cases with clean
reclamation. The final benchmark image passes six SSH disconnect cancellations
within 30 seconds and six successful follow-up runs. Placement unit tests cover
small and sparse topologies. The final image also passes all six one-hart
fixed-work diagnostic calls and all six two-hart real-clock performance/validation
calls (M1/M2/M3). Thread statistics now come from the common retirement
path after all joins, fixing missing short-call diagnostics when main exit raced
worker cleanup. A previous two-hart `icount` M3 diagnostic timed out and remains
recorded as a failed experiment; real-clock MTTCG fallback completed. This work
does not claim to rerun the entire original WASI acceptance matrix.

Evidence and intermediate attempts remain under `target/coremark-threads/goal90/`.
`supervisor-full` and `supervisor-debian-fuel` are the final pair;
`isolated-debian-fuel` is the conservative reference. `supervisor-source.json`
and `.patch` bind the build to source; build logs, regression logs and
`supervisor-process-audit.jsonl` are adjacent. The earlier `retire-*` pair overlapped
an external VM near the end of its Debian run and is not final acceptance evidence.
The next `isolated-*` pair failed M1 at 88.6%, motivating the supervisor fix.
Neither failed nor noisy experiments were deleted or substituted into medians.

Comparison limits remain: Linux uses OS threads and the official Preview 1
adapter, fixed RV64GC compilation and synchronous fuel counting; VibeOS enables
firmware-discovered Zba/Zbb/Zbc/Zbs and retains async scheduling/capability checks.
Compilation and upload are outside CoreMark timing. These are QEMU throughput
measurements, not certified CoreMark ratings or physical-hardware measurements.
Reproduction commands are in the [benchmark guide](../benchmarks/wasm-runtime/coremark-threads.md).

## Previous pthread CoreMark measurement: 66a1e6c (2026-09-09)

Rebuilt kernel revision `66a1e6cfed113db8f2e017f5350ee2bb41b502c6` with
`wasi-benchmark,wasmtime-command-fuel-batch,wasmtime-threads`, using the pinned
nightly and wasi-sdk 33. No runtime optimization was changed for this measurement.
All four runs used QEMU 11.0.3, `virt`, `rv64`, four harts, 1 GiB,
`tcg,thread=multi`, `-rtc base=utc,clock=vm`, and no `icount`. Builds completed
before measurement and VMs ran sequentially on an Apple M3 Max host (14 CPU
cores, 36 GiB RAM). The native baseline compiled the
same pinned upstream CoreMark POSIX pthread sources with Debian GCC 14.2.0
and `-O3 -pthread -DMULTITHREAD=4 -DUSE_PTHREAD=1 -DITERATIONS=1`.

Values below are median **aggregate iterations/second**, from three interleaved
performance samples per worker count. M1/M2/M3 mean one/two/three actual pthread
workers plus a waiting main thread, not independent processes. VibeOS currently
has capacity for three workers and the main thread.

| Platform | M1 | M2 | M3 | M3 / M1 |
| --- | ---: | ---: | ---: | ---: |
| VibeOS Wasmtime, bounded fuel batching | 2163.97 | 3906.73 | 5698.58 | 2.63× |
| Debian native C pthread | 9317.84 | 18863.83 | 28183.75 | 3.02× |
| Debian Wasmtime 48, no fuel | 2667.74 | 5365.68 | 8090.69 | 3.03× |
| Debian Wasmtime 48, fuel | 2416.28 | 4840.18 | 7303.58 | 3.02× |
| Native median / VibeOS median | 4.31× | 4.83× | 4.95× | — |

VibeOS's M3 parallel efficiency is **87.8%**. Its M3 throughput is 70.4% of
Linux Wasmtime without fuel, or 78.0% with fuel. Linux fuel counting reduces
throughput by about 9–10%, without appreciably reducing scaling. VibeOS workers
continue in the same fiber at 96.6–96.8% of fuel decisions across all three
worker counts, confirming that batching is active. The remaining scaling gap
therefore warrants profiling the concurrent runtime/scheduler/check paths;
these measurements do not isolate a particular lock or establish a cause.

All **48 measured samples**, including a separate validation-seed run for every
platform/worker count, passed upstream CRC checks and lasted at least 17.334
seconds. All **15 VibeOS invocations** (three calibrations plus twelve measured
runs) exited zero, used the expected number of distinct worker harts, and
reported `reclaimed=true caps=0 waiters=0`. VibeOS performance ranges were
1851.09–2218.92 (M1), 3475.00–4297.06 (M2), and 5684.08–6145.87 (M3);
the medians should not be interpreted as a guarantee for every run.

Comparison limits: Debian Wasmtime uses the standard Linux runtime, OS threads
and official Preview 1 adapter, with the repository's RISC-V compiler correctness
fixes. Its compiler target is RV64GC; VibeOS additionally enables the firmware's
Zba/Zbb/Zbc/Zbs extensions. Debian's fuel mode grants 100 billion per Store but
does not reproduce VibeOS's asynchronous 10,000-fuel checks, capability checks,
allocation domains or scheduling. Compilation and upload are outside CoreMark's
timed region. These are QEMU throughput measurements, not physical hardware or
certified CoreMark ratings.

Reproduction and native baseline options are documented in
[`coremark-threads.md`](../benchmarks/wasm-runtime/coremark-threads.md).
The verified [machine-readable comparison](../benchmarks/wasm-runtime/results/coremark-threads-66a1e6c.json)
includes revision, executable hashes, ranges and scaling. Full evidence is under
`target/coremark-threads/current/{vibeos-4h,debian-native-4h,debian-wasmtime-4h,debian-wasmtime-fuel-4h}/`:
commands, frozen kernel/native ELF/Linux runner, stdout/stderr, boot logs,
calibration, per-invocation profiles and environment metadata. Build logs and
toolchain provenance are in the parent directory.

The shared Wasm is 46,489 bytes, SHA-256
`3a6b9af26c55b962a79c5fd6a3e52f850b39d1ca373178a436379970a013017f`;
kernel SHA-256 is
`795483f3936e5308eb01173b38c65c9c379e58aebafa1d4b84d0f6fb36a32930`.

## Current Wasmtime command result (2026-09-09)

Ordinary CoreMark Wasm was uploaded over authenticated OpenSSH, compiled inside
VibeOS, and run through the actual command service. The final paired QEMU
measurements meet the **less-than-5× native slowdown** target:

| Runtime | Three performance samples (iterations/s) | Median |
| --- | --- | ---: |
| VibeOS Wasmtime command | 2035.996417, 2020.202020, 2005.454837 | **2020.202020** |
| Debian native C | 9870.941457, 9544.881508, 9932.576474 | **9870.941457** |

Median slowdown is **4.886116×**. Even the fastest Debian sample divided by the
slowest VibeOS sample is **4.952780×**. Validation scores are 1993.779408 and
10054.973822 respectively. All timed intervals exceed 10 seconds and pass the
correct seed-specific CRCs. The VMs ran serially, without concurrent compilation.
These are CoreMark timed-region scores; compilation and SSH setup are excluded,
with separate whole-invocation counters retained in the logs.

The useful change is bounded in-fiber fuel scheduling: authorization,
cancellation and executor competition are checked at every nominal 10000-fuel
boundary, while up to 32 quanta use one native poll. Competing work and blocking
I/O yield normally. The reserve and total fuel are unchanged. Single-writer
accounting avoids unnecessary atomic read-modify-write instructions. Broad
kernel opt-level 3 regressed throughput and was not adopted.

Enable the optional backend with
`WASI_WASMTIME=1 WASI_FUEL_BATCH=1 scripts/run-wasi-qemu.sh`.
Formal runs use `wasi-benchmark,wasmtime-command-fuel-batch` and the benchmark
script's `--wasmtime --fuel-batch` flags. Default images continue to use Wasmi.

Evidence is in `target/coremark-performance/wasmtime-command-final/`,
`debian-command-final/results/native-summary.json` and
`wasmtime-command-final-comparison.json`. The final firmware SHA-256 is
`5e4f1ded7cc2978943ee7e25de4b5a71398a8834c3c34aeec1593d974b0be655`;
Wasm SHA-256 is
`c5f77f7fd38fc3e87e7f9ccbd761327beee01de2adc9f24736ed4c94fe3dcc9a`.
Toolchain versions, frozen firmware, native compiler environment, source/module
hashes, command output and profiles are retained alongside those results.

The new policy passed 23 host streaming cases, bounded-fuel/cancellation tests,
and the complete Rust/C QEMU functional diagnostic with 100 consecutive
reclaimed calls and restart persistence. The four-hart native platform suite
passed **410/410**, including FP state, stack guards, suspended cancellation,
raw fault cleanup and the expected fatal host read-only write. Evidence:
`wasmtime-command-fuel-functional/` and `wasmtime-fuel-platform-recheck/`.
The default Wasmi tests and firmware compilation check also pass.

**Remaining limitation:** functional diagnostics use a recorded 30-second SSH
keepalive. The original 2-second keepalive failed during synchronous compilation;
compiler scheduling/deadlines and compiler stack-fault supervision are not
finished. Meeting the CoreMark target does not claim these hardening gates are
complete. Default limits remain 10 million fuel; only the explicit benchmark
image grants the larger allowance.


## Earlier interpreter investigation

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

## Investigation toward less than five times the native baseline

The requested threshold is strictly above **1904.779374 iterations/s**, using
the retained Debian native median of 9523.896871. The best verified VibeOS result
remains 133.490905; this target is **not achieved**.

The new host-only `instruction-profile` feature counts executed Wasmi operations
per thread. It is absent from firmware builds and instrumented wall times must
not be reported as performance scores. The diagnostic runner uses the same
WASI invocation implementation, accepts the original module bytes and arguments,
and supplies stdin/stdout/stderr and explicit host clocks:

```sh
cargo run --release --locked -p vibeos-wasi-runtime \
  --features instruction-profile --example run -- \
  target/coremark-wasi/coremark.wasm 0 0 0x66 10
```

The ten-iteration diagnostic executed 3,021,448 operations. Twenty-three common
integer, memory and branch operations accounted for 96.264% of them. An
experiment moved these into a smaller dispatch loop, retaining the original
handlers and fuel checks. It regressed to a median of 92.068337 (samples
92.068337, 91.680149, 92.181800); all performance and validation CRCs passed.
The split was reverted. `hot-split/`, `hot-split.elf`, and
`hot-split-instrs.rs` retain the rejected experiment. `opcode-profile.stderr`
and `fivefold-investigation.json` retain the counts and threshold calculation.

The previous profile also shows approximately 76 polls per CoreMark iteration,
and 0.969 ms/iteration outside runtime polls. That overhead alone would prevent
the target even with a hypothetically free interpreter. The scheduler currently
removes and reinserts the whole task record at each poll boundary; reducing
record movement without weakening domain/lifecycle checks is a separate
optimization candidate, not a demonstrated speedup.

At approximately 755,000 fuel per iteration, the former 10-billion benchmark
budget cannot sustain even a ten-second run at the target throughput. The
trusted ceiling and benchmark image budget are now 100 billion. Ordinary
invocations remain at 10 million, every quantum remains at most 10,000, and
guest arguments cannot raise either limit. This is measurement headroom, not
a performance optimization. Historical ELF scores retain their old budgets.

### Task-record indirection experiment

An implementation stored each task record in a SYSTEM-owned box so BTreeMap
removal/reinsertion moved only a pointer. Existing task lifecycle and domain
checks were retained. Core tests completed 380 passing executions (including
overlapping subprocess runs), with one existing documentation example ignored.
The candidate also completed all six benchmark invocations with clean resource
reclamation and passed all CoreMark CRCs.

| Run | Performance samples | Median |
| --- | --- | ---: |
| Boxed task records | 113.202849, 114.786385, 115.339727 | 114.786385 |
| Saved previous ELF, immediate rerun | 114.920635, 114.306534, 114.378767 | 114.378767 |

The prior ELF's contemporaneous score is lower than its historical 133.490905,
so comparing the candidate only against that historical value would incorrectly
attribute host/environment variation to the code change. Against the control,
the candidate is only 0.36% faster, less than the observed run spread. Median
outside-poll cost changed from 1.564 to 1.499 ms/iteration. This does not establish
a useful end-to-end speedup, so task-record indirection was reverted. Evidence
is in `boxed-task/`, `boxed-task-control/`, `boxed-task-comparison.json`,
`boxed-task-tests.log`, and the saved `boxed-task.patch`/`boxed-task.elf`.

The next engine-level investigation is specified in
[WASI_RV64_CODE_CACHE.md](WASI_RV64_CODE_CACHE.md). It reuses existing W^X code
pool and fault-domain reclamation mechanisms. The backend remains default-off.
The fivefold target remains unverified and unmet.

The RV64 compiler in `wasm-rv64/` passed 200 arithmetic/fuel and 16,416 memory
QEMU/OpenSBI executions, plus five host admission/limit tests. It is now connected
to WASI behind the default-off `wasi-rv64-cache` feature and the benchmark tool's
`--rv64-cache` flag. The initial full CoreMark run had correct CRCs but regressed
to median **26.670146**. Six normal invocations reclaimed all code-pool pages.
Approximately 54,477 native entries per iteration expose frequent transitions
through the cache lookup/context bridge. Completing hot instruction coverage
and reducing those transitions is required; this backend is not a retained
performance improvement or evidence that the fivefold goal has been met.

The next cache revision retains the current function's immutable record, skips
interpreter-only native entry stubs, and lowers more hot scalar instructions.
It passed another 900 QEMU comparison/shift cases. CoreMark median recovered to
**133.272217** (samples 133.272217, 132.618735, 135.793099), with CRCs valid and
all code pages reclaimed. Native calls fell to approximately 13,350 per
iteration. This is 4.997× the initial cache, not a demonstrated gain over the
interpreter's historical best. Evidence is in `native-hot/` and
`target/wasm-rv64-hot-probe/`; the native-baseline target remains unmet.

The branch-table/select revision reduced transitions again, to about 5,342
native calls per iteration, and scored median **199.273052**. A subsequent
checked aligned-memory fast path scored **202.740070** (202.740070, 201.348146,
203.816022); its additional 1.7% gain is provisional without a paired control.
Both revisions passed independent validation and all timed samples exceeded
10 seconds. Each benchmark had six zero-page native teardowns and no unclean
lifecycle. The aligned path checks the actual host pointer and uses byte
accesses on misalignment; full overflow/bounds checks precede both paths.
QEMU passed 200 arithmetic/fuel, 16,416 memory, 900 control and 240 table/select
cases, plus six host compiler and 13 WASI runtime tests (one stdlib test ignored).
Evidence: `native-flow/`, `native-aligned/`, `native-aligned-comparison.json`
under `target/coremark-performance/`, and `target/wasm-rv64-aligned-probe/`.
The historical Debian comparison is still approximately 47× slower, not within
5×. Per-quantum scheduling/authorization overhead is now also material and
must be addressed without weakening the 10,000-fuel cancellation boundary.

The aligned revision also passed ordinary-limit QEMU/SSH acceptance with 100
consecutive executions and 139 total requests. Both rebooted programs passed;
128 clean lifecycle records and 124 zero-page native teardown records showed
no residual capabilities, waiters or normal-exit code pages. Evidence is in
`target/coremark-performance/native-aligned-acceptance/`.

## Bounded continuation at fuel boundaries

The experimental native path now avoids a full executor round trip after a
fuel-only yield when no other work is runnable. Each continuation checks the
current exact task/domain, cooperative cancellation, local and stealable ready
work, and all WASI authority again. Each quantum remains 10,000 fuel; a batch
is bounded to 32 quanta. Host-call/I/O suspensions return to the executor.
The default interpreter/component paths do not opt into batching.

A serial candidate/control/candidate comparison used immutable ELFs:

| Revision | Performance scores | Median |
| --- | --- | --- |
| Bounded continuation | 269.596280, 266.791169, 264.253155 | 266.791169 |
| Saved aligned-memory ELF | 230.582205, 230.551905, 231.266065 | 230.582205 |
| Same continuation ELF, repeated | 267.343938, 267.665953, 263.383157 | 267.343938 |

This supports about **16%** improvement against the contemporaneous control,
not 32% against the older historical 202.740070 score. Median time outside the
runtime poll fell from 0.827 to 0.388 milliseconds per iteration. All timed
samples exceeded ten seconds and both seed sets passed CRC validation. Each
run had six zero-code-page teardowns and no unclean lifecycle. Evidence is in
`batched/`, `batched-control/`, `batched-repeat/`, `batched-comparison.json`, and
`batched-source/` under `target/coremark-performance/`.

The core suite passed, including a new check that ready peers and cancellation
prevent continuation. Fourteen WASI runtime tests passed (one stdlib test
ignored), including distinguishing fuel yields from host/terminal states.
The historical Debian ratio is still about 35.6×; the fivefold goal is unmet.

Ordinary-limit regression passed 44 SSH requests, including five consecutive
executions, Ctrl-C, disconnect recovery, containment and both persisted programs
after reboot. All 33 lifecycle records were clean; all 29 normal native
teardowns had zero code-pool pages. Evidence: `batched-acceptance/`. This is a
five-cycle follow-up, not a new 100-cycle acceptance result.

## Parallel-copy and immediate-branch coverage

The native compiler now handles `Copy2` with simultaneous read semantics,
signed immediate comparisons on either operand side, and unsigned immediate
comparisons on the left. All frame references and branch targets retain the
existing checks; unmetered backedges still fall back. QEMU passed 150 new
parallel-copy cases (aliasing, swaps, constants and large frame offsets), 1,500
comparison/shift cases, 240 table/select cases, 16,416 memory cases and 200
arithmetic/fuel cases. Seven host compiler tests passed.

The unchanged CoreMark module scored 299.614112, 299.325348 and 298.032764,
median **299.325348**. The adjacent saved previous ELF scored median
**267.361807** (268.294319, 264.165896, 267.361807), supporting a **12.0%** gain.
All samples lasted more than ten seconds and both validation seed sets passed.
Native entries fell from about 5,342 to 3,439 per iteration. Both benchmark
runs had six clean lifecycle/zero-code-page teardowns. Evidence is in
`native-copy/`, `native-copy-control/`, `native-copy-comparison.json`, and
`native-copy-source/` under `target/coremark-performance/`, with RV64 execution
evidence in `target/wasm-rv64-copy-probe/`.
The historical Debian ratio remains about 31.8×; the fivefold target is unmet.

The ordinary-limit follow-up passed 44 SSH requests, five consecutive runs,
cancellation and reboot, with 33 clean lifecycle records and 29 zero-code-page
normal teardowns (`native-copy-acceptance-retry/`). A pre-key-exchange transport
reset in the first attempt prompted a bounded retry for that negative-auth
fixture; explicit public-key rejection remains mandatory. Original failure
logs are retained in `native-copy-acceptance/`.

## Frame-register cache, containment, and measurement uncertainty

The experimental compiler now combines offset/width into a checked exclusive
end and caches up to six statically frequent frame slots in caller-saved RV64
registers. Entry reloads the frame; a shared exit writes every cached slot and
fuel back before returning for interpretation, fuel exhaustion or a memory
trap. A bounded two-pass compiler retains the uncached variant when the cached
variant exceeds the code budget. This preserves the combined allocation limit.

Eight host tests passed (one internal optimization check and seven limit tests).
The internal check observes 80 repeated frame accesses reduced to four entry/
exit accesses. QEMU passed the existing arithmetic, memory, control, flow and
parallel-copy cases plus an explicit interpreter-update/trap/re-entry case.
Evidence: `target/wasm-rv64-register-transition-probe/` and
`target/coremark-performance/native-register-tests.log`.

Real-clock medians were 282.366229 for the candidate, 262.397280 for the adjacent
saved native-copy control, then 210.224801 for the **same candidate ELF** again.
The separate boundary-only run had median 271.633107 with substantial spread.
These results do **not** establish a stable speedup. Host load also varied
substantially; that observation does not identify the cause of the variation.
All timed samples exceeded ten seconds and passed both CRC seed sets. See
`native-register-comparison.json` and the associated `native-end/`,
`native-register/`, `native-register-control/`, `native-register-repeat/` dirs.
The cache remains experimental and the fivefold goal is unproven and unmet.

Ordinary-limit execution completed **100 consecutive runs** and 126 clean
lifecycle records in the first boot. The original second boot hit the harness's
300-second readiness timeout while its log was still advancing. The process
was ended by the harness; its log is preserved. A subsequent attempt using
**the same disk and exact saved ordinary ELF**, with a 900-second allowance,
was ready in 130.18 seconds and ran both persisted programs successfully.
Across the completed execution phases there were 128 clean lifecycle records,
124 zero-page normal native teardowns, and no unclean lifecycle. This is a
recovered restart verification, not an uninterrupted harness pass. Evidence:
`native-register-acceptance/phase-1-results.json`, `boot-2.log`, `boot-3.log`,
`restart-recovery.json`, `reclamation-summary.json`; recovery driver:
`target/coremark-performance/native-register-restart.py`.

### Separate instruction-count diagnostics

`benchmark-coremark-wasi.py --icount-iterations 1000 --kernel PATH --rv64-cache`
uses fixed work and explicitly labels its output `formal: false`. It emits no
CoreMark rating in `results.json`; standard real-clock runs continue to reject
short or invalid samples and explicitly disable this diagnostic mode. Both
known CRC sets are checked, and only the upstream short-duration diagnostic is
allowed in diagnostic mode. Kernel/module hashes and the exact icount setting
are recorded. The virtual-clock-derived count is an estimate: it includes OS
work and can be affected by idle warp and interrupt timing. It is not a cycle
model or evidence of meeting the real-clock goal. See [QEMU's icount design](https://www.qemu.org/docs/master/devel/tcg-icount.html).

Candidate/control diagnostic medians were approximately 4.754/4.883 million
instructions per iteration; the small difference is near the sample spread.
Evidence: `native-register-icount/` and `native-register-icount-control/`.
This helps guide further investigation without substituting a virtual-time
score for the required formal benchmark.

### Stronger optimizing backend feasibility

The isolated [Cranelift no_std check](../wasm-rv64/experiments/cranelift-no-std/README.md)
pins Cranelift 0.135.1 and its dependency lockfile. Codegen and frontend compiled
successfully for `riscv64imac-unknown-none-elf` with default features disabled,
using the repository nightly and `-Zbuild-std=core,alloc`. This is a prerequisite
only: generated-code execution, execute-only code-pool compatibility, compiler
resource bounds and performance remain to be verified before optional kernel
integration. No Cranelift dependency was added to the root workspace or kernel.

The Cranelift feasibility experiment subsequently passed actual QEMU integer
execution and identified an execute-only compatibility issue: inline wide
constants require reading code pages. Passing a separate read-only literal
allowed 500 integer cases to execute on an execute-only page, with FS/VS off
and a probe-specific integer/ABI audit. See the [experiment report](../wasm-rv64/experiments/cranelift-no-std/README.md).
This is integration evidence only; no new CoreMark performance claim is made.

### Debian engine controls (2026-09-09)

The [isolated Linux runners](../tools/coremark-engines/README.md) provide the
same-engine and compiling-engine controls. All use one `rv64` hart, 1 GiB,
single-threaded QEMU TCG and real clocks without icount. Runs were sequential,
with no host build or other test VM overlapping measurements. The same unmodified
SDK 33 CoreMark module was executed. Every measured sample exceeded ten seconds,
passed upstream CRCs and exited successfully; each engine also passed a separate
validation seed set. These are measured CoreMark results, not EEMBC certification.

The final Debian cohort isolates Wasmi's Cargo features from Wasmtime:

| Mode | Median iterations/s | Three-sample range | Setup median | Peak RSS median |
|---|---:|---:|---:|---:|
| Debian GCC native, `-O3`, no LTO | 8867.683114 | 5621.36–9034.85 | — | 1068 KiB |
| Debian vendored software-float Wasmi | 119.508142 | 106.34–144.21 | 0.043882 s | 2688 KiB |
| Debian Wasmtime 48.0.0, Cranelift speed | 2095.825126 | 1681.43–2625.64 | 2.446575 s | 9968 KiB |
| Debian Wasmtime 48.0.0, Cranelift speed + fuel | 2298.304424 | 513.57–2421.68 | 2.766433 s | 12052 KiB |

**This cohort has substantial host-time variability.** Host load rose from about
5.35 to 12.59; even native throughput dropped sharply. QEMU remained active and
no thermal warning was reported. These observations correlate with the slowdown
but do not isolate its cause. No sample was removed. In particular, the fueled
median exceeding the unfueled median does not demonstrate a fuel optimization.
Ratios of these medians are descriptive only, not controlled estimates of small
engine, fuel or OS costs. Host evidence is retained with the results.

An earlier, less variable cohort measured native **9653.925702**, Wasmtime
**2789.949828** (2781.16–2803.68), and Wasmtime + fuel **2587.046050**
(2585.00–2601.55). Those compiling-engine binaries and their measured outputs
are retained unchanged. They were respectively 3.46× and 3.73× slower than that
cohort's native baseline. Its Wasmi result (161.459830) is exploratory only:
sharing the build with Wasmtime had enabled `bitflags/std` and `smallvec/serde`.
It must not be presented as the strict dependency-feature-matched control.

Before the final Debian cohort, two VibeOS controls also completed three valid
performance samples plus validation:

| VibeOS mode | Median | Range |
|---|---:|---:|
| Fresh same-workspace interpreter-only firmware | 133.916760 | 133.71–134.16 |
| Existing register-cache ELF, rerun without rebuilding | 278.059522 | 276.11–283.32 |

The cache therefore improved that VibeOS cohort by 2.08×. However, host variation
prevents using the later Debian cohort to assert a precise cross-OS percentage;
in particular, the earlier tentative “20% OS difference” is not established by
the strict control. Direct VibeOS profiling remains useful: each 2,632-iteration
interpreter sample spent about 17.14 seconds inside runtime polls and 2.54 seconds
outside them (about 12.96% of invocation time). Removing *all* outside-poll time
would at most yield about 1.15× for those samples, not an order-of-magnitude gain.
That is an upper-bound attribution, not a measured optimization. Normal teardown
and lifecycle checks passed for both VibeOS controls.

The evidence supports prioritizing an optimizing execution engine: compiling
execution is much faster even when VibeOS is absent, while scheduler-only work
cannot explain that gap. Larger compiled regions and fewer interpreter/native
transitions remain hypotheses to test, not individually quantified causes.
The experimental VibeOS cache still has not achieved the fivefold goal. The
Cranelift Wasmi-IR prototype separately passed its 200 QEMU fuel/frame cases;
it remains outside the kernel and has no CoreMark gain claim.

#### Configuration and comparison limits

Wasmi reuses `WasiInvocation` with eager validation, software float, `extra-checks`,
strict structural limits, 16 MiB linear memory, 100 billion total fuel and
10,000-fuel polls. Wasmi is compiled at opt-level 3 with the root release LTO and
size-optimized surrounding runtime. Its native cache and instruction profiling
are disabled. A dependency audit confirms the actual firmware's **Wasmi engine**
and its dependencies match the isolated Linux build's versions and features.
The shared admission policy and limits are identical. Ancillary firmware feature
unions (hash-library traits and admission parser `component-model`) are recorded
in `dependency-audit.json`; the shared admission policy still rejects components.
No claim is made that every ancillary crate, Linux allocation, capability checks,
allocation-domain accounting, ABI or scheduling matches the kernel.

Wasmtime explicitly selects Cranelift `speed` and official WASI Preview 1,
caps linear memory at 16 MiB and receives no directories or environment. Its own
100-billion-fuel counter has different units and no synchronous 10,000-fuel resume
quantum. Its normal stack checks, Linux virtual-memory traps and hardware floating
point remain enabled. These differences are intentional controls, not identical
metering. Setup includes engine creation, compilation, linking and instantiation;
it is excluded from CoreMark's timed interval. RSS covers the whole Linux process
and does not prove a bound on kernel compiler allocation.

Evidence under `target/coremark-performance/`:

- `debian-engines-isolated/`: final manifest, dependency audit, host observations,
  QEMU command, guest environment, `results/engine-results.json` and all raw logs.
- `debian-engines-ready/`: initial cohort, original build manifest and raw outputs;
  preparation failures and successful archive export are retained separately.
- `debian-control-vibeos/` and `debian-control-vibeos-cache/`: samples, profiles,
  hashes and lifecycle logs; exact ELFs are recorded in `environment.json`.
- `debian-engine-comparison.json`: both cohorts and VibeOS controls with explicit
  variability and comparison-limit flags. No cohorts are silently merged.

Reproduction, separate runner builds and sysroot preparation are documented in
the [runner README](../tools/coremark-engines/README.md).

### Direction update: port the Wasmtime stack

Following the compiling-engine controls, the active direction is now the
[Wasmtime runtime/compiler/WASI port](../wasmtime-runtime/README.md), rather than
extending the Wasmi-IR compiler experiment. The new isolated runtime and patched
Wasmtime compilation environment pass a RISC-V bare-metal core/alloc build.
CoreMark translation metadata agrees with pinned upstream. The Cranelift glue
and complete module compilation pipeline now also pass the bare-metal build.
All 80 function bodies match upstream native bytes and relocations; host std and no_std custom-platform
comparisons of the complete compiled module (inlining, trampolines and linking)
produces identical 232,872-byte artifacts. These are compilation checks, not
execution or benchmark results. On-device compilation budgets, execution,
ABI/platform hooks and WASI command integration are still open; no
performance gain or achievement of the fivefold goal is claimed for this port.


The no_std Wasmtime/custom-platform path additionally passed native execution on
macOS AArch64 and QEMU Debian RV64: 100 cycles of normal return and explicit
unreachable/divide/bounds/fuel traps. Each cycle released all platform mappings
and recovered the first-cycle heap baseline with its engine retained. This is
not the kernel's lifecycle gate or a CoreMark score. The host CoreMark compiler
reported 11,915,236 peak requested heap bytes, excluding allocator metadata and
stack; on-device allocation-budget acceptance remains open. Reproduction and
scope are documented in the runtime README above.

The native port now explicitly requires an LP64D RISC-V target: Cranelift's FP
calling convention cannot be mixed with the current IMAC kernel's LP64 ABI.
A complete `riscv64gc-unknown-none-elf` no_std library release build passed, and
native integration on IMAC is rejected. Assembly FP/FCSR context hooks and f64
host-call checks have been added. The kernel's GC target now enables FP at boot
on every hart, preserves FP/FCSR in 528-byte interrupt frames and 400-byte
catch/longjmp contexts. Four-hart QEMU acceptance passed 391 GC and 390 IMAC
checks, including deliberate FP clobber in a real interrupt. An initial existing
fault-isolation test race was fixed by awaiting actual terminal state with a
bounded deadline instead of eight yields. Initial failure and final results are
retained under `kernel-gc-irq-selftest/`, `kernel-gc-final-selftest/` and
`kernel-imac-fp-regression/`. Wasmtime execution is still not connected to these
kernel paths; no new VibeOS score is claimed.


A separate RX code-pool path now supports embedded native constants while the
existing component compiler retains execute-only mappings with MXR clear.
Four-hart QEMU passed 397 GC / 390 IMAC checks, including an actual PC-relative
constant load, exact permissions, zeroed reuse and recovery of abandoned XO+RX
runs across 16 fault/restart cycles. Evidence: `kernel-rx-gc/`, `kernel-rx-imac/`.
This is not yet Wasmtime module loading: image-wide RO followed by text-range RX,
linear-memory mapping and TLS still need the custom platform adapter. The
fivefold performance goal remains unverified.


The kernel now implements image-wide RO-NX freeze followed by page-aligned text
subrange RX publication. Invalid and overlapping ranges reject before mutation;
normal and raw-domain teardown retire mixed permissions before zeroed reuse.
Four-hart acceptance passed 406 GC / 390 IMAC checks (`kernel-image-gc/`,
`kernel-image-imac/`), including executable text between two non-executable
metadata pages and recovery of abandoned mixed images across 16 restarts.
The Wasmtime C API, linear-memory mapping and TLS integration are still pending;
this is not a new CoreMark score.


Wasmtime now compiles and executes raw core Wasm inside the VibeOS GC kernel via
an optional `wasmtime-native` test feature. The native return-42 case and an
infinite loop ending in `Trap::OutOfFuel` passed, followed by empty map registry,
code-pool baseline recovery and no active TLS call pointer. Four-hart QEMU passed
407 checks (`wasmtime-in-kernel/`, ELF hash and native marker recorded). An initial
RO conversion failure exposed partial-page protection lengths and was corrected
by rounding the covered range. Linear memory, complete platform recovery and
WASI/command integration remain pending; no CoreMark gain is claimed yet.


The Wasmtime kernel smoke now includes module-owned linear memory through a
bounded no_std MemoryCreator. Zero reservation permits moving the allocation as
needed; the 16 MiB logical limit and explicit bounds checks remain enforced.
The fixed 16 MiB physical reservation had incurred a 32 MiB size-class charge and
failed the shell's 8 MiB quota; no quota was raised to bypass that failure.
Four-hart QEMU passed 407 checks with guest-side memory.grow relocation, same-call
post-growth load, zero-fill and OOB trap evidence (`wasmtime-linear-movable-kernel/`).
Host memory tests passed 20 lifecycle cycles including omitted-maximum cap checks.
The changed CoreMark compilation configuration produces a 247,480-byte artifact
identical to upstream (`target/wasmtime-module-movable/`). WASI and runtime
performance acceptance remain open.


The first no_std Wasmtime Preview 1 adapter now passes 18 host custom-platform
ABI cases, including real Rust/C stdlib commands and an unchanged CoreMark smoke
(`wasmtime-wasi-host/results.json`). Expected CoreMark CRCs were observed, but the
1000-iteration run is shorter than ten seconds and explicitly reports an invalid
benchmark duration. No new formal score or VibeOS speedup is claimed. This is a
synchronous, bounded-buffer adapter; authenticated command integration, scheduling,
backpressure and supervised cancellation remain pending.

Four-hart VibeOS selftests passed 407 checks with 100 in-kernel compiled WASI
ABI probe invocations (monotonic clock, output, exit 7). Final code mapping and
active TLS checks passed (`wasmtime-wasi-kernel-verified/`). This does not yet
execute CoreMark in VibeOS or establish whole-instance/cancellation cleanup.

### First native Wasmtime execution in VibeOS (2026-09-09)

The ordinary CoreMark module is now compiled and executed inside VibeOS through
the no_std Wasmtime/WASI port. These are trusted synchronous probe results,
not the final SSH/vsh service with fuel-quantum scheduling and cancellation.

| Configuration | CoreMark iterations/s | Evidence |
|---|---:|---|
| VibeOS, generic no_std Cranelift ISA, explicit bounds, fuel | 1480.859886 | `wasmtime-coremark-kernel-single/results.json` |
| Debian, same port/adapter/configuration, performance median of 3 | 1398.210291 | `debian-wasmtime-port-runtime/results/ported-summary.json` |
| Debian native GCC, fresh performance median of 3 | 9947.962785 | `debian-wasmtime-port-control/results/native-summary.json` |

Every performance sample and the separate Debian validation samples exceeded
10 seconds and passed CoreMark CRC validation. The VibeOS module SHA is unchanged
(`c5f77f7fd38fc3e87e7f9ccbd761327beee01de2adc9f24736ed4c94fe3dcc9a`),
with 60000 iterations and a 100-billion total fuel budget. It consumed
38,115,341,140 fuel units, compiled in 1.361562 seconds and ran for 40.517 seconds.
Charged heap peak was 19,641,984 bytes; the owner returned to zero live bytes,
without denials, and the platform mapping/TLS checks passed. The 32 MiB budget
reserves 2 MiB for code and allows 30 MiB for compiler/instance heap allocations.
Kernel selftests passed 407 checks.

The resulting native/VibeOS ratio is about 6.72x, which does not meet the <5x
objective. The comparable port on Debian is not faster; this argues against
focusing the next optimization on VibeOS scheduler overhead. The earlier stock
Wasmtime Debian scores used a different engine configuration: automatic CPU
extension discovery and conventional virtual-memory/trap support. The port
currently uses a generic ISA and explicit bounds with movable memory. These
configuration differences must be separated before attributing the gap to the OS.
The two OS images still differ in guest RAM (Debian 1 GiB, VibeOS 128 MiB), and
no scheduling/permission-revocation acceptance is implied by these probes.

A single-hart multi-thread-TCG control scored 1481.115774. Changing to Debian's
single-thread TCG/virtual-RTC settings did not materially change that result.
The next concrete compiler correction enables C when the Rust native target
already guarantees it; no additional CPU extension is assumed without evidence.

The RV64GC C-extension correction produced 1874.882820 iterations/s over
32.002 seconds on the same single-thread-TCG setup: about 26.6% above the
1480.859886 generic-ISA port. This retained explicit bounds and the 100-billion
fuel limit. CRC validation and all 407 kernel checks passed; the measured
owner's heap peak was 19,605,632 bytes and final live bytes were zero. The raw
result and frozen ELF are under `wasmtime-coremark-kernel-c/`. Relative to the
fresh native median the ratio is still approximately 5.31x, so the objective
remains open. This provides direct evidence that a missing guaranteed CPU
extension accounted for a material part of the performance gap.

A repeat of the same frozen corrected ELF scored 1875.000000 over 32.000 seconds,
again passing CRCs, 407 checks and zero live allocations. Its native slowdown
is 5.305580152x. `wasmtime-coremark-kernel-c-repeat/` retains the ELF, comparison
JSON, source hash manifest, tracked worktree patch, untracked-source archive and
toolchain versions. Host ABI regression remained 18/18, and the original IMAC
Wasmi benchmark image passed its offline release compile check after the shared
clock refactor (`wasmtime-clock-wasmi-check.log`).

### CPU discovery and protected-memory controls (2026-09-09)

An allocation-free FDT v17 reader now intersects scalar Zba/Zbb/Zbc/Zbs support
across exactly the harts which SBI HSM lets this kernel schedule. It reads the
firmware blob before heap initialization and retains only a bit mask. Missing,
duplicate or malformed CPU information falls back to the existing GC baseline.
Five host test groups and a real four-hart QEMU DTB passed. A four-hart boot
confirmed mask 0xf, 407 kernel checks and zero final invocation allocations.

Optional ISA selection did not improve this QEMU TCG cohort:

| Same experimental ELF, single hart | CoreMark iterations/s |
|---|---:|
| GC (optional extensions disabled in QEMU) | 1871.140772 |
| Zba only | 1833.740831 |
| Zbb only | 1849.112426 |
| Zba/Zbb/Zbc/Zbs together | 1807.555582 |

Each is one valid >10-second sample, so this is not a general hardware ranking.
The default engine retains GC; broader selection is now explicitly opt-in with
`wasmtime-discovered-isa`. Firmware `extra_mask` logs **available** extensions,
not the default selection. The final default four-hart image scored 1870.324190
and passed 407 checks (`wasmtime-isa-default/`). Its frozen ELF SHA is
`57589817a2e8465ac95702c767fc6586d12c9ad2d65feaba5e13191ad509d688`.
The IMAC Wasmi image also passed an offline release compile check after the boot
entry signature change. No SIMD or vector-register extensions are enabled.

A separate Debian experiment held GC ISA, speed optimization, 100-billion fuel,
32 KiB Wasm stack, 16 MiB memory limit and disabled COW constant. It changed only
the memory/trap model as a group: movable memory with explicit checks versus a
fixed 4 GiB virtual reservation with a 64 KiB guard and native signal traps.

| Debian Wasmtime 48 profile | Performance median of 3 | Validation-seed score |
|---|---:|---:|
| Explicit checks / movable memory | 1764.238878 | 1678.415576 |
| Protected virtual memory / native traps | 2841.716397 | 2850.220892 |

All eight runs passed CRCs and exceeded ten seconds. The protected-memory group
was 1.6107x faster. Raw data, hashes, toolchain versions and summary are in
`debian-wasmtime-vm-controls/results/vm-summary.json`; the guest script interleaves
the profiles. This does not prove any VibeOS speedup. It identifies protected
virtual memory and native trap integration as the next implementation target,
with IRQ/FP restoration, exact guest bounds and teardown still requiring kernel
validation. Removing bounds checks without those mechanisms is not an option.
The <5x objective and full authenticated/async command integration remain open.

### Native trap integration and RISC-V ABI correction

The optional `wasmtime-hardware-traps` image now routes recognized synchronous
Wasm faults through Wasmtime's native handler and restores supervisor control
bits/FCSR when the native resume bypasses `sret`. Unknown host faults retain
the fatal kernel path. A stronger fault-injection test exposed a pinned
Cranelift 0.135.0 bug: f9/fs1 was absent from DEFAULT_CALLEE_SAVES and present
in DEFAULT_CLOBBERS. The scoped vendored `riscv64-fs1-abi.patch` fixes both sets,
in accordance with the RISC-V hardware floating-point calling convention.

The unpatched diagnostic returned `38654705664` (`9 << 32`, actual fs1 = 0).
After the fix, `wasmtime-hardware-fs1/` passed all 407 four-hart checks,
including 101 native illegal-instruction traps, injected clobbers of all FP
registers with all 12 callee-saved registers restored, FCSR/control restoration,
a subsequent real IRQ, 100 WASI invocations, and a fatal non-Wasm rodata fault.
Frozen ELF SHA: `2bddb8447059e49f839589a98eb5d97b897042a258d56eec0a7f6f69ce4d8304`.
The default IMAC Wasmi build also passed its offline release check.
This is correctness evidence, not a new CoreMark score. Historical upstream
byte-equality results predate the ABI fix; new comparison scripts apply the
same explicit ABI correction to their reference. Historical Debian benchmark
executables and dependency locks are unchanged.

### Fixed guest VA and protected memory: synchronous kernel result

`wasmtime-guarded-memory` reserves 8 GiB of empty Sv39 VA at 64 GiB, with
4 GiB advertised to Wasmtime and a 64 KiB guard. Only committed RW/NX pages
consume physical memory, capped at 16 MiB. Physical backing can change during
growth but the guest VA stays fixed. All-hart TLB shootdowns precede reclamation;
the nine static page tables are deducted from the probe's allocation allowance.
Fuel (100 billion), GC instruction selection, speed optimization and 32 KiB
Wasm stack remain enabled. The Wasm module itself is unchanged.

Four-hart `wasmtime-guards-selftest/` passes 407 checks, four real memory traps,
maximum-u32 and crossing-page OOB accesses, zero initialization, stable-address
growth, failed growth preserving memory, a second memory rejected as busy,
100 WASI cycles, all guest leaves unmapped after Drop, and fatal host faults.
This does not establish forced arena reclamation or asynchronous cancellation.

Fresh single-hart QEMU TCG samples, run serially without concurrent builds:

| Engine | Performance samples | Median |
|---|---|---:|
| VibeOS Wasmtime 48, protected memory | 2899.671371, 2920.418593, 2917.862180 | 2917.862180 |
| Debian native GCC 14.2, -O3 | 10004.439442, 9468.075034, 10092.790008 | 10004.439442 |

Every sample exceeds ten seconds and passes CoreMark CRC validation. Debian's
separate validation-seed sample is 10074.360912. VibeOS takes 3.4287x the native
execution time by these medians, a 1.5562x throughput improvement over the prior
1875-point kernel sample. Kernel compilation takes 0.89–0.91 s; measured heap
peak is 15,334,144 bytes and post-invocation live bytes are zero. VibeOS retains
128 MiB RAM versus Debian's 1 GiB; both use one rv64 TCG CPU and VM-clock timing.
This is a synchronous trusted kernel probe, not the final SSH/vsh service.
Thus the measured kernel path crosses the <5x threshold, but the complete goal
remains open pending command integration, scheduling and cancellation recovery.

Evidence: `wasmtime-guards-performance-{1,2,3}/`,
`debian-native-guards-control/`, and `wasmtime-guards-summary.json` under
`target/coremark-performance/`. The first run contains a source hash manifest,
worktree patch and untracked-source archive. Frozen performance ELF SHA:
`28cae6c3302990de3e2de64ea8a1ece95cd051ca374c057e8652660755c7eb5c`.

The separate VibeOS validation-seed run (`VIBEOS_COREMARK_VALIDATION=1`,
seed CRC `0x18f2`) scored 2929.687500 over 20.480 seconds and again passed all
407 checks with zero live heap. Its frozen ELF SHA is
`a9afe1be691255be8e8d4bdfb971f1403d11dd057393b99429f7692edee17462`.
All three performance logs have seed CRC `0xe9f5`. The full compiled-module
comparison also passed (`wasmtime-fs1-module-control/`): 247,528 bytes identical
between the port and upstream 48 plus the same scoped ABI correction.

To reproduce the kernel measurement from the repository root:

```sh
cd firmware/qemu-virt
VIBEOS_WASMTIME_COREMARK="$PWD/../../target/coremark-wasi/coremark.wasm" \
  cargo build --locked --offline --release \
  --target riscv64gc-unknown-none-elf \
  --features legacy-shell,wasmtime-guarded-memory,wasmtime-coremark-probe
cd ../..
python3 scripts/wasmtime/test-kernel-fp.py \
  --kernel target/riscv64gc-unknown-none-elf/release/vibeos-qemu-virt \
  --work target/coremark-performance/new-guarded-run \
  --require-wasmtime --require-wasi --require-hardware-traps \
  --require-guarded-memory --coremark-module target/coremark-wasi/coremark.wasm \
  --harts 1 --isa-mask 0xf
```

Set `VIBEOS_COREMARK_VALIDATION=1` on the build for the validation seed pair;
the default is performance seeds and 60,000 iterations. Use a fresh work
directory per run; the driver freezes the supplied ELF. The four-hart fault
suite additionally uses `--harts 4 --host-fault`.

### Native asynchronous fuel suspension

`wasmtime-async` enables Wasmtime 48's existing no_std fiber implementation.
A native future wrapper restores supervisor/FCSR state at every poll and Drop,
and preserves the invocation's FCSR across pending host calls. Tests execute
50 fuel-exhaustion runs, 50 suspended cancellations, an asynchronous host wait
and a native trap after that wait. Both single-hart and four-hart selftests pass
407 checks, with post-test code mappings/TLS/guest mappings at baseline.

Cold-start allocation accounting exposed 1,024 retained bytes in the global
code registry's B-tree slab/forest. The scoped `runtime-registry-reclaim.patch`
releases this capacity when the last registered code image is removed, outside
the registry lock. After that fix the async probe has zero live bytes and a
665,216-byte peak. This is normal/cooperative destruction evidence; forced
arena reclamation remains unproven.

With the same ordinary CoreMark Wasm, 100-billion total fuel and **10,000 fuel
per suspension**, three single-hart samples score 2157.109473, 2190.900460 and
2176.910239. Median **2176.910239** is **4.5957x** slower than the contemporaneous
Debian native median 10004.439442. Each invocation performs 3,804,010 manual
future polls, exceeds 27 seconds, passes CRC checks, and frees its 15,334,144-byte
peak heap allocation back to zero. Four-hart verification scores 2195.068413,
passes the same tests and preserves fatal non-Wasm host faults; it is excluded
from the single-hart median.

These runs include real fiber suspension/resumption but **not** the production
command-service scheduler, permission checks per quantum or streamed stdin.
The <5x end-to-end goal remains open. Protected fiber stacks and allocation
ownership on forced termination also remain required before command exposure.

Evidence: `wasmtime-async-registry-performance{,-2,-3}/`,
`wasmtime-async-registry-four-hart/`, `wasmtime-async-summary.json` under
`target/coremark-performance/`. Frozen ELF SHA:
`9249aad6e1eefaca8181f699ad3a8643dcc3017397865538c999c2c193721ae1`.
Use the protected-memory reproduction command above, replacing the build
feature `wasmtime-guarded-memory` with `wasmtime-async` and adding driver option
`--require-async`. The driver records manual polling explicitly in its JSON.

The separate async validation-seed run scored 2198.043741 in 27.297 seconds
(seed CRC `0x18f2`, 3,805,506 polls), passed all 407 checks and ended with zero
live heap. Evidence is `wasmtime-async-validation/`; frozen ELF SHA:
`c04ad0b4b524ae3864c0050b3211f7e97b55e63eea0dfd820c96fcb577ac7dd5`.
The default IMAC Wasmi offline release check passed after these changes.

### Streaming WASI and command-transport adapter

The async Preview 1 linker now sends fd_read/fd_write through a host Streams
trait. It checks every iovec and the result address before polling I/O, supports
short transfers/EOF, and applies one 65,536-byte stdout+stderr budget across
calls. fd_close closes the invocation's transport endpoint and further access
returns BADF. The buffered adapter remains available with its existing semantics.

The kernel CommandStreams adapter reuses the existing CommandIo/GuestIo pipes.
It closes and wakes pipe waiters on Drop without assigning a cancellation reason
or terminal state; those remain supervisor-owned. The new tests cover empty
stdin suspension, input delivery/resume, full stdout backpressure, draining and
resuming, EOF, separate stderr, descriptor closure, invalid later iovecs and
result pointers producing no I/O, and the last short write at the shared output
limit. The real command-pipe scenario repeats 100 times, including cancellation
with a writer pending. Final waiters and heap live bytes are zero; the complete
async test owner peaks at 987,648 bytes.

Four-hart QEMU passes all 407 checks and preserves fatal host faults:
`wasmtime-command-pipe-stress/`, frozen ELF SHA
`73efd0493e5312b37d86eb15e29363ae603a1c7f88a7a1ef1ec8388a0093ed9c`.
The default IMAC Wasmi release compile check also passes. Separately,
`wasmtime-streams-host-final/` records 18 passing host tests, including actual
Rust/C stdlib Hello World, arguments with spaces/UTF-8, input filtering, stderr
and exit status. Its deterministic host adapter suspends before each I/O call
and limits reads to 7 bytes and writes to 11 bytes. The short CoreMark CRC smoke
in that suite is not a score.

This is a verified streaming adapter and connection to command transport. The
public wasm-run backend has **not** yet switched to Wasmtime. Executable task
supervision, forced allocation-domain cleanup and the final scheduled CoreMark
comparison remain outstanding. The earlier 4.5957x result remains the manual
async-fiber measurement, not a new end-to-end claim. Kernel reproduction adds
`--require-streams` to the existing async QEMU driver command; host reproduction
is documented in `wasmtime-runtime/README.md`.

### Raw fault recovery of guarded guest memory

Guarded memory now keeps a fixed kernel record containing the exact allocation
domain and current physical backing/addressable size. The reservation is recorded
before allocating, and growth updates the record in the non-allocating PTE
transaction. The executor can therefore remove guest aliases before freeing a
faulted arena, without dereferencing an arena-owned Memory object or calling Drop.
The sole-memory busy state is released as part of that exact-domain cleanup.

The regression uses 48 actual executor faults: 16 initial allocation failures,
16 growth allocation failures, and 16 deliberate faults after successful growth.
It checks the mapping size present at recovery (0, 65,536 or 196,608 bytes), zero
remaining owner allocations, retired arena metadata, unmapped guest addresses
and zero Memory destructor calls. Budgets account for the heap's page-alignment
rounding, so the allocation/growth failures occur at distinct verified stages.

The fixed fixture has a private exact-domain admission record. It constructs
only MemoryCreator objects and publishes no Engine/Module/TLS/code-registry or
service reference. The first attempt without this record was correctly rejected
by the existing World ownership gate; that gate remains intact. This test-only
admission must not authorize a full Wasmtime invocation. Full native runtime
registry, code-image and TLS recovery remains a prerequisite to command exposure.

Four-hart QEMU passes 408 checks and preserves fatal host faults, followed by
successful native execution, the async cancellation tests and 100 command-pipe
cycles. Evidence: `target/coremark-performance/wasmtime-memory-recovery-verified/`.
Frozen ELF SHA: `7aae59206bf01f4273b5a2145dd2034f25f0defa25268b6e06ee485a0ac4ee94`.
Add `--require-memory-recovery` to the async QEMU driver to require this evidence.
No new performance score is claimed by this recovery test.


### Fixed code registry and post-call runtime arena recovery

The optional native async port now uses `custom-code-registry`: 16 fixed kernel
slots record frozen code ranges, opaque Arc references and their allocation
domains. Lookup retains a reference under the registry lock; normal removal
returns it for destruction outside the lock. This avoids allocating the global
registry inside the first invocation's arena. The default host registry still
uses the previous quiescent-capacity fix. The new vendor patch can be replayed
after the two existing runtime patches and reproduces all changed files exactly.

A separate private test admits a complete isolated Engine/Module/Store graph,
compiles an ordinary memory-bearing Wasm module in the kernel, executes it to
return 42, and then faults the executor task. Recovery detaches fixed code
records and mapping handles without Drop, unmaps guest memory, releases code
pages and reclaims the arena. All 16 cycles restore registry/mapping/heap counts
to zero, retire arena metadata, preserve the code-pool baseline and run no probe
destructors. TLS is explicitly checked to be inactive before reclamation.

Four-hart QEMU passes **409 checks**, including the preceding 48 memory-only
faults, 100 command-pipe cycles and real native hardware traps. Fatal host rodata
fault behavior is preserved. Evidence:
`target/coremark-performance/wasmtime-code-recovery-final/results.json` and
`boot.log`; frozen ELF SHA:
`5f62dff3dde0e593651c3dc6c3e91a4394641925f17486742a3c9ec5b1310fc5`.
The driver now records both code markers and requires them with
`--require-code-recovery`. Default IMAC Wasmi and the host async streaming example
without the custom registry both pass offline compilation checks.

This fixture faults **after** the native call returns; it does not establish
safe recovery of active native TLS/fibers or host callbacks. Production command
integration still needs exact-task cleanup before hart reuse, protected fiber
stacks, compiler-failure ownership coverage, and supervisor-owned I/O references
that cannot leak if arena destructors are skipped. The current Arc-based stream
probe covers cooperative cancellation only. Public `wasm-run` remains Wasmi.
No new CoreMark score is claimed; the earlier 4.5957x manual async result remains
separate from the outstanding scheduled command-service acceptance.


### Active synchronous call fault cleanup

Tracked native calls now save their pre-call TLS slots and floating-point
control state in fixed per-hart kernel records, keyed by the executor task scope
and allocation domain. Normal return removes the record. On permanent task
detach, cleanup restores the outer snapshot without following arena-owned TLS
pointers, then removes all nested records before code/arena reclamation. The
existing managed-component ownership gate still precedes this cleanup. Nesting
is bounded at 16; exhaustion releases the metadata lock before raising a fault.
Untracked probes do not acquire a recovery record.

The task scope identity is intentionally distinct from the scheduler's running
identity: guarded future destruction retains the former after detaching the
latter. A core executor regression verifies that distinction. This identity is
cleanup provenance, not a new authorization or raw-reclaim permit.

The isolated runtime fixture now also performs 16 real synchronous Wasm-to-host
calls whose host callback verifies active TLS, changes FCSR and panics. The
exact-task cleanup path runs once per active failure; subsequent arena recovery
requires inactive TLS, empty code/mapping tables, zero live owner bytes, retired
arena metadata, unchanged code-pool counts and no probe destructors. Another 16
post-call faults remain covered. These callbacks publish no host resource or
I/O reference outside their arena.

This advances active synchronous recovery. Raw termination of an active async
fiber, protected fiber stacks, compiler partial-failure ownership and production
I/O/supervisor lifetime integration still require verification. Public commands
remain on Wasmi; there is no new performance claim for this change.

Final four-hart verification passes all 409 checks, including the additional
16 active-callback faults, and preserves fatal host faults. Evidence is
`target/coremark-performance/wasmtime-active-recovery-final/`; frozen ELF SHA:
`40d18ca0598faf640cd5e03408124eb21ee27fa3cc4205c9baebc003f24c9b91`.
Require the new evidence with `--require-active-recovery`. The core scope test
and default IMAC Wasmi offline release check also pass.


### Async fiber fault and cancellation recovery

The private arena fixture now covers three additional cases, 16 cycles each:
a task faults with a suspended native fiber; the executor resumes the fiber and
its async host callback faults; and the executor cancels the suspended task and
the host future's destructor faults. Each callback first returns Pending, and
the containing task yields to the actual executor before subsequent action.
Stage counters prove that setup failure cannot pass as the intended fault.
The cancellation destructor checks that the running-task identity is absent
while the guarded task-scope identity remains available.

All 48 cases restore inactive TLS, empty code/mapping tables, zero live owner
bytes, retired arena metadata and the original code-pool counts. No outer
DropProbe destructor runs (`drops=0` in the marker); in the cancellation case
the deliberately faulting host-future destructor does run before raw cleanup.
This is not a claim that every destructor was skipped during cooperative cancel.
No stream handle, host resource or saved external waker escapes these fixtures.

Four-hart QEMU passes all 409 checks, including the earlier 32 runtime faults,
48 memory-only faults, 100 command-pipe cycles and native hardware-trap checks.
Fatal host rodata faults remain fatal. Evidence:
`target/coremark-performance/wasmtime-fiber-cancel/`, frozen ELF SHA:
`1ce5e15a3df5fee727a968ff45d9f827ed70c99d767f99c6d88b0cbcc9b7544c`.
The driver requires the three fiber cases with `--require-fiber-recovery`.
The default IMAC Wasmi offline release check also passes.

The port still needs protected fiber stacks with a trap entry that can run
when the interrupted SP is in a guard page. The current trap entry saves its
frame on the interrupted stack; simply adding an unmapped stack page would
risk a recursive trap. Compiler partial-failure ownership and production I/O
supervision also remain prerequisites to public command exposure. These tests
add no CoreMark score; the <5x command-service benchmark remains outstanding.


### Protected fiber stacks and an independent trap entry

The optional native async kernel now gives each hart a 64 KiB RW/NX trap stack
with an unmapped lower guard. Entry computes its address from the cached hart
identity, saves the interrupted SP and all registers without first writing to
the interrupted stack, restores the hart cache before Rust, and restores the
original SP on sret. A trap while already on this stack fails closed rather
than overwriting the outer frame. Sixteen private breakpoint probes deliberately
put SP in an unmapped page and verify that the handler can return to its caller.

Wasmtime's kernel StackCreator now owns up to four 256 KiB RW/NX fiber mappings.
Each fixed virtual slot has an unmapped page below the stack and unmapped space
above it. Physical storage is zeroed and charged to the current allocation
domain. Normal Drop unmaps before freeing; raw fault recovery uses fixed domain
records to remove aliases without following the interrupted StackMemory object.
Existing suspended/resumed/cancellation-destructor faults all pass with this
creator enabled. A live async host callback checks that its actual SP is in the
correct domain's RW/NX mapping and both boundaries are unmapped.

A separate ordinary recursive Wasm module produces StackOverflow 16 times with
fuel still remaining; subsequent I/O and native calls succeed. Thus the stack
limit is distinguished from fuel exhaustion. The independent invalid-SP probes
exercise trap entry safety separately from the compiler's early stack-limit trap.

Both one-hart and four-hart QEMU configurations pass **410 checks** with the same
frozen ELF, SHA:
`55aa44e70c85aba62f9622f82e40aac6879593e4b544e688d6152df6316bc87c`.
Evidence is `target/coremark-performance/wasmtime-protected-stacks/` and
`wasmtime-protected-stacks-one-hart/`. The driver requires this evidence with
`--require-trap-stack --require-fiber-stack`. There are 122 recognized native
hardware traps, four memory faults, and preserved fatal host rodata behavior.
The async owner returns to zero live bytes (987,136-byte peak), and all fiber
aliases are absent at the end. Default IMAC Wasmi offline release check passes.

The sole invocation's heap budget now reserves code storage, guest tables,
all four trap stacks and their page tables, fiber page tables and 16 KiB for
fixed platform records against its 32 MiB total. No CoreMark score was measured
with this build. Compiler failure/scheduling ownership and public command I/O
supervision remain open; production wasm-run still uses Wasmi, and the previous
manual async 4.5957x ratio is not end-to-end acceptance.


### Shared admission and compiler allocation-budget recovery

The Wasmtime command compiler now uses the same structural inspector source as
the Wasmi entry, compiled against each backend's pinned wasmparser. It enforces
the existing profile's types/imports/functions/globals/exports, locals, nesting,
custom/data/element sections, single memory/table and initial-size limits before
Module compilation. Required exports and WASI signatures are still checked
before execution. Sharing the inspector avoids maintaining a second set of
numeric limits; the Wasmi behavior is unchanged.

The custom-platform streaming host suite passes 22 cases. Four new valid core
modules exceed the type, locals, nesting or initial memory limit and must report
`WASI admission: Limit`, proving rejection at admission. Real Rust/C standard
library commands and the short CoreMark CRC smoke continue to pass. Evidence:
`target/coremark-performance/wasmtime-shared-admission-host/`. The Wasmi suite
passes 14 ordinary tests; its normally ignored standard-library test was also
run explicitly and passed separately with both Rust and C artifacts.

The isolated compiler-arena fixture sweeps eight budgets, compiling the same
ordinary minimal WASI command. At 8/32/64/128 KiB, allocation is rejected during
the compile phase after Engine creation. At 256/512/1024/2048 KiB, compilation
succeeds with a 191,488-byte peak and is followed by a deliberate task fault.
All eight arenas retire with zero live heap, code-registry entries and mapping
handles, and original code-pool counts. These are four observed allocation
failure points plus successful-result teardown, not exhaustive allocation-site
coverage or a proof of bounded compiler CPU time.

Four-hart QEMU passes 410 checks, including protected stacks, all preceding
runtime/fiber recovery tests and preserved fatal host faults. Evidence:
`target/coremark-performance/wasmtime-compile-recovery/`, frozen ELF SHA:
`10869e08e733af1093d60a4f94951f8ea46c7698d4c7abfa49ba2fd34a9784bc`.
Use `--require-compile-recovery` to require the budget-sweep marker and retain its
per-budget phase/peak/denial rows. Default IMAC Wasmi offline release check passes.
Compiler scheduling/stack-fault supervision and the public command lifecycle are
still incomplete. No new benchmark score is claimed.

## Experimental real Wasmtime command backend

The opt-in `wasmtime-command` feature now routes ordinary SSH uploads and local
`wasm-run` through the native compiler/runtime and streaming Preview 1 adapter.
Default builds still select Wasmi. The command uses the existing file snapshot,
capability watcher, SYSTEM-owned pipes, invocation allocation domain and reaper.
Native I/O borrows the supervised job; exact-domain fault recovery clears pipe
waiters before reclaiming the runtime graph. The reaper checks the SYSTEM wake
signal reference count after joining the child. Compiler CPU deadlines and
compiler stack-fault supervision remain open, so this is experimental.

Real command measurements (same module, 10,000-fuel quantum, three timed runs):

| Actual SSH command | Median iterations/s | / existing Debian native median |
| --- | ---: | ---: |
| One native poll per executor dispatch | 890.833779 | 11.2304× slower |
| At most 32 immediately-ready polls per dispatch | 1316.296243 | 7.6004× slower |

Evidence: `target/coremark-performance/wasmtime-command-vsh-first/` and
`wasmtime-command-batch/`, each with a frozen ELF, UART and per-request output.
The latter samples are 1326.282005, 1312.874576 and 1316.296243; validation is
1308.810826. This is a 47.8% throughput increase, still short of the 5× goal.
The Debian denominator is the prior 10004.439442 control, not a fresh rerun.
Historical environment files name `wasi-benchmark` in the feature field; their
backend field and UART identify Wasmtime. The driver now records both features.

Batching preserves authority, cancellation and capability checks at every fuel
quantum and returns to the executor when another task needs it or I/O blocks.
A persistent SYSTEM wake signal coalesces immediate wakes and retains external
I/O wakes. Native profile counters distinguish inner polls and outer dispatches;
they include compile/instantiate time, while CoreMark's own timer excludes those.
These command scores supersede the manual async probe as acceptance evidence.

The subsequent Rust/C acceptance build exposed a compiler panic on Rust stdlib
constant `memory.copy`: Wasmtime 48 emitted i8x16 internally on RV64GC without V.
`riscv64-inline-copy.patch` selects scalar chunks on that target and preserves
bounds checking and memmove overlap semantics. The original Rust module now
cross-compiles successfully. Real QEMU functional acceptance is being rerun with
the fix and a dedicated overlap/unaligned-copy fixture; the earlier failed run
is retained at `wasmtime-command-acceptance/`. The scores above predate this fix
and the final resource-limit/error-classification changes.

The fixed compiler image passed real Rust Hello World, then the original
2-second SSH keepalive configuration failed on the next compile. A diagnostic
run with an explicitly recorded 30-second keepalive passed Rust/C arguments,
binary input, stderr, exit 7, the copy oracle, malformed imports, traps, memory
and fuel limits. It then exposed an output-quota loop: FBIG alone allowed the
guest to keep calling the host until fuel expired. The adapter now marks this
as invocation resource exhaustion and immediately unwinds the guest, in both
buffered and streaming modes. A host regression checks the combined stdout/
stderr 65536-byte ceiling. Diagnostic liveness settings do not replace the
original responsiveness gate; both failed runs are retained.

The output-limit-fixed functional diagnostic completed successfully:
`target/coremark-performance/wasmtime-command-output-diagnostic/results.json`,
ELF SHA-256 `20e0901d07c68977c3529a3cd6e3d04551c1e82ad533f3c67ea7c85a2231f696`.
It records 141 commands, 100 consecutive reclaimed invocations, local pipeline
and cancellation, live post-boot C compilation/upload, and persisted Rust/C
execution after reboot. The record explicitly sets `responsiveness_acceptance`
to false because the SSH keepalive interval was 30 seconds. Reboot restoration
was slow but completed within the original 300-second boot deadline.

Both buffered and streaming custom-host suites passed 23 cases in
`wasmtime-output-host-sync/` and `wasmtime-output-host-streams/`; the default
Wasmi suite passed 14 tests (one explicit stdlib test remains ignored by that
normal invocation), and the default firmware release check passed. The actual
Rust module also produces byte-identical 432728-byte RISC-V artifacts in all
three compiler configurations (ported std, reference std plus the two target
correctness patches, and custom-platform no_std):
`wasmtime-rust-copy-module/results.json`, artifact SHA-256
`b37d557094f88e18a0ea4d33e0089461301658692ab1a0145dc0b2a587b48760`.

The post-fix default-profile command control at
`wasmtime-command-fixed-benchmark/` scored 1301.037567, 1302.995557 and
1298.621527 (median 1301.037567); validation scored 1313.443618. All runs were
longer than 13 seconds and passed CRC checks. A pure profile experiment with
`vibeos-kernel` and `vibeos-wasmtime-runtime` set to opt-level 3 initially failed
at boot, without a score (`wasmtime-command-speed-benchmark/`). Disassembly
showed world::build reserving 235344 bytes and kmain reserving 25856 bytes,
exceeding the 258048-byte usable boot stack. Service construction has been moved
to a separate non-inlined phase; the stack size and guard remain unchanged.

A separate diagnostic defect was found in 1-GiB QEMU boots: the firmware DTB is
near 0xbfe00000 but the kernel allocator ends at 0x88000000. ISA capture now runs
before Sv39 and heap initialization, accepts the supported QEMU physical RAM
envelope, and retains only the checked scalar intersection. Previously it
reported no discovered harts/extensions in this configuration. This does not
explain the command score: broader ISA code generation remains deliberately
opt-in, and the measured default continues to generate GC code. The benchmark
driver can now assert and record the *available* firmware ISA mask separately.

The split-stack speed-profile experiment booted and discovered the 1-GiB DTB
correctly, but scored 1186.854661, 1168.466068 and 1203.046052 (median
1186.854661, validation 1215.061602). Consequently those package profile
overrides were not adopted. The default size-oriented kernel profile remains.

A fresh Debian native control ran alone using an independent overlay of the
prepared image, with no package installation. `debian-command-fresh/results/`
contains scores 8879.267357, 9270.424509, 9352.828283; median **9270.424509**.
Validation scored 9348.578929. All intervals were 19.8 seconds or longer and
passed the expected performance/validation CRCs. `native-summary.json` parses
the raw files (the generic driver's custom-script results.json remains empty).

The first bounded in-fiber fuel policy reached 1813.530276, 1818.873793 and
1898.428157, median **1818.873793**, validation 1953.155212. This improves on the
post-fix command control by 39.8%, but remains **5.097×** slower than the new
Debian median. Evidence: `wasmtime-command-fuel-batch-benchmark/`. The quantum
remains 10000 and each boundary still checks capability authority, cancellation
and competing work. At most 31 boundaries continue on the existing fiber; the
32nd yields. Outer batching is disabled, retaining a maximum of 32 quanta per
executor poll. Counter records verify that bound. The host `fuel-custom` test
exhausts identical 1000000 fuel with 99 decisions, reducing 100 polls to 4,
and verifies dropping a pending call followed by reuse.

### wasi-threads on the native backend (2026-09-09)

The `wasmtime-threads` image admits the wasi-threads contract (imported shared
bounded `env.memory`, `wasi::thread-spawn`, `wasi_thread_start`, atomics,
`memory.atomic.wait/notify`) and runs each guest thread as a kernel task pinned
round-robin to an online hart. The vendored runtime gains
`runtime-no-std-threads.patch`: `threads` no longer implies `std`, shared
memories are allocated through the host `MemoryCreator`, atomic waits suspend
the calling fiber through the executor with copy-only waiter tokens, and the
`threads` feature is forwarded to `wasmtime-environ`/`wasmtime-cranelift` so
the atomic builtins keep their trap sentinels (without it the compiler emitted no
trap check after a wait and a cancelled waiter continued into the next host
call). Shared guest memory keeps the fixed reservation and grows by appending
zeroed pages, so threads on other harts never lose a translation. The executor
gains parallel tracked domains: siblings may live on any hart, and a fault
quiesces siblings mid-poll elsewhere (they detach without destructors) before
the arena is reclaimed raw; a poisoned lock spin faults the spinner instead of
hanging its hart. The command service adds up to three thread slots per job, a
job-wide output budget and a four-budget aggregate fuel ceiling.

Evidence on the 4-hart QEMU image (`wasi-ssh-upload,wasmtime-command-fuel-batch,
wasmtime-threads`, generated fixtures uploaded over SSH):

| Fixture | Status | Terminal | Threads / harts |
| --- | ---: | --- | --- |
| `threads-atomics` (cmpxchg/xchg/sub-word rmw/fence) | 0 | Exited(0) | 0 |
| `threads-counter` (3 workers, wait/notify) | 0 | Exited(0) | 3 on `0x7` |
| `threads-wait-timeout` (wait32/wait64 timeouts) | 0 | Exited(0) | 0 |
| `threads-exit` (worker `proc_exit(7)`, main parked) | 7 | Exited(7) | 1 |
| `threads-spawn-cap` (16 spawns, `-EAGAIN` past 3) | 3 | Exited(3) | 3 on `0x7` |
| `threads-grow` (worker grows, main reads page 2) | 0 | Exited(0) | 1 |
| `threads-fault` (worker `unreachable`) | 125 | Trapped | 1 |
| `threads-busy` (3 spinning workers) | 124 | LimitExceeded | 3 |
| `threads-defined-shared`, `threads-no-start` | 126 | Denied | rejected at admission |

Every terminal printed `reclaimed=true caps=0 waiters=0`, and five repeated
`threads-counter` runs followed. `harts_used=0x7` records three distinct harts
polling the three workers of one command. The host `threads-custom` driver
passes the same fixtures, including cancellation of a fiber suspended inside a
wait. The kernel selftest adds `WASMTIME THREADS PASS` (two stores on one shared
memory: atomics, suspended wait, notify, timeout, mismatch, shared growth) and
`WASMTIME PARALLEL RECOVERY PASS` (16 cycles of a primary fault with three
siblings on other harts; every cycle collected siblings mid-poll on another
hart, ran no destructor and reclaimed the arena).

Two selftest checks fail identically on the unmodified base commit and are not
caused by this work: the streaming-adapter probe still expected errno 27 at the
output quota after the adapter was changed to unwind the guest (the probe now
expects the unwind), and `fault/restart heap bump use stabilizes after warmup`
fails on the one-hart configuration at HEAD. The pthreads C fixture
(`tests/wasi/threads.c`, `--target=wasm32-wasi-threads`) is wired into
`build-wasi-examples.sh`, `test-wasi-host.py` and `test-wasi-qemu.py --threads`
but was not executed here because no wasi-sdk is installed on this host. No
CoreMark or throughput claim is made for threaded guests.

### pthread CoreMark: fuel batching, discovered ISA, lock-free quantum gate (2026-09-09)

The four-hart `wasi-benchmark,wasmtime-threads` image measured about 44% of
the Linux Wasmtime control on `M1` (VibeOS 1,389 against Debian 3,153
iterations/s; see `benchmarks/wasm-runtime/coremark-threads.md`). Three
changes close most of that gap. Host-time scores on this machine vary by more
than 10% between samples, so the code-level comparison below uses the new
deterministic diagnostic instead: `benchmark-coremark-threads.py
--icount-iterations 2000 --harts 1` runs a fixed 2,000 iterations per worker
under `-icount shift=0` with single-thread TCG; two runs of one image agree to
the instruction (892,000 per iteration twice), so differences are code, not
noise. The virtual seconds are an instruction count, never a throughput score.

| `M1` image (2,000 iterations, one hart, icount) | instructions per iteration |
| --- | ---: |
| `wasi-benchmark,wasmtime-threads` (the measured baseline) | 982,500 |
| + `wasmtime-command-fuel-batch` | 892,000 |
| + discovered zba/zbb/zbc/zbs code generation | 795,000 |
| + lock-free continuation probe (final) | 768,500 |
| (diagnostic only: fuel batch with every boundary check removed) | 832,500 |

1. **Fuel batching** was already available (`wasmtime-command-fuel-batch`) but
   the threads benchmark image did not select it, so every 10,000 fuel forced a
   fiber switch and an executor round trip. The benchmark now documents and
   records the batched image (`--fuel-batch`), and each invocation prints the
   workers' `thread fuel checks=… continued=…` counters: on `M1` about 95% of
   the 126,800 boundaries of a 20-second run continue on the fiber.
2. **Discovered scalar ISA.** The Linux control compiles for plain RV64GC, and
   VibeOS did too. `wasmtime-command` now selects `wasmtime-discovered-isa`:
   when the boot DTB advertises zba/zbb/zbc/zbs on every schedulable hart,
   Cranelift generates code for them. This is 10.9% fewer instructions per
   iteration on the same module; a target without those extensions keeps
   receiving GC code.
3. **Lock-free quantum gate.** The batching callback used to take the per-hart
   status lock, clone the status Arc, take the global scheduler lock, scan all
   four ready queues and validate the domain record at every 10,000-fuel
   boundary, about 790 instructions plus seven atomic operations that the
   other worker harts contend on. `exec::continuation_probe()` now performs
   that validation once per executor poll, and `ContinuationProbe::may_continue`
   repeats the same decision from atomics: the task's cancellation state, a
   `ReadyHint` occupancy mirror maintained inside every run-queue mutation, and
   a domain epoch that every reclaimable-domain record transition advances.
   The probe is armed before each fiber poll and released after it, in `Drop`
   of the task futures, and in retire/recover. Host tests show it agreeing
   with `current_task_may_continue()` across ready peers, yields and
   cancellation; breaking the hint mirror or the hint check turns them red
   (cancellation alone is also covered by the `Running` state check, so that
   mutation is not distinguishable, as with the locked gate).

Two pre-existing defects surfaced while validating multi-worker runs, both
present in the unmodified baseline image:

- **Intermittent `reclaimed=false` after a normal run** (about one in ten
  `M2`/`M3` runs), after which the command service refused every request with
  status 75. The allocator's `dealloc` read the block header before taking the
  heap lock and then validated the arena links from that snapshot; a
  neighbouring allocation or free on another hart in between (guest threads
  share one arena) failed those checks and the free silently returned, leaving
  the block linked and charged. The header is now read under the lock.
  `core/tests/heap.rs` reproduces the race with two threads on one arena and
  fails within one run when the old ordering is restored. The kernel now prints
  what survived an unclean reclamation (size classes, allocating call sites
  through the benchmark-only `alloc-site-trace` core feature, and the executor's
  view), which is how the leaked object was identified: the boxed
  `allocate_memory` future of a worker's shared-memory import.
- **Hang after a client disconnect** in a threaded run. The reaper only woke
  parked guest threads on authority loss; on cancellation the pipes closed but a
  main thread parked in `memory.atomic.wait` for its join was never polled
  again, and its workers had already stopped at their next fuel boundary. The
  reaper now wakes every task of the job while it is cancelled, so the parked
  thread observes the cancellation and the process ends. The disconnect test
  kills the SSH client three seconds into `M3`/`M2` runs on the benchmark image
  and requires `terminal=Cancelled reclaimed=true` within 30 seconds followed
  by a clean run.

- **Retirement racing a still-reclaiming worker** (once in about fifty
  fixture runs on the ordinary-limit image, seen after `threads-counter`). When
  main returns, `execute` calls `end` and awaits `join_threads`; that join can
  pend, and at the next poll boundary the guest's own `end` makes `stopped`
  drop the whole future, as it must for a main thread parked in a wait after a
  worker's `proc_exit`. `join_threads` had taken the thread handles out of
  their SYSTEM slots, so they vanished with the dropped future and the
  reaper's `reap_threads` had nothing left to join: it retired the job while a
  worker was still being reclaimed on another hart, and the arena check saw
  the worker's entire runtime graph (291 allocations in the observed case).
  `join_threads` now clones a slot's handle and clears the slot only after that
  thread is joined, so whichever of the two paths runs last still waits.

Current formal measurements are in the first section of this document.

Host wall-clock effect of the three changes, measured as an interleaved
`M1` A/B in one host window (fuel batch, ISA, final, repeated three times;
each run is one 15-second performance sample plus its validation sample,
`--workers 1 --samples 1 --seconds 15`; host load fell from 8 to 5 during it):

| image | samples (iterations/s) | about |
| --- | --- | ---: |
| fuel batch only | 2403, 2354, 2310, 2384 | 2,360 |
| fuel batch + discovered ISA | 2419, 2607, 2157, 2427, 2349, 2549 | 2,420 |
| final (+ lock-free gate, fixes) | 2973, 2967, 2846, 2926, 2925, 2934 | 2,930 |

The ISA step is worth more in instructions than in host time under TCG, while
the lock-free gate is worth more in host time than its instruction count: the
seven atomic operations it removes per boundary are contended across the
worker harts under multi-threaded TCG. Absolute numbers on this host move by
more than 10% with load; only the interleaving makes the comparison usable.

Formal four-hart results with the retained harness (three 20-second samples
per worker count, validation seeds as a fourth sample, Debian control run
immediately afterwards in the same host window):

| Workers | VibeOS before (2026-09-09, `vibeos-4h-r4`) | VibeOS after (`vibeos-4h-fuel-batch-isa-probe`) | Debian control, same window (`debian-std-4h-r4`) | after / control |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 1,389 | **2,611** (2,540–2,784) | 3,453 (3,361–3,470) | 76% |
| 2 | 2,271 | **5,088** (4,681–5,111) | 6,136 (6,098–6,369) | 83% |
| 3 | 3,262 | **6,581** (6,273–7,164) | 8,601 (8,237–8,637) | 77% |

Medians of three 20-second performance samples, iterations/second aggregate
over all workers; every sample passed upstream CRC validation and the fourth
(validation-seed) sample also passed. Against the Debian medians of the
original comparison (3,153 / 5,880 / 8,031, measured earlier the same day),
the new image reaches 83% / 87% / 82%. The Debian control measured 40 minutes
earlier in the same session (`debian-std-4h-r3-early`) gave 3,260 / 5,902 /
8,122. Host load on this machine moves both platforms by more than 10%
between windows, so only pairs measured back to back should be compared.

Evidence: `target/coremark-threads/vibeos-4h-fuel-batch-isa-probe/`,
`debian-std-4h-r4/`, `debian-std-4h-r3-early/` and
`comparison-fuel-batch-isa-probe.json`; the earlier
`vibeos-4h-r4`/`debian-std-4h-r2` sets are the original comparison. The
benchmark script now lengthens its calibration until it lasts three seconds
(a 1,000-iteration calibration under-estimated the batched image's `M3`
throughput enough for a measured run to fall below CoreMark's ten-second
minimum), records `--fuel-batch` and the per-thread batching counters, and
offers the icount diagnostic mode; `summarize-coremark-threads.py` counts
calibration attempts from the evidence directory.

Validation of the final tree: 19 core host suites (including the new run-queue
hint, continuation-probe and concurrent-free tests) and the WASI runtime and
command suites pass; the default IMAC firmware still builds; on the four-hart
benchmark image 30 consecutive `M3` runs reclaimed cleanly (the unfixed tree
failed about one in eight), six mid-run disconnects ended `Cancelled` with a
clean lifecycle and a clean follow-up run, and the single-hart icount
diagnostic reads 768,500 instructions per iteration; on the ordinary-limit
acceptance image `scripts/test-wasi-threads-fixtures.py` passed all 57 cases
with 61 clean lifecycles (the unmodified tree failed it at case 18 with an
unclean reclamation). Neither script needs wasi-sdk; the pthreads fixture is
the retained `target/coremark-threads/threads.wasm`.
