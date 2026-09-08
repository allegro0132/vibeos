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

The [isolated Linux runners](../tools/coremark-engines/README.md) add the missing
same-engine and compiling-engine controls. Debian and VibeOS use one `rv64` hart,
1 GiB, single-threaded QEMU TCG and real clocks, without icount. Runs are sequential;
no host compilation overlaps measured samples. The same unmodified SDK 33 CoreMark
module is used throughout. Three performance samples and the independent validation
seed set all exceed ten seconds and pass upstream CRC checks.

| Debian mode | Performance median | Slowdown vs current native | Setup median | Peak RSS median |
|---|---:|---:|---:|---:|
| GCC native, `-O3`, no LTO | 9653.925702 | 1.00× | — | 1092 KiB |
| Vendored software-float Wasmi | 161.459830 | 59.79× | 0.037941 s | 2800 KiB |
| Wasmtime 48.0.0, Cranelift speed | 2789.949828 | 3.46× | 1.496064 s | 10216 KiB |
| Wasmtime 48.0.0, Cranelift speed, fuel | 2587.046050 | 3.73× | 2.311926 s | 11932 KiB |

Wasmi reuses `WasiInvocation` with eager validation, software float, `extra-checks`,
strict structural limits, 16 MiB linear memory, 100 billion fuel and 10,000-fuel
polls. Release optimization and dependency versions are retained from the root
workspace. Its RV64 cache and instruction profiling are disabled. Linux does not
reproduce VibeOS allocation-domain accounting, capability checks or scheduling;
therefore this isolates the shared interpreter/runtime, not the entire kernel.

Wasmtime explicitly selects Cranelift, uses official Preview 1, caps linear memory
at 16 MiB and receives no directories or environment. Its fuel units and synchronous
execution differ from Wasmi's resumable quantum; the fueled row is not an assertion
of identical metering. It retains its normal stack checks, Linux virtual-memory
bounds/traps and hardware float support. Setup includes engine creation, compilation,
linking and instantiation; it is excluded from the upstream CoreMark timed interval.
RSS covers the whole Linux process and is not a kernel compiler-allocation bound.

The compiling engine is 17.28× faster than Debian Wasmi without fuel, and 16.02×
faster with fuel. Fuel reduces this Wasmtime score by 7.27%. This identifies a large
execution-engine opportunity even when VibeOS is absent, and demonstrates that a
compiling engine can fall within fivefold of native on this QEMU workload. It does
not establish that the experimental VibeOS backend has achieved that goal.

Evidence: `target/coremark-performance/debian-engines-ready/manifest.json`,
`qemu-command.json`, `results/engine-results.json`, `results/measurement-environment.txt`,
and all raw `*-performance-*.stdout/.stderr` and `*-validation.stdout/.stderr` files.
Preparation failures (service wait, ownership preservation, case-only Linux header
names) are retained separately; the final archive export and complete measurement
run succeeded. Reproduction is documented with the runners.

A freshly built VibeOS **interpreter-only** control from the same workspace
subsequently scored **133.916760** median (134.162504 / 133.916760 / 133.705867),
with successful validation at 133.522727. Debian's identical interpreter/runtime
is 1.206× faster. Per 2,632-iteration sample, VibeOS spent about 17.14 seconds
inside runtime polls and 2.54 seconds outside them (12.96% of invocation time).
Removing *all* outside-poll time would at most yield roughly 1.15× for these
samples; this is an upper-bound attribution, not a measured optimization.
The residual runtime difference is not isolated to any one cause (target ABI,
code layout, allocator and OS environment also differ). The result supports
prioritizing larger compiled regions and better generated code over scheduler-only
work. Evidence: `debian-control-vibeos.elf`, `debian-control-vibeos/results.json`,
`profiles.json`, `environment.json`, and raw SSH/QEMU logs under the same
`target/coremark-performance/` root. All invocation lifecycle checks passed.
