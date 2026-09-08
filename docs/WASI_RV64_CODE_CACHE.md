# WASI RV64 code-cache investigation

Status: the bounded integer compiler prototype exists in `wasm-rv64/` and its
generated code has executed in a standalone QEMU probe and in WASI through the
explicit `wasi-rv64-cache` firmware feature. It remains disabled by default. The performance goal remains less
than five times the contemporaneous Debian native baseline; no CoreMark speedup
is claimed for the prototype.

## Implemented prototype and evidence

The `no_std`, unsafe-free compiler accepts validated Wasmi IR, explicit frame
slot/constant counts and a code-word budget. It lowers integer arithmetic,
bitwise operations, copies, branches, translated fuel checks, and checked
default-memory scalar accesses with 16-bit offsets. Unsupported
instructions emit an exit at the original instruction index. Backward native
branches currently require a positive fuel check directly at the destination;
other backward branches fall back to interpretation. Native code uses only
caller-saved registers and a fixed, compile-time-checked context ABI. The Wasmi bridge finds the validated function/frame, maintains the instruction
position and fuel, and invokes code published through the kernel code pool.

`scripts/test-wasm-rv64.py` generates a freestanding RV64/OpenSBI probe from the
compiler output. Rust computes expected results for 100 pairs covering zero,
signed limits, all-one bits and mixed bit patterns. Each pair executes once
with sufficient fuel and once across an out-of-fuel exit and resume: 200 cases.
These exercise arithmetic wrapping, i32 zero-extension, signed immediates,
negative constant slots, backward branches and exact continuation positions.
All passed on QEMU. Five host tests cover invalid slots, escaping branches,
unmetered backedges, code-budget exhaustion and unsupported-instruction entries.
A further 16,416 QEMU memory cases cover 19 load/store variants, three offsets,
empty/short/full memories, unaligned host and guest addresses, signed extension,
address overflow, and absence of partial out-of-bounds writes. The memory oracle
is an independent byte-array calculation in the C probe.

```sh
cargo test --release --locked --offline -p vibeos-wasm-rv64
# Requires a full Clang with the RISC-V backend; wasi-sdk's Clang is Wasm-only.
python3 scripts/test-wasm-rv64.py
```

Evidence is under `target/wasm-rv64-probe-memory/`, including generated assembly, the C
probe, ELF, UART output and toolchain metadata. This is a correctness probe, not
a performance benchmark or a complete lifecycle/W^X regression.


## First live WASI execution

The experimental backend uses an explicit per-engine publisher. It reserves at
most 1 MiB of code-pool pages and reduces the invocation heap limit to 31 MiB,
keeping the combined 32 MiB limit. It returns unsupported instructions to the
existing interpreter, including calls and memory growth. The ordinary cache
feature retains 10 million total fuel; combine it with `wasi-benchmark` for long
measurements. Both retain 10,000-fuel quanta.

```sh
python3 scripts/benchmark-coremark-wasi.py --rv64-cache \
  --work target/coremark-performance/native-repeat
```

The first image ran the original CoreMark through OpenSSH with valid CRCs for
all three performance runs and validation. Performance samples were 26.670146,
27.037037 and 26.574445 iterations/s (median 26.670146). This is a regression,
not an accepted performance improvement. Approximately 27.84 million native
entries occurred over 511 iterations, or 54,477 per iteration. The bridge's
per-entry context/fuel work and cache lookup, together with remaining unsupported
hot operations, must be reduced before this can be a useful backend.

All six invocations reclaimed their resources; code-pool live pages returned
to zero after each. This confirms normal reclamation for these executions,
not cancellation/revocation coverage. Evidence is in
`target/coremark-performance/native-cache-initial/` and the saved
`native-cache-initial.elf`. That initial ELF used the cache feature's original
benchmark dependency; subsequent builds select benchmark and cache separately.

The ordinary 10-million-fuel cache image subsequently passed the WASI QEMU
suite: 44 SSH requests, standard Rust/C commands, upload rejection, malformed
module containment, local cancellation, disconnect recovery, live compilation,
five repeated invocations and persistent-file execution after reboot. All 33
invocation lifecycle records reported clean reclamation, zero capabilities and
zero I/O waiters. The 29 normal native-teardown records reported zero live code
pages; early cancellation/admission paths do not print that counter. This run
does not replace the final 100-cycle/backend-hardening acceptance. Evidence is
under `target/coremark-performance/native-cache-acceptance/`, with the ordinary
ELF and source snapshot saved alongside it.

## Function-record reuse and hot instructions

The executor now retains an immutable `Arc` to the current compiled function,
so native segments in that function no longer lock/search the global map.
Compiler metadata marks interpreter-only entries, which bypass native entry
and context/fuel marshaling. Native entry counters are accumulated locally and
published once per interpreter quantum. Function changes reacquire the record;
code remains alive until all references and the engine are dropped.

The compiler additionally handles constant copies, 32-bit shifts, signed/unsigned
comparisons, sign extension and common comparison branches. Another 900 QEMU
cases compare boundary inputs with Rust-computed results; the existing 200
arithmetic/fuel and 16,416 memory cases also pass. Evidence is in
`target/wasm-rv64-hot-probe/`.

The first measurement of this combined change produced 133.272217, 132.618735
and 135.793099 iterations/s, median **133.272217**. Each performance run executed
2,326 iterations for more than 17 seconds; validation also passed. This is
4.997 times the initial cache's 26.670146, but only near the interpreter's
historical best score. It does not establish an advantage over a contemporaneous
interpreter control, much less satisfy the fivefold native-baseline goal.
Native calls fell from about 54,477 to 13,350 per iteration. All six calls
reclaimed their resources and returned the code pool to zero live pages.
Outputs and hashes are in `target/coremark-performance/native-hot/`, with the
saved `native-hot.elf`. Branch tables, fused selects and other unsupported hot
operations still cause frequent interpreter transitions.

The ordinary-budget revision also passed the QEMU acceptance suite with 44 SSH
requests and five repeated runs. All 33 invocation lifecycle records reclaimed
cleanly; 29 normal native-teardown records showed zero code-pool pages. This
includes cancellation/disconnect recovery, live recompilation, and execution
after reboot. Evidence is in `native-hot-acceptance/`; the corresponding ordinary
ELF and source snapshot are retained as `native-hot-ordinary.elf` and
`native-hot-source/` under `target/coremark-performance/`.

## Branch-table and conditional-select lowering

The next experimental revision lowers `BranchTable0` and `SelectI32EqImm16`
(including its `Slot2` parameter). Table destinations are checked original IR
entries; out-of-range unsigned indices take the default. Select copies preserve
all 64 value bits and skip the parameter instruction. Malformed tables and
parameters are rejected by the bounded compiler.

QEMU passed 240 new table/select cases plus the existing 200 arithmetic/fuel,
16,416 memory, and 900 control cases (`target/wasm-rv64-flow-probe/`). Six host
compiler tests passed. The immutable `native-flow.elf` scored 200.000000,
199.273052, and 199.019233; median **199.273052**, 49.5% above native-hot.
All samples lasted over 15 seconds; the independent validation workload passed
at 196.676946. Calls fell to approximately 5,342 per iteration. All six normal
teardowns reported zero live code-pool pages. Evidence and compiler source are
in `target/coremark-performance/native-flow/` and `native-flow-source/`.
This still falls well short of the Debian-relative target; the historical
Debian baseline has not been remeasured for this revision.

## Checked aligned-memory fast path and 100-cycle acceptance

For 2/4/8-byte accesses, generated code now checks host-address alignment after
all effective-address overflow and range checks. Aligned accesses use RV64
loads/stores; misaligned accesses retain the byte implementation. This does not
assume alignment of the embedding's memory base. All 16,416 memory cases and
the arithmetic/control/flow probes passed again, as did six compiler and 13
runtime tests (one stdlib test ignored).

The saved `native-aligned.elf` scored median **202.740070**, with performance
samples 202.740070, 201.348146 and 203.816022; independent validation scored
232.521263. Every timed sample exceeded 10 seconds with valid CRCs. The small
additional improvement over native-flow remains provisional without a paired
control. Benchmark evidence is in `target/coremark-performance/native-aligned/`.

The ordinary-limit build `native-aligned-ordinary.elf` then passed the full
SSH/QEMU harness with **100 consecutive executions** and 139 total requests.
Across two boots, 128 lifecycle records reported `reclaimed=true caps=0
waiters=0`, with no unclean lifecycle. All 124 normal native-teardown records
reported zero live code-pool pages (early cancellation/admission paths do not
print that record). Upload failures, containment, Ctrl-C, disconnect recovery,
post-boot compilation and both persisted programs after reboot passed. Evidence:
`target/coremark-performance/native-aligned-acceptance/`, including
`results.json` and `reclamation-summary.json`. The backend remains experimental
and default-off, and the Debian-relative fivefold goal remains unmet.

## Existing boundaries to reuse

- Wasmi validates and translates the original module to `Op` sequences owned by
  `CompiledFuncEntity` in `vendor/wasmi-softfloat/crates/wasmi/src/engine/code_map.rs`.
  Its pinned instruction allocation remains authoritative throughout an invocation.
- `kernel/src/code_pool.rs` already provides `WritableCode::allocate`, `seal`,
  and `ExecutableCode` teardown. Pages transition from RW-NX to execute-only;
  `kernel/src/mmu.rs` supplies local and remote synchronization. No RWX mapping
  or external native-code upload is needed.
- The kernel fault reclaimer already calls `code_pool::recover_faulted_domain`
  before reclaiming a legacy audited heap domain. Normal teardown must drop
  every code handle before the guest domain is closed.
- WASI owns an independent engine and store. An explicit, default-off engine
  backend setting can keep existing component admission and execution semantics.
  Historical component AOT decisions are not evidence for this WASI experiment.

## Proposed execution boundary

Compile validated Wasmi integer instruction sequences to RV64IM code. Begin
with scalar arithmetic, comparisons, branches, copies, checked memory access,
and fuel consumption. Unsupported instructions return to the existing executor
at their exact original instruction pointer. Calls, host calls, memory growth,
tables and software floats initially remain in the interpreter. Returning from
native code must neither execute an instruction twice nor skip it.

The native entry receives a trusted context containing the current frame base,
default memory base and length, remaining fuel, and original instruction offset.
Guest values cannot supply entry addresses, context pointers or host pointers.
Validate constant/local slot ranges and branch destinations while compiling.
Retain effective-address overflow and range checks, unaligned access semantics,
integer wrapping/sign extension, and unchanged out-of-fuel instruction position.
Native backedges must pass the existing translated fuel checks. Recheck
cancellation, revocation and ready work at every 10,000-fuel boundary. The
experimental native path may continue a fuel-only yield inside the current
task poll when the exact task/domain is active and no other work is runnable;
even then it returns after at most 32 quanta. Host/I/O suspensions return to
the executor. Other paths retain their original scheduling behavior.

Code belongs to one invocation; it is neither persisted nor shared across
instances. Bound compilation work, code size and relocation counts. Reserve
code pages within the existing 32 MiB combined allocation budget, including
temporary compiler storage. A full code pool or unsupported sequence must fall
back to interpretation without loosening limits. Compiled pages and host
instruction offsets must be immutable before publication.

## Evidence required before enabling the backend

1. Execute generated RV64 arithmetic/branch cases in QEMU and compare results
   with Wasmi, including overflow, signed/unsigned comparisons and shifts.
2. Differentially test unaligned and boundary memory accesses, traps, fuel
   exhaustion/resumption and transitions through unsupported instructions.
3. Verify W^X mappings, failed compilation cleanup, cancellation, SSH disconnect,
   permission revocation and exact code-pool/heap/domain reclamation.
4. Run the original Rust/C WASI acceptance programs and unmodified CoreMark.
   Retain compiler/runtime identities, module and ELF hashes, CRCs and timings.
5. Rerun Debian native and VibeOS serially on the same host/QEMU configuration.
   All formal CoreMark samples must last at least ten seconds. Only measured
   throughput above one fifth of that native baseline satisfies the goal.

## Bounded scheduling continuation

The default-off native path now rechecks the exact active task/domain,
cancellation and ready work between fuel quanta, allowing at most 32 immediate
continuations when idle. WASI authority checks run again on each quantum;
host-call/I/O suspensions do not use this path. Core tests exercise ready peers
and cancellation; a runtime test distinguishes fuel, host and terminal states.
The core suite and 14 runtime tests passed (one runtime stdlib test ignored).

Candidate/control/candidate CoreMark medians were 266.791169, 230.582205 and
267.343938: about 16% faster than the contemporaneous saved aligned-memory ELF.
All formal samples and validation CRCs passed. See `batched-comparison.json`
and the three `batched*` benchmark directories in `target/coremark-performance/`.
The ordinary-limit `batched-ordinary.elf` passed 44 SSH requests with five
consecutive executions, cancellation, disconnect recovery and reboot tests.
Across both boots there were 33 clean lifecycle records and 29 normal native
teardowns with zero live code-pool pages. No unclean record occurred. Evidence:
`target/coremark-performance/batched-acceptance/`. This five-cycle follow-up
is separate from the preceding revision's 100-cycle run.

## Parallel-copy and immediate-branch lowering

The compiler now lowers `Copy2` with parallel read semantics and all six
remaining signed/unsigned immediate relational-branch operand placements.
Seven host limit tests and QEMU's 150 parallel-copy, 1,500 control, 240 flow,
16,416 memory and 200 arithmetic/fuel cases passed. Copy tests include aliasing,
swaps, constants and frame addresses outside the signed 12-bit displacement.

The unchanged CoreMark module scored median **299.325348**, versus the adjacent
saved previous ELF's **267.361807**, a 12.0% gain. Native transitions fell to
about 3,439 per iteration. All formal samples exceeded ten seconds with correct
CRCs; independent validation passed. See `native-copy/`, `native-copy-control/`
and `native-copy-comparison.json` under `target/coremark-performance/`.

Ordinary-limit acceptance passed 44 SSH requests with five repeated executions,
cancellation, containment and reboot. Across both boots all 33 lifecycle
records were clean and all 29 normal native teardowns had zero code pages.
Evidence is in `native-copy-acceptance-retry/`. The first attempt's preserved
`native-copy-acceptance/` log records a transport reset before key exchange in
the negative-key fixture. That fixture now retries only bounded pre-auth KEX
failures without WASI activity; it still requires explicit public-key rejection
and never treats a connection reset as authentication evidence. This follow-up
does not replace final 100-cycle acceptance, and the fivefold goal is unmet.

## Frame-slot cache and next backend investigation

The experimental compiler now caches up to six statically frequent mutable
frame slots in caller-saved registers a6, a7 and t3–t6. Every entry
reloads them and the shared exit writes them back, including memory traps and
fuel exhaustion. Constant slots remain read-only in the frame. A two-pass
bounded compiler keeps an uncached fallback if cached emission exceeds its
word budget. Memory bounds use a checked exclusive end before either aligned
or byte access. Eight host checks and the expanded QEMU transition probe pass.

This variant completed 100 ordinary-limit executions and same-disk restart
recovery after the first restart's 300-second timeout. Its real-clock gain
remains unproven because repeated runs of the same ELF varied greatly. Details,
raw paths and the separate non-rating icount diagnostic are recorded in
[WASI_PERFORMANCE.md](WASI_PERFORMANCE.md). The default-off status and fivefold
goal remain unchanged.

A pinned, isolated [Cranelift 0.135.1 feasibility workspace](../wasm-rv64/experiments/cranelift-no-std/README.md)
now verifies no_std RISC-V target compilation. It is not a kernel backend yet.
The next step is executing generated integer code and checking ABI, relocation,
constant-pool and allocation constraints before lowering validated Wasmi IR.

## Cranelift generated-code and page-permission probe

The isolated Cranelift experiment now generates and executes a wrapping integer
loop. The pinned ISA constructor requires G and rejects disabling F/D, so this
is not yet a general IMAC backend. The actual external-literal probe is audited
as a 52-byte RV64IM leaf stream and executes with FS/VS disabled.

SV39 tests passed 500 C-oracle cases on RX code, then reproduced a load page
fault when the inline constant pool's page became execute-only. A second
variant passes all 500 cases with execute-only code and a separate read-only
literal supplied by pointer. Existing code-pool permissions were not changed.
Both functions have no external relocations or declared hardware traps.

This resolves one concrete design question for future lowering: wide literals
must not silently become loads from execute-only code. It does not prove all
Cranelift emissions are compatible, nor bound compiler memory/stack usage.
The kernel remains unchanged by this experiment. Reproduction and next gates:
[Cranelift experiment](../wasm-rv64/experiments/cranelift-no-std/README.md).
Evidence: `target/cranelift-rv64-external-audited/`; bare-metal no_std codegen
check: `target/coremark-performance/cranelift-codegen-no-std-check.log`.

The first actual Wasmi-IR Cranelift prototype also passes 200 execute-only QEMU
fuel/frame cases (`target/cranelift-wasmi-probe/`): metered backward branches,
exact-PC fuel exhaustion, split-budget resume, integer arithmetic/copies and
reloading interpreter-modified slots after unsupported-op fallback. This remains
an isolated bounded prototype with no kernel integration or CoreMark gain claim.
