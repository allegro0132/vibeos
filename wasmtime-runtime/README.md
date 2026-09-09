# Wasmtime 48 platform port

This is the active replacement direction for WASI performance: port Wasmtime's
runtime, Cranelift integration and Preview 1 adapter, then compile **ordinary
uploaded Wasm inside VibeOS** and execute it through existing command services.
The final acceptance remains less than 5× slower than a contemporaneous Debian
native CoreMark baseline, alongside existing WASI lifecycle and containment tests.
A host-AOT-only loader would not satisfy this objective.

The independent workspace prevents `std` features from leaking into the kernel
while the platform port is incomplete. Default builds retain Wasmi. The explicit
`wasmtime-command` firmware feature now selects Wasmtime for local/SSH `wasm-run`;
the component path retains its backend. Wasmtime is pinned to 48.0.0, matching the compiling-engine Debian
control; upstream provenance and the source patches are in
`../vendor/wasmtime-48/`.

Implemented and verified:

- Wasmtime runtime with custom virtual memory and synchronization interfaces
  compiles for `riscv64imac-unknown-none-elf` with `core,alloc` only.
- `configuration()` enables fuel and explicit bounds checks, disables signal-based
  traps, and uses movable, host-owned memory capped at 16 MiB. This is a port configuration,
  not a complete WASI admission policy or allocation-domain implementation.
- Wasmtime's compilation environment, including its component translation types,
  now compiles without `std`. Core/alloc imports and existing no_std collection
  wrappers replace standard-library dependencies. Filesystem-based CLIF paths and
  WAT trace printing remain std-only; compiler semantics are retained.
- Wasmtime's Cranelift glue and complete module compilation pipeline now also
  compile without `std`. The port retains optimization, inlining, trampoline
  generation and linking; native CPU discovery, filesystem output and compiler
  timing instrumentation are std-only. Simulated native DWARF explicitly returns
  an error without std.
- The real CoreMark module translates to the same public metadata summary as
  unmodified upstream: 88 functions, 80 bodies, one memory, one table, two globals,
  eight imports. Both reject the malformed-header control. This is only a
  translation smoke comparison; it does not prove native-code correctness.
- All 80 CoreMark function bodies produce byte-identical RISC-V native code and
  relocation records compared with upstream, with fuel and explicit bounds checks.
  With the original fixed-reservation configuration, the complete module pipeline
  produced the same 232,872-byte artifact as upstream. The current movable-memory
  configuration produces identical 247,480-byte artifacts in upstream, host std
  and no_std custom-platform harnesses (including inlining and trampolines).
  These comparisons compile code but do not execute it.

```sh
CARGO_TARGET_DIR="$PWD/target/wasmtime-platform" cargo check --locked --offline \
  --manifest-path wasmtime-runtime/Cargo.toml --features compiler \
  --target riscv64imac-unknown-none-elf -Zbuild-std=core,alloc
python3 scripts/test-wasmtime-translation.py
python3 scripts/test-wasmtime-codegen.py --work target/wasmtime-codegen-pinned
python3 scripts/test-wasmtime-module.py
```

Evidence: `target/coremark-performance/wasmtime-platform-check.log`,
`wasmtime-pipeline-no-std.log`, `target/wasmtime-translation/results.json`,
`target/wasmtime-codegen-pinned/results.json` and `target/wasmtime-module/results.json`.
The `host-tools` feature enables std only for host comparison; never enable it in
firmware. `host-custom` supplies a host-only custom C API adapter to exercise the
no_std compiler/runtime independently of Wasmtime's standard platform backend.
Its mmap, TLS and lock hooks are testing infrastructure, not kernel hooks.

Next integration gates are concrete and still open:

1. Bound the now-running on-device compiler's memory, stack and scheduling time
   for untrusted modules; the small kernel smoke test does not establish these.
2. Extend the linked code-image/TLS/synchronization bridge to anonymous linear
   memory, remap/unpublication and quiescent registry cleanup after forced exit.
3. Preserve the verified GC FP context and native trap behavior through async
   suspension and cancellation. IMAC remains unsupported for native execution.
4. Port the Preview 1 adaptation to VibeOS clock/stream/capability services. Preserve
   EOF, independent stderr, bounded output, I/O backpressure, cancellation and
   revocation. Async/fuel suspension must return to the scheduler without losing
   guest state; running an entire fuel budget synchronously is not equivalent.
5. Connect file snapshots and authenticated SSH/vsh invocation, rerun adversarial
   and 100-cycle reclamation tests, then measure matched QEMU real-clock CoreMark.
   The fivefold target remains unmet.

## Native execution through the custom platform

`execute-custom` now compiles and executes real native code through the host-only
custom mmap/TLS/lock adapter, including instruction-cache synchronization when
publishing RX code. On both macOS AArch64 and QEMU Debian RV64, 100 cycles passed:
return 42, unreachable, integer divide by zero, out-of-bounds load and fuel
exhaustion. Each cycle compiled five modules. All mappings returned to zero and
live heap returned to the first-cycle baseline with the engine retained.
This validates the custom runtime path on Linux's hard-float ABI, not VibeOS's
IMAC ABI, FP state handling, scheduler, capabilities or allocation domains.

```sh
CARGO_TARGET_DIR="$PWD/target/wasmtime-platform" cargo run --locked --offline \
  --manifest-path wasmtime-runtime/Cargo.toml --features compiler,host-custom \
  --example execute-custom
COREMARK_SYSROOT="$PWD/target/coremark-performance/debian-engines-ready/results/sysroot" \
CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER="$PWD/scripts/coremark/riscv64-linux-cc.sh" \
CARGO_TARGET_DIR="$PWD/target/wasmtime-platform" cargo build --release --locked --offline \
  --manifest-path wasmtime-runtime/Cargo.toml --features compiler,host-custom \
  --example execute-custom --target riscv64gc-unknown-linux-gnu
mkdir -p target/coremark-performance/wasmtime-custom-riscv/inputs
cp target/wasmtime-platform/riscv64gc-unknown-linux-gnu/release/examples/execute-custom \
  target/coremark-performance/wasmtime-custom-riscv/inputs/
python3 scripts/benchmark-coremark-debian.py \
  --work target/coremark-performance/wasmtime-custom-riscv \
  --image-work target/coremark-benchmark/debian \
  --guest-script scripts/wasmtime/execute-debian.sh
```

The prepared Debian image and sysroot are prerequisites from the existing engine
benchmark setup. Evidence is in `target/coremark-performance/wasmtime-custom-riscv/`
(`execution-results.json`, raw output, binary hash, QEMU command and boot log).
The generic benchmark driver's empty `results.json` contains no CoreMark scores;
this run is explicitly an execution/teardown test.

The custom host compiler's CoreMark run used 11,915,236 peak requested heap bytes
and no platform mappings during precompilation. The measurement excludes allocator
metadata, compiler stack and kernel overhead; it does not prove the invocation's
32 MiB allocation budget. RV64 execution smoke peak heap was 132,244 bytes and
peak mapped space was 16,789,504 bytes (including the configured reservation).
These separate maxima must not be interpreted as simultaneous usage or as a
CoreMark execution footprint. Kernel execution and performance acceptance remain
open.

## RISC-V execution ABI and FP context

Native integration now selects `native-riscv`, which requires one of the audited
LP64D targets `riscv64gc-unknown-none-elf` and `riscv64gc-unknown-linux-gnu`.
The IMAC target remains usable for compiler-only type checks but is rejected for
native integration. Adding `+f,+d` instructions to an IMAC target does not change
its C ABI. Cranelift's RV64 ABI assigns floating arguments/results to FP
registers, including runtime builtin calls; mixing this with LP64 is invalid.

`src/riscv.rs` supplies assembly save/restore hooks for all 32 FP registers and
FCSR, in a 272-byte aligned context. These are intended for an assembly trap or
context-switch boundary, not arbitrary Rust calls that would violate compiler
register assumptions. `execute-custom` with `native-riscv` tests all registers
against distinct expected bit patterns and checks FCSR by direct readback after
restoration. It also tests an f64 guest-to-host call and f64 return value.

```sh
CARGO_TARGET_DIR="$PWD/target/wasmtime-platform" cargo build --release --locked --offline \
  --manifest-path wasmtime-runtime/Cargo.toml --features native-riscv \
  --target riscv64gc-unknown-none-elf -Zbuild-std=core,alloc
```

The full no_std library release build passed (`wasmtime-native-gc-build.log`).
For the Debian execution command above, replace `compiler,host-custom` with
`native-riscv,host-custom` and use a fresh output directory so prior evidence is
retained. The latest direct FP-state probe is in
`target/coremark-performance/wasmtime-fp-direct/`.

The GC kernel now enables FS and initializes FCSR before entering Rust on every
hart. Its trap frame is 528 bytes and saves all 32 FP registers plus FCSR; its
catch context is 400 bytes and restores FP state on normal return and longjmp.
IMAC retains the original 256-byte trap and 128-byte catch frames. Target-specific
assembly is selected using the built-in target's D feature; the shared default
firmware target remains IMAC.

Four-hart QEMU kernel acceptance passed: GC 391 checks, IMAC 390 checks. The GC
case injects zero FP registers/FCSR inside a real software-interrupt entry and
checks distinct original values after return. Catch tests also dirty FP state
before nonlocal exits and validate normal, zero-status and nested returns.
One initial run exposed an existing fault-isolation test race: eight yields did
not wait for a task running on another hart. The test now waits at most one second
for the actual faulted state and fault counter. Failed and final logs are both
retained; no failure was discarded as a passing result.

```sh
(cd firmware/qemu-virt && cargo build --locked --offline --release \
  --target riscv64gc-unknown-none-elf --features legacy-shell)
python3 scripts/wasmtime/test-kernel-fp.py \
  --kernel target/riscv64gc-unknown-none-elf/release/vibeos-qemu-virt \
  --work target/coremark-performance/kernel-gc-final-selftest
(cd firmware/qemu-virt && cargo build --locked --offline --release --features legacy-shell)
python3 scripts/wasmtime/test-kernel-fp.py \
  --kernel target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt \
  --work target/coremark-performance/kernel-imac-fp-regression
```

Each result directory records the exact ELF hash, QEMU command and full output.
`kernel-gc-irq-selftest/` retains the initial timing failure. These checks establish
kernel FP context preservation. The later native Wasmtime test below establishes
compilation and execution; bounded compiler stacks and async WASI lifecycle
integration remain required before a performance claim.


## Kernel RX publication

The code pool now exposes a separate `seal_readable()`/`ReadableExecutableCode`
path for optimizing backends that load constants embedded in native code. The
existing `seal()` remains execute-only and MXR remains clear. Both paths retain
exclusive allocation ownership, break-before-make PTE updates, all-hart TLB and
instruction-cache synchronization, and zeroing before reuse. Per-run RX state
is retained in the pool so raw allocation-domain recovery revokes the correct
permissions even when longjmp skips Rust destructors.

Four-hart QEMU acceptance passed 397 GC checks and the original 390 IMAC checks.
The six new GC checks cover exact RX permissions, execution of a PC-relative
inline-constant load, immutable byte inspection, absence of writable-executable
RAM, RW-NX zeroed reuse and live/sealed page baseline recovery. The existing
16-cycle fault/restart test now abandons both XO and RX allocations on GC, and
recovers both without running destructors. Evidence is under
`target/coremark-performance/kernel-rx-gc/` and `kernel-rx-imac/`.

The code pool now also supplies `freeze_image()` and `CodeImage::publish_text()`
for Wasmtime's two-stage protocol: freeze the complete image RO-NX, then publish
page-aligned text subranges RX. Empty, unaligned, overflowing, escaping or
already-published ranges are rejected before modifying the first page. Pool
metadata retains each image page's permissions for normal Drop and raw domain
recovery; retirement groups adjacent pages with the same permissions and restores
RW-NX before zeroing/reuse. `sealed_pages` includes frozen RO image pages.

Four-hart acceptance now passes 406 GC checks and 390 IMAC checks. A three-page
RO/RX/RO image runs a real inline-constant load while both metadata pages remain
readable and non-executable. Rejected overlaps leave metadata RO. The 16-cycle
fault/restart probe abandons XO, RX and mixed-permission images together and
recovers all runs without destructors. Evidence: `kernel-image-gc/` and
`kernel-image-imac/` under `target/coremark-performance/`.

These image-lifecycle primitives now back the experimental Wasmtime C API below.
Wasm linear memory now uses the host MemoryCreator described below; full recovery
and generic anonymous mapping remain open. The native smoke
result below does not establish a CoreMark performance claim.


## Experimental kernel platform bridge

The optional `wasmtime-native` firmware feature now links this crate into the GC
kernel. It supplies Wasmtime's custom VM/TLS/synchronization symbols. Code image
mappings are held in 16 fixed registry slots and backed by the dedicated code
pool. Busy slots remain reserved while permission transitions run outside the
registry lock, avoiding holding that lock over cross-hart TLB synchronization.
Protection lengths cover the last partial page as required by the mmap API.
TLS has two opaque slots per hart; Wasmtime 48's initialization tag is retained,
while the self-test checks that no active call pointer survives teardown.

```sh
(cd firmware/qemu-virt && cargo build --locked --offline --release \
  --target riscv64gc-unknown-none-elf --features legacy-shell,wasmtime-native)
python3 scripts/wasmtime/test-kernel-fp.py \
  --kernel target/riscv64gc-unknown-none-elf/release/vibeos-qemu-virt \
  --work target/coremark-performance/wasmtime-in-kernel --require-wasmtime
```

This feature currently adds a trusted kernel self-test, not a user command.
The bridge only supports code-image RW allocation, whole-image RO freeze,
text-range RX publication and complete unmap. Anonymous linear-memory reservation,
remap and image unpublication remain unsupported and fail explicitly. Registry
cleanup after a task is forcibly abandoned, allocation/fuel scheduling limits,
WASI imports and SSH/vsh integration must be completed before exposing guest
execution through this backend. Passing its smoke test cannot satisfy the
CoreMark performance or full WASI lifecycle gates.


The native kernel smoke test now passes: raw core Wasm is compiled inside the
running VibeOS kernel, its native function returns 42 and consumes fuel, and a
second compiled infinite loop returns `Trap::OutOfFuel`. After teardown the map
registry and code pool recover their baseline, and TLS retains no active call
pointer (the per-hart initialization bit may remain). Four-hart QEMU completed
407 kernel checks with zero failures. The exact ELF hash, native marker and full
log are recorded in `target/coremark-performance/wasmtime-in-kernel/`. The first
failed RO publication attempt is retained in `wasmtime-in-kernel-first/`.
This is a real Wasmtime execution result, but still not WASI or a CoreMark score.

Default IMAC regression after optional engine integration: 390 checks passed
(`target/coremark-performance/wasmtime-integration-imac/`).


## Bounded, movable Wasm linear memory

`configuration()` now installs a no_std `MemoryCreator` backed by the embedding
allocator. It rejects shared/memory64/guarded configurations, aligns allocations
to 4 KiB and caps logical growth at 16 MiB, including when a module omits its
maximum. Memory is zero-filled; growth within capacity preserves the base, while
larger growth allocates/copies before releasing the previous allocation. Failure
preserves the old size/data. The compiler uses zero reservation/guard and explicit
bounds checks with memory movement enabled. Heap pages remain RW-NX.

An initial fixed 16 MiB allocation failed in the kernel: allocator metadata and
size-class rounding charged 32 MiB against the shell's 8 MiB quota. The movable
strategy avoids that upfront allocation and follows actual module needs. This
does not increase any invocation quota or establish the final 32 MiB whole-instance
budget. Old failure logs remain in `wasmtime-linear-kernel/`.

Kernel acceptance in `wasmtime-linear-movable-kernel/` passed 407 checks with a
native `memory_grow_bounds=1` marker: initial/grown zero bytes, an end-crossing
load trap, declared-maximum rejection, and a guest `memory.grow` that relocates
memory followed by a load in the same compiled function. Existing data survived
and the compiled code used the new base. Host `memory-custom` passed 20 cycles
with an omitted maximum, 16 MiB enforcement and steady post-drop heap usage.
The host standalone `Memory::new` path in Wasmtime 48 uses a default allocator;
these tests deliberately instantiate module-owned memory to exercise the actual
configured creator. Imported host memory remains outside this command profile.

```sh
CARGO_TARGET_DIR="$PWD/target/wasmtime-platform" cargo run --locked --offline \
  --manifest-path wasmtime-runtime/Cargo.toml --features compiler,host-custom \
  --example memory-custom
python3 scripts/test-wasmtime-module.py --work target/wasmtime-module-movable
```

With the new compiler tunables, complete CoreMark artifacts still match upstream
byte-for-byte (`target/wasmtime-module-movable/results.json`). This is compilation
comparison, not a runtime score. Async I/O/fuel scheduling, complete forced-exit
cleanup and authenticated invocation integration remain pending.


### Synchronous Preview 1 adapter (2026-09-09)

`src/wasi.rs` provides a no_std adapter for bounded, noninteractive tests. It uses
Wasmtime Caller/Linker and the existing Preview 1 signature table, with args,
empty environment, buffered stdin and separate stdout/stderr, standard descriptor
metadata/close/seek semantics, explicit embedding clocks and full u32 proc_exit.
Known unimplemented imports return NOSYS; unknown imports and bad signatures
are rejected. Core start sections and components are rejected before compilation.
Guest iovecs and result pointers are validated before consuming input or output.
The synchronous buffers cap input and combined output at 64 KiB, use short I/O,
and bound argv to 128 entries / 16 KiB and iovecs to 1024 entries.

```sh
CARGO_TARGET_DIR="$PWD/target/wasmtime-platform" cargo build --locked --offline \
  --manifest-path wasmtime-runtime/Cargo.toml --features compiler,host-custom \
  --example wasi-custom
python3 scripts/wasmtime/test-wasi-host.py
```

Host custom-platform acceptance passed 18 cases, including real C/Rust standard
libraries, spaced/Unicode arguments, 16 KiB input filtering, separated output,
exit 7, exit 0xffffffff followed by unreachable, rejected imports/start section,
bad clock pointers, a later invalid iovec causing no output, and NOSYS linkage.
The unchanged CoreMark module also ran through this adapter with its expected
performance-seed/list/matrix/state CRCs. This 1000-iteration smoke is below ten
seconds: its output explicitly rejects the duration, so it is not a formal score
or a VibeOS performance measurement. Logs and hashes are under
`target/coremark-performance/wasmtime-wasi-host/`.

A proc_exit host error can retain a Wasm backtrace and module mapping; callers
must drop that error before checking post-invocation code reclamation. This is
covered by the host runner's post-drop zero-mapping assertion.

This adapter is not exposed via SSH/vsh. Full structural admission, compiler and
whole-instance allocation accounting, cancellation, permission-revocation cleanup,
async I/O backpressure and quantum fuel scheduling remain integration gates.
The existing Wasmi command backend is unchanged.

The four-hart VibeOS kernel also passed 407 checks, including 100 invocations of
a raw WASI ABI probe compiled inside the kernel: monotonic clock, fd_write,
proc_exit(7) followed by unreachable. At the enclosing selftest boundary all
platform code mappings were freed, code-pool counters returned to baseline and
TLS held no active call pointer. This is not the command-service 100-cycle
cancellation/allocation-domain acceptance test. Evidence:
`target/coremark-performance/wasmtime-wasi-kernel-verified/`, kernel SHA-256
`2993be264d628c30093130de00104abb68572148f071fdae3a25a6eb601ad8b5`.

```sh
python3 scripts/wasmtime/test-kernel-fp.py \
  --kernel target/riscv64gc-unknown-none-elf/release/vibeos-qemu-virt \
  --work target/coremark-performance/wasmtime-wasi-kernel-verified \
  --require-wasmtime --require-wasi
```

### Trusted in-kernel CoreMark measurement (2026-09-09)

The opt-in `wasmtime-coremark-probe` feature embeds the supplied ordinary Wasm
bytes without rewriting imports or sections, then compiles them inside VibeOS.
It is a resource/performance diagnostic, not the final online-upload command.
The compiler and instance use their own measured, untracked owner: 30 MiB heap
plus a conservative reservation of the entire 2 MiB code pool. This intentionally
does not claim a reclaimable arena or cancellation-safe no-escape contract.
The engine is dropped inside the owner as well, including its compiler caches.
WASI realtime/monotonic clocks now share the existing kernel clock implementation
and one RTC latch lock with the Wasmi backend.

```sh
# From firmware/qemu-virt; use an absolute module path.
VIBEOS_WASMTIME_COREMARK=/absolute/path/coremark.wasm \
  cargo build --locked --offline --release --target riscv64gc-unknown-none-elf \
  --features legacy-shell,wasmtime-coremark-probe
# From repository root.
python3 scripts/wasmtime/test-kernel-fp.py \
  --kernel target/riscv64gc-unknown-none-elf/release/vibeos-qemu-virt \
  --work target/coremark-performance/wasmtime-coremark-kernel-single \
  --require-wasmtime --require-wasi --harts 1 \
  --coremark-module target/coremark-wasi/coremark.wasm
```

The build requires the input path when this feature is enabled, records it as a
rebuild dependency, and copies only those bytes into OUT_DIR. Iterations default
to 60000; `VIBEOS_COREMARK_ITERATIONS` changes the trusted fixture count. The
verifier requires the exact module to appear in the ELF, valid CoreMark output,
>=10 seconds, zero post-drop owner bytes and no allocation denials. It records
kernel/module hashes, fuel, timing, heap peak and the QEMU command.

A single-hart, single-thread TCG run with the same module SHA `c5f77f7...` yielded
1480.859886 iterations/s over 40.517 seconds, with valid performance CRCs.
Compilation took 1.361562 seconds; the complete guest call took 40.529089 seconds.
Fuel consumed was 38,115,341,140. The heap peak was 19,641,984 charged bytes;
after teardown live bytes and code mappings were zero. Kernel selftests passed
407 checks. ELF SHA: `e9866092a82b5b4eb68db8050f593a66c3df7e0bf9b9faaddd38560c42111e5e`.
An earlier single-hart multi-thread-TCG control yielded 1481.115774, so that
QEMU setting did not explain the observed gap. Neither run includes async fuel
quantum scheduling or the authenticated command service.

Fresh Debian native control samples were 9947.962785, 9501.103076 and
9959.465536 iterations/s (median 9947.962785); a separate validation-seed run
passed at 10032.289375. All exceeded ten seconds. Compared with the single-thread
VibeOS probe this is approximately 6.72x, so the requested <5x target is not met.
The OS configurations retain 1 GiB Debian versus 128 MiB VibeOS guest RAM; do not
attribute the ratio to any one OS mechanism. Logs are in
`target/coremark-performance/debian-wasmtime-port-control/` and
`target/coremark-performance/wasmtime-coremark-kernel-single/`.

The Debian port control used the same generic no_std code configuration and
adapter, yielding 1354.096141, 1406.370860 and 1398.210291 iterations/s (median
1398.210291); its validation-seed run passed at 1403.574436. Evidence is in
`debian-wasmtime-port-runtime/results/ported-summary.json`, with binary/module
hashes in `environment.txt`. It does not include Linux native CPU discovery.

The first concrete correction now propagates the Rust target's guaranteed C
extension to Cranelift on native RV64GC. Previously no_std used Cranelift's G-only
baseline, while std Linux discovers C and additional CPU extensions. The first
corrected VibeOS run reached 1874.882820 iterations/s (32.002 seconds), with the
same module, explicit bounds and fuel budget. Compiler time was 1.392427 seconds;
heap peak was 19,605,632 bytes and final live bytes remained zero. The 407 kernel
checks passed. The measured ELF is retained in
`target/coremark-performance/wasmtime-coremark-kernel-c/kernel.elf` (SHA
`26d3e90460691abf2b820790668803a9388da8de8e053273dcfb0fdac350220b`).
This is approximately 26.6% above the G-only VibeOS result and still about 5.31x
slower than the fresh native median. Additional CPU extensions are not assumed;
they require an explicit platform contract or runtime detection.

A repeat of that frozen ELF scored 1875.000000 over 32.000 seconds, again passing
407 checks and returning the measured owner to zero. The fresh native slowdown
is 5.305580152x. Reproduction evidence, source hashes/snapshot and comparison JSON
are retained in `wasmtime-coremark-kernel-c-repeat/`. Host ABI tests passed 18/18;
the IMAC Wasmi benchmark image also passed an offline release compile check after
the shared-clock refactor.

### Boot CPU discovery and next memory/trap gate

`riscv_isa.rs` is a bounded, allocation-free reader of FDT v17 CPU extension
lists. It intersects the selected HSM harts, rejects incomplete/ambiguous CPU
records, supports one/two-cell hart IDs and ignores unknown extensions. The
kernel consumes OpenSBI's a1 DTB before heap initialization, with an address/size
check against its mapped heap RAM; no firmware pointer escapes. Five host test
groups plus a real four-hart QEMU DTB passed:

```sh
qemu-system-riscv64 -machine virt,dumpdtb=target/coremark-performance/wasmtime-isa-qemu.dtb \
  -cpu rv64 -smp 4 -m 128M -display none
python3 scripts/wasmtime/test-riscv-isa.py \
  --dtb target/coremark-performance/wasmtime-isa-qemu.dtb
```

Format references: [DTSpec flattened format](https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html)
and [Linux RISC-V CPU bindings](https://github.com/torvalds/linux/blob/master/Documentation/devicetree/bindings/riscv/cpus.yaml).

Detected scalar B extensions are **not enabled by default**: the measured QEMU
cohort favored GC. `wasmtime-discovered-isa` is an explicit experiment and still
requires firmware support on every schedulable hart. Reproduce with that feature
plus `wasmtime-coremark-probe`; `--cpu` and `--isa-mask` in the kernel verifier
allow individual extension controls. `extra_mask` reports discovery, not the
compiler policy. The final default four-hart image passed 407 checks and retained
1870.324190 iterations/s with zero post-drop allocations (`wasmtime-isa-default/`).

The fixed-GC Debian VM controls showed a 1.6107x median advantage for protected
virtual memory/native traps over explicit checks/movable memory. Full data and
configuration are in `docs/WASI_PERFORMANCE.md` and
`target/coremark-performance/debian-wasmtime-vm-controls/results/vm-summary.json`.
This is evidence for the next porting step, not an achieved VibeOS score. The
current kernel still has explicit checks, and general native fault handling,
guarded guest virtual mappings, async scheduling and complete command lifecycle
acceptance remain pending.

Native hardware-trap work additionally requires the scoped Cranelift 0.135.0
fs1 ABI correction in `../vendor/wasmtime-48/riscv64-fs1-abi.patch`.
Historical vanilla-upstream byte comparisons above predate that correction;
current codegen/module comparison scripts explicitly apply it to both sides.
This does not update or replace the historical Debian benchmark executable.

The optional kernel `wasmtime-guarded-memory` feature builds on native traps.
It reserves 8 GiB of otherwise unmapped Sv39 VA at 64 GiB, advertises a fixed
4 GiB Wasm reservation with 64 KiB guard, and commits at most 16 MiB of RW/NX
physical pages. Growth replaces physical backing under a stable guest pointer;
break-before-make and all-hart TLB shootdowns precede freeing old backing.
The sole reservation returns busy to additional memories. Its nine static page
tables are deducted from the trusted CoreMark probe's total allocation budget.
Four-hart selftests passed zero initialization, crossing-page and maximum-u32
OOB traps, stable-pointer growth, declared-maximum failure, concurrent-memory
rejection, 100 WASI cycles, and full unmapping on drop. The runtime still needs
supervised asynchronous execution and forced-recovery integration before this
feature can back untrusted authenticated commands.

The optional `wasmtime-async` kernel feature now enables the pinned no_std fiber
runtime. `NativeFuture` wraps both polling and cancellation, preserving the
host's supervisor/FCSR state and retaining the invocation's FCSR across yields.
A four-hart probe passes 50 fuel-exhaustion runs and 50 cancellations while
suspended, plus a pending asynchronous host call followed by a native trap.
The entire cold-start test uses a separate allocation owner and returns to
zero live bytes (peak 665,216 bytes). The global code registry needed the
quiescent-capacity release patch described in the vendor README to achieve this.

CoreMark with 10,000-fuel suspension and manual polling now has a three-run
median of 2176.910239, 4.5957x behind the fresh Debian native control. This is
fiber overhead measurement; it has no production command scheduler or streamed
WASI I/O. The default no_std fiber stack is still heap-backed without a guard;
protected fiber stacks, asynchronous stream adaptation and forced-recovery
ownership remain gates before authenticated command exposure. Normal Drop and
cooperative cancellation tests do not prove the raw arena-reclaim contract.

Streaming Preview 1 stdio is available with the runtime `async` feature through
`Invocation::with_streams` and `wasi::linker_streams`. The host `Streams` trait
polls short reads/writes, registers readiness wakeups and closes invocation
handles. All vectors and result pointers are checked before any host I/O;
reads/writes are at most 4096 bytes per call and stdout/stderr share a 64 KiB
output allowance. The mutable guest-memory borrow remains exclusive across the
await. Pending operations must not consume input or commit output; dropping the
host stream object must retire its pending registrations.

`kernel/src/wasmtime_command_io.rs` adapts this interface to the existing
`CommandIo`/`GuestIo` transport. This is transport integration, not yet a change
to the public wasm-run execution backend. Host-side real Rust/C stdlib tests
pass with deliberately suspended 7-byte reads and 11-byte writes; kernel tests
cover short I/O, EOF, separate stderr, invalid later iovecs/result pointers with
no I/O, the combined output cap, and actual empty/full command pipes.
Reproduce the host checks using:

```sh
CARGO_TARGET_DIR="$PWD/target/wasmtime-platform" cargo build --locked --offline \
  --manifest-path wasmtime-runtime/Cargo.toml \
  --features compiler,host-custom,async --example wasi-streams-custom
python3 scripts/wasmtime/test-wasi-host.py \
  --runner target/wasmtime-platform/debug/examples/wasi-streams-custom \
  --work target/coremark-performance/new-streams-host
```

The host runner deliberately suspends before each blocking host syscall; it is
a deterministic ABI harness, not an operating-system readiness implementation.
Kernel `CommandIo` readiness uses the existing bounded pipe wakeups. For kernel
verification use the async image and add `--require-streams` to the QEMU driver.

Guarded guest-memory raw recovery now has a copied kernel allocation-domain
record. A private memory-only fixture verifies 48 real executor faults and
unmapping before arena reclamation without Drop. This proves that layer only:
full Engine/Module/code-registry/TLS recovery is not covered by that fixture or
its admission gate. See the latest recovery evidence in WASI_PERFORMANCE.md.


### Kernel protected stack integration

The kernel async profile now overrides the default no_std fiber allocator with
an owned StackCreator: four slots, at most 256 KiB each, zeroed RW/NX pages and
unmapped guards. It uses independent per-hart 64 KiB trap stacks so an unmapped
interrupted SP does not prevent saving an exception frame. The new QEMU driver
flags `--require-trap-stack --require-fiber-stack` require invalid-SP recovery,
recursive Wasm StackOverflow and empty final fiber mappings. Raw fiber cleanup
is included in the private exact-domain runtime fault fixtures, including a
faulting cancellation destructor. These are kernel platform checks; public
command-service admission and compiler supervision are still unfinished.
See `../docs/WASI_PERFORMANCE.md` for hashes, budgets and one/four-hart evidence.


### Shared WASI structural admission

`wasi::compile` now includes the inspector from `wasi-runtime/src/validate.rs`
and uses `vibeos-component-format::PROFILE_1_LIMITS` before allocating compiler
state. Both backends retain their pinned parser versions and share the source
of the structural rules. The host script additionally rejects valid modules
exceeding the profile's type, locals, nesting and initial-memory limits. The
kernel's private compiler budget sweep proves cleanup at four observed compile
allocation failures and after four successful compilations; it does not establish
compiler CPU deadlines or public command-service readiness.

### Experimental command-service diagnostic

`wasmtime-command` now selects this backend for real local/SSH uploads and
`wasm-run`; `WASI_WASMTIME=1` selects the GC firmware target in the launcher.
Use `wasi-ssh-upload,wasmtime-command` for default-limit functional testing and
`wasi-benchmark,wasmtime-command` for the explicitly granted long-running benchmark.
The default Wasmi backend and capability grants retain their existing selection.

The functional diagnostic at
`target/coremark-performance/wasmtime-command-output-diagnostic/results.json`
passed Rust/C stdlib streams/arguments/exit codes, adversarial limits, the scalar
bulk-copy regression, cancellation, 100 reclaimed calls and persisted execution
following reboot. It uses an explicit 30-second SSH keepalive; the original
2-second keepalive failed during synchronous compilation, so compiler scheduling
and responsiveness are still open. Exceeding the combined 64 KiB output quota
now terminates the invocation as resource exhaustion instead of allowing an
ignored-FBIG hostcall loop. Host buffered/streaming suites each pass 23 cases.

### Bounded in-fiber fuel scheduling

Enable the measured command configuration with:

```sh
WASI_WASMTIME=1 WASI_FUEL_BATCH=1 scripts/run-wasi-qemu.sh
```

This builds `wasi-ssh-upload,wasmtime-command-fuel-batch` for RV64GC. It retains
the default 10-million total fuel limit and checks authority/cancellation and
executor competition every 10000 fuel. At most 32 quanta share a native poll;
I/O blocking and competing tasks force a return to the executor. The existing
outer batch is disabled, so these limits cannot multiply. A per-store function
and opaque token borrow the SYSTEM job through its supervised lifetime. The
optional Wasmtime patch changes only the decision to suspend a fiber after
normal refueling; it never grants extra fuel or changes memory checks.

For formal CoreMark, build `wasi-benchmark,wasmtime-command-fuel-batch`, then use
`python3 scripts/benchmark-coremark-wasi.py --wasmtime --fuel-batch --require-isa-mask 0xf --kernel PATH --work FRESH_DIRECTORY`.
This benchmark feature explicitly grants the long-running fuel allowance.
The firmware ISA mask describes available extensions; code generation still
uses GC unless `wasmtime-discovered-isa` is separately selected.

### wasi-threads

The `threads` crate feature (`wasmtime/custom-threads`, implies `async`) adds
`wasi::threads`: `create_shared_memory`, `linker_threads` with a
`ThreadSpawner`, `define_shared_memory`, and `thread_start`. `enable_threads`
turns on the threads proposal, shared memories and a `wasmtime::ThreadHooks`
implementation supplied by the embedding. `compile_with(.., true)` admits the
wasi-threads contract through the shared structural inspector. Complete threaded
commands may have a Core start section for LLD's shared-data/TLS initialization;
the embedding must instantiate them under its guest execution limits. Other
commands continue to reject Core start sections.

Without `std` a `memory.atomic.wait*` cannot park an OS thread. The vendored
runtime instead records the waiter as a copy-only token in a fixed 16-entry
table per shared memory and suspends the calling guest thread's async fiber;
`memory.atomic.notify` marks waiters and asks the hooks to wake their tokens,
and timeouts poll a hook-supplied timer future. The wait libcalls return to
Cranelift through the same trap sentinel as every other builtin, so dropping a
suspended waiter unwinds the guest like any other cancelled fiber.

Host memories that back a shared memory must never move: the host
`BoundedMemoryCreator` commits a shared memory at its declared maximum. Host
calls on shared memory copy through a per-store scratch buffer across any
await, and `Streams::output_remaining` lets the embedding cap output across
every thread of one command.

```sh
cargo run --locked --offline -p vibeos-wasi-runtime --example fixtures -- target/wasi-fixtures
CARGO_TARGET_DIR="$PWD/target/wasmtime-platform" cargo build --locked \
  --manifest-path wasmtime-runtime/Cargo.toml --features compiler,host-custom,threads --example threads-custom
target/wasmtime-platform/debug/examples/threads-custom [--cap N] target/wasi-fixtures/threads-counter.wasm
python3 scripts/wasmtime/test-wasi-host.py
```

`threads-custom` is a round-robin host driver standing in for the kernel
executor: one Store per guest thread, a spawn cap (default 3), the job-wide
output budget, and the process semantics of the kernel backend. The fixtures
cover atomics, a counter shared by three workers with wait/notify completion,
wait timeouts, `proc_exit` from a worker cancelling a parked main thread, the
spawn cap, `memory.grow` visibility across stores, a worker trap and an
all-threads busy loop ending in fuel exhaustion, plus the two admission
rejections. Cancelling a fiber suspended inside a wait is exercised with
`THREADS_CUSTOM_CANCEL_AFTER=1`.
