# Native JavaScript / TypeScript port: feasibility gate

**Status: M1 V8 feasibility passes on QEMU: real expressions, JS exceptions,
full GC and normal teardown. Official esbuild WASI execution also passes.
Node.js, tsc and tsx commands remain unavailable; the full port is incomplete.**

## Milestones

- **M0 — build baseline and pinned inputs:** complete. Source checksums, offline
  probes, and explicit Rust toolchain selection are implemented. The ordinary
  QEMU WASI image builds and boots; VSH executes an echo command. Network tests
  pass (24), as do WASI tests (22; one external-fixture test intentionally ignored)
  and the Python probe tests (8). This is not V8/Node acceptance.
- **M1 — native platform / V8:** complete for the one-shot feasibility gate.
  Real expressions, exceptions, full GC and normal teardown pass on QEMU with
  the protected native ABI and suspendable bridges. See
  [run 3 evidence](node-runtime-acceptance/v8-first-execution/README.md).
  Production cancellation and repeated Node lifecycle qualification remain M3/M5.
- **M2 — esbuild WASI:** complete. Seven real QEMU transform/denial/lifecycle
  cases pass with memory/fuel evidence; the tsx service adapter remains M4.
- **M3 — Node:** execute CJS/ESM, file/stream/timer operations and cancellation.
- **M4 — TypeScript tools:** run tsc and the adapted upstream tsx entirely on
  VibeOS, including cross-file TSX/source maps and negative type checks.
- **M5 — qualification:** authority denial/revocation, cancellation, backpressure,
  100-cycle reclamation and the affected regression suites.

Each completed milestone is committed and pushed to the `implement_nodejs`
branch. The full goal stays open until M1–M5 pass their target acceptance.

The intended implementation is real Node.js with its bundled V8/libuv, statically
linked into an opt-in QEMU image. V8 starts in JIT-less mode. Resource access must
remain capability-backed. The first release targets offline projects, not npm
installation, networking, child processes, user workers or native addons. A port
of the upstream tsx loader/transform code may adapt its launch and esbuild backend.

## Added tooling

`tools/node-runtime/sources.lock.json` pins the initial feasibility inputs:

| Input | Version | Provenance |
| --- | --- | --- |
| Node.js | 24.14.0 | Release commit `f657bb8ed86365ff3fdbe32e27563e778b41486a`, official source archive SHA-256 |
| Bundled V8 | 13.6.233.17 | From the verified Node.js source archive |
| TypeScript | 5.9.3 | Official npm package SHA-512 integrity and source commit |
| tsx | 4.19.3 | Official npm package SHA-512 integrity and source commit |
| esbuild WASI Preview 1 | 0.25.0 | Official npm package integrity, archive SHA-256 and module SHA-256 |

This is a lock for the feasibility inputs, **not** a complete transitive dependency
lock. The tsx dependency tree still needs qualification. Node's V8/libuv sources
are already included in the verified source archive. A separate
`tools/node-runtime/toolchain.lock.json` pins xPack RISC-V GCC 14.2.0-3, including
newlib and static libstdc++, against its upstream release checksums.

```sh
python3 scripts/prepare-node-toolchain.py --offline
```

Omit `--offline` to download the pinned archive. The preparation script verifies
the archive before extracting and records the compiler identity and RV64GC/LP64D
libstdc++ checksum in `target/node-runtime/toolchain/prepared.json`. The V8 public
headers now compile with this toolchain. This is not a linked V8 runtime: compiling
the real V8 mutex implementation still requires the VibeOS semaphore/platform
backend, which upstream does not supply.

With Python 3.12+, the repository's pinned Rust toolchain, and LLVM Clang:

```sh
python3 scripts/node-runtime.py fetch
python3 scripts/node-runtime.py fetch --offline
python3 scripts/node-runtime.py probe --cxx /path/to/llvm/bin/clang++
python3 -m unittest discover -s scripts/tests -p test_node_runtime.py
```

For the prepared bare-metal compiler, use `probe --cxx-kind gcc --cxx
/absolute/path/to/riscv-none-elf-g++`. The admission probe selects `esbuild-wasi`
by default; `--wasi-profile python-wasi` reproduces the smaller profile's denial.

`fetch --only node esbuild` prepares just the probe inputs. Fetching never runs
package lifecycle scripts. Existing archives are reverified, partial downloads
cannot replace verified files, and corrupt cached inputs are rejected rather than
silently replaced. The probe is offline, extracts clean checksum-verified source
trees, and refuses archive links and traversal. All generated files stay under
`target/node-runtime` (or another explicitly selected subdirectory of `target`).

Each probe writes a new `probe-*` evidence directory containing commands, exit
codes, stdout/stderr, compiler version, repository identity, source checksums and
`results.json`. Nonzero prerequisite results produce a nonzero probe exit. Even
if prerequisites eventually pass, the result is only `PREREQUISITES_ONLY`:
`runtime_acceptance` and `qemu_execution` remain `NOT_RUN`.

The Rust admission probe builds the existing WASI runtime unchanged in a separate
host workspace, seeded from the repository lockfile. It reports imports, module
size, memory declarations and the real `WasiInvocation::new` result. It does not
execute the module, compile TypeScript on the host, or replace target acceptance.
The exact resulting host lockfile is saved with the evidence.

## Reproduce the native V8 execution gate

After fetching locked inputs and preparing the pinned cross-toolchain, use fresh
work directories. The current build supports Linux x64 or macOS with x64 host
tool execution; host generators build the static RV64 snapshot and builtins.

```sh
python3 scripts/build-v8.py prepare --work target/v8-port
python3 scripts/build-v8.py configure --work target/v8-port
python3 scripts/build-v8.py engine --work target/v8-port --jobs 4
python3 scripts/check-v8-firmware-link.py --gate \
  --source target/v8-port/source/node-v24.14.0 --work target/v8-link
python3 scripts/test-v8-gate-qemu.py \
  --kernel target/v8-link/v8-gate.elf --work target/v8-execution
```

The link helper selects `node-runtime`, RV64GC/LP64D and the pinned static
runtime. This profile boots the one-shot smoke entry with 1 GiB RAM; it is not
yet an interactive Node command image. The default image retains 128 MiB RAM
and does not link V8. The execution harness requires every runtime marker,
normal QEMU shutdown and no fatal trap; build success alone cannot pass it.

## Historical implementation notes

The notes below retain the sequence of prerequisite checks and failed attempts.
Their pending statements describe the stage at which they were recorded; the
milestone status and linked execution evidence above describe current status.

### Initial observations and disposition

The initial probe ran against repository commit
`9d50dda4da1f137b756bb46d0297942a39defb5b` using Homebrew Clang 22.1.8.

1. **Workspace resolution was broken; the ordinary baseline is now restored.** After initializing
   `vendor/smoltcp` at the repository-pinned commit
   `3a7827a10d6c8a16afbfafb533f9acf7f2bac24c`, `cargo metadata --locked --offline`
   exits 101. `components/net-protocol` references `smoltcp/tcp-buffer-exchange`
   and `smoltcp/tcp-gro-receive`, neither of which exists at that commit. This
   prevented source-bound firmware builds before any JavaScript changes. The
   invalid Cargo feature forwarding has been removed, and selecting either
   unavailable experiment now triggers an explicit compile error instead.
   Ordinary configurations resolve and build; these experimental paths are not
   silently enabled or claimed to work. Restoring them requires the actual
   matching fork implementation and its feature forwarding.
2. **A native V8/Node platform is still required.** Upstream Node configure exits
   2 for `--dest-os=vibeos`. The RV64GC/LP64D C++20 V8 header probe exits 1:
   the installed Darwin libc++ configuration reports `No thread API` and vendor
   availability errors. This is evidence that this toolchain invocation is not
   a usable VibeOS C++ platform, not evidence that V8 cannot be ported. A target
   C/C++ runtime, V8 platform and libuv backend remain implementation work;
   defining Linux macros would not provide them. `--sysroot` allows a future
   qualified target sysroot to be tested without importing host headers by hand.
3. **The official esbuild module initially failed WASI admission.** Its exact size
   is 18,166,737 bytes, above the Python/WASI profile's 16,777,216-byte maximum.
   The runtime's conservative allocation estimate is 581,597,728 bytes, above
   that profile's 536,870,912-byte limit. The observed result is `Limit`, before
   guest execution. The module declares 7,617 functions and an initial 354-page
   memory (23,199,744 bytes); the ordinary 16 MiB memory profile is also too small.

The opt-in `esbuild-wasi` profile now admits and executes this exact upstream
artifact. It uses 1 GiB QEMU RAM, a 24 MiB module ceiling, 128 MiB linear memory,
a 768 MiB owner quota and a fixed 262,144-fuel poll quantum. Go's module contains
100,000 data segments and deeply nested functions; only this profile raises the
corresponding declaration limits. Duplicate imports are linked once while every
import signature is still validated. Default and Python ceilings are unchanged.

The module imports `random_get`, `poll_oneoff` and filesystem operations, among
others. The selected stdin-to-stdout transforms work with the existing granted
clock/stdio services. Unsupported imports continue to return explicit errors;
this does not provide arbitrary Go/WASI filesystem or service compatibility.

## esbuild target gate

```sh
python3 scripts/test-esbuild-qemu.py --work target/esbuild-qemu-new-run
```

The harness verifies the official module checksum, builds and freezes a kernel,
boots a fresh QEMU disk, uploads the module over the explicit test SSH profile,
and executes version, TS, TSX/custom factory, inline source map, syntax error,
denied ambient file write and repeat invocation cases. Successful invocations
must match compiler output and exit codes; all seven must reclaim their arena,
capabilities and waiters. Logs and per-case results stay in the fresh work
directory. The harness never replaces an existing evidence directory.

`target/esbuild-qemu-qualified-1/results.json` records the first seven-case pass:
12.4–13.5 seconds per invocation including SSH, loading, validation and execution.
This establishes standalone esbuild transforms, not Node, tsx or TypeScript type
checking. The patched tsx synchronous/asynchronous service channel is still M4.

The telemetry repeat is checked in under
[`docs/node-runtime-acceptance/esbuild-qemu`](node-runtime-acceptance/esbuild-qemu/results.json),
including raw QEMU logs and compiler input/output. Its kernel SHA-256 is
`5f404c0bd4ffe271eecf833061cb565b2b308c75f45e043d045318c64e912d49`.
All seven invocations reclaimed their arena, capabilities and waiters. Peak
invocation-owner allocation was 96,524,160 bytes (92.05 MiB); this excludes SYSTEM
transport, uploaded source and unrelated kernel allocations. The second run took
14.1–17.6 seconds per invocation while a host regression build ran concurrently;
these are functional timings, not an isolated performance benchmark.

The unchanged ordinary 128 MiB/four-hart image also rebuilds, boots, and executes
a VSH echo. Default/Python/esbuild host runtime suites pass, including declaration
ceiling rejection and repeated-import type validation. Network, SSH and command
service regressions pass (50 tests). Full file/VSH/MMU and 100-cycle Node
qualification remain M5. The evidence records the pre-commit base and hashes of
changed runtime inputs; the tested kernel was frozen before execution.

## Remaining implementation and acceptance

### Native V8 build work in progress

`scripts/build-v8.py` applies the checked-in patches to the checksum-verified
Node archive, copies the C ABI headers, and separates host generators from RV64GC
target objects. It supports these explicit phases:

```sh
python3 scripts/build-v8.py prepare --work target/node-runtime/native-new
python3 scripts/build-v8.py configure --work target/node-runtime/native-new
python3 scripts/build-v8.py base --work target/node-runtime/native-new
python3 scripts/build-v8.py snapshot --work target/node-runtime/native-new
python3 scripts/build-v8.py engine --work target/node-runtime/native-new
```

Preparation is offline and requires the source archive and prepared compiler.
Changed patch/header inputs require a fresh work directory. The host compiler
version, target compiler identity and commands are retained per phase. On macOS,
host generators use x64/Rosetta because this V8 revision supports RV64 simulation
on x64 hosts; all target compilation uses the pinned bare-metal compiler.

The VibeOS configure path and host/target `libbase` archives have been built from
a freshly prepared source tree. The inspected target object is ELF64 RISC-V with
the double-float ABI. Semaphore, once-initialization waits and clocks now call
explicit C ABI bridge functions. **Those Rust bridge functions are not implemented
yet.** The archive build therefore does not prove that V8 links or executes.

The full host snapshot-generator build exposed unguarded RISC-V SIMD selectors
when WebAssembly is disabled. The second patch adds the matching WebAssembly
guards; target Abseil compilation also exposed a non-mmap poison-pointer build
error. Further target synchronization, memory, TLS and C/C++ runtime adaptation
is still required. No QEMU V8 or Node runtime acceptance is recorded here, and
M1 remains open.

The target sampler now has an inactive platform-data object without POSIX signal
handles. Starting CPU sampling or requesting a direct sample reports an explicit
fatal unsupported operation; the launcher must reject profiling options before
those internal V8 APIs are called. This permits ordinary non-profiling engine
construction without falsely claiming that samples are collected. Both host and
RV64 target sampler translation units compile; engine linking and QEMU execution
remain unverified.

The target time-platform adapter now compiles with the generated libbase flags.
It routes V8 wall time through `Time::Now`, positive sleep intervals through a
suspendable deadline wait, and thread identity through the native task bridge.
These bridge declarations still need kernel implementations and target execution
validation; the standalone object check is not sleep or clock acceptance.

The kernel now keeps registered physical hart identities independently of `tp`,
using the logical index in `sscratch`. This leaves `tp` available for a native
execution-context pointer used by the compiler TLS bridge. The opt-in `native-runtime-probe` feature changes `tp` across a real
Rust call, restores it, and verifies both identities on every hart. Build the
QEMU firmware with `wasi-ssh-upload,native-runtime-probe`, then run:

```sh
python3 scripts/test-native-tls-qemu.py --work target/native-tls-qemu
```

The four-hart, 128 MiB QEMU probe and VSH echo passed; core/RISC-V host library
tests also passed. The harness records the kernel hash, source hashes and serial
log. This checks identity only, not native TLS allocation/destructors, FPU state,
trap recovery, or V8 execution. Abseil native wait/clock adapters still need the
Rust execution bridge; target POSIX debugging and timezone dependencies remain
under investigation.

Patches 0005/0006 subsequently disabled unavailable POSIX diagnostic facilities
and adapted cctz to newlib timezone rules. A fresh `native-qualified-2` source
preparation, configure and `support` phase built both host and target Abseil
archives. The initial mutex adapter in that build was then replaced with a
handle-free predicate-wait mutex, because cctz retains it for process lifetime.
The updated adapter passed a host test with four parked contenders, 40,000
protected increments and zero remaining waiters; this is an adapter unit test,
not target scheduler acceptance. Its timezone translation unit also has a
separate RV64GC/LP64D compilation check. A complete engine build and QEMU V8
expression/exception/GC execution remain outstanding.

The target-only `tools/node-runtime/tests/v8-smoke.cc` entry point now compiles
with the generated V8 target library's exact ABI definitions. It selects
jitless/single-threaded mode, requires granted entropy, checks `6 * 7`, catches
a JavaScript `Error`, requires an actual full-GC callback, then disposes the
isolate and process-global V8. The `smoke` build phase produces an object only;
linking the platform bridge and invoking it in QEMU are still required. No
runtime PASS is inferred from this compile check.
The host and RISC-V `v8_libplatform` archives also compile successfully on the
qualified source tree. The `support` phase now builds both Abseil and this
platform library. Its single-threaded default platform is used by the smoke
entry; the underlying VibeOS OS and execution bridges still require linking
and target validation.

The `native-call-probe` firmware feature now exercises a normal-return LP64D
entry on a guarded 256 KiB RW/NX stack. Shared trap/fiber mappings are selected
by `native-stacks`, which `wasmtime-async` also enables. Four QEMU call/return
cycles verified stack bounds, guard mappings, NX, temporary TLS, floating-point
arithmetic, host FCSR/TLS restoration, and mapping removal after normal return.
The evidence is in `docs/node-runtime-acceptance/native-call`. This probe is a
Rust C-ABI callback; C++ destructors, resumable execution and cancellation are
not yet tested. It neither registers a forced-jump recovery hook nor frees a
stack while native frames remain active. Run it after building the LP64D image:

```sh
python3 scripts/test-native-tls-qemu.py --native-call \
  --kernel target/riscv64gc-unknown-none-elf/release/vibeos-qemu-virt \
  --work target/native-call-qemu
```

The IMAC four-hart/VSH regression also passed after extracting `native-stacks`,
and the Wasmtime async LP64D configuration passed `cargo check` (not a Wasmtime
execution regression). The host snapshot build exposed a separate GYP rebuild
bug: it invoked Node configure with GYP arguments and reset the selected
features. That run was stopped and excluded. Patch 0008 routes regeneration to
the GYP driver; a forced regeneration preserved the configuration hash and
confirmed ICU, WebAssembly, pointer compression and sandbox remained disabled.

The native context switch now has QEMU evidence for three yields/four resumes,
with stack objects and TLS/FCSR preserved. A separate `native-cxx-probe` feature
cross-compiles and links a real C++ RAII fixture: C++ and Rust destructor counts
remain zero during suspension and become exactly one on normal return, before
the protected stack is unmapped. See `docs/node-runtime-acceptance/native-cxx`
for source/compiler/kernel identities and serial logs. The fixture deliberately
does not link libstdc++ or use C++ exceptions, so this does not qualify the full
static runtime TCB. Executor parking, cancellation, V8/Node and the 100-cycle
test remain open. Use the LP64D build with
`wasi-ssh-upload,native-runtime-probe,native-cxx-probe`, then:

```sh
python3 scripts/test-native-tls-qemu.py --native-cxx \
  --kernel target/riscv64gc-unknown-none-elf/release/vibeos-qemu-virt \
  --work target/native-cxx-qemu
```

The same fixture now also runs as a fixed-hart executor task. Three native
yields wait on real executor timers, while a second task on the same hart must
make progress during each wait. QEMU passes this parking check, final C++
destruction and stack unmapping; evidence is in
`docs/node-runtime-acceptance/native-park`. Cleanup can drain this known finite
fixture only; it is not a cancellation implementation for arbitrary V8 code.

The host `mksnapshot` executable has now linked successfully in the incremental
development tree with the validated lite/no-Wasm/no-ICU configuration. Its
artifact and configuration hashes are recorded under
`target/node-runtime/native-mksnapshot-result.json`. Target embedded builtins
and engine archives are the next build step; host-tool success remains outside
the required QEMU V8 execution gate.

The target V8 memory adapter now compiles with the generated libbase flags.
It rejects executable data-page requests, validates page geometry, forwards
actual page operations to an ownership-checking native ABI, and explicitly
declines shared mappings and large VA reservations. V8's static flag block
requires a separate registered-image read-only operation, rather than treating
it as invocation heap memory. The Rust page bridge is not implemented yet;
the adapter is not linked into the running QEMU probe and no MMU acceptance is
claimed for it. Patch 0009 integrates it into future prepared target builds;
the memory adapter was subsequently added to the development build after the
previous compiler process terminated.

Rust `NativePages` now owns eager, aligned, zeroed heap backing and per-page
permissions. Its MMU operation validates every old PTE before mutation and
uses the existing break-before-make/TLB synchronization machinery. The QEMU
probe checks live RO/inaccessible/RW-NX mappings, rejects mismatched and invalid
ranges without partial changes, and restores allocator access on destruction;
see `docs/node-runtime-acceptance/native-pages`. The C ABI invocation/handle
registry, partial release and static-image data registration remain to be
implemented. Discard/decommit now validate the whole range before clearing,
preserve discard permissions, and guarantee zeros after decommit/recommit.
QEMU covers mixed permissions, byte contents, unaffected neighboring pages and
rejection before mutation; see `docs/node-runtime-acceptance/native-pages-clear`. This evidence is not a V8 execution or a prohibited
access/fault-injection test.

V8's RISC-V cache flush now uses a native C ABI bridge instead of Linux syscall
headers. The bridge performs the existing local/SBI all-hart instruction-cache
synchronization and cannot return success after an SBI failure. A real C++ call
passes in four-hart QEMU and increases the completed remote-fence counter;
see `docs/node-runtime-acceptance/native-cache`. This does not demonstrate
execution of changed instructions or V8 itself.

A second GYP regeneration defect was found: preserving `config.gypi` alone did
not preserve the generator flavor. Patch 0008 now passes `-fmake-vibeos` during
regeneration. Two consecutive forced regenerations preserve both configuration
and generated host/target libbase makefiles byte-for-byte; evidence is in
`target/node-runtime/native-regeneration-flavor.json`. Build validation now
also checks C++20, target RV64GC/LP64D/medany flags and the regeneration flavor.
The active engine build now includes the memory/time overlays (0009/0011).

The pinned bare-metal GCC was verified to emit emutls rather than ELF TLS
relocations. The Rust `__emutls_get_address` bridge now keeps values per admitted
context, honoring descriptor initialization and alignment without writing a
process-global value into the shared descriptor. Real C++ trivial thread-local
values pass QEMU isolation across two live contexts and five normal-return
calls; see `docs/node-runtime-acceptance/native-cxx-emutls`. A subsequent QEMU run also preserves those TLS values across three actual
executor timer waits while a same-hart peer progresses; see
`docs/node-runtime-acceptance/native-cxx-tls-park`. Execution registration is
released while parked, but the pinned owner retains the TLS storage until
normal completion. Compiler-generated dynamic TLS initialization and explicit LIFO thread-exit
destructors now also pass QEMU, including TLS reads from destructors after
normal C++ stack unwinding; see `docs/node-runtime-acceptance/native-tls-destructors`.
Full static C/C++ runtime integration and resource admission remain open. No firmware linker change was needed for emutls.

The execution context now registers its usable native stack bounds. Its C ABI
checks the actual native sp and returns those bounds to C++; QEMU validates a
real local variable inside the range during TLS calls and after resumption.
The separately compiled V8 stack adapter uses this bridge and frame-address
queries. The initial overly strict frame/CFA bound check and its corrected
passing run are retained in `docs/node-runtime-acceptance/native-stack-bounds`.
This remains a prerequisite, not V8 stack scanning or GC acceptance.

The target libplatform archive references V8's Thread constructor, destructor,
Start and Join even though the selected runtime platform is single-threaded.
The target adapter now compiles those lifecycle methods: starts fail explicitly
with ENOTSUP, synchronous-start handles are released on failure, and invalid
joins fail fatally. This is the first-version background-thread boundary, not
an implementation of workers or key-based TLS. Patches 0013/0014 apply together
in order but are not yet added to the currently running engine build.

The target `libv8_base_without_compiler.a` has now been generated. An archive-level
undefined-symbol comparison against the current target libbase/libplatform,
compiler and Abseil archives is recorded in
`target/node-runtime/native-platform-symbol-audit.json`. It confirms remaining
OS lifecycle, stdio/path, timezone, process identity and Rust memory/synchronization
bridge dependencies. Stack/thread methods have separately compiled adapters,
awaiting integration after the running build. This audit includes references
that a final link may discard and hashes thin archive indexes, not all members;
it is not a successful link or execution gate.

The buffer-formatting adapter also compiles for RV64 and preserves the upstream
formatting truncation and strncpy behavior. Patch 0015 remains outside the
running engine build; this is a compile check, not target C-library acceptance.

The development engine build completed successfully with unchanged validated
configuration (1622.4 seconds). The real host mksnapshot generated snapshot.cc
and embedded.S, which were compiled into the RV64 snapshot archive. Results
are in `target/node-runtime/native-engine-build-4.json`; execution is NOT_RUN.
A subsequent diagnostic executable link, without the kernel bridge or final
firmware layout, failed with 84 distinct unresolved symbols. Its retained-symbol
list and command are in `target/node-runtime/v8-link-audit-2.json`. The pinned
toolchain has no separate libgcc_eh/libatomic archives; omitting those names
allowed the diagnostic link to expose actual dependencies rather than stopping
at missing library files. No fallback runtime was treated as qualified.

The engine phase now also requests v8_zlib, simdutf and highway, which were not
built by the earlier target list. Those support libraries now build successfully, and
patches 0013–0015 are integrated in the target libbase archive. Configuration
validation still passes; the next diagnostic link is recorded in
`target/node-runtime/v8-link-audit-3.json`. Further
Abseil low-level allocation, graph-cycle and per-thread semaphore definitions,
OS methods and kernel bridges remain unresolved. This is not a passing link,
QEMU V8 execution or completed M1.

The Abseil link failures were caused by ABSL_LOW_LEVEL_ALLOC_MISSING, which
excluded the allocator and dependent thread-identity/semaphore/graph-cycle
implementations. Patch 0016 retains the upstream arena algorithm and supplies
an explicit TCB page-allocation/release ABI instead of mmap. Async-signal-safe
allocation remains disabled. Host and target Abseil archives build successfully;
the diagnostic link now has 62 unresolved symbols, resolving 13 previous
Abseil symbols while adding the two real TCB page backend requirements.
See `target/node-runtime/v8-link-audit-4.json`. The TCB page backend must own
process-lifetime arenas separately from invocation heaps, support coalesced
release ranges and account for their retained memory. It is not implemented
yet; no fake mmap or successful no-op release is supplied. Dependent engine
objects/snapshots still require a build refresh after this header change.

The TCB page backend now implements its C ABI with a separate 64 MiB heap owner
and 128 allocation records. Both backing and metadata use that owner. Release
validates complete original-allocation coverage before restoring permissions
and freeing the original layouts. A real C++ QEMU probe passes zero-fill,
partial/oversized/repeated-release rejection, data preservation and owner
live-byte/allocation reclamation; see `docs/node-runtime-acceptance/native-tcb-pages`.
Actual Abseil arena execution, quota exhaustion and successful multi-block
coalescing remain unqualified. The engine refresh is still running.

Provide the target C/C++ platform on the restored firmware baseline. Then
implement and verify the V8 expression/exception/GC gate,
including ABI, floating-point state, protected stack and cancellation handling.
The independent esbuild transform gate is qualified. Preserve the existing
default and Python profiles when adding the Node-to-WASI service bridge.

Only after these gates pass, add the capability-native Node invocation context,
libuv file/stream/timer adapters, virtual project/tool roots, and VSH commands:

```text
node --root @home/project main.js
node --root @home/project -e "console.log(1 + 2)"
tsc --root @home/project -p tsconfig.json
tsx --root @home/project src/main.ts
tsx --root @home/project src/view.tsx
```

These are the planned interfaces, **not available commands**. Subsequent gates
must cover CJS/ESM, actual tsc diagnostics and emission, TSX conversion and source
maps, cross-file imports, denied traversal/writes, revocation, cancellation,
backpressure and 100-cycle resource reclamation. Neither a successful header
compile nor host admission is a substitute for those tests.

Upstream sources: [Node.js release checksums](https://nodejs.org/dist/v24.14.0/SHASUMS256.txt),
[tsx package](https://www.npmjs.com/package/tsx/v/4.19.3),
[TypeScript package](https://www.npmjs.com/package/typescript/v/5.9.3),
[esbuild WASI package](https://www.npmjs.com/package/@esbuild/wasi-preview1/v/0.25.0).

### Native clock bridge (direct ABI qualified)

`native_clock.rs` exposes the V8 microsecond clock ABI through the existing
WASI clock source. Both callers share the QEMU RTC latch lock; monotonic time
uses the SBI counter and configured timebase. Unsupported clocks return -1,
without substituting uptime for Unix time. Calls require an active native TLS
context. The C++ fixture checks positive realtime and nondecreasing monotonic
and realtime readings across its native suspension points. This is a platform
prerequisite, not V8 or Node execution acceptance. The four-hart QEMU fixture
passed; see `node-runtime-acceptance/native-clock/` for logs and exact hashes.

### V8 diagnostic output adapter

The target stdio adapter compiles with the generated V8 target configuration.
Adding it to the diagnostic executable link resolves eight previously missing
OS symbols (62 unresolved to 54). The link still fails, as expected, pending
remaining kernel/newlib and V8 platform bridges. `FOpen` and temporary-file
support remain unresolved, rather than opening an unscoped filesystem.
Patch 0017 passes a zero-fuzz dry run. The currently running engine refresh
predates this patch; integrate it after that process terminates. No runtime
acceptance follows from this compilation/link audit.

### V8 timezone adapter (compile/link evidence only)

The newlib-backed cache compiles with the generated RV64GC/LP64D V8 flags.
The diagnostic link now has 53 unresolved symbols, resolving
`OS::CreateTimezoneCache` without introducing a new unresolved symbol.
Patch 0018 applies without fuzz after 0017 on a temporary copy of the active
GYP file; the live engine build was not modified. Evidence is in
`target/node-runtime/native-timezone-compile.json` and
`target/node-runtime/v8-link-audit-timezone.json`.

Runtime qualification must still cover UTC, positive/negative standard offsets,
half-hour/negative DST, invalid dates, and repeated invocation TZ changes.
The cache uses process-global newlib TZ state under the planned single-active
Node constraint; invocation environment setup/reset is not implemented yet.
This does not qualify V8 Date behavior or the V8 execution milestone.

### V8 lifecycle adapter (compile/link evidence only)

The lifecycle adapter preserves V8 abort-mode selection, RV64's 16-byte frame
alignment, real `ebreak` debug traps, and the upstream flush-then-`_exit` path.
It enumerates no shared libraries because native code is statically linked.
No external profiler or process-priority service exists in the first port.
V8's default Linux profiler filename is ignored without accessing a file.

Target compilation passed. Adding the object to the diagnostic link reduced
unresolved symbols from 53 to 45 with no new unresolved symbols. Patches
0017–0019 applied sequentially with zero fuzz on a temporary GYP copy; they
are not yet applied to the active engine build. Evidence:
`target/node-runtime/native-lifecycle-compile.json` and
`target/node-runtime/v8-link-audit-lifecycle.json`.

The kernel `_exit` backend remains missing and must terminate the trusted
image, not masquerade as safe instance reclamation. Normal completion must
return through the native runner. Fatal/OOM behavior still requires separate
QEMU qualification and is not proven by these link results.

### Native task identity bridge (direct ABI qualified)

Native TLS contexts now receive monotonically allocated positive 32-bit IDs.
`vibeos_native_thread_id` verifies the current admitted context and returns its
stable ID, independently of physical/logical hart IDs and the TLS allocation
address. Exhaustion fails explicitly instead of wrapping/reusing an identity.
The C++ fixture retains the first ID in real emulated TLS and checks it on
each subsequent entry/resume; the Rust fixture checks distinct contexts have
distinct positive IDs. This supplies the identity bridge used by V8's platform
time/thread adapter, without enabling background threads. The four-hart QEMU
fixture passed; evidence is in `node-runtime-acceptance/native-task-id/`.

The memory audit also confirmed that ordinary heap realloc may relocate a
shrunk allocation. It cannot implement V8's address-stable partial tail release
(`PageAllocator::ReleasePages`). The page bridge still needs a distinct
allocation/reclamation strategy before it can safely expose that operation.

### V8 stack diagnostics (walker prerequisite qualified)

Patch 0020 supplies V8's stack-trace constructor and output methods. The walker
uses the admitted stack bounds and RV64 frame records; it rejects unaligned,
out-of-range and non-increasing frame links and respects the output capacity.
It reports raw return addresses, not symbol names, and cannot promise complete
traces through frame-pointer-omitting code or tail calls. Signal-based stack
dumping returns false/ENOTSUP; this is not a Unix signal emulation layer.

Compilation and diagnostic linking resolve five missing methods (45 to 40
remaining). Patches 0017–0020 apply sequentially without fuzz on a temporary
copy of the active GYP file. The actual engine build still predates them.
The C++ fixture exercises the same walker on its native stack and invalid
frame/capacity inputs; the four-hart QEMU test passed. Logs and hashes are in
`node-runtime-acceptance/native-backtrace/`. The V8 methods themselves have not
yet executed in QEMU.

### Address-stable native page pool (helper qualified)

`native_page_pool.rs` adds an owned pool over real `NativePages` backing.
Each allocation receives a nonzero identity recorded outside the protected
pages. A range operation validates page alignment, bounds, and a single live
allocation identity before changing mappings. Releasing a tail clears it,
makes it inaccessible, and immediately returns those pages to the pool; it
does not move the retained prefix. Reallocation recommits zero-filled NX pages.
Backing is retained by the pool until pool destruction, when `NativePages`
restores allocator access and returns the original allocation to the heap.

The probe checks exact tail-address reuse, preserved prefix bytes, zeroed
reused bytes, denied double free and access to freed pages, rejection of a
range crossing two allocations, decommit/recommit, and ordinary pool drop.
This is the memory-management prerequisite only. Invocation-specific pool
admission, quota sizing/accounting, revocation, the V8 C ABI registry and
static-image read-only protection are still pending. Released subranges return
to the pool, not individually to the global heap; accounting must reflect the
pool's still-reserved backing rather than claiming it has been deallocated.

The page-pool helper passed four-hart QEMU execution; exact logs and hashes
are in `node-runtime-acceptance/native-page-pool/`.

### Per-context native memory C ABI (direct ABI qualified)

`NativeTls` now accepts an explicit page-pool capacity and owns `NativeMemory`.
The seven page allocation/protection/clear/release/hint exports operate only
on the admitted current context. A lazily created heap owner bounds reserved
pool backing and metadata (four times visible capacity to cover allocator
rounding); page operations additionally enforce the visible capacity and
allocation identity. The test fixture uses a 1 MiB capacity, not a production
V8 memory limit. No owner scope spans suspension.

Revocation denies further public memory operations, while normal context
destruction reclaims the backing, asserts owner live bytes/allocations are
zero, and unregisters the owner. Optional address hints return null and their
seed does not affect entropy. Static-image read-only protection remains a
separate unimplemented ABI. Full invocation capability admission and limits,
as well as real V8 workloads, are not yet qualified.

The memory C ABI passed four-hart QEMU execution, including cross-context
denial and revocation followed by accounted cleanup. Evidence is in
`node-runtime-acceptance/native-memory/`. Revocation here denies bridge calls;
it does not itself unmap all outstanding pointers or terminate native frames.

### Static-image flag freeze (bridge qualified)

The QEMU linker now declares a page-exclusive V8 flag section with exact start
and end symbols. `vibeos_native_static_readonly` accepts only that complete,
nonempty extent, validates every old PTE before changes, and publishes RO/NX
with local/remote TLB synchronization. The heap page API cannot admit this
section, so it cannot thaw/free it. Repeated freeze calls are idempotent.

A probe page passed four-hart QEMU checks; evidence is in
`node-runtime-acceptance/native-flags/`. The actual V8 flag object separately
cross-compiled into a 4096-byte, 4096-aligned section. Patch 0021 has not yet
been applied to the live engine build; real V8 initialization remains untested.
The production V8 feature must exclude the probe-only flag object currently
enabled by `native-cxx-probe`. No deliberate write-fault test is claimed.

### Integrated V8 platform build through patch 0021

The earlier per-adapter entries describing patches 0017–0021 as not integrated
are historical. The active target source now contains all these patches and
byte-identical platform overlays. Engine/snapshot/support rebuilding succeeded
with an unchanged configuration hash and valid generated target/host flags.
The diagnostic link using integrated archives (no standalone adapter objects)
still reports 40 unresolved symbols, including kernel exports omitted from
that audit and missing runtime interfaces. Evidence is in
`node-runtime-acceptance/v8-platform-build/`. Real firmware linking and QEMU
V8 expression/exception/GC execution remain outstanding.

### First V8/Rust firmware link diagnostic

`scripts/check-v8-firmware-link.py` forces the actual V8 smoke entry into the
fixture firmware's native link. The kernel bridges resolve, leaving 25 missing
interfaces; lld also reports 3088 exception-table relocations into discarded
sections. See `node-runtime-acceptance/v8-firmware-link/` for the command and
failure classification. This is stronger integration evidence than the
standalone library link, but the link still fails and no V8 execution occurred.
The diagnostic is deliberately not a runnable acceptance image.

### C++ default-option correction

The first firmware link exposed V8-generated `.gcc_except_table` relocations.
Inspection showed that the new target inherited C++20 but omitted upstream
Unix defaults `-fno-exceptions`, `-fno-rtti`, and `-fno-strict-aliasing`.
Patch 0022 restores these for the target only. Generated makefiles confirm
all V8 engine/support targets receive them; Torque's explicit `-fexceptions`
override remains intact. Build validation now rejects regression of these
flags. A full affected-target rebuild is running in
`target/node-runtime/native-engine-build-7.log`.

This is a verified configuration correction, not yet proof that all firmware
link errors are fixed. Pinned libstdc++ exception/unwind behavior and the
remaining missing runtime bridges still need integration verification.

### Native notification registration (scheduler primitive qualified)

`native_notify.rs` provides one registered wait per invocation, with a generation
counter and executor Waker. Register-before-predicate-recheck lets the future
observe a wake arriving before its first poll. Polling installs a Waker under
the same lock used to advance the generation; signaling wakes outside the
lock. Dropping a wait removes its registration, and concurrent wait admission
is rejected. Counters fail on exhaustion instead of silently wrapping.

This is a scheduler-side synchronization prerequisite. It does not yet implement
the C ABI wait/semaphore functions, timeout dispatch, or cancellation of active
C++ frames. Its Rust probe tests early notification, actual timer-delayed peer
notification, exclusive admission and cancelled-registration cleanup.

The notification primitive passed four-hart QEMU execution. Exact logs and
hashes are in `node-runtime-acceptance/native-notify/`; this is not yet the
C++ wait bridge or its timeout/cancellation qualification.

### Native wait C ABI and suspended-future bridge (timed path qualified)

The protected-stack runner now lends a pinned Rust future on its retained
native stack to the executor. A type-erased poll function runs only while the
native stack is parked; the pending request is cleared before native execution
resumes and destroys that future normally. TLS and floating-point context use
the existing RISC-V swap boundary. Predicate callbacks run on the native stack,
never on the scheduler stack.

The timed/untimed wait and wake C ABI now register before predicate checks,
recheck readiness and the original monotonic deadline after wakes, and use
executor notification/timer futures without polling loops. Missing suspension
hooks fail explicitly for waits that actually need to park. Timer durations
round up to milliseconds. Each context permits only one admitted wait.

This initial runner supports normal completion only. Dropping an active runner
is explicitly fatal under this firmware's aborting panic policy; it does not
pretend to unwind C++ frames or reclaim them safely. Cooperative V8 termination
and ownership-preserving cancellation remain mandatory before VSH exposure.
Semaphore handles and external backend wake routing are not implemented yet.

The real C++ timed-wait path passed four-hart QEMU, including same-hart peer
progress, retained guards, ordinary destructor return and stable native ID.
Evidence is in `node-runtime-acceptance/native-wait/`; arbitrary cancellation,
external readiness wake routing and real V8 execution remain unqualified.

### Native semaphore handles (basic C ABI qualified)

The semaphore C ABI now uses per-context handle tables, with monotonically
allocated opaque IDs that are never dereferenced. Up to 256 live handles are
admitted per context. Initial negative counts and signed-count overflow are
rejected. Lookup clones the semaphore before releasing the table borrow, so
waits suspend without retaining a mutable registry borrow. Permit acquisition
uses acquire ordering; posting publishes with release ordering and signals the
context's notifier. A wait holds an Arc until its native frame returns.

Destroying foreign/stale or actively used handles is fatal under the declared
lifecycle contract; ordinary wait/signal operations reject invalid handles.
Remaining unreferenced handles are dropped with their context. This does not
yet route notifications from libuv backends, implement general native
cancellation, or qualify Abseil/V8 semaphore use.

The C++ semaphore fixture passed four-hart QEMU for permit consumption, empty
timeouts with actual parking, posting, stale-handle rejection, and overflow.
Evidence is in `node-runtime-acceptance/native-semaphore/`; cross-context and
post-after-park paths remain to be qualified.

### Semaphore backend posting rights (direct path qualified)

A trusted backend can obtain a one-shot `PostPermit` only by resolving a
semaphore in the currently admitted invocation. The opaque native handle is
never sufficient for a different invocation or a later backend context to
look up another owner's semaphore. The posting right retains the exact
semaphore/notifier until completion, posts with release ordering, and is then
dropped. The existing destruction check prevents freeing a semaphore while
such a posting right is outstanding.

The probe schedules a kernel completion after 2 ms, then C++ waits indefinitely
on the empty semaphore. It verifies exactly one permit is consumed after
resume. Another protected-stack fixture attempts a foreign-context post before
an owner post and destruction. This does not implement cancellation/revocation
of outstanding backend posting rights or libuv service integration.

The backend-post and foreign-context checks passed four-hart QEMU; evidence
is in `node-runtime-acceptance/native-semaphore-wake/`. The native indefinite
wait parks and resumes on an actual kernel completion, with exactly one permit
consumed. Cancellation/revocation of retained posting rights and libuv
integration remain pending.

### Second V8/Rust firmware link diagnostic

The patch-0022 target rebuild completed successfully in 877.6 seconds. The
follow-up firmware link has no discarded-section relocation errors (previously
3088), and resolves the new wait/semaphore bridges. It still fails with 18
undefined symbols: newlib syscall/aligned-allocation support, entropy and three
V8 platform methods. Exact commands and full output are in
`node-runtime-acceptance/v8-firmware-link-2/`. This does not yet qualify a
runnable firmware, JS exceptions/GC, Node, or any V8 execution milestone.

### V8 file-platform integration

Patch 0023 adds FOpen with the upstream regular-file restriction, tmpfile via
newlib, and stable virtual process identity for the one-thread invocation.
Target libbase builds and the diagnostic firmware link now resolves all V8 OS
methods, leaving 16 runtime symbols (including newly required `_unlink`).
Evidence is in `node-runtime-acceptance/v8-firmware-link-3/`. The capability
syscall backend is still missing; filesystem safety and behavior are not yet
qualified, and no real V8 execution has occurred.

### Capability-granted native entropy bridge

The native context may now receive an explicit entropy grant. Requests acquire
READ leases, suspend through the native runner while the existing queued
entropy service works, and revalidate before copying complete results. Missing
authority, unsupported lengths and service errors return failure without a
partial successful result. There is no timer/PRNG fallback or ambient grant.

The modern virtio-rng QEMU test passed for no-grant denial and a granted 32-byte
request from a protected native stack. Evidence is in
`node-runtime-acceptance/native-entropy/`. The first test command omitted
`virtio-mmio.force-legacy=false`; correcting that transport setting enabled
firmware discovery. Revocation/fault/length-boundary testing and real V8 use
remain pending.

### Native newlib adapter and fourth firmware link diagnostic

Patch 0024 adds `_gettimeofday`, `_getpid`, `_getentropy` and
`posix_memalign` against the pinned newlib ABI. The entropy wrapper stages up to
256 bytes via 64-byte granted service requests, preserving caller storage on
failure. Target compilation and mock host contracts pass. The forced real-V8
firmware link now reports 11 missing syscall symbols (down from 16); heap,
capability files/streams and termination remain incomplete. See
[node-runtime-acceptance/v8-firmware-link-4](node-runtime-acceptance/v8-firmware-link-4/README.md).
This is link diagnostic evidence, not QEMU V8 acceptance or an M1 milestone.

### Bounded newlib heap bridge

`native_libc_heap` now supplies a process-lifetime, separately accounted 16 MiB
sbrk range for the pinned static runtime. The C++ adapter maps exhaustion to
ENOMEM. QEMU verifies signed bounds, trim/regrow clearing, stable break on
failure and RW/NX mappings. The retained physical allocator charge is 33,562,624
bytes; this capacity is not released on invocation teardown. Actual newlib
malloc/free, per-invocation allocation limits and repeat-run reclamation remain
unqualified. Evidence:
[node-runtime-acceptance/native-libc-heap](node-runtime-acceptance/native-libc-heap/README.md).

### Native standard-stream bridge

Native contexts now accept an explicit CommandIo grant. The Rust C ABI for
read/write stages at most 1024 bytes and parks on transport futures; newlib
adapters map negative bridge results to errno. QEMU verifies actual output
backpressure with a registered writer, ordered delivery, stdin/EOF, grant denial
while blocked, unchanged denied-read output and zero retained waiters. The
fixture uses Rust entry points; actual newlib stdio and V8 execution remain
unqualified. VSH/CSpace admission and descriptor metadata/close remain pending.
See [native-stdio evidence](node-runtime-acceptance/native-stdio/README.md).

### Native standard-stream descriptor lifecycle

Standard-stream grants now track closed fds across bridge-operation clones.
QEMU verifies pipe metadata, invalid/repeated close, read/write rejection after
close, and cleanup after grant denial. The newlib adapters implement `_close`,
`_fstat`, `_isatty` and `_lseek` for these pipes, with explicit ESPIPE/ENOTTY
errors. Host mock tests and target compilation pass; actual newlib FILE and
regular-file execution remain pending. See
[native-fd evidence](node-runtime-acceptance/native-fd/README.md).

### Fatal native-image termination

The native fatal-exit backend records its status and requests SBI shutdown;
newlib `_exit` delegates to it, and unsupported signal delivery returns ENOTSUP.
A separate QEMU image proves termination from the protected native stack.
QEMU/OpenSBI returns host status 0 even for native status 42/SBI SYSTEM_FAILURE;
this limitation and the first failed expectation are preserved in
[native-exit evidence](node-runtime-acceptance/native-exit/README.md).
This does not implement normal Node process.exit or cooperative cancellation,
and does not claim destructor execution, instance reclamation or OOM recovery.

### Capability-native unlink

Native unlink now obtains a fresh WRITE invocation lease from the granted
FileTreeRoot capability and commits a real file transaction through the
parking bridge. QEMU verifies missing/readonly/revoked authority, parent escape,
directory protection and successful deletion. The newlib adapter compiles for
the target and passes mock errno tests. Active leases retain the existing
CSpace admission semantics; mid-commit revocation and durable publication still
need qualification. See [native-unlink evidence](node-runtime-acceptance/native-unlink/README.md).
This does not yet supply open/read/write file descriptors or V8 execution.

### Native read-only file descriptors

The capability-backed open path now creates bounded per-context read-only file
descriptors. Read, seek and metadata recheck authority; reads stage up to 1024
bytes and revalidate before delivery. QEMU verifies content across file chunks,
EOF, seek, close, stale handles and revocation. Newlib `_open` and regular-file
stat/seek routing compile for the target. Write/create/truncate and symlink
support are explicitly incomplete, and current readers use file-tree snapshots.
See [native-open evidence](node-runtime-acceptance/native-open/README.md).
This remains prerequisite evidence, not actual V8 execution.

### First successful real-V8 firmware link

The complete forced V8 smoke gate now links against the native Rust bridges
and pinned static C/C++ runtime with no undefined symbols or relocation errors.
The QEMU linker script retains priority-sorted native initialization and
termination arrays; the smoke entry calls the process-once newlib initializer.
Evidence: [firmware-link-11](node-runtime-acceptance/v8-firmware-link-11/README.md).
The resulting diagnostic fixture is not bootable as a V8 acceptance image:
its extra fixture flag page and probe boot path still need separation. No V8
expression, exception, GC or newlib constructor execution is yet claimed.

### Dedicated real V8 execution attempts

A `node-runtime` QEMU profile now boots with matched 1 GiB board/linker memory
and runs the actual V8 gate with native TLS, stack, entropy and stream grants.
The first two attempts failed: an Abseil executable orphan section landed
outside RX text (fixed in the linker), then V8's default Leap Tiering requested
a 256 MiB dispatch-table reservation. Patch 0025 disables that configuration and
requires consistent host/target definitions; a full rebuild is needed.
[First-execution evidence](node-runtime-acceptance/v8-first-execution/README.md)
records both failures. Expression/exception/GC acceptance is still pending.

### Shared-kernel regression checks

The default 128 MiB IMAC image passes the existing
[WASI QEMU/OpenSSH suite](node-runtime-acceptance/wasi-regression/README.md),
including cancellation, 100 reclaimed invocations and cold restart. The separate
[three-boot file-tree suite](node-runtime-acceptance/file-tree-regression/README.md)
also passes persistence and powered-off image verification. These checks cover
existing functionality affected by shared kernel/linker changes; they do not
establish native Node filesystem support or V8 execution acceptance.
