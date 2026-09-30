# Native JavaScript / TypeScript port

**Status: real V8 and official esbuild WASI execute on QEMU. Native Node now
runs through capability-rooted local VSH and authorized OpenSSH PTY sessions.
CJS/ESM, files, stdio/pipes, timers, exact exit status and cooperative cancellation
pass target tests. Official tsc now checks projects, emits JS/declarations,
and reports type errors on target. Adapted upstream tsx also executes TS/TSX
projects on target. The agreed M1–M5 QEMU qualification is complete, including
final production-image regressions. See the disclosed test limitations below.**

[Current compatibility and limits](NODE_RUNTIME_COMPATIBILITY.md).

## Milestones

Current numbering follows the agreed implementation order. Older evidence below
retains its original internal milestone labels.

- **M0 — build baseline and pinned inputs:** complete; the earlier baseline
  and ordinary QEMU/WASI/VSH verification evidence is retained below.
- **M1 — feasibility:** complete for one-shot real V8 expression/exception/GC
  and official esbuild WASI TS/TSX transformation on QEMU. See
  [V8 evidence](node-runtime-acceptance/v8-first-execution/README.md).
- **M2 — Node loop:** complete; the [fresh 57-patch build and execution](node-runtime-acceptance/node-fresh-57/README.md)
  passes VSH, authorized SSH and 100 successful launcher invocations. [Local VSH evidence](node-runtime-acceptance/node-vsh/README.md)
  covers eval, CJS/ESM, files, pipes, stream-capability redirection, exit 7,
  uncaught diagnostics and CPU/idle Ctrl-C followed by successful relaunch.
  [OpenSSH PTY evidence](node-runtime-acceptance/node-ssh/README.md) covers the
  admitted project-root capability, pipe input, exit 7 and remote Ctrl-C/relaunch.
  The SSH/VSH transport retains its existing buffered command-output semantics.
  [Launcher lifecycle evidence](node-runtime-acceptance/node-launcher-entry/README.md)
  records earlier 100-cycle execution and the subsequent ownership fixes.
- **M3 — TypeScript tools:** complete. [Fresh build and final target evidence](node-runtime-acceptance/toolkit-fresh-build/README.md)
  qualifies the full toolchain on QEMU, including authorized OpenSSH PTY use.
  [Official tsc evidence](node-runtime-acceptance/tsc-qemu/README.md)
  covers project checking, noEmit, JS/declaration emission, running emitted JS
  and source-positioned type diagnostics. The adapted official esbuild JS API
  passes TS/TSX, custom JSX factory, source-map and diagnostic checks on QEMU;
  see [API evidence](node-runtime-acceptance/esbuild-api/README.md).
  The [native transport](node-runtime-acceptance/esbuild-node-binding/README.md)
  also passes Promise, mixed-call and exit-cleanup checks. [Adapted upstream
  tsx](node-runtime-acceptance/tsx-qemu/README.md) now passes CJS/ESM, dynamic
  import, offline modules, custom JSX factory and mapped exceptions on QEMU.
  The final production image passes tsc, tsx, Node, directory boundaries,
  transform cancellation, backpressure, OOM and 100 launches; a matching
  probe profile passes the official esbuild API and Promise/exit-cleanup suite.
- **M4 — safety and lifecycle:** complete. The [lifecycle audit](node-runtime-acceptance/lifecycle-audit/README.md)
  qualifies path/readonly boundaries, live project/tool parent revocation,
  CPU/idle and WASI-transform cancellation, backpressure, and separate fatal/OOM
  behavior. A fresh patched build fixes foreground-runner and cppgc wrapper
  retention. File, eval and uncaught-error workloads each pass 100 QEMU launches
  with exact stable non-cache allocator occupancy and synchronization counts;
  file/TLS/page owners, invocation grants, leases and I/O waiters are reclaimed.
  Intentional bounded process caches remain explicitly inventoried.
- **M5 — regression and evidence:** complete. The [final qualification](node-runtime-acceptance/final-regression/README.md)
  passes production Node/tsc/tsx, SSH with the original keepalive, esbuild APIs,
  exclusions, 100 launches, and default file/VSH/WASI/MMU regressions. Affected
  host suites pass; the expanded Python suite has one documented pre-existing
  frontend-composition failure. Versions, logs, timings, memory observations
  and the [requirement audit](node-runtime-acceptance/final-regression/requirements.md)
  are retained. This is the agreed first-release scope, not full Node compatibility.

Milestones are committed and pushed to `implement_nodejs`.

The implementation uses real Node.js with its bundled V8/libuv, statically linked
into an opt-in QEMU image. V8 starts JIT-less. Resource access remains rooted in
explicit capabilities. The first release targets offline projects; npm online
installation, network services, child processes, user workers, native addons and
watch are excluded. The upstream tsx loading/transform adaptation is implemented
and qualified through the complete fresh-build target suite.
Optional node:sqlite and SQLite-backed Web Storage are excluded with upstream
`--without-sqlite`; their exact runtime rejection remains unqualified.

## Added tooling

`tools/node-runtime/sources.lock.json` pins the initial feasibility inputs:

| Input | Version | Provenance |
| --- | --- | --- |
| Node.js | 24.14.0 | Release commit `f657bb8ed86365ff3fdbe32e27563e778b41486a`, official source archive SHA-256 |
| Bundled V8 | 13.6.233.17 | From the verified Node.js source archive |
| TypeScript | 5.9.3 | Official npm package SHA-512 integrity and source commit |
| tsx | 4.19.3 | Official npm package SHA-512 integrity and source commit |
| esbuild WASI Preview 1 | 0.25.0 | Official npm package integrity, archive SHA-256 and module SHA-256 |

This source lock is supplemented by `tools/node-runtime/toolkit.lock.json`,
which pins the offline tool packages and transitive dependencies used by the
adapted tsx launcher. Packaging manifests record every payload and adapter hash;
the prepared toolkit has passed reproducibility and target execution checks.
Node's V8/libuv sources are included in the verified source archive. A separate
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

## Node/libuv work in progress

Patch 0027 supplies VibeOS libuv platform types and explicit unsupported network
operations. Nine upstream common sources cross-compile, including timers and
address conversion. The initial failed full libuv build and common-object
results are retained in
[libuv-common-build](node-runtime-acceptance/libuv-common-build/README.md).
Reproduce the object check with `scripts/check-libuv-platform.py --source
<prepared-node-source> --work target/<fresh-directory>`.

The dedicated timer/async loop backend now passes a
[QEMU prerequisite](node-runtime-acceptance/libuv-loop/README.md): upstream timer
and phase callbacks, coalesced async notification, `UV_RUN_ONCE`/`NOWAIT`, busy
loop rejection and normal close. Add `--uv-loop` to both the V8 link helper and
QEMU harness to require this check before V8. The helper now selects the
`native-uv-probe` fixture and also requires an
[async stdin request](node-runtime-acceptance/libuv-async-read/README.md) to
complete after timer progress. Its request queue polls the real transport
without parking the whole event loop. The
[async stdout backpressure check](node-runtime-acceptance/libuv-async-write/README.md)
also passes: nine requests deliver 9216 validated bytes, with timer progress
while the bounded pipe is full. Regular-file async IO, the uv_stream layer,
full libuv GYP integration and actual Node execution remain pending.
The [descriptor-file prerequisite](node-runtime-acceptance/libuv-files/README.md)
passes capability-rooted open, synchronous read, snapshot fstat, deferred
open/close callbacks and revocation denial. Positioned IO and writable files
remain incomplete; the test uses a volatile
file tree, not durable storage. A subsequent
[path prerequisite](node-runtime-acceptance/libuv-paths/README.md) now passes
stat/lstat/realpath, contained symlink open/read, traversal denial and circular
link rejection. Resolved readers pin metadata and content together; the
file-store host suite passes 29 tests (5 existing ignored cases).

Patch 0029 now builds the backend through upstream libuv GYP, separating native
target sources from the host platform used by `node_js2c`. The
[GYP archive QEMU check](node-runtime-acceptance/libuv-gyp-build/README.md)
passes all current libuv/V8 prerequisites using the actual target `libuv.a`.
`build-v8.py uv` and `build-v8.py node` expose the next build phases. Node target
compilation has started: patch 0030 removes native-addon dynamic loading;
c-ares' Unix socket dependency is the next observed failure. Node has not yet
linked or executed.

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

Node incremental build update: patches 31–33 preserve pure IP conversion while rejecting DNS operations, select static-image debugging, and adapt address conversion. Target compilation now reaches `node.cc`, failing on unavailable `sys/termios.h`. See `node-build-6` through `node-build-9` in `docs/node-runtime-acceptance/libuv-gyp-build`. Node execution acceptance remains pending.

Node build update (10–15): embedded startup, credential selection, process-operation rejection and static reporting now compile. The next observed failure is the POSIX thread-based SIGINT watchdog in `node_watchdog.cc`. Cancellation and Node runtime acceptance remain pending; evidence is in `docs/node-runtime-acceptance/libuv-gyp-build`.

Node build 17 now produces the first target `libnode.a`; all 40 patches apply to a fresh locked extraction and its libuv configuration/build pass. This is compile/archive evidence only: Node firmware linking, execution and cancellation remain pending. See `node-build-17.json`, archive member hashes and `fresh-40-*` evidence in `docs/node-runtime-acceptance/libuv-gyp-build`.

First Node embedding link: the new one-shot `node-smoke.cc` compiles for RV64GC, but firmware linking reports 500 unresolved symbols (150 libuv APIs plus bundled libraries and native helpers). Evidence is in `docs/node-runtime-acceptance/node-first-link`. Dependency build now reaches zstd pthread support after patch 41 adapts nghttp2 byte order. No Node QEMU execution has occurred.

Node link attempt 2: ten real bundled dependency archives build; upstream no-snapshot source is included. Missing symbols decrease from 500 to 291 (150 libuv, 75 SQLite, 63 uvwasi, three newlib). Evidence: `docs/node-runtime-acceptance/node-first-link/run-2`. No Node firmware or execution acceptance yet.

Libuv sync prerequisite now passes QEMU: regular/recursive mutexes, semaphore permits and parked condition timeout/relock, alongside prior V8 and libuv gates (17 parks, zero waiters). Evidence: `docs/node-runtime-acceptance/libuv-sync/run-2`; the failed fixture ordering run is preserved. Full Node, concurrency and invocation lifecycle acceptance remain pending.

Libuv metrics and read/write lock gates now pass QEMU: metrics mutex lifecycle, eight timer-loop init/close cycles, shared readers and exclusive write/try-lock behavior. Evidence: `docs/node-runtime-acceptance/libuv-metrics` and `libuv-rwlock`. Full Node execution, concurrent contention and repeated invocation lifecycle remain pending.

Newlib prerequisite QEMU pass: capability-rooted `stat`, explicit unsupported hard-link creation, and monotonic parked `sleep`; includes escape, missing path, symlink loop and revocation checks (29 parks, zero waiters). Evidence: `docs/node-runtime-acceptance/node-libc`. Full Node firmware linking/execution remains pending.

Node firmware link 3 still fails with 206 unresolved names, down from 291: 131 libuv and 75 SQLite/session APIs. Sync/newlib references are resolved; Node WASI explicitly rejects because V8 WebAssembly is disabled. The esbuild WASI service is unchanged. Evidence: `docs/node-runtime-acceptance/node-first-link/run-3` and `node-wasi-boundary`. No Node execution acceptance yet.

Libuv clocks/identity prerequisite passes QEMU: realtime, monotonic clock, uptime, 3 ms parked sleep, stable native task identity and single-task parallelism. Existing gates still pass (31 parks, zero waiters). Evidence: `docs/node-runtime-acceptance/libuv-clock`. Full Node startup and toolchain execution remain pending.

Libuv unlink now passes QEMU with real rooted transactions: synchronous deletion, deferred async completion via Rust-owned futures, read-only admission refusal, escape/directory/revocation denial. Evidence: `docs/node-runtime-acceptance/libuv-unlink/run-3` (33 parks, zero waiters), with build/fixture failures retained. Slow durable publication, cancellation and full Node execution remain pending.

Queued filesystem `uv_cancel` now passes QEMU: deferred ECANCELED completion preserves a queued deletion target; already-polled stdin returns EBUSY and completes normally. Repeated/late cancellation and request reuse are checked. Evidence: `docs/node-runtime-acceptance/libuv-cancel` (35 parks, zero waiters). This does not satisfy JavaScript infinite-loop cancellation or full Node acceptance.

Rooted `uv_fs_readlink` now passes QEMU in sync/async forms: literal self-link, short-buffer preservation, ordinary-file error, escape and revocation denial. Evidence: `docs/node-runtime-acceptance/libuv-readlink` (36 parks, zero waiters). Full Node module resolution remains pending.

Capability-backed `uv_fs_access` passes QEMU: read/write rights, read-only denial, missing and escaped paths, invalid modes, async completion and revocation. X_OK is explicitly unsupported; W_OK checks authority, not implemented write-open support. Evidence: `docs/node-runtime-acceptance/libuv-access` (37 parks, zero waiters). Full Node execution remains pending.

Node link attempt 4 still fails with 198 unresolved symbols (123 libuv, 75 SQLite/session), resolving 8 names since run 3. Evidence: `docs/node-runtime-acceptance/node-first-link/run-4`. Node QEMU execution remains pending.

Capability-rooted `uv_fs_scandir` passes QEMU: sorted names and file/directory/symlink types, full/partial cleanup, deferred callback, path errors and revocation denial. Evidence: `docs/node-runtime-acceptance/libuv-scandir` (38 parks, zero waiters). Node startup and TypeScript directory consumption remain pending.

Rooted `uv_fs_mkdir`, `uv_fs_rename` and `uv_fs_rmdir` pass QEMU with real sync/async transactions, descendant preservation, type/nonempty errors, read-only/escape/revocation denial. Evidence: `docs/node-runtime-acceptance/libuv-tree` (45 parks, zero waiters). Unix mode bits do not replace capability authority. Full Node and compiler-output acceptance remain pending.

File-tree inode-addressed range-write/truncate primitives pass host tests (31 passed, 5 ignored) and a QEMU identity/path-reuse/sparse/truncation/snapshot fixture. Evidence: `docs/node-runtime-acceptance/file-ranges`. Native writable descriptors and libuv file-write integration remain pending; this does not establish Node compiler-output support.

Existing-file writable native descriptors and synchronous libuv writes/ftruncate pass QEMU: identity after rename, content readback, live metadata, mode restrictions and revocation denial (53 parks, zero waiters). Host file-store tests pass (31 passed, 5 ignored). Evidence: `docs/node-runtime-acceptance/libuv-write-file`. Creation, async file IO, unlinked-open lifetime and full Node output remain pending.

Synchronous native/libuv create, exclusive-open, truncate-open and append pass QEMU, including newlib EEXIST, content readback, symlink collision, escape/read-only/revocation denial (60 parks, zero waiters). Evidence: `docs/node-runtime-acceptance/libuv-create/run-2`. Async create/write and full Node/TypeScript execution remain pending.

Async regular-file writes and ftruncate pass QEMU with owned Rust transaction futures, deferred completion, content/size checks and queued cancellation preserving data. Evidence: `docs/node-runtime-acceptance/libuv-async-file` (62 parks, zero waiters). Delayed durable publication, async reads/open and full Node remain pending.

Node firmware link 5 still fails with 193 missing names (118 libuv, 75 SQLite/session), resolving 5 names since run 4. Evidence: `docs/node-runtime-acceptance/node-first-link/run-5`. Real Node execution remains pending.

Node link 6 removes all 75 SQLite/session references via upstream `--without-sqlite`; 118 libuv symbols remain unresolved. Target libnode build 20 and fresh 46-patch preparation/configuration/libuv build pass. Evidence: `docs/node-runtime-acceptance/node-first-link/run-6` and `node-without-sqlite`. No Node execution milestone yet.

Excluded child-process/watch/host-signal APIs pass QEMU ENOTSUP/no-side-effect checks (14 APIs, 63 parks, zero waiters). Node constructor guards compile but JS rejection tests remain unexecuted. Link 7 still has 107 unresolved names, resolving 11 since run 6. Evidence: `docs/node-runtime-acceptance/libuv-excluded` and `node-first-link/run-7`.

Owned async regular-file reads pass QEMU: deferred bytes/EOF, cancellation preserving cursor/buffer, delivery-buffer retry, consumed IDs and denied delivery after capability revocation. Evidence: `docs/node-runtime-acceptance/libuv-async-file-read` (64 parks, zero waiters). Persistent-latency/concurrent cursor qualification, async create-open and full Node remain pending.

Sync/async positioned regular-file IO passes QEMU: content and unchanged cursor, invalid/overflow offset refusal, and ESPIPE for stdio positioning. Evidence: `docs/node-runtime-acceptance/libuv-positioned-io` (67 parks, zero waiters). Full Node/TypeScript and remaining lifecycle/storage qualification are still pending.

The first-port Node network boundary passes 32 QEMU ENOTSUP/no-mutation checks (68 parks, zero waiters); TCP/UDP constructor rejection guards compile. Node firmware link 8 still has 78 unresolved names, resolving 29 since run 7. Evidence: `docs/node-runtime-acceptance/libuv-network-excluded` and `node-first-link/run-8`. Native Node/TypeScript acceptance remains pending.

Invocation-local stdio pipe handle lifecycle passes QEMU: descriptor classification, stdin attachment/direction, data preservation, duplicate/IPC refusal, deferred close and endpoint closure. Evidence: `docs/node-runtime-acceptance/libuv-stream-handles` (69 parks, zero waiters). Stream data transfer and complete Node stdio remain pending.

Nonblocking `uv_try_write` now passes actual multi-vector stdout output, invalid-buffer/direction and closed-handle checks in QEMU (69 parks, zero waiters). Evidence: `docs/node-runtime-acceptance/libuv-stream-write/run-3`; prior assertion failures are retained. Stream short-transfer/backpressure qualification, queued writes/reads and Node execution remain pending.

Node link 9 still fails with 69 unresolved libuv symbols, resolving 9 since run 8. Evidence: `docs/node-runtime-acceptance/node-first-link/run-9`. No Node runtime milestone yet.

Queued `uv_write`/non-IPC `uv_write2` now pass QEMU with exactly 16 KiB of ordered multi-vector data, copied descriptors, partial progress, deferred callbacks, close cancellation and zero remaining queue/active state. Evidence: `docs/node-runtime-acceptance/libuv-async-stream-write/run-2` (71 parks, zero waiters). Stream reads/shutdown and full Node execution remain pending.

`uv_shutdown` now passes QEMU queued-write drain, deferred callback ordering, descriptor preservation, repeated-shutdown/write rejection and close cancellation checks. Evidence: `docs/node-runtime-acceptance/libuv-stream-shutdown/run-2` (72 parks, zero waiters). The verifier treats stdout/stderr as separately ordered streams; run 1's assertion failure is retained. Stream reads and complete Node execution remain pending.

Stream reads now pass QEMU delayed input, small-buffer delivery, ENOBUFS retry, stop/restart preservation and EOF/close checks. Evidence: `docs/node-runtime-acceptance/libuv-stream-read` (74 parks, zero waiters). Cached delivery rechecks authority; revocation/reentrant-callback races and duplicate-descriptor ownership remain unqualified. Full Node execution remains pending.

Node link 10 still fails with 64 unresolved libuv symbols, resolving 5 since run 9. Evidence: `docs/node-runtime-acceptance/node-first-link/run-10`. No Node runtime milestone yet.

Invocation-local `uv_cwd`/`uv_chdir` now pass QEMU relative IO/unlink, root escape denial, short-buffer behavior, directory replacement detection and revocation checks. Evidence: `docs/node-runtime-acceptance/libuv-cwd` (82 parks, zero waiters). Renamed cwd recovery, queued-path/chdir races and complete Node module execution remain limited or pending as documented.

Invocation-owned environment now passes QEMU explicit seed/isolation, shared libuv/newlib access, enumeration snapshots, unset/empty values and size/count limits. Evidence: `docs/node-runtime-acceptance/libuv-environment` (83 parks, zero waiters). Full Node process.env and lifecycle/cache qualification remain pending.

Fresh 51-patch preparation/configuration/libuv build and host libc contract checks pass (see `libuv-environment/fresh-build`). Node link 11 still has 58 unresolved symbols, resolving 6 since run 10; see `node-first-link/run-11`. No Node execution milestone yet.

Relative symlink and hard-link operations pass QEMU literal-target/inode checks, async copied arguments, queued cancellation, escape/read-only/revocation denial and cleanup. Evidence: `docs/node-runtime-acceptance/libuv-links` (93 parks, zero waiters). Absolute symlink targets remain explicitly unsupported; full Node execution remains pending.

Eight Unix owner/mode/timestamp mutation APIs now return explicit ENOTSUP through synchronous/deferred filesystem request paths. QEMU checks callbacks, cancellation, cleanup and unchanged file metadata/content; evidence: `docs/node-runtime-acceptance/libuv-metadata-unavailable` (95 parks, zero waiters). These metadata features remain unsupported, and Node execution remains pending.

Node link 12 still has 48 unresolved libuv symbols, resolving 10 since run 11; evidence: `node-first-link/run-12`. No Node runtime milestone yet.

File sync APIs now check authoritative publication with fresh descriptor authority; in-progress publication returns explicit EBUSY. QEMU covers commit/busy, deferred completion, cancellation, unchanged generation and denial checks; evidence: `docs/node-runtime-acceptance/libuv-file-sync` (100 parks, zero waiters). File-store host tests: 32 passed, 5 ignored. Volatile-root testing does not establish disk-flush or power-loss guarantees.

IPC/TTY exclusion APIs and nonblocking standard-stream mode pass QEMU unchanged-output/no-callback checks; evidence: `docs/node-runtime-acceptance/libuv-ipc-tty-unavailable` (101 parks, zero waiters). Node IPC constructor protection compiles and has a prospective JS test, but Node execution remains pending.

Node link 13 still has 37 unresolved libuv symbols, resolving 11 since run 12; evidence: `node-first-link/run-13`. No Node execution milestone yet.

Memory queries now pass QEMU actual-allocation visibility and RSS refusal checks; evidence: `libuv-memory` (102 parks, zero waiters). System/free readings use board RAM and heap accounting; unified process quota/RSS attribution remains unavailable. Node link 14 still has 32 unresolved libuv symbols, resolving 5 since run 13; evidence: `node-first-link/run-14`. No Node execution milestone yet.

Directory handles now pass QEMU batched enumeration/types/EOF, async completion/cancellation, replacement refusal and revocation/cleanup tests; evidence: `libuv-directory` (114 parks, zero waiters). Enumeration is a snapshot; renamed/deleted directory handles fail closed. Full Node execution and teardown qualification remain pending.

Node link 15 still has 29 unresolved libuv symbols, resolving the three directory APIs since run 14; evidence: `node-first-link/run-15`. Node execution remains unaccepted.

Invocation-owned process titles and logical pid/ppid now pass QEMU copy/bounds/identity and stdio preservation checks; evidence: `libuv-process` (116 parks, zero waiters). Executable-path lookup remains explicitly unsupported until the launcher/tool mount provides a virtual path; Node's upstream argv[0] fallback is retained. Full Node JS process behavior remains unaccepted.

Node link 16 still has 22 unresolved libuv symbols, resolving 7 process metadata/initialization names since run 15; evidence: `node-first-link/run-16`. Node execution remains pending.

Native thread creation/join/naming exclusion APIs pass QEMU unchanged-output/no-entry/identity checks; evidence: `libuv-thread-excluded` (118 parks, zero waiters). Node Worker constructor rejection compiles and patch 53 applies with zero fuzz; JavaScript behavior remains unexecuted. Thread-based internal custom loaders also remain unsupported pending the planned in-instance tsx adaptation.

Node link 17 still has 18 unresolved libuv symbols, resolving 4 thread exclusion APIs since run 16; evidence: `node-first-link/run-17`. Node execution remains pending.

The serialized native `uv_queue_work` path passes QEMU deferred execution, cancellation, requeue/free and mixed file/timer progress checks; evidence: `libuv-work` (122 parks, zero waiters). Callbacks run on the protected native stack, one per loop iteration; running C/C++ work is not forcibly interrupted. A Node asynchronous zlib roundtrip test is prepared but unexecuted.

Node link 18 still has 17 unresolved libuv symbols, resolving `uv_queue_work` since run 17; evidence: `node-first-link/run-18`. Full Node execution remains pending.

OS accounting/account/priority/interface rejection and explicit HOME queries pass QEMU; evidence: `libuv-os-boundary` (123 parks, zero waiters). Unsupported queries preserve outputs; home lookup uses invocation environment only. Full Node API and toolchain execution remain pending.

Node link 19 still has 8 unresolved libuv symbols, resolving 9 OS query/home boundary names since run 18; evidence: `node-first-link/run-19`. Full Node execution remains pending.

Temporary file/directory creation now passes QEMU sync/async entropy-backed exclusive creation, byte-exact content preservation, queued cancellation and revocation checks; evidence: `libuv-temp` (142 parks, zero waiters). Parking work runs only on the native stack. Forced entropy/collision/storage failures and full Node execution remain pending.

Node link 20 still has 6 unresolved libuv symbols, resolving temporary file/directory creation since run 19; evidence: `node-first-link/run-20`. Full Node execution remains pending.

System image labels, explicit HOSTNAME and CPU/load unavailability pass QEMU; evidence: `libuv-system` (143 parks, zero waiters). Node CPU/load bindings compile with explicit ENOTSUP and patch 54 applies with zero fuzz. The void libuv load-average ABI uses NaN samples; Node JS behavior remains unexecuted.

Node link 21 still has two unresolved libuv symbols (`uv_fs_copyfile`, `uv_fs_statfs`), resolving four system-query names since run 20; evidence: `node-first-link/run-21`. Full Node execution remains pending.

Atomic regular-file copy and permission-checked statfs refusal pass QEMU; evidence: `libuv-copy` (162 parks, zero waiters). Copy preserves immutable content and target hard-link identity, supports deferred cancellation and rejects unsupported forced storage reflink. Durable-fault qualification and full Node execution remain pending.

Node link 22 resolves all undefined symbols but still fails with 21 medany relocations to absent weak zstd trace hooks; evidence: `node-first-link/run-22`. No Node ELF or execution yet.

Node link 23 produces the first complete Node ELF after disabling absent weak zstd trace hooks; evidence: `node-first-link/run-23`. First real QEMU execution fails at duplicate cppgc initialization in the embedding test (`node-first-execution/run-1`); Node JavaScript/teardown acceptance remains pending.

After removing duplicate cppgc initialization, Node's second QEMU run reaches JavaScript loading but rejects `process.cwd` because the gate omitted a project capability. It tears down normally with return 1 and zero waiters; evidence: `node-first-execution/run-2`. A private project fixture is being attached explicitly.

Node's third target execution runs Buffer/Promise/timer and asynchronous zlib checks and returns zero with no waiters. Its verifier still fails because normal environment cleanup closes stdout before the teardown marker; evidence: `node-first-execution/run-3`. A kernel test-probe completion channel is being added; no complete M2 milestone yet.

Real Node's preliminary embedding gate now passes QEMU with inline JS/Buffer/Promise/timer, asynchronous zlib and normal teardown, return 0 and zero waiters; evidence: `node-first-execution/run-4`. The earlier failures are retained. Project module/filesystem/cancellation and full M2 acceptance remain pending.

Asynchronous create/truncate opens now pass libuv cancellation/preservation tests (`libuv-open-async`, 167 parks). Real Node project execution passes cross-file CJS, ESM dynamic import and sync/Promise file creation/read/write/truncation with return 0 and zero waiters (`node-project-execution/run-2`, 11 parks). Full M2 and TypeScript acceptance remain pending.

Real Node stdin/UTF-8/EOF execution now passes alongside prior project and runtime tests; evidence: `node-stdin-execution` (13 parks, return 0, zero waiters). Nonzero exit, cancellation, production commands and full M2 acceptance remain pending.

Real Node nonzero exits now pass QEMU: passive `process.exitCode=7` and active `process.exit(7)` both complete native teardown, propagate 7 and leave zero waiters. Evidence: `node-exit-execution/run-1` and `node-explicit-exit-execution/run-3`; failed outer-TryCatch assertions and the diagnostic run are retained in runs 1–2. This does not qualify infinite-loop cancellation or complete M2.

The same gate source also passes default exit-0 regression after explicit-exit support (`node-exit-execution/default-regression`), including prior CJS/ESM, filesystem, stdin and async runtime checks.

VibeOS-only V8 bytecode-budget checkpoints now yield through the retained native stack and observe CommandIo cancellation after resumption. The actual Node-context infinite-loop gate passes same-hart cancellation, normal termination/teardown, return 130 and zero waiters (`node-cancel-execution/run-1`, 194 parks). This is not yet a production VSH cancellation or full M2/M4 qualification.

The patched V8/native checkpoint also passes the non-cancelled Node regression with native return 0 and zero waiters (`node-cancel-execution/default-regression`), covering all prior project/stream/runtime checks.

The upstream Node main-module bootstrap now passes QEMU with `/main.cjs` read through the project grant (`node-main-execution/run-1`). Main identity, argv, cwd, all prior project/runtime checks, exit 0 and teardown pass (193 parks, zero waiters). VSH registration and reusable runtime lifecycle remain pending.

The shared project fixture also passes the original embedding-entry QEMU regression (`node-main-execution/inline-regression`); the build records and rechecks JS fixture/generated include hashes.

Native FileGrant now takes a fresh-lease provider suitable for a VSH invocation. The bounded VSH provider observes resource revocation and job cancellation in host tests (33 VSH tests pass); the generic provider passes the Node main-module QEMU regression with return 0 and zero waiters. Evidence and precise remaining integration limits: `native-authority-provider/README.md`. Production command wiring and subtree project-root admission remain pending.

Directory-bounded immutable snapshots now constrain link resolution, listing, content reads and recursive-copy source traversal. Host tests pass (34 passed, 5 ignored), and the ordinary Node main-file QEMU regression remains green with return 0 and zero waiters (`directory-snapshot-boundary`). Live writable subtree admission and Node use of that boundary remain pending.

Live FileTreeRoot directory views now share parent storage while bounding snapshots, readers, inode admission and transactions. Bounded transactions reject pre-existing edits and outside inode mutations. Host tests pass (37 passed, 5 ignored), and actual Node QEMU execution from a granted project subdirectory denies sibling visibility and outward-link read/write/realpath while preserving the parent's protected file (`directory-live-boundary/run-1`, return 0, 196 parks, zero waiters). VSH source-capability projection/revocation and production command registration still require integration.

Final live-directory boundary regression also passes QEMU (`directory-live-boundary/run-2`) after stale content-stager admission and cross-view ancestor-copy checks; host file-store suite remains 37 passed, 5 ignored.

Native project projection now retains its original capability lease and revalidates directory identity at every operation; the QEMU probe rejects revoked parents, replacement directories, retargeted entry links and readonly writes (`project-authority-projection/run-1`). Real Node additionally observes EACCES for both new path reads and a previously opened descriptor after parent revocation, then completes normal exit/teardown with return 0 and zero waiters (`project-authority-projection/node-revocation`, 208 parks). Production VSH provider wiring remains pending.

Node/V8 process initialization is now separated into `tools/node-runtime/runtime/node-process.*`. Fresh native invocation contexts share only an explicitly owned synchronization domain for process-global locks. The first repeated-run failure identified an invocation-local semaphore backing Node's global `cli_options_mutex`; bounded fatal frame logs and symbolization are retained. Two executions then pass, followed by 100 consecutive main-file executions in QEMU (`node-repeat-execution/run-4`, 64.5674 s host wall time, peak kernel heap 305765120 bytes, cleanup live-byte variation 256 bytes, zero standard-stream waiters per run). Bump remaining stabilizes after iteration 2. Production command wiring, repeated failure/cancellation inventory and complete M4 remain pending.

A launcher-facing `vibeos_node_run` ABI now separates runtime execution from smoke assertions. File startup and upstream `-e` evaluation both pass QEMU through this ABI, including require/argv and the full shared project checks (`node-launcher-entry`). The ABI uses invocation-owned Node options and normal per-call cleanup; VSH registration, idle cancellation wakeup and dedicated error/exit/cancel qualification for this new entry remain pending.

The reusable launcher ABI now passes explicit `process.exit(7)` and idle-loop cancellation in QEMU (`node-launcher-entry/explicit-exit` and `idle-cancel`). The latter enters a 60-second native timer wait, is cancelled by a same-hart peer, and returns 130 with normal cleanup after 114 ms and zero waiters. CommandIo cancellation now wakes an owned native-domain observer; libuv readiness and loop return observe the cancelled grant. Eight host CommandIo tests pass. VSH registration, new-ABI CPU/exception/repeat acceptance and full M2 remain pending.

The idle-cancellation change passes the full ordinary launcher main-file QEMU regression with exit 0 and zero waiters (`node-launcher-entry/idle-cancel-regression`).

CPU-loop cancellation through the reusable launcher initially exposed a Node callback teardown failure (fatal exit 1). Patch 0057 now stops cancelled callbacks before async-hooks cleanup and disables JS callback retry. The timer-callback infinite-loop QEMU retest returns 130 with normal teardown and zero waiters; both failed and passing evidence are retained in `node-launcher-entry/cpu-cancel`. Production VSH cancellation remains pending.

The reusable launcher ABI now passes 100 serial ordinary Node main-file invocations after patch 0057 (`node-launcher-entry/repeat-100`): all return 0 with zero waiters and complete all project/stream/runtime checks. QEMU host wall time is 66.726 seconds; cleanup live heap stays within 36186624–36186880 bytes. This does not qualify repeated error/cancellation cycles or production VSH admission.

Production `node --root @home/project main.js` and `-e` now run through VSH
capability command registration and a persistent SYSTEM-owned pinned supervisor.
Automatic gate startup is separately gated by `node-runtime-gate`; `--node-shell`
builds the command image. The first mixed VSH test uncovered cppgc global metadata
allocated in an invocation page pool; initialization now uses a separate bounded
4 MiB process-lifetime TCB page pool. Failed and passing evidence is retained in
`node-vsh/`. Run 4 passes eval, CJS, dynamic ESM, pipe input, filesystem IO, timer,
stream-capability redirection, nonzero conditional exit, uncaught diagnostics,
and CPU/idle Ctrl-C followed by successful fresh invocations. SSH execution,
exact VSH numeric exit status, final-source lifecycle/regression qualification,
and complete M2 evidence remain pending.

`node-vsh/run-5` additionally verifies the exact VSH Returned(7) result and
uncaught eval source position [eval]:1:7 while repeating the complete mixed
command and Ctrl-C sequence. All checks pass.

Authorized OpenSSH PTY execution now passes against the native Node image
(`node-ssh/run-3`): bounded project-root admission, eval, stdin pipeline, exact
exit 7, Ctrl-C and fresh invocation after cancellation. The platform grants the
already recovered home tree only to the existing admitted command profile and
never to onboarding sessions. Existing SSH/VSH output capture semantics remain
in effect; 20 SSHD host tests pass. Full final-source regression is still pending.
