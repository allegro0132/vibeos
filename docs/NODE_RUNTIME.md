# Native JavaScript / TypeScript port: feasibility gate

**Status: implementation in progress. The QEMU firmware build/boot baseline is
restored. V8, Node.js, tsc and tsx are not yet available inside VibeOS; their
runtime acceptance remains open.**

## Milestones

- **M0 — build baseline and pinned inputs:** complete. Source checksums, offline
  probes, and explicit Rust toolchain selection are implemented. The ordinary
  QEMU WASI image builds and boots; VSH executes an echo command. Network tests
  pass (24), as do WASI tests (22; one external-fixture test intentionally ignored)
  and the Python probe tests (8). This is not V8/Node acceptance.
- **M1 — native platform / V8:** implement the target C/C++ support, platform
  backend, ABI and lifecycle; execute expressions, exceptions and GC on QEMU.
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

## Initial observations and current disposition

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
