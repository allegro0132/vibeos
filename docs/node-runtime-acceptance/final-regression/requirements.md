# Original-plan completion audit

This audit uses the agreed first-release scope. It does not claim full Node
compatibility, online npm, network servers, subprocesses, user workers, addons
or watch support. The checked-in histories retain earlier failures; only the
specified passing runs below establish each gate.

| Requirement | Implementation / authoritative evidence | Result |
|---|---|---|
| Real Node 24, bundled V8/libuv; fixed sources, compilers, TS/tsx/esbuild and checksums | [Version manifest](version-manifest.json), [fresh cross-build](../lifecycle-audit/fresh-build/), production/probe archive-member manifests | Pass |
| Opt-in node-runtime, 1 GiB QEMU memory/board/linker agreement, one active instance; default image excludes Node | Firmware feature graph (default empty), board/build memory selection, `native_node::BUSY` admission; [M1 image](../v8-first-execution/README.md), final default-profile MMU/file/VSH and opt-in production boots | Pass |
| Reproducible cross-build, separate host generators and target products, pinned static C++ TCB | `scripts/build-v8.py`, `tools/node-runtime/patches`, [fresh build](../lifecycle-audit/fresh-build/), [final link inputs](production-link/) | Pass |
| VibeOS page allocator, clock, entropy, synchronization, TLS and scheduler integration | `kernel/src/native_*`, `tools/node-runtime/platform`; [native C++ suspension](../native-cxx/README.md), [TLS destructors](../native-tls-destructors/README.md), final real Node/tsx operation | Pass |
| JIT-less static builtins, no oversized V8 virtual reservations or background compilation/GC; NX data | VibeOS GYP patches disable JIT/WebAssembly/pointer compression/Leap Tiering, `node-process.cc` enables `--jitless --single-threaded`; [V8 gate](../v8-first-execution/run-3/), [native page protection](../native-call/README.md) | Pass |
| RV64 LP64D bridge, FP/FCSR/TLS restoration, protected independent stack | `native_call.rs` and native context-switch assembly; [ABI/guard test](../native-call/README.md), [C++ yield/RAII test](../native-cxx/README.md) | Pass |
| Suspendable native task, cooperative cancellation, normal C++ destruction rather than forced jumps | `native_call.rs::NativeAsync`, Node/V8 cooperative-checkpoint patches; [final CPU/idle cancellation](node/results.json), [WASI-transform cancellation](tsx-cancel/results.json), [M4 teardown](../lifecycle-audit/README.md) | Pass |
| Upstream CJS/ESM/dynamic import, Buffer, Promise, timers and required builtins through a dedicated libuv backend | [Node](node/results.json), [tsx](tsx/results.json), [100 mixed workloads](cycles/results.json), [Promise transform binding](esbuild-node/results.json) | Pass |
| Invocation project/tools/stdio grants, explicit environment and bounded resources | `native_node.rs`, `native_tls.rs`, `native_files.rs`; [environment isolation](../libuv-environment/), [M4 exact inventories](../lifecycle-audit/README.md) | Pass |
| Virtual cwd/root, module/fs/realpath/write containment and live authority revocation | [Final boundaries](boundary/results.json), [live project/tool revocation and restart](../lifecycle-audit/sync-authority/results.json), prior descriptor-revocation evidence under project-authority projection | Pass |
| Sync I/O parks; async I/O uses event loop rather than scheduler busy-wait | Native park/wait bridge and bounded libuv async reads; [native wait](../native-wait/README.md), [Node files/streams/timers](node/results.json), final SSH responsiveness | Pass |
| Official tsc/declarations as independent read-only tools; -p, noEmit, JS and declaration output, real error diagnostics | [tsc](tsc/results.json), [tool/root boundary](boundary/results.json), immutable toolkit manifest | Pass |
| Upstream tsx loading/resolution/transforms/source maps adapted to same instance; no child/IPC/watch path | `tools/node-runtime/toolkit/tsx-adapt.py` and launchers; [tsx TS/TSX/import/factory/maps](tsx/results.json), [watch rejection](exclusions/results.json) | Pass |
| Official esbuild WASI Preview 1, restricted sync/async conversion independent of V8 WebAssembly | [Initial independent WASI gate](../esbuild-qemu/results.json), [final official API](esbuild-api/results.json), [native Promise binding](esbuild-node/results.json), disabled JS WebAssembly test | Pass |
| Checking/compilation/transformation/execution all in guest; host only builds runtime, stages tools/projects | Target scripts submit TS sources and inspect guest-emitted artifacts; [tsc](tsc/commands.in), [tsx](tsx/commands.in), [esbuild API](esbuild-api/commands.in) | Pass |
| VSH registered node/tsc/tsx --root interfaces; launcher strips --root and sets virtual project cwd; quotes/pipes/redirection/status/cancellation | `native_node.rs`; [Node/VSH](node/results.json), [default VSH](default-shell/vsh.log), [tool invocations](tsc/commands.in), [boundaries](boundary/results.json) | Pass |
| Same commands through authorized SSH, offline node_modules, project/tool grants kept separate | [SSH PTY transcript](ssh/ssh-pty.log), [SSH checks](ssh/results.json), [offline import](tsx/results.json), [M4 tool revocation](../lifecycle-audit/sync-authority/results.json) | Pass |
| First-release unsupported functionality rejects clearly | [Exclusion checks](exclusions/results.json): worker, sync/async subprocess, TCP/UDP, signal, addon, file watch/poll, tsx watch and V8 WebAssembly; successful Node restart afterward | Pass |
| M1 expression, exception and GC in real V8 plus independent TS/TSX WASI conversion | [V8 run 3](../v8-first-execution/run-3/results.json), [esbuild target cases](../esbuild-qemu/results.json) | Pass |
| M2 functional loop and M3 complete compiler/executor project flow | Final Node, tsc, tsx, esbuild and SSH suites listed above | Pass |
| M4 traversal, readonly, revocation, infinite-loop cancellation, backpressure, 100 exits and precise resource reclamation | [M4 audit](../lifecycle-audit/README.md), final boundary/cancellation/backpressure/cycle regressions | Pass |
| Separate real V8 fatal and unrecoverable OOM cases; no promise of isolate recovery | [Independent fatal](../lifecycle-audit/fresh/fatal/results.json), [final OOM](oom/results.json), whole-image shutdown behavior recorded | Pass |
| M5 affected host tests, QEMU file/VSH/WASI/MMU, versions/logs/memory/time/compatibility | [Final report](README.md), retained host and target logs, [compatibility matrix](../../NODE_RUNTIME_COMPATIBILITY.md) | Pass with disclosed pre-existing broader-suite failure |

The expanded Python suite's frontend-composition failure predates this port;
[historical source evidence](host/preexisting-frontend-check.json) and its raw
failure are retained. It is not counted as a pass. Normal-suite ignored opt-in
host cases are also listed in the report. The affected host suites and every
required target gate above pass. The qualification remains four-hart QEMU,
with whole-image failure for V8 fatal faults/OOM and the first-release feature
exclusions; it is not a claim of full Node compatibility or single-hart SSH
responsiveness during long transforms.
