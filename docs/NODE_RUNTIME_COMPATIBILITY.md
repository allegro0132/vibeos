# VibeOS Node port compatibility

This is the VibeOS port of pinned Node.js 24.14.0 / V8 13.6.233.17, not a claim
of complete Node compatibility. The implementation uses real upstream Node and
V8, JIT-less and single-threaded, on QEMU RV64GC. The default firmware does not
link Node. See [pinned sources](../tools/node-runtime/sources.lock.json),
[toolchain](../tools/node-runtime/toolchain.lock.json), and
[milestone status](NODE_RUNTIME.md).

The table records target execution evidence for the implementation to date.
The [fresh build and execution](node-runtime-acceptance/node-fresh-57/README.md)
qualifies M2, including local VSH, authenticated SSH and 100 successful launcher
cycles after the process-page ownership fix. The broader M4 inventory/security
audit and M3 official TypeScript/tsx toolchain remain incomplete.

| Area | Verified behavior / current boundary | Evidence |
|---|---|---|
| V8 | Real expression evaluation, exceptions, GC, normal destruction; JIT-less; static builtins; data pages NX | [V8 gate](node-runtime-acceptance/v8-first-execution/README.md) |
| Entry points | `node --root @home/project main.js` and `node --root @home/project -e source`; launcher removes `--root`; cwd is `/` within the granted project | [VSH](node-runtime-acceptance/node-vsh/README.md) |
| Modules | CJS cross-file require, ESM and dynamic import; no ambient global module search | [Project](node-runtime-acceptance/node-project-execution/run-2/README.md), [VSH](node-runtime-acceptance/node-vsh/README.md) |
| JavaScript core | Buffer, Promise, timers; bounded serial async zlib work | [Launcher](node-runtime-acceptance/node-launcher-entry/README.md) |
| Files | Sync and Promise reads/writes, create/truncate, directories and module file access through fresh capability leases | [Project authority](node-runtime-acceptance/project-authority-projection), [VSH](node-runtime-acceptance/node-vsh/README.md) |
| Paths | Project-relative namespace; sibling hidden; outward symlink read/write/realpath denied; original authority revocation also denies already-open reads | [Directory boundary](node-runtime-acceptance/directory-live-boundary), [Project authority](node-runtime-acceptance/project-authority-projection) |
| Streams | UTF-8 split input and EOF, VSH pipelines, existing stream-capability redirection such as `> @console` | [Stdin](node-runtime-acceptance/node-stdin-execution/README.md), [VSH](node-runtime-acceptance/node-vsh/README.md) |
| Termination | Exact exit 7, uncaught error with eval source position, CPU and idle Ctrl-C, successful invocation after cancellation | [VSH](node-runtime-acceptance/node-vsh/README.md) |
| SSH | Authenticated interactive OpenSSH PTY using the command profile's project-root grant; pipe input, exit 7, Ctrl-C and relaunch | [SSH](node-runtime-acceptance/node-ssh/README.md) |
| SSH output | Existing VSH transport captures bounded command output until completion; live output streaming and interactive Node stdin from the PTY are not claimed | [SSH](node-runtime-acceptance/node-ssh/README.md) |
| SSH exec | Separate restricted SSH exec policy; arbitrary `ssh host node ...` has not been admitted or qualified | [SSH](node-runtime-acceptance/node-ssh/README.md) |
| Environment | Explicit empty initial environment in the production launcher; invocation-local mutable environment, no host inheritance | [Environment](node-runtime-acceptance/libuv-environment) |
| Concurrency | One active native Node invocation; busy admission rejected; process synchronization shared across serial invocations | [Launcher](node-runtime-acceptance/node-launcher-entry/README.md), [VSH](node-runtime-acceptance/node-vsh/README.md) |
| Runtime memory | Invocation page pools plus bounded process-lifetime TCB storage; 4 MiB process page pool retains global cppgc metadata | [Ownership failure and correction](node-runtime-acceptance/node-vsh/README.md) |
| TypeScript / tsx | Official tsc/tsx have not yet executed on target; commands are not registered | M3 pending |
| esbuild | Official WASI Preview 1 TS/TSX transforms passed separately; the Node/tsx transform bridge remains pending | [esbuild](node-runtime-acceptance/esbuild-qemu) |

Excluded first-release facilities include npm online installation, network
services/DNS, general subprocesses, IPC, user workers, native addons, signals,
watch mode and V8 WebAssembly. The platform uses explicit unavailable errors;
it does not substitute host execution. The existing WASI service used by
esbuild is separate from V8 WebAssembly and Node's unavailable WASI binding.

The production launcher currently requests a read/write project root. Read-only
tool mounts and the TypeScript wrapper admission policies remain to be added.
Node CLI option coverage beyond the documented file and eval forms is not
claimed. V8 fatal faults and unrecoverable OOM remain failures of the trusted
runtime image; they are not recovered by dropping or jumping over native stacks.
