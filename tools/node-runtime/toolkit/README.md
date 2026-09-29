# Offline tool platform adapters

`adapt.py` runs during `scripts/prepare-node-toolkit.py`. It first verifies the
exact SHA-256 of the pinned upstream esbuild 0.25.0 `lib/main.js`, then replaces
its Node-specific executable discovery, child process and worker transport
with `esbuild-platform.js`. The shared upstream protocol, option validation,
transform response processing, diagnostics and source-map handling are kept.
One small shared-code branch returns locally detected option diagnostics
directly instead of submitting a service logging request.

Both adapter inputs and resulting payload hashes are recorded in the toolkit
manifest. The firmware link validates the recorded adapter hashes against the
current files, in addition to validating every payload and the packed image.
No npm scripts or host JavaScript execute while preparing the toolkit.

The VibeOS transport creates a fresh upstream channel per transform and passes
its single request to the invocation-owned native binding. The latter admits
only bounded transform packets and runs the official WASI Preview 1 module
through the kernel WASI service. This does not use V8 WebAssembly. Sync calls
suspend their native stack; Promise calls complete through the libuv loop.
Input is limited to 1 MiB of UTF-8, output to the native bridge's 4 MiB limit,
and neither input nor output may use temporary files.

This is explicitly a VibeOS port. `build`, `context`/watch/serve,
`formatMessages` and `analyzeMetafile` return ENOTSUP. `stop()` has no persistent
child process to stop; admitted requests finish or are cancelled during
invocation teardown. The adapter fails explicitly outside a runtime with the
native binding. Tool authority is still checked by the native boundary.

`tsx-adapt.py` checks exact hashes of the affected upstream tsx 4.19.3 files before
adapting them. The current-instance launcher uses Node 24 `registerHooks` and
the upstream loader's resolution, tsconfig and source-map logic. Its resolve
and load functions use synchronous filesystem operations; the ESM transformer
uses the upstream synchronous transformer pipeline with ESM output. These
synchronous calls suspend through the existing native/WASI bridge. They do not
start a worker or child process. CommonJS hook results return transformed
source directly instead of using the worker loader's data-URL workaround.

IPC client modules become inert, per-invocation in-memory maps replace disk
caches, and temporary-directory imports no longer query ambient OS identity.
Full transform inputs replace SHA-1 cache keys, removing the cache's OpenSSL
dependency without substituting a cryptographic implementation. Redundant
side-effect crypto imports are removed from the upstream entry modules too.
The parser is fixed to tsx's bundled upstream JavaScript lexer fallback; its
optional WebAssembly lexer initialization is removed, preserving the runtime's
no-WebAssembly boundary. Source conversion still uses official esbuild WASI.
The original async esbuild/tsx transformation helpers remain available. The
VSH launcher explicitly rejects watch and subprocess-oriented CLI modes.
These implementation changes require target CJS/ESM/TSX/source-map qualification;
preparing a toolkit alone is not execution evidence.
