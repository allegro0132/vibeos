# Upstream tsx current-instance port: target qualification

The optional toolkit registers production `tsx --root @ROOT/project SCRIPT`
through the VSH capability command mechanism. The launcher strips the root
argument, grants the independently read-only toolkit, sets the script argv,
and uses Node 24 synchronous module hooks on the current Node instance.

The checked platform adapter retains upstream tsx 4.19.3 resolution,
tsconfig, transformation, dynamic-import interop and source-map logic.
Synchronous load hooks use retained native-stack filesystem/esbuild calls.
IPC clients are inert and per-invocation memory maps replace disk caches.

Earlier target attempts expose the following port requirements:

- `run-1/`: `ERR_NO_CRYPTO` while importing `node:crypto`. This Node port has
  OpenSSL disabled. The adapter now uses full source/options strings as private
  cache keys and removes redundant crypto imports. No replacement crypto API
  is introduced.
- `run-2/`: `ReferenceError: WebAssembly is not defined`. Upstream tsx bundles
  both a WebAssembly lexer and a JavaScript fallback, but initializes the former
  unconditionally. The adapter now selects the bundled JavaScript fallback
  and removes the WebAssembly initialization/blob. Actual TS/TSX conversion
  still goes through official esbuild WASI, not through V8 WebAssembly.
- `run-3/`: the first source file converts through WASI, but the CJS next-resolve
  callback reports `MODULE_NOT_FOUND`, unlike the ESM worker's
  `ERR_MODULE_NOT_FOUND`. Extension candidate probing stopped on that code.
  The adapted hooks now handle both codes, and use the requested file URL for
  CJS transformation instead of requiring the worker loader's `responseURL`.

Each directory retains serial output, fixture commands, result checks, link
hashes and the exact toolkit manifest used by that image. Failed-run runtime
inputs are identified by the frozen link manifest; the harness's additional
working-tree hashes are collected when the harness finishes and may include
subsequent adapter edits while it awaited a missing success marker.

`run-4/` passes the target test `scripts/test-tsx-qemu.py` through the production
`tsx` command: cross-file CJS and ESM, dynamic import, offline node_modules,
custom JSX factory from tsconfig, mapped exception at `/error.ts:2:7`, exit 1,
and successful restart after that failure. All ten WASI jobs report reclaimed
arenas, zero capabilities and zero waiters. Each guest owner peaks at
96,523,904 bytes; this is not total system memory.

The adapted toolkit was prepared twice offline with identical pack SHA-256
`5633f49158bd22c45b1e2ed7f3213cd00f486002ada22e4021a012ce02adcb69` and tar SHA-256
`e273084660bf34615e9353e544f8fad69c544e0a0bddd6f4c3bcde6383ca1c98`.
The image still reuses qualified fresh-57 V8/Node archives and the separately
built bridge-platform libuv archive. Same-image tsc regression passes in
`../tsc-qemu/with-tsx/`; final clean-build qualification remains outstanding
before closing M3. Build and toolkit
preparation alone are not execution evidence.

The driver now supports optional `--fail-marker` diagnostics. The tsx test
uses this to stop when an unexpected exit 1 precedes a success marker, while
explicitly accepting exit 1 for its intentional mapped-exception fixture.
Default behavior for other existing driver callers is unchanged.
