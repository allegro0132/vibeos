# Official esbuild JavaScript API on VibeOS

`run-1/` records real Node/V8 execution of the platform-adapted official esbuild
0.25.0 JavaScript package in QEMU, invoking the official WASI Preview 1 module
through the native bridge. No host JavaScript compiler or V8 WebAssembly is
used. The test imports the package from the separate read-only tool mount.

Passed target checks:

- `transformSync` compiles typed TS to JavaScript and returns an external map
  with the original filename, source text and nonempty mappings.
- Promise `transform` compiles TSX with custom `h`/`Fragment` JSX options and
  preserves the `view.tsx` source-map filename.
- Invalid TS produces the upstream structured syntax diagnostic at
  `broken.ts:1:13`, as well as its readable message.
- Invalid options preserve upstream errors in synchronous and Promise APIs.
  Input above 1 MiB is rejected with EFBIG before WASI submission.
- Unsupported build/context operations report ENOTSUP.
- Another invocation succeeds after these errors. All four actual WASI jobs
  report reclaimed arenas, zero capabilities and zero waiters. Their owner
  peak is 96,523,904 bytes each, not total system memory.

The adapter replaces the Node transport portion of the pinned package and
keeps upstream shared parsing, protocol, transform and diagnostic logic.
See `tools/node-runtime/toolkit/README.md` for the replacement boundaries and
remaining API limitations. The toolkit was prepared twice offline with matching
tar SHA-256 `c590b10220db785d7b157dc84d5e2a83165ad670159e15a2ea993403507f558f`
and pack SHA-256 `c109e20c7f8ced02d585b269b521aed11d8be17b75aac6ceca17e235c884e001`.
The manifest records upstream and adapter input/output hashes.

Reproduce by preparing the toolkit, linking the `--js-esbuild-probe` image as
documented in `../esbuild-node-binding/`, then running
`scripts/test-esbuild-api-qemu.py --kernel IMAGE --work target/FRESH_DIRECTORY`.
The link still reuses qualified fresh-57 V8/Node archives with bridge-platform
libuv; the final complete clean build remains outstanding.

This passes the official JS transform API boundary, not tsx loading or the
complete M3 milestone. Upstream tsx is still unmodified in this toolkit.
