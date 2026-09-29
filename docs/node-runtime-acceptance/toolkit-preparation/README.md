# Offline upstream tool inputs (M3 prerequisite)

`scripts/prepare-node-toolkit.py` prepares the locked official TypeScript 5.9.3,
tsx 4.19.3, esbuild JS API 0.25.0, get-tsconfig 4.7.5 and resolve-pkg-maps 1.0.0
packages, plus the separately locked esbuild WASI Preview 1 module. Registry
SHA-512 integrity is checked before extraction. No npm install scripts or host
JavaScript execute. Optional native esbuild binaries and fsevents are omitted;
the manifest explicitly lists those omissions.

```
python3 scripts/prepare-node-toolkit.py --output target/node-runtime/toolkit-first
python3 scripts/prepare-node-toolkit.py --offline --output target/node-runtime/toolkit-offline
```

Both runs produce the same tar SHA-256:
`d3704c60112a59e0be70b3175863bf50fae0d7a66f17a513fd3302e83193a1a5`.
The 200 payload files occupy 42,468,102 bytes. File hashes and package identities
are retained in `manifest.json`; `results.json` records reproducibility, tar
metadata/membership, dependency closure, official compiler/declaration presence,
existing-output rejection and corrupted-input rejection checks.

The tar uses fixed timestamps/ownership and read-only file modes. These modes
are packaging metadata, not guest authority enforcement. A separate read-only
capability mount and official tsc execution now pass the later
[tsc gate](../tsc-qemu/README.md). Platform patches for the tsx/esbuild interface
and actual TSX execution remain required. This is not M3 acceptance.

The preparer also emits `toolkit.pack`, a bounded file container embedded only
by `node-toolkit` builds. Its SHA-256 is
`fad849389f877ba962525bf711df73431e166398504929ac789b54d0e94e8d72`.
Offline regeneration matches byte-for-byte; the link validator rejects a
modified pack before invoking the firmware build.
