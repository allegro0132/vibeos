# C8.8-F2 software-float fork provenance

This directory is an acceptance-only, package-identity-isolated fork of the
four Wasmi 1.1.0 crates. It does not replace crates.io packages through Cargo's
patch mechanism. The production Profile 1 runtime continues to resolve stock
`wasmi` 1.1.0 from crates.io, while the opt-in acceptance crate alone names the
renamed path package `vibeos-wasmi-softfloat`.

## Source identities

All four Wasmi crates came from commit
`8273dfb09d493971b7bb12fe614d740cdc857175` of
`https://github.com/wasmi-labs/wasmi`. Their exact crates.io archive SHA-256
values, original repository paths, and renamed local package identities are in
`PROVENANCE.toml`. The checked-in `LICENSE-MIT` and `LICENSE-APACHE` files were
read from that exact official commit; the verifier binds their bytes.

The arithmetic backend is crates.io package
`rustc_apfloat 0.2.3+llvm-462a31f5a5ab`, archive SHA-256
`486c2179b4796f65bfe2ee33679acf0927ac83ecf583ad6c91c3b4570911b9ad`,
Git revision `eeaacad81247af65d4043cb3e32d023a652d7951`, and LLVM APFloat
baseline `462a31f5a5abb905869ea93cc49b096079b11aa4`. Its exact Apache-2.0
WITH LLVM-exception license and detailed relicensing analysis are copied under
`third-party/rustc_apfloat/` and byte-bound by the verifier. Its normal direct
dependency closure is `bitflags 2.13.1` plus `smallvec 1.15.2` with
`const_generics` and `union`; every selected registry checksum is frozen in
`PROVENANCE.toml` and checked against `Cargo.lock`. The remaining `libm` edge
is optional and reachable only through the fork's forbidden `simd` feature; it
is pinned and recorded but absent from the selected candidate lock edge.

## Pristine and patched digest procedure

`UPSTREAM_FILES.sha256` was generated from `README.md` and every regular file
under `src/` in each of the four checksum-verified crates.io archives. Archive
paths are deterministically remapped to the local `crates/{wasmi,core,ir,
collections}` paths, and records are bytewise sorted. Rewritten Cargo manifests
are intentionally outside this pristine source set and are hashed separately.

The content-manifest digest starts SHA-256 with the ASCII domain
`vibeos-c88-f2-content-manifest-sha256-v1` followed by NUL. For each record in
bytewise path order, it appends the UTF-8 relative path, NUL, and the 32 raw
bytes represented by that file's SHA-256. Applying this procedure to
`UPSTREAM_FILES.sha256` produces the pristine identity; applying it to the
current README/source tree produces the patched identity. Applying it to the
four rewritten `Cargo.toml` files produces their separate identity.

The delta digest starts SHA-256 with
`vibeos-c88-f2-patch-delta-sha256-v1` followed by NUL. For each added, deleted,
or modified path in bytewise order it appends: path, NUL, one byte (`A`, `D`,
or `M`), NUL, the 32-byte pristine hash (all zero for an addition), and the
32-byte patched hash (all zero for a deletion). The expected path set and all
five aggregate digests are frozen independently in both the provenance file
and verifier.

## Verification

Run:

```sh
python3 scripts/verify-c88-f2-supply-chain.py --self-test
```

The offline verifier checks source and manifest digests, official licenses,
all archive and selected dependency identities, fully renamed/path-only fork
edges, the absence of workspace `[patch.crates-io]`, the unchanged stock
Profile 1 lock and dependency identity, and the permanent code-5
`ValidationOnly`/`runtime_ready=false`/no-current-engine invariants. Self-test
mutations occur only in memory and demonstrate rejection of source drift,
stock-lock tampering, patch injection, code-5 activation, and package-identity
collapse.
