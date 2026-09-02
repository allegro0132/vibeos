# C2.3 cross-language Canonical ABI fixtures

These two Core Wasm modules are offline evidence for the C2.3 acceptance
criterion. They implement the same `vibe:fixture/canonical-language@1.0.0`
contract in freestanding Rust and C. The integration test embeds each module in
the same Component Model wrapper, validates the exact WIT world, instantiates
it through Vibe's bounded synchronous runtime, and runs the same typed corpus.

The source inputs are:

| Language | Source | Bytes | SHA-256 |
|---|---|---:|---|
| Rust | `component-format/tests/corpus/guests/typed_guest.rs` | 4,498 | `6cbd0295b8ba932163ba70443cacabc62edeec84104f116cbdb48cef990bd021` |
| C | `component-format/tests/corpus/guests/typed_guest.c` | 4,337 | `c1bbc09cdce9b21237e6efc596530421c4c1696df03964a3a1ea6a31beeab877` |
| WIT | `component-format/tests/corpus/wit/canonical-values.wit` | 631 | `9f8d2aad8b904f8ee28d4a18154752e6ed76bf6db66754a07fef7d9e6ffea24c` |

The Rust fixture uses repository toolchain `nightly-2026-08-01` (`rustc
1.99.0-nightly`, commit
`ad3d0bc141a02cf446e384136d250a1f6950fed5`, aarch64-apple-darwin rustc
SHA-256 `fa817099946eee0d4a4ed1d6593b05596f34f92181363e467c6253e84ce431af`)
and its pinned `rust-lld` SHA-256
`6f44b61e91d6d7b6ba80bb75391587bb4fa832b248281bd67d519516cde43f98`.
The C fixture uses the reviewed wasi-sdk 33 arm64 macOS release: archive
SHA-256 `85c997a2665ead91673b5bb88b7d0df3fc8900df3bfa244f720d478187bbdc78`,
Clang `22.1.0-wasi-sdk` LLVM commit
`4434dabb69916856b824f68a64b029c67175e532`, Clang SHA-256
`356b0fdc2006a584582b4958c4ed461813d7492ca412f21727ba7875af93433d`,
and wasm-ld SHA-256
`1682e0d83e144ce8e9b3d5f9dbb628ffdbe404c374c86b5757c00bce4a4d1f24`.

Both builds target `wasm32-wasip1` but are freestanding, import nothing, use
the MVP CPU profile, and pin initial and maximum memory to 131,072 bytes. Each
linker also emits the same private, unexported, unreferenced mutable
`__stack_pointer` global. Mutable Core globals are outside Vibe's Profile 1, so
the checked-in fixtures are not the compiler bytes directly.

The fail-closed sanitizer at `scripts/sanitize-c2-language-core.py` accepts
only the two exact compiler-output digests below, parses canonical top-level
section framing, requires the sole global section to be exactly the reviewed
10-byte stack-global section, removes that whole section, and pins the exact
output digest. It also rejects input symlinks and creates its output without
clobbering an existing path. Its reviewed source is 7,059 bytes with SHA-256
`1536bceca3750ffed0301757e8b255c11882fc5fa06389240a37b8b877ac894c`.
The runtime test then applies Vibe's normal Core inspection to the sanitized
fixtures, which also proves no dangling global reference remains.

The two-stage outputs are:

| Language | Compiler Core bytes | Compiler Core SHA-256 | Checked-in Profile 1 bytes | Checked-in Profile 1 SHA-256 |
|---|---:|---|---:|---|
| Rust | 567 | `149ff653148bf98c6929c9392e5239d1cf3516f3902329a05d0bec3762a0fa11` | 557 | `79e1eb3f2043c4ae224da6057279f80f32ec171106ad2112e8f7d2bf62e96f52` |
| C | 1,040 | `e3d7284a26c34448465ebc12f5024e41e4cc9cae9943f251523a85863ae2aa91` | 1,030 | `20e26c154f2fc3d0892a2175dd85912ea2df77ff43e22200864eba7e6d3f7e8e` |

The resulting checked-in artifacts export only the reviewed Canonical ABI
surface plus memory:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `canonical-values-rust.core.wasm` | 557 | `79e1eb3f2043c4ae224da6057279f80f32ec171106ad2112e8f7d2bf62e96f52` |
| `canonical-values-c.core.wasm` | 1,030 | `20e26c154f2fc3d0892a2175dd85912ea2df77ff43e22200864eba7e6d3f7e8e` |

Run the fail-closed reproduction gate with:

```sh
C2_WASI_SDK_PATH=/path/to/wasi-sdk-33.0-arm64-macos \
  ./scripts/rebuild-c2-language-fixtures.sh
```

The gate verifies every source and tool binary, rebuilds each exact compiler
Core, applies the pinned sanitizer, and requires byte-identical Profile 1
outputs. It performs no network access. The fixtures demonstrate
cross-language ABI interoperability; they do not make either guest compiler
part of VibeOS's target runtime or widen Profile 1.
