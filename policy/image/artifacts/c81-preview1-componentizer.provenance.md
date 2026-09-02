# C8.1 Preview1 componentizer fixtures

These files are immutable, off-device C8.1 evidence. They do not authorize
execution. The transformer and admission result both report
`runtime_ready=false` and `guest_calls=0`.

## Pinned toolchain and adapter provenance

- Rust crates: `wit-component = 0.255.0` and `wasmparser = 0.255.0` exactly.
- Evidence CLI: `wasm-tools 1.255.0 (76e20611d 2026-07-30)`, built from the
  same 0.255.0 parser/encoder generation. The reviewed binary used for this
  evidence has SHA-256
  `7578041abd93bc44b436f6c24c8556b0597a5317cb000aec71164b4406de9d8d`.
- Adapter release asset revision:
  `wasmtime-v48.0.0-f1412a598f96f3c261a19118d94caffcb0c36235/wasi_snapshot_preview1.command.wasm`.
- Upstream release asset:
  `https://github.com/bytecodealliance/wasmtime/releases/download/v48.0.0/wasi_snapshot_preview1.command.wasm`.
- Adapter import name passed to `ComponentEncoder`:
  `wasi_snapshot_preview1` exactly.
- The adapter targets WASI 0.2.12.

The checked-in 51,828-byte adapter asset and its SHA-256 are normative. The
release tag and source commit above are provenance locators, not a claim that a
fresh source build is bit-for-bit reproducible. No adapter search path,
environment lookup, network lookup, or implicit default is used by the
transformer.

The complete release asset must not be confused with embedded Core module 1.
`wit-component` prunes the complete 51,828-byte asset to a 9,581-byte module in
this composition. The manifest commits to the complete official asset, while
the embedded-module list separately commits to the pruned bytes.

## Exact fixture commitments

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `c81-fd-write.core.wat` | 365 | `e0397e429a713a041fdb471606efc2754304283cd3783a844c95ff454f019420` |
| `c81-fd-write.core.wasm` | 145 | `5ac1eb14874721c8355669fd91811f9a0165d96f1382ff82f08f3dfc0634bb0c` |
| `c81-wasmtime-v48.0.0-preview1-command-adapter.wasm` | 51,828 | `316dfbf171591d69ae414efd13b85933ca13526af8d9e0a735ab88ae08fd85f0` |
| `c81-fd-write.preview1-wrapped.component.wasm` | 17,495 | `b910b4428e9ff442649f36a59707373a34d73f50f11fc1ae1266cd9f19e9f48e` |
| `c81-fd-write.component.wit` | 3,317 | `39c4ec95a1e92a8df777b03d0d11349b150725c50d862231fca35d61f9347ed4` |
| `c81-fd-write.preview1-wrapped.cmp1` | 74,739 | `615e3ad744df57709009c864cfbf0b5a2abaee7d12d99b4e1773541ef655fd74` |

The CMP1 envelope's independently encoded artifact commitment is
`c913a32e180e179fba8c52b20f50f47649d95838c5c9feeb3162ff58e7404f4c`.
This is distinct from the SHA-256 of the complete raw CMP1 file shown above.

The Core fixture has one bounded 32-bit, unshared memory (`initial=1`,
`maximum=16`); one function import,
`wasi_snapshot_preview1.fd_write: (i32, i32, i32, i32) -> i32`; one defined
function; exports `memory` and `_start`; no start section, table, global, data,
or element; and one bounded `name` custom section. It has no `args` or
`proc_exit` import.

## Independently observed Component structure

The Component has 86 top-level section occurrences. Counts below are
`occurrences/vector entries`; `-` means the section embeds one binary rather
than a vector.

| Section id and kind | Count |
| --- | ---: |
| 0 custom | 2 / - |
| 1 Core module | 4 / - |
| 2 Core instance | 12 / 15 |
| 4 nested Component | 1 / - |
| 5 Component instance | 1 / 1 |
| 6 alias | 30 / 42 |
| 7 Component type | 9 / 10 |
| 8 canonical | 18 / 18 |
| 10 import | 8 / 8 |
| 11 export | 1 / 1 |

The 18 canonical entries are four resource drops, thirteen lowers, and one
lift. Embedded Core modules in parser traversal order are:

| Ordinal | Bytes | SHA-256 | Role |
| ---: | ---: | --- | --- |
| 0 | 145 | `5ac1eb14874721c8355669fd91811f9a0165d96f1382ff82f08f3dfc0634bb0c` | exact guest |
| 1 | 9,581 | `96cbc60f3ef3ad13621236858694165e0b4dd02052ab38b875285e1aeafb4f66` | pruned adapter-derived module |
| 2 | 318 | `1e30d212a60962a6eefee3b6ba9249332aa0a430b7e3bacca792bf86ef89ae0e` | generated shim |
| 3 | 183 | `3c11674007ed6e8d74e99a1d2b52dc41cf1acd842f20ebd6e438593668d7d7ff` | generated shim |

The exact WIT evidence has eight imports and one export, all version 0.2.12:

- imports: `wasi:io/error`, `wasi:io/streams`, `wasi:cli/stdin`,
  `wasi:cli/stdout`, `wasi:cli/stderr`, `wasi:clocks/wall-clock`,
  `wasi:filesystem/types`, and `wasi:filesystem/preopens`;
- export: `wasi:cli/run`.

It declares four resources. The checked-in `.wit` is the byte-for-byte output
of `wasm-tools component wit`; it is independent evidence, never trusted in
place of parsing the Component bytes.

## Exact admission pins derived from output bytes

The following entries are sorted by `(direction, kind, name)`. Each digest is
over the exact raw wasmparser entry bytes, excluding the enclosing section id,
section length, and vector count.

| Direction | Kind | Name | Raw bytes | Raw-entry SHA-256 |
| --- | --- | --- | ---: | --- |
| import | instance | `wasi:cli/stderr@0.2.12` | 26 | `6fc47ffb74b1b905a5b8fe1c467ea8199eb091ffb0e9e2874f7ac986a4a91a32` |
| import | instance | `wasi:cli/stdin@0.2.12` | 25 | `e5ff52618b9ebffbca4783de197eda34847f87c0a4351c0aea669cf7ba2db4a4` |
| import | instance | `wasi:cli/stdout@0.2.12` | 26 | `9f231e2d8ad27a675d433c795b154f0246ca22f8d600bda2ddc60e76c8aa9d25` |
| import | instance | `wasi:clocks/wall-clock@0.2.12` | 33 | `09d4e71704cfc40ffbd71d8481daab692c737df30fafc26d89e89a745f6116b7` |
| import | instance | `wasi:filesystem/preopens@0.2.12` | 35 | `cb5037f354e73e9b1ae3380e90d00371bdd943c720aa7d0e5727e9591c507a90` |
| import | instance | `wasi:filesystem/types@0.2.12` | 32 | `2fbf66c40479ed438de2ac00b156d8d88bbf38447c6b76449502be035d8849c5` |
| import | instance | `wasi:io/error@0.2.12` | 24 | `40fed392ca0fd40a1feff77e63776a6bdc059a2cf26cd60366f3f77d2b7cc344` |
| import | instance | `wasi:io/streams@0.2.12` | 26 | `9a16c9faac49b9dbf019eb4735259eb0d58ac3bc824867ab2aa374826ca95241` |
| export | instance | `wasi:cli/run@0.2.12` | 24 | `c2429760150a601023aa7883ffaf212116e2a304829b6aab11aaadb84e510478` |

The lowering fingerprint is SHA-256 over the exact byte domain
`vibeos.preview1-wrapped.canonical-lowerings.v1\0`, followed in top-level
traversal order by each of the 13 `CanonicalFunction::Lower` raw entries as
`u64le(entry_length) || entry_bytes`. Its value is
`a5f5d1b1b1a09d92718132121d367acef0aed6364b58b1aac3e70daef62701f8`.

## Reproduction

Run from the repository root with the pinned `wasm-tools` CLI on `PATH`:

```sh
wasm-tools --version
wasm-tools parse policy/image/artifacts/c81-fd-write.core.wat \
  -o /private/tmp/c81-rebuilt.core.wasm
cmp /private/tmp/c81-rebuilt.core.wasm \
  policy/image/artifacts/c81-fd-write.core.wasm

cargo run --offline --locked -p vibeos-c81-preview1-componentizer -- \
  --core policy/image/artifacts/c81-fd-write.core.wasm \
  --adapter policy/image/artifacts/c81-wasmtime-v48.0.0-preview1-command-adapter.wasm \
  --output /private/tmp/c81-rebuilt.component.wasm
cmp /private/tmp/c81-rebuilt.component.wasm \
  policy/image/artifacts/c81-fd-write.preview1-wrapped.component.wasm

wasm-tools component wit /private/tmp/c81-rebuilt.component.wasm \
  -o /private/tmp/c81-rebuilt.component.wit
cmp /private/tmp/c81-rebuilt.component.wit \
  policy/image/artifacts/c81-fd-write.component.wit

cargo test --offline --locked -p vibeos-c81-preview1-componentizer
```

The Rust transformer uses `ComponentEncoder::validate(true)` and then a fresh
`wasmparser::Validator` pass over the resulting Component. None of these
commands instantiate or execute the guest.

## License

The official Wasmtime adapter is distributed by the Bytecode Alliance under
`Apache-2.0 WITH LLVM-exception`. See the adjacent adapter notice and the
complete upstream v48.0.0 `LICENSE` file linked from it. The notice is not a
substitute for the full upstream license text. The local WAT fixture and
generated evidence follow the repository's license.
