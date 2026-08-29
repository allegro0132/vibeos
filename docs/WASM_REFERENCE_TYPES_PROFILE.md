# Reference Types validation profile

C8.12 closure: `c812-r3-qualified-reference-validation-successor-review-eligible`.
Live roadmap: `c813-e2-reference-executable-implemented-pre-qemu`.

C8.12 is the next one-feature widening after the released code-8 SIMD runtime.
C8.12-R1 allocates a fresh validation-only identity; it does not reinterpret or
extend any older artifact:

| Coordinate | Frozen value |
|---|---|
| Identity | `PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION` |
| Artifact profile code / ABI | 9 / 9 |
| Runtime ABI | 9 |
| Component / Core profile | 6 / 6 |
| Stage | `ValidationOnly` |
| Core revision | `webassembly-core-2.0-reference-types-1.0-nullable-funcref-c812-validation-v1` |
| Component revision | `wasmparser-component-model-0.255.0-c812-ref-validation-v1` |
| Canonical ABI revision | `component-model-0.255.0-sync-no-core-reference-boundary-c812-ref-validation-v1` |
| WIT world | `vibe:references/validation@1.0.0` |
| Candidate engine | `vibeos-wasmi-reference-validation@1.1.0-vibeos-ref1.1` |

The numeric surface returns to the Profile-1 integer-only baseline. The sole
semantic widening is bounded WebAssembly Reference Types 1.0 inside embedded
Core modules: nullable `funcref`, `ref.null func`, `ref.is_null`, `ref.func`,
single-result typed select, one funcref table, Reference Types table operations,
and active element segments. Bulk-memory operations and passive/declarative
element segments remain forbidden.
`externref`, typed function references, GC objects, host reference imports or
exports, and every Component/Canonical/WIT reference boundary are forbidden.

Wasmi 1.1.0's reference-types configuration also enables wasmparser's
`GC_TYPES` support because the parser requires it for heap-type decoding. This
is a parser dependency, not semantic permission: the C8.12 inspection layer
must reject structs, arrays, `i31`, typed function references, and every other
GC form. Floats, SIMD, relaxed SIMD, exceptions, memory64, multiple memories,
threads/shared memory, bulk memory, tail calls, and extended const remain
disabled.

The engine identity is frozen as a new facade derived from the pinned
`vibeos-wasmi-softfloat@1.1.0-vibeos-f2.1` source, with floats disabled. R1 did
not materialize that facade, bind a current engine, admit code 9, or execute it.
R2 now implements the codec, isolated dual-pass candidate validator, syntax
containment, negative and fixed mutation corpora, Component confinement,
default-off rejection boundaries, supply-chain closure, and RISC-V object
audit. Code 9 remains non-current, non-executable, non-durable, and
non-migratable throughout C8.12.

The ordered nodes are:

| Node | Exit gate |
|---|---|
| C8.12-R1 | Freeze code/ABIs 9, profile 6, revisions, engine, bounded semantics, authority boundaries, and fixed-QEMU policy |
| C8.12-R2 | Implement and audit the validation-only engine, containment, corpus, and rejection paths |
| C8.12-R3 | Pass fresh normal and optimized `qemu-virt-rv64-tcg-icount-v1` evidence and become eligible only for an independently numbered executable-successor design review |

R2 materializes the new two-file facade and the default-off
`vibeos-wasm-reference-candidate` crate. The exact validator enables only
`REFERENCE_TYPES` plus the parser-required `GC_TYPES`, then rejects every GC
composite type with `into_iter_err_on_gc_types`, every non-`funcref` reference,
more than one table, passive/declarative elements, reference-valued exports,
and all imports. A second Wasmi translation pass must accept the same bytes.
The Component path reuses the synchronous integer-only boundary and delegates
each embedded Core module to this validator; ordinary inspection and durable
loading still reject code 9.

The fixed corpus covers four candidate tests, three Component containment
tests, and 256 deterministic byte mutations (208 structural/semantic
rejections; the remaining name/non-semantic mutations retain zero current
engine authority). The offline `riscv64imac-unknown-none-elf` closure audit
covers seven rlibs and finds no F/D/V opcode, semantic native-float helper, or
reachable `libm`.

Fixed QEMU is the formal C8.12 qualification target. It is emulator-scoped and
claims no physical equivalence. Milk-V Duo supplies zero inputs and remains a
paused optional observation; unrelated hardware gates are unchanged.

R3 binds pushed source commit
`43516cd6fe4d88c583f681714950884dc8660d4c` and tree
`89ca3d099ef3981cc2d760a8993d47d5a6585cc7` to one QEMU 11.0.3 rv64
TCG/icount boot. All eight exact cases and the containment record pass, with
208 mutations rejected and 48 accepted only as inert nonsemantic/name changes.
The nine-record semantic SHA-256 is
`bf33470617822af905ab8877797416e79aed3cde5a257689b3bbdda4df156279`.
Normal and optimized verification and the final-ELF no-F/D/V/no-native-float
audit pass. This opens only design review for a separately numbered executable
successor; it allocates nothing and grants code 9 no current engine, execution,
admission, durable, migration, production, or release authority.

Code 5 remains permanently inert. Code 7 remains validation-only and
non-migratable. Code 8 retains exactly its already released sealed,
authority-free volatile SIMD scope and gains no reference-types support.

The canonical R1 contract is
[`c812-reference-types-design-v1-contract.json`](../acceptance/wasm-reference-target/artifacts/c812-reference-types-design-v1-contract.json).
The canonical R3 qualification contract is
[`c812-r3-fixed-qemu-qualification-v1-contract.json`](../acceptance/wasm-reference-target/artifacts/c812-r3-fixed-qemu-qualification-v1-contract.json).
