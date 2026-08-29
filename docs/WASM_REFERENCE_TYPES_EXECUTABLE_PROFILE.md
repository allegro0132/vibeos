# Reference Types executable successor profile

Status: `c813-e3-qualified-sealed-reference-runtime-released`.

C8.13 is the independently numbered executable successor made eligible by the
C8.12-R3 fixed-QEMU decision. It does not promote or reinterpret validation-only
code 9.

| Coordinate | Frozen value |
|---|---|
| Identity | `PROFILE_7_SYNC_REFERENCE_TYPES_EXECUTABLE` |
| Artifact profile code / ABI | 10 / 10 |
| Runtime ABI | 10 |
| Component / Core profile | 7 / 7 |
| Stage | `Executable` |
| Core revision | `webassembly-core-2.0-reference-types-1.0-nullable-funcref-c813-executable-v1` |
| Component revision | `wasmparser-component-model-0.255.0-c813-reference-executable-v1` |
| Canonical ABI revision | `component-model-0.255.0-sync-no-core-reference-boundary-c813-reference-executable-v1` |
| WIT world | `vibe:references/runtime@1.0.0` |
| Selected engine | `vibeos-wasmi-reference-executable@1.1.0-vibeos-ref2.1` |

The executable surface preserves the exact C8.12 bounded semantics: nullable
Core-internal `funcref`, one funcref table, active element segments, exact
Reference Types 1.0 operations, deterministic fuel, and an integer/byte-only
host boundary. `externref`, typed function references, GC objects, passive or
declarative elements, bulk memory, floats, SIMD, memory64, threads, and every
Component/Canonical/WIT reference value remain forbidden.

E2 materializes the separately named Wasmi facade, code-10 current-engine
binding, fuel-bounded executor, and sealed authority-free volatile admission
lifecycle. The executor has no imports and exposes only integer values; Core
references remain internal. Cancellation, fault, recovery, and revocation are
explicit. Durable graph publication, migration, ordinary command admission,
production authority remain unavailable. E3 releases only this sealed volatile
runtime after one fixed-QEMU boot and normal/optimized verification of the same
capture; it grants no durable, migration, or ordinary-command authority.

| Node | Exit gate |
|---|---|
| C8.13-E1 | Freeze code/ABIs 10, profile 7, revisions, engine, world, semantics, non-promotion, and fixed-QEMU policy |
| C8.13-E2 | Implement the executor, current-engine binding, sealed authority-free volatile admission/lifecycle, durable rejection, supply-chain closure, and RISC-V audit |
| C8.13-E3 | Pass fresh normal and optimized fixed-QEMU evidence before releasing only the sealed volatile code-10 runtime |

Code 5 remains permanently inert. Code 7 remains validation-only. Code 9
remains validation-only, non-current, non-executable, and non-migratable. Code
8 retains exactly its prior SIMD scope. Fixed QEMU is emulator-only; Milk-V
Duo remains paused, optional, and has zero gate effect.

The E3 evidence is source-bound to commit `cdeefb93564ad0269306d27fabe879a8d88ac1df`
and tree `e27f0978db7b1ed70c9dcae028b6109d2717cf4e`; run ID
`11f097eaa1ab51be766811018d0955ccc722f83feba7b37d0f095a31ae3d85b7`
produced semantic SHA-256
`6a654a8428f4f4479db637ab90d391c989c43b2c67dfc51570bd4ac617cc1a49`.

The canonical design contract is
[`c813-reference-executable-design-v1-contract.json`](../acceptance/wasm-reference-target/artifacts/c813-reference-executable-design-v1-contract.json).
The implementation contract is
[`c813-reference-executable-implementation-v1-contract.json`](../acceptance/wasm-reference-target/artifacts/c813-reference-executable-implementation-v1-contract.json).
The qualification contract is
[`c813-e3-fixed-qemu-qualification-v1-contract.json`](../acceptance/wasm-reference-target/artifacts/c813-e3-fixed-qemu-qualification-v1-contract.json).
