# Reference Types executable successor profile

Status: `c813-e1-reference-executable-design-frozen-pre-implementation`.

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

The selected engine is a new, separately named facade over the pinned Wasmi
source. E1 freezes its identity and configuration only; no package, current
engine, executor, admission path, migration, production authority, or release
exists yet.

| Node | Exit gate |
|---|---|
| C8.13-E1 | Freeze code/ABIs 10, profile 7, revisions, engine, world, semantics, non-promotion, and fixed-QEMU policy |
| C8.13-E2 | Implement the executor, current-engine binding, sealed authority-free volatile admission/lifecycle, durable rejection, supply-chain closure, and RISC-V audit |
| C8.13-E3 | Pass fresh normal and optimized fixed-QEMU evidence before releasing only the sealed volatile code-10 runtime |

Code 5 remains permanently inert. Code 7 remains validation-only. Code 9
remains validation-only, non-current, non-executable, and non-migratable. Code
8 retains exactly its prior SIMD scope. Fixed QEMU is emulator-only; Milk-V
Duo remains paused, optional, and has zero gate effect.

The canonical design contract is
[`c813-reference-executable-design-v1-contract.json`](../acceptance/wasm-reference-target/artifacts/c813-reference-executable-design-v1-contract.json).
