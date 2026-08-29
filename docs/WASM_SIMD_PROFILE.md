# Deterministic SIMD profile

Status: `c810-s1-simd-design-frozen-pre-implementation`.

This document defines the independently numbered C8.10 widening. It is the
first unfinished non-Float C8.8 feature selected after C8.9 closure. C8.10-S1
freezes a validation-only identity and implementation gates; it does not add a
current engine, executable artifact, admission route, release, or production
authority.

## Frozen identity

| Field | Value |
|---|---|
| Name | `PROFILE_4_SYNC_SIMD_VALIDATION` |
| Artifact profile code | 7 |
| Artifact ABI | 7 |
| Runtime ABI | 7 |
| Component profile | 4 |
| Core profile | 4 |
| Stage | `ValidationOnly` |
| Core revision | `webassembly-core-2.0-fixed-width-simd-1.0-deterministic-software-float-c810-v1` |
| Component revision | `wasmparser-component-model-0.255.0-c810-simd-validation-v1` |
| Canonical ABI revision | `component-model-0.255.0-sync-float-values-no-v128-boundary-c810-simd-validation-v1` |
| WIT world | `vibe:simd/validation@1.0.0` |
| Sole export | `run(mode: u32, input: list<u8>) -> list<u8>` |
| Imports | none |

Code 7 is deliberately absent from the runtime codec and current-engine
resolver in S1. Implementation belongs to later nodes. Code 5 remains
permanently `ValidationOnly`, inert, and non-migratable. Code 6 remains the
released scalar-Float executable identity and does not gain SIMD.

## Semantic boundary

C8.10 selects fixed-width WebAssembly SIMD 1.0 only. `v128` is an internal Core
value: it cannot appear in a public WIT type, Canonical ABI flat value, host
import, or host export. The byte-list test world is an authority-free envelope,
not a `v128` ABI extension.

Integer lanes use WebAssembly lane-width wrapping and saturation rules. Vector
transport preserves all 128 bits. Scalar and lane floating-point operations use
deterministic software float; numeric NaN results become the fixed positive
quiet NaN for their lane width while transport operations preserve bits.
Relaxed SIMD is forbidden. Reference types, exceptions, memory64, multiple
memories, GC, threads, and shared memory remain disabled.

The selected S2 engine identity is
`vibeos-wasmi-simd-softfloat@1.1.0-vibeos-simd1.1`, derived from the frozen
`vibeos-wasmi-softfloat@1.1.0-vibeos-f2.1` source tree. It does not exist as a
bound runtime in S1. S2 must remove `libm` and host-float dependence from every
fixed-SIMD lane operation, reuse the reviewed software-float backend, make
relaxed SIMD unrepresentable, freeze fuel, retain `no_std + alloc`, and prove
the RISC-V output contains no F, D, or V instructions or semantic helper
symbols.

## Ordered nodes

| Node | Exit condition |
|---|---|
| C8.10-S1 | Freeze code 7, ABI/revisions, semantics, engine design, authority boundary, and target policy |
| C8.10-S2 | Implement and audit the independent deterministic Core SIMD engine and supply chain |
| C8.10-S3 | Prove Component containment plus fixed differential and fuzz corpora; `v128` remains Core-internal |
| C8.10-S4 | Close default-off candidate admission, quota, lifecycle, recovery, and durable rejection |
| C8.10-S5 | Pass fresh normal/optimized fixed-QEMU qualification and decide only successor-review eligibility |

The fixed target gate is `qemu-virt-rv64-tcg-icount-v1` with fresh source/tree,
suite, challenge, run ID, capture, predicates, and normal/optimized
verification. Historical Float evidence cannot satisfy a C8.10 gate. Milk-V
Duo remains paused and optional, supplies zero inputs, and has no gate,
completion, or release effect. Emulator qualification is not physical-hardware
equivalence.

The canonical design contract is
[`c810-simd-widening-design-v1-contract.json`](../acceptance/wasm-simd-target/artifacts/c810-simd-widening-design-v1-contract.json).
Verify it with:

```sh
python3 -B scripts/verify-c810-simd-widening-design.py --check-contract
python3 -O -B scripts/verify-c810-simd-widening-design.py --check-contract
python3 -B scripts/verify-c810-simd-widening-design.py --selftest
python3 -O -B scripts/verify-c810-simd-widening-design.py --selftest
```
