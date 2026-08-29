# Deterministic SIMD profile

Status: `c810-s3-simd-contained-corpora-passed-pre-admission`.

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

Code 7 is now encoded/decoded and has a sealed validation contract, but remains
deliberately absent from the current-engine resolver. Code 5 remains
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

The implemented S2 engine identity is
`vibeos-wasmi-simd-softfloat@1.1.0-vibeos-simd1.1`, derived from the frozen
`vibeos-wasmi-softfloat@1.1.0-vibeos-f2.1` source tree. S2 removes `libm` and
host-float dependence from fixed-SIMD lane operations, reuses the reviewed
software-float backend, disables relaxed-SIMD validation, freezes Wasmi's
unit-per-instruction/64-bytes-per-fuel schedule, and retains `no_std + alloc`.
The pinned RISC-V audit passes across the complete candidate closure with no
semantic LLVM FP, runtime float helper, or RISC-V F, D, or V instruction.

The default-off `vibeos-wasm-simd-candidate` exercises integer, saturating,
shuffle, memory, floating-lane, repeatability, adjacent-feature rejection, and
exact fuel boundaries. It is acceptance-only, import-free, not production
ready, and supplies no current engine. C8.10-S3 now proves that `v128` remains
embedded-Core-only and pins separate 512-case differential and mutation
corpora. Production admission and lifecycle remain C8.10-S4 work.

## Ordered nodes

| Node | Exit condition |
|---|---|
| C8.10-S1 | Freeze code 7, ABI/revisions, semantics, engine design, authority boundary, and target policy |
| C8.10-S2 | Complete: independent deterministic Core SIMD engine, supply chain, fuel, and RISC-V object audit |
| C8.10-S3 | Complete: Component containment plus fixed differential and fuzz corpora; `v128` remains Core-internal |
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

The canonical S2 implementation contract is
[`c810-simd-widening-implementation-v1-contract.json`](../acceptance/wasm-simd-target/artifacts/c810-simd-widening-implementation-v1-contract.json).
Verify it and its engine closure with:

```sh
python3 -B scripts/verify-c810-simd-widening-implementation.py --check-contract
python3 -O -B scripts/verify-c810-simd-widening-implementation.py --check-contract
python3 -B scripts/verify-c810-simd-widening-implementation.py --selftest
python3 -O -B scripts/verify-c810-simd-widening-implementation.py --selftest
python3 scripts/verify-c810-s2-supply-chain.py --self-test
python3 scripts/verify-c810-s2-riscv-object.py
cargo test --locked --offline -p vibeos-wasm-simd-candidate --features c810-s2-acceptance
```

The canonical S3 containment/corpus contract is
[`c810-simd-containment-corpus-v1-contract.json`](../acceptance/wasm-simd-target/artifacts/c810-simd-containment-corpus-v1-contract.json).
Verify it with:

```sh
python3 -B scripts/verify-c810-simd-containment-corpus.py --check-contract
python3 -O -B scripts/verify-c810-simd-containment-corpus.py --check-contract
python3 -B scripts/verify-c810-simd-containment-corpus.py --selftest
python3 -O -B scripts/verify-c810-simd-containment-corpus.py --selftest
cargo test --locked --offline -p vibeos-component-runtime --features c810-s3-acceptance --test c810_s3_simd_containment
```
