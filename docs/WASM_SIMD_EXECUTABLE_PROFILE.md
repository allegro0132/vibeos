# Executable SIMD successor profile

Status: C8.11 closed at `c811-s3-qualified-sealed-simd-runtime-released`; the
live roadmap is `c812-r1-reference-types-validation-design-frozen-pre-implementation`.

C8.11 allocates an executable successor to the completed code-7 fixed-width
SIMD validation program. It is a new identity, not an in-place promotion or
reinterpretation of code 7. C8.11-S1 froze the design. C8.11-S2 now implements
the code-8 codec, exact current engine, authority-free volatile admission,
lifecycle/accounting, and durable rejection. C8.11-S3 now passes fresh normal
and optimized fixed-QEMU verification and releases only this sealed volatile
code-8 admission path. Durable publication and ordinary command integration
remain closed.

## Frozen identity

| Field | Value |
|---|---|
| Name | `PROFILE_5_SYNC_SIMD_EXECUTABLE` |
| Artifact profile code | 8 |
| Artifact ABI | 8 |
| Runtime ABI | 8 |
| Component profile | 5 |
| Core profile | 5 |
| Stage | `Executable` |
| Core revision | `webassembly-core-2.0-fixed-width-simd-1.0-deterministic-software-float-c811-exec-v1` |
| Component revision | `wasmparser-component-model-0.255.0-c811-simd-exec-v1` |
| Canonical ABI revision | `component-model-0.255.0-sync-float-values-no-v128-boundary-c811-simd-exec-v1` |
| wasm-tools revision | `wasm-tools-v1.255.0-76e20611d1920a7a39ca08983c6c77c3060de380` |
| WASI revision | `wasi-not-selected-c811-sync-simd` |
| WIT world | `vibe:simd/runtime@1.0.0` |
| Sole export | `run(mode: u32, input: list<u8>) -> list<u8>` |
| Imports | none |

Profile code, artifact ABI, and runtime ABI 8 are deliberately fresh. A code-7
artifact remains validation-only forever and cannot become executable after an
upgrade. Code 5 remains permanently inert and non-migratable. Code 6 retains
its existing scalar-Float release scope and gains no SIMD.

## Frozen semantics and engine

The successor retains the qualified fixed-width SIMD 1.0 semantics: integer
lane wrapping and saturation, bit-exact 128-bit transport, deterministic
software-float lanes, fixed positive quiet NaNs for numeric results, and bit
preservation for transport operations. Relaxed SIMD remains forbidden.
Reference types, exceptions, memory64, multiple memories, GC, threads, and
shared memory remain disabled.

`v128` remains a Core-internal value. It cannot appear in WIT, Canonical ABI
flat values, host imports, or host exports. The byte-list world is an
authority-free envelope and does not widen the Component boundary.

C8.11-S1 selected
`vibeos-wasmi-simd-executable-softfloat@1.1.0-vibeos-simd2.1`, derived from the qualified
`1.1.0-vibeos-simd1.1` tree at predecessor commit
`2038c3134fe94d1ca297764c9fd8ee7d39a24123`. S2 materializes it as a two-file,
no-std facade over that exact 168-file audited base closure and binds only code
8 to the current engine. The separate `vibeos-wasm-simd-executable` wrapper
keeps relaxed SIMD disabled and remains `production_ready: false` until S3.
The `riscv64imac-unknown-none-elf` object audit finds no semantic LLVM floating
operations, FP helpers, or F/D/V instructions in the complete executable
closure.

Admission is exact-image-pinned, import-free, resource-free, and caller-
authority-free. It accepts only `vibe:simd/runtime@1.0.0`, one 64-KiB Core
instance, the exact compile reservation, and the canonical `run` lift. The
admitted token is move-only and exposes neither durable nor ordinary-command
conversion. Fuel exhaustion, cancellation, fault recovery, revocation, and
instance reclamation are covered by the S2 lifecycle tests. Code 5 remains
permanently inert; code 7 remains non-current and non-migratable.

## Ordered nodes

| Node | Exit condition |
|---|---|
| C8.11-S1 | Freeze code/ABIs 8, profile 5, exact revisions, world, engine, semantics, non-promotion, and target policy |
| C8.11-S2 | Implement the code-8 codec, exact current engine, admission/lifecycle, durable rejection, supply-chain closure, and RISC-V audit |
| C8.11-S3 | Pass fresh source-bound normal and optimized fixed-QEMU qualification before any release decision |

The formal target is `qemu-virt-rv64-tcg-icount-v1`. C8.10 receipts cannot be
relabeled as C8.11 evidence. S3 requires a fresh source commit/tree, challenge,
run ID, capture, node-specific predicates, and normal/optimized verification.
Milk-V Duo remains paused, optional, and non-gating, contributes zero input,
and is not claimed equivalent to the emulator. Other hardware gates remain
unchanged.

The canonical S1 contract is
[`c811-simd-successor-design-v1-contract.json`](../acceptance/wasm-simd-target/artifacts/c811-simd-successor-design-v1-contract.json).
Verify it with:

```sh
python3 -B scripts/verify-c811-simd-successor-design.py --check-contract
python3 -O -B scripts/verify-c811-simd-successor-design.py --check-contract
python3 -B scripts/verify-c811-simd-successor-design.py --selftest
python3 -O -B scripts/verify-c811-simd-successor-design.py --selftest
```

The canonical S2 contract is
[`c811-simd-successor-implementation-v1-contract.json`](../acceptance/wasm-simd-target/artifacts/c811-simd-successor-implementation-v1-contract.json).
Its verifier, supply-chain audit, RISC-V object audit, and Rust tests are listed
in [TESTING.md](../TESTING.md). Passing S2 means only “implemented and ready
for fixed-QEMU qualification”; it does not authorize release or production.

## C8.11-S3 qualification and release

The formal campaign binds pushed source commit
`90f95df4503a3992067fa68dbcd7d9dd9485ef10`, tree
`2ab8ca62c1a37dd766c86d2fd8fd9d5f873927cd`, run ID
`c7404023823bea9027e0c55bd564a062dc591974dd7385bd8957a4b4c3d61de8`,
seven semantic records, and semantic SHA-256
`ddab9d539744523b332787be6f8a101de00108479c9644136538524f20cd4514`.
Normal and optimized verification and the final-ELF audit pass. The release is
limited to exact-image-pinned, authority-free, volatile code-8 admission. Code
5 remains permanently inert; code 7 remains validation-only, non-current, and
non-migratable. Milk-V Duo contributed zero inputs and remains paused and
non-gating; no physical equivalence is claimed.
