# C8.10-S2 fixed-SIMD software-float fork

This directory is the identity-isolated, acceptance-only code-7 engine fork.
It derives from Wasmi 1.1.0 commit
`8273dfb09d493971b7bb12fe614d740cdc857175` and retains the independently
audited `rustc_apfloat` backend from the scalar-float predecessor.

All four Cargo packages have new `vibeos-*-simd-softfloat` identities and the
version `1.1.0-vibeos-simd1.1`. No workspace Cargo patch redirects stock Wasmi.
Only `wasm-simd-candidate` can reach this fork, and only behind its default-off
`c810-s2-acceptance` feature.

The fork removes the upstream SIMD-to-`libm` edge. Fixed SIMD floating-point
lanes call the same bit-oriented APFloat wrappers as scalar Core operations.
The relaxed-SIMD implementation is compiled but deterministic; validation
explicitly disables the relaxed proposal, so those operators are unreachable.
The public V128 boundary is an integer bit pattern with explicit little-endian
conversion.

The content digest in `PROVENANCE.toml` covers every fork crate manifest,
README, source, license, and third-party notice. It excludes the provenance
files themselves, the pristine upstream manifest, Cargo locks, and build
outputs to avoid circular or environmental inputs.

Verification is offline:

```sh
python3 scripts/verify-c810-s2-supply-chain.py --self-test
python3 scripts/verify-c810-s2-riscv-object.py
```

The first command binds package graph, content, code-7 inertness, code-5
permanent inertness, and deterministic SIMD mappings. The second uses the
pinned Rust/LLVM toolchain to prove that the complete RISC-V candidate closure
contains no semantic LLVM floating-point operation, no float helper, and no
RISC-V F, D, or V instruction.
