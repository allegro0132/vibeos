# Isolated Cranelift feasibility check

This independent workspace pins Cranelift 0.135.1 and disables default crate
features. It is not linked into the kernel or root workspace.

```sh
cargo check --locked --offline \
  --manifest-path wasm-rv64/experiments/cranelift-no-std/Cargo.toml \
  --target riscv64imac-unknown-none-elf -Zbuild-std=core,alloc
python3 scripts/test-cranelift-rv64.py
```

The no_std check now includes actual code-generation logic. The host emitter
builds a wrapping integer loop with a wide integer constant. QEMU/OpenSBI runs
500 independent C-oracle cases for each variant under SV39:

- Inline constant: arithmetic passes on an RX page. Changing that page to
  execute-only produces the expected load page fault at its constant pool.
- External constant: 500 cases pass with execute-only generated code and the
  literal on a separate read-only page. MXR, floating-point state and vector
  state are disabled during execution. Its full 52-byte leaf instruction
  stream is checked against a probe-specific RV64IM whitelist, with writes
  restricted to caller-saved registers. Neither variant has external
  relocations or compiler-declared hardware traps.

Cranelift's ISA constructor rejects disabling F/D because it currently
requires G configuration. Thus the constructor itself is not an IMAC-only
admission check: every future generated function still needs an appropriate
ISA guarantee. The probe whitelist is intentionally not a general verifier.
Likewise, supplying an external literal solves this probe's execute-only
constraint, not all possible constant/jump-table emission in a full backend.

Evidence: `target/cranelift-rv64-external-audited/` contains the raw generated
bytes, linked ELF, disassembly, QEMU log, identities and hashes. The cross-check
log is `target/coremark-performance/cranelift-codegen-no-std-check.log`.

Before integration, validate non-leaf ABI/stack behavior, compiler stack and
allocation bounds, all emitted ISA features and constant-pool forms, and
WASI fuel/trap/continuation handling. These probes do not establish a CoreMark
speedup or satisfy the Debian-relative performance goal.

Sources: [Cranelift 0.135.1 API](https://docs.rs/cranelift-codegen/0.135.1/cranelift_codegen/),
[upstream codegen features](https://github.com/bytecodealliance/wasmtime/blob/main/cranelift/codegen/Cargo.toml).

The bounded `wasmi` lowering prototype now executes actual Wasmi IR on QEMU.
`target/cranelift-wasmi-probe/results.json` records 200 additional execute-only
cases covering I32 arithmetic/copies, a fuel-metered backward branch, exhaustion
at the original PC, split-budget resumption, unsupported-operation fallback, and
frame reload after an interpreter-side edit. This is still not kernel integration:
constant slots, guest memory operations, broader opcode coverage, general emitted
ISA/ABI validation, and compiler allocation bounds remain open. The existing
500 RX and 500 external-literal XO cases also pass; inline constant pools still
fault as expected on XO pages with MXR disabled.
