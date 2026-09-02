# C2.7 host reference provenance

`c27_component_reference.rs` uses Wasmtime only as a benign, host-only
Component Model execution reference for the two C2.3 cross-language fixtures.
Vibe performs its own Profile-1 inspection and exact-world check before the
same derived Component bytes are handed to Wasmtime. Wasmtime is not an
admission oracle, is not linked into the VibeOS target, does not widen Profile
1, and is not evidence that hostile Components are safe to admit.

The reference dependency is the exact crates.io package `wasmtime` 48.0.0:

| Field | Pin |
|---|---|
| Upstream repository | `https://github.com/bytecodealliance/wasmtime` |
| Release tag | `v48.0.0` |
| Release commit | `f1412a598f96f3c261a19118d94caffcb0c36235` |
| crates.io package SHA-256 | `f12115b509def01c338ec8ee9b52c4cefb27f7b8db57279c5c7cfe2e9eaf9900` |
| Direct features | `component-model`, `cranelift`, `runtime`, `std` (default features disabled) |
| Declared Rust version | `1.95.0` |
| License | `Apache-2.0 WITH LLVM-exception` |

The full commit is recorded by the published crate's `.cargo_vcs_info.json`,
and the package digest is pinned by `Cargo.lock`. The official immutable
release page also identifies `v48.0.0` with that commit:

`https://github.com/bytecodealliance/wasmtime/releases/tag/v48.0.0`

The test enables Wasmtime's Component Model and fuel instrumentation, uses an
empty linker, sets and observes a finite fuel balance for every call, and
compares Wasmtime's dynamic `Val` result with both Vibe and a neutral expected
representation. The four-case corpus and its digest remain the C2.3 pins; this
test adds an independent implementation, not a new corpus or a general
conformance claim.
