# C8.8 deterministic scalar-float profile

**Status (2026-08-29): C8.8-F1 complete as contract metadata only.** F1 is
the first of five ordered Float increments. It freezes an immutable
validation-only artifact identity and the semantic requirements for a future
deterministic software-float implementation. It does not validate or execute a
Float instruction, expose a Float value through WIT, activate admission, or
claim that cross-target determinism has been demonstrated. C8.8-F2 is next;
Float and C8.8 remain incomplete.

Milk-V Duo physical testing remains paused at operator request. Fixed QEMU is
the selected target for the later F5 emulator qualification; it is not needed
and was not used for F1.

## 1. Frozen identity

The following dimensions are distinct and are all part of the closed F1
contract:

| Field | Exact value |
|---|---|
| CMP1 artifact profile code | `5` |
| Artifact ABI | `5` |
| Component profile | `2` |
| Core profile | `2` |
| Runtime ABI field | `5` |
| Core revision | `webassembly-core-2.0-scalar-f32-f64-deterministic-software-float-v1` |
| Component revision | `wasmparser-component-model-0.255.0` |
| Canonical ABI revision | `component-model-0.255.0-sync-float-values-deterministic-software-float-v1` |
| wasm-tools revision | `wasm-tools-v1.255.0-76e20611d1920a7a39ca08983c6c77c3060de380` |
| WASI revision | `wasi-not-selected-sync-float` |
| Stage | `ValidationOnly` |
| Newly selected Core scalar types | `f32`, `f64` only |
| Canonical ABI feature addition | `FloatValues` only |

The profile code, ABI numbers, CMP1 format version, and the five revision
strings in the artifact contract are separate version axes. Equal numeric
values do not make them interchangeable.

Profile 1 remains permanently integer-only. None of its identities, feature
vectors, dependency checksums, or current engine bindings are widened by this
contract.

## 2. Permanent inertness of code 5

Code 5 is an inspection and exact CMP1 encode/decode identity only. These are
permanent change-control requirements:

- `execution_enabled()` is false and the stage remains `ValidationOnly`;
- `current_validation_engine_identity(PROFILE_2_SYNC_FLOAT)` returns `None`;
- the sealed F1 metadata contract reports `runtime_ready=false`;
- the metadata contract names a target configuration but contains no frontend
  or runtime package, source, revision, or checksum identity;
- the CGV1 durable graph constructor and decoder reject code 5;
- loader admission, durable installation/publication, command construction,
  and guest invocation have no code-5 activation path.

F2 through F5 must not promote code 5 in place. If the complete Float evidence
eventually passes, an executable successor must receive a new profile code,
artifact ABI, runtime ABI, and exact engine identity. Its number is deliberately
not allocated by F1.

## 3. Exact deterministic NaN policy

This profile requires one exact result, not the WebAssembly specification's
broader allowed set of canonical or arithmetic NaNs:

- the only canonical `f32` quiet NaN is positive `0x7fc0_0000`;
- the only canonical `f64` quiet NaN is positive
  `0x7ff8_0000_0000_0000`.

If `add`, `sub`, `mul`, `div`, `ceil`, `floor`, `trunc`, `nearest`, `min`,
`max`, `sqrt`, `promote`, or `demote` produces or propagates a NaN, the result
must be the fixed positive canonical quiet NaN for its width. Compile-time
constant folding of those numeric operations must produce exactly the same
bits as runtime execution.

Pure Core value transport preserves every bit, including the NaN sign and
payload. This includes constants, loads, stores, reinterpret operations,
locals, globals, `select`, and Core calls and returns. Comparisons produce the
WebAssembly-specified integer result without modifying either operand.

Component-level `f32` and `f64` each have one abstract NaN value, unlike
Core's many NaN bit patterns. Therefore every Component/Canonical ABI boundary,
including scalar or nested lift/lower and Component calls/returns, collapses a
lifted Core NaN to that one value and emits the fixed positive canonical bits
when lowering it. The same rule applies to Component binary value encoding.
This follows the bound Component Model revision's
[fundamental numeric value semantics](https://github.com/WebAssembly/component-model/blob/main/design/mvp/Explainer.md#fundamental-value-types).

The sign-only operations preserve exponent, quiet bit, and payload:

- `abs` clears only the sign bit;
- `neg` toggles only the sign bit;
- `copysign` replaces only the left operand's sign with the right operand's
  sign.

The `ConstantFold` policy class applies only to folds of the canonicalizing
numeric operations. Folding transport or sign-only operations keeps their
respective bit-preserving or sign-only disposition. Accepting any NaN from an
allowed set, canonicalizing transported Core values, preserving an arbitrary
payload across a Component/Canonical ABI boundary, or changing a sign-only
operation's payload fails the profile.

For non-NaN values, the future implementation must provide WebAssembly's exact
rounding behavior, including round-to-nearest ties-to-even, signed zero,
`min`/`max`, and subnormals. Fast-math, fused-operation contraction, FTZ/DAZ,
and dependence on ambient host-FPU state are forbidden. Numeric comparison,
integer conversion, and finite promote/demote must use the same reviewed
deterministic backend. SIMD, relaxed SIMD, saturating float-to-integer,
references, exceptions, memory64, multiple memories, GC, and threads remain
disabled adjacent features.

## 4. Ordered implementation gates

| Increment | Scope | Exit gate |
|---|---|---|
| C8.8-F1 | Contract and identity | Exact code-5 artifact round-trip, adjacent-field rejection, strict NaN metadata, unchanged Profile 1, no current engine, and durable graph rejection |
| C8.8-F2 | Deterministic Core validation and execution | Independently identified reviewed software-float engine; all scalar instructions, translator folds, traps, limits, differential corpus, fuzzing, and fuel/quantum evidence pass while code 5 stays inert |
| C8.8-F3 | WIT and Canonical ABI `f32`/`f64` | Exact flat/lift/lower, memory, nested-value, realloc/cleanup, differential, and hostile-input evidence pass without adding ambient authority |
| C8.8-F4 | Default-off admission and lifecycle | Loader/image policy, quotas, revoke/cancel, fault reclamation, durable rejection, and explicit candidate-only activation tests pass; production code 5 remains inert |
| C8.8-F5 | Target qualification and activation review | Host and fixed-QEMU exact-bit/fuel evidence pass; physical-Duo qualification follows when resumed; only then may a separately numbered executable successor be reviewed |

An increment is not complete merely because a later layer can be sketched or
compiled. Each increment is verified, committed, and pushed independently.

## 5. F2 dependency and trap gates

F2 must not use a workspace-wide `[patch.crates-io]` replacement for Wasmi.
Profile 1 must continue to resolve its existing crates.io `wasmi` 1.1.0 package
and checksum. The software-float candidate must have a disjoint dependency
identity, preferably a renamed package or a dependency alias backed by a
separate reviewed Git/vendor source.

The F2 candidate identity must record at least the package name and version,
source URL or vendored provenance, exact commit/tree or content checksum,
feature set, patch/diff digest, software-float backend and checksum, and the
transitive `wasmi_core`, IR, and parser identities. This identity is added in
F2; it is deliberately absent from the sealed F1 metadata and must not enter
the production current-engine resolver while code 5 remains inert.

The F1 target setting vector freezes the Wasmi 1.1.0 default fuel schedule as
the candidate schedule. F2 must prove that the independent fork preserves it.
A different schedule requires a new reviewed contract and cannot silently
reinterpret code 5.

The current Profile-1-only runtime maps Wasmi's
`BadConversionToInteger` to the static `Validation` trap because Float is
guest-unreachable. Before any F2 candidate executes Float, it must select and
ABI-version a stable guest execution trap for NaN and out-of-range
float-to-integer truncation. Tests must cover positive and negative overflow
and NaN for every `f32`/`f64` to `i32`/`i64`, signed and unsigned truncating
instruction. The saturating-conversion proposal remains rejected. This trap
gate must close before F2 can complete.

## 6. F1 evidence and non-claims

The F1 host gate proves the exact profile/codec metadata, NaN constants and
operation classification, Profile-1 non-widening, absence from the current
engine resolver, and graph fail-closed behavior. Mutations of code, stage, ABI,
revision, feature bit, or adjacent profile fields are rejected.

F1 provides no reviewed software-float backend, Float validator or executor,
runtime values, WIT/Canonical ABI implementation, execution trap, differential
or fuzz corpus, fuel proof, QEMU result, or physical result.
`cross_target_bit_determinism_required=true` is a future acceptance
requirement, not current evidence.
