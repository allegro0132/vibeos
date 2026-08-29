# C8.8 deterministic scalar-float profile

**Status (2026-08-29): C8.8-F1 through C8.8-F4 are complete. F5 remains open;
its host/fixed-QEMU sub-gate and Duo compile-readiness slice pass.** F1 freezes
the immutable validation-only artifact identity and deterministic semantic
contract. F2 supplies an independently identified, acceptance-only Core
validator and software-float executor behind `c88-f2-acceptance`; it does not
bind profile code 5 to a current engine or production activation path.
F3 supplies an acceptance-only, bit-represented WIT and Canonical ABI codec
behind `c88-f3-acceptance`; the production Profile-1 codec still rejects every
scalar-float shape. Its allocation evidence is a codec request/byte trace
replayed through the existing cleanup machine, not runtime wiring. F4 adds a
separate default-off candidate admission and lifecycle behind acceptance-only
feature gates; the image adapter binds that lifecycle to one exact image pin.
It does not add a production command, durable object/publication, or
current-engine binding. The latest non-physical F5 work passes at pushed
implementation commit `c4ea5e5ca1de622884f33c01bf06653f498360aa`.
Milk-V Duo physical qualification remains paused and unclaimed, so F5, Float,
and C8.8 are not fully closed and no executable successor is authorized.

Milk-V Duo physical testing remains paused at operator request. Fixed QEMU is
the selected target for F5 emulator qualification and has formal execution
evidence; it was not used for F1 through F4. The Duo readiness image was only
cross-linked and statically audited: it was not packaged, flashed, booted, or
captured, and it claims neither physical nor source-build provenance. F4
evidence remains host-only. The RISC-V evidence through F3 remains compile-
and object-level evidence rather than a QEMU or physical execution claim.

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
- production loader admission, durable installation/publication, command
  construction, and production guest invocation have no code-5 activation
  path. Explicit default-off acceptance harnesses do not alter this identity
  or register it with a production resolver.

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

For non-NaN values, the F2 candidate provides WebAssembly's exact rounding
behavior, including round-to-nearest ties-to-even, signed zero,
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
| C8.8-F5 | Target qualification and activation review | Host and fixed-QEMU exact-bit/fuel evidence plus inert Duo compile readiness pass; three operator-confirmed physical-Duo cold boots remain required when testing resumes; only then may a separately numbered executable successor be reviewed |

An increment is not complete merely because a later layer can be sketched or
compiled. Each increment is verified, committed, and pushed independently.
F1 through F4 have closed their respective gates. F5's host/fixed-QEMU sub-gate
has passed, while its paused physical-Duo sub-gate prevents full closure.

## 5. Closed F2 dependency and trap gates

F2 does not use a workspace-wide `[patch.crates-io]` replacement for Wasmi.
Profile 1 must continue to resolve its existing crates.io `wasmi` 1.1.0 package
and checksum. The candidate uses separately renamed, vendored Wasmi packages
at upstream commit `8273dfb09d493971b7bb12fe614d740cdc857175`, fork version
`1.1.0-vibeos-f2.1`, patched content-manifest SHA-256
`2d94218e4fa5eea30b8e516e055fae8f72465dbc1ef75f8b1df3495cbcd0432f`,
and patch-delta SHA-256
`3d2aec1d7e510fc3b3edb87dcacb2d4ed34eb448356704a027841b047938ec64`.
The exact archive, manifest, license, dependency, source, and Profile-1
isolation identities are frozen in `vendor/wasmi-softfloat/PROVENANCE.toml`.

The backend is `rustc_apfloat 0.2.3+llvm-462a31f5a5ab` at Git revision
`eeaacad81247af65d4043cb3e32d023a652d7951`, with archive SHA-256
`486c2179b4796f65bfe2ee33679acf0927ac83ecf583ad6c91c3b4570911b9ad`.
Square root is a pure-integer, fixed 24-round (`f32`) or 53-round (`f64`)
restoring algorithm with exact midpoint comparison. The selected fork closure
has SIMD disabled and no selected `libm` edge. Profile 1 continues to use the
unchanged stock crates.io Wasmi identity.

The independent fork preserves the F1 target setting vector and Wasmi 1.1.0
default fuel schedule. Float and integer instructions use the same base-cost
schedule, and deterministic resumable-call tests pin repeated quantum traces,
total fuel, terminal cleanup, and recovery after a Float trap.

The current Profile-1-only runtime still maps Wasmi's
`BadConversionToInteger` to static `Validation` because Float is
guest-unreachable there. The F2 candidate maps quiet and signaling NaN
truncation to the new stable `InvalidConversionToInteger` trap (`0x0207`) and
keeps finite overflow and positive or negative infinity on `IntegerOverflow`
(`0x0202`). Runtime and translator-fold fixtures cover all eight
`f32`/`f64` to `i32`/`i64`, signed and unsigned truncating instructions,
including exact valid boundaries and adjacent overflow. The
saturating-conversion proposal remains rejected.

## 6. F1/F2/F3/F4/F5 evidence and non-claims

The F1 host gate proves the exact profile/codec metadata, NaN constants and
operation classification, Profile-1 non-widening, absence from the current
engine resolver, and graph fail-closed behavior. Mutations of code, stage, ABI,
revision, feature bit, or adjacent profile fields are rejected.

The F2 host gate covers every scalar arithmetic, comparison, rounding,
conversion, reinterpretation, and sign-only instruction in runtime and
translator-fold paths; constant/local/global/load/store/select/call transport;
strict canonical NaNs; fused compare/branch/select paths; Profile-1 limits;
import denial; stable traps; and fuel/quantum behavior. A fixed-seed 50,000-case
host IEEE differential corpus has digest `0x05e1fa8e3d779f53`. A separate
4,096-case end-to-end candidate-Wasmi fuzz corpus has digest
`0xee61731687e8c81d`; mutated and random hostile Core bytes have digest
`0xb8eca6402ca6a5df`. The offline supply-chain verifier also proves five
fail-closed mutations.

The pinned `riscv64imac-unknown-none-elf` release build passes an object-level
audit of the candidate fork, `rustc_apfloat`, and acceptance crate: no semantic
FP arithmetic, comparison, conversion, `sqrt`, compiler float helper, or
RISC-V F/D instruction remains. LLVM sign-only `fneg`, `fabs`, and `copysign`
forms lower exclusively to integer bit operations. This is cross-target
implementation evidence; exact-bit target execution is separately supplied by
the F5 qualification in section 7.

F3 adds `CanonicalF32`/`CanonicalF64` and a separate
`CandidateFlatValue::{F32Bits,F64Bits}` representation; production
`CoreValue`, current engine bindings, and the Profile-1 codec are unchanged.
All NaNs collapse by integer masks to the fixed positive quiet-NaN bits at
flat and memory Component boundaries, while finite values, infinities, signed
zero, and subnormals retain their exact bits. The candidate covers direct and
indirect calls, variant joins, nested record/list/result values, bounds and
alignment, protected return areas, and fixed-capacity allocation journals. Its
exact payload request/byte trace is replayed through the unchanged
`CanonicalMachine`, covering successful cleanup, abort, uncertain realloc,
and failed free/discard paths without claiming a runtime connection.

The pinned Wasmtime 48 differential fixture executes import-free scalar and
nested-record Component boundaries in both bit directions. It observes the
reference raw bits and compares the candidate after an independent integer
NaN oracle. A 4,096-case scalar bit corpus is pinned by digest
`0x8ebf9db2d4472f51`; a separate 4,096-case nested hostile-memory corpus is
pinned by `0x93ce1dbfabf6b333`. The candidate Component plan has no imports,
host imports, executable exports, or runtime-ready state. The same build also
proves that default WIT parsing and the production Canonical ABI continue to
reject scalar Float, while the synchronous candidate rejects adjacent async
functions, futures, and streams.

The F3-specific offline RISC-V verifier binds a 29-rlib target closure by
digest `c2295c33c17e489953cf014cb7f5acef9b0f674b4fd09142ba2dcc492736f618`
and scans 126 LLVM/native objects. The complete closure has no RISC-V F/D
opcode; the three workspace-owned artifacts must remain 29 LLVM-bitcode
objects and have no LLVM floating-point type or transport, semantic operation,
float helper, or float symbol. The stock
Profile-1 `libm`/Wasmi software-float objects are recorded as an unchanged
inherited baseline rather than attributed to the dependency-free F3 feature.

F3 itself provides no direct candidate-to-runtime allocator wiring or image
admission. F4 closes that separate acceptance boundary with one immutable
image pin:

- component SHA-256
  `5fdb9dc9a48a9c54e899a5dc724445083c055dbf0d664927ba55d9780cc9996a`;
- WIT world `vibe:float-acceptance/lifecycle@1.0.0` and sole synchronous export
  `run(mode: u32, left: f32, right: f64) -> f64`;
- image/adapter feature `c88-f4-float-candidate` and admission/runtime feature
  `c88-f4-acceptance`, all default-off;
- exactly one embedded module, one Core instance, one Canonical function, no
  imports or host imports, no resources, and no caller authority;
- a 131,072-byte memory ceiling, 100,000 total fuel, 100-fuel poll quantum,
  zero resources, and a fresh exact compile reservation derived from the sole
  embedded module.

The activation label `c88-f4-float-candidate` is candidate metadata, not a
command name or command manifest. The sealed image projection reparses the
independently pinned WIT, obtains a move-only candidate admission receipt,
revalidates a fresh plan, derives the compile reservation, and connects the F3
bit-only Canonical values to the F2 candidate executor. A sealed decoder
sidecar independently resolves the sole Component `run` through its synchronous
Canonical lift to module 0, instance 0, and Core export `run`; it remains
separate from the empty ordinary execution plan. Same-signature lift-to-other
and unused-extra-wiring mutations fail before candidate compilation. The
projection exposes no artifact bytes, grants, durable graph,
`AdmittedComponent` conversion, VSH command, or production resolver
registration.

Host lifecycle tests preserve nonzero finite, signed-zero, subnormal, and NaN
boundary behavior. Each move-only lifecycle enforces at most one live instance
and rejects insufficient compile reservation, a below-minimum memory limit, zero or
adjacent-invalid fuel/quantum limits, nonzero resources, and adjacent image,
world, profile, label, topology, import, and authority inputs. Store-limit
tests grow memory exactly to the policy ceiling and trap the next growth;
finite-fuel execution checks every pending quantum, exhausts deterministically,
reclaims, and cold-recovers. Cancellation and other traps likewise drop the
complete candidate instance and require a cold `recover`; revocation is
absorbing and cannot recover. Reclamation counters prove one reclaim per
cancelled, faulted, or revoked live instance. The ordinary admission path still
rejects code 5, and both the durable production loader and CGV1
constructor/decoder reject it before command or publication creation.

F4 is explicit candidate-only activation evidence. Code 5 remains permanently
`ValidationOnly`, `execution_enabled() == false`, absent from both current
engine resolvers, and unavailable to production loading, durable
installation/publication, command construction, or guest invocation. F4 made
no fixed-QEMU execution claim; F5 owns that separate evidence. Physical-Duo
qualification remains paused. Any executable successor still requires a
separately numbered identity after F5 fully closes.

F4 does not establish a system-wide admission or concurrency ledger. The
memory, fuel, compile, resource, and one-live-instance ceilings are scoped to
each explicitly constructed acceptance lifecycle. A future production
successor must add and review any global owner/concurrency accounting under its
new identity rather than inferring it from this candidate harness.

## 7. F5 host, fixed-QEMU, and Duo compile readiness

The host and fixed QEMU execute the shared `no_std` `qualify()` routine. The
default-off Duo selector cross-links the same producer into a separate Milk-V
image envelope, but its immutable arm byte is zero. If accidentally booted it
fails closed before qualification and quiesces; the readiness workflow itself
performs no execution. The QEMU image feature
`wasm-c88-f5-float-qemu-acceptance` and Duo image feature
`wasm-c88-f5-float-duo-compile-readiness` are mutually exclusive, default-off,
and isolated from production, command, storage, network, USB, and SSH paths.
Neither registers code 5 with a current engine or production resolver.

The formal runner accepts only a clean `codex/wasm` worktree whose HEAD is
already equal to `refs/remotes/origin/codex/wasm`. It builds offline in a
private Cargo home and target directory, binds all 190 `Cargo.lock` registry
archives, rejects Git dependencies and ambient ancestor Cargo configuration,
disables Git replace objects, and records the exact pinned 3,603-file
`rust-src` tree. Its fixed platform is QEMU 11.0.3 plus the pinned OpenSBI image,
one RV64 CPU, one hart, 128 MiB, single-thread TCG, deterministic `icount`, and
no network device. Dirty smoke mode cannot export or verify formal evidence.

At pushed implementation commit
`c4ea5e5ca1de622884f33c01bf06653f498360aa` (tree
`ec7e1195b1a8ba4a88d37a817a9e0f64c4432016`), challenge
`8fb4bba646b9755b897d5dcbab0cb5724f0c2821b30ee99bbfe76c9a470fce9a`
produced the formal QEMU run ID
`08cf7c906917fb6a9d1b482f461f12abfc30339bd7136124ae609fa5568c1caa`.
The run accepted 1,176 records: 146 Core, 13 F3, 12 F4, 1,000 fuel, and 5
lifecycle. The semantic SHA-256 is
`51896391bb2a3493f1252e2633f54678bb1e69aa46a7e740dc4bc110381504f1`.
The exact retained identities are:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| Audited/booted QEMU kernel ELF | 40,449,184 | `0ef0ce1bf8f9aad1a5f35bbd783c94ea2fcfbc0fffc72285d5fe5efd781f146e` |
| QEMU UART transcript | 384,916 | `ede6c9fc7b68982f372762af51d4a786224c6a54c115ac50be7f7e5a4d8de621` |
| QEMU final-ELF audit | 2,031 | `cc70f99f265eb1fa767407b555d7324a7e49a4ed8d24b856859416f3557896af` |
| QEMU canonical environment | 84,839 | `3307451b5273f00d455ca95cea58e13e78dbcbea5e752a11274cc1abcff48fe6` |

The environment's complete evidence digest is
`6ad5d168efc32abf88bf982ef59decdd6eaa53f2c1a25d38f2d732c2a2eac8df`.
Both normal and optimized independent verifier runs accept the four retained
artifacts, and an optimized standalone audit regenerates the retained ELF
report byte-for-byte.

The final ELF is static, relocation-free, W^X, RV64 IMAC, RVC, and soft ABI.
The auditor finds 381,934 decoded instructions, 381,935 canonical boundaries,
42,010 trusted direct targets, 128,657 code symbols, and zero F/D opcodes,
undefined symbols, or forbidden Float helpers. Its native scan guarantee is
limited to trusted control flow at canonical decoder boundaries. It makes no
claim about arbitrary-PC redirection or hardware NX.

The same implementation commit freezes the default-off Duo suite
`vibeos.c88.f5.float-target.duo-v1` for platform
`milkv-duo-cv1800b-c906-v1`, stage `compile-only-inert-sentinel`, and binding
mode `reserved-non-evidence-sentinel`. Its checked-in identities are:

| Duo readiness artifact | Bytes | SHA-256 |
|---|---:|---|
| Contract manifest | 4,159 | `1c85f22cacee7c8eb7693578052fe0452169eace99f1dab06e08aa0e42771b11` |
| Transcript schema | 4,692 | `e25d9a38d194993906b7fe5ec9708654ea31e2386ac61f0fa360ed8ad1eb7439` |
| Locally observed cross-linked ELF | 40,331,520 | `e9a58e681c4d3e073dbeb1d15f569600e0ab2a97c07f13ed1dc0c676b5d62b1e` |
| Local final-ELF audit | 2,031 | `0b3384b35d85fdee970b98f523b7bd814102611549c08e7915625310954beac4` |

The reserved sentinel run ID is
`c5c8ec42e56fbeaf38106965e5ec6735cb86a93af530cd37f5002dba1971b4ac`,
and its immutable marker is `vibeos.c88.f5.duo.compile-readiness.arm=0`. The
Duo ELF audit finds 380,650 decoded instructions, 380,651 canonical
boundaries, 41,883 trusted direct targets, 128,210 code symbols, and zero
forbidden opcodes, Float helpers, or undefined symbols. The ELF SHA records
this local compile-readiness run; the verifier freezes the required structure
and embedded contract payload rather than globally pinning whole ELF bytes,
because source-build provenance is not claimed. Its result remains
`execution_armed=false`, `capture_present=false`,
`physical_evidence_present=false`, and
`source_build_provenance=not-claimed`.

The sentinel ELF and run ID can never satisfy the physical gate, and patching
the readiness image is not an arming procedure. Resumed testing requires a
separately reviewed physical feature/arm contract with formal, non-sentinel
bindings. The same-identity rule below applies only across the three captures
of that future physical run.

The future physical gate requires three operator-confirmed independent power
cycles and cold boots of one byte-identical kernel/challenge/run ID, unique
capture boot IDs with ordinals 0 through 2, and strict metadata, 1,176 records,
END, PASS, terminal quiescence, and operator power-off ordering. All present
counters are zero and `gate_satisfied=false`. The fixed-QEMU result remains
emulator evidence with `physical_provenance=not-claimed`; the Duo result is
compile/static evidence only. Milk-V Duo qualification remains deferred, so
this section does not close F5, Float, or C8.8 and does not allocate or
authorize a separately numbered executable successor.
