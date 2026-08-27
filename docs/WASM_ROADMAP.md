# Component Model admitted-code roadmap

This document defines the dependency order, security invariants, acceptance
gates, and compatibility boundaries for admitting WebAssembly components into
VibeOS. It complements [BLUEPRINT.md](BLUEPRINT.md),
[CAPABILITY_SHELL.md](CAPABILITY_SHELL.md), and
[PROGRAM_PERSISTENCE.md](PROGRAM_PERSISTENCE.md).

**Status (2026-08-27): implementation in progress.** The repository now contains
bounded Core validation/execution, Component decoding and Canonical ABI,
admission/loading, compatibility, and C8 profiling evidence. The dependency
sequence and acceptance text below remain the roadmap rather than a claim that
every milestone is complete. Current C8.3/C8.4 evidence and its explicit
remaining gaps are tracked in [WASM_AOT_DECISION.md](WASM_AOT_DECISION.md) and
[TESTING.md](../TESTING.md).

---

## 1. Outcome

The public VibeOS application format will be a deliberately bounded WebAssembly
Component Model profile. Applications describe typed imports and exports in
WIT; VibeOS admits those requirements against explicit policy and CSpace
authority. Core Wasm remains the private execution substrate underneath the
component boundary.

The first complete release must let VibeOS load an immutable component after
the kernel image was built, validate the component and every embedded Core Wasm
module, assign exact CSpace authority and resource budgets, execute it without
trusting the component, suspend async calls, revoke and cancel it, reclaim it
after a trap, and recover an admitted artifact after reboot without persisting
a live handle.

```text
immutable ComponentArtifact + versioned WIT world
                         |
                         v
admission: decode -> validate -> derive typed import graph -> apply policy
                         |
                         v
                  AdmittedComponent
                         |
                         v
ComponentInstance = Canonical ABI + resources + embedded Core Wasm instances
        |                                           |
        v                                           v
supervised Task/arena                         one exact CSpace
        |                                           |
        `------ typed async calls/resources --------'
                                                    |
                                                    v
                                          VibeOS typed services
```

The three layers have separate responsibilities:

- **Component Model and WIT** define typed application contracts, resource
  ownership, composition, and language interoperability.
- **Core Wasm validation and interpretation** confine instructions and linear
  memory. They remain mandatory even though Core Wasm is not the public ABI.
- **CSpace** remains the sole source of authority to observe or affect the host
  environment.

This changes Bet 4 from “one source compiler is the only admission path” to the
more general rule: **admission is a kernel service**. Vibe source remains one
admitted format; a validated component becomes another. Arbitrary ELF, native
code, component-derived AOT bytes, and readable blobs remain non-executable.

## 2. Decisions frozen for the first release

1. **Component-first contract, Core-first implementation.** WIT and the
   Component Model are the developer-facing ABI from C0. C1 still implements
   bounded Core Wasm execution before C2 can execute any component.
2. **A constrained profile, not “all Component Model.”** Every supported binary
   construct, Core proposal, Canonical ABI option, WIT type, adapter, and WASI
   interface is versioned and allowlisted. Unsupported constructs fail before
   instantiation.
3. **One component principal before composition.** The first runnable profile
   admits one top-level component with one CSpace. Arbitrary nested component
   instantiation and multi-principal composition wait for C6.
4. **Synchronous Canonical ABI before native async.** C2 closes lifting,
   lowering, resource, realloc, and cleanup semantics before C5 adds `async
   func`, `stream<T>`, and `future<T>`.
5. **Vibe WIT packages before broad WASI.** VibeOS defines the smallest typed
   interfaces needed for streams, clocks, randomness, blobs, and diagnostics.
   Selected WASI 0.3 interfaces may be implemented later; no standard world is
   granted wholesale.
6. **No ambient namespace.** No interface opens a global path, device name,
   object ID, address, command registry, or arbitrary socket. An operation that
   cannot be implemented from an explicit capability fails closed.
7. **Interpreter first.** The normative engine interprets validated Core Wasm.
   There is no in-kernel JIT and no writable-plus-executable transition. AOT is
   a later, measured, rebuildable cache path.
8. **No raw capability representation.** `Cap`, slot/generation pairs, resource
   pointers, persistent identities, and CSpace names never enter component
   linear memory or printable component values.
9. **No persisted execution state.** Linear memory, stacks, tables,
   continuations, resource handles, pending calls, fuel, and TaskIds are
   boot-local. Persistence stores immutable code, interface/manifest data,
   admission policy, and durable roots only.
10. **No threads or shared memory in Profile 1.** Component concurrency does not
    imply host threads or shared linear memory. Those require a separate profile.
11. **Exact version binding.** Artifacts name the Vibe Component Profile,
    Component Model binary/Canonical ABI revision, WIT packages, Core Wasm
    profile, runtime ABI, and adapter hashes. “Supports Component Model” or
    “supports WASI” without exact versions is not a durable contract.

## 3. Security invariants

These invariants are release-blocking. Violating one is a security bug.

1. **CSpace is authoritative.** Component resource tables contain opaque local
   tokens that resolve to `Cap` values in the exact instance CSpace. They are not
   a second rights database and never cache an object pointer as authority.
2. **Imports are requirements, not grants.** WIT imports and component wiring
   describe what code would like to use. Admission grants only the intersection
   of those requirements, caller-grantable authority, and image/operator policy.
3. **One admitted node is one principal.** A component instance gets a fresh
   CSpace incarnation. In C6, every separately admitted graph node gets its own
   CSpace. Embedded Core modules and adapters inside one node are implementation
   units and share only that node's authority ceiling.
4. **Resource ownership is not authority creation.** `own<T>` may transfer a
   local handle under supervisor policy; `borrow<T>` is call-scoped. Neither may
   mint, widen, duplicate, serialize, or reconstruct a capability.
5. **Checks occur at use.** Every host operation resolves the local resource,
   verifies its exact kind and rights, and observes derivation liveness.
   Revocable operations revalidate before every externally visible publication
   after suspension.
6. **In-flight semantics are explicit.** A call uses either a revocable operation
   token or a separately reviewed bounded invocation lease. Revoke prevents later
   acquisitions; it is never described as undoing a side effect that already
   linearized.
7. **Canonical ABI memory is hostile.** Every lifted pointer, length,
   discriminant, string, list, record, variant, realloc result, and cleanup call
   is checked against the exact current linear memory and configured limits.
   Host references never survive growth, suspension, or re-entry.
8. **Adapters have no hidden authority.** An adapter is ordinary admitted Core
   Wasm charged to the component. It can use only declared imports, has fuel and
   memory limits, and cannot obtain a service merely because it is runtime-supplied.
9. **Memory is bounded before allocation.** Component and Core decoding have
   independent byte, nesting, definition, type, instance, alias, canonical
   function, adapter, resource, memory, table, and custom-section limits.
10. **Execution is temporally bounded.** Total fuel limits an invocation. A
    smaller poll quantum forces the Core interpreter and Canonical ABI machinery
    to save continuations and return `Pending`, so component code cannot wedge a
    hart.
11. **Admission is atomic.** Validation, graph planning, candidate CSpaces,
    resource tables, memories, streams, accounts, and task envelopes are complete
    before any start function or exported operation executes. Failure publishes
    no partial task, grant, resource, command, or side effect.
12. **Async completion is incarnation-bound.** A pending call names the exact
    component generation, TaskId, allocation arena, CSpace incarnation, function,
    resource token, and operation token. A late completion cannot publish into a
    restarted or replaced instance.
13. **Teardown is monotonic.** Failure or cancellation closes publication,
    revokes instance CSpaces, cancels pending calls, detaches tasks, reclaims
    audited arenas, and only then publishes one immutable terminal report.
14. **Code is data until admitted.** `READ` on a component, Core Wasm module, WIT
    package, adapter, or hash is not `INVOKE`. Only the trusted admission service
    may produce a volatile `Command` or runnable instance.
15. **Diagnostics reveal no authority.** Errors may report WIT names, versions,
    resource kinds, policy labels, and stable trap codes, but never raw handles,
    slots, generations, pointers, executable addresses, or durable object IDs.

## 4. Vibe Component Profile 1

C0 freezes exact numeric limits and binary feature flags. The conceptual first
profile is:

- one top-level component principal;
- a bounded number of embedded Core Wasm modules and instances;
- one private linear memory per accepted Core module, with a mandatory effective
  maximum selected from the module declaration and supervisor ceiling;
- WIT scalar types, strings, lists, tuples, records, flags, enums, options,
  results, variants, and resources;
- `own<T>` and call-scoped `borrow<T>` with bounded per-instance resource tables;
- synchronous Canonical ABI calls first, followed by the exact WASI 0.3-era
  async ABI revision selected in C5;
- bounded adapter and canonical lift/lower counts;
- deterministic traps and exact terminal-status mapping;
- integer Core Wasm arithmetic/control flow initially.

The following start disabled:

- nested component instantiation and arbitrary composition before C6;
- threads and shared memory;
- memory64 and multiple memories;
- SIMD;
- GC-managed object graphs and broad reference-type surfaces;
- Core exceptions, stack switching, and tail calls except where an exact async
  ABI implementation is separately admitted;
- dynamic linking and runtime package discovery;
- floating point until C0 closes the integer-only RISC-V ABI, soft-float, NaN,
  differential, and fuel-accounting decision;
- filesystem worlds, global preopens, environment mutation, processes, raw
  sockets, and unrestricted networking;
- component-provided or external AOT/native code.

Features are enabled one at a time only with component validation, Core
execution, Canonical ABI, differential, fuel, target, quota, revocation, and
fault-containment evidence. Profile widening is an explicit ABI revision.

## 5. WIT and CSpace mapping

The first Vibe packages are versioned independently:

| WIT package | Backing authority | Initial surface |
|---|---|---|
| `vibe:stream@1` | `RECV` or `SEND` on an exact bounded stream | async read/write and explicit close |
| `vibe:clock@1` | `READ` on an exact monotonic clock | monotonic time only |
| `vibe:random@1` | `READ` on an exact random source | bounded exact fill |
| `vibe:blob@1` | `READ` on Store plus an exact stored-object proxy | length, bounded read, verified chunks |
| `vibe:log@1` | `WRITE` on an exact diagnostic sink | bounded structured events |

There is no raw block, MMIO, DMA, packet, CSpace, task, code pool, persistent-ID,
or arbitrary TCP-connect package in Profile 1. New packages require independent
rights, ownership, cancellation, revocation, bounds, information-flow, and fault
recovery review.

The logical resource mapping is:

```text
component-local resource index
    -> resource-table entry { expected WIT type, local Cap, ownership state }
    -> exact current CSpace lookup
    -> typed VibeOS resource + exact Rights
```

Resource rules:

- An integer index is meaningful only in one component instance and generation.
- `borrow<T>` creates no capability and cannot escape its dynamic call scope.
- `own<T>` transfer between separately admitted nodes asks the trusted supervisor
  to derive or proxy authority into the target CSpace, then retires the source
  local handle according to the WIT move. Copying the integer is insufficient.
- A resource whose cap lacks `GRANT` cannot be transferred directly. Persistent
  resources use the existing revocable proxy model rather than bypassing durable
  derivation rules.
- Dropping a component resource removes that instance's local binding and runs
  bounded host cleanup. It does not automatically revoke the supervisor's parent
  authority or another explicitly derived child.
- Resource-table exhaustion fails before an ownership transition becomes visible.

## 6. Artifact and source boundaries

The design distinguishes data, admission, invocation, and runtime state:

| Object | Lifetime | Meaning |
|---|---|---|
| `ComponentArtifact` | immutable, optionally durable | Exact component bytes, profile/ABI versions, interface manifest, limits, hashes, and signer policy |
| `ComponentPlan` | boot-local, inert | Validated typed import/export graph, embedded Core modules, adapters, canonical functions, resource needs, and policy requirements |
| `AdmittedComponent` | boot-local policy result | A plan plus the exact authority and image/operator ceilings under which instances may be created |
| `ComponentCommand` | volatile `Command` resource | A VSH-invokable factory derived from an admitted component rather than untrusted text |
| `ComponentInstance` | one task incarnation | Core interpreter state, Canonical ABI state, memories, resources, fuel, pending calls, and terminal state |

Derived summaries are recomputed from the exact component bytes during
admission. Stored import graphs and feature summaries are diagnostic metadata,
not authority.

The provisional source boundaries are:

| Location | Owns | Must not own |
|---|---|---|
| `component-format/` | Canonical `ComponentArtifact` envelope, exact profile/ABI identifiers, limits, manifest codecs | Live caps, engine state, kernel services |
| `wasm-runtime/` | Pinned Core engine wrapper, Core profile validator, limits, fuel/quantum, traps and continuations | WIT policy, board services, durable roots |
| `component-runtime/` | Component decoder, WIT/type graph, Canonical ABI, resource-table mechanics, component continuations | Image policy, ambient services, raw CSpace mutation |
| `services/component-admission/` | Immutable manifest, import plan, signer/operator checks, admitted model, durable recovery policy | MMIO, VSH parsing, implicit authority |
| `kernel/component_platform.rs` | Exact CSpace lookup, owner/arena integration, async host adapters, service and storage boundaries | Component parsing policy or global name lookup |
| `components/vsh` | Atomic `ComponentCommand` planning and Job/status integration | Component validation, implicit grants, raw service access |
| `policy/image` | Allowed profiles, WIT packages/signers, budgets, boot installation set | Runtime-derived trust decisions |
| `acceptance/kernel-tests` and `scripts/` | Target gates, corpus drivers, independent disk inspection and physical evidence | Production fixtures or hidden authority |

C0 may refine names, but dependency direction is binding: format, Core runtime,
Component runtime, and admission policy remain host-testable; the kernel adapter
supplies live authority; VSH consumes an already admitted command rather than
becoming a loader or validator.

## 7. Execution and async model

Every embedded Core interpreter is polled through its owning component future.
The component owns two independent execution budgets:

- **Total fuel** bounds the complete invocation, including adapter Core Wasm and
  charged Canonical ABI work. Exhaustion maps to VSH `BudgetExceeded`.
- **Poll quantum** bounds one executor poll. Quantum exhaustion saves all needed
  Core/component continuations, self-wakes once, and returns `Pending`; it does
  not reset total fuel.

C2 initially supports synchronous Canonical ABI calls. C5 adds the exact native
async Component Model revision associated with the selected WASI 0.3 profile:

```text
Running component
    -> lower typed call and validate resource/arguments
    -> execute Core Wasm / call host
    -> Ready(value): lift bounded result and continue
    -> Pending(future/stream operation): save continuation, release all locks,
       await through SYSTEM-owned registration, revalidate, lift, and resume
```

No CSpace, service, resource-table, stream, component-runtime, or allocator lock
may be held across suspension. Backpressure and cancellation are part of the
interface contract, not an out-of-band convention.

The stable result mapping is:

| Component result | VSH / component result |
|---|---|
| normal return | `Success` / `Exited` |
| declared application error or non-zero CLI exit | `Returned(code)` or command-defined typed failure |
| fuel exhaustion | `BudgetExceeded` |
| missing, wrong-kind, or revoked authority | `Denied` |
| unsupported optional interface | `Unavailable` |
| validated Core trap, invalid Canonical ABI value, or defined resource misuse caused by component input | `Faulted` with stable code |
| supervisor or foreground cancellation | `Cancelled` |

Kernel boot, interrupt, validator, engine, or host-service invariant failures are
not relabeled as component traps. They remain kernel defects and fail stop.

## 8. Dependency sequence

```text
C0 Component contract, profile, corpus and engine decisions
  -> C1 Portable bounded Core Wasm execution
      -> C2 Single-component synchronous Canonical ABI
          -> C3 CSpace-backed WIT resources
              -> C4 Supervised ComponentCommand + VSH admission
                  -> C5 Native async functions, streams and futures
                      -> C6 Bounded multi-principal composition
                          -> C7 Durable installation and upgrade
                              -> C8 Compatibility, hardening and optional AOT
```

C0--C5 are the minimum proof of the Component Model direction. C6 proves the
multi-principal composition thesis. C7 completes the first durable component
release. C8 compatibility and optimization do not block Component v1.

## 9. Milestones

### C0 — Contract, corpus, and engine decisions

**Goal:** freeze the developer-facing component contract and select reviewable
Core/component implementation foundations before linking target code.

| # | Work item | Acceptance |
|---|---|---|
| C0.1 | Freeze Vibe Component Profile 1, Core profile, WIT package versions, artifact ABI, trap taxonomy, limits, total fuel, and poll quantum | Versioned constants and malformed-boundary tests exist in portable crates |
| C0.2 | Build a representative component corpus first | Checked-in WIT and Rust/C-generated fixtures cover valid components, malformed binaries, resources, canonical lift/lower, adapters, imports, limits and unsupported features |
| C0.3 | Spike at least two Core-engine options | Each validates, interprets, limits, fuels, traps and resumes the same Core corpus under the target allocator model |
| C0.4 | Spike one constrained Component frontend end to end | It decodes one component, validates its WIT world and embedded modules, and invokes a synchronous typed export on the host |
| C0.5 | Record the engine/frontend decision | Cover `no_std`/allocator fit, unsafe and dependencies, license/provenance, proposal versions, resumability, deterministic fuel, target size, panic/OOM behavior and RISC-V support |
| C0.6 | Decide integer-only versus deterministic software float | The kernel's integer-only ABI remains until target context, soft-float, NaN, Canonical ABI, differential and fuel semantics are closed |
| C0.7 | Establish baselines before budgets | Record code/static size, validator peak memory, empty instance cost, startup, Core fuel throughput and lift/lower cost for each candidate |

**Gate:** the project pins a Core engine and a Component frontend, or explicitly
chooses smaller in-tree implementations after documenting why reviewed
dependencies failed. A broad from-scratch implementation is not the default.
If the complete frontend cannot meet the measured TCB/footprint budget, the
profile is narrowed; the project does not silently fall back to an untyped
public Core-Wasm ABI.

**C0.7 baseline (2026-08-28):** the reproducible evidence contract lives in
`wasm-candidates/evidence/`. It records the closed candidate/metric
applicability matrix, pinned fixtures and toolchain, RISC-V allocated
code/static size, host validator and empty-instance memory, cold startup, exact
Core fuel consumption, and Canonical ABI lift/lower cost. Baseline replacement
requires the explicit `scripts/collect-c0-baseline.py --update` command. CI
never rewrites it: CI verifies the checked-in record, its source hashes,
derived statistics, heap cleanup invariants, and rejection mutations, then
rebuilds the host collector, all four RISC-V probes, and generated fixtures
without recollecting timings.

### C1 — Portable bounded Core Wasm execution

**Goal:** provide the mandatory private execution substrate in a host-testable
`no_std + alloc` crate without kernel services.

| # | Work item | Acceptance |
|---|---|---|
| C1.1 | Add the pinned Core engine wrapper and exact Core profile validator | `cargo check` passes for the VibeOS target; every disabled proposal fails before instantiation |
| C1.2 | Enforce decode limits before attacker-controlled allocation | Length, count, nesting, locals, types, tables, memories, data, elements and custom-section mutations never exceed the validation account |
| C1.3 | Enforce mandatory effective maxima | `memory.grow`, table growth, call depth and engine allocation fail deterministically without charging another owner |
| C1.4 | Implement total fuel and resumable poll quantum | An infinite loop returns after one bounded quantum and terminates only when total fuel or cancellation wins |
| C1.5 | Freeze stable Core trap diagnostics | Arithmetic, unreachable, out-of-bounds, bad indirect call, call depth, validation and fuel failures have exact tested codes |
| C1.6 | Add differential and specification evidence | The complete pinned `wg-1.0` `fac.wast` baseline agrees across its official assertions, Vibe, and DLR; profile rejections remain separately asserted |
| C1.7 | Fuzz decode, validate, instantiate and execute | The pinned local corpus remains panic-free, respects configured allocation/execution bounds, reaches every stage, and produces stable terminals |

**C1.2 bounded decode account (2026-08-28):**
`wasm-runtime/tests/decode_limits.rs` constructs raw Core modules locally and
pins both sides of every applicable enabled Profile-1 ceiling: raw/declared
lengths, bounded and imported-plus-defined counts, compact-import expansion,
materialization-capable disabled recursive-type and operator vectors, parameter
and result arities, compressed locals, structured-control nesting, table/memory
declarations, data lengths/segments, element segments/items, and aggregate
encoded custom names plus data. Enabled exact ceilings are admitted; fields
modeled by `CoreSummary`, the Core decoder's structural account, also report the
exact count. Limit-plus-one cases return their stable `AdmissionError`, while
the numeric result ceiling does not enable disabled multi-value.

Inputs are built outside the measured interval. A host `System`-allocator
wrapper then records, for the current test thread, allocation calls, cumulative
requested bytes and the largest individual request around both `inspect_core`
and the production `ValidatedCore::new_in` entrypoint. These are request-envelope
metrics, not live/high-water memory or kernel-owner attribution. Rejected inputs
must produce identical errors and envelopes through both paths, proving that
the zero-reservation entrypoint does not reach Wasmi compilation. Absolute small
bounds plus shallow-versus-materialization-size comparisons prevent hostile
declarations from amplifying predecode allocation.

Type, table, global, data and MVP element framing is predecoded before
attacker-sized vectors can be materialized, and function control nesting uses a
fixed 129-frame stack. Core raw bytes bound data payload storage; segment and
element-item counters provide independent structural ceilings. This closes
C1.2 for the frozen Core Profile-1 grammar. Component decoding, successful Wasmi
compilation, instantiation, growth/call-depth enforcement, kernel allocator
ownership, QEMU/Duo allocation and exhaustive fuzzing remain separate evidence
boundaries or later roadmap nodes.

**C1.3 effective maxima (2026-08-28):**
`wasm-runtime/tests/effective_maxima.rs` pins adjacent runtime boundaries through
the production wrappers. A two-page image/store policy admits the guest growth
that reaches page two, then repeatedly traps page three as `LimitExceeded`
without changing memory. A smaller module-declared maximum remains a distinct
Core bounds failure. The controlled host table seam reaches exactly 4,096 MVP
function-table elements and rejects 4,097 with stable size and diagnostics,
while guest `table.grow` remains rejected before compilation because reference
types stay disabled. A countdown call accepts 128 active frames, rejects the
129th as `CallDepthExceeded`, repeats the same terminal, and remains reusable.

`ValidatedCore::required_compile_bytes` performs bounded structural inspection
without constructing a Wasmi engine or module. Both constructors check the
caller-provided per-compilation policy ceiling before engine creation, clone,
or `Module::new`; the calculator-reported charge succeeds and charge-minus-one
returns the stable allocation-reservation admission error. A 27-byte raw probe
compactly declares 4,096 locals; `CoreSummary::max_locals` records that count,
and the charge includes the corresponding pointer-sized per-function
expansion. A thread-local host allocator probe labels two synthetic caller owner
scopes. The rejected constructor has exactly the inspector's
allocation-request fingerprint, successful selected-scope compilation observes
a request at least as large as that expansion, and the other label is unchanged.
This deterministic policy charge is not an upper bound on Wasmi's
allocation-request total or live/high-water memory; the copyable reservation is
neither an owner credential nor a ledger debit.

This closes C1.3 for one portable Profile-1 Core memory/table/call stack and the
pre-engine allocation policy gate with active-scope request attribution.
Authentic kernel owner capabilities, exact full-lifecycle charging/reclamation,
and aggregate memory across all Core instances in a Component principal remain
C4.2/C6 boundaries. No QEMU or physical-Duo allocation claim is made here.

**C1.6 selected baseline (2026-08-27):** the offline fixture is the complete
official [`test/core/fac.wast`](https://github.com/WebAssembly/spec/blob/977f97014c962f7bd1291fcc6d28b41a924882bf/test/core/fac.wast)
from WebAssembly/spec `wg-1.0` commit
`977f97014c962f7bd1291fcc6d28b41a924882bf`, not a rewritten subset. Its exact
2,602 bytes are pinned by SHA-256
`7bf27b090f6533865acc79a37e0331b27fa11d7a3ab27b02e32e2efddfb405e7`; the
vendored license is independently pinned, and
[`PROVENANCE.md`](../wasm-runtime/tests/spec/core-wg-1.0/PROVENANCE.md) records
the immutable source URL, path, commit, sizes, and digests. The runner requires
the file's one module, all five `assert_return` actions, and its one
`assert_exhaustion`, rejecting any extra directive. For every return it compares
the official WAST result with both Vibe's bounded Profile-1 engine and the
pinned DLR reference runtime; the exhaustion action must classify as Vibe
`CallDepthExceeded` and DLR `StackExhaustion`. This closes a selected integer
semantic baseline covering calls/recursion, locals, structured control flow,
the fixture's non-negative factorial comparisons, and wrapping `i64`
arithmetic. It is not a claim of full
WebAssembly Core 2.0 conformance and does not widen Profile 1. C1.6 did not by
itself close C1.7; the independent bounded gate below now supplies that selected
deterministic evidence.

**C1.7 selected robustness evidence (2026-08-27):**
`wasm-runtime/tests/core_robustness.rs` generates its corpus locally with fixed
xorshift64* seed `0x6a09_e667_f3bc_c909`. It pins 679 inputs, 575,262 total
bytes, and FNV-1a digest `0xbe6b2c8ae635595a`: raw lengths 0--192, equal-length
tails after the exact Core magic/version, and 96 valid Profile-1 modules plus
one truncation and one bit flip of each. The accepted modules cover integer
arithmetic, direct calls, `if`, loops, bounded memory, and `unreachable`;
separate cases cover a disabled float signature, an unlinked import, bounded
nontermination and recursion, a tight compile reservation, and the exact
524,289-byte module-size limit-plus-one input. Ordinary structured inputs never
exceed 4,096 bytes. Every corpus pipeline exercise is protected by
`catch_unwind`; every admitted summary/reservation is checked against Profile
1, and execution uses
50,000 total fuel with a 10,000-fuel quantum and at most six polls. The 96
unmodified generated modules and dedicated spin/recursion cases require exact
`Ready`, `Unreachable`, `FuelExhausted`, and `CallDepthExceeded` outcomes.
Mutated or arbitrary inputs may reject earlier or terminate differently, but
must remain panic-free and bounded, may not reach a host call, and must clear
the active call on every terminal result. This closes the C1.7 criterion for
the selected deterministic bounded CI evidence. It is not coverage-guided or
exhaustive fuzzing, and it does not assert that all possible Core byte
sequences have been enumerated.

**Demo:** a host test invokes exported integer functions, grows bounded memory,
observes exact traps, and resumes an infinite loop across multiple quanta. This
is infrastructure evidence, not the final public application interface.

### C2 — Single-component synchronous Canonical ABI

**Goal:** execute one constrained component and close rich-value/resource ABI
semantics before adding live authority or async behavior.

| # | Work item | Acceptance |
|---|---|---|
| C2.1 | Decode and validate Profile-1 component binaries | Excess aliases, definitions, instances, canonical functions, adapters, nesting and embedded module bytes fail before instantiation |
| C2.2 | Resolve one exact WIT world | Unsatisfied, duplicate, version-mismatched and type-incompatible imports/exports fail with stable diagnostics |
| C2.3 | Implement bounded canonical lowering/lifting | Scalars, strings, lists, tuples, records, flags, enums, options, results and variants round-trip across language fixtures |
| C2.4 | Implement realloc and cleanup rules | Bad pointers, lengths, alignments, discriminants, realloc results, traps and cleanup re-entry cannot expose host memory or leak across a failed call |
| C2.5 | Implement inert resource tables | `own`, `borrow`, move, drop, stale indices, double-drop and table exhaustion are model-tested without any live CSpace yet |
| C2.6 | Charge adapters and ABI work | Embedded adapter instructions consume Core fuel; host lift/lower allocation and work consume component budgets |
| C2.7 | Differential and fuzz evidence | Accepted components agree with a pinned reference implementation; component bytes and canonical values are fuzzed separately |

**Selected C2.3 evidence (2026-08-27):** the exact
`vibe:fixture/canonical-language@1.0.0` world now executes through two
independently authored freestanding guests, one Rust and one C. Both implement
the same Canonical ABI function whose input/output type graph covers every
Profile-1 non-resource value family and return both arms of a typed variant.
The import-free compiler outputs are rebuilt with byte-pinned toolchains, passed
through a digest-allowlisted transform that removes only the linkers' private,
unreferenced mutable stack global, and revalidated as Profile-1 Core before
being embedded in import-free Components. The test pins both Core and derived
Component byte identities, the exact WIT world, four typed boundary cases, 276
aggregate dynamic bytes, and corpus digest `0x5a3e5d03338a9be3`. Both languages
produce the exact same typed values under a 1,000,000-work budget,
10,000-work quantum, and 101-poll ceiling without a host operation, trap,
poisoned instance, or retained continuation. Exact source/tool/artifact
provenance and the offline reproduction command are documented in
`component-runtime/tests/fixtures/language/PROVENANCE.md` and `TESTING.md`.
This closes the selected C2.3 cross-language acceptance evidence without
claiming C2.7 reference-runtime agreement or fuzz coverage.

**Selected C2.7 evidence (2026-08-27):** the same byte-pinned Rust and C
Components are now admitted by Vibe against Profile 1 and the exact WIT world,
then executed through both Vibe and pinned Wasmtime 48.0.0 with an empty linker
and finite fuel. Both engines run all four C2.3 cases for both fixtures and
agree with each other and with a neutral named representation, while retaining
the 276-dynamic-byte and `0x5a3e5d03338a9be3` corpus pins. Wasmtime is a
host-test-only, default-feature-disabled dev dependency whose release commit,
crates.io package digest, features, license, and Rust version are recorded in
`component-runtime/tests/reference/PROVENANCE.md`; it is not a Profile-1
admission oracle and is not linked into the target.

Component bytes and Canonical values have separate deterministic bounded
corpora. The byte gate fixes seed `0x243f6a8885a308d3`, 4,323 inputs,
4,604,005 aggregate bytes, all proper-prefix truncations and one-bit-per-byte
mutations of two admitted fixtures, a 1,048,577-byte limit-plus-one case, exact
decoder classifications, and digest `0x9edc2bd8460d97a4`; every decode is
panic-contained. The value gate fixes 512 valid cases across all 19
non-resource families, 799 type nodes, 772 value nodes, 1,026 dynamic bytes,
88 list elements, 65 allocations, depth 6/5, and digest
`0xbf10e036e7750d0b`. It independently requires exact memory32 lower/lift
round-trips and accounting, 512 stable type-mismatch mutations, and 32 named
invalid type/value/memory rejections. These gates close the selected C2.7
differential and separate-fuzz acceptance evidence without claiming exhaustive
coverage-guided fuzzing; resource/Canonical-ABI state fuzzing remains C3.6.

**Demo:** a host-only component accepts a record containing strings and lists,
uses an inert borrowed resource, and returns a typed variant with exact output
matching the reference runtime.

### C3 — CSpace-backed WIT resources

**Goal:** bind typed component resources to VibeOS authority without turning
resource tables, WIT, or ownership syntax into a second capability system.

| # | Work item | Acceptance |
|---|---|---|
| C3.1 | Bind each resource index to one exact local Cap and expected WIT type | Guessed, stale, cross-instance, cross-restart, wrong-type and over-righted handles are denied |
| C3.2 | Implement operation-time lookup | Every host operation checks the current CSpace, resource kind, rights and derivation liveness; no object authority is cached |
| C3.3 | Implement `borrow` and `own` against capability semantics | Borrow cannot escape; move cannot copy or widen authority; failed target derivation leaves source ownership unchanged |
| C3.4 | Land synchronous clock, random, blob-read and structured-log interfaces one by one | Each package has independent rights, bounds, revocation, fault and negative-authority tests |
| C3.5 | Keep persistent authority behind proxies | Component resource transfer cannot bypass durable `GRANT` restrictions or reconstruct an object from a durable ID |
| C3.6 | Fuzz resource and Canonical ABI state together | Growth, aliasing, move/drop, revoke, trap and resource-table exhaustion cannot expose a host pointer or strand authority |

**Demo:** a component with an empty CSpace cannot observe anything. Granting one
random resource permits only that exact call; revocation denies the next call;
another instance using the same numeric resource index remains denied.

### C4 — Supervised instances and VSH admission

**Goal:** turn an admitted component into a first-class supervised VSH command
without making raw component bytes executable.

| # | Work item | Acceptance |
|---|---|---|
| C4.1 | Add a sealed admitted-component template | One artifact identity creates a fresh component generation, TaskId, CSpace incarnation, owner, arena, limits and runtime continuation |
| C4.2 | Charge all instance state to the exact owner | Component/Core metadata, memories, tables, resources, stacks, continuations and adapters return to baseline on normal return and cancellation |
| C4.3 | Add a pure inspect/admission planner | It reports profile, WIT world, imports/exports, embedded modules, adapters, limits and policy result without instantiating or running start code |
| C4.4 | Derive an immutable `ComponentCommand` manifest | WIT requirements are intersected with caller authority and image ceilings exactly like existing `Command` manifests |
| C4.5 | Extend VSH atomic Job admission | Candidate CSpaces, resources, streams, accounts and tasks remain unpublished until the complete pipeline passes admission |
| C4.6 | Bind cancellation, restart and late-wakeup identity | A retired generation cannot resume, publish or reuse a resource in its replacement |
| C4.7 | Integrate typed terminal status and observability | Pipelines, conditionals, Ctrl-C, jobs, SSH sessions, `ps`, `caps` and `mem` retain existing semantics without leaking handles or addresses |
| C4.8 | Prove audited trap reclamation | Sixteen repeated component fault/restart cycles reclaim the complete arena without running interrupted guest destructors or growing registrations |

**Acceptance demo:** an image-policy-provided synchronous component transforms a
bounded value/stream surrogate in a VSH pipeline. A later unauthorized pipeline
stage prevents this component from starting or producing an external side effect.

### C5 — Native async functions, streams, and futures

**Goal:** map the selected WASI 0.3-era Component Model async ABI to VibeOS
futures, backpressure, cancellation, and revocation.

| # | Work item | Acceptance |
|---|---|---|
| C5.1 | Freeze and implement one exact async Canonical ABI revision | `async func`, `stream<T>` and `future<T>` binaries outside the selected revision fail closed |
| C5.2 | Add resumable component continuations | Suspension holds no host lock, consumes bounded state, and resumes on the exact task/hart without spinning |
| C5.3 | Land `vibe:stream@1` | A component reads and writes bounded byte streams with real backpressure and exact normal/failure/cancel close propagation |
| C5.4 | Bind pending operations to exact incarnations | Revoke, cancellation, fault, close and restart races cannot publish a late value, wake a replacement, or strand a waiter |
| C5.5 | Charge async work and storage | Futures, streams, waitables, adapters and wake registrations have explicit per-component bounds and accounting |
| C5.6 | Add selected standard interfaces only after review | Any accepted WASI 0.3 clocks/random/CLI interface names exact resource mapping and never falls back to ambient state |
| C5.7 | Fuzz async state machines | Suspend/resume, nested calls, backpressure, cancellation, trap, drop and post-await revocation transitions never panic or leak |

**Demo:** a component implements a real VSH stream filter. Revoking its output
capability while a write is pending prevents the next publication, cancels or
finishes the already-linearized operation according to the frozen contract, and
leaves the shell and peer stages live.

### C6 — Bounded multi-principal composition

**Goal:** compose independently admitted components while preserving a separate
CSpace, lifecycle, and resource budget for every security principal.

| # | Work item | Acceptance |
|---|---|---|
| C6.1 | Define a bounded `ComponentGraph` plan | Node, edge, nesting, adapter, resource, memory and total-budget ceilings are checked before allocation |
| C6.2 | Admit the complete typed graph atomically | Missing imports, type/version mismatch, cycles outside policy, duplicate resources and authority amplification run no node |
| C6.3 | Give every admitted node an exact principal | Each node has its own component generation, CSpace, Task/arena, fuel, resources and terminal report |
| C6.4 | Implement supervised resource transfer across edges | `own` derives/proxies into the target before retiring the source; `borrow` is scoped to one edge invocation and cannot be retained |
| C6.5 | Propagate async wake, cancellation and backpressure through chains | A -> B -> host and longer chains neither actively poll nor lose wakeups; failure teardown has a deterministic direction and typed cause |
| C6.6 | Preserve least authority under replacement | Updating or restarting one node creates fresh local resources; siblings retain no stale route into the replacement |
| C6.7 | Add information-flow inspection | Diagnostics can show the typed graph and policy labels without showing resource indices, Caps, pointers or object IDs |

**Demo:** separately built decoder, filter, and sink components form a typed
async pipeline. The decoder cannot reach the sink capability directly; revoking
one graph edge stops only the authorized flow and graph teardown returns every
node to its baseline.

### C7 — Durable installation, recovery, and upgrade

**Goal:** persist admitted components and reconstruct exact least authority
without making WIT names, aliases, hashes, or object IDs into execution authority.

| # | Work item | Acceptance |
|---|---|---|
| C7.1 | Define a canonical `ComponentArtifact` object kind | Header binds exact bytes, all profile/ABI/WIT/adapter versions, manifest, limits, hashes and signer policy; reserved fields are zero |
| C7.2 | Persist only read authority to the artifact | Durable v1 `INVOKE` remains absent; the loader creates a volatile `ComponentCommand` only after complete revalidation and policy admission |
| C7.3 | Add authenticated admission policy | Development may trust image-pinned bytes; deployable installation requires configured signer/operator policy. A content hash alone is never authenticity |
| C7.4 | Make publication crash-safe | Component object and exact durable root commit before local command publication; every prefix cut recovers none or one complete artifact |
| C7.5 | Revalidate on every boot | Component/Core validation, WIT graph, adapters, hashes, limits, signer policy and engine ABIs pass before any fresh CSpace/resource/task exists |
| C7.6 | Add bounded graph version replacement | Replacement becomes visible only after durable admission; old graph nodes drain or are explicitly cancelled under policy |
| C7.7 | Keep runtime state ephemeral | Reboot creates fresh Tasks, arenas, CSpaces, memories, resources, fuel and pending-call state; no numeric token survives |
| C7.8 | Add independent disk evidence | A host parser verifies artifact bytes, graph/manifest, versions, hashes, record order, roots, upgrades, corruption and every documented crash prefix |

**Demo:** boot 1 installs and invokes one signed or image-pinned component graph;
boot 2 recovers it with the same typed manifest and entirely fresh runtime
identities. Mutation of any module, adapter, WIT, ABI, limit, root, graph, or
signer field fails closed.

Authenticated rollback resistance remains outside this milestone until a
monotonic hardware root exists.

### C8 — Compatibility, hardening, and optional AOT

**Goal:** grow ecosystem compatibility and performance only after the native
component security boundary is measured and stable.

| # | Work item | Acceptance |
|---|---|---|
| C8.1 | Adapt legacy WASIp1 off-device | A pinned Preview-1 adapter wraps a Core module into an admitted component; VibeOS still accepts the component artifact, not a raw ambient WASIp1 process |
| C8.2 | Support a bounded compatibility corpus | Checked-in Rust and C stdin/stdout filters run unchanged through selected CLI streams/arguments/exit; paths, processes, mutable environment, threads and raw sockets remain absent |
| C8.3 | Publish runtime costs | Report validation, startup, lift/lower, async, composition, host-call, memory, fuel and cancellation/revocation costs on fixed QEMU and physical-Duo baselines |
| C8.4 | Decide whether AOT is justified per workload | AOT proceeds only when a named product workload misses a frozen budget and profiling attributes the miss to interpretation |
| C8.5 | Treat AOT as a rebuildable cache | Original component/Core bytes and policy remain authoritative; cache mismatch discards native code and never widens WIT imports or rights |
| C8.6 | Reuse the sealed W^X lifecycle | Link RW-NX, validate imports/relocations, seal X-only, execute, quiesce, unseal, zero and reclaim; no JIT or RWX page exists |
| C8.7 | Regenerate or verify native output | A pinned trusted compiler reproduces native bytes, or an equivalently reviewed verifier proves the accepted surface before execution |
| C8.8 | Widen profiles one feature at a time | Float, SIMD, references, exceptions, memory64, multiple memories, GC, threads or broader WASI each require separate semantics and evidence |

As of 2026-08-27, the C8.4 chain includes the live trusted-terminal boundary
and the private 24-sample collector, now a build-bound single-cold-boot
protocol. The collector closes META + 24 SAMPLE + END locally, with three warmups, 21
retained samples, an absorbing Failed/Closed state, atomic physical UART
records, and a separate QEMU audit sink whose markers explicitly carry
`decision_eligible=0 formal_uart=0`. The software-side independent
frozen-source envelope, build/package envelopes, host-observed Docker runtime
closure, full-SD-image verifier, read-only three-boot capture program,
immutable C8.3 precondition, and final 63-sample evidence verifier are
implemented and covered by host-only synthetic tests. Those tests use no
device, Docker, network, flash, reset, or physical cold boot. Package preflight
and the independent image verifier validate their own package/verify runtime
attestations before using the container-mounted source verifier; the
independent verifier also completely validates the package attestation to
which its image audit remains bound.

Milk-V Duo physical testing is paused at operator request. Consequently, C8.3
still lacks its three physical-Duo cold boots, C8.4 still lacks three attested
cold boots and 63 retained physical samples, and neither row is complete. No
workload-specific AOT decision exists; the final workload-specific AOT decision
remains open and may not be inferred from software self-tests or QEMU
diagnostics. Independent source materialization and local Docker runtime
custody are now closed prerequisites in the software path. They remain
software evidence only and do not attest hardware identity, a remote host, or
a physical cold boot. C8.5 remains gated on a future verified C8.4 result.

## 10. Test and evidence matrix

The existing VibeOS evidence layers remain mandatory:

| Layer | Component responsibility | Blind spot |
|---|---|---|
| Portable unit/model tests | Artifact codecs, profiles, WIT/type graphs, import policy, resource ownership, Canonical ABI, status and lifecycle models | Real allocator, MMU, IRQ and executor behavior |
| Differential/spec tests | Core instructions/traps plus Component/Canonical ABI behavior against pinned references | VibeOS authority and target integration |
| Fuzzing | Component/Core decoders, validators, canonical values, resources, adapters, async resumptions and malformed artifacts | Exhaustive target interleavings and hardware DMA |
| In-kernel self-test | Live CSpace use/revoke, ownership, quotas, quantum yield, cancellation, arena reclamation and W^X if AOT exists | Complete remote and persistent workflows |
| QEMU acceptance | VSH/SSH component invocation, multicore progress, async chains, composition, fault/restart, two-boot persistence and raw-disk evidence | Physical Duo cache, storage, entropy and long-duration behavior |
| Physical Duo gate | Target runtime, memory pressure, microSD persistence, network streams, repeated install/run/revoke/restart and soak | Other boards and certification |

Security-sensitive mutations must prove that the gates are live:

- remove one Core or Canonical ABI bounds check;
- skip one Core, adapter, or ABI fuel charge;
- treat a WIT import as an automatic grant;
- retain a `borrow<T>` after its call;
- duplicate an `own<T>` resource without target derivation;
- reuse a resource index after restart;
- cache a resource pointer across revoke;
- publish an async result after cancellation;
- omit one component/module/adapter/WIT/manifest hash binding;
- enable one unsupported component or Core feature;
- alter one durable root, graph edge, or crash-order record;
- expose one ambient clock, random source, path, or endpoint.

Every mutation must be caught by a named layer. A green compatibility corpus
without mutation evidence is not sufficient for the confinement claim.

## 11. Metrics and release budgets

C0 measures candidates before freezing thresholds. Every release then reports:

- Core and Component runtime `.text`, `.rodata`, and writable static footprint;
- validator peak memory for accepted and hostile components;
- empty component, embedded-module, adapter and resource-table overhead;
- time to decode, validate, plan, instantiate, first instruction and first output;
- Core and adapter fuel throughput;
- Canonical ABI scalar, string/list, record/variant and resource lift/lower cost;
- synchronous, suspended and cross-component host-call latency;
- stream throughput, wake latency and backpressure memory;
- graph admission and teardown cost by node/edge count;
- revocation-to-denial and cancellation-to-terminal latency in poll quanta;
- normal, cancellation, trap and restart heap return-to-baseline;
- native-component and adapted-WASIp1 corpus pass counts with explicit exclusions;
- QEMU and physical-Duo soak duration and restart count;
- dependency, source-line, unsafe-site, proposal-version and fuzz-corpus inventory
  added to the TCB.

No footprint or percentage target is invented before C0 measures the candidate
implementations on the pinned toolchain and target. Updating a baseline is an
explicit review action, never a normal test side effect.

## 12. Risk register

| Risk | Severity | Mitigation |
|---|---:|---|
| Component decoding and Canonical ABI greatly enlarge the TCB | **High** | C0 comparative audit, constrained profile, exact version pin, dependency/unsafe inventory, differential tests and fuzzing |
| Resource tables become a second authority database | **High** | Store only local-token-to-Cap bindings; use exact current CSpace lookup and never cache object authority |
| `own`/`borrow` semantics are confused with grant/revoke | **High** | Supervisor-mediated transfer, scoped borrows, transactional target derivation and model tests for every failure point |
| Canonical ABI lifting exposes host memory or amplifies allocation | **High** | Checked arithmetic, limits before allocation, immediate memory validation, hostile realloc fixtures and allocation-aware fuzzing |
| Interpreter or adapter work defeats cooperative cancellation | **High** | Mandatory per-poll quantum separate from total fuel; charge adapters and ABI work; test shell latency under loops and large values |
| Async completion publishes after revoke/restart | **High** | Exact-incarnation pending tokens, post-await revalidation, terminal publication fence and race-model tests |
| Composition hides authority flow inside adapters or nested modules | **High** | One principal before C6, typed graph inspection, per-node CSpaces, adapter import audits and atomic graph admission |
| Broad WASI reintroduces POSIX ambient authority | **High** | Vibe WIT packages first, exact standard-interface allowlist, no global preopens/fallback namespace and negative tests |
| Component Model and WASI revisions drift | **High** | Bind exact binary/Canonical ABI/WIT/adapter versions; revalidate on boot; version packages rather than silently upgrading |
| Floating point conflicts with the integer-only kernel ABI | Medium | Keep the Core profile integer-only until software-float or complete target-context and differential evidence lands |
| AOT becomes unaudited native authority | **High** | Interpreter remains normative, component bytes remain authoritative, regenerate/reverify cache, sealed W^X, never accept external native bytes |
| Content hash is mistaken for publisher authenticity | **High** | Separate integrity from signer/operator admission and document rollback limits until a hardware root exists |
| Dynamic component state violates audited-arena no-escape | **High** | Only copied values, opaque caps and SYSTEM-owned registrations cross arenas; complete fault-reclaim evidence before C4 |
| Standards work eclipses the VibeOS thesis | Medium | C0--C5 prioritize CSpace-backed typed async execution; compatibility and broad WASI remain C8 work |

## 13. Definition of done for Component v1

Component v1 comprises C0--C7 and is complete only when:

1. WIT/Component Model is the documented developer-facing application ABI;
   direct custom Core imports are internal implementation details, not a second
   public platform.
2. A component with an empty CSpace cannot print, read time/randomness, access an
   object, open a path, or reach the network.
3. Component bytes, WIT names, imports, hashes, aliases, adapter presence, and
   manifest text cannot mint authority or become executable without admission.
4. Guessed, stale, cross-instance, cross-restart, wrong-type, revoked and
   over-righted resources fail at the exact host operation.
5. `borrow` cannot escape, `own` cannot duplicate or amplify authority, and
   cross-node transfer is atomic with target derivation/proxy creation.
6. Infinite loops, deep calls, memory growth, oversized canonical values,
   resource exhaustion, adapters, traps, blocked streams, cancellation and
   restart cannot wedge a hart or escape component bounds.
7. Normal return, cancellation, Core/Canonical trap, async failure, and sixteen
   repeated fault/restart cycles return audited memory, resources and
   registrations to their documented baselines.
8. VSH can run native components in foreground, background, pipelines,
   conditionals, SSH exec, and restricted interactive sessions without changing
   existing atomic admission or teardown semantics.
9. A bounded multi-principal graph preserves one CSpace and budget per node,
   propagates wake/backpressure/cancellation, and exposes no undeclared edge.
10. A two-boot test restores one admitted component graph with fresh runtime
    identities and exact reconstructed least authority; independent disk evidence
    rejects every documented mutation and crash prefix.
11. Host tests, selected Core and Component reference tests, differential corpus,
    fuzzers, self-tests, four-hart QEMU gates, and the physical-Duo gate are green
    on pinned tools.
12. The trust model names the exact Core/Component/Canonical ABI/WIT versions,
    engines, adapters, dependencies, unsafe sites, unsupported surface,
    performance costs, physical-security limits and rollback limits.

Legacy WASIp1 compatibility, complete standard WASI worlds, JIT, AOT, threads,
shared memory, and broad proposal support are not part of Component v1.

## 14. Reference specifications and candidate tooling

- [WebAssembly Core Specification](https://webassembly.github.io/spec/core/)
- [WebAssembly Component Model](https://component-model.bytecodealliance.org/)
- [Component Model specification repository](https://github.com/WebAssembly/component-model)
- [WASI releases](https://wasi.dev/releases)
- [WASI 0.3 native async](https://wasi.dev/releases/wasi-p3)
- [`wasm-tools`](https://github.com/bytecodealliance/wasm-tools)
- [`wit-bindgen`](https://github.com/bytecodealliance/wit-bindgen)
- [`wasmi` interpreter API](https://docs.rs/wasmi/)
- [WebAssembly Micro Runtime](https://github.com/bytecodealliance/wasm-micro-runtime)

These links identify C0 inputs, not dependencies selected by this document.
The Component Model is still evolving even though WASI 0.2 and 0.3 provide
released component profiles. The repository must pin exact revisions, source,
patches, provenance, licenses, and qualification evidence after C0 chooses the
implementation foundations.
