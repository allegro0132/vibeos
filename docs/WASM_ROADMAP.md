# Component Model admitted-code roadmap

This document defines the dependency order, security invariants, acceptance
gates, and compatibility boundaries for admitting WebAssembly components into
VibeOS. It complements [BLUEPRINT.md](BLUEPRINT.md),
[CAPABILITY_SHELL.md](CAPABILITY_SHELL.md), and
[PROGRAM_PERSISTENCE.md](PROGRAM_PERSISTENCE.md).

**Status (2026-08-30): implementation in progress.** The repository now contains
bounded Core validation/execution, Component decoding and Canonical ABI,
admission/loading, compatibility, and C8 profiling evidence. The dependency
sequence and acceptance text below remain the roadmap rather than a claim that
every milestone is complete. C1 through C8.2 remain accepted complete by
historical-evidence policy; none is reopened, rerun, or individually rewalked.
C8.3 is accepted complete by historical-evidence policy and is not being
rerun. Formal fixed-QEMU evidence completes C8.4 for the selected workload.
C8.5 through C8.7 were not entered for that workload
and remain globally deferred. The C8.8 Float widening is closed by the formal
fixed-QEMU F5 decision below. The independently numbered C8.9 Float
successor is now allocated. C8.9-S1 froze its new code-6 identity, ABIs,
revisions, software-float engine, non-promotion rules, and fixed-QEMU policy;
C8.9-S2 implements and verifies its codec, current-engine binding, exact
authority-free admission, executor, lifecycle, and durable rejection. C8.9-S3
now closes the fresh fixed-QEMU gate and releases only that sealed Float
runtime. Its closure position is `c89-s3-qualified-sealed-float-runtime-released`.
The next listed C8.8 widening, fixed-width SIMD, is now allocated as C8.10.
C8.10-S1 freezes validation-only code 7, ABI/revisions, deterministic semantics,
the independent engine plan, and non-authorization boundaries. C8.10-S2
implements and audits its isolated deterministic fixed-SIMD engine. C8.10-S3
closes Component containment and fixed differential/mutation corpora. C8.10-S4
closes the default-off volatile admission/lifecycle, one-instance quota,
explicit recovery/revocation, and durable loader rejection. C8.10-S5 now
passes a fresh normal/optimized fixed-QEMU campaign and makes only a successor
design review eligible. C8.11-S1 allocates that successor as a distinct code-8
executable SIMD design without promoting code 7. C8.11-S2 now implements its
exact engine, runtime, authority-free volatile admission, lifecycle, durable
rejection, supply-chain closure, and RISC-V object gate. The previous position
was `c811-s1-simd-executable-design-frozen-pre-implementation`. C8.11-S3 now
qualifies and releases only the sealed volatile code-8 runtime; the current
position is `c811-s3-qualified-sealed-simd-runtime-released`.
Every later feature widening remains separately unallocated and incomplete.
The earlier non-numbered fixed-QEMU
target/release policy checkpoint makes fresh source-bound
`qemu-virt-rv64-tcg-icount-v1` evidence the prospective generic WASM
target/release gate. Milk-V Duo remains a paused optional observation with no
gate, completion, or release effect. The decision contracts and explicit gaps
are tracked in
[WASM_AOT_DECISION.md](WASM_AOT_DECISION.md) and [TESTING.md](../TESTING.md).

**C8.8 Float status (2026-08-29):** F1 through F5 are complete for the Float
widening only. F1 freezes the immutable
validation-only identity and deterministic scalar-float contract; F2 closes
the independently identified, acceptance-only Core validator/software-float
executor, differential, fuzz, trap, limit, fuel, supply-chain, and RISC-V
object gates. F3 closes the acceptance-only WIT and Canonical ABI scalar-float
value, memory, nested-value, allocation-request/cleanup-model, differential,
and hostile-input gates. F4 closes the default-off, exact-image-pinned
candidate admission/lifecycle path, including quota, cancel/revoke, fault
reclamation/recovery, and durable-rejection gates. Artifact profile code 5
remains permanently `ValidationOnly` and inert: it has no production
admission, command, durable/publication, current-engine, or production
execution path and can never be promoted in place. The host/fixed-QEMU portion
of C8.8-F5 first passed at pushed implementation commit
`c4ea5e5ca1de622884f33c01bf06653f498360aa`. The formal decision at pushed
source commit `0f06212f890077b2a3d1b4405a128058cb07c55e` now makes the fixed
`qemu-virt-rv64-tcg-icount-v1` matrix the normative F5 exit gate and replaces
the physical-Duo requirement for C8.8-F5 only. It accepts all 1,176 records
with semantic SHA-256
`51896391bb2a3493f1252e2633f54678bb1e69aa46a7e740dc4bc110381504f1`.
Milk-V Duo testing remains paused; its readiness and physical-v1 contracts are
retained, non-blocking, and make no physical claim
(`physical_provenance=not-claimed`). Every unrelated hardware gate is
unchanged. This decision closes F5 and the Float widening only; it neither
closes another C8.8 feature widening nor authorizes an engine, execution,
production admission, native bytes, AOT, or in-place promotion. At F5 closure
it opened only design review for a separately numbered successor whose identity
was then unallocated and whose implementation was not authorized.
The historical `post-c88-f5-pre-allocation` charter froze eight unresolved,
blocking review questions and allocated or authorized nothing. Explicit user
authorization on 2026-08-29 subsequently opened the separately versioned C8.9
design/implementation/qualification sequence; it does not rewrite that charter.

**C8.9 status (2026-08-29): C8.9-S1 through C8.9-S3 complete.**

**C8.10 status (2026-08-29): C8.10-S1 through C8.10-S5 complete.**

**C8.11 status (2026-08-30): C8.11-S1 through C8.11-S3 complete.**

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
10. **Execution is temporally bounded.** Total fuel limits charged execution. A
    smaller poll quantum is a hard ceiling on newly granted fuel: resumable Core
    interpreter and Canonical ABI work saves continuations and returns `Pending`.
    Together with finite code, nesting, and call-depth limits this prevents
    unbounded interpreter work. An indivisible engine metering unit larger than
    the quantum fails closed instead of silently widening that grant:
    insufficient remaining total fuel takes priority, otherwise it is a quantum
    policy failure. A fuel grant is not itself a wall-clock preemption guarantee.
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

C8.8-F1 selects the deterministic-software-float branch and freezes its exact
semantics. F2 closes the acceptance-only Core backend, provenance, conversion
trap, host differential/fuzz, fuel, and RISC-V object gates. F3 closes the
acceptance-only WIT and Canonical ABI boundary, including nested values and an
exact allocation trace replayed through the existing cleanup model. F4 closes
the separately gated, exact-image-pinned candidate admission/runtime lifecycle
without registering code 5 as a current engine or exposing it as a command or
durable object. F5 now closes the target gate through its formal fixed-QEMU
replacement decision. These increments still do not enable Float execution:
Profile 1 stays integer-only, code 5 stays permanently validation-only and
inert, and F5 made only a then-unallocated separately numbered successor
eligible for design review. The later C8.9-S1 allocation does not change any of
those code-5 claims.

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
- **Poll quantum** bounds the newly granted fuel in one executor poll. For a
  resumable metering unit, quantum exhaustion saves the Core/component
  continuation, the owning executor self-wakes once, and returns `Pending`; it
  does not reset total fuel.

That `Pending` rule applies to resumable metering units. When the remaining
total can cover it, an indivisible engine charge larger than the configured
quantum terminates with stable `LimitExceeded` before its side effect. If the
remaining total is also insufficient, `FuelExhausted` takes priority. Neither
the Core wrapper nor a higher layer may grant extra fuel to force the operation
through. C1.4 pins this boundary for the Core engine. Canonical ABI charging and
executor wake integration close in their own later nodes.

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
| C1.4 | Implement total fuel and resumable poll quantum | An infinite loop returns after one bounded fuel grant and terminates only when total fuel or cancellation wins |
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

**C1.4 total fuel and resumable poll quantum (2026-08-28):**
`wasm-runtime/tests/fuel_quantum.rs` pins the production Core wrapper to enabled
fuel consumption and Wasmi 1.1's versioned default cost schedule. It rejects
zero total fuel, zero quantum, either Profile-1 ceiling plus one, and a quantum
larger than its total, while the exact maximum pair remains executable. A
preemptible infinite loop with total 41 and quantum 10 returns four exact
`Pending` states `(consumed, remaining) = (9, 32), (19, 22), (29, 12), (39,
2)`, followed by the single `FuelExhausted` terminal at `(41, 0)`. Thus each
poll consumes no more than its grant, the logical total remains monotonic across
Wasmi store-fuel resets, and exhaustion does not leave a runnable continuation.

Cancellation after the first yield consumes no additional guest fuel. It also
wins when a checked external debit has already reduced the remaining balance to
zero, because cancellation is observed before another interpreter step. Both
terminal paths clear active state and permit immediate reuse. The legacy
borrowed invocation now delivers `Ready`, `FuelExhausted`, or `Cancelled` once;
a later poll returns `Validation` without relabeling the prior terminal or
changing its metrics.

The grant quantum has an explicit fail-closed edge. Wasmi meters some translated
blocks and dynamic operations as indivisible units; under its pinned
64-bytes-per-fuel default, a ten-page `memory.grow` has a 10,240-fuel dynamic
charge, larger than Profile 1's maximum 10,000-fuel quantum. With 20,000 total
fuel the gate repeats that operation and requires exact `(4, 19,996)` metrics,
`LimitExceeded`, unchanged one-page memory, cleared active state, and reuse.
With only 10,000 total fuel the same request is instead `FuelExhausted` at `(4,
9,996)`, so remaining total-budget insufficiency wins when both ceilings are
insufficient.

The adjacent nine-page charge is 9,216 fuel. Quantum 9,220 completes it in one
poll at exact `(9,220, 10,780)` metrics; quantum 9,219 and the exact charge
quantum 9,216 first return `Pending` at `(4, 19,996)`, then resume to the same
final metrics and memory. Quantum 9,215 returns `LimitExceeded`, while a 9,219
total returns `FuelExhausted`; neither path mutates memory.
The runtime never widens the grant to force either operation through. Therefore
the row's “only total fuel or cancellation wins” is the acceptance result for
the preemptible spin fixture, while an oversized indivisible metering unit is a
separate stable policy failure.

This closes the portable Core fuel-ledger and continuation substrate, not a
wall-clock or cycle bound. Wasmi precharges translated blocks, so a resumed
poll can execute a suffix charged by an earlier poll; the gate bounds newly
debited fuel, not an exact source-instruction count per poll. Host/adapter/
Canonical ABI charging remains C2.6, and executor self-wake, target latency,
exhaustive opcode fuel coverage, and physical-Duo execution are not claimed by
this host gate.

**C1.5 stable Core trap diagnostics (2026-08-28):**
`component-format/tests/profile.rs` freezes the numeric value and exact
kebab-case name of all fourteen `TrapCode` variants. The public `code()` method
defines the stable 16-bit diagnostic projection for Component ABI and
supervisor boundaries. `wasm-runtime/tests/trap_diagnostics.rs` separately classifies the
twelve Core-facing codes, excluding the later `CanonicalAbi` and
`ResourceMisuse` categories, and pins every Wasmi 1.1 Core trap variant through
the production typed mapping. It also fixes the complete Wasmi memory and table
error families, whether direct or wrapped by instantiation. Null indirect
targets and numeric table bounds both intentionally become
`TableOutOfBounds`; wrong target signatures remain
`IndirectCallTypeMismatch`. The disabled-profile float-to-integer conversion
trap maps fail-closed to `Validation` but is not guest-reachable in Profile 1.

The production fixtures cover adjacent successful and failing signed division,
conditional `unreachable`, the first invalid four-byte memory load, and the
valid, null, wrong-signature, and first-out-of-range indirect-call cases. They
also pin 128 active frames versus the rejected 129th, plus short-fuel
exhaustion. Each execution trap repeats with the same identity, removes its
terminal continuation, and leaves the instance reusable. Missing exports,
wrong arity, and wrong scalar input types return exact `Validation` before
installing active state; C1.5 fixed the single-instance start path to enforce
the parameter type as well as its count.

The admission matrix repeats exact malformed `Validation`, disabled-feature
`UnsupportedFeature`, and module-size `LimitExceeded` results through both the
bounded inspector and compiler. Active data placement at the first byte beyond
memory maps to `MemoryOutOfBounds`; active element placement at the first slot
beyond a table maps Wasmi's typed instantiation error to `TableOutOfBounds`.
Both standalone and Component-group paths repeat those results, and adjacent
placements instantiate successfully. A Component-group policy one byte below
the module's initial memory maps to `LimitExceeded` instead of generic
validation. No diagnostic relies on Wasmi display or debug text.

This closes the stable diagnostics named by C1.5 for the portable Profile-1
Core boundary. The gate is not full Core conformance, differential or fuzz
coverage, a Canonical ABI/resource taxonomy result, a timing guarantee, or a
QEMU/physical-Duo execution claim; those remain C1.6, C1.7, C2+, and target
integration work.

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
xorshift64* seed `0x6a09_e667_f3bc_c909`. It pins 679 execution inputs and
575,262 total module bytes. FNV-1a digest `0x7fc98ac32e54fb64` commits every
case tag, module length and byte, and `i32` invocation argument: raw lengths
0--192, equal-length tails after the exact Core magic/version, and 96 valid
Profile-1 modules plus one truncation and one bit flip of each. The accepted
modules cover integer arithmetic, direct calls, `if`, loops, bounded memory,
and `unreachable`; separate cases cover a disabled float signature, an
unlinked import, bounded nontermination and recursion, a tight compile
reservation, and the exact 524,289-byte module-size limit-plus-one input.
Ordinary structured inputs never exceed 4,096 bytes.

Every corpus pipeline exercise is protected by `catch_unwind`, repeated from a
fresh pipeline, and required to produce the same full result. Every admitted
summary/reservation is checked against Profile 1. Execution uses 50,000 total
fuel with a 10,000-fuel quantum and at most six polls; pending and terminal
metrics conserve the ledger and advance by no more than one quantum. The 96
unmodified generated modules and dedicated spin/recursion cases require exact
`Ready`, `Unreachable`, `FuelExhausted`, and `CallDepthExceeded` outcomes.

The normalized ordered outcome digest `0x2e7b93e373f2c522` commits complete
admission/instantiation errors, start/execution trap codes, and typed ready
vectors for all 679 inputs. Exact counts pin 552 admission rejections, 127
admissions, 126 instantiations, 111 starts, 101 ready terminals, 10 trapped
terminals, one instantiation rejection, and 15 start rejections. No arbitrary
or mutated input may silently change stage or terminal, panic, reach a host
call, exceed its poll bound, or retain an active call after termination.

This closes the C1.7 criterion for the selected deterministic bounded CI
evidence. It is not coverage-guided or exhaustive fuzzing, and it does not
claim every possible Core byte sequence, actual cumulative/live allocator
measurements, kernel-owner attribution, wall-clock bounds, or exhaustive opcode
coverage.

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

**Selected C2.1 evidence (2026-08-28):**
`component-runtime/tests/component_profile_limits.rs` pins adjacent Profile-1
inspection boundaries. Exact maxima succeed with sealed inert plans and exact
summaries: 256 definitions, 256 aliases, 16 Core instances and 16 Component
instances in independent namespaces, 256 canonical functions, 16 lowering
adapters, type depth 16, eight embedded modules, and one 524,288-byte embedded
Core module. Every maximum-plus-one input returns `DecodeError::Limit` without
yielding the `ComponentPlan` required for instantiation. The 524,289-byte Core
case remains below the enclosing 1 MiB Component ceiling, independently
proving the embedded-module limit rather than the artifact limit. Nested
Component sections remain unsupported and inert.

The allocation-free predecoder now aggregates top-level and instance-type
aliases under the same 256-entry account and charges each canonical lower to
the 16-adapter account before reading its remaining fields. Dedicated
truncated-entry tests require those known excess counts to win before the
regular parser can materialize data, while the regular decoder retains the
same limits before reserving plan storage. The C2.7 byte corpus and digest are
unchanged; one header-prefixed input is intentionally reclassified from
malformed to limit by this earlier alias-count check. This closes the selected
C2.1 structural acceptance evidence without claiming C2.2 WIT resolution,
C2.3--C2.6 runtime ABI semantics, or C2.7 differential/fuzz coverage.

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
decoder classifications (863 accepted, 520 non-Components, 2,527 malformed,
134 unsupported, 11 limited, 267 invalid embedded Core, and one invalid
wiring), and digest `0x9edc2bd8460d97a4`; every decode is
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
| C8.4 | Decide whether AOT is justified per workload | A verified miss attributed to interpretation may open C8.5 design review only; C8.4 never authorizes AOT or accepts native bytes |
| C8.5 | Treat AOT as a rebuildable cache | Original component/Core bytes and policy remain authoritative; cache mismatch discards native code and never widens WIT imports or rights |
| C8.6 | Reuse the sealed W^X lifecycle | Link RW-NX, validate imports/relocations, seal X-only, execute, quiesce, unseal, zero and reclaim; no JIT or RWX page exists |
| C8.7 | Regenerate or verify native output | A pinned trusted compiler reproduces native bytes, or an equivalently reviewed verifier proves the accepted surface before execution |
| C8.8 | Widen profiles one feature at a time | Float, SIMD, references, exceptions, memory64, multiple memories, GC, threads or broader WASI each require separate semantics and evidence |
| C8.9 | Activate Float under an independent identity | A new code-6 executable identity must pass separately frozen design, implementation/admission, and fresh fixed-QEMU qualification nodes; code 5 remains permanently inert |
| C8.10 | Widen fixed-width SIMD under an independent validation identity | New code 7 freezes fixed SIMD 1.0 with deterministic software-float lanes, no public `v128` boundary, no relaxed SIMD, and staged engine, containment, admission/lifecycle, and fixed-QEMU gates before any successor review |
| C8.11 | Allocate an independent executable SIMD successor | New code 8 and ABIs 8 freeze fixed SIMD semantics, an exact engine identity, closed authority-free world, code-7 non-promotion, implementation gates, and fresh fixed-QEMU qualification before release |

The C8.3 row above is retained verbatim as the historical v1 acceptance text.
C1 through C8.3 are treated as complete under the project's historical-evidence
policy and are not rerun. This status does not assert that absent physical
publication files exist, does not synthesize or backfill a Duo publication,
and does not turn fixed-QEMU output into physical provenance.

The Float widening is itself divided into five ordered increments. Completion
of one increment does not activate code from the next:

| # | Float increment | Acceptance |
|---|---|---|
| C8.8-F1 | Freeze contract and identity | Code 5, exact revisions and feature vector, scalar `f32`/`f64`, strict exact-bit NaN policy, Profile-1 non-widening, artifact mutation coverage, no current engine, and CGV1 rejection are frozen as metadata only |
| C8.8-F2 | Implement deterministic Core validation and execution | A reviewed software-float Wasmi candidate with an independent package/source/checksum identity covers every scalar instruction and translator fold, stable conversion traps, limits, differential/fuzz corpus, and fuel/quantum behavior; code 5 remains inert |
| C8.8-F3 | Implement WIT and Canonical ABI floats | `f32`/`f64` flat values and lift/lower paths close exact-bit, memory-bounds, nested-value, realloc/cleanup, hostile-input, and differential evidence without adding authority |
| C8.8-F4 | Close default-off admission and lifecycle | Candidate-only loader/image policy, quota, revoke/cancel, fault reclamation, and durable-rejection tests pass; production code 5 remains inert |
| C8.8-F5 | Qualify targets and review activation | Host and the formal fixed-QEMU normal/optimized matrix pass 1,176 exact-bit/fuel records; fixed QEMU replaces the physical-Duo exit requirement for this gate only, and completion opens only design review for a separately numbered, unallocated successor |

The complete F1/F2/F3/F4/F5 Float contract and evidence are specified in
[WASM_FLOAT_PROFILE.md](WASM_FLOAT_PROFILE.md). F2 uses the renamed, vendored
`vibeos-wasmi-*-softfloat` package family only behind the
`c88-f2-acceptance` feature. `rustc_apfloat` implements deterministic
arithmetic and conversions; a fixed 24/53-round pure-integer algorithm
implements square root. Strict NaN canonicalization and bit-preserving
transport, every scalar runtime and translator-fold path, fused branches,
stable conversion traps, Profile-1 limits, import denial, deterministic
fuel/quantum traces, fixed-seed differential and end-to-end fuzz corpora,
hostile byte mutations, and offline supply-chain checks pass. A pinned RISC-V
release-object audit finds no semantic FP instruction, compiler FP helper, or
target F/D opcode; remaining sign-only LLVM forms lower to integer bit
operations. Stock Profile 1 and permanent code-5 inertness remain unchanged.
F3 adds a separate bit-only flat representation and exact Component-boundary
NaN normalization behind `c88-f3-acceptance`. It covers direct/indirect flat
and memory lift/lower, Canonical ABI variant joins, nested record/list/result
values, bounds/alignment, protected return areas, allocation journals,
and byte-for-byte replay through the existing success/abort/failure cleanup
state machine, fixed-seed bit and hostile-memory corpora, and an import-free
Wasmtime 48 scalar/nested differential fixture. Its offline
RISC-V audit binds the 29-rlib target closure and finds no F/D opcode in 126
objects; all 29 workspace-owned objects remain LLVM-auditable and have no
host-float type/transport, semantic FP, helper, or symbol. Default WIT and the
production Profile-1 codec remain unchanged, and the synchronous candidate
rejects adjacent async WIT shapes. The F3 replay remains cleanup-model
evidence rather than runtime wiring.

F4 adds one default-off image pin behind `c88-f4-float-candidate`. Its exact
component SHA-256 is
`5fdb9dc9a48a9c54e899a5dc724445083c055dbf0d664927ba55d9780cc9996a`, its
world is `vibe:float-acceptance/lifecycle@1.0.0`, and its sole export is
`run(mode: u32, left: f32, right: f64) -> f64`. The separately gated admission
and runtime path admits no imports, host imports, resources, caller authority,
command manifest, durable graph, or publication authority. The image fixes a
two-page memory ceiling, 100,000 total fuel, a 100-fuel poll quantum, and zero
resources; compile reservation is freshly derived and exact. Host tests cover
exact Float bits and NaN normalization, one-live-instance enforcement,
exact Component-to-Core `run` binding, under-reservation and adjacent quota
rejection, grow-to-memory-ceiling enforcement, finite-fuel exhaustion,
cancellation, absorbing revocation, trap reclamation, cold recovery, and
durable loader/CGV1 rejection.
This is explicit candidate-only activation evidence, not a current-engine or
production activation path. F4 itself made no fixed-QEMU or physical-Duo
execution claim; those remain separately attributed to F5.

The non-physical portion of F5 reuses one `no_std` qualification routine on the
host and in isolated, default-off target images. The frozen corpus contains 146
Core runtime/fold/repeatability observations, 13 Canonical ABI records, 12
image/lifecycle vectors, 1,000 fuel records, and 5 terminal lifecycle
snapshots. A pre-decision fixed-QEMU regression from clean, already-pushed
implementation commit `c4ea5e5ca1de622884f33c01bf06653f498360aa`, source tree
`ec7e1195b1a8ba4a88d37a817a9e0f64c4432016`, and challenge
`8fb4bba646b9755b897d5dcbab0cb5724f0c2821b30ee99bbfe76c9a470fce9a`
used the fixed QEMU 11.0.3 `qemu-virt-rv64-tcg-icount-v1` contract. It accepted
all 1,176 data records and reproduced semantic SHA-256
`51896391bb2a3493f1252e2633f54678bb1e69aa46a7e740dc4bc110381504f1`.
The source-bound run ID is
`08cf7c906917fb6a9d1b482f461f12abfc30339bd7136124ae609fa5568c1caa`.

That preliminary QEMU kernel is 40,449,184 bytes with SHA-256
`0ef0ce1bf8f9aad1a5f35bbd783c94ea2fcfbc0fffc72285d5fe5efd781f146e`;
the UART transcript is 384,916 bytes with SHA-256
`ede6c9fc7b68982f372762af51d4a786224c6a54c115ac50be7f7e5a4d8de621`.
The byte-reproducible final-ELF report is 2,031 bytes with SHA-256
`cc70f99f265eb1fa767407b555d7324a7e49a4ed8d24b856859416f3557896af`;
the canonical environment envelope is 84,839 bytes with file SHA-256
`3307451b5273f00d455ca95cea58e13e78dbcbea5e752a11274cc1abcff48fe6`
and whole-envelope evidence digest
`6ad5d168efc32abf88bf982ef59decdd6eaa53f2c1a25d38f2d732c2a2eac8df`.
Normal and optimized independent verifier replays passed, and standalone ELF
audits reproduced that report byte-for-byte.

The final QEMU RV64 IMAC ELF is static, relocation-free, W^X, soft-ABI/RVC, and
has zero forbidden F/D opcodes, undefined symbols, or Float helper symbols at
381,935 canonical decoder boundaries. It contains 381,934 decoded
instructions, 42,010 trusted direct control-flow targets, and 128,657 code
symbols. This audit is deliberately limited to trusted native control flow at
canonical decoder boundaries; arbitrary-PC redirection and hardware NX are not
claimed. The build envelope still closes 190 Cargo registry archives and the
exact 3,603-file, 71,790,604-byte pinned `rust-src` tree. These are emulator
and local software-custody facts only: `physical_provenance=not-claimed`.

The formal F5 exit decision was published from clean, pushed source commit
`0f06212f890077b2a3d1b4405a128058cb07c55e`. Its publisher directly ran the
normal and optimized verifier workers against one fresh fixed-QEMU evidence
set. Both modes accepted exactly 1,176 records and reproduced semantic SHA-256
`51896391bb2a3493f1252e2633f54678bb1e69aa46a7e740dc4bc110381504f1`.
The fresh source-bound run ID is
`53c9f7ed099c371724867d060c3994cb4b3ad93d46404156f40914d7f3b30254`.
The checked-in closure identities are:

| Fixed-QEMU F5 closure identity | Value |
|---|---|
| Decision ID | `1841ae06e4c8bef4842a59bbc65362fa860e37d6d8a1d79cc68e3fc5a87004f9` |
| Decision SHA-256 | `1d118cdb4f5709f4ce93331b1cd6b60435e6c530eb800e9c21e0a3e8569030d4` |
| Normal receipt SHA-256 | `4d70865a6a665829457ee0e9ec34c9fa38de51ed6ee2bcb2be1356d752355c1a` |
| Optimized receipt SHA-256 | `4f95fcd2b4d2524b1d27fce7bbf77846f4f7d0030da8ebe277ffc062e53550e0` |

This decision makes fixed QEMU the formal replacement for the physical-Duo
exit requirement of C8.8-F5 only. It is emulator evidence with
`physical_provenance=not-claimed`, consumes zero physical inputs, and changes
no other hardware gate. It closes F5 and the Float widening while explicitly
leaving every other C8.8 feature widening incomplete.

Separately, earlier pushed implementation commit
`c4ea5e5ca1de622884f33c01bf06653f498360aa` freezes the Duo suite
`vibeos.c88.f5.float-target.duo-v1` for platform
`milkv-duo-cv1800b-c906-v1`. Its 4,159-byte manifest has SHA-256
`1c85f22cacee7c8eb7693578052fe0452169eace99f1dab06e08aa0e42771b11`;
its 4,692-byte transcript schema has SHA-256
`e25d9a38d194993906b7fe5ec9708654ea31e2386ac61f0fa360ed8ad1eb7439`.
The reserved non-evidence sentinel run ID is
`c5c8ec42e56fbeaf38106965e5ec6735cb86a93af530cd37f5002dba1971b4ac`,
with immutable arm marker `vibeos.c88.f5.duo.compile-readiness.arm=0`. The
build only cross-links; it does not package, flash, connect to serial, or
execute.

The locally audited Duo RV64 IMAC ELF is 40,331,520 bytes with SHA-256
`e9a58e681c4d3e073dbeb1d15f569600e0ab2a97c07f13ed1dc0c676b5d62b1e`.
Its 2,031-byte audit report has SHA-256
`0b3384b35d85fdee970b98f523b7bd814102611549c08e7915625310954beac4`;
it contains 380,650 decoded instructions, 380,651 canonical boundaries, 41,883
trusted direct targets, and 128,210 code symbols, with zero forbidden opcodes,
Float helpers, or undefined symbols. This ELF identity records the local
compile-readiness run; the verifier intentionally freezes structure and
payload rather than globally pinning whole ELF bytes because source-build
provenance is not claimed.

The sentinel ELF and run ID can never satisfy the retained physical-v1 contract, and patching
the readiness image is not an arming procedure. A separate host-side wire and
campaign-verifier contract now exists at pushed commit
`f502240a88eeb218ca923276675d7b6dec3e4030`, tree
`d63a2a1ff68ab84586a1b53ee24982e232bc5b0f`. Its checked-in identities are:

| Duo physical-v1 verifier artifact | Bytes | SHA-256 |
|---|---:|---|
| Transcript/campaign contract | 5,605 | `01284fa4bb76a24e0a40e39fddec109e98ff36ec8912bb806f7a52a520a6617e` |
| Transcript schema | 5,923 | `08007a5e68e53181592dd9eaecf124a630b2eddfdc20c146504ff1d4df8811f5` |
| Host-only verifier | 56,129 | `09a98255b9deb8c5d14b19ecb4c0c5725cfbef25a60b1d84f2f4bbfbda649928` |
| Independent shared semantic oracle | 134,348 | `36451c3c614486a714b3466b77b329fee8a1368603ffaa9d2925b75b3f666686` |

The suite is `vibeos.c88.f5.float-target.duo-physical-v1`, with a distinct
NUL-terminated run-ID domain and physical-only UART prefix. The verifier
rejects readiness, fixed-QEMU, and C8.4 families; validates exact formal
non-sentinel bindings; enforces `META -> 1176 records -> END -> PASS`; and
recomputes semantic SHA-256
`51896391bb2a3493f1252e2633f54678bb1e69aa46a7e740dc4bc110381504f1`
through the independently byte-pinned F5 oracle. Normal and optimized contract
checks and the 53-mutation synthetic self-test are byte-identical. A host-only
in-memory translation of the retained formal-QEMU records also exercises the
normal semantic branch under both interpreters, but remains verifier test input
and never physical evidence.

The retained verifier node reserves the future feature
`wasm-c88-f5-float-duo-physical-qualification` and arm marker
`vibeos.c88.f5.duo.physical-qualification.arm=1`; neither exists as an
executable producer in this node. Milk-V Duo testing remains paused. If it is
voluntarily resumed, the retained campaign still requires a separately
reviewed feature/arm producer with formal, non-sentinel bindings and must bind
one build environment, package envelope, kernel ELF, and full SD image across
three operator-confirmed power cycles and cold boots. Every retained physical
counter remains zero and `gate_satisfied=false`; no physical evidence is
claimed. Those retained readiness and physical-v1 artifacts are scoped
non-evidence and non-blocking for C8.8-F5.

As of 2026-08-29, C1 through C8.3 are accepted complete by historical-evidence
policy. The completed C8.4 decision-bearing chain is the fixed-QEMU contract
below. It reuses the live trusted-terminal boundary and private 24-sample collector
to emit META + 24 SAMPLE + END through the platform-neutral atomic UART sink,
with three warmups and 21 retained samples. Formal and dirty-smoke builds are
compile-time and wire-distinct; an independent host verifier closes the exact
workload, transcript, source, helper, QEMU, OpenSBI, OpenSSH, and publication
envelopes. Formal builds use an exact commit-plus-gitlink object export and a
fresh private Cargo target; a sanitized remote query proves the bound source
commit is actually advertised. Only byte-identical private copies of frozen
QEMU/OpenSBI plus the kernel are executed; pinned `/usr/bin/ssh` executes in
place only after repeated Darwin sealed/read-only APFS, ownership, mode, link,
`SF_RESTRICTED`, same-device, version, hash, and byte-length attestation.
The formal build additionally audits the project and pinned rust-src
`Cargo.lock` files into a conflict-free 213-package union and consumes only
checksum/inventory-verified sources through one private read-only directory
source. It runs absolute Cargo from `/`, never executes rustup, and closes the
complete nightly toolchain, rust-src, crate-source, and non-system `ld.lld`
Mach-O runtime trees before and after compilation. Its private Cargo home is
config-only before and after: deterministic `.global-cache`, package-lock, and
cache-tag runtime outputs are exact-gated, recorded, removed, and fsynced;
unknown entries fail closed.
Each committed non-final SAMPLE is fenced by `PendingAcceptance`. SAMPLE 23
and the stability gate split Ready25 from the sole PendingEnd authority, but
`PendingTerminal` keeps Ready25 unstartable until all remaining fallible
request-tail checks pass and the finalizer commits END; abandonment or END
failure is absorbing and never retries.
The firmware search, QEMU version probe, and live process share one manifest-frozen,
deny-by-default environment with exact locale, timezone, and `PATH` values and
fresh private campaign-local `HOME`, `TMPDIR`, and `XDG_CONFIG_HOME`; ambient
`DYLD_*`, `QEMU_*`, and user configuration are absent. OpenSSH is not resolved
through `PATH`. A dedicated `/bin/sh` launcher pins CPython 3.14.6 with
`-I -B -S`, an absent `/var/empty` pycache sink, a deterministic reachable
stdlib/lib-dynload inventory, the Framework and Python.app executable, and
exact `_hashlib`/libcrypto, `_lzma`/liblzma, and `_zstd`/libzstd identities;
fixed empty OpenSSL configuration/provider inputs prevent ambient loading.
Dynamic maintained helpers execute only stable UTF-8 source snapshots and
propagate their actual hashes through the peer closure; ignored bytecode and
site customization cannot become decision inputs. The 10 MHz decision clock
is statically closed through `live_tick -> sbi::time -> rdtime` and the QEMU
board constant. The earlier absorbing QEMU audit sink remains a separate
integration-only test and cannot enter either decision dataset.

The retained physical-Duo chain remains implemented but non-blocking: it has
the build-bound single-cold-boot protocol, three-boot/63-sample aggregation,
independent frozen-source and build/package envelopes, host-observed Docker
runtime closure, full-SD-image verifier, read-only capture program, and final
evidence verifier. Its host-only synthetic tests use no device, network, flash,
reset, or physical cold boot and establish no physical provenance.

Milk-V Duo physical testing is paused at operator request. The retained
physical contract and tooling remain available but are no longer a C8.4
prerequisite. The decision-bearing replacement is the disjoint
`qemu-virt-rv64-tcg-icount-v1` contract: one fresh QEMU process, 3 warmups, 21
retained samples, 10 MHz `rdtime`, a pre-frozen 1,000,000-tick budget, and a
1.10 retained stability ceiling. It uses a separate suite, schema, and run-id
domain and explicitly records `platform_class=emulator` and
`physical_provenance=not-claimed`; it cannot be presented as Duo evidence.
Formal fixed-QEMU evidence in
[`benchmarks/wasm-aot-decision/qemu-v1/`](../benchmarks/wasm-aot-decision/qemu-v1/)
completes C8.4 at source commit
`e950a2facb6a6c230e67becb186bddf34a5924bb` and run ID
`a22f28ef7aab11de5c4858e9a4e4c5b5b4e6e763c43a126ad84d4ac80b9f500f`.
Its stable p95 total is 2,901,632 ticks and p95 non-interpretation is 2,804,417
ticks, both above the 1,000,000-tick budget. The miss is therefore not
attributable to interpretation and the outcome is
`aot-not-justified-on-fixed-qemu`; AOT remains unauthorized and no native code
is accepted. C8.5 through C8.7 are skipped for this workload and remain
globally deferred; they are not marked complete.
The current C8.4 gate is the fixed-QEMU publication-integrity auditor: it binds
the four checked-in evidence files to publication commit `cbb1d0f`, binds the
recorded source/capture-time verifier members to source commit `e950a2f`, and
rechecks the stored emulator-only/no-AOT decision with zero physical inputs.
It is a structure/hash check and does not replay QEMU, publisher execution, or
ephemeral host custody. The source-bound physical-Duo verifier and tooling stay
retained, paused, non-blocking, and non-evidence; no current physical input is
required, and unrelated hardware gates are unchanged.
The C8.8 Float widening is complete through F5 under decision
`1841ae06e4c8bef4842a59bbc65362fa860e37d6d8a1d79cc68e3fc5a87004f9`.
That decision formally substitutes fixed QEMU for the physical-Duo gate only
for C8.8-F5. Milk-V Duo testing stays paused and its readiness and physical-v1
contracts stay retained, non-blocking, and non-evidence; every unrelated
hardware gate is unchanged. No other C8.8 feature widening is complete. Code 5
remains permanently `ValidationOnly` and inert, and the closed Float evidence
only made design review eligible for a separately numbered successor that was
then unallocated. F5 itself authorized no successor implementation, engine
binding, execution, production admission, native-byte acceptance, AOT, or
in-place promotion; the later C8.9-S1 contract is the separate allocation and
implementation authority.

### Post-C8.8-F5 successor review boundary (not an allocated node)

The neutral
[`float-successor-review-boundary-v1-contract.json`](../acceptance/wasm-float-target/artifacts/float-successor-review-boundary-v1-contract.json)
turns design-review eligibility into a fail-closed charter without selecting a
design. Its verifier checks canonical contract bytes plus the exact historical
F5 contract, verifier, decision, and normal/optimized receipt members. Passing
means `review-charter-integrity-only`: it neither replays F5 evidence nor
establishes that the review passed.

At publication of this historical charter, the successor identity was
`unallocated`. Its roadmap number, profile code, artifact/runtime ABIs,
Core/Component revisions, stage, engine, supply chain, production admission
path, durable format, and target/release evidence gate were all unselected.
Code 5 was and remains permanently `ValidationOnly`, inert, and ineligible for
migration or promotion in place. The later C8.9-S1 allocation is a separate
contract and does not mutate or relabel this historical charter.

Eight review questions remain unresolved and blocking for later, separately
versioned work: identity/version allocation; engine/supply-chain selection;
semantic and evidence inheritance; production admission/authority; durability,
upgrade and rollback; global accounting/concurrency/lifecycle; target/release
evidence; and final authorization/rollout. F5 evidence may be referenced only
for the closed F5 identity and cannot automatically become successor engine,
activation, admission, or release evidence.

The fixed-QEMU replacement remains scoped to C8.8-F5. Milk-V Duo stays paused,
retained, non-blocking, and non-evidence; this charter takes zero physical
inputs and changes no unrelated hardware gate. C8.5--C8.7 remain globally
deferred and every other C8.8 widening remains incomplete. The separate
prospective target/release policy below does not broaden or rewrite this
historical decision.

### Fixed-QEMU target/release policy v1 (policy checkpoint; not a roadmap implementation node)

This non-C-numbered checkpoint is a governance policy. The policy checkpoint
roadmap position is `post-c88-f5-pre-allocation`. The policy scope is
`prospective-wasm-roadmap-target-and-release-gates`. The policy contract is not
target evidence and satisfies no target or release gate. The normative generic
WASM target/release gate is fresh, source-bound fixed QEMU on
`qemu-virt-rv64-tcg-icount-v1`. Fresh node-specific source, suite, challenge,
run, capture, acceptance predicates, and evidence remain mandatory. Historical
C8.4 and C8.8-F5 QEMU evidence cannot satisfy a future gate.

The policy has `physical_inputs_required=0`,
`physical_inputs_permitted=0`, `physical_provenance=not-claimed`, and
`physical_equivalence_claimed=false`. Fixed QEMU is emulator evidence, not a
claim about Milk-V Duo performance, physical provenance, cache behavior, or
board equivalence. Milk-V Duo remains paused and optional; any later
observation is separate and has no gate, completion, or release effect. Its
machine fields are `gate_effect=false`, `completion_effect=false`, and
`release_effect=false`; resuming it voluntarily cannot replace or mutate the
formal QEMU evidence set.

This replacement is limited to the prospective generic WASM target/release
gate. Any acceptance claim that is intrinsically about real hardware remains a
separate physical gate, including microSD persistence, DWMAC networking, USB,
entropy, cache/DMA coherency, thermal and electrical behavior, and
certification. Those gates are neither satisfied nor weakened by QEMU.
Unrelated board, device, entropy, physical-security, and certification gates
remain unchanged.

The canonical policy contract is
[`fixed-qemu-target-release-policy-v1-contract.json`](../acceptance/wasm-roadmap/artifacts/fixed-qemu-target-release-policy-v1-contract.json).
Passing its verifier proves policy integrity only. Code 5 remains permanently
`ValidationOnly` and inert. No successor identity, roadmap number, profile,
ABI, engine, implementation, execution, admission, release, or production
authority is allocated by this policy. It also authorizes no durable
publication, migration, native bytes, AOT, JIT, RWX, rollout, or in-place
promotion.

## 9.1 C8.9 independent executable Float successor

Explicit allocation creates C8.9 as a new identity rather than an F6 or an
in-place change to code 5. Its ordered nodes are:

| # | Scope | Exit gate |
|---|---|---|
| C8.9-S1 | Freeze independent design | Code 6, artifact/runtime ABI 6, Component/Core profile 3, exact Core/Component/Canonical revisions, the exact vendored software-float Wasmi engine, the closed WIT world, code-5 non-promotion, and the fixed-QEMU policy are frozen |
| C8.9-S2 | Implement runtime and admission | The code-6 codec, current engine binding, validator/executor, Canonical ABI, exact admission surface, lifecycle/accounting, rollback, durable rejection, and negative code-5 isolation gates pass |
| C8.9-S3 | Qualify and decide release | Fresh source-bound normal and optimized evidence on `qemu-virt-rv64-tcg-icount-v1` passes the node-specific contract before any release or production authority is granted |

C8.9-S1 is complete under
[`c89-float-successor-design-v1-contract.json`](../acceptance/wasm-float-target/artifacts/c89-float-successor-design-v1-contract.json).
It selects `PROFILE_3_SYNC_FLOAT_EXECUTABLE`, profile code 6, artifact/runtime
ABI 6, Component/Core profile 3, deterministic scalar-float revision suffix
`c89-exec-v1`, and `vibeos-wasmi-softfloat` version
`1.1.0-vibeos-f2.1` at upstream revision
`8273dfb09d493971b7bb12fe614d740cdc857175`. The selected execution stage is
`Executable`. C8.9-S2 is complete under
[`c89-float-successor-implementation-v1-contract.json`](../acceptance/wasm-float-target/artifacts/c89-float-successor-implementation-v1-contract.json): code 6 now has an exact artifact codec, current software-float engine proof,
closed import-free admission, bit-only Canonical ABI, bounded move-only
lifecycle, cold recovery, and explicit ordinary-command/durable rejection.
Code 5 remains outside every current-engine and executable path. C8.9-S3 is
complete under
[`c89-s3-fixed-qemu-qualification-v1-contract.json`](../acceptance/wasm-float-target/artifacts/c89-s3-fixed-qemu-qualification-v1-contract.json):
the fresh pushed source `2e9bc0c3648656cca8e4d198cbb6a7350975090a`
passed 1,176 records under normal and optimized verification on fixed QEMU.
Release and production authority apply only to the sealed, authority-free
Float admission. Ordinary command routing, durable publication, AOT, JIT,
native bytes, and RWX remain unauthorized.

The C8.9 closure position is `c89-s3-qualified-sealed-float-runtime-released`.
Milk-V Duo remains paused and optional with zero gate effect; no physical
equivalence is claimed. Historical C8.8-F5 evidence was not reused.

## 9.2 C8.10 deterministic fixed-width SIMD widening

C8.10 is the first unfinished non-Float C8.8 widening. C8.10-S1 is complete
under
[`c810-simd-widening-design-v1-contract.json`](../acceptance/wasm-simd-target/artifacts/c810-simd-widening-design-v1-contract.json).
It allocates `PROFILE_4_SYNC_SIMD_VALIDATION`, profile code 7, artifact/runtime
ABI 7, Component/Core profile 4, and stage `ValidationOnly`. Fixed-width SIMD
1.0 is selected; relaxed SIMD and every adjacent proposal remain forbidden.
`v128` is Core-internal and cannot cross WIT, Canonical ABI, or host-call
boundaries.

The S2 engine is now materialized as
`vibeos-wasmi-simd-softfloat@1.1.0-vibeos-simd1.1`. It removes host-float and
`libm` dependence from SIMD lane semantics, freezes
fuel, and passes a complete RISC-V object audit with no F, D, or V instructions.
The closure is recorded by
[`c810-simd-widening-implementation-v1-contract.json`](../acceptance/wasm-simd-target/artifacts/c810-simd-widening-implementation-v1-contract.json).
S3 closes Component containment and corpora. S4 closes a default-off,
exact-image-pinned, authority-free volatile admission token and single-instance
acceptance lifecycle, including explicit cancel/fault recovery, terminal revoke,
and ordinary loader rejection. It creates no durable or command conversion. S5
uses fresh fixed-QEMU evidence to decide successor-review eligibility only.

S5 passed fresh fixed-QEMU evidence at source commit
`4b2add7ccf9dee18891b89548ee24a3e6d828f98`, run ID
`ca57bdf2af07484ef48e8ef09e51700e1f5b7a169de04c58594b66a96c7c8b61`,
under normal and optimized verification. This made a successor design review
eligible but did not itself allocate or authorize one.
Code 5 remains permanently inert, code 6 gains no SIMD, and code 7 remains
validation-only, non-current, non-durable, unreleased, and non-production.
Milk-V Duo remains paused, optional, non-gating, and supplies zero input.
See [WASM_SIMD_PROFILE.md](WASM_SIMD_PROFILE.md) for the frozen design.

## 9.3 C8.11 independent executable SIMD successor

C8.11 follows the same non-promotion rule used by the Float successor. It does
not reinterpret code 7. C8.11-S1 allocates
`PROFILE_5_SYNC_SIMD_EXECUTABLE`, profile code 8, artifact/runtime ABI 8,
Component/Core profile 5, and stage `Executable`. It freezes exact Core,
Component, Canonical ABI, wasm-tools, WIT-world, semantic, engine, authority,
and fixed-QEMU identities under
[`c811-simd-successor-design-v1-contract.json`](../acceptance/wasm-simd-target/artifacts/c811-simd-successor-design-v1-contract.json).

The selected S2 engine is
`vibeos-wasmi-simd-executable-softfloat@1.1.0-vibeos-simd2.1`, derived from the qualified
C8.10 engine tree but independently named. C8.11-S2 materializes its two-file
facade, binds the exact code-8 current engine, and audits the complete closure.
Fixed-width SIMD 1.0 and deterministic software-float lanes are retained;
relaxed SIMD and every adjacent proposal remain forbidden. `v128` remains
Core-internal and cannot cross WIT, Canonical ABI, or host boundaries.

The ordered nodes are:

| # | Scope | Exit gate |
|---|---|---|
| C8.11-S1 | Freeze independent design | Code/ABIs 8, profile 5, exact revisions, world, engine, semantics, code-5/code-7 non-promotion, and target policy are frozen |
| C8.11-S2 | Implement runtime and admission | Code-8 codec, exact current engine, validator/executor, authority-free admission, lifecycle/accounting, durable rejection, supply-chain closure, and RISC-V audit pass |
| C8.11-S3 | Qualify and decide release | Fresh source-bound normal and optimized fixed-QEMU evidence passes the node-specific contract before any release or production authority is granted |

The previous roadmap position was
`c811-s1-simd-executable-design-frozen-pre-implementation`. The implementation
position was `c811-s2-simd-executable-implemented-pre-fixed-qemu`. The current
position is `c811-s3-qualified-sealed-simd-runtime-released`; the next widening
is unallocated. S2 granted only the exact code-8 current-engine binding and sealed
authority-free volatile admission. It grants no durable publication, ordinary
command, release, or production authority. Code 5 remains permanently inert,
code 7 remains validation-only and non-migratable, and historical C8.10
evidence cannot satisfy C8.11. Milk-V Duo remains paused with zero gate input. See
[WASM_SIMD_EXECUTABLE_PROFILE.md](WASM_SIMD_EXECUTABLE_PROFILE.md).

C8.11-S3 binds pushed source commit `90f95df4503a3992067fa68dbcd7d9dd9485ef10`
to a fresh fixed-QEMU campaign with seven records and semantic SHA-256
`ddab9d539744523b332787be6f8a101de00108479c9644136538524f20cd4514`.
Normal and optimized verification and the final-ELF audit pass. The release is
strictly the sealed authority-free volatile code-8 path; durable publication,
ordinary commands, AOT/JIT/native bytes/RWX, and every unrelated hardware gate
remain unchanged.

## 10. Test and evidence matrix

The existing VibeOS evidence layers remain mandatory:

| Layer | Component responsibility | Blind spot |
|---|---|---|
| Portable unit/model tests | Artifact codecs, profiles, WIT/type graphs, import policy, resource ownership, Canonical ABI, status and lifecycle models | Real allocator, MMU, IRQ and executor behavior |
| Differential/spec tests | Core instructions/traps plus Component/Canonical ABI behavior against pinned references | VibeOS authority and target integration |
| Fuzzing | Component/Core decoders, validators, canonical values, resources, adapters, async resumptions and malformed artifacts | Exhaustive target interleavings and hardware DMA |
| In-kernel self-test | Live CSpace use/revoke, ownership, quotas, quantum yield, cancellation, arena reclamation and W^X if AOT exists | Complete remote and persistent workflows |
| QEMU acceptance | VSH/SSH component invocation, multicore progress, async chains, composition, fault/restart, two-boot persistence and raw-disk evidence | Physical Duo cache, storage, entropy and long-duration behavior |
| Formal fixed-QEMU WASM target/release gate | Fresh source-bound, node-specific validation, execution, lifecycle, quota, fault, restart, and soak evidence on pinned emulator profiles | Physical cache/DMA, native microSD/DWMAC/USB/entropy, thermal/electrical behavior, physical security, and certification |
| Optional Milk-V Duo observation (paused) | Separately scoped observations only; never a target/release gate input or completion condition | No generic WASM gate, completion, or release effect |

The formal fixed-QEMU row replaces only the former generic mandatory physical
Duo row. Real-hardware requirements for microSD, DWMAC, USB, entropy,
cache/DMA coherency, thermal/electrical behavior, certification, or another
explicit board property remain independent physical gates.

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
- change either fixed canonical NaN bit pattern or weaken exact-bit checking to
  a WebAssembly allowed-set check;
- classify a canonicalizing Float operation as transport/sign-only, canonicalize
  a transported Core value, preserve an arbitrary NaN payload across the
  Component/Canonical ABI boundary, or let `abs`/`neg`/`copysign` alter a
  NaN payload;
- make profile code 5 executable, bind it to the current engine, or admit it to
  CGV1, durable publication, or guest invocation;
- replace Profile 1's Wasmi dependency with a workspace-wide Cargo patch;
- expose `BadConversionToInteger` to a Float guest while still reporting the
  static `Validation` trap, conflate NaN conversion (`0x0207`) with finite or
  infinite overflow (`0x0202`), or widen the saturating-conversion proposal;
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
- fixed-QEMU target/release soak duration, restart count, and exact baseline identity;
- optional physical-Duo observations, if collected, reported separately with no gate effect;
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
| Floating point conflicts with the integer-only kernel ABI | Medium | Keep Profile 1 integer-only and code 5 permanently inert; the reviewed software-float, exact-bit NaN, conversion-trap, Canonical ABI, differential/fuel, and fixed-QEMU evidence opens only a separately numbered successor design review, never in-place activation |
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
    fuzzers, self-tests, four-hart QEMU gates, and every applicable fresh
    fixed-QEMU target/release gate are green on pinned tools. Optional Milk-V
    Duo observation does not block completion or release.
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
