# VibeOS Developer Plan

What to build, in what order, and how we will know it works.
For *why* the system is shaped this way, see [BLUEPRINT.md](BLUEPRINT.md).

---

> **Current status (2026-08-12):** M1, M2, and the M3.5 lifecycle/evidence
> sequence through 3.16, M4.5, M5.5, M6, and Storage V2 M7.0--M7.6 are
> complete. The original M3 language-expansion items remain partial. Run
> `scripts/status.sh` for the live host-test and corpus inventory; the
> QEMU harness reports target check counts from the boot it actually observed.
> See [TESTING.md](../TESTING.md).

## Reassessment: what should happen next

The repository now proves much more than the original plan expected: the capability
algebra, cross-space revocation, scheduler edge cases, compiler front end, emitted
instruction surface, and native execution paths all have automated coverage. The
remaining risk is no longer dominated by missing syntax. It is dominated by the gap
between **authority** and **lifecycle**: a space can be revoked and its task can now be
cooperatively cancelled with owned wait/timer registrations and a bounded tagged heap account;
audited components now also have bounded fault reclamation and fresh-grant restart.

The revised priority order is:

| Priority | Outcome | Why now |
|---|---|---|
| P0 | Reproducible truth | Pin the toolchain, run the real-rustc oracle in CI, add benchmarks, and remove stale generated/status facts from prose. Performance is part of Bets 2–3 and currently mostly unmeasured. |
| P1 | Supervised components | Bind `TaskId`, `CSpace`, memory ownership, cancellation, exit reason, and restart policy into one lifecycle. This closes the largest gap in the v1 contract. |
| P2 | Resource-safe async runtime | Cancellation-safe wait/timer registration, component heap quotas, and reclaimable fault domains. Required before persistent or numerous components are credible. |
| P3 | Durable authority and one real device | Specify object identity, derivation/tombstone persistence, and crash consistency; then build virtio-blk and the capability-addressed store against that model. |
| P4 | Language performance and breadth | Establish the benchmark first, then decide whether SSA/register allocation or structs/references buys more evidence for the thesis. |
| P5 | Multicore and MMU integrity | Scale only after lifecycle and single-hart invariants are explicit and model-tested; bring W^X/guard pages forward if threat-model work shows they outrank throughput. |

This is a sequencing correction, not a change of thesis. Blueprint §8.1 records the
architectural reasons. The completed M1/M2 history below remains useful evidence;
the new execution plan starts after the M3 record.

## Capability-native shell track

The post-v1 shell track borrows Bash's composition syntax without adopting its
POSIX authority model. **S0--S5 are complete:**
[CAPABILITY_SHELL.md](CAPABILITY_SHELL.md) freezes the surface grammar,
capability/value separation, per-stage authority rules, atomic Job admission,
closeable bounded-stream contract, cancellation order, resource limits, security
invariants, and the downstream acceptance gates. The portable `vsh` module now
implements those gates; the legacy diagnostic commands remain available beside
the capability-native command table only in explicit `legacy-shell` test
builds. Normal images boot a separately supervised `vsh` CSpace/component.

| Stage | Status | Outcome |
|---|:---:|---|
| S0 | ✅ | Normative capability-native shell contract and downstream acceptance gates. |
| S1 | ✅ | Pure bounded lexer/parser/AST, span diagnostics, limits, and host corpus tests. |
| S2 | ✅ | Volatile `INVOKE`, immutable manifests, closeable streams, and ephemeral persistent-cap proxies. |
| S3 | ✅ | Atomic Job admission, dynamic stage CSpaces/tasks, background supervision, join/cancel, and fail-fast teardown. |
| S4 | ✅ | Safe-Rust `echo`/`wc`, host negative acceptance, and QEMU `echo hello \| wc > @console` plus foreground Ctrl-C. |
| S5 | ✅ | Bounded `if`/`while`, scoped value-only functions, command substitution, and immutable exact-manifest script artifacts. |

## 0. The one thing to fix first

*(Written before M1. Kept as the rationale.)*

**VibeOS had zero automated tests.** Every claim in this repository — the four
capability refusals, the compiler's output, the scheduler's wake semantics — was
verified by a human reading QEMU output once. Two real bugs (the dropped self-wake,
the missing `running` task in `ps`) reached `main` and were caught by eye.

The confinement argument in Blueprint §6.3 is currently a table in a Markdown file.
A codegen bug that emits a wrong frame offset is a privilege escalation, and nothing
in the repository would notice.

So M1 is not "add some tests." It is the precondition for every milestone after it,
and nothing else should be built first.

---

## 1. Sequencing principle

Milestones are ordered by **what unblocks what**, not by what is most fun.

```
M1 Foundations ──┬─► M2 Confinement ──┬─► M3 Memory & Types
   (tests, CI,   │     (unwinding,    │      (regions, arrays,
    crate split, │      stack probes, │       type checking)
    revocation)  │      watchdog)     │
                 │                    └─► M3.5 Lifecycle & Evidence
                 └─► (unblocks everything: no milestone lands untested)
                                             │
                              M4 Durable authority + block device
                                      ┌──────┴──────┐
                           language track       M5 Multicore
                                      │         M6 MMU integrity
                                      └──────┬──────┘
                                           v1.0
                                             │
                              M7 scalable Blob CAS storage
```

M2 comes before M3 because adding language features to a compiler whose generated
code cannot be safely aborted multiplies the blast radius of every new feature.
Multicore stays late because it multiplies scheduler states before lifecycle is
defined. MMU work is no longer forced to be last: W^X and guard pages may be pulled
forward as a small integrity slice, but per-process isolation remains a non-goal.

---

## 2. Milestones

### M1 — Foundations (v0.2)

**Goal:** make the system testable, and close the capability model's correctness gap.

**Theme:** nothing here is user-visible. That is the point.

| # | Work item | Notes |
|---|---|---|
| 1.1 ✅ | Split runtime and firmware crates | `vibeos-core` and `vibeos-rustc` are portable no_std libraries; `vibeos-kernel` is a board-selected no_std archive; `firmware/qemu-virt` and `firmware/milkv-duo` own entry symbols and final linking. |
| 1.1a ✅ | Extract an `arch` shim | `cap`, `chan`, and the compiler are already pure and will build for the host as-is. `sync`, `heap`, and `exec` are not: they contain RISC-V `csr`/`wfi` inline asm. Put interrupt enable/disable, `wfi`, and `rdtime` behind a small trait with a no-op host implementation. Without this, the most bug-prone code in the tree (the scheduler) stays untestable off-target. |
| 1.2 ✅ | Host unit tests for `cap` | Attenuation, cascading revoke, generation staleness, `WrongType`, every `CapError` variant. This is the security core; it should have the densest tests in the tree. |
| 1.3 ✅ | Host unit tests for `lex`/`parse` | Golden ASTs, and every diagnostic string asserted — error messages are a UI. |
| 1.4 ✅ | Host unit tests for the instruction encoders | Encode each instruction and compare against known-good words. Cheap, and catches the class of bug that is a privilege escalation. |
| 1.5 ✅ | In-kernel test runner | `selftest` shell command plus a `--test` boot mode that runs assertions and exits via SBI with a nonzero code on failure. This is what CI drives. |
| 1.6 ✅ | QEMU integration harness | A script that boots, feeds stdin, captures output, strips `\r`/ANSI, and diffs against expected. Every shell command gets a golden transcript. |
| 1.7 ✅ | GitHub Actions CI | `cargo test` on host + QEMU integration on every push. No merge without green. |
| 1.8 ✅ | **Cross-space revocation** | Done with an `Arc`-linked derivation graph rather than a keyed registry: a cap is live only if its own node and every ancestor are. Revocation therefore reaches copies in spaces the revoker cannot name, with no registry to keep in sync. |
| 1.9 ✅ | Make generation wrap unreachable | `u64` generations, or refuse to reuse a slot that has wrapped. |
| 1.10 ✅ | Fix the `wfi` wake race | Make "check ready queue" and "sleep" atomic w.r.t. interrupts, so the 50 ms heartbeat is a heartbeat rather than a correctness crutch. |

**Acceptance:**
- ✅ `cargo test` runs on the host with no QEMU and covers cap/lex/parse/encode.
- ✅ CI fails on a deliberate one-word change to an encoder. Ten mutations were
  verified to be caught; the one that is *not* caught by host tests — a wrong
  frame offset — is caught by the QEMU conformance run, and that asymmetry is
  documented in TESTING.md as the reason both layers exist.
- ✅ `revoke` on a cap granted into another space kills the copy. The
  known-gap test failed exactly as designed when 1.8 landed, and was replaced by
  five cascade tests.
- ✅ The heartbeat is now 10 s (was 50 ms) with no change in observable latency;
  the shell stays responsive because keystroke wakes are no longer lost to the
  check-then-sleep race.

**Found by the tests as they were written** (all fixed in the same commit):
- An `if` statement anywhere but last in a block failed to parse. The demo only
  worked because its `if` happened to be final.
- `bump()` does not advance past `Eof`, so the `pos -= 1` backtrack in `ident()`
  walked onto the *previous* token and blamed it for the error.
- Keywords rendered in diagnostics via `Debug`: "expected identifier, found `Fn`".

**Risk:** the crate split touches every file. Do it first, in one commit, before the
tree grows further. The `arch` shim is the part likely to be under-scoped — the
scheduler's correctness bugs so far have all been interrupt-ordering bugs, and those
are exactly what a no-op host arch will *not* reproduce. Host tests buy fast
iteration on scheduler logic; interrupt behaviour still belongs in 1.5.

---

> **M2 status: complete.** Every hole in BLUEPRINT §6.4 is closed and tested.
> 117 host tests, 49 in-kernel checks, 7 QEMU transcript cases including a
> differential run against real rustc.

### M2 — Confinement (v0.3)

**Goal:** turn Blueprint §6.3 from an argument into an enforced property.

Everything here descends from one missing mechanism: **there is no way to abort
running generated code.** Blueprint §6.4 items 1–3 are all the same hole.

| # | Work item | Notes |
|---|---|---|
| 2.1 ✅ | Program trampoline | Save callee-saved regs + `sp` + `ra` before entering generated code; a runtime hook can restore them and return an error. A small catch/longjmp pair in RV64 asm unlocks 2.2–2.4; 3.15 later moved the entire returns-twice edge behind its assembly ABI. |
| 2.2 ✅ | Stack probes | Emit a `sp` limit check at every function prologue. On breach, abort through the trampoline with `stack overflow`. Closes the hole where recursion corrupts `.bss`. |
| 2.3 ✅ | Division and overflow checks | Emit checks; abort with the message real rustc would print. Removes the "RISC-V semantics" caveat from the README. |
| 2.4 ✅ | Fuel / watchdog | Emit a budget decrement at loop back-edges and function entry; exhausting it aborts. A compiled `while true {}` must return control to the shell. |
| 2.5 ✅ | Codegen differential testing | Compile a corpus with the in-kernel compiler *and* with real `rustc` on the host; compare stdout. The corpus doubles as a regression suite and is the strongest oracle available for a compiler this small. |
| 2.6 ✅ | Parser fuzzing | `cargo-fuzz` on the host. The parser must never panic; it must only return `Err`. |
| 2.7 ✅ | Emitter audit | Enumerate every instruction the emitter can produce and prove each is frame-local or compiler-chosen. Turn Blueprint §6.3's table into an asserted test. |
| 2.8 ✅ | Task fault isolation | A panicking component costs its own task, not the machine. The guard invokes user poll code inside an assembly catch boundary, so `longjmp` abandons only that thunk and the scheduler's frame and locals are never disturbed. The faulted task is leaked rather than dropped, because running destructors over a future interrupted mid-poll would be worse than leaking. |

**Acceptance:** all six abort paths are covered by the in-kernel self-test and by
the `aborts` golden transcript, and the shell survives every one of them.

**Acceptance demo:**
```
vibe> rustc edit
  | fn main() { let mut i = 0; while i >= 0 { i = i + 1; } }
  | .
  --- running natively ---
  program aborted: exceeded execution budget
vibe>                          <- shell still alive, components still ticking
```
plus deep recursion aborting cleanly, and `1/0` reporting a divide-by-zero panic.

**Measured cost** (demo program, 5 runs each, min / median):

| | runtime | code size |
|---|---|---|
| unchecked (pre-M2) | 1838 / 2036 us | 3528 B |
| checked | 1918 / 2063 us | 4020 B |

About +4% at the minimum and +1% at the median — inside the noise on this
benchmark — for +14% code size. The 15% budget was not spent, and no check was
weakened to get there. Two optimisations did the work: a positive literal
divisor is provably neither zero nor -1 so both division guards are omitted, and
a function with no call and no loop cannot fail to terminate so it is not
charged fuel (it still gets a stack probe, which is the security-critical one).

The honest reason the overhead is this small is that the stack-machine code
generator is already so instruction-heavy — 11 instructions per constant, two
per stack slot — that the checks disappear into it. When M3's register allocator
lands, the checks will become proportionally more expensive and this needs
re-measuring.

---

> **M3 status: partial.** 3.1, 3.2, 3.3 and the acceptance demo are done; 3.7
> now covers both bounded program regions and tagged kernel-component allocations.
> 3.4 (structs and references) and 3.5/3.6 (SSA IR and register allocation) are not started.
> See "What M3 did not do" below.

### M3 — Memory and a real language (v0.4)

**Goal:** make compiled programs useful without making them unconfined.

Programs today are functions over `i64`. Everything interesting needs storage — and
storage is exactly where confinement gets hard, which is why this comes after M2.

| # | Work item | Notes |
|---|---|---|
| 3.1 ✅ | `MemoryRegion` resource | A bounded arena obtained *by capability*, with `READ`/`WRITE` rights. A program gets memory the same way it gets a console. |
| 3.2 ✅ | Arrays with bounds checks | Checks are unsigned, so a negative index fails the same test — Rust indexes with `usize`, and this is how the subset keeps that guarantee with only `i64`. The region base lives in `s3` and the cursor in `t5`, and the audit asserts that `t5` is only ever `s3 + offset` and always preceded by a bounds check: a program picks an *index*, never an address. |
| 3.3 ✅ | `bool`, unit, and a real type checker | A separate pass that validates *and* annotates: `!` is rewritten to bitwise or logical by operand type, and printed values are tagged so a `bool` renders as `true`/`false`. The point was less catching user mistakes than making the subset a genuine subset — v0.1 accepted `if 1`, which Rust rejects, and every such disagreement was a hole in the differential oracle. |
| 3.4 ⬜ | Structs and `&`/`&mut` with move semantics | Affine values, not a full borrow checker. Enough to write a program with state. |
| 3.5 ⬜ | An SSA IR | Between AST and codegen. Required before any optimization is worth attempting, and it gives the emitter audit (2.7) a narrower surface. |
| 3.6 ⬜ | Linear-scan register allocation | Retire the stack machine. Target: within 3× of `rustc -O0` on the benchmark corpus. |
| 3.7 ✅ | Heap quotas per space | Compiled programs allocate from their bounded `MemoryRegion` capability. Kernel components now run with a stable allocator owner, and every heap block carries that owner in its header; the allocator enforces live-byte quotas before consuming a block and credits deallocation to the original owner. |

**Acceptance: met.** `tests/programs/sort.rs` allocates a 12-element array from
the granted region, scrambles it, insertion-sorts it in place, prints both
orders, and verifies the result — and produces byte-identical output to real
rustc. Out-of-bounds, negative-index, and region-exhaustion all abort cleanly
with the shell surviving, covered by the in-kernel self-test.

### What M3 did not do

**3.5 / 3.6 — the SSA IR and register allocator are not written.** What landed
instead was the cheap half of the same goal: constants are materialized in one
or two instructions instead of a fixed eleven, and literal arithmetic is folded
away. Measured on the demo program (5 runs, min / median):

| | runtime | code size |
|---|---|---|
| pre-M2, unchecked | 1838 / 2036 us | 3528 B |
| M2, checked | 1918 / 2063 us | 4020 B |
| M3, checked + folded | 754 / 1486 us | 3500 B |

So the safety checks now cost *nothing net* against the unchecked baseline —
shortening constants more than paid for them — and the median is 28% faster than
M2. That is a real gain, and it is not the milestone: a stack machine still
spends two instructions per value on stack traffic, which is what an allocator
would remove. The roadmap's "within 3× of `rustc -O0`" target also has no harness
yet, because the comparison is across architectures and machines; that needs
defining before it can be claimed.

**3.4 — structs and references are not started.** This is the largest remaining
language change and wants the type checker to grow a notion of place expressions
first.

---

### M3.5 — Lifecycle and evidence (complete)

**Goal:** turn the current demo components into bounded, observable, restartable
units before adding persistence or more concurrency.

| # | Work item | Acceptance |
|---|---|---|
| 3.8 ✅ | Introduce a `Component` record owning `TaskId`, `CSpace`, memory owner/budget, and state (`Running`, `Exited`, `Faulted`, `Cancelled`) | `ps` and `caps` report the same identity and terminal reason. |
| 3.9 ✅ | Add cooperative task cancellation and join/exit reporting | Cancelling a parked, ready, and self-waking task works; each is polled no more after cancellation. |
| 3.10 ✅ | Make wait queues and timers cancellation-safe | Dropping/cancelling a waiter removes or invalidates its registration; stress tests leave no stale wakers. |
| 3.11 ✅ | Add component-owned allocation accounting | A component exceeding its quota faults without consuming another component's budget; normal exit drops its tagged allocations back to the account baseline. |
| 3.12 ✅ | Replace the permanent fault leak with an owned fault arena | Repeated fault/restart cycles have bounded heap growth. No destructor is run across a `longjmp`. |
| 3.13 ✅ | Add a `bench` command and machine-readable baseline | Record IPC round-trip, IRQ-to-poll latency, cap lookup by derivation depth, heap high-water, compile throughput, and generated code size/runtime. CI detects agreed regression thresholds. |
| 3.14 ✅ | Make builds and differential tests reproducible | Pin an exact nightly; CI runs `scripts/differential.sh` before QEMU; status/test counts come from commands or are explicitly dated snapshots. |
| 3.15 ✅ | Write single-hart scheduler and panic invariants | Model wake/cancel/fault transitions; document that an in-tree non-yielding future remains trusted until preemption or instrumentation exists. |
| 3.16 ✅ | Define resolved-capability lease semantics | Console hooks revalidate a revocable token per operation. Raw memory is covered by a non-cloneable, exclusive invocation lease. Host and QEMU tests distinguish revoke-before-run, revoke-during-run, and a cold launch after revocation. |

3.8 separates stable `ComponentId` from a task incarnation's `TaskId`, so a
later restart can keep its supervisory and memory-owner identity while replacing
the task and CSpace. The boot-time `World` routing and supervisor-held space cap
remain static; the 3.12 restart path replaces the component instance atomically
with a fresh generation, task, arena, and explicit grants.
`ps` and `caps` read the same retained snapshot, including
`returned` and `fault` terminal reasons after the executor removes the task.
The `prog` CSpace is reported honestly as unbound because generated code still
runs synchronously in the shell task. Component snapshots now join that identity
with the allocator's live, peak, budget, and denial counters.

3.9 keeps cancellation cooperative and makes the poll boundary explicit. Ready
and parked tasks are detached from the task map and ready queue, dropped outside the
scheduler lock, and then published as `Cancelled`; an active poll is allowed to
return, after which `Faulted` takes precedence over `Cancelled`, which takes
precedence over a normal return. Poll counts therefore count only real calls to
`Future::poll`. Retained handles provide race-free join/exit reports, and `cancel`
is intentionally separate from capability `revoke`.

3.10 gives every wait and timer registration a unique token. Wait queues also carry
an epoch: channel and UART consumers create a listener before checking their
predicate, so an IRQ or peer wake in the check/register gap is observed on first
poll. Repoll updates the existing waker; Ready, Drop, and cancellation unregister
immediately. Timer entries are deadline-ordered, removing the earliest re-arms the
hardware, and the IRQ path pops due entries without allocating. Wakers are invoked
and released outside registry locks; spawn pre-reserves the ready queue to the
live-task upper bound, so those IRQ wakes do not grow it. Stress tests cancel
hundreds of parked tasks and sleepers and require both registries to return to
baseline. A task interrupted mid-poll is never dropped. Ordinary tasks remain
conservatively leaked; audited World tasks are reclaimed only after incarnation-wide
registration cleanup and quiescence.

3.11 tags every allocation with its original owner, so cross-component and IRQ
deallocation cannot debit whichever task happens to be running. The executor installs
the component owner only while polling or destroying its future; scheduler, channel,
timer, wait, capability, and TTY storage use the SYSTEM domain. A quota refusal records
the denial and faults only that component. A normal return or cancellation runs Drop
and returns live use to baseline, after which the temporary owner account can be
unregistered. Faulted allocations remain owned until the 3.12 arena boundary either
observes normal Drop returning them or raw-reclaims a faulted incarnation without
running destructors across `longjmp`.

3.12 keeps the stable `ComponentId`, allocator owner, and `Space` object while every
restart installs a new generation, `TaskId`, `ArenaId`, and explicitly granted CSpace.
CSpace reset retains slot generations, preventing stale handles from aliasing new grants.
The raw path is deliberately sealed: registration targets must be SYSTEM/supervisor
stable, messages may not carry arena-backed ownership across the boundary, and only
the audited World factory can opt a task into reclamation. Host tests cover sibling
teardown, nested cancellation, recursive-executor rejection, registry cleanup, and
domain-tagged lock recovery. The target self-test performs sixteen real quota-fault /
restart cycles, observes no destructor calls, and requires heap use to plateau.

3.13 publishes a versioned guest JSON stream and a checked-in QEMU/TCG baseline.
The runner fixes `virt`/`rv64`/one hart/single-threaded TCG plus deterministic
`icount`, records QEMU and Rust revisions, and refuses silent schema or sample-count
changes. The 2026-08-08 baseline records IPC p95 110 ticks (257 samples), timer
IRQ-to-poll p95 24 ticks (129), cap lookup p50 2–4 ticks across derivation depths
0–32, compile p50 357,646 source B/s (21), a 113,792 B heap high-water, and
828 B code / 1 B data / 1,862 tick runtime for the fixed generated workload.
These are regression coordinates for one virtual environment, not a cross-machine
Linux-pipe comparison.

3.14 makes the evidence reproducible rather than merely repeatable on one laptop.
`rust-toolchain.toml` pins `nightly-2026-08-01` and records its full rustc commit;
local scripts reject a mismatched compiler and no longer use the stable-compiler
bootstrap escape hatch. CI is an explicit `host-tests -> differential -> qemu-tests`
chain. The real-rustc oracle is byte-exact, read-only by default, fails on missing
or orphan expectations, and updates only through `--update`. Repository inventory
comes from `scripts/status.sh`; target self-test totals come from the live QEMU
transcript instead of copied prose.

3.15 separates a task's lifecycle phase from the place that owns its future. A
pure fixed-point model exhaustively explores two tasks in the same and different
fault arenas across wake, cancel, dispatch, pending/ready/fault, destructor fault,
reclaim, and publication. Debug builds check the corresponding concrete scheduler
invariants at mutation boundaries: a future has one owner, each logical hart has at
most one running slot, ready IDs are unique, and a committed terminal claim cannot
be revived or rewritten. The RISC-V fault boundary is now a single-return
`vibe_catch` call from Rust; its internal assembly owns both the initial save and
the non-local return, including per-frame interrupt state. This removes the
unmodelled returns-twice edge from Rust/LLVM while preserving nested task and
generated-program recovery. The kernel now builds for the integer-only
`riscv64imac-unknown-none-elf` `lp64` ABI, matching the integer register context
the catcher actually preserves rather than silently promising `lp64d` FPU state.
None of this turns cooperative scheduling into
temporal isolation: an admitted in-tree future that never yields remains trusted.

3.16 makes resolution lifetime part of the capability API instead of an implicit
property of `Arc`. `Revocable<T>` rechecks the complete derivation ancestry at every
operation acquisition; a successful check linearizes an already-started operation,
so revocation prevents later operations without pretending to interrupt one in
flight. `InvocationLease<T>` is non-cloneable and deliberately survives revocation
for one bounded invocation. Generated console hooks use the first form. Generated
raw memory uses the second form, holds an exclusive `MemoryInvocation` across the
complete catcher call, and releases it after both normal and non-local returns.
`rustc lease` deterministically revokes `prog` before its second console operation:
the second write is denied, the active memory computation still returns 42, and a
second launch with no fresh grants aborts before acquiring memory. Typed resolution
now uses safe `Arc::downcast` on the real trait object rather than trusting a
resource-provided `as_any` result.

**Acceptance:** start a component, revoke its authority, cancel it while blocked,
observe its terminal state, restart it with a fresh explicitly granted CSpace, and
repeat fault/restart enough times to demonstrate bounded memory. Publish the first
repeatable measurement table for the four architectural bets. The generated-program
demo reports whether revocation is immediate or invocation-scoped and tests exactly
that contract.

**Non-goal:** cancellation is not preemption. It takes effect at a poll boundary and
cannot rescue a trusted future that never yields; the API and documentation must not
claim otherwise.

---

### M4 — Devices and persistence (v0.5)

**Goal:** stop being a demo.

| # | Work item | Notes |
|---|---|---|
| 4.0 ✅ | Specify the durable-capability format and crash model | Stable object/derivation/space/transaction IDs, fixed sealed records, prepare/commit grants, tombstone-first revoke, high-water allocation, and fail-closed recovery. Host tests enumerate every sector-prefix and flush boundary. |
| 4.1 ✅ | virtio-blk driver as a supervised component | Modern virtio-mmio discovery, explicit MMIO/DMA/service grants, fixed SYSTEM DMA, bounded split queue, IRQ completion, timeout/reset, cancel, quarantine, and bounded fault restart. QEMU verifies the host backing sector after write+flush. |
| 4.2 ✅ | Capability-addressed store | Objects are named by capability, not by path. `store.get(cap)` / `store.put(obj) -> cap`. Blueprint §9 forbids a path namespace; this is the alternative. |
| 4.3 ✅ | Persist a CSpace | The fixed `persistent-test` SpaceId restores a typed object-capability graph only after inert preflight, external root policy, and atomic installation. Three boots prove ancestor tombstones and generation-1 slot reuse. |
| 4.4 ✅ | virtio-net + a typed socket endpoint | Modern device ID 1, q0 RX/q1 TX, two fixed eight-entry queues, bounded `Endpoint<Packet>`, shared reset/quarantine, and independent raw-L2 host evidence. |
| 4.5 ✅ | Source and binary persistence | `rustc save hello` / `run hello`. One canonical ProgramArtifact binds source, relocatable VIBEEXE, ABIs, hashes, and exact reconstructed authority. |

4.0 fixes the authority-store ABI before a device can make accidental bytes durable.
The append-only v1 log uses canonical 512-byte little-endian records, CRC32C, a
non-zero final seal, and a strict previous-sequence/CRC chain. Stable typed IDs are
reserved by a flushed exclusive high-water mark before use. Grants publish only
after a matching prepare and commit have each been flushed; revocation writes and
flushes its tombstone before killing live state. Recovery revalidates exact external
root policy, parent `GRANT`, rights attenuation, object/type identity, transaction
binding, and slot-generation reuse, then applies ancestor tombstones in a final pass.
All 0..512 prefix cuts of every record and every grant/revoke/high-water protocol
boundary recover either the old state or the exact requested subset. The proof is
explicitly limited to the documented single-writer, prefix-torn-write, ordered-flush
media contract; CRC is not authentication or rollback resistance. See
[DURABLE_FORMAT.md](DURABLE_FORMAT.md). The `durable` shell demo runs the same pure
recovery verifier.

4.1 adds the first supervised hardware driver. It scans QEMU `virt` transports,
accepts only a modern block device, and negotiates a deliberately small split-ring
surface. A fixed, page-aligned SYSTEM DMA slab outlives every reclaimable driver
arena; no client pointer enters a descriptor. Timeout, component cancellation, and
fault-after-notify all reset and confirm status zero before descriptor reuse. A
failed confirmation quarantines the device. Faulted incarnations restart at most
three times with bounded backoff, while explicit cancellation does not restart
automatically. The `block` transcript reads a host-seeded sector, writes and flushes
another, and the harness then compares the raw backing sector after shutdown. See
[VIRTIO_BLK.md](VIRTIO_BLK.md).

4.2 extends that same canonical journal with object prepare/chunk/commit records;
kinds 1--8 share one decoder, high-water mark, transaction table, and numeric ID
class map. The service scans a fixed region through an attenuated backend cap,
flushes before publication, rereads the committed bytes, and atomically mints only
into the pre-await CSpace incarnation. There is no path, `open(ObjectId)`, or object
enumeration API. Repeated injected raw faults against a host-seeded 506-record
journal prove the fixed `.bss` scratch buffer, bounded streaming recovery, and
exact-task/domain claim cleanup remain heap-bounded; the final append fills all
512 slots before the host independently parses the powered-off raw image. See
[OBJECT_STORE.md](OBJECT_STORE.md).

4.3 registers one fixed `persistent-test` `SpaceId` and restores only its externally
admitted `StoredObject` graph. Unified journal recovery remains inert until an exact
root policy matches; the complete slot table and `root -> child -> grandchild`
derivation graph are then installed atomically into the same CSpace incarnation.
One disk survives three QEMU boots: creation and readback, tombstone-first ancestor
revoke, then generation-1 child-slot reuse. The target never receives Store `WRITE`,
and an independent host parser checks the final raw graph plus 19 records times 512
strict prefix cuts. See [PERSISTENT_CSPACE.md](PERSISTENT_CSPACE.md).

**M4.3 acceptance:** the three-boot fixed-space lifecycle above is green, including
raw-media verification and tombstoned descendants staying dead.

4.4 deliberately acknowledges only `VIRTIO_F_VERSION_1` and uses one pair of
eight-entry split queues with contiguous 12-byte-header-plus-frame DMA buffers.
Owned `Packet` values cross bounded typed endpoints; client pointers never enter a
descriptor. RX/TX share one epoch and one reset boundary, so a timeout, malformed
completion, or post-notify component fault quarantines both queues until status zero
is confirmed. The unprivileged QEMU acceptance peer listens only on localhost and
strictly verifies four-byte-length-prefixed raw Ethernet HELLO/CHALLENGE/ACK frames.
See [VIRTIO_NET.md](VIRTIO_NET.md).

**M4.4 acceptance:** the ordinary exchange matches both its guest transcript and
canonical host frame evidence. The recovery case observes the faulted
incarnation's abandoned HELLO, then a second HELLO and complete exchange from a
fresh device epoch. Both focused non-update QEMU cases and the complete regression
suite are green.

4.5 publishes the fixed `hello` source and canonical address-independent VIBEEXE
as one read-only durable object root. A global SpaceId-partitioned root-policy
union admits the M4.3 and program graphs together and rejects every extra root.
Recovery strictly decodes both formats, recompiles the source with the current
trusted compiler, requires byte-identical VIBEEXE, and only then links it. Console
`WRITE` and memory `READ|WRITE` are reconstructed from a private supervisor policy
CSpace; legacy `prog` authority and Store `WRITE` are absent. See
[PROGRAM_PERSISTENCE.md](PROGRAM_PERSISTENCE.md).

**M4.5 acceptance:** one raw disk survives two boots. The first saves and runs;
the second appends nothing, restores slot 0/generation 0, verifies current compiler
identity, and runs with the exact manifest. An independent parser verifies the
powered-off journal/artifact/VIBEEXE plus every strict record-prefix cut.

**M4 final acceptance: met.** Save `hello` at the shell, reboot, and run the
recovered source/binary object with exactly the fixed persisted authority manifest.

---

### M5 — Multicore (v0.6)

| # | Work item |
|---|---|
| 5.1 ✅ | Per-hart run queues with work stealing |
| 5.2 ✅ | IPI-based cross-hart wakeups (SBI `sbi_send_ipi`) |
| 5.3 ✅ | Audit every `SpinLock` for real contention; replace the hot ones with lock-free structures |
| 5.4 ✅ | Hart-local storage for the scheduler's `running` slot |
| 5.5 ✅ | Boot secondary harts via SBI HSM |

**Acceptance:** `-smp 4` with the integration suite green and measurable throughput
scaling on a parallel benchmark. Loom or a similar model checker on the scheduler.

**Resolved risk:** 5.4 replaced the singleton running state; 5.5 validates those
slots under simultaneous physical execution.

5.1 makes ready ownership explicit across four logical hart queues. Each enqueue,
wake, cancel, fault, and dispatch keeps `TaskId -> queue owner` synchronized under
the scheduler lock; hart 0 prefers local FIFO work and deterministically steals
eligible remote work. Spawn reserves every queue for the global live-task bound, so
an IRQ wake performs no allocation. Scheduler stats expose per-hart queued,
dispatch, and steal counts, while `wake_with_disposition` returns the disposition
and target hart for the M5.2 notification boundary without breaking the original
`wake` API. Raw-reclaimable fault arenas remain hart-affine and
non-stealable because sibling quiescence is not yet a cross-hart invariant.

**M5.1 acceptance:** pure queue tests and a two-task fixed-point model cover unique
ownership, capacity, steal, wake-during-poll, cancellation, and fault publication.
`scripts/qemu-test.sh smp_queues` retains the one-CPU physical acceptance boundary,
places one untracked task on each logical remote queue, and requires hart 0 to
steal all three with each task executing exactly once. IPI delivery, hart-local
running slots, and secondary-hart boot remain gated to 5.2, 5.4, and 5.5
respectively.

5.2 publishes a lock-free runnable reason only after queue insertion. Each logical
hart mailbox combines reason bits and a kick-armed bit in one atomic word: a
`Release` publication arms at most one SBI doorbell, a failed send clears only the
armed bit so later publication can retry, and the receiver clears SSIP, executes an
explicit `fence iorw, iorw`, then consumes reasons plus armed state in one `Acquire`
swap. The producer likewise fences before its SBI call. Current-hart notifications
do not send needless self-IPIs. The IRQ-masked idle gate samples the ready queue and
consumes its local mailbox before WFI; a consumed reason forces another executor
turn, while a later delivered SSIP is harmlessly stale. This avoids both lost sleep
and a permanently busy idle loop after work is stolen or cancelled.

Logical queue ids are not assumed to be firmware hartids. Online registration binds
each logical hart to the physical id supplied by SBI, and standardized sends use
`hart_mask = 1, hart_mask_base = physical_hartid`. VibeOS does not guess the
topology-sized bit vector required by legacy EID 0x04; unavailable modern IPI support
is therefore fail-stop instead of a falsely successful wake.
Only the boot hart is online in M5.2. Offline logical queues retain reasons without
issuing invalid SBI calls, ready for the already-awake HSM startup handoff in M5.5.
An unexpected send failure for an online hart is fail-stop at the executor hook so
firmware failure cannot be misreported as a component fault.

**M5.2 acceptance:** concrete host tests cover coalescing, stale IPIs, offline
handoff, non-contiguous physical hartid mapping, failed-send retention and retry.
Small-state models enumerate all 70 enqueue/set/fence/send versus
IRQ-off/check/check/WFI merges and all 35 clear/fence/swap versus concurrent-publish
merges. The one-CPU `smp_queues` QEMU case proves stopped logical harts retain reasons
without SBI calls and deliberately forces one boot-hart self-doorbell through real
OpenSBI, SSIP trap acknowledgement, and executor return. Physical secondary
execution, per-hart running state, and `-smp 4` acceptance remain gated to 5.5, 5.4,
and the M5 final acceptance respectively.

5.3 records every lock family and its retain/replace decision in
[`SPINLOCK_AUDIT.md`](SPINLOCK_AUDIT.md). The lock itself now publishes a complete
owner/arena/task record under a phase-plus-generation token; a stale fault
recovery cannot ABA-unlock a later guard, conservative SYSTEM-domain cleanup must
match the exact nonzero task key, guards are statically non-`Send`, and Drop
verifies its acquisition hart before restoring local interrupt state.
Allocation-free telemetry distinguishes acquisitions, observed contention, and
fault recovery. Only stable locks named by a cleanup hook opt into provenance;
ordinary hot locks retain the lean CAS path, keeping the committed performance
budget green.

The locks in the device-data portion of IRQ handling are removed: PLIC dispatch
uses bounded atomic handler snapshots, UART RX is a fixed SPSC ring, virtio block
and network callbacks carry their validated MMIO base in the same atomic handler
publication, and executor callbacks use atomic function slots. Transactional locks
for scheduler lifecycle, waiters, timers, heap accounting, capability graphs, and
durable recovery remain explicit. This does not describe the complete IRQ path as
lock-free: waiter detach and scheduler wake still use those audited boundaries.

**M5.3 acceptance:** host threads race the atomic IRQ cells for 100,000 iterations,
exercise real SpinLock contention, separate same-domain task recovery, reject
stale-generation recovery and cross-hart guard Drop, and compile-fail a `Send`
guard. `smp queues` exercises the target path,
samples the retained scheduler lock, and requires zero contention on its honest
single-hart boundary. Physical contention and the scaling decision are deliberately
measured after M5.5 boots secondaries.

5.4 replaces the scheduler's singleton `running`/`running_woken` pair with one
slot per logical hart. Dispatch, wake, cancellation, reporting, and ownership
invariants inspect the complete slot set, while each executor may poll only the
slot matching its exact logical identity. Current-task identity, task fault
recovery context, allocation owner/arena provenance, allocation-failure
diagnostics, interrupt state, nested task catchers, generated-program catchers,
runtime console authority, and the deterministic revocation hook are likewise
hart-local. Every scope that restores ambient state is non-`Send` and verifies
same-hart restoration. Target code never treats a dense-looking firmware hartid
as a logical slot: successful self-registration caches `logical_index + 1` in
the hart's `sscratch`, while zero is a fail-closed unregistered token. One
executor turn resolves that identity once and passes the validated slot through
its owner/task/recovery scopes.

Tracked reclaimable arenas remain home-hart and non-stealable. A fault detaches
only its own running slot, proves no peer slot is still executing that arena,
then removes parked/ready siblings before recovery and publication without
holding the scheduler lock across reclaim work.

**M5.4 acceptance:** host tests nest one logical hart's executor inside another
to expose two simultaneous running slots, preserve each hart's current task and
allocation domain, route wake and remote cancellation to the exact slot, and
prove a fault on one hart leaves the other running task intact. Heap tests isolate
owner/arena and OOM diagnostics, reject cross-hart scope Drop, and compile-fail a
`Send` owner scope. The target release build plus the existing nested catcher,
program-abort, self-test, and `smp_queues` QEMU paths remain green. Actual
simultaneous physical execution is deliberately gated to M5.5. The fixed QEMU
budget remains green (`ipc_roundtrip_ticks` p95 152, `irq_to_poll_ticks` p95 36)
without widening the committed thresholds.

5.5 implements SBI HSM status/start with its asynchronous contract intact. The boot
hart reserves mappings while targets remain offline; each secondary selects a
private 256 KiB stack slot from its logical opaque value, installs hart-local trap
and timer state, self-registers, and only then publishes the ready barrier and
accepts IPIs. M6.2 subsequently leaves the first 4 KiB of each slot unmapped and
uses the remaining 252 KiB as its stack without changing the HSM slot stride.
OpenSBI may choose any coldboot physical hart, which dynamically becomes logical 0
and owns the sole enabled PLIC S-mode context. BSS, heap, World, device, and PLIC
initialization therefore still execute exactly once. The boot scanner is
deliberately limited to QEMU `virt`'s dense physical IDs `0..3`; the mapping layer
itself retains sparse-ID host coverage, while a general platform port needs FDT
topology enumeration.

Machine-local tasks can opt into non-stealable placement; the UART shell is pinned
to logical 0 so its acceptance commands have an unambiguous source. `smp queues`
parks one exact-hart task on each secondary, drains the placement doorbells, and
wakes all three from the boot hart through real SBI/SSIP delivery. A synchronized
four-hart scheduler-lock sample must observe nonzero contention; the final full
suite run recorded 1,688 contended acquisitions out of 2,170. Existing exhaustive
run-queue, lifecycle, scheduler, and IPI state models remain the similar-model-
checker acceptance layer.

**M5.5 acceptance:** all 18 integration cases pass with `-smp 4`, including 336
in-kernel checks, raw disk/network evidence, three-boot persistent CSpace, and
two-boot program persistence. The equal-work scaling command uses four exact-hart
workers and a roughly 75 ms serial window; the final run measured 773,610 serial
ticks versus 275,290 parallel ticks (`2.810x`) against a conservative `1.25x` CI
floor. Its strict parser has positive and fail-closed fixtures, and both the parser
and physical scaling run are CI steps.

---

### M6 — The MMU, for integrity (v0.7)

Not for isolation — Blueprint §9. For the things software checks do worse:

| # | Work item |
|---|---|
| 6.1 ✅ | Sv39 paging with a single address space |
| 6.2 ✅ | Guard pages below every stack (makes 2.2 defence-in-depth rather than sole defence) |
| 6.3 ✅ | W^X for code buffers: writable while emitting, execute-only after `fence.i` |
| 6.4 ✅ | Read-only mapping for `.rodata` and the capability tables |

M6.1 installs one ASID-zero Sv39 root shared by every hart. It identity-maps only
the 126 MiB kernel RAM window and only the 4 KiB device pages touched by the PLIC,
UART, and eight virtio-mmio transports; the OpenSBI prefix, null page, unused MMIO,
and unused physical space stay absent. RAM and devices deliberately use 4 KiB
leaves even before RAM permissions diverge. Device leaves are non-executable. The
boot hart constructs the hierarchy in zeroed `.bss`, publishes it,
and enables paging before global kernel initialization. SBI HSM starts peers with
`satp=0`; each secondary installs and reads back the shared root before trap setup,
self-registration, or its online bit.

**M6.1 acceptance:** six host tests cover known-word PTE/satp encoding, canonical
virtual addresses, and fail-closed leaf validation. The `mmu` command reports the
live ranges, leaf sizes, and all four hart readbacks; 21 in-kernel checks walk the
live hierarchy and verify identity, permissions, and deliberate holes. Every QEMU boot
must publish the Sv39 marker,
so the complete integration suite cannot silently fall back to Bare mode.

M6.2 divides every fixed 256 KiB per-hart slot into one invalid 4 KiB page at its
low end and 252 KiB of identity-mapped, read/write, non-executable stack. The slot
stride remains 256 KiB, so the secondary-entry shift and hart-to-slot mapping do
not change. Generated-code stack probes stop 8 KiB above the first usable byte,
leaving mapped room for the normal abort path between their floor and the guard.

**M6.2 acceptance:** four in-kernel checks cover all four invalid guard PTEs, the
first and last usable RW-NX pages, the unchanged aligned slot stride, guard address
classification, and the exact 8 KiB abort reserve. The expected-fatal
`guard_page` QEMU case performs a real store into hart 0's printed guard address;
the raw harness requires exception cause 15 (`store page fault`), requires `stval`
to equal that address exactly, and requires the guard-specific trap marker.

This is a fail-stop boundary for accesses whose address lands in the guard, not a
complete stack-clash defence or recovery stack. A sufficiently large or corrupted
`sp` adjustment can jump over one guard page into another mapped page. A real
overflow can also fault again when trap entry tries to save registers on the same
bad stack, so skipped-guard protection would require probing or a stronger boundary
and reliable diagnostics or recovery would require a separate per-hart emergency
trap stack. M6.2 claims exact guard-page enforcement, not either stronger property.

M6.3 changes the default kernel-RAM leaf from RWX to RW-NX, then applies two
deliberate exceptions: linker-delimited kernel text is R-X, and generated code is
execute-only after sealing. Generated instructions live in a dedicated, page-aligned
2 MiB pool rather than sharing allocator pages. The trusted compiler links directly
into an exclusively owned `WritableCode` run while it is RW-NX; sealing consumes that
writable view and publishes an `ExecutableCode` which exposes only its entry address,
length, and page count. Persisted VIBEEXE still passes byte-identical recompilation
admission before it reaches this same link-and-seal path.

Every RW-NX/execute-only transition validates the complete old range before changing
anything, installs invalid PTEs, performs local and synchronous remote `sfence.vma`,
installs the new PTEs, and performs a second all-hart TLB shootdown. Sealing then adds
local `fence.i` plus SBI RFENCE `remote_fence_i` before the executable object is
published. The page-table lock covers the complete break-before-make transaction.
The boot barrier rejects an unrepresentable physical-hart mask or missing SBI RFENCE
support, and a failed live shootdown is fail-stop because partial permission
publication cannot be rolled back safely. Every hart also clears and reads back
`sstatus.MXR` before publishing paging enabled, so an execute-only leaf cannot be
loaded through MXR.

Dropping sealed code removes execute permission through the same break-before-make
protocol, clears every byte in the page run including padding, and only then returns
its first-fit allocation record for reuse. Allocation identities include generation
and allocation-domain ownership. The audited fault-domain reclaimer runs only after
all-hart task quiescence and applies the same unseal/clear/free sequence to code whose
Rust `Drop` was skipped by `longjmp`.

**M6.3 acceptance:** host tests cover exact SBI RFENCE requests and errors, local
fence/MXR state, fail-closed sparse physical-hart mask construction, and the
compiler's exact-length, no-write-on-error in-place linker. In-kernel checks walk
the real PTEs for R-X text, RW-NX free pool pages, execute-only compiled pages, and
the absence of any writable-executable RAM leaf; sixteen fault/restart cycles also
require code-pool use to return to baseline without invoking an interrupted
destructor. The non-fatal `wx` QEMU case seals and runs one image on the boot hart
and hart 1, drops it, requires a zeroed same-address allocation, seals different
code there, and obtains the new value on hart 1 without a per-run `fence.i`. Three
expected-fatal cases require real instruction/load/store page faults (causes 12,
13, and 15) for executing a writable page and reading or writing a sealed page;
the raw harness requires each printed probe address to equal `stval` exactly.

This is an integrity boundary inside one shared S-mode address space, not process
isolation or proof that the emitter is correct. The fixed pool is tracked by
allocation domain but is a separate global resource rather than bytes charged to a
component's heap quota. Audited tracked faults reclaim it; conservative untracked
faults retain the existing leak-on-fault policy.

M6.4 maps the linker-delimited `.rodata` range read-only and non-executable during
boot. Capability tables use a separate linker-reserved 4 MiB page pool. Every
mutation first clones and edits a complete candidate `Vec<Slot>` under SYSTEM
allocation. Commit has no `await`: it moves that candidate into a fresh, exclusively
owned RW-NX page run, seals the complete run R-- with break-before-make and two
all-hart `sfence.vma` phases, and only then atomically replaces the CSpace's
authoritative table. The retired table is no longer authoritative before it returns
to RW-NX; its `Slot` values are dropped, every byte is cleared, and the first-fit run
may then be reused.

Normal validation errors occur before publication and leave the old table
authoritative. An exceptional fault or fail-stop during SYSTEM candidate construction
or protection may conservatively leak that detached candidate; M6.4 does not claim
rollback across such non-local failure. The hardware protection covers the published
`Slot` snapshot, including its generation and live entry's rights, object pointer,
and derivation pointer. CSpace scalar lifecycle fields and each `Derivation.alive`
`AtomicBool` remain writable supervisor metadata. This is neither per-component
isolation nor immutable storage for the complete capability graph.

**M6.4 acceptance:** the host capability suite checks page-aligned COW replacement
and exact allocate/protect/release backend ordering.
In-kernel checks require the `.rodata` endpoints and every non-empty published World
capability table to be R--, require every live pool page to be read-only, and exercise
mint/derive/revoke plus cleared same-address reuse. The non-fatal `ro` QEMU case adds
hart-1 lookup and post-revoke denial while checking the expected all-hart shootdowns.
Two expected-fatal cases store into `.rodata` and a published capability table; the
raw harness requires cause 15 and requires `stval` to equal each printed probe address
exactly. Every QEMU boot must also publish the `.rodata`/4 MiB COW-pool marker.

---

### v1.0 — Definition of done

1. Every Blueprint §6.4 hole closed or documented as accepted, with a test.
2. CI green: host unit tests, QEMU integration, compiler differential corpus, fuzzing.
3. A supervised component can be added, granted authority, run, revoked, cancelled,
   observed, reclaimed, and restarted — without restarting the machine. “Cancelled”
   is explicitly cooperative unless a later isolation mechanism strengthens it.
4. `-smp 4`.
5. Programs survive reboot with exactly the authority that was persisted.
6. Published measurements for every number in §5.

### M7 — Scalable capability-addressed storage (post-v1)

**Status (2026-08-12):** M7.0--M7.6 are complete: SHA compatibility,
capability-scoped block contracts, canonical segment format, append-only
storage, streaming CAS, and root-based crash-safe cleaning. M7.6 online growth,
quotas, and scrub add capability-gated adjacent capacity, governed admission,
and bounded anonymous media verification. M7.7 migration and default cutover is
next. See [STORAGE_V2_MAINTENANCE.md](STORAGE_V2_MAINTENANCE.md) for the accepted
maintenance, accounting, and scrub contract.

M7 replaces the fixed 512-sector M4 journal backend with a managed-block-device
Blob CAS backed by immutable segments, dual checkpoints, root-based garbage
collection, quotas, scrub, and capability-scoped online growth. It preserves the
existing `StoredObject` API and keeps content digests separate from authority.
The logical Merkle format moves to the pure-Rust `sha2` implementation without
changing any encoded byte or root.

The ordered stages are M7.0 SHA compatibility, M7.1 block-range and geometry
contracts, M7.2 canonical segment format, M7.3 append-only segment storage, M7.4
streaming CAS, M7.5 GC, M7.6 growth/quotas/scrub, and M7.7 M4 migration and
cutover. Raw NOR/NAND, paths, chunk-level deduplication, encryption, multi-device
RAID, and online shrink are outside this milestone. The complete dependency and
acceptance plan is in [STORAGE_V2_ROADMAP.md](STORAGE_V2_ROADMAP.md).

---

## 3. Workstreams

The continuing tracks after the partial M3 milestone are:

| Track | Owns | Near-term outcome |
|---|---|---|
| **Lifecycle** | `exec`, `cap`, `heap`, `world` | M3.5 supervision, cancellation, ownership, and reclamation; gates persistent services and multicore |
| **Evidence** | `tests`, `scripts`, CI, `bench` | Reproducible builds, real-rustc oracle execution, regression budgets, and dated metrics |
| **Compiler** | `compiler`, `kernel/rustc`, trampoline | Resolved-cap lease semantics are complete; 3.4–3.6 remain evidence-driven language-track work rather than a persistence prerequisite |
| **Platform** | drivers, storage, `tty`, `shell` | M4.0--M4.5 durable model followed by M7 segment/checkpoint storage, GC, growth, and migration |
| **Scaling/integrity** | scheduler, `sync`, trap, boot, page tables | M5/M6 after single-hart lifecycle transitions are model-tested |

The lifecycle track is the integration spine: a driver, persisted program, or remote
endpoint is not ready to ship until it has an owner, budget, cancellation path, and
observable exit state. Evidence can proceed in parallel; language breadth must not
silently become the critical path for storage or supervision.

---

## 4. Testing strategy

Four layers, cheapest first.

**Host unit tests** — `cargo test`, no QEMU. Everything pure: capability algebra,
lexer, parser, instruction encoders, heap size classes. This is where the density
should be highest, because it is where iteration is fastest.

**In-kernel self-test** — a `--test` boot mode running assertions that need real
hardware: interrupt delivery, timer wakeups, wake-during-poll, allocator under
fragmentation. Exits via SBI with a status code.

**QEMU integration** — golden transcripts. Boot, feed stdin, normalize `\r` and ANSI,
diff. Every shell command and every diagnostic gets one.

**Compiler differential testing** — the highest-value item in the plan. Compile a
corpus with both the in-kernel compiler and real `rustc`, and compare stdout. Every
program in the subset is also a valid Rust program, so real rustc is a free oracle.
Grow the corpus with every bug found.

Plus: **fuzzing** the parser (must never panic), and **`loom`** on the scheduler once
M5 makes concurrency real.

**Rule:** a bug that reaches `main` gets a regression test in the same commit as its
fix. Both bugs found so far — the dropped self-wake and the missing `running` task —
should be the first two entries in the in-kernel self-test.

---

## 5. Metrics

Numbers to publish and defend. Bets 2 and 3 are performance claims; unmeasured, they
are just assertions.

| Metric | Why | Today |
|---|---|---|
| IPC round-trip (ns) | Bet 2 claims a queue push beats a mode switch. Prove it against a Linux pipe. | unmeasured |
| Wake latency: IRQ → task polled | Bet 3's core claim | unmeasured; the known `wfi` lost-wake race is fixed |
| Idle CPU draw | Should be zero | unmeasured |
| Compile throughput (KB/s) | 3528 B from ~3 fn in ~5–15 ms today | rough |
| Generated code vs `rustc -O0` | Honest accounting of the stack machine's cost | unmeasured |
| Cap lookup cost | On every operation; must stay cheap | unmeasured |
| Kernel size / `unsafe` count | TCB is the product | snapshot required; report source lines and `unsafe` sites separately |

Add the `bench` shell command in M3.5. Results must include QEMU version, CPU model,
toolchain revision, build profile, sample count, and distribution (not only a minimum).

---

## 6. Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| A codegen bug is a privilege escalation, and the emitter is unverified | **High** | 2.5 differential testing, 2.7 emitter audit, 3.5 SSA IR to narrow the surface |
| Authority revocation is mistaken for task termination | **High** | M3.5 supervised `Component`, explicit cancellation states, end-to-end revoke/cancel/restart test |
| A resolved object outlives the cap that authorized it | **High** | 3.16 explicit lease semantics; operation-time revalidation for revocable devices; no “immediate” claim for raw memory without enforcement |
| Ordinary faulted tasks leak heap | **Medium** | 3.12 reclaims only sealed World arenas after incarnation-wide teardown; generic tasks retain the sound conservative leak policy until they gain an equivalent no-escape contract |
| Bet 2's cheap-IPC claim goes unmeasured and turns out false | High | §5 metrics in M3.5, before optimizing or scaling the design |
| Physical multicore execution exposes hidden singleton runtime state | Medium | 5.4 partitions running/current-task, heap provenance, trap, and recovery state; 5.5 must boot secondaries only after stacks and per-hart trap setup are ready |
| Language features outrun confinement | Medium | M2 strictly before M3; no new syntax without an abort path |
| Scope sprawl into POSIX compatibility | Medium | Blueprint §9 is binding |
| A pinned toolchain becomes unavailable or its provenance drifts | Medium | 3.14 records the exact rustc commit, verifies it locally and in CI, and makes all build entry points consume the same rustup file |

---

## 7. Engineering standards

- **`unsafe` needs a comment naming the invariant it relies on**, and stays out of
  the capability decision path.
- **Diagnostics are a UI.** Compiler errors carry line numbers and say what real
  rustc says. They are asserted in tests.
- **Known limits are documented, not hidden.** The README's "Known limits" section is
  load-bearing; anything not fixed goes there in the same commit.
- **No silent truncation.** If something bounds coverage — a queue depth, a corpus
  size, a retry cap — it says so at runtime.
- **Every milestone ships a demo you can type at the shell.** If it cannot be
  demonstrated in the shell, it is not done.
