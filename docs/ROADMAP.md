# VibeOS Developer Plan

What to build, in what order, and how we will know it works.
For *why* the system is shaped this way, see [BLUEPRINT.md](BLUEPRINT.md).

---

> **Current status (2026-08-09):** M1, M2, and the M3.5 lifecycle/evidence
> sequence through 3.16, M4.5, and M5.2 are complete. M5.3 lock contention audit is next. Run
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
| 1.1 ✅ | Split into three crates | `vibeos-core` (no_std lib: cap, chan, exec, heap, sync), `vibeos-rustc` (no_std lib: the compiler), `vibeos-kernel` (bin). |
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
invariants at mutation boundaries: a future has one owner, the single hart has at
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
| 5.3 | Audit every `SpinLock` for real contention; replace the hot ones with lock-free structures |
| 5.4 | Hart-local storage for the scheduler's `running` slot |
| 5.5 | Boot secondary harts via SBI HSM |

**Acceptance:** `-smp 4` with the integration suite green and measurable throughput
scaling on a parallel benchmark. Loom or a similar model checker on the scheduler.

**Risk:** the `running`/`running_woken` mechanism is single-hart by construction and
will need rethinking, not porting.

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

**M5.5 preflight risk:** a pre-M5.5 `-smp 4` smoke run did not produce the
shell-ready marker even though `_start` contains a non-boot-hart park branch. M5.1
does not hide that gap or claim parked-hart evidence; the SBI/QEMU handoff must be
diagnosed before secondary boot is enabled or `-smp 4` becomes acceptance.

---

### M6 — The MMU, for integrity (v0.7)

Not for isolation — Blueprint §9. For the things software checks do worse:

| # | Work item |
|---|---|
| 6.1 | Sv39 paging with a single address space |
| 6.2 | Guard pages below every stack (makes 2.2 defence-in-depth rather than sole defence) |
| 6.3 | W^X for code buffers: writable while emitting, execute-only after `fence.i` |
| 6.4 | Read-only mapping for `.rodata` and the capability tables |

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

---

## 3. Workstreams

The continuing tracks after the partial M3 milestone are:

| Track | Owns | Near-term outcome |
|---|---|---|
| **Lifecycle** | `exec`, `cap`, `heap`, `world` | M3.5 supervision, cancellation, ownership, and reclamation; gates persistent services and multicore |
| **Evidence** | `tests`, `scripts`, CI, `bench` | Reproducible builds, real-rustc oracle execution, regression budgets, and dated metrics |
| **Compiler** | `compiler`, `kernel/rustc`, trampoline | Resolved-cap lease semantics are complete; 3.4–3.6 remain evidence-driven language-track work rather than a persistence prerequisite |
| **Platform** | drivers, storage, `tty`, `shell` | M4.0--M4.5 durable model, virtio block/network, object store, fixed persistent CSpace, and verified source/binary persistence |
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
| Physical multicore execution races the single `running` slot | Medium | 5.1 completed the model-checked queue redesign; 5.4 must make the running slot hart-local before 5.5 boots secondaries |
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
