# VibeOS Developer Plan

What to build, in what order, and how we will know it works.
For *why* the system is shaped this way, see [BLUEPRINT.md](BLUEPRINT.md).

---

> **M1 status: complete.** 101 host tests, 37 in-kernel checks, 5 golden
> transcripts, CI on every push. See [TESTING.md](../TESTING.md).

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
M1 Foundations ──┬─► M2 Confinement ──┬─► M3 Memory & Language ──► M5 Multicore
   (tests, CI,   │     (unwinding,    │      (arenas, arrays,       (per-hart
    crate split, │      stack probes, │       IR, regalloc)          queues, IPI)
    revocation)  │      watchdog)     │
                 │                    └─► M4 Devices & Persistence
                 └─► (unblocks everything: no milestone lands untested)
                                                    │
                                              M6 MMU for integrity
                                                    │
                                                  v1.0
```

M2 comes before M3 because adding language features to a compiler whose generated
code cannot be safely aborted multiplies the blast radius of every new feature.
M6 comes last because it is the only milestone that is pure defence-in-depth: every
hole it closes is closed better upstream by M2.

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
> 117 host tests, 49 in-kernel checks, 7 golden transcripts including a
> differential run against real rustc.

### M2 — Confinement (v0.3)

**Goal:** turn Blueprint §6.3 from an argument into an enforced property.

Everything here descends from one missing mechanism: **there is no way to abort
running generated code.** Blueprint §6.4 items 1–3 are all the same hole.

| # | Work item | Notes |
|---|---|---|
| 2.1 ✅ | Program trampoline | Save callee-saved regs + `sp` + `ra` before entering generated code; a runtime hook can restore them and return an error. A `setjmp`/`longjmp` pair in ~30 lines of RV64 asm. Unlocks 2.2–2.4. |
| 2.2 ✅ | Stack probes | Emit a `sp` limit check at every function prologue. On breach, abort through the trampoline with `stack overflow`. Closes the hole where recursion corrupts `.bss`. |
| 2.3 ✅ | Division and overflow checks | Emit checks; abort with the message real rustc would print. Removes the "RISC-V semantics" caveat from the README. |
| 2.4 ✅ | Fuel / watchdog | Emit a budget decrement at loop back-edges and function entry; exhausting it aborts. A compiled `while true {}` must return control to the shell. |
| 2.5 ✅ | Codegen differential testing | Compile a corpus with the in-kernel compiler *and* with real `rustc` on the host; compare stdout. The corpus doubles as a regression suite and is the strongest oracle available for a compiler this small. |
| 2.6 ✅ | Parser fuzzing | `cargo-fuzz` on the host. The parser must never panic; it must only return `Err`. |
| 2.7 ✅ | Emitter audit | Enumerate every instruction the emitter can produce and prove each is frame-local or compiler-chosen. Turn Blueprint §6.3's table into an asserted test. |
| 2.8 ✅ | Task fault isolation | A panicking component costs its own task, not the machine. `setjmp` sits inside the guard function rather than the caller, so a `longjmp` restores *that* frame and returns normally — the scheduler's frame and locals are never disturbed. The faulted task is leaked rather than dropped, because running destructors over a future interrupted mid-poll would be worse than leaking. |

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

### M3 — Memory and a real language (v0.4)

**Goal:** make compiled programs useful without making them unconfined.

Programs today are functions over `i64`. Everything interesting needs storage — and
storage is exactly where confinement gets hard, which is why this comes after M2.

| # | Work item | Notes |
|---|---|---|
| 3.1 | `MemoryRegion` resource | A bounded arena obtained *by capability*, with `READ`/`WRITE` rights. A program gets memory the same way it gets a console. |
| 3.2 | Arrays with bounds checks | Emitted checks, abort on breach via the M2 trampoline. Bounds checking is what keeps 3.1 from reopening the pointer-forgery hole. |
| 3.3 | `bool`, unit, and a real type checker | Currently `i64` is load-bearing for everything, including conditions. A separate type pass replaces the ad-hoc checks scattered through codegen. |
| 3.4 | Structs and `&`/`&mut` with move semantics | Affine values, not a full borrow checker. Enough to write a program with state. |
| 3.5 | An SSA IR | Between AST and codegen. Required before any optimization is worth attempting, and it gives the emitter audit (2.7) a narrower surface. |
| 3.6 | Linear-scan register allocation | Retire the stack machine. Target: within 3× of `rustc -O0` on the benchmark corpus. |
| 3.7 | Heap quotas per space | Blueprint §8 "Memory". A component that leaks should exhaust its own budget, not the system's. |

**Acceptance:** a compiled program that allocates an array from a capability-granted
region, sorts it, prints it, and is killed cleanly when it indexes out of bounds or
exceeds its memory budget.

---

### M4 — Devices and persistence (v0.5)

**Goal:** stop being a demo.

| # | Work item | Notes |
|---|---|---|
| 4.1 | virtio-blk driver as a component | An async task holding an MMIO capability. The first driver that is not built into the kernel. |
| 4.2 | Capability-addressed store | Objects are named by capability, not by path. `store.get(cap)` / `store.put(obj) -> cap`. Blueprint §9 forbids a path namespace; this is the alternative. |
| 4.3 | Persist a CSpace | Save and restore a component's authority across boot. This is the interesting half: a persisted cap must not resurrect revoked authority. |
| 4.4 | virtio-net + a typed socket endpoint | `Endpoint<Packet>`, not a byte stream. |
| 4.5 | Source and binary persistence | `rustc save hello` / `run hello`. Compiled code becomes a storable object with a cap on it. |

**Acceptance:** write a program at the shell, save it, reboot, run it — and its
authority after reboot is exactly what was persisted, with revoked caps staying dead.

---

### M5 — Multicore (v0.6)

| # | Work item |
|---|---|
| 5.1 | Per-hart run queues with work stealing |
| 5.2 | IPI-based cross-hart wakeups (SBI `sbi_send_ipi`) |
| 5.3 | Audit every `SpinLock` for real contention; replace the hot ones with lock-free structures |
| 5.4 | Hart-local storage for the scheduler's `running` slot |
| 5.5 | Boot secondary harts via SBI HSM |

**Acceptance:** `-smp 4` with the integration suite green and measurable throughput
scaling on a parallel benchmark. Loom or a similar model checker on the scheduler.

**Risk:** the `running`/`running_woken` mechanism is single-hart by construction and
will need rethinking, not porting.

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
3. A component can be added, granted authority, run, revoked, and killed — without
   restarting the machine and without a hole in the story.
4. `-smp 4`.
5. Programs survive reboot with exactly the authority that was persisted.
6. Published measurements for every number in §4.

---

## 3. Workstreams

Four tracks that can proceed in parallel once M1 lands.

| Track | Owns | Milestones |
|---|---|---|
| **Kernel core** | `exec`, `sync`, `heap`, `trap`, boot | 1.10, M5, M6 |
| **Capability system** | `cap`, `chan`, `world` | 1.2, 1.8, 1.9, 3.7, 4.3 |
| **Compiler** | `rustc/` | 1.3–1.4, M2, M3 |
| **Platform** | drivers, storage, `tty`, `shell` | M4 |

Cross-track dependency to watch: M2's trampoline (2.1) is owned by Compiler but is
what Kernel core needs for task fault isolation (2.8). Land it early in M2.

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
| Wake latency: IRQ → task polled | Bet 3's core claim | unmeasured (≤50 ms worst case, from the `wfi` race) |
| Idle CPU draw | Should be zero | unmeasured |
| Compile throughput (KB/s) | 3528 B from ~3 fn in ~5–15 ms today | rough |
| Generated code vs `rustc -O0` | Honest accounting of the stack machine's cost | unmeasured |
| Cap lookup cost | On every operation; must stay cheap | unmeasured |
| Kernel size / `unsafe` count | TCB is the product | 3418 lines, ~33 `unsafe` |

Add a `bench` shell command in M1 so these are trackable from the start.

---

## 6. Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| A codegen bug is a privilege escalation, and the emitter is unverified | **High** | 2.5 differential testing, 2.7 emitter audit, 3.5 SSA IR to narrow the surface |
| Bet 2's cheap-IPC claim goes unmeasured and turns out false | High | §5 metrics in M1, before the design ossifies |
| The single-hart executor design does not survive M5 | Medium | Treat 5.1 as a redesign, not a port; write the model check first |
| Language features outrun confinement | Medium | M2 strictly before M3; no new syntax without an abort path |
| Scope sprawl into POSIX compatibility | Medium | Blueprint §9 is binding |
| Homebrew Rust + `RUSTC_BOOTSTRAP=1` breaks on a toolchain bump | Low | Pin via `rust-toolchain.toml` in M1; CI on a fixed nightly |

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
