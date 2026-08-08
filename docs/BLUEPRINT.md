# VibeOS Blueprint

Architecture and design rationale. For what to build next, see [ROADMAP.md](ROADMAP.md).

**Status (2026-08-08):** M1 and M2 are complete; M3 is partial, and M3.5 has begun
with 3.8 through 3.14 complete. The implementation is about 10,500 lines across
`core`, `compiler`, and `kernel`. `scripts/status.sh` derives the current host and
corpus inventory, while the QEMU harness reports target check counts from the boot
it observed. Everything described as *implemented* below runs today; planned work
is marked as such. Version strings in the boot banner are historical and are not
used as the source of truth; milestone state lives in [ROADMAP.md](ROADMAP.md).

---

## 1. Thesis

Four bets. Each targets something conventional systems locked in for reasons that
have since expired.

### Bet 1 — Authority is a capability, never a name

Unix decided that reaching a resource means *naming* it (a path, a pid, a uid) and
asking a global policy oracle for permission. Every confused-deputy bug lives in the
gap between the name you asked about and the object you got.

VibeOS has no global namespace. No paths, no uids, no root, no ambient authority.
A component acts on a resource only by presenting a handle from its own capability
space, and every operation names the rights it requires.

**Consequence:** least privilege stops being a discipline you have to maintain and
becomes the only thing expressible. A component that was never handed a console
cannot print, and there is no configuration mistake that changes that.

### Bet 2 — Isolation is a type system, not a page table

Hardware isolation is expensive exactly where modern systems lean hardest: a syscall
or IPC costs a mode switch, a TLB flush, and a copy. That price bought protection
*from unsafe languages*. When components are memory-safe by construction, you can
charge a function call instead.

**Consequence:** IPC is a queue push. Components compose at library cost, so
decomposing a system into many small components stops being a performance decision.

**The bill:** the language implementation joins the TCB. See §7 — and Bet 4, which
is how we intend to pay it.

### Bet 3 — Concurrency is a future, not a thread

A thread is a stack you pay for whether or not you are using it, plus a scheduler
that must forcibly interrupt you because it cannot tell when you are idle. A
suspended `Future` is exactly the bytes it needs, and it says when to come back.

**Consequence:** no per-task stacks, no context switches, no preemption. An
interrupt handler's entire job is to turn a hardware event into `Waker::wake()`.
Idle draws no power.

**The bill:** a task that never yields wedges the machine. Generated programs are
instrumented with fuel, but cooperative scheduling remains an unenforced contract
for in-tree component futures (§8.1).

### Bet 4 — The toolchain is a kernel service

This one is newer, and it is what the in-kernel compiler is actually for.

Conventionally, introducing code means `exec`ing an ELF: the kernel maps a blob it
cannot understand and then spends the rest of the process's life defending against
it with hardware. The blob's authority comes from *who ran it*.

In VibeOS, introducing code means **compiling it**. The compiler is part of the
kernel, so the only machine code in the system is machine code the kernel emitted,
under a policy it chose. Generated code has no instruction that reaches hardware
and no way to name anything the compiler did not give it. Its authority comes from
the capability space the compiler compiled it against.

**Consequence:** confinement is a property of the code generator rather than of the
MMU, which is what makes Bet 2 affordable without making the *programs* trusted.
Only the compiler is.

**Status:** the mechanism runs today (`rustc hello`, and `revoke prog` silences
byte-identical machine code). The *argument* has holes, enumerated honestly in §6.4.

---

## 2. System architecture

```
                      ┌───────────────────────────────────────────┐
   components         │ shell   sensor   logger   guest   prog    │  async tasks,
   (this is           │   │       │        │        │      │      │  each holding a
    "userland")       │   └───────┴────┬───┴────────┴──────┘      │  CSpace and nothing
                      └────────────────┼──────────────────────────┘  else
                                       │  caps + typed channels
                      ┌────────────────┼──────────────────────────┐
   kernel services    │  cap    chan    dev    tty    rustc        │
                      └────────────────┼──────────────────────────┘
                      ┌────────────────┼──────────────────────────┐
   runtime            │  exec (scheduler)   heap   sync            │
                      └────────────────┼──────────────────────────┘
                      ┌────────────────┼──────────────────────────┐
   hardware           │  trap   plic   uart   sbi   boot/linker    │
                      └───────────────────────────────────────────┘
                                       │
                                  OpenSBI (M-mode)
```

There is no privilege boundary between these layers — they are an *ordering*
discipline, not an enforcement one. A layer may call downward and must not call
upward except through a capability it was handed.

### Module map

| Module | Approx. lines | Role | Contains `unsafe` |
|---|---:|---|:--:|
| `cap.rs` | 376 | Rights, `Cap`, `CSpace`, attenuation, revocation | 1 (downcast) |
| `chan.rs` | 116 | Typed bounded endpoints; rights pick the direction | — |
| `exec.rs` | 1212 | Scheduler, tracked lifecycle, cancellation/join, wakers, wait queues, timers | 1 (waker construction) |
| `world.rs` | 408 | The system image: supervised components, spaces, wiring | — |
| `shell.rs` | 458 | Operator interface | — |
| `tty.rs` | 110 | Console line discipline, quiet | — |
| `dev.rs` | 102 | Devices and bounded memory as capability-guarded resources | — |
| `compiler/` | 2454 | Lexer, parser, type checker, RV64 code generator | — |
| `kernel/rustc.rs`, `trampoline.rs` | 433 | Confined runtime and nested non-local fault exit | yes |
| `heap.rs` | 106 | Bump allocator + size-class free lists | yes |
| `sync.rs` | 59 | Interrupt-safe spinlock | yes |
| `trap.rs` | 161 | S-mode trap entry; IRQ → waker | 3 |
| `uart.rs` `plic.rs` `arch/riscv.rs` | 253 | Hardware | 10 |
| `main.rs` | 159 | Boot, panic, entry | 1 |

Line counts are a dated snapshot, not a target. `unsafe` is concentrated in the
hardware layer, allocator, waker construction, the `lookup_as` downcast, and the
generated-code/fault trampolines. None is in the rights or revocation decision path.

---

## 3. The capability model

### Objects

```rust
Rights  = { READ, WRITE, SEND, RECV, GRANT, REVOKE }   // 6 bits
Cap     = { slot: u32, generation: u32 }               // private fields
CSpace  = Vec<Slot>
Slot    = { generation: u32, entry: Option<{ obj, rights, parent }> }
```

A `Cap` is meaningless outside the `CSpace` that issued it. It is not a pointer, not
an index into anything global, and carries no rights of its own — rights live in the
slot, which is why revoking one handle invalidates copies of it.

### Invariants

These are the properties the rest of the system is allowed to assume. Anything that
breaks one is a security bug, not a behavior change.

1. **No forgery.** `Cap`'s fields are private. Safe code cannot construct one; it can
   only receive one from a holder.
2. **Monotone attenuation.** `derive` and `grant` require `GRANT` on the source and
   `rights ⊆ source.rights`. There is no operation that widens rights — not
   privileged, not admin-only. Absent.
3. **Rights are checked at use, not at acquisition.** Every `lookup` names what it
   needs. Holding a handle is not permission; holding a handle *with the right* is.
4. **Revocation is immediate for capability lookup.** Bumping a slot's generation
   makes every outstanding copy of that handle stale on its next lookup. A service
   that caches the resolved object has created a lease outside this guarantee; the
   current generated-program runtime does this for the duration of one invocation,
   as called out in §6.3 and §8.1.
5. **Spaces are objects.** A `CSpace` is itself a `Resource`, so "supervise that
   component" is expressible as a capability rather than as a special case.

### How revocation reaches across spaces

Every capability points at a node in an `Arc`-linked derivation graph. `derive`
and `grant` both create a *child* node, so lineage survives a cap travelling into
another space. A cap is live only if its own node and every ancestor are alive,
which makes revocation O(1) to perform and immediately visible to subsequent lookups
everywhere — including in spaces the revoker cannot name and does not know exist.

Slots holding a cap killed by an ancestor become stale rather than empty; they
stop resolving and stop appearing in `list` at once, and `collect` frees them.

Generations are `u64` and saturate rather than wrap; a slot that somehow reached
`u64::MAX` is retired instead of reused, so a stale handle can never alias a
fresh one.

---

## 4. The execution model

A task is `Pin<Box<dyn Future<Output = ()> + Send>>` plus a name and a poll count.
The scheduler is a `BTreeMap<TaskId, Task>` and a ready `VecDeque<TaskId>`.

**The waker is the `TaskId` itself**, cast into the raw-waker data pointer. Clone is
identity, drop is a no-op, wake is a queue push. No `Arc` or refcount is involved;
spawn reserves ready-queue capacity for the live-task upper bound so the wake path
does not allocate.

The main loop:

```
pop a ready id  →  lift the task out of the map  →  poll it  →  put it back
   ↓ (nothing ready)
enable interrupts, wfi
```

Lifting the task out of the map is what lets it spawn and wake freely mid-poll
without deadlocking on the scheduler lock. It also created the subtlest bug in the
system so far: a task that wakes *itself* during its own poll found nothing in the
map and had the wake dropped, which hung `yield_now` forever. `Sched::running_woken`
now catches that, and it covers the harder case too — an interrupt that lands
mid-poll for the task being polled.

**Wait queues** give every listener a unique registration token and capture the
queue epoch when the listener is constructed. Consumers prepare the listener before
checking their channel/UART predicate; a wake between construction, the check, and
first poll advances the epoch and is observed rather than lost. Repoll replaces the
waker, and Drop/cancellation removes the token. `wake_all` drains under the queue
lock and invokes wakers only after releasing it.

**Timers** are kept in deadline order with the earliest entry at the end of the
vector. A `Sleep` owns one token, updates rather than duplicates its waker, and
unregisters on Ready or Drop. Removing the earliest timer reprograms the hardware
immediately. The timer interrupt pops due entries without allocating and wakes them
outside the registry lock. A 10 s heartbeat is only an idle backstop; the scheduler
masks interrupts, rechecks the ready queue, executes `wfi`, and restores the prior
interrupt state as one lost-wake-free sleep sequence.

---

## 5. The IPC model

One primitive: `Endpoint<T>`, a bounded typed queue with a wait queue on each side.

Two things follow from *typed*:

- There is no `read(fd, buf, n)` and no ioctl. The protocol is a Rust type, so
  mismatches are compile errors rather than parse failures at 3am.
- **Direction is a right, not a type.** One object serves both ends; `SEND` lets you
  push and `RECV` lets you pull. Attenuating a cap to `SEND` alone *is* handing out a
  write-only pipe. This is why the sensor cannot read the channel it publishes to.

Backpressure is `await`, not `EAGAIN` — a full queue suspends the sender instead of
returning an error the caller is free to ignore.

---

## 6. The compiler

### 6.1 Pipeline

```
source ──lex──► tokens ──parse──► AST ──collect──► string table
                                   │                    │
                                   └────codegen(2 passes)┘──► Vec<u32> ──fence.i──► call
```

No IR and no register allocator. Values live on the machine stack; only `t0`/`t1`
are live between instructions, so nothing ever needs spilling across a call. This
costs performance and buys an emitter small enough to audit — which matters more
than speed, because the emitter is a security boundary (§6.3).

### 6.2 Two invariants that make it simple

- **Instruction size never depends on an address.** Addresses use a fixed-length
  materialization sequence; ordinary integer constants use a shorter value-dependent
  sequence. So pass 1 (discover function addresses) and pass 2 (emit calls to them)
  still agree on layout by construction, with no fixpoint iteration.
- **Stack slots are 16 bytes, not 8.** Wasteful, and it makes `sp` ABI-aligned at
  every call boundary for free, including calls back into Rust.

Branches are an inverted conditional over a `jal`: ±1 MB of range instead of the
4 KB a bare `beq` allows.

With no MMU and no W^X, loading a program is `fence.i` plus a transmute of the code
buffer to a function pointer.

### 6.3 Why generated code is confined

The claim: *a compiled program can do nothing but arithmetic and call the runtime
hooks the compiler chose for it.* The argument, and it is worth stating as an
argument because it is what Bet 4 rests on:

| Escape route | Why it is closed |
|---|---|
| Reach hardware directly | The language has no MMIO, no `asm`, no pointer type. Codegen emits `ld`/`sd` only at `s0`-relative frame offsets or through the bounds-checked memory-region cursor. |
| Forge a pointer | Nothing in the language produces an address. Address materialization is limited to string-table addresses, function targets, runtime hooks, and the capability-granted region base — all compiler- or kernel-chosen. |
| Call something it was not given | Call targets are statically resolved function names or the print/abort runtime hooks. There is no function pointer or user-selected indirect branch. |
| Name the runtime hooks | Their addresses are baked into the emitted stream. The language has no syntax that reaches them. |
| Keep authority after revocation | **Partially closed.** Program launch resolves console and memory caps, so revocation before launch is enforced. The current runtime caches the console object and raw memory extent for the invocation; revocation during an invocation is therefore not yet a demonstrated boundary. |

**Verified by demo:** `revoke prog` followed by a new run leaves byte-identical machine
code running to completion with nothing to say. This proves launch-time authority,
not operation-time revocation of already-running code.

### 6.4 Where the argument used to leak

Five holes were listed here in v0.1. Four are closed; the code generator now
emits a check for each, and a failed check calls a runtime hook that longjmps
out of the program (`kernel/src/trampoline.rs`).

| Was | Now |
|---|---|
| Deep recursion walked `sp` into `.bss` | Every prologue proves `sp >= s1` before the frame is used. `s1` is set by the trampoline and is callee-saved, so the check is a register compare and needs no memory access. |
| `while true {}` wedged the machine | Fuel in `s2`, charged per call and per loop back-edge. A function with no call and no loop cannot fail to terminate and is not charged. |
| Division by zero followed RISC-V semantics | Guarded, including `i64::MIN / -1`. A literal zero divisor is a compile error, as in real rustc. |
| Integer overflow wrapped silently | `+`, `-`, `*` and unary `-` are checked and abort with rustc's own wording. |

The fifth — **the emitter is unverified** — is reduced rather than closed. It now
has three defences, and it remains the highest risk in the system:

- The confinement claims above are asserted as tests that walk the emitted
  instruction stream: the permitted opcode set, every memory access
  frame-relative, every indirect jump a recognised call or return, every
  absolute address belonging to the program's own data, its own code, or a
  runtime hook.
- Real rustc is used as a differential oracle. Every program in
  `tests/programs/` is valid in both languages; CI compiles each with rustc,
  runs it, and requires VibeOS to produce identical bytes.
- The front end is fuzzed against 25,000 generated inputs, every prefix and
  every single-character deletion of the samples, and rejects nesting deeper
  than 64 — `rustc edit` reads arbitrary console input onto a 256 KiB kernel
  stack with no guard page, so unbounded parser recursion was itself a way to
  corrupt memory from the shell prompt.

Because these checks exist, `!` is now Rust's bitwise complement rather than
logical negation: a subset that disagrees with the language it claims to subset
cannot use that language as an oracle.

---

## 7. Trust model

**In the TCB today:**

- The Rust compiler and its codegen (we compile the kernel with it)
- Every line of the kernel, including all component code — one trusted build
- The in-kernel compiler's emitter (§6.3)
- OpenSBI, and the hardware

**Not in the TCB:**

- Programs compiled by the in-kernel compiler — *this is the interesting one*, and
  it is only true to the extent §6.4 gets closed.

**The direction of travel.** Bet 2 puts the language implementation in the TCB.
Bet 4 is how the bill gets paid: if the only path to new machine code is a compiler
we trust, then the *programs* need not be trusted, and we get language-based
isolation's cheap IPC without language-based isolation's usual "recompile the world
from trusted source" requirement.

That makes the in-kernel compiler the security-critical component of the system.
It should be treated that way: smallest possible emitter, differential testing
against real rustc, and eventually a verified or verifying backend.

---

## 8. Cross-cutting concerns

**Memory.** Compiled programs receive a bounded `MemoryRegion` capability and abort
on exhaustion. Kernel heap blocks carry an immutable component-owner header and are
charged by their actual size class, including allocator metadata and alignment. Each
component has live/peak/denial counters and a hard live-byte quota; exceeding it faults
that task before consuming another owner's budget, while deallocation credits the
header owner even when it runs from another component or an IRQ. Normal return and
cancellation run Drop and return live use to the account baseline. Audited World
components additionally receive a per-incarnation arena. A fault first quiesces every
task in that arena, drains SYSTEM-owned runtime registrations, abandons future envelopes
without Drop, and raw-reclaims the arena. Ordinary tasks retain the conservative leak
policy because they have no proven allocation-escape boundary.

**Time.** `rdtime` at 10 MHz, SBI timer for wakeups. No monotonic-vs-wall
distinction because there is no wall clock. Timer insertion and token removal are
linear, while the interrupt pops due entries from the ordered tail without allocating;
this is fine at ~10 sleepers and still the wrong data structure at 10,000.

**Failure.** Two failure domains, both built on the same trampoline. A compiled
program that fails a safety check is aborted and the shell survives (§6.4). A
component that panics is caught at the executor's poll boundary. An audited component
fault tears down its whole incarnation arena without running interrupted destructors;
an ordinary task is still leaked because that is the only sound generic fallback.
Every other component keeps running. Cooperative cancellation instead detaches a ready or parked future
and drops it normally, or waits for the active poll to return before reclaiming it.
Joiners retain the exact exit, fault, or cancellation report. `ps` retains supervised
components' exact identity, state, terminal reason, and final poll count, alongside
executor-wide exit, fault, and cancellation totals.

What is still fatal: a panic with no landing pad armed, which means a fault in
the kernel's own boot path or inside an interrupt handler.

**Observability.** `ps` (poll counts), `caps` (capability tables), `chan` (queue
depth), `mem` (heap). Poll counts are a genuinely good scheduler metric — they say
how often a component *needed* the CPU, which threads cannot tell you.

### 8.1 Current assessment and design corrections

The project is strongest where its thesis is executable rather than aspirational:
capability attenuation and cross-space revocation have dense host tests; generated
code has a small audited instruction surface, differential tests, bounded memory,
stack probes, and fuel; and QEMU transcripts exercise the complete path. The crate
split also puts most policy and compiler logic on the host-testable side of a narrow
architecture seam.

The current design step is **component lifecycle**, not a wider language. A
supervised `Component` now binds a stable `ComponentId` to its current `TaskId`,
CSpace, declared memory owner/budget, and retained terminal state. That closes the
identity and observability gap. `revoke` still removes authority without stopping
execution unless a supervisor separately calls `cancel`. Cooperative cancellation
and join reporting now cover ready, parked, self-waking, and currently polling
tasks. Wait queues and timers now own cancellation-safe registration tokens, replace
wakers on repoll, and release them on Drop; their predicate call sites use
listener-before-check epochs to close IRQ races. Component budgets are enforced
by tagged allocation ownership. Audited component incarnations now add a reclaimable
arena and sealed restart template: restart retains `ComponentId`, memory owner, and the
boot-static `Space`, while installing a new `TaskId`, `ArenaId`, generation, and CSpace
grants. Slot generations survive CSpace reset, so an old `Cap` cannot alias a fresh
grant. Sixteen target fault/restart cycles verify bounded heap growth and zero interrupted
destructors. The remaining M3.5 work is measurement reproducibility and resolved-cap
lease semantics.

Five boundaries must stay explicit:

1. **Capabilities constrain object access, not arbitrary trusted component code.**
   In-tree Rust components remain in the TCB and may call kernel internals directly.
   Only code accepted by the in-kernel compiler currently gets the stronger
   confinement claim in §6.3.
2. **Cooperative scheduling is not temporal isolation.** Fuel bounds generated
   programs, but an in-tree future that never returns `Pending` can still wedge the
   hart. Cooperative cancellation takes effect only at poll boundaries; hard
   containment ultimately needs instrumentation, preemption, or a
   narrower admitted component format.
3. **Revocation needs durable semantics before persistence.** Persisting raw slot and
   generation pairs is insufficient: reboot must not resurrect a descendant of a
   revoked cap. Stable object identity, derivation records, and atomic tombstones are
   part of the storage design, not a later serialization detail.
4. **Lookup-time revocation is not use-time revocation after resolution.**
   `rustc::run` currently resolves console and memory once, then caches an `Arc` and
   a raw region extent. The design must explicitly choose between revocable
   operation-time handles and invocation-scoped leases. Direct generated loads and
   stores cannot promise immediate revocation without instrumentation or a mapping
   boundary.
5. **Claims need reproducible measurements.** IPC cost, wake latency, capability
   lookup depth, heap high-water marks, code size, and generated-code performance
   need automated baselines. Optimizing with SSA or adding multicore before those
   baselines would make the thesis harder to evaluate, not easier.

These corrections preserve the four bets, but change the order of work: establish
truthful, repeatable baselines; add ownership and lifecycle; specify durable authority;
then widen the language and scale across harts. See the reassessed sequence in the
Roadmap.

---

## 9. Non-goals

Stated so they stop being re-litigated:

- **POSIX compatibility.** The entire point is that the POSIX object model is what
  we are replacing. A compatibility layer would reintroduce ambient authority.
- **A path-based filesystem.** Persistence, when it arrives, is capability-addressed
  (§Roadmap M4). Paths are a global namespace by another name.
- **Per-process page tables.** The MMU is wanted eventually for *integrity* — guard
  pages, W^X — not for isolation.
- **A general-purpose Rust compiler.** The in-kernel compiler exists to explore
  Bet 4. Self-hosting is not a goal.
- **Running untrusted native binaries.** There is no ELF loader and there should not
  be one; a blob you did not compile is exactly the thing Bet 4 rejects.
