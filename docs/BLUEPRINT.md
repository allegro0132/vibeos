# VibeOS Blueprint

Architecture and design rationale. For what to build next, see [ROADMAP.md](ROADMAP.md).

**Status:** v0.1 — boots on RISC-V under QEMU, ~3400 lines. Everything described as
*implemented* below runs today; everything described as *planned* does not exist yet
and is marked as such.

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

**The bill:** a task that never yields wedges the machine. Cooperative scheduling
is a contract, and v0.1 has no way to enforce it (§6.4).

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

| Module | Lines | Role | Contains `unsafe` |
|---|---:|---|:--:|
| `cap.rs` | 283 | Rights, `Cap`, `CSpace`, attenuation, revocation | 1 (downcast) |
| `chan.rs` | 110 | Typed bounded endpoints; rights pick the direction | — |
| `exec.rs` | 267 | Scheduler, wakers, wait queues, timers | 3 (waker vtable, `wfi`) |
| `world.rs` | 183 | The system image: spaces, components, wiring | — |
| `shell.rs` | 295 | Operator interface | — |
| `tty.rs` | 110 | Console line discipline, quiet | — |
| `dev.rs` | 50 | Devices as capability-guarded resources | — |
| `rustc/` | 1417 | Lexer, parser, RV64 codegen, confined runtime | 2 (call generated code) |
| `heap.rs` | 109 | Bump allocator + size-class free lists | 7 |
| `sync.rs` | 72 | Interrupt-safe spinlock | 6 |
| `trap.rs` | 161 | S-mode trap entry; IRQ → waker | 3 |
| `uart.rs` `plic.rs` `sbi.rs` | 223 | Hardware | 10 |
| `main.rs` | 138 | Boot, panic, entry | 1 |

All `unsafe` is in the hardware layer, the allocator, the waker vtable, and the two
places that deliberately cross a type boundary (`lookup_as`, calling generated code).
None of it is in the capability decision path.

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
4. **Revocation is immediate and retroactive.** Bumping a slot's generation makes
   every outstanding copy of that handle stale on its next use, including inside
   already-running native code.
5. **Spaces are objects.** A `CSpace` is itself a `Resource`, so "supervise that
   component" is expressible as a capability rather than as a special case.

### How revocation reaches across spaces

Every capability points at a node in an `Arc`-linked derivation graph. `derive`
and `grant` both create a *child* node, so lineage survives a cap travelling into
another space. A cap is live only if its own node and every ancestor are alive,
which makes revocation O(1) to perform and immediately visible everywhere —
including in spaces the revoker cannot name and does not know exist.

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
identity, drop is a no-op, wake is a queue push. No `Arc`, no refcount, no allocation
on the wake path.

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

**Timers** are a `Vec<(deadline, Waker)>` scanned on the timer interrupt, plus a
50 ms heartbeat so the idle hart always wakes even with nothing armed. That
heartbeat also papers over a real race: the gap between "ready queue is empty" and
`wfi` is not atomic, so a wake landing in that window costs up to 50 ms of latency
instead of being lost. Fixing it properly needs the check and the wait to be one
operation.

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

- **Instruction size never depends on an address.** 64-bit constants always take a
  fixed 11-instruction sequence. So pass 1 (discover function addresses) and pass 2
  (emit calls to them) agree on layout by construction, with no fixpoint iteration.
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
| Reach hardware directly | The language has no MMIO, no `asm`, no pointer type. Codegen emits `ld`/`sd` only at `s0`-relative frame offsets. |
| Forge a pointer | Nothing in the language produces an address. `li64` materializes only integer literals, string-table addresses, and call targets — all compiler-chosen. |
| Call something it was not given | Call targets are statically resolved function names or the two runtime hooks. There is no computed call, no function pointer, no indirect branch. |
| Name the runtime hooks | Their addresses are baked into the emitted stream. The language has no syntax that reaches them. |
| Keep authority after revocation | `rt_print_*` resolves the `prog` space's console cap **on every call**, not once at load. |

**Verified by demo:** `revoke prog` leaves byte-identical machine code compiling and
running to completion with nothing to say.

### 6.4 Where the argument leaks — the honest list

These are the holes. Each one is a roadmap item, not a footnote.

1. **Stack overflow.** Deep recursion walks `sp` down past the 256 KiB stack into
   `.bss`. The linker puts the stack *below* the heap, so an overflow corrupts kernel
   state rather than faulting. No guard page (no MMU) and no stack probe.
2. **Unbounded execution.** A compiled `while true {}` wedges the machine, because
   there is no preemption and no way to abort a running program.
3. **Division by zero** follows RISC-V semantics (`-1`; `%` yields the dividend)
   instead of panicking, because aborting mid-program needs a non-local exit that
   does not exist yet.
4. **Integer overflow** wraps silently. Real Rust would panic in debug.
5. **The emitter is unverified.** The confinement argument is a table in a document,
   not a proof or even a test suite. A codegen bug that emits a wrong offset is a
   privilege escalation, and nothing would currently catch it.

Items 1–3 share one fix: a trampoline that can unwind out of generated code. That
is why they are scheduled together (Roadmap M2).

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

**Memory.** One heap, one allocator, no per-component accounting. A component can
exhaust the heap and take down the system. Quotas are a capability question
(a `MemoryRegion` resource with a budget) and are not yet modelled.

**Time.** `rdtime` at 10 MHz, SBI timer for wakeups. No monotonic-vs-wall
distinction because there is no wall clock. Timers are a linear scan, fine at ~10
sleepers and wrong at 10,000.

**Failure.** Kernel panic → SBI shutdown. Faults print cause/stval/sepc and halt.
There is no per-component failure domain: a component that panics takes the machine
with it, which for a system built on component isolation is an obvious gap. Task-
level fault isolation needs the same unwinding machinery as §6.4.

**Observability.** `ps` (poll counts), `caps` (capability tables), `chan` (queue
depth), `mem` (heap). Poll counts are a genuinely good scheduler metric — they say
how often a component *needed* the CPU, which threads cannot tell you.

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
