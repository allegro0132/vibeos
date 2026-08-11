# VibeOS Blueprint

Architecture and design rationale. For what to build next, see [ROADMAP.md](ROADMAP.md).

**Status (2026-08-09):** M1, M2, M3.5, M4.0--M4.5, M5.1--M5.5, and M6 are
complete; the original M3 language-expansion items remain partial. The
implementation is across `core`, `compiler`, and `kernel`.
`scripts/status.sh` derives the current host and corpus inventory, while the QEMU
harness reports target check counts from the boot it observed. Everything
described as *implemented* below runs today; planned work is marked as such.
Version strings in the boot banner are historical and are not used as the source
of truth; milestone state lives in [ROADMAP.md](ROADMAP.md).

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
   hardware           │ trap  plic  uart  virtio-blk/net  sbi/linker│
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
| `cap.rs` | ~600 | Rights, `Cap`, `CSpace`, attenuation, revocation, explicit leases | — |
| `chan.rs` | 116 | Typed bounded endpoints; rights pick the direction | — |
| `durable.rs` | ~1000 | Sealed authority-log codec, stable IDs, fail-closed recovery | — |
| `virtio.rs` | growing | Pure modern virtio block/net protocol and queue lifecycle models | — |
| `kernel/virtio_*.rs` | growing | MMIO transport, stable DMA, supervised block/network services | yes |
| `components/netstack` | growing | Capability-confined IPv4/TCP stack, echo service, and network control plane | — |
| `kernel/netstack_platform.rs` | small | Kernel-private packet/network-control adapter and recovery-only hooks | — |
| `components/sshd` | growing | Capability-confined SSH protocol, authentication, sessions, and VSH frontend | 1 (secret wipe) |
| `kernel/ssh_platform.rs` | small | Kernel-private network, entropy, signer, policy, command, and log adapters for `sshd` | — |
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
hardware layer, allocator, waker construction, and the
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
4. **Resolved authority has an explicit lifetime.** Bumping a slot generation or
   killing a derivation makes later lookups stale. `Revocable<T>` additionally
   revalidates the complete ancestry at every operation acquisition; an acquisition
   that overlaps a concurrent revoke may finish, but no later one succeeds.
   `InvocationLease<T>` instead authorizes one already-started bounded invocation
   and deliberately survives revocation. Legacy raw `Arc` lookup is TCB-only and
   documents that it has the latter lifetime.
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
The scheduler is a `BTreeMap<TaskId, Task>` and four logical per-hart ready
`VecDeque`s. Queue ownership is explicit task metadata and is updated atomically
with queue membership under the scheduler lock.

**The waker is the `TaskId` itself**, cast into the raw-waker data pointer. Clone is
identity, drop is a no-op, wake is a queue push. No `Arc` or refcount is involved;
spawn reserves every ready queue for the global live-task upper bound so the wake
path does not allocate even after a task migrates through stealing.

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

M5.1 keeps physical execution on hart 0 while making queue behavior genuinely
four-hart: a dispatcher consumes local FIFO work first, then steals eligible work
from remote queue backs in cyclic order. `wake_with_disposition` reports whether
work was newly enqueued, already queued, running, or inactive together with its
target hart while the original `wake` API remains intact; an allocation-free
notification hook and idle predicate form the M5.2 IPI seam.
Tasks in audited raw-reclaim arenas remain hart-affine and non-stealable. The
scheduler now owns one `running`/wake slot per logical hart and checks complete-slot
quiescence before reclaim. M5.5 also exposes explicit non-stealable placement for
machine-local control and acceptance tasks.

M5.2 implements that seam with per-logical-hart atomic reason mailboxes. A mailbox
also owns its kick-armed bit, so interrupt acknowledgement consumes both atomically;
Release/Acquire ordering and explicit RVWMO I/O fences bridge ready-queue publication,
the SBI ecall, SSIP clear, and executor return. An IRQ-masked idle turn consumes a
reason rather than spinning forever if its work was stolen or cancelled. Logical
hart ids bind explicitly to firmware-provided physical hartids, and only online
physical harts receive standardized `mask=1, base=hartid` SBI calls. M5.2 keeps only
the boot hart online; stopped secondaries retain software reasons for M5.5.

M5.5 uses SBI HSM `hart_status` and asynchronous `hart_start`. The boot hart first
reserves a unique logical/physical mapping without publishing ONLINE; each
secondary selects its 256 KiB stack slot from the logical opaque value, installs
`tp`, `sscratch`, `stvec`, and its local timer, then self-registers and publishes a
ready bit. M6.2 leaves the low 4 KiB page of every slot unmapped and maps the other
252 KiB read/write and non-executable; the 256 KiB stride and the shift-only HSM
selection stay unchanged. The firmware-selected coldboot hart always owns logical
0, so QEMU may choose any physical ID without repeating BSS/global initialization.
Only that physical hart enables external interrupts, and the PLIC S-mode context
is computed from its actual ID; secondaries enable only software and timer
interrupts. Current topology discovery intentionally scans QEMU `virt`'s dense
physical IDs `0..3`; a general platform port must enumerate the FDT instead of
extending that assumption.

M5.3 hardens the interrupt-safe lock for physical-hart ownership and records the
complete retain/replace inventory in [SPINLOCK_AUDIT.md](SPINLOCK_AUDIT.md).
Device handler lookup, UART receive buffering, virtio IRQ transport snapshots, and
executor callback publication are atomic; scheduler lifecycle, wait queues, timers,
heap accounting, capability graphs, and recovery transactions retain short audited
locks with allocation-free contention counters.

M5.4 makes the execution ambient state explicit per logical hart: scheduler
running/woken slots, current-task and task-recovery identity, allocation
owner/arena and OOM diagnostics, interrupt context, nested task/program jump
buffers, generated-program console authority, and revocation-hook state. Scope
types are non-`Send` and validate same-hart restoration. On target, every lookup
uses the logical-to-physical mapping registered with the IPI layer and fails stop
if no mapping exists; only host models permit dense physical ids. The scheduler
stores a validated `logical_index + 1` token in each hart's `sscratch` so poll
and allocation hot paths do not rescan global topology; zero remains the
unregistered fail-closed value. It still uses one short global lifecycle lock,
but never holds it while polling, dropping, recovering, or reclaiming.

The scheduler lifecycle has two orthogonal coordinates. Its **phase** is running,
cancel-requested, terminal-committed, or terminal-published; its **location** is
ready, parked, exactly one hart's running slot, detached for reclamation, or gone. The runtime
and its fixed-point host model enforce these invariants:

- every live future has exactly one owner, and every ready ID occurs once;
- at most one task occupies the running slot, and only it may carry a deferred wake;
- cancellation becomes terminal only at a poll/reclaim boundary;
- fault wins over a pending cancellation, while a committed normal exit resists a
  late cancellation;
- publication happens only after Drop or audited raw reclamation, so a supervisor
  cannot restart against memory still being torn down;
- a tracked-arena fault detaches every sibling in that arena and no task outside it.

Debug builds check the concrete collections at scheduler mutation boundaries. A
pure two-task BFS explores the lifecycle state space for both shared and distinct
arenas, so violations report a deterministic predecessor trace instead of depending
on host timing.

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

M4.4 applies the same rule at the network boundary: the service exchanges owned
`Packet` values of at most one Ethernet frame through `Endpoint<Packet>`. It does
not expose the virtio DMA slab, a byte stream, an fd, or an ioctl surface. RX copies
the device-certified prefix into a packet before descriptor reuse, while TX copies
from the packet into stable SYSTEM DMA. See [VIRTIO_NET.md](VIRTIO_NET.md).

---

## 6. The compiler

### 6.1 Pipeline

```
source ──lex──► tokens ──parse──► AST ──collect──► relocatable template + strings
                                   │                              │
                                   └────codegen(2 passes)─────────┘
                                                                  │
                     RW-NX code-pool run ◄──link_into─────────────┘
                               │
                   break-before-make + all-hart fences
                               │
                               └────────► execute-only image ──► call
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

M6.1 runs this single address space through Sv39. M6.2 makes each stack's 4 KiB
guard invalid and its 252 KiB usable portion RW-NX. M6.3 removes execute from all
ordinary RAM, maps linker-delimited kernel text R-X, and moves generated instructions
into a dedicated 2 MiB page pool. A trusted linker receives an exclusive RW-NX
`WritableCode`, relocates directly into its exact slice, then consumes it to produce
an immutable execute-only `ExecutableCode`; no writable slice survives publication.
Every permission change uses invalid PTEs as a break-before-make phase, two all-hart
TLB shootdowns, and, when sealing, an all-hart instruction-cache fence. Generated-
code probes retain an additional 8 KiB of mapped abort room above the stack guard.

M6.4 maps linker-delimited `.rodata` R-- during boot and publishes capability-table
snapshots R-- from a linker-reserved 4 MiB pool. A CSpace mutation constructs and
validates a detached SYSTEM-owned `Vec<Slot>`, moves it into fresh exclusive RW-NX
pages, completes break-before-make plus all-hart TLB shootdowns to seal those pages,
and only then replaces the authoritative table. The retired snapshot is restored to
RW-NX only after replacement, then its slots are dropped, its complete run is cleared,
and its pages become reusable. Normal errors leave the old snapshot authoritative;
an exceptional SYSTEM allocation/protection fault may conservatively leak a detached
candidate because this synchronous commit path does not promise non-local rollback.

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
| Rewrite admitted code | The linker writes a private RW-NX page run, then removes write and read permission before publishing it. All harts complete the permission and instruction-cache transition first, and `sstatus.MXR` is cleared so execute-only does not imply readable. |
| Keep authority after revocation | Console hooks use `Revocable<ConsoleDev>` and revalidate before each operation. Raw memory is deliberately invocation-scoped: a non-cloneable `InvocationLease<MemoryRegion>` plus an exclusive claim covers the catcher call and is dropped after normal or abort return. Revocation prevents the next invocation. |

**Verified by demo:** `revoke prog` followed by a new run proves launch-time denial.
`rustc lease` additionally revokes immediately before the second generated console
operation: that operation is suppressed, the active memory lease still computes 42,
and a second cold launch without fresh grants aborts on its first array allocation.

`mmu wx` supplies the mapping-side evidence: it executes one sealed image on both
the boot hart and hart 1, releases it, observes a zeroed same-address first-fit run,
seals different instructions there, and obtains the new result on hart 1 without a
per-run `fence.i`. Separate fatal probes prove that writable code cannot execute and
that sealed code can neither be loaded nor stored. SBI RFENCE is a boot requirement
for multicore; a missing extension, unrepresentable online physical-hart mask, or
failed live shootdown is fail-stop rather than a partially published permission state.

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

W^X prevents an accepted image from remaining writable and executable; it does not
prove that the instructions accepted from the trusted emitter are safe. That remains
the purpose of the structural audit, differential oracle, and fuzzing below.

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
  than 64. `rustc edit` reads arbitrary console input on a 252 KiB usable kernel
  stack; M6.2 now faults accesses that land in the slot's invalid 4 KiB guard,
  while the parser limit prevents hostile input from deliberately consuming the
  stack and entering that fatal path.

The guard is deliberately a fail-stop boundary for addresses within that page, not
an emergency stack or complete stack-clash defence. A corrupted `sp` can jump over
one guard page into another mapped page, and trap entry saves registers on the
current `sp`, so an actual bad-`sp` overflow may fault recursively before the
normal diagnostic can run. Faulting accesses that land in the guard is the M6.2
claim; skipped-guard protection needs probing or a stronger boundary, and reliable
overflow reporting or recovery needs a separate per-hart trap stack.

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
components additionally receive a per-incarnation arena. After permanently detaching a
faulted task, the executor first invokes a non-allocating cleanup hook with its exact
`TaskId` and allocation domain so stable service claims cannot remain wedged. It then
quiesces every task in an audited arena, drains SYSTEM-owned runtime registrations,
abandons future envelopes without Drop, and raw-reclaims the arena. Ordinary tasks retain
the conservative memory-leak policy because they have no proven allocation-escape boundary,
but receive the same exact-task stable-state cleanup before `Faulted` is published.

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

Rust calls the trampoline through `vibe_catch(buf, thunk, context)`, an ordinary
single-return FFI function. Assembly performs both the context save and any later
non-local return internally, restoring `ra`, `sp`, `s0..s11`, and the entry SIE bit
from each 16-byte-aligned frame. Rust/LLVM therefore never has to reason about a
callsite returning twice. Nested catch frames are independent; the target self-test
checks normal and fault returns, register/stack canaries, eight nested frames, and
interrupt-state restoration. The kernel target is explicitly the integer-only
`riscv64imac-unknown-none-elf` `lp64` ABI; it does not advertise the `lp64d`
callee-save contract without an FPU context implementation.

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
destructors. Reproducible builds, the lifecycle model, and the M5.1 logical queue
model, M5.4 nested-hart execution model, and M5.5 four-hart QEMU execution are now in place. Explicit
resolved-cap lease semantics now complete the M3.5 sequence.

Five boundaries must stay explicit:

1. **Capabilities constrain object access, not arbitrary trusted component code.**
   In-tree Rust components remain in the TCB and may call kernel internals directly.
   Only code accepted by the in-kernel compiler currently gets the stronger
   confinement claim in §6.3. M6.3--M6.4 protect code, `.rodata`, and published
   capability-table bytes inside the shared S-mode address space; they do not turn
   that address space into a privilege boundary. M6.4 freezes only the published
   `Slot` snapshot (generation plus the live entry's rights, object pointer, and
   derivation pointer). CSpace scalar lifecycle fields and `Derivation.alive`
   `AtomicBool` nodes remain RW supervisor metadata, so this is not immutable storage
   for the complete capability graph.
2. **Cooperative scheduling is not temporal isolation.** Fuel bounds generated
   programs, but an in-tree future that never returns `Pending` can still wedge the
   hart. Cooperative cancellation takes effect only at poll boundaries; hard
   containment ultimately needs instrumentation, preemption, or a
   narrower admitted component format.
3. **Durable semantics precede object publication.** M4.0 specifies stable typed IDs,
   sealed append-only derivation records, prepare/commit grants, tombstone-first
   revoke, and high-water allocation. Recovery rejects malformed ancestry and lets
   an ancestor tombstone win over every descendant. This proves the pure crash model,
   M4.1 now supplies real supervised virtio-blk media with reset-before-DMA-reuse.
   M4.2 resolves immutable bytes through object capabilities over a unified kinds
   1--8 journal, with commit-flush-before-mint and raw-backing verification. M4.3
   now restores the fixed `persistent-test` CSpace only after inert preflight,
   external root selection, ancestor-tombstone filtering, and atomic typed graph
   installation. M4.4 applies the same supervised, reset-before-reuse discipline
   to two virtio-net queues behind typed packet endpoints. See [DURABLE_FORMAT.md](DURABLE_FORMAT.md),
   [VIRTIO_BLK.md](VIRTIO_BLK.md), [OBJECT_STORE.md](OBJECT_STORE.md), and
   [PERSISTENT_CSPACE.md](PERSISTENT_CSPACE.md), plus the network acceptance
   contract in [VIRTIO_NET.md](VIRTIO_NET.md).
4. **Revocation cannot retroactively erase an in-flight operation.** Console hooks
   revalidate a `Revocable` token before every write; a successful check linearizes
   that operation before an overlapping revoke. Direct generated loads and stores
   use an explicit invocation lease because they cannot be interposed without
   instrumentation or a mapping boundary. Revocation blocks the next invocation,
   not raw accesses already covered by that lease.
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
