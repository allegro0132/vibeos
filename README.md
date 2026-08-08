# VibeOS

A capability-secure, single-address-space, async-first operating system kernel.
v0.1 boots on RISC-V under QEMU and gives you an interactive shell.

```
   __   __ __  _           ____  ____
   \ \ / /(_)| |__   ___  / __ \/ ___|
    \ V / | || '_ \ / _ \| |  | \___ \
     \_/  |_||_.__/ \___/ \____/|____/   v0.1
```

## Documents

- **[docs/BLUEPRINT.md](docs/BLUEPRINT.md)** — architecture, the four bets, the
  capability model's invariants, the compiler's confinement argument and where it
  leaks, and the trust model.
- **[docs/ROADMAP.md](docs/ROADMAP.md)** — the developer plan: milestones M1–M6,
  workstreams, testing strategy, metrics, and the risk register.
- **[TESTING.md](TESTING.md)** — the four test layers and what each one is blind to.

## Testing

```sh
cargo test --workspace     # 209 host tests, no QEMU, ~1s
./scripts/qemu-test.sh     # 8 QEMU cases (7 goldens + differential), ~4min
./scripts/bench.py         # fixed QEMU/TCG baseline + regression policy
```

Plus an in-kernel self-test (307 checks) for what the host cannot fake — real
timer interrupts, real wakeups, the live capability graph, and machine code
actually executing. Type `selftest` in the shell. See **[TESTING.md](TESTING.md)**
for why there are four layers and which mutations each one catches.

## Running it

```sh
./run.sh          # interactive; exit with Ctrl-A then X
./qrun.sh 10      # run for 10 seconds, feed the shell from stdin
```

Needs `qemu-system-riscv64`, a Rust toolchain with `rust-src`, and `ld.lld`.
`RUSTC_BOOTSTRAP=1` is set by the scripts because `-Z build-std` is required to
get `core`/`alloc` for a bare-metal target; a nightly toolchain works without it.

`bench` in the shell emits a versioned JSON-lines measurement set. The host
runner fixes the machine, CPU, hart count, TCG mode, and virtual clock, records
QEMU/toolchain metadata, and checks the committed baseline. Updating that truth
is always explicit: `./scripts/bench.py --update`.

## The design

Three bets, each aimed at something conventional systems got locked into for
reasons that have expired.

### 1. Authority is a capability, never a name

Unix decided that the way to reach a resource is to *name* it — a path, a PID, a
uid — and then ask a global policy oracle whether you're allowed. Every
confused-deputy bug in the last forty years lives in the gap between the name
you asked about and the object you got. VibeOS has no global namespace at all:
no paths, no uids, no root, no ambient authority of any kind.

A component can act on a resource only by presenting a `Cap` from its own
`CSpace`, and every operation names the rights it requires:

```rust
let ep = space.lookup_as::<Endpoint<Reading>>(tx, Rights::SEND)?;
ep.send(reading).await;
```

`Cap` has private fields, so safe code cannot mint one. It can only receive one
from a holder — and `grant`/`derive` can only ever *shrink* rights. Amplification
isn't policed at runtime; it's absent from the API.

The system image in `world.rs` has 5 spaces wired to 1 channel, a console, and a
bounded memory region. Four are owned by supervised components; `prog` is the
explicitly unbound execution space used synchronously by the shell task:

| space  | holds                                    | therefore cannot          |
|--------|------------------------------------------|---------------------------|
| init   | everything, `ALL` rights                 | —                         |
| sensor | telemetry `SEND`                         | read others' readings     |
| logger | telemetry `RECV`, console `WRITE`        | forge a reading           |
| guest  | console `WRITE`                          | pass the console on       |
| prog   | console `WRITE`, memory `READ|WRITE`      | reach any other resource  |

Run `probe` in the shell to watch four attacks get refused. `revoke guest` pulls
a live component's authority out from under it, while `cancel guest` separately
stops its task; authority and lifecycle are deliberately different controls.

### 2. Isolation is a type system, not a page table

Hardware isolation is expensive precisely where modern systems need it most:
a syscall or IPC costs a mode switch, a TLB flush, and a copy. That price bought
protection from *unsafe languages*. If components are memory-safe by
construction, you can charge a function call instead.

VibeOS runs every component in one address space with no MMU and no user mode.
The enforcement boundary is `unsafe` — of which there are ~10 uses, all in the
hardware layer (`sbi`, `uart`, `plic`, `trap`, `heap`, `sync`) and none in the
capability core's decision path. IPC is a queue push, not a context switch.

The honest caveat: this makes the Rust compiler part of the TCB, and a component
compiled from unsafe code could forge a `Cap` by transmuting one. v0.1 is a
single trusted build. The path to untrusted components is to make the loader,
not the linker, the boundary — verified-bytecode or WASM components, which
preserves the cheap-IPC property while removing the compiler from the TCB.

### 3. Concurrency is a future, not a thread

A thread is a stack you pay for whether or not you're using it, plus a scheduler
that must forcibly interrupt you because it can't tell when you're idle. Async
Rust already knows: a suspended task is exactly the bytes it needs and nothing
more, and it tells the scheduler when to come back.

So VibeOS has no threads, no kernel stacks per task, and no preemption. The unit
of scheduling is a `Future`. Interrupt handlers do exactly one thing — turn a
hardware event into `Waker::wake()`:

```rust
match code {
    5 => exec::timer_tick(),            // wake expired sleepers
    9 => { /* claim PLIC IRQ */ uart::handle_irq() },  // wake the RX waiter
}
```

`sleep_ms(1200).await` is a timer registration, not a blocked stack. An idle
VibeOS parks in `wfi` and draws no CPU. The waker is the `TaskId` itself cast to
the raw-waker pointer — no allocation, no refcounting, no `Arc` per wake.

The system image binds each supervised unit into one retained `Component`
record: a stable `ComponentId`, its current task incarnation, its CSpace, an
enforced memory owner/budget, and lifecycle state. `ps` and `caps` read that same
record, so an exited, faulted, or cancelled task keeps both its identity and terminal reason
after the executor removes it. Heap blocks carry immutable owner provenance;
quota refusal faults only the requesting component, and cross-owner frees credit
the allocator account that originally paid for the block.

Each retained task handle supports cooperative cancellation and async join/exit
reporting. Cancelling a ready or parked task detaches it and drops its future
without another poll; cancelling the task currently running takes effect when
that poll returns. Faults win over simultaneous cancellation, terminal states
are absorbing, and a stale wake cannot revive a task. This is not preemption: an
in-tree future that never yields can still wedge the single hart. Wait listeners
carry an epoch and unique registration token, while sleeps carry a unique timer
token; normal completion, Drop, and cancellation release those registrations
immediately. Audited World components run in per-incarnation fault arenas: a
fault detaches the entire arena, purges its registrations, and reclaims its
blocks without invoking the interrupted future's destructors. Ordinary tasks
without that no-escape audit still use the conservative leak-on-fault policy.

## A Rust compiler, inside the OS

`rustc hello` compiles a Rust hello world to native RV64 and runs it, without
leaving the kernel:

```
vibe> rustc hello
  compiled 1 fn -> 460 B of RV64 + 14 B of data in N us
  --- running natively ---
Hello, world!
  --- exited with 0 in N us ---
```

`rustc demo` builds something with more in it — recursion, `while`, `%`,
short-circuit `&&`, `if` as an expression:

```
vibe> rustc demo
  compiled 3 fn -> N B of RV64 + N B of data in N us
  --- running natively ---
Hello, world!
fib(0) = 0  fib(1) = 1  fib(2) = 1  ...  fib(9) = 34
gcd(1071, 462) = 21
30 is even and greater than ten
```

`rustc edit` takes a program typed at the console, ended with a lone `.`.

### The subset

Types are `i64`, `bool`, and `()`, checked by a real type pass — conditions must
be `bool`, so `if 1` is the error it is in Rust.

`fn` with typed parameters and return type, `let` / `let mut`, assignment,
`if`/`else` **as an expression**, `else if` chains, `while`, `return`, block tail
expressions, fixed-size `[i64; N]` arrays with bounds-checked indexing,
recursion, `+ - * / %`, `== != < <= > >=`, short-circuiting
`&& ||`, unary `-` and `!`, and `print!`/`println!` with `{}` holes. Line
comments. Up to 8 parameters and 252 locals per function.

Diagnostics carry line numbers and say what real rustc would say:

```
error: line 1: cannot assign twice to immutable variable `x` (declare it `let mut`)
error: line 2: cannot find value `y` in this scope
error: line 1: `f` takes 1 argument(s) but 2 were supplied
error: line 1: format string wants at least 2 argument(s), 1 given
```

### How it works

AST straight to machine code — no IR, no register allocator. Values live on the
machine stack and only `t0`/`t1` are live between instructions, so nothing ever
needs spilling across a call. Slots are 16 bytes wide to keep `sp` aligned to
the RISC-V C ABI at every call boundary.

Codegen runs twice: pass 1 discovers function addresses, pass 2 emits calls to
them. Instruction sizes never depend on addresses: compiler-chosen function and
runtime addresses use the fixed-length `li64` sequence, while ordinary integer
literals use the shortest stable one- or two-instruction form when possible. Both
passes therefore agree on layout. Branches are emitted as an inverted conditional
over a `jal`, giving ±1 MB of range instead of the 4 KB a bare `beq` would allow.

Because VibeOS has no MMU and no W^X, "load the program" is `fence.i` followed by
transmuting the code buffer to a function pointer and calling it.

### And this is where it earns its place in *this* OS

Generated machine code has no way to reach hardware. Its only output path is a
call to compiler-chosen runtime hooks whose addresses a program cannot name,
forge, or substitute. At each program invocation, `rustc::run` resolves the
`prog` space's console and memory capabilities and holds those resolved objects
for that invocation. Revocation before the run is enforced; whether revocation
during a run should invalidate that invocation lease is roadmap 3.16:

```
vibe> revoke prog
  revoked 2 cap(s) in `prog`
vibe> rustc hello
  compiled 1 fn -> 460 B of RV64 + 14 B of data in N us
  --- running natively ---
  --- exited with 0 in N us ---
  note: output was suppressed -- `prog` holds no console capability
```

Same compiler, byte-identical machine code, and it still runs to completion — it
just has no authority to say anything. On a conventional OS, native code that has
already been loaded owns whatever its process owns. Here, authority is not a
property of the code.

## What's here

| file | |
|---|---|
| `world.rs` | the system image: spaces, components, wiring |
| `dev.rs` | console and memory-region resources |
| `shell.rs` | interactive shell (`probe`, `revoke`, `caps`, `ps`, …) |
| `trap.rs` | S-mode trap entry, IRQ → waker |
| `uart.rs`, `plic.rs`, `sbi.rs`, `dev.rs` | hardware |
| `compiler/` | lexer, parser, RV64 code generator (its own crate, host-testable) |
| `core/` | capabilities, channels, scheduler, allocator, lock (host-testable) |
| `rustc.rs` | wires the compiler to the capability system and to hardware |
| `selftest.rs` | in-kernel test suite |
| `arch/` | the seam between portable logic and the machine (riscv + host shim) |

~10,500 Rust lines across `core`, `compiler`, and `kernel` (2026-08-08 snapshot).

## Shell

```
ps              component identities, lifecycle, and poll counts
spaces          capability spaces in the system
caps <space>    component owner and capability table
rustc hello     compile and run a Rust hello world, natively
rustc demo      compile and run a larger sample (fib, gcd, loops)
rustc conform   compile and run the language conformance program
selftest        run the in-kernel test suite
bench           emit the versioned machine-readable benchmark suite
rustc edit      type your own program; end it with a lone `.`
probe           attempt four illegal operations, show the refusals
revoke <space>  pull a component's authority at runtime (`guest` or `prog`)
cancel <name>   cooperatively stop a component (the active shell is protected)
restart <name>  restart a terminal audited component with fresh grants
chan            telemetry channel depth and totals
quiet           mute background components (`verbose` restores)
mem             kernel heap usage
uptime          seconds since boot
echo <text>     write via init's console capability
halt            shut the machine down
```

## Confinement

A compiled program cannot reach hardware, and every way it could get stuck is
checked. Try them:

```
vibe> rustc edit
  | fn main() -> i64 { let mut i = 0; while i >= 0 { i = i + 0; } i }
  | .
  --- aborted: exceeded execution budget (after N us) ---
vibe> ps
  ...                        <- shell alive, every component still ticking
```

The same for stack overflow, divide by zero, remainder by zero, `i64::MIN / -1`,
and arithmetic overflow — each with the wording real rustc uses. A component
that *panics* is caught the same way and costs only its own task.

## The console

Components print from tasks the shell knows nothing about, so the tty owns the
bottom line of the screen: any asynchronous write erases the prompt, prints, and
redraws the prompt with your partial input intact. Type `up`, let a reading land,
finish with `time`, and you still ran `uptime`.

`quiet` mutes the demo components; `verbose` brings them back. That is a
rendering setting, not an authority one — muting decides what reaches the
screen, whereas `revoke` decides who is allowed to speak at all. `ps` keeps
showing rising poll counts while muted, because the components never stopped.

## Known limits of v0.1

Deliberate, not overlooked:

- **Single hart.** The spinlock is real but `-smp 1` is the only tested config.
- **`lookup_as` uses `Arc::from_raw` after an `Any` check.** Sound, but it wants
  `Arc::downcast` once that's usable through the `Resource` trait object.
- **`!` is logical negation, not Rust's bitwise NOT.** The subset has no `bool`,
  so `!5` is `0` here and `-6` in real Rust. This is the one place the subset is
  not a strict subset, and it is what the roadmap's differential testing against
  real rustc would flag first.
- **No structs, references, generics, traits, or borrow checking.** A program is
  functions over `i64`, `bool` and fixed-size arrays.
- **Array indices are `i64`, not `usize`.** There is no `as`, so a corpus program
  valid in both languages keeps counters separate from values.
- **Runtime infrastructure is charged to the SYSTEM heap domain.** Component
  quotas cover dynamic allocation while their future is polled or destroyed;
  task envelopes, wait registries, capability tables, and IRQ work remain part
  of the trusted kernel budget.
- **Only audited component fault arenas are reclaimed.** Their tasks, runtime
  registrations, and allocation escape boundaries are sealed by the World
  factory. An ordinary task interrupted mid-poll is still conservatively leaked.
- **A panic with no landing pad is still fatal** — a fault in the boot path or
  inside an interrupt handler halts the machine.
- **Fuel is a fixed budget, not a deadline.** A long-running legitimate program
  is aborted at 20M calls-plus-iterations. Making it a clock needs a timer read,
  which generated code is not permitted.
- **No persistence, no MMU, no user mode, no multicore.** In that order.
