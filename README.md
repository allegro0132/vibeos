# VibeOS

A capability-secure, single-address-space, async-first operating system kernel.
v0.1 boots on RISC-V under QEMU and gives you an interactive shell.

```
   __   __ __  _           ____  ____
   \ \ / /(_)| |__   ___  / __ \/ ___|
    \ V / | || '_ \ / _ \| |  | \___ \
     \_/  |_||_.__/ \___/ \____/|____/   v0.1
```

## Running it

```sh
./run.sh          # interactive; exit with Ctrl-A then X
./qrun.sh 10      # run for 10 seconds, feed the shell from stdin
```

Needs `qemu-system-riscv64`, a Rust toolchain with `rust-src`, and `ld.lld`.
`RUSTC_BOOTSTRAP=1` is set by the scripts because `-Z build-std` is required to
get `core`/`alloc` for a bare-metal target; a nightly toolchain works without it.

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

The system image in `world.rs` is 4 spaces wired to 1 channel and 1 device:

| space  | holds                                    | therefore cannot          |
|--------|------------------------------------------|---------------------------|
| init   | everything, `ALL` rights                 | —                         |
| sensor | telemetry `SEND`                         | read others' readings     |
| logger | telemetry `RECV`, console `WRITE`        | forge a reading           |
| guest  | console `WRITE`                          | pass the console on       |

Run `probe` in the shell to watch four attacks get refused, and `revoke guest`
to pull a live component's authority out from under it — no signal, no restart,
no cooperation from the component.

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

## A Rust compiler, inside the OS

`rustc hello` compiles a Rust hello world to native RV64 and runs it, without
leaving the kernel:

```
vibe> rustc hello
  compiled 1 fn -> 328 B of RV64 + 14 B of data in 5559 us
  --- running natively ---
Hello, world!
  --- exited with 0 in 228 us ---
```

`rustc demo` builds something with more in it — recursion, `while`, `%`,
short-circuit `&&`, `if` as an expression:

```
vibe> rustc demo
  compiled 3 fn -> 3528 B of RV64 + 70 B of data in 4533 us
  --- running natively ---
Hello, world!
fib(0) = 0  fib(1) = 1  fib(2) = 1  ...  fib(9) = 34
gcd(1071, 462) = 21
30 is even and greater than ten
```

`rustc edit` takes a program typed at the console, ended with a lone `.`.

### The subset

`fn` with `i64` parameters and return type, `let` / `let mut`, assignment,
`if`/`else` **as an expression**, `else if` chains, `while`, `return`, block tail
expressions, recursion, `+ - * / %`, `== != < <= > >=`, short-circuiting
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
them. Instruction *sizes* never depend on addresses — 64-bit constants are always
materialized in a fixed 11-instruction sequence — so both passes agree on layout
by construction. Branches are emitted as an inverted conditional over a `jal`,
giving ±1 MB of range instead of the 4 KB a bare `beq` would allow.

Because VibeOS has no MMU and no W^X, "load the program" is `fence.i` followed by
transmuting the code buffer to a function pointer and calling it.

### And this is where it earns its place in *this* OS

Generated machine code has no way to reach hardware. Its only exit is a call to
`rt_print_str`/`rt_print_int`, whose addresses the compiler bakes in and which a
program cannot name, forge, or substitute. Those hooks resolve the `prog` space's
console capability **on every call**:

```
vibe> revoke prog
  revoked 1 cap(s) in `prog`
vibe> rustc hello
  compiled 1 fn -> 328 B of RV64 + 14 B of data in 589 us
  --- running natively ---
  --- exited with 0 in 165 us ---
  note: output was suppressed -- `prog` holds no console capability
```

Same compiler, byte-identical machine code, and it still runs to completion — it
just has no authority to say anything. On a conventional OS, native code that has
already been loaded owns whatever its process owns. Here, authority is not a
property of the code.

## What's here

| file | |
|---|---|
| `cap.rs` | capabilities, rights, CSpaces, attenuation, cascading revoke |
| `chan.rs` | typed bounded channels; rights decide which end you hold |
| `exec.rs` | the executor, wakers, wait queues, timers |
| `world.rs` | the system image: spaces, components, wiring |
| `shell.rs` | interactive shell (`probe`, `revoke`, `caps`, `ps`, …) |
| `trap.rs` | S-mode trap entry, IRQ → waker |
| `uart.rs`, `plic.rs`, `sbi.rs`, `dev.rs` | hardware |
| `rustc/` | lexer, parser, RV64 code generator, capability-gated runtime |
| `heap.rs` | bump allocator with size-class free lists |
| `sync.rs` | interrupt-safe spinlock |

~3300 lines total.

## Shell

```
ps              live tasks and how many times each was polled
spaces          capability spaces in the system
caps <space>    dump a space's capability table
rustc hello     compile and run a Rust hello world, natively
rustc demo      compile and run a larger sample (fib, gcd, loops)
rustc edit      type your own program; end it with a lone `.`
probe           attempt four illegal operations, show the refusals
revoke <space>  pull a component's authority at runtime (`guest` or `prog`)
chan            telemetry channel depth and totals
quiet           mute background components (`verbose` restores)
mem             kernel heap usage
uptime          seconds since boot
echo <text>     write via init's console capability
halt            shut the machine down
```

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
- **Cross-space revoke doesn't cascade.** `grant` into another space records no
  parent link, so revoking the source doesn't chase the copy. Intra-space
  revoke does cascade. Fixing this needs a global derivation tree.
- **The heap never returns large blocks.** Allocations over 64 KiB come from the
  bump region and are leaked on free. Nothing in the current image allocates
  that large.
- **`lookup_as` uses `Arc::from_raw` after an `Any` check.** Sound, but it wants
  `Arc::downcast` once that's usable through the `Resource` trait object.
- **The compiler's subset is `i64`-only.** No structs, arrays, references,
  generics, traits, or borrow checking — a program is functions over integers
  plus formatted printing. Division by zero follows RISC-V semantics (`-1`,
  and `%` yields the dividend) rather than panicking.
- **Compiled programs run on the shell task's 256 KiB stack**, so deep
  recursion in generated code will run off the end of it.
- **No persistence, no MMU, no user mode, no multicore.** In that order.
