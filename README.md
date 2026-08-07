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
| `heap.rs` | bump allocator with size-class free lists |
| `sync.rs` | interrupt-safe spinlock |

~1800 lines total.

## Shell

```
ps              live tasks and how many times each was polled
spaces          capability spaces in the system
caps <space>    dump a space's capability table
probe           attempt four illegal operations, show the refusals
revoke <space>  pull a component's authority at runtime
chan            telemetry channel depth and totals
mem             kernel heap usage
uptime          seconds since boot
echo <text>     write via init's console capability
halt            shut the machine down
```

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
- **No persistence, no MMU, no user mode, no multicore.** In that order.
