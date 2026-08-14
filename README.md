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
- **[docs/ROADMAP.md](docs/ROADMAP.md)** — the developer plan: milestones M1–M7,
  workstreams, testing strategy, metrics, and the risk register.
- **[docs/STORAGE_V2_ROADMAP.md](docs/STORAGE_V2_ROADMAP.md)** — the post-v1
  managed-block Blob CAS plan: `sha2`, segment/checkpoint format, root-based GC,
  online growth, quotas, scrub, and M4 migration.
- **[docs/STORAGE_V2_FORMAT.md](docs/STORAGE_V2_FORMAT.md)** — the frozen v1
  segment, seal, checkpoint, and power-cut recovery ABI.
- **[docs/STORAGE_V2_STORE.md](docs/STORAGE_V2_STORE.md)** — the append-only
  segment writer, catalog/allocation payload ABI, bounded recovery, and fault model.
- **[docs/STORAGE_V2_CAS.md](docs/STORAGE_V2_CAS.md)** — the canonical streaming
  Blob layout, CAS catalog ABI, complete-Blob deduplication, and authority rules.
- **[docs/STORAGE_V2_GC.md](docs/STORAGE_V2_GC.md)** — persistent/runtime roots,
  typed edges, generation pins, and the crash-safe G/G+1/G+2 reuse barrier.
- **[docs/CAPABILITY_SHELL.md](docs/CAPABILITY_SHELL.md)** — the S0 contract for
  Bash-inspired syntax with capability-native commands, streams, Jobs, limits,
  cancellation, and fail-closed admission.
- **[docs/SPINLOCK_AUDIT.md](docs/SPINLOCK_AUDIT.md)** — the M5.3 complete lock
  inventory, IRQ hot-path replacements, retained transaction boundaries, and
  multicore measurement gates.
- **[docs/MMU.md](docs/MMU.md)** — the shared Sv39 map, boot publication
  contract, mapped apertures, per-hart stack guards, and integrity-hardening
  sequence.
- **[docs/HARDWARE_ARCHITECTURE.md](docs/HARDWARE_ARCHITECTURE.md)** — firmware,
  BSP, kernel-adapter, and driver-crate boundaries plus compile-time board
  composition.
- **[docs/MILKV_DUO.md](docs/MILKV_DUO.md)** — single-core Milk-V Duo
  (CV1800B) support, SDK packaging, and hardware validation checklist.
- **[docs/DURABLE_FORMAT.md](docs/DURABLE_FORMAT.md)** — the stable authority-log
  ABI, crash model, transaction ordering, recovery algorithm, and proof limits.
- **[docs/OBJECT_STORE.md](docs/OBJECT_STORE.md)** — the capability-only object
  API, unified on-disk journal, publication boundary, and raw-media acceptance.
- **[docs/PERSISTENT_CSPACE.md](docs/PERSISTENT_CSPACE.md)** — the fixed
  `persistent-test` CSpace, external root policy, atomic recovery install, and
  three-boot acceptance boundary.
- **[docs/PROGRAM_PERSISTENCE.md](docs/PROGRAM_PERSISTENCE.md)** — canonical
  source/VIBEEXE objects, crash-safe publication, compiler revalidation, and
  restored least authority.
- **[docs/WASM_ROADMAP.md](docs/WASM_ROADMAP.md)** — the Component Model-first
  admitted-code plan: WIT contracts, bounded Core-WASM execution, CSpace-backed
  resources, native async, composition, durable installation, and later adapters/AOT.
- **[docs/VIRTIO_NET.md](docs/VIRTIO_NET.md)** — the modern virtio-net subset,
  typed packet boundary, device-wide reset contract, and localhost L2 evidence.
- **[docs/SSH.md](docs/SSH.md)** — the staged capability-native path from raw
  Ethernet through bounded TCP to a public-key-only SSH `exec` service.
- **[docs/JITTERENTROPY.md](docs/JITTERENTROPY.md)** — the pinned Rust crate,
  isolated Duo smoke/raw-delta probe, SP800-90B evidence workflow, and
  fail-closed production admission gate.
- **[TESTING.md](TESTING.md)** — the four test layers and what each one is blind to.

## Testing

Initialize the pinned Sunset fork after cloning the repository:

```sh
git submodule update --init --recursive
```

```sh
cargo test --workspace \
  --exclude vibeos-kernel \
  --exclude vibeos-firmware-qemu-virt \
  --exclude vibeos-firmware-milkv-duo # portable tests, no firmware link
cargo test --manifest-path vendor/sunset/Cargo.toml -p sunset \
  --no-default-features --features alloc # audited Sunset fork tests
cargo check -p vibeos-sshd # board-neutral SSH component
./scripts/differential.sh    # exact-output oracle using the pinned rustc
./scripts/qemu-test.sh       # QEMU goldens plus the differential corpus
./scripts/qemu-tcp-test.sh   # N1 static/DHCP IPv4 and TCP echo through host forwarding
./scripts/qemu-tcp-test.sh recovery # N2 stack/driver generation-recovery gate
./scripts/qemu-iperf3-test.sh # real iperf3 client, forward and reverse TCP
./scripts/qemu-ssh-security-test.sh # N3 entropy/identity capability gate
./scripts/qemu-ssh-test.sh   # N4/N5 real OpenSSH exec and rejection gate
python3 -B scripts/milkv-tcp-test.py ADDRESS # physical Duo TCP/rearm gate
python3 -B scripts/milkv-dhcp-test.py # isolated direct-link DHCP peer
./scripts/milkv-ssh-test.sh ADDRESS # explicit insecure physical SSH/VSH gate
./scripts/build-milkv-duo.sh --jitterentropy-probe # isolated Duo entropy probe
./scripts/build-milkv-duo.sh --jitterentropy-ssh-probe # fixed-key SSH evidence transport
./scripts/build-milkv-duo.sh --iperf3-server # DHCP iperf3 server image for Duo
./scripts/bench.py           # fixed QEMU/TCG baseline + regression policy
./scripts/bench.py --smp-scaling # four-hart equal-work throughput acceptance
python3 -B scripts/storage-v2-image.py --selftest # independent format verifier
./scripts/status.sh --check  # derive inventory and verify the active rustc pin
```

Plus an in-kernel self-test for what the host cannot fake — real
timer interrupts, real wakeups, the live capability graph, and machine code
actually executing. Type `selftest` in the shell; the QEMU harness reports its
observed check count. See **[TESTING.md](TESTING.md)** for why there are four
layers and which mutations each one catches.

## Running it

```sh
./run.sh          # interactive; exit with Ctrl-A then X
./qrun.sh 10      # run for 10 seconds, feed the shell from stdin
./scripts/qemu-usb-test.sh  # PCI/XHCI, USB keyboard, storage, and hotplug
```

Normal images boot directly into `vsh>` with a dedicated CSpace. The broad
diagnostic shell is compiled only with the `legacy-shell` test feature; the
QEMU golden and benchmark harnesses select that feature explicitly.

Board selection and final linking live in `firmware/qemu-virt` and
`firmware/milkv-duo`. Build from one firmware directory at a time so Cargo
loads `firmware/.cargo/config.toml` and never unifies mutually exclusive board
features into one kernel archive. Each board crate supplies typed hardware
descriptions; kernel adapters add capabilities, IRQ routing, synchronization,
and supervision around board-independent `drivers/*` engines. See
**[docs/HARDWARE_ARCHITECTURE.md](docs/HARDWARE_ARCHITECTURE.md)** for the crate
boundaries and driver inventory.

The QEMU `virt` port also owns its generic PCI ECAM host: it discovers type-0
functions, sizes and assigns 32/64-bit BARs, enables bus mastering per driver,
and routes INTx through the PLIC. The XHCI driver uses that interface for USB
enumeration, interrupt-driven HID boot keyboards, and Bulk-Only/SCSI mass
storage. `usb info`, `usb read N`, and the destructive CI-only `usb test`
diagnostic expose the live devices. The acceptance script types its commands
through `usb-kbd`, hot-unplugs/replugs that keyboard, and verifies the guest's
USB-storage write directly in the host backing image.

Milk-V Duo boot images are generated with the official SDK. The deliverable image
contains a FAT boot partition plus a raw VibeOS data partition and no Linux root
filesystem. Follow
**[docs/MILKV_DUO.md](docs/MILKV_DUO.md)** for the build and flashing procedure.
The Milk-V production and optional Jitterentropy probe images use the
`vendor/jitterentropy-rs` submodule pinned to one upstream commit. The Duo build
script verifies and idempotently applies the recorded VibeOS qualification
patch in that submodule; see `patches/jitterentropy-rs/README.md`. The parent
repository ignores the resulting expected dirty marker. No separate C compiler
is required.

Needs `qemu-system-riscv64`, `ld.lld`, and rustup. The repository pins
`nightly-2026-08-01` (including `rust-src` and LLVM tools) in
`rust-toolchain.toml`; every local script and CI build consumes that same file.
`scripts/status.sh --check` fails if the active compiler commit differs from the
recorded pin.

`bench` in the shell emits a versioned JSON-lines measurement set. The host
runner fixes the machine, CPU, hart count, TCG mode, and virtual clock, records
QEMU/toolchain metadata, and checks the committed baseline. Updating that truth
is always explicit: `./scripts/bench.py --update`. The separate `--smp-scaling`
mode uses four multithreaded TCG vCPUs, exact-hart workers, equal serial/parallel
work, and a committed minimum `1.25x` speedup.

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

The base system image in `world.rs` has five spaces wired to one channel, a console,
and a bounded memory region. Four are owned by supervised components; `prog` is
the explicitly unbound execution space used synchronously by the shell task.
When virtio-blk is discovered, private driver and store-backend spaces plus the
fixed `persistent-test` and `saved-program` CSpaces are added. A private
`saved-program-policy` space is the supervisor root for reconstructed console and
memory authority. The backend holds only attenuated block `READ|WRITE`; neither
persistent target receives Store `WRITE`:

| space  | holds                                    | therefore cannot          |
|--------|------------------------------------------|---------------------------|
| init   | everything, `ALL` rights                 | —                         |
| sensor | telemetry `SEND`                         | read others' readings     |
| logger | telemetry `RECV`, console `WRITE`        | forge a reading           |
| guest  | console `WRITE`                          | pass the console on       |
| prog   | console `WRITE`, memory `READ|WRITE`      | reach any other resource  |
| virtio-blk | MMIO, DMA, block service `READ|WRITE` | console or object caps    |
| store-backend | block service `READ|WRITE`        | paths or client CSpaces   |
| persistent-test | durable stored-object caps      | Store `WRITE` or paths    |
| saved-program-policy | console/memory policy roots | block, Store, or program artifact |
| saved-program | artifact `READ`, console `WRITE`, memory `READ|WRITE` | Store `WRITE`, paths, or legacy `prog` authority |

Run `probe` in the shell to watch four attacks get refused. `revoke guest` pulls
a live component's authority out from under it, while `cancel guest` separately
stops its task; authority and lifecycle are deliberately different controls.

### 2. Isolation is a type system, not a page table

Hardware isolation is expensive precisely where modern systems need it most:
a syscall or IPC costs a mode switch, a TLB flush, and a copy. That price bought
protection from *unsafe languages*. If components are memory-safe by
construction, you can charge a function call instead.

VibeOS runs every component in one shared S-mode address space with no user mode
or per-process page tables. Its shared Sv39 map enforces kernel integrity
properties such as invalid stack guards, not component isolation. The enforcement
boundary remains `unsafe` — of which there are ~10 uses, all in the hardware layer
(`sbi`, `uart`, `plic`, `trap`, `heap`, `sync`) and none in the capability core's
decision path. IPC is a queue push, not a context switch.

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
in-tree future that never yields can still wedge its executor hart. Wait listeners
carry an epoch and unique registration token, while sleeps carry a unique timer
token; normal completion, Drop, and cancellation release those registrations
immediately. Audited World components run in per-incarnation fault arenas: a
fault detaches the entire arena, purges its registrations, and reclaims its
blocks without invoking the interrupted future's destructors. Ordinary tasks
without that no-escape audit still use the conservative leak-on-fault policy.
Both paths first notify a non-allocating exact-task fault hook after permanent
detach, so an abandoned persistent-store claim cannot wedge later callers.

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

VibeOS now has one shared Sv39 address space. M6.2 leaves each 4 KiB stack guard
invalid and maps the remaining 252 KiB in its fixed 256 KiB per-hart slot RW-NX.
M6.3 makes ordinary RAM RW-NX and linker-delimited kernel text R-X. Generated
instructions no longer live in the heap: the compiler relocates directly into an
exclusive page run from a dedicated 2 MiB code pool while it is RW-NX, then seals
that run execute-only before exposing its entry point. Every hart clears
`sstatus.MXR`, so execute-only pages cannot be read as data.

Sealing and unsealing use break-before-make PTE updates, local fences, and
synchronous SBI RFENCE operations for every other online physical hart. A sealed
buffer is never published until both TLB shootdowns and the all-hart instruction-
cache fence complete. Drop removes execute permission, zeros the complete page run
including padding, and only then permits same-address reuse; audited component-fault
recovery applies that same sequence after all-hart quiescence when `longjmp` skipped
Rust destructors. `mmu wx` demonstrates sealed execution on the boot hart and hart 1,
zeroed same-address reuse, and different code executing remotely after reuse.

M6.4 also maps linker-delimited `.rodata` R-- at boot and gives capability tables a
linker-reserved 4 MiB COW pool. Each mutation finishes a detached SYSTEM-owned
candidate, moves it into exclusive RW-NX pages, seals them R-- with all-hart
break-before-make shootdowns, and only then swaps the authoritative snapshot. The
retired table returns to RW-NX only after that swap, then drops its entries, clears
the full run, and permits same-address reuse. `mmu ro` exercises mint, derive,
cross-hart lookup, revoke, stale-handle denial, and reuse; separate fatal probes prove
that stores to `.rodata` and a published table fault at the exact address.

This protects the published `Slot` snapshot—generation, rights, object pointer, and
derivation pointer—not the complete capability graph. CSpace lifecycle scalars and
the derivation nodes' `alive` atomics remain writable supervisor metadata, and the
shared S-mode address space still provides integrity hardening rather than component
isolation. Candidate commit is synchronous and ordinary errors preserve the old
authoritative table; an exceptional SYSTEM allocation/protection failure may
conservatively leak a detached candidate.

### And this is where it earns its place in *this* OS

Generated machine code has no way to reach hardware. Its only output path is a
call to compiler-chosen runtime hooks whose addresses a program cannot name,
forge, or substitute. At each invocation, `rustc::run` resolves the `prog`
space's capabilities with two explicit lifetimes. Console output holds a
revocable token and rechecks its complete derivation before every print operation.
Raw memory holds one non-cloneable, exclusive invocation lease across the native
call because generated loads and stores cannot be interposed. Revocation therefore
denies the next console operation while allowing already-authorized memory work to
finish; a later launch cannot acquire either lease. `rustc lease` demonstrates all
three boundaries:

```
vibe> rustc lease
  --- lease run 1: revoke before console operation 2 ---
lease-visible
  --- exited with 42 in N us ---
  note: output was suppressed -- `prog` console authority is absent or revoked
  note: hook revoked 2 cap(s); the active memory lease completed
  --- lease run 2: cold launch after revocation ---
  --- aborted: the granted memory region is too small for this program (after N us) ---
  note: no grant or hook was installed between runs
```

The second print is absent because its revocable console token was killed first.
The value 42 proves that the already-acquired memory lease completed, while the
cold second launch proves that revocation was not mistaken for a permanent cached
object. On a conventional OS, native code that has already been loaded owns whatever
its process owns. Here, authority is not a property of the code.

## What's here

| file | |
|---|---|
| `world.rs` | the system image: spaces, components, wiring |
| `dev.rs` | console and memory-region resources |
| `kernel/src/legacy_shell.rs` | feature-gated diagnostic shell (`probe`, `revoke`, `caps`, `ps`, …) |
| `trap.rs` | S-mode trap entry, IRQ → waker |
| `uart.rs`, `plic.rs`, `sbi.rs`, `dev.rs` | hardware |
| `compiler/` | lexer, parser, RV64 code generator (its own crate, host-testable) |
| `core/` | capabilities, channels, scheduler, allocator, lock (host-testable) |
| `durable-format/` | zero-dependency sealed-log codec, stable IDs, and fail-closed recovery (`no_std`) |
| `blob-format/` | canonical immutable Merkle blob encoding and chunk proofs (`no_std`) |
| `storage-device/` | capability-scoped block ranges, geometry, sessions, and mutation certainty (`no_std`) |
| `segment-format/` | allocation-free Storage V2 segment/checkpoint codec and verifier (`no_std`) |
| `segment-store/` | bounded streaming Storage V2 Blob CAS, complete-Blob deduplication, root-based cleaning, and opaque authority publication (`no_std + alloc`) |
| `random/` | bounded ChaCha20 DRBG and explicit entropy-source contract (`no_std`) |
| `runtime/riscv/` | bare-metal RISC-V CSR, assembly, and SBI runtime seam (`no_std`) |
| `components/netstack/` | configurable IPv4/TCP stack and VSH network control plane (`no_std`) |
| `components/iperf3-server/` | bounded iperf3-compatible single-stream TCP server (`no_std`) |
| `kernel/src/netstack_platform.rs` | thin packet/network-control adapter plus recovery-only test hooks |
| `components/vsh/` | capability-native interactive loop, foreground cancellation, rendering, and command registration (`no_std`) |
| `kernel/src/vsh_platform.rs` | console capability and hardware/management command adapters |
| `kernel/src/legacy_shell.rs` | feature-gated diagnostic and hardware acceptance shell |
| `components/sshd/` | capability-confined SSH protocol and VSH session component (`no_std`) |
| `kernel/src/ssh_platform.rs` | thin kernel-private adapter for SSH capabilities and services |
| `services/ssh-identity/` | trusted host signing and immutable authorized-key capability services (`no_std`) |
| `acceptance/kernel-tests/src/ssh_*` | opt-in SSH security assertions, fixed test identities, and insecure Milk-V bring-up RNG |
| `services/object-store/` | capability-addressed journal, recovery, transactions, and stored-object resources (`no_std`) |
| `kernel/src/store_platform.rs` | thin block capability, CSpace publication, and heap-accounting adapter |
| `services/program-store/` | canonical saved-program artifact validation and recovered graph authorization (`no_std`) |
| `kernel/src/program_store_platform.rs` | compiler, execution, CSpace publication, and fault-recovery adapter |
| `services/authority-store/` | persistent CSpace policy, stable identities, rights, and service contract (`no_std`) |
| `kernel/src/authority_store_platform.rs` | atomic CSpace installation and exact-task recovery adapter |
| `acceptance/kernel-tests/` | guest self-test harness, SSH acceptance policy, and machine-readable benchmark scenarios (`no_std`, host-checkable) |
| `kernel/src/selftest_platform.rs`, `kernel/src/bench_platform.rs` | hardware test cases and kernel capability adapters |
| `rustc.rs` | wires the compiler to the capability system and to hardware |
| `arch/` | the seam between portable logic and the machine (riscv + host shim) |

~10,500 Rust lines across `core`, `compiler`, and `kernel` (2026-08-08 snapshot).

## Default vsh

```text
help            capability-native command summary
echo ...        write value arguments
wc              count stdin bytes, words, and lines
let NAME VALUE  set a session value
if/then/else/fi bounded conditional execution
while/do/done   loop with a fixed iteration budget
function N ...  define a scoped, value-only function
$(...)          bounded command substitution
run-script @S   run a read-only script with an exact authority manifest
jobs            list background Jobs
wait %N         join a Job
cancel %N       cancel a Job
ps              component lifecycle snapshots
caps [space]    sanitized capability summary
mem             bounded-memory accounts
quiet           mute background component output
verbose         restore background component output
reboot          cold reboot
poweroff        power off
```

The dedicated QEMU `tcp-echo` image and the production Milk-V Duo image install
a bounded Linux-style IPv4 control surface. Admitted devices are sorted by a
stable bus-topology key and exposed as the boot-local `netN` list; `ethN` is an
accepted compatibility spelling for the same index. Milk-V Duo starts in DHCP
mode. Inspect `ip link show` before selecting an interface; a single-NIC QEMU
boot normally exposes `net0`:

```text
ip link show
ip -4 addr show dev net0
ip addr replace 192.168.1.20/24 dev net0
ip route replace default via 192.168.1.1 dev net0
dhclient net0
dhclient -r net0
```

Possession of each installed vsh command capability is the authority to invoke
the operation. Images without an IPv4 stack do not install these commands.

The dedicated iperf3 images listen on TCP port `5201` and support one TCP
stream in the normal client-to-server direction or reverse mode. Build and
exercise the QEMU image with `./scripts/qemu-iperf3-test.sh`. For Milk-V Duo,
build `./scripts/build-milkv-duo.sh --iperf3-server`, boot the generated image,
wait for DHCP, inspect the address with `ip -4 addr show dev net0`, then run
`iperf3 -c ADDRESS` or `iperf3 -c ADDRESS -R` from the peer. UDP, parallel
streams, bidirectional mode, authentication, IPv6, and non-zero omit intervals
are rejected; test duration is capped at 60 seconds.

Interactive editing is shared by the default and test shells: `Up`/`Down`
browse command history, while `Left`/`Right` move the insertion cursor.
Backspace and insertion work in the middle of a line. `Tab` completes command
names from the current session's installed capabilities and defined functions;
ambiguous prefixes expand to their longest common prefix. Input is bounded to
4 KiB, and history to the newest 64 entries / 64 KiB.

Functions store syntax and value-parameter names, never resolved capability
handles. A syntactic `@name` in a function is resolved again when called.
Command substitution runs in an isolated value/function scope, removes trailing
newlines, and is capped at 64 KiB of output. Immutable script artifacts are
limited to 64 KiB and run only after every syntactic capability use exactly
matches their manifest.

## Test shell

The following diagnostic surface exists only in `legacy-shell` builds used by
the integration and benchmark harnesses:

```
ps              component identities, lifecycle, and poll counts
spaces          capability spaces in the system
caps <space>    component owner and capability table
rustc hello     compile and run a Rust hello world, natively
rustc demo      compile and run a larger sample (fib, gcd, loops)
rustc conform   compile and run the language conformance program
rustc lease     revoke during a run, then retry without new grants
selftest        run the in-kernel test suite
bench           emit the versioned machine-readable benchmark suite
durable         recover a sealed capability log and tombstone
blk info        report the supervised block backend and capacity
blk test        read, write, flush, read back, and verify the real backing disk
net info        report the supervised network backend and queue state
net test        exchange a typed raw-L2 challenge with the localhost test peer
net fault       fault after TX publication, reset/restart, then repeat the exchange
rustc edit      type your own program; end it with a lone `.`
pcspace test    exercise the three-boot persistent CSpace lifecycle
smp queues      prove queues/IPIs and report the M5 lock audit sample
probe           attempt four illegal operations, show the refusals
revoke <space>  pull a component's authority at runtime (`guest` or `prog`)
cancel <name>   cooperatively stop a component (the active shell is protected)
restart <name>  restart a terminal audited component with fresh grants
chan            telemetry channel depth and totals
quiet           mute background components (`verbose` restores)
mem             kernel heap usage
uptime          seconds since boot
echo <text>     write via init's console capability
reboot          cold reboot the machine
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
redraws the prompt with your partial input and cursor position intact. Start
typing a command, move left, let a reading land, and you can continue editing at
the same position.

`quiet` mutes the demo components; `verbose` brings them back. That is a
rendering setting, not an authority one — muting decides what reaches the
screen, whereas `revoke` decides who is allowed to speak at all. `ps` keeps
showing rising poll counts while muted, because the components never stopped.

## Known limits of v0.1

Deliberate, not overlooked:

- **Boot topology discovery is QEMU-virt-specific.** Four physical harts boot via
  SBI HSM and may use any firmware-selected coldboot hart, but the current boot
  scanner deliberately covers QEMU `virt`'s dense physical IDs `0..3`. The
  logical/physical mapping itself rejects aliases and is tested with sparse IDs;
  a general platform port still needs FDT topology enumeration.
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
- **Persistent authority is deliberately fixed-shape; there is still no user
  mode or per-process isolation.** M5.1 provides four logical ready queues
  and hart0 work stealing. M5.2 adds SBI/SSIP doorbells, atomic reason mailboxes,
  and explicit logical-to-physical hart mapping. M5.3 removes the PLIC/UART
  RX/virtio data locks, hardens fault-recoverable
  locks, and publishes their contention telemetry. M5.4 partitions scheduler
  running/wake slots, current-task and allocation provenance, interrupt markers,
  and task/program recovery state per logical hart. A validated per-hart
  `sscratch` token keeps those lookups O(1). M5.5 boots three secondaries through
  SBI HSM, gives all four harts private 256 KiB stack slots and local trap/timer
  state, routes external interrupts only through the dynamic boot-hart PLIC
  context, and runs the complete integration suite with `-smp 4`.
  M6.1 installs one shared Sv39 identity map on all four harts, with 4 KiB RAM
  leaves, non-executable device mappings, and deliberate holes for firmware,
  null, and unused physical space. M6.2 makes the first 4 KiB of every stack slot
  an invalid guard, maps the remaining 252 KiB RW-NX, and keeps 8 KiB of that
  usable stack below the generated-code floor for its normal abort path. Any access
  that lands in the guard faults, but a single-page guard does not catch a corrupted
  `sp` that jumps over it into another mapped page and is not a recovery stack: an
  already bad `sp` may fault recursively during trap entry before a diagnostic can
  run. Type/capability confinement remains the isolation boundary; this page table
  exists for integrity hardening.
  M4.3 restores
  the externally constrained `persistent-test` graph. M4.5 adds one immutable
  `hello` ProgramArtifact whose source and canonical
  VIBEEXE are revalidated against the current compiler before execution, with an
  exact console/memory manifest. This is not a general component checkpoint,
  update, naming, authentication, or rollback-resistance facility.
- **No IOMMU.** The fixed DMA slab is capability-addressed in software, but the
  checked descriptor builder remains hardware-facing TCB. An unconfirmed reset
  quarantines the slab instead of pretending revocation stopped in-flight DMA.
- **Networking remains deliberately feature-gated.** Diagnostic images expose
  only bounded raw-L2 service. Driver/stack queues carry owned `StampedPacket`
  values tied to one boot-local device epoch and stack generation. One
  independent `net-stack` component can fairly drive the runtime-discovered
  list of explicitly capability-backed `netN` interfaces; each owns separate packet endpoints,
  smoltcp state, ARP, IPv4 address, route, DHCPv4 client, session generation,
  and listener set. Revocation or quarantine retires only the affected
  interface. Bounded `TcpListener` capability frontends give each service
  exclusive authority over its own port and generation-bound connections; SSH
  no longer owns the IPv4 stack. The QEMU policy still wires one VirtIO NIC.
  The Milk-V policy sorts DWMAC and any detected USB CDC-ECM function by stable
  MMIO/USB topology and then assigns boot-local `netN` names. They have distinct
  packet endpoints, controls, DHCP clients, and restart supervision; the
  service listener remains deliberately attached to the DWMAC capability root,
  independent of its assigned ordinal. Any further
  multi-NIC policy must grant one distinct endpoint/control/listener bundle per
  admitted device; parsing `net1` never creates hardware authority.
  The shared core supports eight listeners per interface and has a two-port
  isolation test. It
  still provides no DNS resolver, IPv6, general UDP API, or POSIX socket
  namespace. `qemu-tcp-test.sh recovery` defines a test-only N2 gate for
  stack and virtio-driver restart coordinates. Its synthetic stale-packet hooks
  are absent from normal images and do not model delayed DMA completion or a
  late IRQ. The native DWMAC DHCP/IP path has passed carrier, lease acquisition,
  and eight fresh exact-echo TCP streams on a live board. Simultaneous DWMAC +
  CDC-ECM physical acceptance, restart coordinates, delayed completion, late
  IRQ, and long-duration stress remain open.
- **SSH acceptance fixtures remain separate from production provisioning.** A
  bounded, fail-closed virtio-rng capability now feeds a domain-separated,
  zeroizing ChaCha20 DRBG; tracked fault reclamation scrubs complete allocator
  blocks before reuse. An opaque Ed25519 signer and immutable binary-key policy
  are exercised by the explicit `ssh-security-test`, `ssh-test`, and
  `milkv-ssh-acceptance` images. The SSH images permit a restricted exec profile
  and one PTY-backed interactive VSH session while rejecting unsupported request
  combinations and subsystems. The acceptance images visibly embed fixed
  fixtures and the Milk-V bring-up image uses deterministic reboot-repeating
  bytes. The production Milk-V image links neither fixture: OSR=3
  jitterentropy-rs seeds its DRBG and creates a persistent per-device host key
  on first boot. SSH then exposes a restricted `vibe`/`vibeos` onboarding
  login; a verified `ssh-authorize` commit permanently switches the device to
  public-key-only authentication and disconnects that session. Device-side
  `ssh-keygen` creates a separate, unregistered client key pair. This is a
  project deployment decision, not
  NIST/CMVP certification; microSD confidentiality, authenticated policy
  updates, and rollback resistance remain open.
