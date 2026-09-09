# Raw WASI Preview 1 commands

`wasi-preview1-command-v1` is an independent, opt-in Core WebAssembly command
entry point. It supplements the Component-first roadmap; it does not change
Component formats, admitted profile codes, sealed historical fixtures, or their
compatibility guarantees. The guest receives only its invocation's three standard
streams. The file-loading capability is never installed in the guest CSpace.

## Build and run

Use the repository's `nightly-2026-08-01`, wasi-sdk **33** (Clang
`22.1.0-wasi-sdk`), and the vendored software-float Wasmi from `Cargo.lock`.
Install `wasm32-wasip1` and the SDK for your host, then:

```sh
rustup target add --toolchain nightly-2026-08-01 wasm32-wasip1
export WASI_SDK_PATH=/path/to/wasi-sdk-33.0-arm64-macos
./scripts/build-wasi-examples.sh
./scripts/run-wasi-qemu.sh
```

The sample builder rebuilds Rust `std` with `-Z build-std=std,panic_abort`, using
the same Wasm MVP CPU and explicitly enabled target features as the application.
C uses the SDK's WASI libc. Both set a 16 MiB memory maximum and a 64 KiB stack.
Compiler outputs are executed directly: no section stripping after linking,
import rewriting, or replacement of standard-library calls with test shims.

In another terminal:

```sh
./scripts/wasi-client.py upload target/wasi-examples/rust-hello.wasm
./scripts/wasi-client.py run rust-hello.wasm
./scripts/wasi-client.py run rust-hello.wasm args 'a b' 中文
printf 'hello\n' | ./scripts/wasi-client.py run rust-hello.wasm filter
./scripts/wasi-client.py run rust-hello.wasm stderr
./scripts/wasi-client.py run rust-hello.wasm exit  # exit 7
```

On the QEMU UART console:

```text
wasm-run @home/wasm/rust-hello.wasm args "a b"
echo hello | wasm-run @home/wasm/rust-hello.wasm filter
```

No local stdin connection means immediate EOF. Interactive terminal input is not
provided. The host script connects to localhost port 22222 by default, verifies
the pinned host key, and uses the existing public QEMU acceptance identity.
`WASI_SSH_PORT` and `WASI_WORK_DIR` customize the launch script; matching client
options are `--port`, `--identity`, and `--known-hosts`. The launch script retains
`disk.raw`; stopping and restarting it preserves uploaded files. Runtime instances
are never persisted or automatically launched. `WASI_SKIP_BUILD=1` explicitly
reuses an already built firmware binary.

The dedicated image enables `wasi-ssh-upload`, which includes `wasi-ssh`,
`wasi-preview1`, file trees, and the existing SSH test/network features. The
`wasi-ssh` image permits execution but not upload. Ordinary SSH images receive
neither permission. This launch configuration uses public test identities and
binds the forwarded SSH listener only to localhost; it is a development fixture,
not production identity provisioning. No Milk-V Duo qualification is claimed.

## Command protocol and authority

Authenticated SSH `exec` accepts two typed, value-only requests:

```text
wasm-upload NAME BYTE_LENGTH SHA256
wasm-run NAME [arguments...]
```

The upload body is raw SSH stdin and must end with EOF. A name is at most 128
ASCII bytes, starts with an alphanumeric character, contains only alphanumerics,
`.`, `_`, and `-`, and ends in `.wasm`. Paths, symlinks and shell expansions are
not accepted. Arguments support quoting and backslash escaping; they are never
reinterpreted as shell syntax. SSH's command-string limit is 4096 bytes, within
the runtime's larger argument limit.

Upload streams through the existing content stager, checks exact byte length and
lowercase SHA-256, then publishes one file transaction under `@home/wasm/NAME`.
Failed or interrupted transfers leave the old file intact. Cancellation is
rechecked after backend waits, before the atomic root-publication operation;
once that operation begins, it completes atomically even if the peer disconnects. Temporary unreferenced
content uses the store's existing reclamation rules. Successful upload does not
validate executable content or grant execution. Every execution obtains a regular
file reader from one namespace snapshot and validates the complete pinned bytes.
Concurrent file replacement cannot change those bytes. Local and remote clients
share the live home file-tree authority and its transaction claim.

Local command admission requires both the command's `INVOKE` capability and
`READ` on its file-tree operand. The SSH platform hook separately authorizes the
typed upload/run request for the authenticated profile; default platform hooks
deny it. An admitted SSH request receives a separate loader CSpace with the
corresponding service `INVOKE` capability and a file-root capability (`READ` for
execution, `READ|WRITE` for upload). These loader capabilities stay outside the guest. Network/authentication authority is rechecked while pumping data. Loss
of authority or connection cancels the invocation. A fresh guest CSpace contains
only the three stream endpoints. An independent supervisor joins and reclaims the
guest before releasing the single-instance slot. It checks source/command
authority every 10 ms while the guest is blocked on I/O; ordinary guest quanta
also revalidate it. The first cancellation reason survives subsequent teardown
revocations.

## Compatibility and limits

A module must export `memory` and `_start: () -> ()`. `_start` is explicitly
called after instantiation; a Core start section is rejected except for the
complete native WASI threads contract described below. Only function
imports from `wasi_snapshot_preview1` with exact Preview 1 signatures are allowed.
Component binaries and host memory/table/global imports are rejected.

Enabled features: Wasm32, one memory and at most one table, scalar integers and
software float, mutable globals, sign extension, saturating float conversion,
multi-value, bulk memory and reference types. SIMD, GC, exceptions, memory64,
multiple memories, tail calls and extended constants are excluded. Threads are
excluded on the interpreter image and admitted only by the `wasmtime-threads`
native image described below.
Omitted memory/table maxima are supported; the host limiter remains authoritative.

| Interface | Behavior |
| --- | --- |
| `args_sizes_get`, `args_get` | UTF-8 program name and arguments, NUL terminated |
| `environ_sizes_get`, `environ_get` | Empty environment |
| `fd_read`, `fd_write` | fd 0 stdin, fd 1 stdout, fd 2 stderr; EOF and short transfers |
| `fd_fdstat_get`, `fd_filestat_get`, `fd_close` | Standard-stream metadata and invocation-local close |
| `fd_seek`, `fd_tell` | `SPIPE` for open standard streams |
| `fd_prestat_get`, `fd_prestat_dir_name` | `BADF`; no preopened directories |
| `proc_exit` | Non-returning, preserves the full `u32` status |
| `clock_time_get`, `clock_res_get` | Explicit embedding clocks; QEMU supplies realtime (Goldfish RTC) and monotonic (RISC-V timebase), in nanoseconds |
| Other known Preview 1 imports | Linked with exact signatures; return `NOSYS` |
| Unknown imports or incorrect signatures | Rejected before execution |

All iovecs and result addresses are validated before consuming input or writing
output. Streams use bounded 8 × 1024-byte queues; guest I/O waits register executor
wakers. The interpreter yields on host calls and fuel quanta.

| Resource | Default maximum |
| --- | --- |
| Module | 512 KiB |
| Linear memory | 16 MiB |
| Guest allocation owner | 32 MiB |
| Arguments, including program name | 128, 16 KiB including NULs |
| Combined stdout and stderr | 64 KiB |
| Fuel / interpreter quantum | 10,000,000 / 10,000 |
| Concurrent WASI instances | 1; additional requests return 75 (busy) |
| Iovecs per call | 1024 |
| Table elements / call depth | 4096 / 128 |

Other structural limits derive from `PROFILE_1_LIMITS`. The standalone runtime
requires its embedding caller to supply the allocation domain; the kernel creates
and supervises that domain. Runtime terminals distinguish exit, trap, cancellation,
permission denial and resource exhaustion. SSH maps non-exit terminals to 125,
130, 126 and 124 respectively, and transmits guest exit values as `u32`. OpenSSH's
own process exit status may truncate that value. Vsh preserves 1–255, maps larger
nonzero guest values to status 1, and retains the original in `TerminalDetail::WasiExit`.

There is no guest filesystem, networking, random source, or promise of the
complete WASI standard world. Standard libraries may import such functions
successfully but receive `NOSYS` if they use them.

## wasi-threads (native backend)

The `wasmtime-threads` firmware feature (which implies `wasmtime-command`)
admits the [wasi-threads](https://github.com/WebAssembly/wasi-threads) contract
as produced by wasi-sdk `--target=wasm32-wasi-threads -pthread` with
`-Wl,--import-memory -Wl,--export-memory`: an imported shared, bounded `env.memory`, the
`wasi::thread-spawn: (i32) -> i32` import, the exported `wasi_thread_start`
entry, and the threads proposal's atomics, `memory.atomic.wait32/64` and
`memory.atomic.notify`. A module that uses any half of the contract without the
other is rejected before compilation; a defined (non-imported) shared memory is
rejected; the interpreter image rejects all of it with the existing `Import`
terminal.

For this complete contract, a Core start section is allowed: LLD uses it to
initialize shared passive data and pthread TLS. It runs during asynchronous
instantiation under the same fuel, memory, and allocation limits as guest
execution. Non-threaded commands still reject Core start sections.

| Aspect | Behavior |
| --- | --- |
| Threads | At most 3 spawned threads per command (main plus three, one native fiber stack each); `thread-spawn` beyond that returns `-EAGAIN` (`-6`) |
| Placement | Each thread is a kernel task pinned round-robin to an online hart; threads run in parallel on a multi-hart machine |
| Shared memory | One fixed guest virtual reservation; growth appends zeroed pages and never relocates; failure returns `-1` to the guest instead of terminating |
| Waits | `memory.atomic.wait*` suspends the thread's fiber through the executor; timeouts are rounded up to whole milliseconds |
| Process semantics | `proc_exit` or a trap in any thread ends the command with that status; `_start` returning ends every thread; cancellation, revocation and fuel/output limits apply to the whole command |
| Budgets | Each thread's store carries the invocation fuel budget; the command is limited to four budgets in total; stdout/stderr share one 64 KiB budget |
| Faults | A fault in any thread tears down the whole arena after siblings mid-poll on other harts have detached; no destructor runs |

`fd_read`/`fd_write` from several threads interleave at the granularity of one
host call. There is still no `sched_yield` beyond the Preview 1 stub, no
thread-local descriptor state, and no thread join primitive other than the
guest's own atomics.

Clock IDs 2/3 (CPU time) return `NOSYS`; invalid IDs return `INVAL`. The complete
8-byte result range is checked before consulting the embedding, including
unaligned results. Clock providers are optional and default to `NOSYS` in the
standalone runtime. The QEMU execution service grants clock reads along with
stdio; revocation still terminates the invocation. Milk-V has monotonic time
only, with no fabricated Unix epoch. Precision is an allowed error hint; these
providers return the current counter without intentional coarsening.

The explicit `wasi-benchmark` firmware feature raises total fuel to 10 billion;
the ordinary image remains at 10 million and both yield every 10,000 fuel.
All other memory, output, authorization, cancellation and concurrency limits
are unchanged. Run `WASI_BENCHMARK=1 scripts/run-wasi-qemu.sh` for the benchmark
image and real-time QEMU clock configuration (no `icount`). See
[CoreMark](COREMARK_WASI.md) for benchmark methodology and reproduction.

## Repeatable acceptance

```sh
cargo test --locked --offline -p vibeos-wasi-runtime -p vibeos-wasi-command
WASI_EXAMPLE="$PWD/target/wasi-examples/rust-hello.wasm" \
  cargo test --locked --offline -p vibeos-wasi-runtime genuine_standard_library -- --ignored
WASI_EXAMPLE="$PWD/target/wasi-examples/c-hello.wasm" \
  cargo test --locked --offline -p vibeos-wasi-runtime genuine_standard_library -- --ignored
./scripts/test-wasi-oracle.py --wasmtime /path/to/wasmtime-48.0.0
(cd firmware/qemu-virt && cargo build --locked --offline --release --features wasi-ssh-upload)
./scripts/test-wasi-qemu.py --work target/wasi-acceptance-fresh
# wasi-threads on the native backend (4 harts):
(cd firmware/qemu-virt && cargo build --locked --offline --release --target riscv64gc-unknown-none-elf \
   --features wasi-ssh-upload,wasmtime-command-fuel-batch,wasmtime-threads)
./scripts/test-wasi-qemu.py --work target/wasi-acceptance-threads --wasmtime --fuel-batch --threads
# Thread lifecycle regressions that need no wasi-sdk on the host: interleaved
# fixture/fault/CoreMark runs on the image above, and client disconnects
# during long pthread CoreMark runs on the benchmark image.
cargo run --locked --offline -p vibeos-wasi-runtime --example fixtures -- target/wasi-fixtures
./scripts/test-wasi-threads-fixtures.py target/riscv64gc-unknown-none-elf/release/vibeos-qemu-virt \
   target/wasi-threads-fixtures target/wasi-fixtures target/wasi-examples/c-threads.wasm \
   target/coremark-wasi/coremark-threads.wasm
./scripts/test-wasi-threads-disconnect.py BENCHMARK_KERNEL target/wasi-threads-disconnect 3
```

Use a fresh acceptance work directory. The QEMU harness uses real OpenSSH clients,
keeps boot logs and the disk, tests both standard libraries, quoted arguments,
binary input, stderr, status 7, upload failures, malformed/import/pointer/fuel/
memory/output containment, disconnect recovery, local pipelines, compilation after
boot, 100 sequential invocations, and restart persistence. It writes `results.json`
only on success. Wasmtime 48.0.0 is an independent host output/status oracle.

Primary ABI references: [Rust wasm32-wasip1 target](https://doc.rust-lang.org/stable/rustc/platform-support/wasm32-wasip1.html),
[Preview 1 WITX](https://github.com/WebAssembly/WASI/blob/wasi-0.1/preview1/witx/wasi_snapshot_preview1.witx).
