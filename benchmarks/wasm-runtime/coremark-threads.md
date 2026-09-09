# CoreMark pthread scaling on RV64

`scripts/benchmark-coremark-threads.py` runs the same unmodified upstream
CoreMark POSIX pthread module on the VibeOS native command service and the
standard Linux Wasmtime runtime. It uses real QEMU virtual-clock progression,
`virt`, `rv64`, 1 GiB RAM and `tcg,thread=multi`, without `icount`.
The official Wasmtime 48 CLI removed `-S threads`; its unpatched constant-copy
lowering also panics on RV64 without V. Those are separate failed compatibility
controls, not benchmark scores. The Linux control instead uses
`tools/coremark-engines/src/bin/wasmtime-threads.rs`: standard Wasmtime 48,
official Preview 1, Linux OS threads and one Store per worker, with the same
vendored RISC-V compiler correctness fixes as VibeOS (fs1 ABI and scalar inline
copy). Linux uses the scalar RV64GC compiler target and retains its normal
virtual memory and signal traps. Current VibeOS command images also enable
zba/zbb/zbc/zbs when advertised on every hart; this compiler-policy difference
must accompany the comparison even though the QEMU CPU model is identical.
The default matrix keeps four harts online and varies the workload through
CoreMark's `M1`, `M2`, and `M3` arguments. These count **workers**; a separate
main thread waits for their completion. VibeOS has four native fiber slots,
so three workers exhaust the currently supported capacity.

## Reproduce

Use an otherwise idle host. Run compilation and the two VMs sequentially;
do not measure while another build or QEMU instance is consuming CPU.

```sh
WASI_SDK_PATH=/path/to/wasi-sdk-33.0-arm64-macos COREMARK_THREADS=1 \
  sh scripts/build-coremark-wasi.sh

# Use the repository's pinned Rust toolchain, not a system Homebrew rustc.
rustup run nightly-2026-08-01 cargo build --locked --offline --release \
  -p vibeos-firmware-qemu-virt --target riscv64gc-unknown-none-elf \
  --features wasi-benchmark,wasmtime-command-fuel-batch,wasmtime-threads

python3 scripts/benchmark-coremark-threads.py vibeos --fuel-batch \
  --work target/coremark-threads/vibeos-4h \
  --kernel target/riscv64gc-unknown-none-elf/release/vibeos-qemu-virt

python3 scripts/benchmark-coremark-threads.py debian \
  --work target/coremark-threads/debian-4h \
  --debian-image /path/to/debian-nocloud-riscv64.qcow2 \
  --debian-kernel /path/to/extracted/boot/vmlinux \
  --debian-initrd /path/to/extracted/boot/initrd.img \
  --wasmtime tools/coremark-engines/target/riscv64gc-unknown-linux-gnu/release/wasmtime-threads
```

Build the Linux runner with the exported Debian sysroot, linker variables and
toolchain described in `tools/coremark-engines/README.md`, using
`--features compiled-threads --bin wasmtime-threads`. The benchmark script's
`--prepare-sysroot` mode can prepare an independent Debian overlay and export
`sysroot.tar`; this preparation requires network access and is not a measurement.

The Debian runner verifies paths and records their hashes; verify the base image
against Debian's published checksum before running it. It creates a fresh qcow2
overlay and leaves the original image untouched. No guest network is required.
The existing `scripts/prepare-coremark-debian.sh` prepares a pinned Debian image
and extracts a matching kernel/initrd (on macOS use `7zz` if `7z` is absent).

Repeat the Debian command with a fresh `--work` and `--debian-fuel` for the
metered Linux control. `--harts 1` is a useful serial hardware control with the
same worker counts. Each work directory is an evidence set and must be fresh.

For the native Linux pthread baseline, use the same Debian image/kernel/initrd
arguments with `--native-debian` and omit `--wasmtime`. The image must already
contain GCC and libc development headers. The driver verifies the pinned, clean
upstream CoreMark checkout, snapshots it, and builds it inside Debian with
`-O3 -pthread -DMULTITHREAD=4 -DUSE_PTHREAD=1 -DITERATIONS=1`. It runs the same
M1/M2/M3 matrix, calibration and validation as the Wasm controls. Compiler
version, source hashes, build command and the native ELF are retained. This row
compares native C to Wasm; its recorded module hash identifies the associated
Wasm comparison workload, not the executable used for the native measurement.

## Interpretation and gates

Calibration uses 1,000 iterations per worker and targets 20 seconds by default.
Three performance samples interleave worker counts; a fourth sample uses the
upstream validation seeds. Every measured sample must last at least ten seconds,
print the CRC fields for every worker, pass upstream validation, and exit zero.
The score is aggregate iterations/second, not the per-worker rate. Speedup is
the median aggregate score divided by the same platform's M1 median.

VibeOS additionally requires the expected spawned-thread count, distinct hart
count and `reclaimed=true caps=0 waiters=0` for every invocation. Compiler setup
and SSH transfer are outside CoreMark's internal timed region. Thread creation,
joins and scheduling during CoreMark are inside it.

The optional `--thread-fixture` accepts the compiled `tests/wasi/threads.c`
program and checks `spawnmany` before measurement. It requires exactly three
successful spawns and `EAGAIN`; any failed cleanup aborts the run. Keep this
capacity stress result separate from successful CoreMark results.

`--fuel-batch` records the bounded in-fiber fuel policy and requires every
invocation's per-thread `thread fuel checks=… continued=…` evidence: workers
continued on their fibers at most boundaries instead of switching to the
executor. Without the feature the image measured ~1,450 M1 iterations/s here;
see [WASI_PERFORMANCE.md](../../docs/WASI_PERFORMANCE.md) for the retained
comparison. Command images also generate zba/zbb/zbc/zbs code when the
firmware advertises them on every hart.

`--icount-iterations N --harts 1` is a deterministic diagnostic: fixed work per
worker under `-icount shift=0` and single-thread TCG, reported as virtual
seconds and labelled `formal: false`. Two runs of one image agree to the
instruction, so it isolates code-path changes from host noise; it is not a
throughput score and the multi-hart round-robin variant is not deterministic.

The default Debian runner has no fuel counter. `--debian-fuel` enables 100 billion
fuel per store, but does not reproduce VibeOS's 10,000-fuel asynchronous yields,
allocation domains, capability checks, bounded fibers, or scheduler. The Linux
runner and the vendored VibeOS runtime are both Wasmtime 48, but have different
platform implementations and code generation policies. Report both absolute
throughput and within-platform scaling; QEMU TCG numbers are not physical
RISC-V hardware performance or certified CoreMark ratings.

Raw stdout/stderr, command lines, module/kernel/image hashes, calibration,
per-sample JSON and VibeOS thread/cleanup logs remain under `--work`.
`summary.json` contains median throughput and scaling. Failed runs retain their
logs and must not be included as valid performance samples.

Verify the retained stdout against the JSON (including per-worker CRC values,
cleanup and identical Wasm/QEMU configuration) and combine successful runs with:

```sh
python3 scripts/summarize-coremark-threads.py \
  target/coremark-threads/vibeos-4h target/coremark-threads/debian-4h \
  target/coremark-threads/debian-fuel-4h \
  --output target/coremark-threads/comparison.json
```
