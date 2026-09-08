# Debian RISC-V engine controls

This isolated workspace builds two Linux runners. `wasmi` includes the repository's
host example and uses the exact vendored software-float Wasmi and WASI runtime.
Build it without the `compiled` feature so Wasmtime cannot unify extra dependency
features into its graph. Its release profile matches the root workspace: size optimization and LTO, with
Wasmi itself at opt-level 3. `extra-checks` and eager validation remain enabled;
instruction profiling and the experimental RV64 cache are disabled. The trusted
CoreMark budget is 100,000,000,000 fuel, granted in 10,000-fuel polls.

`wasmtime` pins Wasmtime and official WASI Preview 1 to 48.0.0 and explicitly
selects Cranelift `speed`. It compiles each process's module before `_start`;
compilation/instantiation time and execution time are reported separately.
`--fuel` enables its own 100,000,000,000-fuel counter. Wasmtime fuel units differ
from Wasmi, and synchronous Wasmtime does not reproduce Wasmi's resumable
10,000-fuel polling. Measure both fuel modes; do not present them as identical
metering. Neither runner inherits directories or environment. Both cap linear
memory at 16 MiB. Linux allocation, scheduling, stack checks and signal-based
traps differ from VibeOS; the Linux runner has no VibeOS allocation-domain or
capability checks. CoreMark's timed workload is integer, though Wasmtime uses
hardware floating point where requested by the module.

Install the pinned nightly Linux target with `rustup target add riscv64gc-unknown-linux-gnu`
and fetch locked dependencies once before offline builds. Prepare a Debian directory using `scripts/prepare-coremark-debian.sh`. For a new
output directory pass that directory to `--image-work` in the commands below.
An independent qcow2 overlay may use the already prepared native-baseline disk
as its backing file while that baseline VM is stopped.

```sh
python3 scripts/benchmark-coremark-debian.py \
  --image-work target/coremark-benchmark/debian --work target/debian-engines \
  --guest-script scripts/coremark/prepare-debian.sh
mkdir -p target/debian-engines/results/sysroot
tar -xf target/debian-engines/results/sysroot.tar -C target/debian-engines/results/sysroot
ln -s usr/lib target/debian-engines/results/sysroot/lib
ln -s riscv64-linux-gnu/ld-linux-riscv64-lp64d.so.1 target/debian-engines/results/sysroot/usr/lib/ld-linux-riscv64-lp64d.so.1
export COREMARK_SYSROOT="$PWD/target/debian-engines/results/sysroot"
export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER="$PWD/scripts/coremark/riscv64-linux-cc.sh"
export CC_riscv64gc_unknown_linux_gnu="$CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER"
export AR_riscv64gc_unknown_linux_gnu=llvm-ar
cargo build --locked --offline --release --target riscv64gc-unknown-linux-gnu \
  --manifest-path tools/coremark-engines/Cargo.toml --bin wasmi
cargo build --locked --offline --release --target riscv64gc-unknown-linux-gnu \
  --manifest-path tools/coremark-engines/Cargo.toml --features compiled --bin wasmtime
cp tools/coremark-engines/target/riscv64gc-unknown-linux-gnu/release/{wasmi,wasmtime} target/debian-engines/inputs/
cp target/coremark-wasi/coremark.wasm target/debian-engines/inputs/
python3 scripts/benchmark-coremark-debian.py \
  --image-work target/coremark-benchmark/debian --work target/debian-engines \
  --guest-script scripts/coremark/measure-debian-engines.sh
```

The guest records a fresh GCC native baseline plus both engines, interleaves
three performance samples, and validates a second seed set. Each measured sample
must pass upstream CRC checks and run at least ten seconds. Calibration aims at
25 seconds. `/usr/bin/time -v` also records whole-process elapsed time and RSS.
No host build or other QEMU workload should overlap measured samples. Retain
module/runner/source hashes, lockfiles, commands and raw output with the result.
