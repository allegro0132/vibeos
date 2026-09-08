# CoreMark on VibeOS WASI and Debian RISC-V

The measurements below record the original implementation. Subsequent
[performance investigation and fixes](WASI_PERFORMANCE.md) improve the WASI
median from 26.393402 to 105.579898 iterations/s using the same configuration.

The unmodified [official CoreMark](https://github.com/eembc/coremark) sources and
POSIX port execute as a raw WASI Preview 1 module. QEMU realtime and monotonic
clocks are now available. Timed measurements require the explicit
`wasi-benchmark` firmware image; normal WASI limits remain unchanged.

## Reproduce

Prerequisites: the repository Rust nightly, wasi-sdk 33 (Clang 22.1.0), Python 3,
OpenSSH, QEMU system RISC-V, qemu-img and 7z. All compiler flags apply to all six
translation units. The upstream commit is pinned to
`1f483d5b8316753a742cbf5590caf5bd0a4e4777`; neither algorithms nor POSIX timing
code nor the compiled module is rewritten.

```sh
export WASI_SDK_PATH=/path/to/wasi-sdk-33.0-arm64-macos
scripts/build-coremark-wasi.sh
mkdir -p target/coremark-benchmark
"$WASI_SDK_PATH/bin/clang" --target=wasm32-wasip1 -O2 -msign-ext -mbulk-memory \
  tests/wasi/clock.c -Wl,--max-memory=16777216 -Wl,--strip-all \
  -o target/coremark-benchmark/clock.wasm
scripts/benchmark-coremark-wasi.py

# Run the two virtual machines sequentially, with no other CPU-heavy work.
scripts/prepare-coremark-debian.sh
scripts/benchmark-coremark-debian.py
scripts/compare-coremark.py
```

The Debian preparation script downloads the official nocloud RISC-V image
`20260831-2587` and checks its pinned SHA-512, then extracts the original kernel and
initrd using 7z. The baseline boots that full Debian OS via OpenSBI,
installs GCC and libc development headers inside the guest, and compiles/runs
native RISC-V CoreMark there. This is not host execution through qemu-user.
Package versions are saved because Debian's package repositories can change.
The base image is preserved; a separate qcow2 overlay contains installation work.
Only dedicated inputs and result directories are exposed through 9p; source
inputs are read-only. The image ships with a locked root account. The runner selects systemd's
local serial debug shell and masks the conflicting serial getty; it exposes
no network login port. `systemd.firstboot=off` skips the installation wizard.
Measurements wait for ordinary systemd boot completion.

Each runner calibrates with a fixed short run, selects approximately 20 seconds
of work, then records three performance runs (`0,0,0x66`) and one validation run
(`0x3415,0x3415,0x66`). Every measured run must last at least 10 seconds and print
`Correct operation validated`; status 0 alone is insufficient. Calibration is
not counted as a score. Median and range should be reported instead of selecting
the fastest sample. These are locally validated measurements, not an EEMBC
certification or a submission to its published results database.

## Clock and execution contracts

`clock_time_get` and `clock_res_get` return nanoseconds. QEMU realtime uses the
Goldfish RTC's latched low/high register pair under a lock; monotonic time uses
`rdtime` and the BSP's 10 MHz timebase. CPU clocks return `NOSYS`. All timestamp
pointers are checked before consulting a clock. Standalone runtime embeddings
must explicitly supply clocks; defaults remain unsupported.

`WASI_BENCHMARK=1 scripts/run-wasi-qemu.sh` selects the benchmark feature and
omits `icount`. QEMU uses `-rtc base=utc,clock=vm`. Instruction-derived virtual
time from the ordinary deterministic acceptance launch must not be presented as
wall-time throughput. Both benchmark VMs use `virt`, `rv64`, 1 hart, 1 GiB RAM
and `-accel tcg,thread=single`. CoreMark is single-threaded. VibeOS's BSP and
linker still use only the first 128 MiB RAM (about 114 MiB heap), with a 32 MiB
guest allocation quota; Debian manages its full RAM allocation.

The benchmark image raises total fuel from 10 million to 10 billion. Every
10,000 fuel still yields to the scheduler. One WASI instance, 16 MiB guest linear
memory, 32 MiB allocations, 64 KiB combined output, authorization/revocation,
SSH disconnect and cancellation remain enforced. The 120-second SSH request
timeout also remains. The command arguments cannot increase the budget.

The comparison is **Debian native execution versus the VibeOS Wasmi software
float interpreter** inside the same QEMU configuration. It includes compiler,
libc, interpreter, scheduler and OS background-work differences; it does not
isolate OS overhead or measure physical RISC-V hardware performance. Keep the
host otherwise idle and retain spread between repetitions.

## Evidence

VibeOS outputs, statuses, clock probe and clean lifecycle logs are under
`target/coremark-benchmark/vibeos-single/`. Debian's serial boot transcript,
exact QEMU command, guest package/compiler information, executable checksum and
outputs are under `target/coremark-benchmark/debian/`. Large images and generated
evidence are intentionally excluded from Git.

The linked WASI module is 38,214 bytes, SHA-256
`c5f77f7fd38fc3e87e7f9ccbd761327beee01de2adc9f24736ed4c94fe3dcc9a`.
Its prior short-run CRC results also matched Wasmtime 48.0.0. The upstream
`coremark.md5` header entry is stale at the pinned commit; source cleanliness is
checked against Git, and exact source hashes are retained instead of modifying
the header to satisfy that manifest.

Diagnostic four-hart VibeOS set (2026-09-08, QEMU 11.0.3, macOS arm64); excluded from the final single-hart comparison:

| Run | Iterations | Seconds | Iterations/second |
| --- | ---: | ---: | ---: |
| Performance 1 | 270 | 18.640 | 14.484979 |
| Performance 2 | 270 | 23.251 | 11.612404 |
| Performance 3 | 270 | 26.089 | 10.349189 |
| Validation | 270 | 24.536 | 11.004239 |

Performance median: **11.612404**; range: **10.349189–14.484979**. The spread is
material, so a single sample should not be treated as a stable machine rating.

## Final single-hart comparison (2026-09-08)

Both measured sets passed all CRC checks and the >= 10 second run rule.
Debian completed a clean systemd shutdown; both runners exited with status 0.

| Environment | Performance samples (iterations/s) | Median | Range |
| --- | --- | ---: | --- |
| VibeOS WASI / Wasmi | 26.393402, 26.368358, 26.459534 | 26.393402 | 26.368358–26.459534 |
| Debian 13.6 native / GCC 14.2.0 | 9534.584779, 9489.085186, 9523.896871 | 9523.896871 | 9489.085186–9534.584779 |

The native median is **360.84×** the interpreter median;
VibeOS WASI reaches **0.277%** of this native baseline.
This ratio describes the complete execution stacks, not isolated OS overhead.

| Environment / sample | Iterations | Seconds |
| --- | ---: | ---: |
| VibeOS performance-1 | 528 | 20.005 |
| VibeOS performance-2 | 528 | 20.024 |
| VibeOS performance-3 | 528 | 19.955 |
| VibeOS validation | 528 | 19.959 |
| Debian performance-1 | 186916 | 19.604 |
| Debian performance-2 | 186916 | 19.698 |
| Debian performance-3 | 186916 | 19.626 |
| Debian validation | 186916 | 19.668 |

The Debian kernel is `6.12.107+deb13-riscv64`, libc is `2.41-12+deb13u3`.
The VibeOS module uses wasi-sdk 33 / Clang 22.1.0 and the repository software
float Wasmi engine. QEMU is 11.0.3 on macOS arm64. Both run the same pinned
CoreMark algorithm sources with `-O3`, using their respective standard libraries.

The host test suite passed 17 tests (12 runtime, 4 command service, 1 BSP);
one standalone stdlib fixture test remains opt-in. Both ordinary and benchmark
firmware built successfully. The target clock probe, all six final WASI
invocations, and clean capability/I/O/domain reclamation passed.

Machine-readable results: `target/coremark-benchmark/comparison.json`;
source/toolchain/kernel/module provenance: `target/coremark-benchmark/manifest.json`.
