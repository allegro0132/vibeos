# Milk-V Duo CoreMark / Wasmtime — 2026-09-10

Physical CV1800B/C906, one application hart, VibeOS Wasmtime 48 backend.
Three performance samples per worker count; one separate validation-seed run.
Workers share one hart; a separate main thread waits for them.

| Workers | Sample 1 | Sample 2 | Sample 3 | Median iterations/s | Relative to M1 |
|---|---:|---:|---:|---:|---:|
| 1 | 574.612 | 572.091 | 574.324 | 574.324 | 1.000× |
| 2 | 214.362 | 218.086 | 217.320 | 217.320 | 0.378× |
| 3 | 217.083 | 216.107 | 216.975 | 216.975 | 0.378× |

All twelve scored/validation invocations lasted 19.914–20.498 seconds, passed
upstream CRC validation and exited zero. All fifteen invocations including
calibration reported `reclaimed=true caps=0 waiters=0`; spawned worker counts
matched M1/M2/M3 and every hart mask was `0x1`. Calibration is excluded from
medians. These checks do not imply EEMBC certification.

## Configuration and timer adaptation

- SDK 33, Clang 22.1.0, upstream CoreMark commit
  `1f483d5b8316753a742cbf5590caf5bd0a4e4777` (unchanged sources).
- `-O3 -pthread -msign-ext -mbulk-memory -DMULTITHREAD=4 -DUSE_PTHREAD=1 -DITERATIONS=1`.
- Explicit linker timer adapter maps the POSIX port's realtime request to
  WASI monotonic time; errors terminate the program. Duo has no realtime epoch.
  The original module printed zero elapsed time and is retained as failed
  calibration in `target/duo-coremark-measurement`; it produced no valid score.
- Timed module SHA-256:
  `43813bca9d5039a4962dfdeda4f5ba317ae4066df3cf74fbba6c36a6d48caeb4`.
- Benchmark image SHA-256:
  `2993d3f0d06aa84a84731f7e66174f90d2b455150ec5b0d0a383fb9727be8a7e`.
- 100 billion fuel per Store; 10,000 fuel quantum; maximum continuation batch
  32; normal authority/cancellation checks. Production SSH keys, no test identity.
- Hardware timebase 25 MHz. JIT compilation and SSH upload are outside the
  upstream timed region. Default logger/heartbeat workloads remained enabled.
- No physical Linux baseline was measured in this session. Previous QEMU
  Debian numbers use different hardware and module timing adaptation and must
  not be treated as a physical Duo comparison.

## Performance observation

M2/M3 deliver about 38% of M1 aggregate throughput. UART counters show frequent
continuation in M1, but almost none with competing workers. The scheduler's
`ContinuationProbe` rejects continuation when other work is ready, so threads
return through the scheduler at fuel boundaries. This is evidence pointing to
single-hart scheduling/fiber-switch overhead, not an isolated causal benchmark;
no optimization was applied during measurement.

## Evidence and reproduction

[Raw outputs, UART, metadata, hashes and results](results/duo-coremark-2026-09-10/).
See `analysis.json` for per-run fuel counters. Build the `--wasmtime-benchmark`
image and provision SSH as described in `docs/MILKV_DUO.md`, then:

```sh
COREMARK_THREADS=1 COREMARK_MONOTONIC=1 \
  WASI_SDK_PATH=target/toolchains/wasi-sdk-33.0-arm64-macos \
  sh scripts/build-coremark-wasi.sh
python3 scripts/benchmark-coremark-duo.py \
  --known-hosts target/duo-coremark-access/known_hosts \
  --work target/duo-coremark-next
```
