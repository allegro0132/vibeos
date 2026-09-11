# Storage performance qualification

This directory defines the fixed QEMU `virt`/RV64 comparison contract. Results
come from guest production paths only; host-only adapters are not accepted by
the record validator.

`workloads-v1.json` is the complete qualification matrix. `schema-v1.json` is
the versioned JSONL record contract. Every coordinate has one of `ok`,
`unsupported`, `failed-closed`, or `inconclusive`; unsupported measurements do
not contain zero-valued timing fields.

The initial executable guest path is `object-durable-put-get`. VibeOS invokes
the selected M4 or Storage v2 `StoreService` directly. Linux uses the static
agent under `linux/` and performs:

```
write temporary -> fdatasync -> rename -> fsync directory -> read-back
```

The remaining block, file-tree, recovery, dedup, and GC coordinates stay in
the manifest so a qualification run cannot silently omit them while their
guest agents are added.

## Reproducible Linux guest

`linux/versions.json` pins Debian 13 nocloud build `20260810-2566`, its SHA-512,
Linux `6.12.101+deb13-riscv64`, and the ext4 creation arguments. The Debian root
and 1 GiB benchmark disk are separate virtio-blk devices. Per-sample accounting
is read from the benchmark device's own sysfs statistics, so root-disk I/O is
not attributed to the workload.

Prepare it with Docker and QEMU EDK2 firmware. Debian binary packages provide
GCC and e2fsprogs; the script compiles only the small agent, not a toolchain:

```
./scripts/build-linux-storage-bench.sh \
  /path/to/edk2-riscv-code.fd /path/to/edk2-riscv-vars.fd
```

Run an ext4 guest point with the same QEMU machine contract:

```
python3 scripts/storage-bench.py run-linux \
  --root-image target/storage-bench-debian/debian-13-nocloud-riscv64-configured.qcow2 \
  --firmware-code /path/to/edk2-riscv-code.fd \
  --firmware-vars target/storage-bench-debian/debian-13-nocloud-riscv64-vars.fd \
  --agent target/storage-bench-debian/storage-bench-agent \
  --data-image target/storage-bench-debian/storage-bench-ext4.raw \
  --object-bytes 4096 --vms 1 --warmups 1 --samples 2 \
  --output /tmp/linux-4k.jsonl
```

## VibeOS sample run

Build the dedicated feature path and run one short smoke point:

```
cd firmware/qemu-virt
cargo build --release --features storage-bench
cd ../..
python3 scripts/storage-bench.py run-vibeos \
  --kernel target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt \
  --data-image target/storage-v2-native-verified.raw \
  --object-bytes 4096 --vms 1 --warmups 1 --samples 2 \
  --output /tmp/vibeos-4k.jsonl
python3 scripts/storage-bench.py validate /tmp/vibeos-4k.jsonl
python3 scripts/storage-bench.py summarize /tmp/vibeos-4k.jsonl
```

The comparison command accepts separate result files, preserving their
provenance while rejecting duplicate sample coordinates:

```
python3 scripts/storage-bench.py compare \
  /tmp/vibeos-m4-4k.jsonl /tmp/vibeos-v2-4k.jsonl /tmp/linux-4k.jsonl
```

Full latency qualification uses the manifest defaults: five independent VMs,
five warmups and twenty retained samples per VM. A coefficient of variation
above 10% is reported as `inconclusive`. Baselines are immutable unless the
operator uses the explicit command:

```
python3 scripts/storage-bench.py update-baseline results.jsonl \
  benchmarks/storage/baselines/v2-baseline.json --update \
  --correctness-evidence qualification-correctness.json
```

The powered-off Storage v2 verifier and `fsck.ext4 -fn` remain correctness
gates outside timed regions. The update command requires both evidence records,
a clean recorded Git worktree, and every explicitly backend-scoped manifest
coordinate. A failed correctness gate or partial matrix blocks baseline update.

## Read-path attribution and focused regression

For `object-range-get`, `latency_ns` includes the initial durable put. Compare
`get_latency_ns` to measure just the range read. Linux range-get and large-object
samples now report both put/get phase latency alongside their composite total.
VibeOS records expose `phases.put_*` and `phases.get_*` I/O counts and bytes;
get counters are total minus put, and inconsistent totals are rejected. Zero
device reads may reflect the existing caches, not zero verification work.

The CAS streaming reader uses a 64 KiB content window and up to 16 hash pages,
all local to one invocation. The object range API authenticates the needed
envelope bytes with native CAS proofs and then verifies the outer blob proof.
Persistent/transient authority checks and small-object hot-cache generation
checks remain in place. The disk format is unchanged.

The focused 1 MiB host regression reduced PageDevice read requests from 781 to
34 and pages from 793 to 286, compared with the original CAS implementation
using the same harness. These are deterministic I/O counts, not wall-clock
speedup claims. The regression also checks unaligned and out-of-bounds ranges:

```sh
cargo test -p vibeos-segment-store --test perf_steady_state \
  large_object_append_and_cold_recover -- --nocapture
cargo test -p vibeos-segment-store --test cas_streaming
cargo test -p vibeos-object-store
python3 -m unittest scripts/test_storage_bench.py
```

The 2026-09-11 QEMU smoke runs passed for 4 KiB and 128 KiB range workloads,
and for range/full reads of 1 MiB objects. For the latter, get performed 28
device reads / 167,936 bytes for a 4 KiB range versus 40 reads / 1,216,512 bytes
for the whole object. Short-run latency variance was too high for formal
qualification. Repeated manifest resolution and nested-proof work remain
optimization opportunities. Local logs, JSONL and the detailed report are in
`target/storage-read-optimization-20260911/`; the formal baseline is unchanged.
