# Storage v2 qualification results

Measured 2026-08-16 on branch `claude/enhance_storage`, commit
`0fb425c1732cde978fda8701c46a57a1b731b147` (clean tree; every JSONL record
carries the commit and an empty diff hash). Values are medians of 5 samples
per coordinate (1 warmup), collected by `scripts/storage-bench.py run-vibeos`
under the fixed machine contract:

- QEMU 11.0.3 `virt`, RV64, `-smp 1 -m 512M -accel tcg,thread=single`,
  virtio-blk (`queue-size=128`, non-legacy), 1 GiB raw data image
- host: macOS arm64 (Apple silicon); guest wall-clock dominated by TCG, so
  ratios between the two guests matter more than absolute times
- vibeOS kernel: `firmware/qemu-virt` built with `--features storage-bench`
- Linux baseline: the reproducible Debian 13 ext4 guest under `linux/`
  (same machine contract, benchmark disk isolated from the root disk);
  Linux medians come from the pinned baseline JSONL runs

| workload | vibeOS (storage v2) | Linux/ext4 | ratio | samples |
|---|---:|---:|---:|---:|
| **Raw block** | | | | |
| random read 4 KiB QD1 | 113.3 µs | 184.4 µs | 0.6x | 5/5 |
| random write 4 KiB QD1 | 226.5 µs | 333.4 µs | 0.7x | 5/5 |
| flush QD1 | 85.7 µs | 64.8 µs | 1.3x | 5/5 |
| sequential 128 KiB | 601.9 µs | 459.7 µs | 1.3x | 5/5 |
| sequential 64 MiB | 599.5 µs | 700.8 µs | 0.9x | 5/5 |
| random read 4 KiB QD4 | unsupported (current virtio facade has one in-flight request slot) | n/a |  | 0/5 |
| random read 4 KiB QD16 | unsupported (current virtio facade has one in-flight request slot) | n/a |  | 0/5 |
| **Object store** | | | | |
| put 4 KiB | 46.2 ms | 5.9 ms | 7.8x | 5/5 |
| get 4 KiB | 0.1 ms | 0.1 ms | 2.3x | 5/5 |
| put 128 KiB | 173.6 ms | 6.7 ms | 25.9x | 5/5 |
| put 360 KiB | 564.6 ms | 11.0 ms | 51.6x | 5/5 |
| range-get 4 KiB | 44.3 ms | 3.8 ms | 11.5x | 5/5 |
| revoke 4 KiB | 45.2 ms | 13.3 ms | 3.4x | 5/5 |
| v2 large 1 MiB (put+get) | 1.80 s | 0.02 s | 80.0x | 5/5 |
| v2 large 16 MiB (put+get) | 4.88 s | 0.19 s | 26.2x | 5/5 |
| v2 large 64 MiB (put+get) | 14.79 s | 0.73 s | 20.3x | 5/5 |
| dedup-gc unique 4 KiB | 65.8 ms | n/a |  | 5/5 |
| dedup-gc all-dup 4 KiB | 54.9 ms | n/a |  | 5/5 |
| **File tree** | | | | |
| create+fsync+unlink 4 KiB | 115.3 ms | 6.8 ms | 17.0x | 5/5 |
| create+fsync+unlink 1 MiB | 251.7 ms | n/a |  | 5/5 |
| overwrite 4 KiB | 224.6 ms | 15.3 ms | 14.6x | 5/5 |
| directory of 100 files | 620.5 ms | 368.6 ms | 1.7x | 5/5 |
| batch-create 1000 | unsupported (staged persistence exceeds the bounded guest benchmark budget) | 2008.2 ms |  | 0/5 |
| sequential write 16 MiB | 1.65 s | n/a |  | 5/5 |
| sequential write 64 MiB | 6.92 s | 0.58 s | 12.0x | 5/5 |
| sequential write 256 MiB | 38.44 s | n/a |  | 5/5 |


## Notes

- `unsupported` rows are declared, not skipped: queue depths above 1 need a
  virtio facade with more than one in-flight request slot, and
  `file-batch-create` at 1000 files exceeds the bounded guest benchmark
  budget for staged persistence.
- Raw block coordinates run at parity with the Linux guest (0.6–1.3x); the
  gap in the durable-commit coordinates is checkpoint and verification
  overhead in the storage v2 commit protocol, not block-layer cost.
- Object `get` and `range-get` include full Merkle verification of the
  returned content. Large objects (>1.44 MiB) commit by reference as
  external CAS blobs and verify end-to-end on both put and get.
- `directory of 100 files` and the sequential coordinates are steady-state
  numbers: samples repeat in one booted VM against one aging image, so they
  include garbage-collection pressure. The first (fresh-image) directory
  sample is 137 ms versus the 368 ms ext4 median.
- Compared with the previous qualification run of this branch, the fused
  file transaction commit and the garbage-collection read-path fixes cut
  `create+fsync+unlink 4 KiB` from 180 ms to 115 ms, the 100-file directory
  median from 917 ms to 620 ms, and 256 MiB sequential from an escalating
  25→140 s to a stable ~38 s; 64 MiB sequential no longer degrades across
  samples.
