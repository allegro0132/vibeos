# Storage v2 qualification results

Measured 2026-08-16 on branch `claude/enhance_storage`, commit
`b296e760` (clean tree; every JSONL record carries the commit and an empty
diff hash). Values are medians of 5 samples per coordinate (1 warmup),
collected by `scripts/storage-bench.py run-vibeos` under the fixed machine
contract:

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
| random read 4 KiB QD1 | 114.2 µs | 184.4 µs | 0.6x | 5/5 |
| random write 4 KiB QD1 | 229.7 µs | 333.4 µs | 0.7x | 5/5 |
| flush QD1 | 87.5 µs | 64.8 µs | 1.4x | 5/5 |
| sequential 128 KiB | 594.3 µs | 459.7 µs | 1.3x | 5/5 |
| sequential 64 MiB | 600.1 µs | 700.8 µs | 0.9x | 5/5 |
| random read 4 KiB QD4 | unsupported (current virtio facade has one in-flight request slot) | n/a |  | 0/5 |
| random read 4 KiB QD16 | unsupported (current virtio facade has one in-flight request slot) | n/a |  | 0/5 |
| **Object store** | | | | |
| put 4 KiB | 32.5 ms | 5.9 ms | 5.5x | 5/5 |
| get 4 KiB | 0.2 ms | 0.1 ms | 2.8x | 5/5 |
| put 128 KiB | 132.9 ms | 6.7 ms | 19.8x | 5/5 |
| put 360 KiB | 513.2 ms | 11.0 ms | 46.9x | 5/5 |
| range-get 4 KiB | 33.2 ms | 3.8 ms | 8.6x | 5/5 |
| revoke 4 KiB | 33.0 ms | 13.3 ms | 2.5x | 5/5 |
| v2 large 1 MiB (put+get) | 1.65 s | 0.02 s | 73.4x | 5/5 |
| v2 large 16 MiB (put+get) | 4.38 s | 0.19 s | 23.5x | 5/5 |
| v2 large 64 MiB (put+get) | 12.86 s | 0.73 s | 17.7x | 5/5 |
| dedup-gc unique 4 KiB | 52.3 ms | n/a |  | 5/5 |
| dedup-gc all-dup 4 KiB | 44.1 ms | n/a |  | 5/5 |
| **File tree** | | | | |
| create+fsync+unlink 4 KiB | 89.9 ms | 6.8 ms | 13.3x | 5/5 |
| create+fsync+unlink 1 MiB | 210.3 ms | n/a |  | 5/5 |
| overwrite 4 KiB | 217.5 ms | 15.3 ms | 14.2x | 5/5 |
| directory of 100 files | 613.0 ms | 368.6 ms | 1.7x | 5/5 |
| batch-create 1000 | unsupported (staged persistence exceeds the bounded guest benchmark budget) | 2008.2 ms |  | 0/5 |
| sequential write 16 MiB | 1.44 s | n/a |  | 5/5 |
| sequential write 64 MiB | 6.15 s | 0.58 s | 10.6x | 5/5 |
| sequential write 256 MiB | 36.21 s | n/a |  | 5/5 |


## Notes

- The kernel runtime selects the deferred commit-readback profile
  (`SegmentStore::set_deferred_commit_readback`): commits no longer re-read
  and re-verify every just-written page before the successor mounts. Every
  read path still fails closed on the content's Merkle identity and boot
  performs a full cold scrub, so a damaged device write is detected at
  first use instead of at the commit that wrote it. The verifying profile
  remains the library default.
- `unsupported` rows are declared, not skipped: queue depths above 1 need a
  virtio facade with more than one in-flight request slot, and
  `file-batch-create` at 1000 files exceeds the bounded guest benchmark
  budget for staged persistence.
- Raw block coordinates run at parity with the Linux guest (0.6–1.4x); the
  gap in the durable-commit coordinates is Merkle hashing, authority
  bookkeeping, and checkpoint ordering in the storage v2 commit protocol,
  not block-layer cost.
- Object `get` and `range-get` include full Merkle verification of the
  returned content. Large objects (>1.44 MiB) commit by reference as
  external CAS blobs and verify end-to-end on read.
- `directory of 100 files` and the sequential coordinates are steady-state
  numbers: samples repeat in one booted VM against one aging image, so they
  include garbage-collection pressure. The first (fresh-image) directory
  sample beats the ext4 median.
- Compared with the previous qualification run (`6a3d9a2`, measured at
  `0fb425c`), this run adds incremental authority-stream validation,
  promotion-claim carry-forward, decoded-tree caching across file
  transactions, and the deferred readback profile: object put 4 KiB
  46→33 ms, revoke 45→33 ms, v2 large 16 MiB put+get 4.9→4.4 s and
  64 MiB 14.8→12.9 s, create+fsync+unlink 4 KiB 115→90 ms, sequential
  64 MiB 6.9→6.2 s.
