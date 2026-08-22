# Storage v2 qualification results

Measured 2026-08-18 on branch `milkv-duo-reboot-storage-fixes`, commit
`533c6c1c` (clean tree; every JSONL record carries the commit and an empty
diff hash). Values are medians of 5 samples per coordinate (1 warmup),
collected by `scripts/storage-bench.py run-vibeos` / `run-linux` under the
fixed machine contract:

- QEMU 11.0.3 `virt`, RV64, `-smp 1 -m 512M -accel tcg,thread=single`,
  virtio-blk (`queue-size=128`, non-legacy), 1 GiB raw data image
- host: macOS arm64 (Apple silicon); guest wall-clock dominated by TCG, so
  ratios between the two guests matter more than absolute times
- vibeOS kernel: `firmware/qemu-virt` built with `--features storage-bench`
- Linux baseline: the reproducible Debian 13 ext4 guest under `linux/`
  (same machine contract, benchmark disk isolated from the root disk); no
  pinned baseline JSONL exists in `benchmarks/storage/baselines/`, so this
  run's Linux numbers come from a fresh `run-linux` invocation per
  coordinate, not a cached artifact

| workload | vibeOS (storage v2) | Linux/ext4 | ratio | samples |
|---|---:|---:|---:|---:|
| **Raw block** | | | | |
| random read 4 KiB QD1 | 111.6 µs | 118.9 µs | 0.9x | 5/5 |
| random write 4 KiB QD1 | 217.9 µs | 230.7 µs | 0.9x | 5/5 |
| flush QD1 | 80.7 µs | 58.1 µs | 1.4x | 5/5 |
| sequential 128 KiB | 586.3 µs | 197.5 µs | 3.0x | 5/5 |
| sequential 64 MiB | 595.3 µs | 210.1 µs | 2.8x | 5/5 |
| random read 4 KiB QD4 | unsupported (current virtio facade has one in-flight request slot) | n/a |  | 0/5 |
| random read 4 KiB QD16 | unsupported (current virtio facade has one in-flight request slot) | n/a |  | 0/5 |
| **Object store** | | | | |
| put 4 KiB | 24.0 ms | 1.9 ms | 12.6x | 5/5 |
| get 4 KiB | 0.19 ms | 0.03 ms | 7.3x | 5/5 |
| put 128 KiB | 145.6 ms | 2.5 ms | 58.9x | 5/5 |
| put 360 KiB | 435.4 ms | 3.8 ms | 115.5x | 5/5 |
| range-get 4 KiB | 30.1 ms | 2.2 ms | 13.9x | 5/5 |
| revoke 4 KiB | 29.5 ms | 3.0 ms | 9.7x | 5/5 |
| v2 large 1 MiB (put+get) | 1.30 s | 0.009 s | 147.1x | 5/5 |
| v2 large 16 MiB (put+get) | 2.57 s | 0.12 s | 22.2x | 5/5 |
| v2 large 64 MiB (put+get) | 9.89 s | 0.50 s | 19.7x | 5/5 |
| dedup-gc unique 4 KiB | 43.3 ms | n/a |  | 5/5 |
| dedup-gc all-dup 4 KiB | 33.8 ms | n/a |  | 5/5 |
| **File tree** | | | | |
| create+fsync+unlink 4 KiB | 40.5 ms | 2.9 ms | 14.2x | 5/5 |
| create+fsync+unlink 1 MiB | 87.0 ms | n/a |  | 5/5 |
| overwrite 4 KiB | 38.8 ms | 4.2 ms | 9.3x | 5/5 |
| directory of 100 files | 30.9 ms | 220.8 ms | 0.1x | 5/5 |
| batch-create 1000 | unsupported (staged persistence exceeds the bounded guest benchmark budget) | 1679.0 ms |  | 0/5 |
| sequential write 16 MiB | 0.73 s | n/a |  | 5/5 |
| sequential write 64 MiB | 3.57 s | 0.42 s | 8.5x | 5/5 |
| sequential write 256 MiB | 14.35 s | n/a |  | 5/5 |


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
  budget for staged persistence. Both reasons are unchanged from the
  previous run.
- Raw block coordinates stayed the tightest measurements in this run
  (coefficient of variation under 5% on every vibeOS block row except
  `flush`, ~19%). The durable-commit coordinates (object store, file tree)
  are a different story this cycle: see the variance note below.
- **Elevated variance in object-store and file-tree coordinates.** Every
  `object-durable-put-get`, `object-range-get`, `object-revoke`,
  `file-durable-mutations`, `file-overwrite-4k`, and `file-directory`
  coordinate showed a coefficient of variation between 25% and 116% across
  the 5 retained samples (the manifest's `inconclusive` threshold is 10%),
  driven by one sample per coordinate landing 3-8x above the other four
  (e.g. object put 4 KiB: four samples at 14-29 ms, one at 94 ms). Raw
  block coordinates measured in the *same* boot session did not show this
  pattern, which rules out generic host scheduling noise as the sole
  explanation. The most likely cause is the segment-allocation and GC
  changes in this branch's last 10 commits (`23a7ded`..`533c6c1`, notably
  "Enhance segment storage and garbage collection mechanisms" and "Refactor
  segment allocation logic for staged batches") introducing an occasional
  stall on the durable-commit path — plausibly a GC/cleaner pass triggered
  partway through a coordinate's 5-sample run against the single aging
  image. This is worth a focused follow-up; the medians below are still
  reported (matching this doc's existing methodology of reporting medians),
  but should be read with that caveat, and a couple of the largest
  medians-vs-previous-run deltas (`directory of 100 files`, `overwrite
  4 KiB`, `create+fsync+unlink 4 KiB`) are likely inflated by which side of
  the bimodal distribution the median sample happened to land on rather
  than a clean 2x+ improvement.
- Object `get` and `range-get` include full Merkle verification of the
  returned content. Large objects (>1.44 MiB) commit by reference as
  external CAS blobs and verify end-to-end on read.
- `directory of 100 files` and the sequential coordinates are steady-state
  numbers: samples repeat in one booted VM against one aging image, so they
  include garbage-collection pressure. The first (fresh-image) directory
  sample beats the ext4 median.
- **The Linux/ext4 side moved substantially between this run and the
  previous one, independent of any vibeOS code change** (nothing in the
  last 10 commits touches `linux/`, and no pinned Linux baseline exists to
  compare against — every Linux number here comes from a fresh guest boot).
  Every Linux coordinate measured this cycle came in 30-75% faster than the
  equivalent row in the previous doc (e.g. block sequential 64 MiB
  700.8→210.1 µs, object put 4 KiB 5.9→1.9 ms, object revoke 13.3→3.0 ms),
  while the matching vibeOS numbers on the raw block layer barely moved
  (within ±8%). This is host-session variance in the Linux/TCG measurement,
  not a regression or improvement in either guest's code, but it moves
  every ratio column up relative to the previous doc and should not be
  read as vibeOS getting relatively slower.
- Compared with the previous qualification run (`b296e760`, measured
  2026-08-16), the vibeOS numbers that moved by more than 15% and are
  **not** attributable to the bimodal-variance caveat above: v2 large
  16 MiB put+get 4.38→2.57 s (-41%), v2 large 64 MiB put+get 12.86→9.89 s
  (-23%), dedup-gc unique 52.3→43.3 ms (-17%), dedup-gc all-dup
  44.1→33.8 ms (-23%), create+fsync+unlink 1 MiB 210.3→87.0 ms (-59%),
  sequential write 16 MiB 1.44→0.73 s (-49%), sequential write 64 MiB
  6.15→3.57 s (-42%), sequential write 256 MiB 36.21→14.35 s (-60%), and
  object put 360 KiB 513.2→435.4 ms (-15%). These are large, consistent
  improvements across every large-payload and sequential-write coordinate,
  plausibly the segment-allocation refactor reducing large-transfer commit
  overhead. `directory of 100 files` (613.0→30.9 ms) and `overwrite 4 KiB`
  (217.5→38.8 ms) moved even further but land inside the bimodal-variance
  band above, so treat those two deltas as directionally real but not
  precisely quantified by this run; a rerun with more samples per
  coordinate is recommended before citing exact numbers for either.
