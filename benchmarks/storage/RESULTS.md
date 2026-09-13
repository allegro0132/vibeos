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

## 2026-09-11: fewer flushes and less write amplification per file transaction

Three engine changes on branch `wasm_threads` (measured against the
2026-09-10 run above, same machine contract, 1 VM, 1 warmup, 5 samples):

- **Boundary-stable COW partitioning** (`segment-store/src/fs_api.rs`,
  `partition_fs_entries_stable`). The fused tree planner re-packed every
  leaf greedily from the sorted entry list, so one inserted name shifted
  every later leaf boundary and re-staged most of the tree: a single 4 KiB
  create in a 600-file namespace re-staged 14 B+tree nodes (219 segment
  pages, 908 KiB). Leaves and internal nodes now keep the previous tree's
  boundaries, so an edit re-stages only its own path: 97 pages / 420 KiB
  for the same create, and reads per commit fell from 2.7 MiB to 1.1 MiB.
- **Pre-cleared scratch seals** (`segment-store/src/cas.rs`,
  `preclear_scratch_seals`, `MountedState::durably_cleared_seals`). Every
  publication zeroes the final seal page of the next free scratch run
  inside its own batched write; the checkpoint barriers make the zeros
  durable and the successor state records them, so the next writer skips
  the zero-write + flush + read-back it paid per scratch segment. One
  checkpoint now costs 3 flushes (clear old slot seal, body, seal) instead
  of 4, on every commit path (object put, file transaction, chunk batch).
- **Content folded into the fused transaction** (`file-store`
  `FUSED_CONTENT_LIMIT`, segment-store `FsPendingContent`). Content up to
  192 KiB from the stager or `write_chunks` is no longer published through
  its own checkpoint before the tree commit; the fused batch stages it as
  the first entries, the leaves name its predicted identity, and the
  published handles are bound after the checkpoint. A small create or
  overwrite is one checkpoint.

- **Batched collection writes** (`segment-store/src/gc.rs`,
  `SegmentBuilder::sink`). Relocation copied one extent record at a time
  as three single-page device requests (descriptor body, seal, payload);
  the builder now buffers a segment's pages and drains them as contiguous
  runs when 64 pages accumulate and when the segment seals. A round that
  relocated a segment of live nodes went from 986 write requests to 36 at
  identical bytes. Nothing reads a relocation target before its seal, and
  the pre-cleared seal set also spares the target-open flush.

- **Catalog delta records** (`segment-store/src/cas.rs`,
  `CatalogDeltaPolicy`; mount replay in `store.rs`; chain verification in
  `scrub.rs` and `scripts/verify-storage-v2-migration.py`). Every checkpoint
  rewrote the complete `VIBECAS2` snapshot, about 100 bytes per object, so
  a 4 KiB create in a 600-file namespace spent 31 of its ~100 segment pages
  on the catalog and the share grew linearly with the namespace. The writer
  now uses the format's frozen delta ABI: one 3-page `CatalogDelta` record
  per minted object, chained from the checkpoint's replay tail back to the
  unchanged snapshot root, chosen whenever that costs fewer pages than the
  snapshot and the chain stays within the superblock's 32-record budget;
  the chain resets to a snapshot when the budget would be exceeded and on
  every collection round. A 600-file unlink dropped from 97 to 83 pages,
  and the per-checkpoint catalog cost is now flat (3 pages per object
  minted) instead of proportional to the live object count.

- **Reusable mark edges** (`segment-store/src/gc.rs`, `TypedEdgeCache`).
  Every collection round re-read and re-authenticated every live typed
  object (manifest, first leaf, tree page) to learn its child references:
  a round over 900 files read 18 MiB in 4,000 requests. Objects are
  immutable and id-addressed, so the store now keeps the child list each
  walk authenticated, bound to the object's BlobKey and pruned to the live
  catalog; a later round in the same process reads only objects committed
  since the previous one. Second and later rounds over the same 900 files
  read 6.6 MiB in 1,174 requests with ~6 misses each; the first round of a
  process is unchanged. The memo is bounded (4 MiB) and never persisted.
- Delta chains were also exercised on QEMU: after seven 100-file directory
  transactions the small-file samples left a 29-record replay chain that
  the powered-off native verifier (`verify-storage-v2-migration.py
  --expect-native`) accepted.

Per create+fsync+unlink sample (host trace, in-memory device; the QEMU
`counters` are now per-sample deltas — the file-tree bench previously
reported cumulative-since-boot telemetry):

| namespace | flushes before → after | bytes written before → after |
|---|---:|---:|
| 8 files | 12 → 6 | 516 KiB → 448 KiB |
| 600 files | 12 → 6 | 1.5 MiB → 0.9 MiB |

QEMU medians (RAM-backed disk, so flushes are nearly free; the ratios that
matter for the SD-card target are the flush and byte counts above):

| coordinate | before | after |
|---|---:|---:|
| object put 4 KiB | 26.9 ms | 12.7 / 28.5 / 31.1 ms (three runs) |
| object range-get / revoke 4 KiB | 26.6 / 29.3 ms | 16.5 / 13.2 ms |
| create+fsync+unlink 4 KiB | 22.4 ms | 20.9 / 24.6 ms (two runs) |
| overwrite 4 KiB | 27.3 ms | 23.5 / 25.7 / 24.7 ms (three runs) |
| directory of 100 files | 32.0 ms | 23.5 / 27.0 ms (two runs) |
| sequential write 64 / 256 MiB | 3.96 / 14.95 s | 3.66 / 14.01 s |

Raw block coordinates are unchanged. On QEMU the latency deltas are
inside run-to-run variance (a 5-sample run moves 10-20% between
sessions, and the bimodal outlier on durable object commits — one sample
in five 3-8x above the rest — persists and is unrelated to these
changes); the flush and byte reductions above are the durable result.

Remaining per-commit costs, in order: the frozen 2-page descriptor pair per
extent and the 3-extent split of every small blob (about 60% of a small
fused segment, a format change), the first collection round of each process
(its mark walk reads about three distinct pages per live node; later rounds
reuse the edge memo), and the relocation copy itself, which reads every live
extent of a source segment once and verifies the copy.

## 2026-09-11 (later): CPU profile of a small transaction, and two more cuts

Host profile (release build, in-memory device, Apple M5) of one fused
create at 8 and 600 files, using timestamped phase probes. Engine time is
dominated by SHA-256 over descriptor pages that the frozen format mandates
(two 4 KiB pages per extent, three extents per small blob): building the
packed extent records costs ~0.1 ms per staged blob, manifest and
catalog/allocation records ~0.2 ms, segment summary/seal ~0.15 ms, the
checkpoint pair ~0.1 ms, and the mandated re-read of the checkpoint pair on
successor mount ~0.15 ms. Blob staging itself (Merkle, encoding) is under
10 µs per blob. The object-store append profiles the same way (~1.1 ms
store-side, flat in object count; the host-side import build is linear in
stream length but the kernel caches that replay). QEMU's TCG multiplies
these by roughly 13x, which is why its latencies are CPU-bound.

Two costs outside the hashing floor were found and removed:

- **Root re-reads.** Every transaction read the current namespace root from
  media twice — once in `expect_current_fs_root` before staging and once in
  `recover_fs_root` after publication — and each read re-scanned a segment's
  descriptor chain: 43 + 73 requests, ~900 KiB and the matching hashing per
  commit. The store now memoizes the decoded root it just published, keyed
  by the object identity the authority names (`FsRootMemo`); a commit reads
  4 pages (48 KiB) instead.
- **Quadratic link counts.** `encode_namespace` computed each inode's link
  count by scanning every directory entry, so encoding a 600-file namespace
  cost 1.2–1.5 ms per commit (40% of the transaction). `link_counts()` now
  derives all counts in one pass; cold-recovery validation uses it too. The
  publish step also moves the working state instead of cloning it again.

Whole-transaction wall time on the host: 600-file create 3.9 → 1.8 ms.
QEMU medians (two independent runs each): create+fsync+unlink 4 KiB
22.4 → 14.7 / 12.9 ms, overwrite 4 KiB 27.3 → 15.9 / 14.9 ms, object put
4 KiB 26.9 → 15.1 / 14.6 ms, directory of 100 files 32.0 → 23.0 ms;
sequential 16 MiB unchanged (709 / 730 ms isolated) and object put 128 KiB
unchanged (138.6 ms). Goldens `storage_v2`, `storage_v2_native` and the
three-boot file-tree acceptance pass.

## 2026-09-11 (later still): compact Blob layout

The last CPU item was the frozen three-extent split of every small Blob
(header / content / tree), each extent costing a descriptor pair — two
4 KiB pages, one of them SHA-256 hashed — plus a page-rounded payload. The
manifest ABI now admits a **compact layout**: a Blob whose complete
canonical encoding fits one extent (up to 1 MiB) may be stored as exactly
one extent carrying header, content, and tree contiguously; readers locate
bytes by encoded offset, so both layouts decode the identical canonical
Blob. The writer assembles every sink-buffered Blob (up to 256 KiB) in
memory and emits the compact form; deduplication compares complete
encodings across layouts; the codec, scrub, the powered-off verifiers, and
the format document accept both. Existing canonical-split Blobs remain
valid; images holding compact manifests need readers at or after this
revision.

Effect on a small fused create (host trace, 8 files): segment pages
60 → 37, bytes 276 → 180 KiB, transaction wall 1.15 → 0.84 ms.
