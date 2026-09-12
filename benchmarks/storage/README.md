# Storage performance qualification

This directory defines the fixed QEMU `virt`/RV64 comparison contract. Results
come from guest production paths only; host-only adapters are not accepted by
the record validator.

Current v2 write policy in this worktree uses a 4 KiB inline cutoff and the
bounded external hot-read cache described below. Earlier 16 KiB measurements
and the rejected uncached 4 KiB trial are historical comparisons, not the
current policy. These QEMU results do not qualify physical SD hardware.
Streaming scratch writes now use up to 128 KiB per submission; the earlier
64 KiB run measurements below are retained as baselines.
Whole-object verification also uses a 128 KiB content window; directed ranges
retain their demand-sized reads.

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
qualification. Local logs, JSONL and the detailed report are in
`target/storage-read-optimization-20260911/`; the formal baseline is unchanged.

## SD-oriented QEMU experiments

Both runners accept `--read-bps`, `--write-bps`, `--read-iops` and
`--write-iops` (nonnegative integers, zero means unlimited). They throttle only
the benchmark disk and record the limits in `environment.storage_throttle`.
Comparison rejects mismatched profiles for the same workload coordinate;
throttled experiments cannot replace the formal unthrottled baseline.
These QEMU average-rate limits allow bursts. They do not simulate SD commands,
card firmware, erase behavior or flush latency, and cannot qualify real cards.

The current v2 facade puts objects larger than 16 KiB into the existing external
content path instead of embedding them in the authority journal. The on-disk
format and recovery ordering are unchanged. Batched proof ranges share one
manifest resolution and bounded verification buffers (up to 32 ranges).
PageDevice reads reuse cached prefixes/suffixes, with at most one device read
per original hardware-sized chunk to avoid turning cache holes into many SD
commands. All returned content still passes the existing verification path.

The 2026-09-11 exploratory run used one VM, one warmup and three retained
samples, with read/write limits of 4/2 MiB/s and 400/200 IOPS. Baseline firmware
was built from `9ccce326f0fc2a79d804da9de1bf2eb59014ad75`:

| Phase | Baseline median | Changed median |
| --- | ---: | ---: |
| 128 KiB durable put | 552.664 ms | 58.909 ms |
| 1 MiB durable put | 7.560677 s | 1.333638 s |
| 4 KiB range read from 1 MiB object | 34.290 ms | 8.146 ms |

The put rows use the final external-content policy; the range row isolates the
batched-proof change. These short runs are not formal latency qualification.
For 1 MiB put, device writes fell from 4.24–7.13 MiB to 1.22–1.29 MiB per
retained sample, and authority growth fell from 2,962 to 2 records per object.
The range row still uses 28 physical reads / 167,936 bytes; its gain reflects
less repeated metadata/proof processing, not reduced physical read traffic.
The host regression separately reduces five native range reads from 61 to 15
PageDevice requests and from 91 to 21 pages by sharing their reader.

Reproduce a limited large-object point with:

```sh
python3 scripts/storage-bench.py run-vibeos \
  --kernel target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt \
  --data-image target/storage-v2-native-verified.raw \
  --output /tmp/vibeos-limited-1m.jsonl \
  --object-bytes 1048576 --workload object-v2-large \
  --vms 1 --warmups 1 --samples 3 \
  --read-bps 4194304 --write-bps 2097152 \
  --read-iops 400 --write-iops 200 \
  --boot-timeout 120 --sample-timeout 180
```

Local binaries, SHA-256 manifest, JSONL, summaries and test logs are in
`target/storage-sd-qemu-20260911/`. Validation covers CAS streaming/corruption,
object-store tests, exhaustive cache patterns, and crash cuts for external
objects of 16 KiB + 1 and 128 KiB. The final QEMU firmware passes selftests;
the Milk-V Duo target passes a compile check only. Large streaming puts still
issued roughly 281 writes per 1 MiB object before the following change.

### Bounded streaming writes

Large CAS writers now coalesce contiguous scratch content/header/tree pages
into runs of at most 16 pages (64 KiB). A full run or an address discontinuity
submits the pending pages. The final partial run drains before dedup comparison
and metadata publication, and its allocation is released before those phases.
Small-object fused sinks and existing flush/checkpoint ordering are unchanged.
A failed or cancelled submission leaves the writer failed; it cannot resume
writing or publish uncertain data. Dropping the writer still requires recovery.

The matched follow-up QEMU experiment compares the previous external-content
firmware with this change, using the same 4/2 MiB/s and 400/200 IOPS profile,
one VM, one warmup and three retained samples:

| Put phase | Before coalescing | After coalescing |
| --- | ---: | ---: |
| 1 MiB median latency | 1.345467 s | 0.546106 s |
| 1 MiB write requests | 281–291 | 30–40 |
| 16 MiB median latency | 21.898398 s | 8.894833 s |
| 16 MiB write requests | 4325 | 305 |

Write bytes and flush counts match sample for sample at both sizes;
the change reduces command count rather than weakening durability or reducing
stored content. Results remain exploratory QEMU measurements, not real SD
qualification or a replacement for the formal baseline.

The host 3 MiB + 17 byte regression crosses content extents and segment
boundaries, including a partial final page/run: 824 written pages use 89
requests, then every chunk verifies after a cold mount. Fault tests cover each
of 16 page boundaries within a streaming run, including not-submitted errors,
durable ambiguous errors and cancellation, and reject subsequent writer reuse.
Existing fused-append crash sweeps also pass with coalescing enabled.

```sh
cargo test -p vibeos-segment-store --lib --test cas_streaming \
  --test perf_steady_state --test fused_append_recovery
```

The final host run passes 201 tests with one pre-existing ignored test.
QEMU release firmware builds, guest selftests and the Milk-V Duo compile check
pass. A single unthrottled 64 MiB put/get smoke also succeeds (5.924 s total);
it is a capacity/correctness smoke, not a before/after latency comparison. Binaries,
build provenance, JSONL and test logs are saved locally under
`target/storage-streaming-write-20260911/`.

## File-tree measurement corrections

New `file-sequential` samples use `content_pattern=splitmix64-offset-v1`:
each aligned eight-byte word is a little-endian SplitMix64 permutation of
`seed + word_index * 0x9e3779b97f4a7c15` modulo 2^64. Both guest agents generate
bytes from the absolute file offset, regardless of their I/O buffer sizes.
Earlier VibeOS data repeated every 256 bytes, and the Linux agent repeatedly
wrote the same buffer. In particular, large persistent file chunks could be
identical, unintentionally exercising dedup rather than unique sequential data.
Both agents now verify every readback byte; VibeOS additionally rejects missing,
empty or length-mismatched chunks instead of counting them as successful reads.

File-tree records also carry `latency_scope=workload`. VibeOS formerly divided
elapsed time by the reported operation count while Linux reported the entire
workload. VibeOS now reports the entire workload too; operation counts remain
descriptive. For `file-sequential`, timing includes staging/durable publication,
verified readback and removal, so it must not be presented as write-only latency.
Do not reuse the old file-tree latency ratios as current Linux comparisons.
The runner preserves both metadata fields and rejects comparisons mixing data
patterns or latency scopes. Missing metadata denotes the historical contract.

File-tree and object benchmarks share the same bounded wait for storage boot
selection before timing starts. The missing file-tree wait previously caused
immediate root-recovery failures on rate-limited devices still mounting or
scrubbing; an actual fail-closed selection still terminates the wait.

Use a disposable blank image for a fresh benchmark namespace. The runner clones
and extends it to the benchmark firmware's 1 GiB device geometry; launching
that firmware directly against a 64/128 MiB image does not cover its provisioned
range. Initialization and the boot wait remain outside the workload timer.

```sh
python3 -m unittest scripts/test_storage_bench.py
rustc --edition 2021 --test kernel/src/storage_bench_pattern.rs \
  -o /tmp/storage-bench-pattern-tests
/tmp/storage-bench-pattern-tests
```

The tests compare the actual Rust and C pattern implementations over unaligned
offsets, page/large-chunk boundaries and wrapping seeds, and inject corruption.
QEMU release and Milk-V Duo compile checks pass. The Linux C agent also passes
a native host warning-as-error compile (with the unused raw-block `O_DIRECT`
flag stubbed on macOS); no new Linux/ext4 timing claim is made from that check.
Local firmware, JSONL and logs for this correction are in
`target/storage-file-pattern-20260911/`. Early failed-closed setup samples there
are diagnostic evidence only, not performance results.

The verified run (`verified-unique-limited-16m.jsonl`) uses one VM, one warmup
and three retained samples at 4/2 MiB/s and 400/200 IOPS. All four complete
successfully with exact readback. Retained complete-workload latencies are
17.849285, 18.143329 and 17.622981 seconds (median 17.849285 seconds). Device
writes are 18,157,568–18,231,296 bytes and reads 36,126,720–37,744,640 bytes.
This is a corrected exploratory starting point, not a speedup over the old
repeated-data/per-operation figures. The final firmware passes QEMU selftests.

## Preserve the kernel readback policy across runtime rebuilds

The kernel configures deferred payload readback when constructing its initial
`SegmentStore`, but the rebuild after an unformatted probe or cancelled
operation used the library's default strict profile. A shared constructor now
preserves the configured profile across both paths. This is a verification
policy restoration, not a cache-only optimization: both profiles keep the same
flush/checkpoint barriers, but strict mode detects damaged acknowledged writes
during commit, while deferred mode detects them when the content is read from
media or scrubbed. Every returned content byte still requires Merkle verification;
write-through caches can retain valid original bytes before media damage is
observed. Do not describe the result as preserving commit-time damage detection.

A host phase trace of a 16 MiB file under the configured deferred profile reads
464 KiB while staging, 48 KiB while committing the tree, 18,192 KiB while
reading the file, and 48 KiB while removing it. The kernel's unintended strict
profile after fresh-store initialization explained the extra full payload pass.
The read-phase regression verifies every byte and bounds read amplification
below 1.25 times the logical file length.

The matched QEMU comparison uses the corrected unique-data/workload-time
contract, a fresh blank image, one VM, one warmup, three retained samples and
the same 4/2 MiB/s, 400/200 IOPS limits:

| 16 MiB complete file workload | Before rebuild fix | After rebuild fix |
| --- | ---: | ---: |
| Median elapsed | 18.419526 s | 13.265848 s |
| Device bytes read | 36,126,720–37,744,640 | 18,210,816–19,836,928 |
| Device bytes written | 18,157,568–18,231,296 | unchanged per sample |
| Flush requests | 12, 19, 12 | unchanged per sample |

All samples verify the complete file. The approximately 28% time reduction is
exploratory and specific to restoring this policy; it is not a strict-versus-
strict algorithm speedup or real-card qualification.

Validation passes 11 CAS streaming tests (including acknowledged damaged writes
under both profiles), 5 fused-append crash sweeps, and 27 file-store tests with
one existing ignored test. The damaged-write test confirms strict commit
rejection and deferred rejection on both directed/full verification, including
after cold mount. Milk-V Duo compilation passes. The production file-tree QEMU
acceptance passes three boots, hard links, symlinks, recursive removal, GC
pressure and independent powered-off verification after each boot. Run it with:

```sh
QEMU_SMP=1 QEMU_ACCEL=tcg,thread=single sh scripts/qemu-file-tree-test.sh
```

Saved firmware, policy provenance, JSONL and verification logs are in
`target/storage-runtime-policy-20260911/`. The benchmark ELF uses the diagnostic
shell; the separate file-tree acceptance ELF supplies the production VSH
session with its bound `@home` capability.

## Bound filesystem metadata read amplification

Filesystem metadata now uses the existing whole-object verified reader instead
of verifying the object and then resolving every leaf a second time. Data-node
prefix reads use that batched path for objects up to 8 KiB; larger nodes retain
the directed first-leaf proof, so following a skip pointer does not read a large
file chunk in full.

The larger improvement comes from resolving CAS manifests through the existing
authenticated segment-chain memo. Previously every manifest lookup walked the
sealed segment's complete descriptor chain again. The memo is bounded to 48
segments, keyed by segment number and generation, checks the checkpoint horizon,
and discards freed segments during GC. Manifest payloads are still read and
hash-checked on every invocation. Cold scrub bypasses this memo; subsequent
physical damage to cached descriptor pages is detected by an uncached scan,
rather than by every hot dereference. This extends the existing content-pointer
cache contract to manifest pointers; it changes neither disk format nor commit
readback policy.

A host trace recovering a populated 100-file tree after a cold store mount
(excluding mount I/O itself) changes from 10,642 reads / 20,934 pages to 569 reads
/ 819 pages. These are PageDevice calls, not physical-card measurements. The
regression test bounds both requests and pages and checks all recovered sizes.
Another test damages data and manifest bytes after a successful read and checks
that subsequent reads reject them, covering 4,097-, 131,073- and 600,001-byte
objects.

The QEMU comparison uses `file-directory`, 100 files of 4 KiB per invocation,
a blank image, one VM, one warmup and three retained samples, with 4/2 MiB/s
and 400/200 read/write IOPS limits. Each invocation creates a new directory,
commits its files, lists it and recovers the complete tree; directories persist
between samples, so the three samples measure increasing tree sizes, not three
independent repetitions of an identical tree. Both firmware versions already
have the runtime readback-policy fix above.

| Retained sample | Before | After | Device bytes read before / after |
| --- | ---: | ---: | ---: |
| 1 | 5.676598 s | 1.007131 s | 4,337,664 / 65,536 |
| 2 | 8.372544 s | 1.058010 s | 9,797,632 / 147,456 |
| 3 | 11.271092 s | 1.076765 s | 15,273,984 / 241,664 |

The sequence median improves 7.91 times. Writes remain identical per sample:
2,072,576 / 2,084,864 / 2,101,248 bytes, 21 requests and 3 flushes each.
This is an exploratory QEMU result under bandwidth/IOPS limits, not a physical
SD-card qualification or a comparison with the historical Linux ratios.

Validation passes 183 segment-store unit tests (one ignored), 11 CAS streaming,
5 fused-append recovery, 4 steady-state performance, 22 GC recovery, and 28
file-store tests (one ignored). QEMU release build and Milk-V Duo compile-only
checks pass. The production file-tree acceptance also passes three boots,
durable hard links, symlinks, recursive removal, GC pressure, cold recovery and
independent powered-off verification. Saved baseline/candidate firmware, hashes, JSONL, source patch,
attribution logs and summary are in `target/storage-metadata-read-20260911/`.

## Bound the batch-publication drain buffer

`PageSink::drain` previously retained its staged pages, allocated another vector
of entry pointers for deduplication, and copied each complete contiguous run
into a second page buffer. Large batches therefore needed an extra contiguous
allocation proportional to their longest write run.

The drain now deduplicates entries in place, preserving the last submitted
value for each page, and uses one reusable buffer of at most 32 pages (128 KiB).
Consumed page boxes are released as the drain proceeds. The staged transaction
itself still occupies memory proportional to its size; this change bounds the
additional page-copy buffer, not total transaction memory. Ascending page order,
write-failure propagation and the caller's existing durability barriers remain
unchanged. A regression covers unordered input, three versions of every page,
gaps between runs, bounded requests and immediate stop after an ambiguous write
failure, with no reads or flushes permitted during the drain.

Against the saved metadata-optimization candidate above, the same QEMU
100-file directory sequence gives 1.013919 / 1.052643 / 1.096679 seconds
(median 1.052643 seconds, previously 1.058010). All retained samples have
identical device read/write bytes, request counts and flush counts. This small
timing difference is not evidence of a throughput improvement: the benefit is
the bounded additional buffer. The baseline is the previous run's saved ELF
and JSONL, not a newly interleaved timing trial. Evidence is saved under
`target/storage-bounded-sink-20260911/`.

Validation passes 184 segment-store unit tests (one ignored), 11 CAS streaming,
5 fused-append recovery, 22 GC recovery, 4 steady-state performance and 28
file-store tests (one ignored). The QEMU three-boot production acceptance,
including GC and independent powered-off verification, and Milk-V Duo
compile-only check also pass. No physical SD device was exercised.

## Rejected experiment: move 4 KiB blob envelopes out of the inline journal

A fresh profile of the saved bounded-sink firmware shows that ordinary 4 KiB
blob writes still append 15 authority records per invocation. Device writes
grow as those inline payloads accumulate. Moving the write-policy cutoff from
16 KiB to 4 KiB routes a 4 KiB logical blob plus its envelope through external
CAS (an unwrapped object of exactly 4 KiB would still be inline).

The experiment uses the same blank image, 4/2 MiB/s and 400/200 IOPS limits,
one VM, one warmup and twelve retained `object-durable-put-get` samples per
version. Each sample publishes unique content and reads it immediately, so
these are hot read-after-write results, not cold SD reads. Samples accumulate
objects in one VM. Baseline and candidate runs were sequential, not interleaved.

| Twelve 4 KiB publications | Existing 16 KiB cutoff | Trial 4 KiB cutoff |
| --- | ---: | ---: |
| Median put | 26.608 ms | 18.468 ms |
| Sum of put times | 493.631 ms | 369.859 ms |
| Median get | 0.258 ms | 3.5995 ms |
| Total device bytes written | 2,359,296 | 1,761,280 |
| Total flush requests | 40 | 40 |

Although writes improve, the approximately fourteenfold hot-read slowdown is
not acceptable as a default small-object policy. The experiment is rejected;
the worktree and index retain the 16 KiB cutoff. Further work should reduce
inline authority append amplification while preserving its small-read path,
or lower external-read CPU overhead before reconsidering the cutoff.

Both variants passed all twelve byte-verifying samples. Object-store tests
pass (77 unit/integration tests and 14 documentation tests), as do the five
fused-append recovery sweeps, including compact small external objects. The
trial firmware, restored-policy baseline, JSONL, summary, rejected source and
decision manifest are retained in `target/storage-inline4k-20260911/`.
The preceding profile is in `target/storage-current-profile-20260911/`;
its 16 MiB timings overlapped a compiler run and must not be used for latency
comparisons. None of these runs qualifies a physical SD card.

The trial's `storage_v2_native` acceptance boots and passes shell checks, but
the overall script exits 1: the powered-off verifier rejects sealed sector 95
with `unknown record kind 9`. Rust defines kind 9 as `ObjectExternal`;
`scripts/persistent-cspace-image.py` does not decode it. This is not a passing
cold-image verification. The rejected raw image and full log are retained with
the experiment, and supporting external records in the independent verifier
remains necessary before relying on that acceptance for this representation.

## External-object support in the independent verifier

The verifier now decodes `ObjectExternal` records, enforcing canonical length,
reserved bytes, nonzero Merkle root, reserved stable IDs and unique transaction
and object identities. Legacy M4 recovery still rejects external records by
default. V2 journal recovery retains their identity separately from bytes;
selected external objects are materialized only from fully verified CAS content
with the matching hash algorithm, object kind, length and root. Existing exact
authority-to-CAS mapping and quota checks still apply. Unselected historical
objects may lack content after collection without gaining authority.

The unchanged QEMU image rejected above now passes the complete powered-off
CLI verifier. Flipping a byte in its external Blob content is rejected. The
migration verifier selftest passes 25,120 cases, including missing/mismatched
CAS identities, malformed external metadata, duplicate IDs, legacy rejection
and all 512 strict byte prefixes of an external record. The existing 19-record
legacy strict-prefix suite also passes. Evidence is saved in
`target/storage-external-verifier-20260911/`.

This closes the offline parser gap; it does not reverse the rejected 4 KiB
cutoff experiment or change runtime durability or storage policy. The image was
reverified offline; the complete QEMU acceptance script was not rerun here.

## Cache newly committed small external objects

The runtime's existing hot-read cache previously accepted only recovered inline
bytes. External records contain no inline bytes, so even an immediate read after
a successful external publication repeated CAS resolution and verification.

After successful publication, the exact new stable object may now populate that
cache from its submitted payload. Before insertion, its kind, exact length and
canonical Merkle root must match the committed external record. The cache keeps
the existing 72 KiB per-object, 256 KiB total and 64-entry limits. Reads still
require the current authority generation and boot proof; cold recovery and
ambiguous failures clear the cache. A stale or evicted token falls back to the
normal verified read path. As with the existing inline and page caches, a hot
hit is not fresh evidence about subsequent physical-media damage.

The matched QEMU experiment uses 32 KiB logical blobs, the unchanged 16 KiB
inline threshold, one VM per version, one warmup and twelve retained unique
put/get samples, under 4/2 MiB/s and 400/200 IOPS limits. Baseline and candidate
run sequentially from the same blank template.

| Metric | Before external cache admission | After |
| --- | ---: | ---: |
| Median put | 19.453 ms | 18.9475 ms |
| Median immediate get | 2.747 ms | 0.6995 ms |
| Median complete put/get | 22.1075 ms | 19.665 ms |

All samples verify the returned bytes, and all device counters match per sample.
The approximately 3.9-times get improvement is a hot-read software-path result:
both versions already perform zero device reads in this get phase. It is not a
cold-read or physical SD-card speedup. No format, threshold or durability policy
changes accompany cache admission. Evidence and saved firmware are under
`target/storage-external-hot-20260911/`.

QEMU kernel selftest passes (390 reported checks), including the extended
hot-cache assertions for altered payload, wrong length, wrong kind, inline
records, capacity eviction and clearing weak tokens. Milk-V Duo compilation
also passes. The independent verifier changes from the previous section remain
unchanged; this runtime cache does not participate in powered-off verification.

## Retest the 4 KiB cutoff with external hot-read caching

With verified external cache admission in place, the v2 facade now uses a
4 KiB inline write cutoff. The fixed format limits and existing on-disk
representations are unchanged. Blob envelopes for 4 KiB and 8 KiB logical
payloads use external CAS, keeping their content out of later authority-log
rewrites. Raw objects of at most 4 KiB remain inline.

Each variant uses two fresh QEMU VMs, one warmup and twelve retained unique
put/get samples per VM, with the same blank template and 4/2 MiB/s, 400/200 IOPS
limits. Both variants have the external cache; only the inline cutoff differs.
Variants and sizes run sequentially. Totals below cover 24 retained samples.

| Metric | 16 KiB cutoff | 4 KiB cutoff |
| --- | ---: | ---: |
| 4 KiB median put | 16.5655 ms | 10.6905 ms |
| 4 KiB median hot get | 0.1305 ms | 0.1445 ms |
| 4 KiB total device writes | 4,718,592 bytes | 3,522,560 bytes |
| 8 KiB median put | 49.775 ms | 12.625 ms |
| 8 KiB median hot get | 0.3475 ms | 0.172 ms |
| 8 KiB total device writes | 5,931,008 bytes | 3,620,864 bytes |

For each size both variants issue 80 flushes, and their immediate get phases
perform no device reads. The cutoff reduces total writes by approximately 25%
and 39% respectively. The earlier fourteenfold 4 KiB read regression is gone;
the new 4 KiB hot-get median is still 14 microseconds higher, while its put
median improves about 35%. These are read-after-write results; cold-read
performance has not been quantified by this experiment.

Object-store tests pass (77 unit/integration and 14 documentation tests).
The five fused-append recovery sweeps now also exercise an admitted external
object of 4,097 bytes at every mutation boundary, verifying cold-recovered
contents and old-or-complete-new publication. The existing 16 KiB and 128 KiB
external cut sweeps remain. Firmware, source hashes, JSONL and summaries are
saved under `target/storage-small-cas-20260911/`.

The native Storage V2 QEMU acceptance now passes both boots and the complete
powered-off verifier (including the external record that previously failed
parsing). Milk-V Duo compile-only validation passes. The 4 KiB cutoff is
retained with external cache admission; no real device was modified or tested.

## Reuse pages within a directed CAS read

Directed chunk/range reads now retain the header-validation window for their
content and proof reads. Hash lookups may also hit an existing content window;
a hash miss still uses the separate hash slots so proof traversal cannot evict
payload read-ahead. This avoids rereading the compact Blob's first page after
checking its header, and its final page when content and proof hashes share it.
All windows are per invocation, and all Merkle proof checks remain in place.

A host fault-device regression mounts an 8 KiB compact Blob cold, then reads
its final leaf. Page reads fall from 25 to 24; the shared content/proof page is
read once rather than twice. A first-leaf check also bounds its header page to
one read. Damaging a required proof hash after those successful reads makes
the next invocation fail. These counts exclude mount I/O and count pages,
not necessarily grouped device requests or actual SD commands. No wall-clock
speedup is claimed from this trace.

Validation passes 184 segment-store unit tests (one ignored), 12 CAS streaming
tests, 5 fused-append recovery sweeps, 4 steady-state tests and 28 file-store
tests (one ignored). QEMU release and Milk-V Duo compile-only checks pass.
Source and traces are saved in `target/storage-proof-reuse-20260911/`.
The native QEMU acceptance also passes two boots and independent powered-off
verification. This acceptance validates behavior, not the trace's performance
on the emulated device; its hot cache can already hide redundant page reads.

## Empty logical ranges do not select leaf zero

`read_blob_ranges` previously mapped every zero-length range to leaf zero.
It now emits an empty result in place and preserves the preceding verified
leaf for subsequent ranges. Bounds, object authority, manifest and canonical
header checks still precede this handling; this is not an unchecked early
return. Nonempty requested bytes still require their normal Merkle proofs.

The regression compares an empty batch with two zero-length ranges at offset
zero and EOF: both now perform only two metadata/header page reads in the test
fixture, versus four for the old zero-length range path. An empty range beyond
EOF fails before I/O. A mixed batch reading the second leaf still succeeds
when the unrequested first leaf is damaged, while a request for that damaged
content fails. This is a host page-count result, not a throughput measurement.

Validation passes 185 segment-store unit tests (one ignored), 12 CAS streaming
tests and the QEMU firmware compile check. No fresh QEMU timing or hardware
run is claimed for this boundary fix. Logs and source hashes are saved under
`target/storage-empty-range-20260911/`.

## Match streaming writes to the 128 KiB transfer ceiling

Large-object scratch writes now buffer up to 32 pages (128 KiB), matching the
existing SD/virtio transfer ceiling and the bounded metadata-drain buffer.
This increases payload-buffer capacity by 64 KiB per active streaming writer;
it does not reduce total bytes written or change durability barriers.

Host attribution for a 16 MiB file changes staging from 329 to 201 write
requests, with the same 17,436 KiB and ten flushes. A separate 3 MiB + 17-byte
CAS stream changes from 89 to 65 write requests, with 824 pages and four
flushes in both versions. Partial-failure/cancellation coverage now exercises
all 32 page boundaries of a submitted run. Acknowledged-damaged-write tests
still cover both strict and deferred verification policies.

The matched QEMU workload writes, verifies and deletes a unique 16 MiB file,
using one fresh VM and one warmup per variant. Read/write bandwidth stays at
4/2 MiB/s and read IOPS at 400. Both profiles are reported:

| Write request limit | Retained samples | 64 KiB batches | 128 KiB batches |
| --- | ---: | ---: | ---: |
| 200 IOPS (standard profile) | 3 | 12.955218 s | 13.084967 s |
| 20 IOPS (request-limited control) | 2 | 21.466940 s | 16.009608 s |

Values are median complete-workload times. The standard profile is roughly
unchanged (candidate about 1% slower); the deliberately request-limited
control improves about 25%. The latter was added to distinguish request
overhead from bandwidth limits, not as a claim about a particular SD card.
Device read/write bytes and flush counts match per sample in both profiles.
Standard-profile write requests fall from 337 / 346 / 337 to 209 / 218 / 209.

The baseline is the saved proof-reuse firmware. It predates the empty-range
fix, which this nonempty file workload does not exercise. Candidate firmware
includes that fix and the enlarged streaming buffer. The retained baseline
samples start after an overlapping host-test build finished during warmup.
Twelve CAS streaming tests, five fused-append recovery sweeps, four steady-state
tests, the large-file attribution check, QEMU execution and Duo compilation
validate this change. Evidence is in `target/storage-stream128-20260911/`.

## Use 128 KiB windows for whole-object reads

The sequential verifier's content window now fetches up to 32 pages rather
than 16, still clamped to the declared extent. Directed chunk/range readers
keep read-ahead disabled. The reader adds 64 KiB of content-window capacity;
its separate sixteen hash-page slots are unchanged. These window bounds are
not a bound on total object/output-buffer memory. Merkle validation and the
per-invocation cache lifetime remain unchanged.

The 16 MiB host file-read trace falls from 459 to 331 PageDevice read requests,
with 17,360 KiB read in both versions. Its byte-verifying regression now also
bounds read requests below 400, in addition to the existing byte-amplification
bound. Twelve CAS streaming tests (including corruption and directed-read
bounds), four steady-state tests and the large-file trace pass.

QEMU uses the same unique 16 MiB write/readback/delete workload, one VM and one
warmup per variant. Both variants already use 128 KiB streaming writes. Read/
write bandwidth stays at 4/2 MiB/s and write IOPS at 200:

| Read request limit | Retained samples | 64 KiB read window | 128 KiB read window |
| --- | ---: | ---: | ---: |
| 400 IOPS (standard) | 3 | 13.148333 s | 12.994929 s |
| 40 IOPS (request-limited control) | 2 | 22.491344 s | 19.256930 s |

Median complete-workload times are shown. The standard result is roughly flat;
the deliberately request-limited control improves about 14%. Read/write bytes,
write requests and flushes match per sample. Standard-profile read requests
fall from 458 / 680 / 458 to 330 / 552 / 330. QEMU readback and Duo compilation
pass, but these request limits do not establish performance on a physical SD
card. The change is retained; evidence is in `target/storage-read128-20260911/`.


### Qualifying the larger buffers at 128 MiB RAM (2026-09-11)

The runner now accepts `--memory-mib` (default 512) for both VibeOS and Linux
and records it in each sample. Summaries reject mixing memory sizes within a
workload coordinate; older runner records retain their fixed 512 MiB meaning.
Provisioning remains at 512 MiB, independently of timed Linux runs.

VibeOS RAM is a compile-time board/linker contract, so `--memory-mib 128`
must use firmware built with `--features storage-bench-128m`. This feature
includes the normal storage benchmark and selects 128 MiB in both the BSP
and linker. Passing 128 MiB to an ordinary 512 MiB benchmark ELF is invalid;
an initial mismatched attempt was interrupted and produced no usable samples.
Guest RAM size does not change component allocation quotas.

With the 128 MiB ELF (verified `__heap_end = 0x88000000`), the unique 16 MiB
file write/readback/delete workload passes one warmup plus three retained
samples at the standard 4/2 MiB/s, 400/200 read/write IOPS limits. Complete
workload times are 12.946488 / 13.457037 / 12.949880 seconds, median 12.949880 s.
The previous 512 MiB run with the same storage optimizations had median
12.994929 s. Every device counter matches at each retained seed, including
read/write requests, bytes and flushes. This is a bounded-memory qualification
with roughly unchanged performance, not a measured peak-heap claim or a
physical SD result. It does not establish that larger workloads fit 128 MiB.

The runner's ten host tests pass, including mixed-memory rejection. Firmware,
build log, JSONL samples and summary are in `target/storage-memory128-20260911/`.


### Fill deferred metadata pages in place (2026-09-11)

`write_payload_records_with_header` now fills each sink-owned page directly
instead of building a temporary vector of up to 32 pages and then copying it
into the deferred sink. This removes up to 128 KiB of simultaneous temporary
payload storage and one payload copy in that path. The sink retains the same
page count, physical destinations and zero padding. Its bounded drain, direct
(non-sink) device write batching, and publication barriers are unchanged.
This is an allocation/copy reduction; it does not predict lower SD I/O counts.

Validation: 185 segment-store unit tests pass (one ignored), along with 12 CAS
streaming tests, five fused-append recovery tests and the 16 MiB file trace.
The latter retains 201 stage writes / 10 flushes and 331 read requests.
A 128 MiB QEMU run with one warmup and three retained unique 16 MiB file
write/readback/delete samples passes. Median complete-workload time is
12.956447 s versus 12.949880 s before the change, with every device counter
identical for each retained seed. Throughput is unchanged within this small
sample; the retained benefit is the eliminated temporary allocation and copy.
Evidence: `target/storage-owned-sink-20260911/`.


### Larger files with 128 MiB RAM and bounded stager capacity (2026-09-11)

The owned-sink 128 MiB firmware also passes unique 64 MiB and 256 MiB file
write/readback/delete qualification, one fresh VM and one un-warmed sample per
size, at 4/2 MiB/s and 400/200 read/write IOPS. These are capacity/correctness
observations, not statistically established performance comparisons:

| Logical file | Full workload | Device read bytes | Device write bytes | Read requests | Write requests | Flushes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 64 MiB | 52.245993 s | 73,109,504 | 71,442,432 | 1,694 | 786 | 35 |
| 256 MiB | 223.154691 s | 346,107,904 | 284,672,000 | 14,407 | 3,071 | 104 |

The benchmark generates and checks content in 4 KiB pieces. In particular,
the 256 MiB success demonstrates a file larger than guest RAM without a
whole-file test buffer. Read amplification rises from about 1.09 to 1.29;
its source needs separate attribution. Samples and logs are under
`target/storage-memory64file-20260911/`.

Inspection also found that incremental `Vec` growth gave nominal 3 MiB
persistent chunks 4 MiB capacity. The existing variable-input 20 MiB stager
test, extended to bound both pending and staged capacities, fails before the
fix. The final growth now uses `reserve_exact` at the chunk limit, preserving
incremental allocation for small inputs and the existing four-chunk batching.
This removes up to 4 MiB of spare capacity in a full batch; it does not change
chunk contents, on-disk layout or commit frequency. The large QEMU samples
above precede this capacity-only fix.

After the capacity fix, all 28 file-store tests pass (one ignored). The 128 MiB
QEMU 16 MiB unique file workload passes one warmup and three retained samples;
median full-workload time is 13.143506 s versus 12.956447 s before the fix
(about 1.4% slower in this small sample), and every device counter matches by
seed. Retain the verified capacity bound without claiming a throughput gain.
Before/after host logs, firmware and QEMU samples are preserved in
`target/storage-stager-capacity-20260911/`.


### Segment-proof LRU for larger files (2026-09-11)

A new explicitly ignored 256 MiB host trace reuses the normal unique-file
stage/commit/read/delete test. Its byte pattern differs from the QEMU
SplitMix64 pattern, so compare each environment only with itself. The trace
shows the old 48-entry segment-proof memo repeatedly evicting low-numbered
segments, even when they were recently accessed: eviction was by smallest
physical key rather than recency.

The memo now uses a bounded deque and promotes successfully used proofs.
It still holds at most 48 exact `(segment, generation)` keys, checks the same
checkpoint horizon, and retains the existing GC invalidation and cold-scrub
bypass. Replacing an existing key no longer evicts an unrelated proof.

| Host 256 MiB phase | Old read requests / KiB | LRU read requests / KiB |
| --- | ---: | ---: |
| Stage | 3,207 / 17,240 | 3,351 / 18,392 |
| Commit | 4 / 48 | 4 / 48 |
| Readback | 8,920 / 302,328 | 6,697 / 284,544 |
| Delete | 4 / 48 | 4 / 48 |

Readback repeated-page traffic falls from 29,312 to 8,288 KiB; staging gets
slightly worse, but total reads still fall by 16,632 KiB. Writes and flushes
are unchanged. The ignored large-file regression now requires fewer than
7,000 readback requests and less than 1.1x readback byte amplification.
The LRU unit test covers capacity, recency, replacement, generation/horizon
binding and clear. All 186 segment-store unit tests (one ignored), 12 streaming,
five fused recovery and 28 file-store tests (two ignored) pass, and the large
ignored regression passes separately. Evidence is under
`target/storage-scan-lru-20260911/`.

QEMU 128 MiB, one fresh-VM 256 MiB sample at the standard limits, passes full
readback and deletion: 221.092733 s versus the prior 223.154691 s. Read requests
fall from 14,407 to 13,318 and read bytes from 346,107,904 to 337,186,816 (8.5 MiB
less); write bytes/requests and all 104 flushes match. The earlier QEMU image
also predates the stager capacity fix, so the host before/after trace is the
isolated LRU comparison. A single roughly 0.9% timing improvement is too small
to establish a throughput gain, but the actual device read reduction is
visible in QEMU. No physical SD measurements are implied.


### Recovery qualification after cache and allocation changes (2026-09-11)

The current worktree passes `qemu-test.sh storage_v2_native`: two native V2
boots, object recovery/readback and powered-off verification, with unmanaged
and absent-M4 regions unchanged. It also passes `qemu-file-tree-test.sh` at
128 MiB, covering three boots, hard links, canonical symlinks, recursive
removal, GC pressure and cold recovery. The independent final image verifier
accepts the generation-13 empty tree (one inode, zero dirents) after removal
and maintenance relocation. These correctness gates are not performance
measurements and do not replace the 256 MiB workload's I/O evidence.

The LRU unit test now also checks GC retention against an allocation map:
Allocated entries survive; Retired, Free and out-of-range entries are removed.
The focused test passes. Logs, all three powered-off verification reports,
final file-tree image and SHA-256 are in `target/storage-lru-recovery-20260911/`.


### Exact range-get byte validation (2026-09-11)

The QEMU object-range-get benchmark previously accepted a result by descriptor
identity alone. It now compares the returned bytes with the exact requested
4 KiB leaf slice of the generated payload, including the shorter final leaf.
This check runs after the existing timing endpoint; the content pattern and
operation timing contract are unchanged.

A 128 MiB QEMU run validates a 4,097-byte object at seeds 1/2 (one-byte tail,
then first page), and a 131,073-byte object at seeds 32/33/34 (one-byte tail,
first page, second page). All five records report `ok`. These immediate
put/get samples report zero device reads during get: they qualify the byte
check and warm path, not cold-media random-read performance. Firmware, logs
and JSONL records are under `target/storage-range-bytes-20260911/`.


### Data-cache-evicted range-get diagnostic (2026-09-11)

Use `--workload object-range-get-uncached-data` to evict the kernel object-byte
cache and write-through page cache between put and the timed range read.
Eviction holds the exclusive V2/page-device operation; it neither writes nor
flushes storage and leaves mounted authority/proof metadata intact. Failure
to obtain that operation makes the sample fail closed. This is explicitly
not powered-off recovery or a fully cold metadata cache. The separate workload
name keeps it out of ordinary warm range-get comparison coordinates.

QEMU 128 MiB, standard limits, with 131,073-byte objects at seeds 32/33/34
(one-byte tail, first leaf, second leaf) passes exact byte validation and
performs 17/18/19 get read requests for 114,688/118,784/122,880 bytes. Get times
are 10.957/5.585/5.592 ms; these are single diagnostic samples. The matching
warm reads previously did no device I/O. A 4,097-byte tail/first-page pair
also passes with nonzero device reads. Every get phase has zero writes and
flushes. This establishes a reproducible physical-read path for further
metadata/proof attribution, not evidence about physical SD performance.
Evidence: `target/storage-uncached-range-20260911/`.


### Coalesce the immutable segment trailer read (2026-09-11)

A descriptor-chain scan now reads the contiguous summary body/seal and final
segment body/seal as one 16 KiB request instead of two 8 KiB requests. A constant
assertion binds their adjacency; both record pairs are independently decoded
and verified as before. The successful-path bytes and 16 KiB total buffer
allocation remain unchanged. On malformed summary input the new request may
also fetch the final-seal pair before rejecting the summary, but cannot
publish or authenticate an invalid result.

All 186 segment-store unit tests (one ignored), 12 streaming, five fused
recovery and 28 file-store tests (two ignored) pass. QEMU 128 MiB repeats the
same data-cache-evicted range samples as the preceding diagnostic:

| Object bytes / requested leaves | Old get requests | New get requests | Get read bytes |
| --- | --- | --- | --- |
| 4,097 / tail, first | 14, 14 | 12, 12 | 102,400 each |
| 131,073 / tail, first, second | 17, 18, 19 | 15, 16, 17 | 114,688 / 118,784 / 122,880 |

All five exact-byte validations pass; read bytes, workload writes and flushes
match by seed. The two-request reduction per get is visible on QEMU, without
claiming a physical SD timing improvement. Evidence is preserved under
`target/storage-trailer-read-20260911/`.


### Coalesce the segment header and first descriptor (2026-09-11)

For a referenced sealed segment, the two header pages are immediately followed
by the first descriptor pair. The scan now fetches all four together, with a
compile-time adjacency assertion. Later descriptors reuse the second half of
this buffer and are still read at their exact positions; no intervening payload
pages are fetched. Peak page-buffer storage matches the old header-plus-current-
descriptor allocation. A corrupt header/empty segment may cause two extra pages
to be fetched before rejection, without changing validation or publication.

The same 186 unit, 12 streaming, five fused recovery and 28 file-store tests
pass. QEMU data-cache-evicted range-get with identical seeds confirms another
two-request reduction per sample: 4,097-byte objects now use 10 get requests;
131,073-byte tail/first/second reads use 13/14/15. All five byte checks pass,
with read bytes, writes and flushes unchanged. Together with trailer coalescing,
this saves four requests versus the initial uncached-data baseline (14 and
17/18/19 respectively). This is an I/O-count result, not a physical SD timing
claim. Evidence: `target/storage-header-read-20260911/`.


### Repeated request-limited range comparison (2026-09-11)

To test whether coalescing segment headers/trailers translates into latency,
compare the pre-coalescing `storage-uncached-range-20260911/candidate.elf` with
`storage-header-read-20260911/candidate.elf`. Each variant uses two fresh
128 MiB VMs, one warmup and eight retained samples per VM, 131,073-byte objects,
seed 32, 4/2 MiB/s read/write bandwidth, and 20/200 read/write IOPS. Runs are
sequential with no concurrent builds or host tests. Workload remains
`object-range-get-uncached-data`, retaining mounted metadata as documented.

| Median metric | Before | After |
| --- | ---: | ---: |
| Get, all 16 retained samples | 914.211 ms | 711.410 ms |
| Put + get, all retained samples | 960.780 ms | 765.849 ms |
| Get, VM 0 | 914.211 ms | 692.865 ms |
| Get, VM 1 | 913.772 ms | 712.447 ms |

All records pass exact byte checks. Each paired get saves exactly four read
requests; get read bytes and workload write bytes/requests/flushes match by
seed. Get median improves about 22%, and full-workload median about 20%.
Both VM groups agree on direction. Samples within a VM share evolving store
state, so they are paired workload observations, not 16 independent VM trials.
The intentionally low request limit establishes a QEMU request-limited benefit;
it does not predict performance at normal limits or on a physical SD card.
JSONL records, runner logs and per-seed comparison are in
`target/storage-range-iops-20260911/`.


### Standard-limit range comparison with reversed run order (2026-09-11)

Repeat the preceding pre/post-coalescing comparison at the usual 400 read IOPS
(4/2 MiB/s, 200 write IOPS, same 128 MiB RAM, workload, size and seeds). An
initial before/after pair of two-VM runs gave inconsistent VM-level directions,
so add after/before runs to balance ordering. Each variant now has four fresh
VMs and 32 retained samples, with one warmup and eight samples per VM. No
compilation or host tests run during sampling.

| Pooled median | Before | After |
| --- | ---: | ---: |
| Get | 5.1415 ms | 5.0340 ms |
| Put + get | 58.1755 ms | 58.5150 ms |

Two paired VM get medians improve and two worsen; pooled changes are small.
Treat normal-limit latency as approximately flat in this experiment, rather
than asserting a general speedup from the 20-IOPS result. All 32 paired samples
still save four get requests with identical get read bytes and workload writes/
flushes, and all exact-byte checks pass. The reproducible benefit remains fewer
requests and lower latency when request rate is the bottleneck. Samples within
a VM are not independent VM trials. Evidence and all per-VM medians are in
`target/storage-range-standard-20260911/balanced-summary.json`.


### SD command-path compatibility of coalesced reads (2026-09-11)

The Duo production file-tree firmware compiles with the current storage read
coalescing (`cargo check --release --features file-tree` from its firmware
directory). The SD backend forwards multi-sector reads to the SDHCI driver's
CMD18 path; the transfer ceiling is 256 sectors / 128 KiB, so the coalesced
16 KiB metadata request is 32 sectors within that limit.

A new SDHCI host test checks 4/16/128 KiB requests publish CMD18 with exact
8/32/256 sector counts and perform the existing abort on the fake device's
interrupt error. The full driver suite passes. Plain MMIO memory cannot emulate
write-one-to-clear interrupt status, so this validates command setup and error
handling, not successful transfers on physical media. The board wrapper still
falls back to single-sector CMD17 for the session after a CMD18 failure; in
that mode, fewer upper-layer requests need not reduce SD command count.
No hardware policy or fallback was changed. Logs:
`target/storage-sd-read-contract-20260911/`.


### Admit the thousand-file batch within bounded pin storage (2026-09-11)

A host reproduction of 1,000 staged 4 KiB files in one transaction failed with
`Capacity(Metadata)` at the old 1,024 runtime-root-pin capacity. The same test
passes with 2,048 slots, including a fresh mount and checking all 1,000 file
contents. An open namespace pins file stream tails as well as transient tree
nodes, so the file count alone is not the required pin count.

Simply enlarging the by-value array caused the QEMU kernel to hit its guarded
stack during boot. Root/reader slot arrays now have fixed-length boxed storage,
initialized incrementally via checked heap allocation. Pin acquisition still
never grows the arrays; reservation, owner cleanup and generation validation
are unchanged. On the 64-bit host the registry handle is 56 bytes and backing
slots use 153,600 bytes, versus 79,912 bytes for the previous inline 1,024-root
registry: about 72 KiB additional storage per runtime. A test bounds both the
handle size and total allocation. The failed boot log is retained as evidence
of why heap initialization is required.

The guest benchmark now admits 101–1,000 files only when each is at most 4 KiB;
its existing <=100-file behavior and transaction edit guard remain. A fresh
128 MiB QEMU VM completes one `file-batch-create`, 1,000 x 4,096 bytes, seed 32,
at the usual 4/2 MiB/s and 400/200 read/write IOPS limits. Complete commit time
is 8.934386 s, with 151 write requests / 18,096,128 bytes, eight flushes and
one read request / 24,576 bytes. This benchmark shares one generated payload
between files; it is not a unique-content-per-file result. It verifies commit
success; the independent host test supplies all-file cold-content validation.
One fresh-VM batch does not qualify repeated accumulation of 1,000-file batches.
No new Linux ratio is inferred from the historical table.

After heap initialization, 187 segment-store unit tests (one ignored), 12
streaming, five fused recovery, 28 file-store tests (three ignored) and the
explicit thousand-file recovery test pass. Duo production file-tree compilation
also passes. Evidence is in `target/storage-batch1000-20260911/`.

The production file-tree QEMU gate also passes all three boots after this
change: hard/symbolic links, recursive removal, GC pressure, cold recovery and
powered-off independent verification. Its boot logs and verifier reports are
included in the same evidence directory.


### Deduplicate small payloads before staging batch scratch (2026-09-11)

The trusted batch staging path now detects an identical payload already staged
in the same batch before allocating or writing another scratch extent. The
lookup is bounded to inputs at most 256 KiB; it computes the ordinary Blob
Merkle descriptor and matches kind, length, root and reference codec. It reuses
the first entry's manifest while retaining a distinct predicted object ID and
ObjectMapping for every input. The first copy still follows the normal staging
and publication protocol. No additional payload cache or quota bypass is added;
this existing trusted staging API does not take a principal quota reservation.

The thousand-file shared-content host test drops from 17,560 KiB / 151 writes /
eight flushes to 1,464 KiB / 21 writes / four flushes, and cold mount verifies
all files. Its regression now bounds writes below 2 MiB and flushes at four.
The mixed-batch test covers unique equal-sized content, small in-batch repeats,
a repeated already-committed blob and a large blob, and asserts distinct object
identities. A dedicated fault test cuts every publication mutation with three
failure modes, checks all-or-nothing cold recovery and re-stages/readbacks the
same mixed duplicate batch. Both pass, along with 187 pre-existing unit tests,
12 streaming, five fused recovery and 28 file-store tests. The new power-cut
test runs separately. The 16 MiB unique-file control retains 201 stage writes /
17,436 KiB / ten flushes; its readback byte count remains 17,360 KiB. Duo
production file-tree compilation passes.

One matching fresh 128 MiB QEMU sample, 1,000 x 4 KiB files sharing one payload,
seed 32 and standard 4/2 MiB/s, 400/200 IOPS, reports:

| Metric | Before early dedup | After |
| --- | ---: | ---: |
| Single-transaction workload | 8.934386 s | 0.864106 s |
| Write bytes | 18,096,128 | 1,613,824 |
| Write requests | 151 | 21 |
| Flushes | 8 | 4 |

The approximately 10x observed time difference is for this duplicate-content
qualification sample; it is not a general unique-file or physical-SD speedup.
The reduction in flushes follows fewer scratch segments, with the existing
publication barriers preserved. Evidence: `target/storage-batch-early-dedup-20260911/`.

The unique-content control stages 100 distinct 4 KiB files in one transaction
and verifies every file after cold mount. Twelve host test runs alternate early
dedup enabled / disabled / disabled / enabled in groups of three. Both variants
issue 33 writes / 3,120 KiB, four flushes and four reads / 48 KiB before cold
recovery. Median measured commit time is 11.108 ms enabled versus 10.221 ms
disabled (8.7% higher). These are host test timings, not QEMU or SD latency;
the extra descriptor hashing has a measurable cost in this unique-input control.
The shared-content speedup above must not be generalized to unique inputs.
The ignored `unique_file_batch_commit_and_cold_recovery` test shares the
thousand-file test fixture and reports staging-plus-commit and commit-only
timing, excluding fixture construction and cold verification. This control
qualifies 100 unique files, not 1,000 unique files. Logs and summary are in
`target/storage-batch-unique-control-20260911/`. The temporary disabled guard
used for the control has been restored; production retains early batch dedup.

### Rejected sampled-content filter (2026-09-11)

A 24-byte head/middle/tail rejection filter was evaluated before the full
in-batch content hash. It preserved full-key authentication and passed all 188
unit tests, including a single-byte difference outside the sampled regions,
empty/short duplicates, distinct object identities and publication power cuts.
However, it did not demonstrate a latency benefit. Alternating host groups
(enabled / disabled / disabled / enabled, three samples each) measured commit
medians of 15.023 versus 12.100 ms for 100 unique 4 KiB files, with substantial
between-group variation. A larger 100 x 128 KiB control measured 35.086 versus
31.500 ms. Both variants retained identical I/O: 33 writes / 3,120 KiB / four
flushes for 4 KiB files, and 138 writes / 16,004 KiB / seven flushes for 128 KiB
files. All files passed cold recovery. These are host timings, not SD results.

The filter and its per-entry memory cost were removed from production. The
expanded correctness cases and ignored
`unique_128k_file_batch_commit_and_cold_recovery` control are retained. Evidence
is in `target/storage-batch-sample-filter-20260911/`; its `candidate.elf` is a
compiled but rejected experiment, not a qualified QEMU performance result.

### Unique-file batch QEMU control (2026-09-11)

`file-batch-create-unique` creates distinct deterministic content using the
SplitMix64 offset pattern, commits one transaction, and validates every byte of
every file through its reader. Its timed scope includes generation, staging,
commit and full readback. It has a separate workload name from the existing
shared-payload, commit-only batch test. The guest bounds it to 100 files and
128 KiB per file (nonempty input); this does not qualify 1,000 unique files.

Eight fresh 128 MiB QEMU runs use seed 32, 4/2 MiB/s and 400/200 IOPS. At each
size the order is early dedup enabled / disabled / disabled / enabled, one
sample per VM, without warmups. All pass full readback:

| 100-file workload | Enabled median | Disabled median | Reads | Writes | Flushes |
| --- | ---: | ---: | ---: | ---: | ---: |
| 4 KiB per file | 2.691077 s | 2.624491 s | 476 / 2,691,072 B | 34 / 3,223,552 B | 4 |
| 128 KiB per file | 17.824328 s | 17.609923 s | 3,600 / 15,237,120 B | 138 / 16,416,768 B | 7 |

Each row's I/O is identical across all four runs. Two samples per variant do
not establish a small timing regression or speedup. The full-workload medians
are about 2.5% and 1.2% higher with early dedup; the duplicate-content benefit
must still not be generalized to these inputs. The Raw file-data reader calls
`get_blob_chunk` per 4 KiB, unlike the batched whole-node Stream reader. This
is a candidate for reducing sequential read requests; these aggregate counters
do not independently attribute every request to that path.

Evidence and both ELF hashes: `target/storage-qemu-unique-batch-20260911/`.
The disabled guard was restored and the standard target ELF restored from the
enabled build. These tests validate in-boot readback, not cold remount or SD
hardware performance; the host unique-file controls separately cover cold
recovery.

### Read authenticated payloads in bounded page runs (2026-09-11)

The unique batch investigation traced the request count below the file reader:
fused content uses the FS Stream codec and already reaches whole-node reads,
but `read_pointer_payload_after_scan` fetched its payload one page at a time.
An explicit sequential reader API did not change the QEMU I/O counts and was
removed, including its WASI and shell call-site changes. That rejected
experiment is recorded in `target/storage-raw-read-batch-20260911/`.

The payload reader now issues runs of at most 32 pages (128 KiB) directly into
the final byte allocation using safe array slices. Only a partial final page
uses the previous one-page temporary buffer. No additional recovery workspace
or data cache is introduced. Pointer/extent binding, exact page count and full
payload SHA-256 validation precede exposure of the result; media errors still
discard the incomplete result. The on-disk format and write barriers are
unchanged. This benefits existing whole-payload consumers without a new file
reader API.

Fresh 128 MiB QEMU samples use the same 100-file unique workload, seed 32,
4/2 MiB/s and 400/200 IOPS. Each size runs before / after / after / before:

| Size per file | Before median | After median | Read requests before / after |
| --- | ---: | ---: | ---: |
| 4 KiB | 2.722473 s | 2.719284 s | 476 / 476 |
| 128 KiB | 17.704007 s | 12.441084 s | 3,600 / 500 |

All eight samples pass full readback. The 128 KiB workload has 86.1% fewer
read requests and about 29.7% lower observed median total time. Each variant
has two fresh-VM samples; this is not a physical-SD latency claim. Read bytes
(15,237,120), write bytes (16,416,768), write requests (138) and flushes (seven)
are identical for the 128 KiB workload. The 4 KiB counters are also unchanged.

All 188 segment-store unit tests pass, including post-read content corruption
and publication fault tests. The 100 x 128 KiB unique host cold-recovery test
passes, and Duo production file-tree compilation passes. Logs, ELF hashes and
summary: `target/storage-payload-read-runs-20260911/`.

The production file-tree QEMU gate also passes all three boots after this
change: hard links, symbolic links, recursive removal, GC pressure, cold
recovery and powered-off independent verification. Its boot logs and verifier
reports are included in the same evidence directory.

### Batch authority snapshot reads during recovery (2026-09-11)

`read_pointer_authority_payload` now uses the same bounded 128 KiB direct-read
helper as ordinary payloads. Each extent fills a slice of the final, pre-reserved
snapshot buffer instead of allocating a second extent-sized buffer and copying
it. The existing maximum snapshot size, extent-chain checks, each extent's
SHA-256 and the final chain hash are retained. No larger recovery budget, extra
cache or on-disk change is required.

The host `large_object_append_and_cold_recover` fixture appends three distinct
1 MiB objects and recovers a multi-extent authority chain spanning segments.
Its counting device now reports cold mount and subsequent authority recovery
separately. A control restores only the old per-page authority I/O loop:

| Phase | Per-page control requests | Batched requests | Read bytes, both |
| --- | ---: | ---: | ---: |
| Cold mount | 2,031 | 266 | 9,695,232 |
| Subsequent authority recovery | 66 | 66 | 3,514,368 |

Cold mount issues 86.9% fewer reads in this fixture. The regression requires
fewer than 512 cold-mount requests and still checks recovery of all three
objects. This is host device-call attribution, not measured SD latency or a
QEMU boot-time speedup. The control keeps the new allocation layout to isolate
I/O grouping and is removed after the comparison.

All 188 unit tests and five fused append recovery tests pass, including the
multi-extent publication path. The cold recovery fixture passes again with
the request-count guard enabled. Evidence:
`target/storage-authority-read-runs-20260911/`.

Duo production file-tree compilation and the three-boot QEMU file-tree gate
also pass, including GC pressure, cold recovery and powered-off independent
verification. Their logs and boot verifier reports are in the same directory.

### Payload read failure boundaries (2026-09-11)

The shared direct-read helper now has a regression covering ten lengths: empty,
single-byte, page tails, exact pages, the 128 KiB boundary, and two full runs
plus a partial page. It verifies contiguous addresses, exact page coverage and
the 32-page request ceiling. For each request in each nonempty case, a fake
device writes the first page of the transfer and then reports an error. All
15 injected failures propagate without issuing later requests; retrying with
the failure removed returns all expected bytes. This qualifies error handling
of the helper, not cancellation or a physical device's DMA behavior.

The new test and the SDHCI 4/16/128 KiB multiblock command-size contract test
pass. No production behavior changed in this validation step. Evidence:
`target/storage-payload-read-errors-20260911/`.

### Preserve read runs through device views (2026-09-11)

`SpanSnapshotDevice` and `SinkOverlayDevice` now forward consecutive uncached
pages as a single `read_pages` call. Previously the trait default split each
request back into single-page reads. Buffered pages are copied directly;
overlapping snapshot spans retain first-span priority and repeated sink writes
retain last-write priority. No buffer, cache budget or durable format changes.
The inner device still enforces its transfer limit. Partial-transfer errors stop
the request sequence immediately.

The new regression covers mixed cached/missing spans, overlapping snapshots,
repeated sink writes, fully cached and fully missing requests, empty and
overflowing ranges, and errors at each missing run. It passes along with 190
unit tests, five fused recovery tests, Duo file-tree compilation and the
three-boot QEMU file-tree gate with offline verification.

The host steady-state replacement attribution test exposed an existing limit:
both the optimized path and a per-page forwarding control fail on append index
39 (the 40th append) with `Gc(MemoryLimit)`. At that comparison point this test
was **not passing**; budgets and workload length were left unchanged.
For the identical 39 successful appends before that failure, read requests are
470 before and 455 after; both read 3,195 pages, write 2,702 pages in 385 requests,
and flush 173 times. GC-classified rounds have identical I/O in both versions,
so this is a modest forwarding benefit, not a demonstrated GC speedup. No
latency or physical-SD performance claim is made.

Evidence, including both failure logs: `target/storage-device-view-runs-20260911/`.
The GC phase-budget correction below subsequently resolves this failure.

### Account for the mounted-state release before GC relocation (2026-09-11)

The 40th-append failure came from the relocation workspace preflight: it
combined 1,224,140 retained bytes and 901,482 transient bytes against the default
2,097,152-byte recovery ceiling, exceeding it by 28,470 bytes. This included
the original `self.mounted` copy even though the protocol drops that copy before
relocation allocates its workspace. The local planning state remains live.

GC now preflights the relocation and post-relocation phases using the retained
bytes after that already-scheduled release. The preflight does not modify the
current ledger or drop the mounted state: ordinary planning allocations remain
fully charged, and a rejected preflight leaves the current mounted state intact.
The actual drop and ledger release still occur immediately before relocation.
Both operation workspace bounds, overflow checks and the configured limit are
retained. This corrects a conservative lifetime estimate; it does not claim a
measured reduction in allocator RSS.

`steady_state_replace_attribution` now completes all 40 original appends with
the unchanged 2 MiB ceiling, including GC on append index 39. No workload was
shortened. A ledger regression checks projected peak accounting, unchanged
current charges, rejection of impossible releases/overflow, and the requirement
to perform a real release before reusing memory in the current phase.

All 191 unit tests, five fused recovery tests and four performance attribution
tests pass. Duo file-tree compilation and the three-boot QEMU file-tree gate
also pass, including GC, cold recovery and powered-off verification. Evidence:
`target/storage-gc-phase-budget-20260911/`. This qualifies the original failing
workload, not indefinite append growth or physical-SD performance.

### Bound GC planning tables to the frozen catalog (2026-09-11)

Extending the steady-state fixture to 128 appends exposed another budget stop
at index 49, after the earlier index-39 correction. GC reserved mark tables for
the configured maximum 4,096 objects and blobs even when the frozen catalog
contained far fewer entries. Mark object/blob capacities now use the actual
catalog lengths, bounded by the configured ceiling and a one-entry empty-case
minimum. Valid traversal cannot discover more distinct catalog identities;
missing/stale references still fail closed. The preflight uses these same
capacities. Root and per-object child limits are unchanged.

Separately, computing authority snapshot size for GC no longer clones and
encodes the complete snapshot. A checked, allocation-free frozen-format size
helper is shared with validation/encoding; generation changes do not change
table widths. Ordinary, external-root and relocated snapshots are tested
against their actual encoded lengths. Actual publication still performs the
normal encoding and authentication.

The default steady-state regression is extended from 40 to 50 appends, keeping
the 2 MiB budget and normal-append I/O/flush guards. It passes. Longer probes can
set `VIBEOS_STEADY_APPEND_COUNT=128`; the 128-append probe now completes 59
appends and fails at index 59 with `Gc(MemoryLimit)`. That probe remains failing,
not an indefinite-growth qualification. Its original and updated failure logs
are retained in `target/storage-gc-catalog-sized-20260911/`.

All 191 unit tests, five fused recovery tests and four performance attribution
tests pass, with an additional explicit 50-append run. These changes reduce
planning allocations; no new timing or physical-SD speedup is claimed.

The three-boot QEMU file-tree gate and Duo file-tree compilation also pass;
boot logs and offline verifier reports are in the same evidence directory.

### Release GC root snapshots and avoid verifier state clones (2026-09-11)

The 128-append probe still reached `Gc(MemoryLimit)` at index 59 after the
catalog-sized mark change. Relocated blob verification cloned the entire
mounted state just to change its generation bounds. It now passes a Copy-only
`ManifestReadContext` containing store identity, admitted segment count and
generation bounds through the existing verifier. Descriptor checks, header
validation, payload reads and Merkle verification remain unchanged; the context
cannot create an authorized handle. The memory bound continues to charge the
separate relocated authority value, which remains live during root encoding
and readback.

The captured root list also remained allocated after marking, though relocation
only needed its count. GC now saves that count, releases the allocation charge
and drops the list before loading manifests. This list owns copied identifiers,
not pins; the mark retains the resolved identities and the pin registry remains
responsible for their lifetime. No configured memory ceiling is increased.

The default attribution regression is extended to 64 appends and passes with
the same 2 MiB recovery ceiling and I/O guards. All 191 unit tests, five fused
recovery tests and four attribution tests pass. The final 128-append probe
completes 69 appends, then fails at index 69 with `Gc(MemoryLimit)`; it is not a
passing long-growth result. No new latency or physical-SD speedup is inferred.

Duo compilation and the three-boot QEMU file-tree gate pass, including GC,
cold recovery and offline verification. Evidence and the remaining failure:
`target/storage-gc-workspace-lifetimes-20260911/`.

### Distinguish legacy inline and external-content steady-state growth (2026-09-11)

The original steady-state fixture uses `encode_object_transaction`, adding the
complete 4 KiB payload to the logical authority history at every append. Its
128-append budget failure therefore measures growing legacy inline history.
The new `steady_state_external_attribution` fixture uses the existing external
object record plus an authenticated attached CAS payload. It defaults to 128
appends; the inline fixture remains at 64, and either accepts the explicit
`VIBEOS_STEADY_APPEND_COUNT` override. No production encoding threshold changed.
This tests the storage primitive with raw 4 KiB payloads, not the object-store
facade's envelope or its threshold selection.

The external fixture verifies every appended payload through its transient
witness. Both fixtures cold-mount after completion and check that ungranted
objects do not become persistent authority. Cold recovery intentionally does
not grant/read the transient payloads. All five attribution tests pass,
including the default 128 external appends under the same 2 MiB budget.

Separate runs at 64 appends, same repeated 4 KiB content and store geometry:

| Metric | Legacy inline | External content |
| --- | ---: | ---: |
| Final logical authority stream | 492,032 B | 66,048 B |
| Written pages | 6,310 | 2,332 |
| Write requests | 711 | 573 |
| Flushes | 295 | 295 |

The external run writes about 63% fewer pages in this host fixture. These are
existing encoding choices, not a new production speedup. Append counters include
the harness's common initial format/import costs; external readback verification
is counted separately and excluded from the table. No timing or SD latency
comparison is inferred. The legacy 128-append failure at index 69 is unchanged
and remains recorded; passing the external workload does not resolve it.

Evidence: `target/storage-steady-encodings-20260911/`. This validation step changes
only the attribution harness and documentation.

### QEMU sustained object publication exposes a capacity failure (2026-09-11)

Run the current `storage-bench-128m` ELF with one 128 MiB QEMU guest, a fresh
blank image, 4 KiB `object-durable-put-get`, seeds 32 onward, and 128 requested
samples. Throttles are 4 MiB/s read, 2 MiB/s write and 400/200 read/write IOPS.
The kernel uses its existing 64 MiB recovery budget; this is not the host
fixture's 2 MiB ceiling. Each operation publishes a distinct Merkle-encoded
object, retains its live capability and verifies immediate readback. The
encoded envelope exceeds the facade's 4 KiB inline cutoff. No cold recovery
or physical SD timing is qualified by this probe.

Both runs complete 107 verified operations and fail at zero-based index 107
(the 108th publication, seed 139). The diagnostic replay reports:

```
bench-detail authority append error: Cas(Store(Capacity(CleanerReserve)))
```

The facade exposes this as `Store(Corrupt)`. That mapping is not evidence of
media corruption. This remains an unresolved capacity failure, not a passing
128-operation run. The initial runner was interrupted after recording the
failure because it continued waiting on the invalidated service; the replay
stops automatically and returns exit status 1.

Three-flush operations write 135,168–249,856 bytes for 4,096 content bytes
(33–61x device write amplification). Growth operations occur every 11 samples
through index 99, with increasing read traffic. At index 102 the serial log
confirms foreground GC: 608 reads, 102 live objects/blobs and eight reclaimed
segments. The whole publication at that index performs 39 flushes, reads
6,242,304 bytes and writes 6,303,744 bytes; put latency is 5.410 s in the first
run and 4.650 s in the replay. Immediate get phases issue zero device reads,
so these results do not measure cold-get performance.

Code inspection identifies two capacity assumptions for follow-up: foreground
admission checks the free-segment count, while blob staging requires a
contiguous free run; the authority append only retains a retry import when
free segments are at most cleaner reserve plus six. The logs do not yet prove
which condition causes the failure. Do not treat raising the memory budget
or relaxing the cleaner reserve as a demonstrated fix. The sample's authority
shape fields describe a cached view and must not be used as current allocator
occupancy; use maintenance diagnostics for that purpose.

The runner now accepts optional `--serial-log PATH` and `--stop-on-failure`.
The former preserves raw bytes as they are consumed, including diagnostics
before an incomplete record; the latter saves the first non-ok record, halts
and cleans up the guest, skips remaining VMs and returns 1. Default behavior
is unchanged. Eleven runner tests pass, including fragmented-marker and EOF
transcript retention; the failed replay exercises the actual QEMU stop path.

Evidence: `target/storage-qemu-object-steady-20260911/` contains the exact ELF,
both JSONL runs, replay serial log, summary and runner test output. This step
changes benchmark tooling and documentation, not production storage behavior.

### Reuse isolated free segments for object publication (2026-09-11)

The diagnostic replay confirms that the 108th 4 KiB publication failed with
22 free segments, two cleaner-reserved segments and 107 live CAS objects.
The data writer requested a contiguous data-plus-metadata run, even though
allocation-map v2 can represent a separately placed metadata carrier. A trial
which merely retained the bounded GC retry under fragmentation completed one
more append, then failed with 32 free segments. That retry trial is removed.

V2 now requires adjacency only for the scratch data segments. Admission still
reserves one additional free segment for metadata above the unchanged cleaner
and root-policy floor. The metadata carrier is selected from free segments
excluding scratch. One helper supplies that exact carrier both to the
pre-write seal-clear protocol and the final publication; allocation transitions
are sorted before validation. Legacy prefix allocation retains its adjacency
rule. No disk format, quota, durability barrier or recovery memory limit changes.

An initial placement-only trial failed the existing GC/cold-mount regression:
preparation still cleared `last_data_segment + 1`, which could be occupied.
That trial was rejected and its ELF/patch retained for diagnosis. The final
implementation uses the shared selector before clearing, so it does not clear
an occupied neighbor. The existing GC/ID-high-water regression now explicitly
requires reuse of an isolated free hole and checks the pinned stream after
three destructive GC rounds and cold mount.

With the same fresh-image, seed, RAM and throttling configuration as the prior
probe, the final QEMU run completes all 128 writes and immediate full readbacks.
This qualifies that sequence, not indefinite growth or physical SD performance.
The first 107 successful operations read the same 104,054,784 device bytes in
9,238 requests as the diagnostic baseline. They write 26,972,160 bytes versus
26,963,968, and perform 402 flushes versus 398: this is a fragmentation/capacity
fix, not a measured reduction in write amplification. The current contiguous
pre-clear hint can miss isolated holes, which safely fall back to the normal
clear/flush/readback protocol; adapting that hint is further performance work.

Validation: 191 unit tests, five fused append/power-cut recovery tests and five
attribution tests pass. The production three-boot QEMU file-tree gate passes
with GC, cold recovery and powered-off verification. Duo `file-tree` compilation
passes; no physical device was accessed. The benchmark-only append error line
now includes actual `StoreInfo`, avoiding reliance on cached authority-shape
counters when diagnosing capacity.

Evidence: `target/storage-qemu-fragmentation-20260911/` includes diagnostic,
rejected placement, retry-only and final ELFs; serial logs/JSONL for diagnostic,
retry and final runs; their hashes, comparison summary, test and boot logs.

### Pre-clear isolated free holes without an extra barrier (2026-09-11)

The independent metadata allocator can reuse isolated free segments, but its
pre-clear hint still selected only a contiguous run. Those holes consequently
fell back to zero-write/flush/readback before each new scratch write. The hint
now selects the first at most four segments free in both the durable base and
the successor allocation maps, including isolated holes. The four-segment
work bound is unchanged; newly allocated and newly freed segments remain
excluded. The writer still reads back the zero seal before using a carried
proof. Legacy allocation skips this v2 pre-clear path as before.

The new regression covers fragmented holes, the four-segment bound, an empty
hint, a single candidate, contiguous space, and exclusion of segments live in
either checkpoint. All 192 unit tests, five fused/power-cut recovery tests and
five steady-state attribution tests pass.

A matched fresh-image QEMU run repeats 128 unique 4 KiB publications with all
live capabilities retained and immediate full readback. Both before and after
use 128 MiB RAM, 4/2 MiB/s read/write limits and 400/200 IOPS; all 128 operations
pass. The before run is the independently placed metadata version documented
above, not the earlier failing allocator.

| Whole-run metric | Before | After |
| --- | ---: | ---: |
| Flush requests | 555 | 533 |
| Write requests | 1,569 | 1,569 |
| Written bytes | 46,424,064 | 46,424,064 |
| Read requests | 9,524 | 9,522 |
| Read bytes | 105,742,336 | 105,734,144 |

This removes 22 flushes (about 4% of the complete run), without changing written
bytes. The final ordinary append uses three flushes instead of four. These
single-run device counters do not establish a physical SD latency speedup or
a reduction in payload/metadata write amplification. Growth and GC traffic
remain included in the whole-run totals.

Evidence: `target/storage-preclear-holes-20260911/` contains the candidate ELF,
its hash and baseline reference, JSONL/serial logs, summary and test results.

The production three-boot QEMU gate also passes, including GC, cold recovery
and powered-off verification, and the Duo `file-tree` build check passes.
Boot logs and the compile result are retained alongside the benchmark evidence.
No physical device was accessed.

### Amortize growth remounts on larger provisioned stores (2026-09-11)

The sustained object probe spends substantial I/O in `grow`: growth retains
its strict remount, which re-reads existing state before admitting the new
suffix. The foreground policy previously requested only the device-scaled
22-segment maximum hysteresis regardless of how much data had accumulated.

Capacity policy now lives in the independently testable
`kernel/src/storage_capacity_policy.rs`. Admission hysteresis is the maximum
of the existing scaled hysteresis and the admitted-segment count capped at
one quarter of the provisioned device and 64 segments. The adjacent capability
still bounds the actual suffix, and all growth validation, memory limits,
checkpoint publication and strict remount behavior remain unchanged. Enlarging
admission extends the free bitmap; it does not write every new payload page.
The GC free target and its bounded round policy keep the old hysteresis.
Devices with at most 88 segments retain their prior admission policy, including
the default 16-segment/64 MiB Duo slice. This optimization primarily benefits
larger provisioned regions; it is not a demonstrated gain on that small slice.

Policy tests exhaust the small-device cases and cover growing admission,
unchanged collection targets, monotonic bounds, and `u64::MAX` inputs. A fresh
128 MiB QEMU guest repeats the same 128 unique 4 KiB puts with live capabilities
retained and immediate full readback, limited to 4/2 MiB/s and 400/200 IOPS.
Both versions complete all 128 operations successfully.

| Whole-run metric | Previous pre-clear version | Adaptive admission |
| --- | ---: | ---: |
| Growth operations | 10 | 5 |
| GC rounds | 12 | 8 |
| Read requests | 9,522 | 3,626 |
| Read bytes | 105,734,144 | 39,096,320 |
| Write requests | 1,569 | 1,400 |
| Write bytes | 46,424,064 | 38,957,056 |
| Flush requests | 533 | 477 |

Device reads fall about 63%, writes about 16%, and flushes about 11% in this
matched sequence. Earlier admission changes the later allocation/GC schedule,
so the totals include that effect; they are not per-growth latency figures.
This is one run per version and does not establish a physical SD speedup.

Evidence: `target/storage-growth-amortization-20260911/`, including the candidate
ELF/hash, baseline reference, JSONL and raw serial log, policy tests and summary.

The production three-boot QEMU file-tree gate passes, including GC, cold
recovery and powered-off verification. Duo `file-tree` compilation passes.
These logs and the exact policy source are saved with the benchmark evidence.

### A 16-segment QEMU profile and rejected small-object floor tuning (2026-09-11)

Build from `firmware/qemu-virt` with
`--features storage-bench-128m,storage-bench-small-store` to cap the benchmark's
provisioned v2 region at 16 four-MiB segments plus its anchor area. The initial
eight-segment format grows only within that cap. The runner still uses its
1 GiB data image and the separate raw-block window stays in the same location.
This models the small region's capacity, not the SD controller, card FTL or
physical latency. Default benchmark builds keep the larger provisioned region.

Benchmark kernels now emit `VIBE_STORAGE_BENCH_GEOMETRY` before the shell-ready
banner. The runner validates it and records `storage_v2_provisioned_segments`
in the environment. Object/file summaries reject mixed known sizes, and also
reject mixing known with unknown geometry for one storage-v2 coordinate.
Older ELFs without the marker remain runnable; their geometry is unknown.
Raw-block comparisons are exempt because their separate window did not move.
Twelve runner tests pass, including parsing, malformed/duplicate records and
mixed-geometry rejection.

Small-store workload: `v2-dedup-gc`, 4 KiB, `unique`, seed 32, one 128 MiB VM,
zero warmups, 4/2 MiB/s and 400/200 IOPS. Every sample puts, verifies and revokes
eight objects. Seeds overlap between adjacent samples, so `unique` describes
the eight contents within a sample, not globally unique contents across the
run. Both the 8-sample (64-operation) and 32-sample (256-operation) baselines
pass with the guest reporting exactly 16 provisioned segments.

An experimental runtime change sent small object appends through the existing
scaled free-capacity helper, reducing their foreground floor from nine to six
on this profile. It also passed both lengths, but the longer run did not show
a sustained barrier reduction:

| 256-operation run | Original policy | Rejected scaled-floor trial |
| --- | ---: | ---: |
| GC rounds | 85 | 84 |
| Write requests | 3,773 | 3,758 |
| Written bytes | 91,660,288 | 91,353,088 |
| Flushes | 1,542 | 1,533 |
| Flushes after the first 64 operations | 1,152 | 1,152 |

The short-run improvement was mainly one deferred GC round. The trial is
removed; no production free-floor, quota or cleaner-reserve policy changes
remain from this experiment. The accepted change is the capacity profile and
geometry-aware measurement support. This gives a small-store baseline for
addressing growing metadata write amplification rather than treating a lower
foreground target as a demonstrated sustained optimization.

Evidence: `target/storage-small-store-20260911/` includes baseline and rejected
trial ELFs, short/long JSONL and serial logs, a summary, the rejected patch and
runner test output. `candidate.elf` in that directory is the rejected floor
trial; `baseline.elf` is the accepted small-profile behavior.

A rebuilt default `storage-bench-128m` ELF reports 223 provisioned segments
and passes a put/readback smoke test, confirming that the small-store cap is
feature-scoped. No physical device was accessed or modified in this step.

### Small-region authority compaction and catalog replay preservation (2026-09-11)

Runtime authority compaction now evaluates streams from 128 records on regions
of at most 16 segments. Larger regions and boot compaction retain the 2,048
record threshold. The existing quarter-growth evaluation watermark and minimum
compaction savings remain in force. Runtime compaction preserves ungranted
objects, stable object IDs and ID high-water; it only folds redundant history.

The experiment also exposed a correctness bug: authority replacement reused the
CAS catalog root but reset the checkpoint's catalog replay count/tail. The
in-memory catalog masked the lost delta mappings until remount/growth, after
which GC could fail with `RootDoesNotResolve`. Authority replacement and GC-root
policy publication now preserve the replay chain when retaining the catalog.
GC relocation still resets it when publishing a complete replacement catalog.
Regression coverage forces catalog deltas, replaces authority, remounts, and
reads both old persistent handles and transient witnesses for inline/external
objects. Root-policy synchronization and shared-blob GC also exercise forced
deltas. Checkpoint format and durability barriers are unchanged.

Using the 16-segment profile and the same 32-sample/256-operation workload above:

| Counter | Baseline | Early compaction with replay fix |
| --- | ---: | ---: |
| Write requests | 3,773 | 3,689 |
| Written bytes | 91,660,288 | 75,288,576 |
| Flushes | 1,542 | 1,576 |
| Read bytes | 32,768 | 32,768 |

All operations pass. This trades 2.2% more flushes for 17.9% fewer written bytes;
physical SD latency and wear effects remain unmeasured. Content uniqueness is
per sample, as documented above. The same early threshold on the 223-segment
profile passed 128 retained-object puts/readbacks after the replay fix, but
increased written bytes from 38,957,056 to 43,368,448 and flushes from 477 to 521.
That large-region policy is rejected; the lower threshold is capacity-scoped.

Evidence is in `target/storage-runtime-compaction-20260911/`. `default.elf` is
the failed pre-fix trial; `default-fixed.elf` fixes replay but still uses the
rejected early threshold on large regions. `small-fixed.elf` measures the
corrected early threshold on 16 segments, before adding the capacity guard.
Use the `*-final` artifacts for the final capacity-scoped implementation.

Final qualification: the capacity-scoped `small-final` run passes all 256
operations and exactly reproduces the small-region I/O totals above. The
223-segment `default-final` run passes all 128 retained-object operations and
exactly matches baseline counters (3,626 reads / 39,096,320 read bytes, 1,400
writes / 38,957,056 written bytes, 477 flushes). The 224 selected segment-store
unit/recovery/steady-state tests pass (one existing test ignored). The production
three-boot file-tree gate passes GC, cold recovery and powered-off verification;
Duo file-tree compilation passes. No physical SD device was accessed.

### Reuse the GC checkpoint-slot clear proof (2026-09-11)

The G+2 reuse checkpoint writes the same anchor slot whose old G seal GC
already durably cleared after reader quiescence. Previously publication
cleared that slot again, adding one page write and one flush per collection.
The normal and cold-resume reuse paths now pass the existing exact-zero proof
to publication. Publication rereads the entire seal and requires it to remain
zero before writing the checkpoint body; all other callers still clear their
slots normally. Allocation-segment sealing/flush and payload verification stay
before checkpoint publication. The G+1 relocation checkpoint, reader barrier,
old-seal durable clear, and G+2 body/seal durability barriers remain intact.

A new fault regression corrupts the reuse allocation while acknowledging the
write, in both normal collection and cold G+1 resumption. Both fail before
publishing G+2, preserve a mountable G+1, and subsequently resume to G+2.
The existing every-mutation failure/cancellation matrix also passes.

The 16-segment QEMU workload from the preceding section passes all 256
operations. Against `storage-runtime-compaction-20260911/small-final.jsonl`:

| Counter | Before | After |
| --- | ---: | ---: |
| Write requests | 3,689 | 3,602 |
| Written bytes | 75,288,576 | 74,932,224 |
| Flushes | 1,576 | 1,489 |
| Read requests / bytes | 8 / 32,768 | 8 / 32,768 |

There are 87 GC rounds: each saves exactly one write and one flush. The 5.5%
flush reduction is a QEMU I/O-count result, not a physical SD latency claim.
Evidence, candidate ELFs and transcripts are in
`target/storage-gc-barrier-20260911/`. The earlier `tests.log` exercised a
superseded experiment that moved verification after publication; that ordering
was not retained. `final-tests.log` and `gc-regression-tests.log` cover the
accepted implementation with verification before publication.

The default 223-segment profile also passes all 128 retained-object
puts/readbacks: eight GC rounds reduce flushes from 477 to 469 and writes from
1,400 / 38,957,056 bytes to 1,392 / 38,924,288 bytes. Reads remain
3,626 / 39,096,320 bytes. Both comparisons use the same seed and throttles
as their preceding baselines. The selected 225 host tests pass (one existing
test ignored), including all 23 GC recovery tests. The production three-boot
file-tree gate passes GC, cold recovery and powered-off verification; Duo
file-tree compilation passes. No physical device was accessed.

### Long-running small-region churn exposes authority-history amplification (2026-09-11)

The accepted `storage-gc-barrier-20260911/small.elf` also passes 128 samples,
1,024 put/readback/revoke operations, with the same 16-segment profile, seed 32,
128 MiB RAM and 4/2 MiB/s, 400/200 IOPS throttles. The first 32 samples exactly
reproduce the preceding short-run counters. Full transcripts and window totals
are `small-long.{jsonl,serial.log}` and `small-long-summary.json` in that evidence
directory. This workload's content uniqueness remains per sample, not global.

| Operation window | Written bytes | Flushes | Final authority records |
| --- | ---: | ---: | ---: |
| 1–256 | 74,932,224 | 1,489 | 296 |
| 257–512 | 126,926,848 | 1,472 | 546 |
| 513–768 | 178,130,944 | 1,460 | 829 |
| 769–1,024 | 235,655,168 | 1,448 | 1,341 |

All windows pass, but the final window writes 3.15 times the first window's
bytes. Fewer checkpoint barriers do not bound the metadata growth. Runtime
`compact(false)` retains ungranted logical objects even after callers revoke
their capabilities; GC can reclaim their CAS payloads while the authority
snapshot keeps accumulating and being rewritten. This is evidence of a
remaining sustained-write bottleneck, not a steady-state throughput claim.

The next optimization needs a store-owned proof of runtime liveness before
removing ungranted history. A conservative path can compact at a pre-append
boundary only when the runtime root registry proves there are no live object
pins, retaining all policy-required objects and ID/slot high-water history.
The proof and replacement must share the exclusive mutation epoch; a kernel
scan of object kinds/IDs or an earlier GC count is insufficient. The current
post-append hook already owns the newly minted transient witness, so it cannot
simply enable boot-boundary dropping. Any implementation must preserve active
persistent and transient handles, reject stale proofs, and pass remount,
fault-injection and long-churn comparison before replacing the current policy.
No runtime dropping behavior is enabled by this investigation.

Runtime-quiescence groundwork: `PinRegistry::roots_are_empty` now provides an
allocation-free, bounded seqlock observation. A live or claimed root reports
nonempty; an in-progress writer or concurrent handoff reports `SnapshotBusy`.
Nine pin tests pass, including explicit handoff assertions for this observation
(`target/storage-quiescent-compaction-20260911/pin-tests.log`). This is not a
persistable proof: a subsequent registration can invalidate the observation.
`recover_persistent_authority_recognized(&self, ...)` can construct handles, so
an exclusive mutation borrow alone is not a complete registration exclusion
across shared-runtime store instances. The compaction transaction needs that
exclusion without holding a spin lock across I/O, and must permit creation of
the replacement view only after publication. No caller uses the observation to
drop history yet; no new performance improvement is claimed by this groundwork.

The registry now also provides an internal `EmptyRootAdmissionGuard`: under
the short root-writer lock it checks that every root slot is free and closes
root registration. The owning guard retains no spin lock across suspension;
ordinary and completion-critical registrations return `SnapshotBusy` until
drop reopens admission. Nested closure is rejected. Tests cover live roots,
32 concurrent mint/closure races (exactly one succeeds), cross-thread rejection,
and cancellation of a pending future. All 12 pin tests pass; the preceding full
library run passes 195 tests with one existing ignored test (before adding the
final race test). Duo file-tree compilation passes. Evidence is in
`storage-quiescent-compaction-20260911/admission-*.log` under `target/`.

This guard closes root registration only; it is not a reader-epoch proof or a
license to rewrite authority. It is not yet wired into runtime compaction.
Integration must check reader quiescence and exact authority generation/policy,
keep exclusion through durable publication, then release it before rebuilding
any returned view that itself needs to mint roots. A stale/cancelled/failed
transaction must not accidentally publish a history-pruned view.

The store transaction `compact_unpinned_persistent_authority` is now implemented
but not yet called by the kernel. Its admission guard also requires all reader
slots (including claims) to be free and excludes subsequent reader registration.
The transaction checks exact generation, stream, policy, principal policy and
admitted bindings; derives a compacted stream with preserved high-water state;
and requires an exact policy-revalidated import of those proposed bytes. It
retains existing CAS bindings/external roots and the registration guard through
snapshot publication, then reopens registration before constructing the returned
view. Caller revalidation is followed by a shared-generation check before I/O.

The new inline/external-object regression verifies that a live transient witness
prevents compaction and remains readable; after its release the transaction
removes orphan history, preserves ID high-water and survives remount. Rejected
policy callbacks, wrong replacement bytes and stale generations do not publish.
The selected suite passes 231 tests (one existing ignored); after adding the
final pre-I/O generation recheck, the focused transaction test is rerun. Evidence
is `transaction-suite.log` and `transaction-focused-tests.log`. Kernel wiring,
transaction-specific power-cut/cancellation tests and the 1,024-operation QEMU
comparison remain required before this path can replace the current runtime
policy. There is no new performance claim yet.

### Qualified quiescent-history compaction on small regions (2026-09-11)

The kernel now calls the store-owned quiescent transaction when obtaining the
baseline-policy authority head, before a facade caller encodes its next append.
It is limited to regions of at most 16 segments and at least 128 logical records.
Busy device epochs skip the attempt. Active root or reader pins prevent it;
other external policies and larger regions retain their existing behavior.
The exact shared mutation epoch covers the transaction and publication of the
new runtime view, and rewritten-chain preflight caches are invalidated.

A dedicated fault matrix now injects failures and cancellations at every media
mutation of this transaction. Each cold recovery selects the exact old stream
or the exact complete compacted stream, and registration reopens in every case.
The selected host suite passes 232 tests (one existing ignored test), including
that matrix and live-witness/ID-high-water checks. Evidence is
`target/storage-quiescent-compaction-20260911/integrated-tests.log` and
`transaction-fault-tests.log`.

The qualified 16-segment ELF passes a 128-operation smoke test and the same
1,024-operation churn run used above. All operations put, verify and revoke;
content uniqueness is per sample. QEMU throttles, seed and memory are unchanged.

| Operation window | Previous written bytes | Quiescent compaction written bytes | New final records |
| --- | ---: | ---: | ---: |
| 1–256 | 74,932,224 | 60,497,920 | 70 |
| 257–512 | 126,926,848 | 62,001,152 | 75 |
| 513–768 | 178,130,944 | 62,185,472 | 111 |
| 769–1,024 | 235,655,168 | 60,809,216 | 52 |

Total written bytes fall from 615,645,184 to 245,493,760 (60.1%); write requests
fall from 16,849 to 13,811. Flushes increase from 5,869 to 5,989 (2.0%). Reads
remain eight requests / 32,768 bytes. History and window write volume remain
bounded across this run; the result does not establish arbitrary-duration
behavior or a physical SD latency improvement. Workloads retaining live handles
continue using conservative history retention and cannot assume this saving.
Candidate ELF/hash, short/long JSONL, serial logs and `long-summary.json` are in
the same evidence directory. `small.elf` is the integrated small-profile build.

Final qualification also passes the production three-boot file-tree gate
(including GC, cold recovery and powered-off verification) and Duo file-tree
compilation. A rebuilt default 223-segment benchmark passes all 128 retained
object puts/readbacks and exactly matches its preceding baseline: 3,626 reads /
39,096,320 bytes, 1,392 writes / 38,924,288 bytes, and 469 flushes. Its ELF/hash,
JSONL and `default-summary.json` accompany the small-region evidence. No physical
SD device was accessed or modified.

### Rejected one-append compaction deferral (2026-09-11)

The preceding churn transcript showed two conservative rewrites before each
quiescent rewrite. A trial deferred the conservative rewrite only when an
append first crossed the small-region threshold, giving the next authority
recovery a chance to reclaim orphan history. If pins remained live, the next
append could still run the conservative compactor.

The identical 1,024-operation churn run passed: writes fell from 245,493,760 to
233,197,568 bytes (5.0%), with 16 quiescent rewrites instead of 18 conservative
plus nine quiescent rewrites. GC rounds rose from 350 to 355, offsetting most
barrier savings: flushes only fell from 5,989 to 5,985.

A second, matched 16-segment comparison retained all 128 object capabilities.
Both versions passed and neither ran quiescent compaction, but deferral changed
allocation/GC placement adversely:

| Retained-object counter | Qualified baseline | Rejected deferral |
| --- | ---: | ---: |
| Read requests | 6,487 | 6,955 |
| Read bytes | 32,575,488 | 35,016,704 |
| Write requests | 2,321 | 2,334 |
| Written bytes | 88,788,992 | 90,001,408 |
| Flushes | 745 | 745 |

The 7.5% read-byte and 1.4% write-byte regressions make unconditional threshold
crossing an inadequate scheduling signal. The trial is removed; the kernel
code was compared back to the qualified quiescent-compaction patch (ignoring
only Git hash-abbreviation length). The preceding 60.1% churn-write reduction
remains the accepted implementation. Future scheduling changes should use a
current liveness hint, without treating that hint as authorization to drop
history, and qualify both revoked and retained workloads.

Evidence: `target/storage-compaction-order-20260911/`, including matched JSONL,
serial logs, counter summary, rejected ELF/hash and revert verification.
`small.elf` there is the rejected trial, not the accepted production policy.

### Liveness-aware compaction scheduling (2026-09-11)

The small-region threshold-crossing deferral now additionally requires a
store-owned scheduling hint: the exact new transient witness covers every
observed runtime root, there are no observed readers, and the current authority
has neither durable object bindings nor external persistent roots. Durable
bindings need not occupy runtime pin slots, so they are checked separately.
A foreign witness, a busy root snapshot, failed allocation or extra root rejects
the hint. The hint does not close admission and never authorizes history removal;
quiescent compaction still performs its full guarded transaction. If the hint is
false, conservative compaction runs at its original point.

The helper uses a bounded root snapshot, and the kernel charges its temporary
allocation to the system owner. Tests cover the new witness alone, unrelated
runtime roots, readers, foreign runtime context and an older persistent handle.
The full library suite passes 199 tests with one existing ignored test; after
adding the unrelated-root assertion the two focused quiescent tests pass,
including the transaction fault matrix. Duo file-tree compilation passes.

Both comparisons use the same qualified 16-segment profile, 4 KiB payloads,
seed 32, one 128 MiB VM, no warmups and 4/2 MiB/s, 400/200 IOPS throttles:

| Counter | Qualified baseline | Liveness-aware scheduling |
| --- | ---: | ---: |
| 1,024 revoked-object operations: written bytes | 245,493,760 | 233,197,568 |
| Write requests | 13,811 | 13,675 |
| Flushes | 5,989 | 5,985 |
| Read requests / bytes | 8 / 32,768 | 8 / 32,768 |
| 128 retained-object operations: read bytes | 32,575,488 | 32,575,488 |
| Write bytes | 88,788,992 | 88,788,992 |
| Read / write requests | 6,487 / 2,321 | 6,487 / 2,321 |
| Flushes | 745 | 745 |

Every operation passes. The revoked workload keeps the 5.0% write-byte saving
of the rejected unconditional trial; the retained workload exactly reproduces
baseline I/O instead of regressing. These remain scoped QEMU counter results,
not physical SD latency claims; revoked-workload uniqueness remains per sample.
Evidence is `target/storage-live-compaction-order-20260911/`, including qualified
ELF/hash, transcripts, JSONL, `summary.json`, tests and build logs.

The production three-boot file-tree gate passes GC pressure, cold recovery and
powered-off verification. The accepted scheduling change is retained; no physical
device was accessed or modified.

### Rejected GC padding-read elimination (2026-09-11)

A trial made the normal payload reader return whether the physical final-page
padding was zero, letting GC reuse that observation instead of reading the
last page again. Payload and padding corruption tests still failed before
checkpoint publication, and all selected host tests, Duo compilation and the
trial three-boot gate passed.

However, the matched 16-segment, 128-retained-object QEMU run had identical
physical I/O: 6,487 reads / 32,575,488 bytes, 2,321 writes / 88,788,992 bytes,
and 745 flushes. `CapabilityPageDevice::read_page` already serves the immediate
second tail-page read from its page cache. Removing a logical PageDevice call
did not remove a block-device request on this path. The trial also computed
padding observations for ordinary reads that did not consume them, so it is
not retained without a demonstrated benefit.

Both changed source files were restored exactly to their qualified pre-trial
index state. Evidence is `target/storage-gc-padding-read-20260911/`, containing
the rejected patch, ELF/hash, matched counters, transcript, tests/build logs
and revert verification. `small.elf` there is the rejected trial. Future read
optimization should attribute actual page-cache misses rather than counting
source-level `read_page` calls. No physical SD device was accessed.

### Reuse page-cache buffers (2026-09-11)

`PageCache::insert` now updates an existing entry in place and reuses the LRU
victim's boxed page when the cache is full. Previously both paths allocated a
fresh 4 KiB buffer first (charged as 8 KiB by the kernel allocator). Capacity,
recency, invalidation and cold-proof clearing remain unchanged. Free-capacity
allocation remains outside the lock, followed by a recheck for concurrent
insertion. BTreeMap node allocations are still possible; this is specifically
page-buffer reuse, not an allocation-free cache.

Two host tests extracted from the actual kernel source pass, using a mutex
shim for the kernel spinlock: all 256 eight-page hit patterns, plus allocation
counting, updated contents, LRU victim pointer reuse, clearing/invalidation and
same-key insertion during allocation. These prove sequential behavior and the
allocation recheck; they are not a kernel concurrency stress test.

The matched throttled QEMU run (16 segments, 128 MiB RAM, 128 retained 4 KiB
objects, seed 32) passes every sample. Baseline and candidate both issue
6,487 reads / 32,575,488 bytes, 2,321 writes / 88,788,992 bytes and 745 flushes.
The optimization removes unnecessary page-buffer allocation on the tested
cache paths; no wall-clock speedup or physical SD improvement is claimed.
QEMU benchmark firmware and Duo file-tree compilation pass. Evidence is
`target/storage-page-cache-reuse-20260911/`, including the benchmark ELF,
extracted test harness, test/build logs, transcript and matched counters.
The final source differs from the measured ELF only by formatting and stronger
test-only content assertions; the production cache algorithm is identical.

The production three-boot file-tree gate also passes durable hard links,
symlinks, recursive removal, GC pressure, cold recovery and powered-off
verification. No physical device was accessed or modified.

### Borrow complete payload write batches (2026-09-11)

The direct CAS payload writer and legacy extent writer now share
`write_payload_pages`. Complete-page batches borrow the original payload;
only a batch containing the partial final page allocates a zero-padded copy.
The 32-page request partition and all caller-owned publication barriers remain
unchanged. This removes allocation, zeroing and copying for complete batches;
it does not promise fewer block requests or a smaller worst-case final buffer.
The PageSink-owned path remains unchanged because it needs owned pages.

A focused test covers empty input, byte-offset input, page and 32-page
boundaries, exact request addresses/counts, zero padding, source pointer identity
for complete batches, and ambiguous failure at every request position. The
selected suite passes 233 tests with one ignored, including GC and fused append
recovery. QEMU benchmark firmware builds and Duo file-tree compilation passes.

Matched throttled QEMU runs use the prior page-cache-reuse ELF as baseline:
16 segments, 128 MiB RAM, 8 retained 360 KiB objects, seed 32, the same blank
image and 4/2 MiB/s read/write, 400/200 read/write IOPS limits. All samples pass.
Both runs issue 56 reads / 2,105,344 bytes, 193 writes / 7,360,512 bytes and
49 flushes. This confirms unchanged I/O for this bounded workload; eight
samples do not establish a latency improvement. No physical SD claim is made.
Evidence is `target/storage-borrowed-payload-write-20260911/`, with baseline
and candidate JSONL/transcripts, candidate ELF/hash, tests, builds and summary.

The production three-boot gate passes GC pressure, cold recovery and powered-off
verification, as well as hard links, symlinks and recursive removal. The borrowed
payload change is retained. No physical device was accessed or modified.

### Range-get data-cache attribution (2026-09-11)

The original aggregate range-get timing includes the preceding durable put.
To isolate reads, the following measurements use only `phases.get_*`, after
publication and (in the evicted case) `benchmark_evict_read_data`. That hook
clears hot object bytes and the device page cache, but retains mounted metadata
and proof provenance: this is **not cold boot or cold recovery**.

Each row has four samples per cache mode on the qualified borrowed-payload ELF,
16 segments, 128 MiB RAM, seed 32, no warmups, the same blank template and
4/2 MiB/s, 400/200 read/write IOPS throttle. Each get returns one 4 KiB leaf;
leaf indices follow the existing seed-modulo-leaf-count benchmark rule.
All 32 samples pass, with no get-phase writes or flushes.

| Object size | Evicted get read bytes | Evicted read requests | Warm read bytes / requests |
|---|---:|---:|---:|
| 4 KiB | 100 KiB | 10 | 0 / 0 |
| 128 KiB | 112–120 KiB | 13–14 | 0 / 0 |
| 360 KiB | 144 KiB | 19 | 0 / 0 |
| 1 MiB | 172 KiB | 25 | 0 / 0 |

The 1 MiB result rules out a whole-object physical read for these leaf requests,
but eviction exposes 25–43 times physical read amplification relative to the
4 KiB output. Immediate post-put warm reads hide this cost entirely in this
bounded workload. Source inspection identifies manifest resolution, descriptor
validation, header and Merkle proof reads along the path; these counters do not
yet attribute bytes to each phase, so they do not justify removing any check.
The next read-path investigation should attribute that fixed validation cost
and determine why existing authenticated scan memoization does not eliminate
it on this public capability path, before changing read-ahead or cache capacity.

Evidence: `target/storage-range-attribution-20260911/`, with all eight JSONL
runs, serial transcripts, environment/ELF provenance and `summary.json`.
This round changes measurement documentation only; it makes no latency or
physical SD claim and accessed no real device.

### Range-get physical-page trace (2026-09-11)

A diagnostic ELF temporarily logs only successful physical read misses after
benchmark data eviction. A single 1 MiB / seed-32 range-get passes and reproduces
the uninstrumented run's exact 25 requests / 176,128 bytes. The trace itself
must not be used for latency comparisons. Kernel source was restored exactly
to its pre-instrumentation snapshot; `trace.elf` is diagnostic only.

The segment ABI has 16 anchor pages and 1,024 pages per segment. Reads at
3,088/4,108 (four pages each) and 3,093/3,096/3,099 (two each) scan segment 3's
header/first descriptor, trailer, and remaining descriptors. Reads at
2,064/3,084 (four each) and 2,069/2,327/2,334 (two each) do the same for segment 2.
These match `scan_segment`'s authenticated chain-walk request pattern.
Together they account for 10 requests and 28 pages = 112 KiB, or 65.1% of the
172 KiB get read volume. The remaining 15 one-page requests total 60 KiB and
cover payload/header/proof observations; this trace does not subdivide them.

The public blob API has two proof layers: its envelope header/content/siblings
are logical ranges authenticated again by the CAS Merkle layer. Existing
`VerifiedSegmentScans` misses on these two segments in this first post-publication
read; the trace shows the actual scans rather than merely counting source calls.
Next, investigate transferring already verified segment evidence from successful
publication readback into the runtime memo. Such a change must not retain proof
from failed, cancelled or unpublished writes, and must preserve generation,
GC-retirement and cold-proof invalidation rules. No validation was removed here.

Evidence: `target/storage-range-trace-20260911/` contains the diagnostic patch,
ELF/hash, trace, exact counter reconciliation, pre-instrumentation snapshot and
restore verification. No real device was accessed or modified.

### Confirmed first-read proof cost, not a memo retention failure (2026-09-11)

The proposed transfer of publication readback proofs is inapplicable to the
current kernel profile: `StorageV2Runtime` enables `set_deferred_commit_readback(true)`.
CAS commit skips its full segment readback in that profile. Consequently the
new segment proofs observed missing above have not yet been established;
inserting writer-derived entries would bypass the first media verification.
No such optimization was implemented. This corrects the preceding investigation
hypothesis about reusable commit readback evidence.

A diagnostic run first performs the ordinary data-evicted range read, then
evicts data again and repeats the same leaf, asserting exact bytes and descriptor
equality. Separate `MEMO_REPEAT` counters cover only that second read. Existing
mounted metadata and segment proof memo entries survive the second eviction.

| Object | First evicted read (prior matched baseline) | Repeated evicted read |
|---|---:|---:|
| 4 KiB | 10 requests / 100 KiB | 3 requests / 12 KiB |
| 1 MiB | 25 requests / 172 KiB | 15 requests / 60 KiB |

Both one-sample diagnostic runs pass and repeat reads issue no writes/flushes.
For 1 MiB, exactly the previously attributed 10 segment-scan requests / 112 KiB
disappear: the existing authenticated memo works after first verification.
This is evidence against a memo retention bug, not a new performance gain.
The remaining repeated-read cost is a better optimization target than skipping
first-read segment validation. These measurements do not exercise memo eviction
under a large working set or establish latency distributions.

Evidence is `target/storage-range-memo-proof-20260911/`. Diagnostic JSONL totals
include the extra read, so do not compare their ordinary get/aggregate counters
or timings with baseline; use the separately logged counters and `summary.json`.
The patch, diagnostic ELF/hash, serial logs and exact source restore verification
are retained. Production source was restored, and no real device was accessed.

### Coalesce only a required two-page proof tree (2026-09-11)

A broad experiment fetched proof trees up to 64 KiB after copying out the
content leaf. For 360 KiB objects it reduced range-get requests 19 → 18 with
144 KiB unchanged. For 1 MiB objects it reduced requests 25 → 20 but increased
reads 172 → 180 KiB. The broad policy is not retained: fewer commands alone
would hide additional read amplification and unnecessary proof copies.

The final policy applies only when the tree occupies a separate manifest
extent and its length is greater than one page and at most two. Such a tree
has 128 padded leaves: every proof needs a leaf sibling from its first page
and an upper-level sibling from its second. Reading the two pages together
therefore adds no otherwise-unneeded physical page. Compact envelopes and
larger trees retain demand reads. First-read segment validation and every
Merkle proof verification remain unchanged. Temporary copied tree output is
bounded to 8 KiB; the existing content window holds the prefetched pages.

A structural test enumerates every leaf for all 65–128-leaf geometries; an
integration test cold-mounts and authenticates all 90 leaves of a 360 KiB blob.
The selected suite passes 235 tests, one ignored, including GC and fused append
recovery. QEMU firmware build and Duo file-tree compilation pass.

Matched final QEMU runs (four samples each, 16 segments, 128 MiB RAM, seed 32,
4/2 MiB/s and 400/200 read/write IOPS) all pass. The 360 KiB range-get uses
18 requests / 144 KiB versus baseline 19 / 144 KiB (5.3% fewer read requests).
The 1 MiB control remains 25 requests / 172 KiB, avoiding the broad trial's
extra reads. These are data-evicted get-phase counters, not cold-boot numbers
or a measured physical-SD latency improvement.

Evidence is `target/storage-proof-prefetch-trial-20260911/`: `trial.elf` and
unsuffixed JSONL are the rejected broad experiment; `two-page.elf` and
`*-final.jsonl` are the final bounded implementation. Patches, hashes, matched
summary, tests and build logs are retained. No real device was accessed.

The production three-boot file-tree gate passes GC pressure, cold recovery and
powered-off verification. The two-page-only policy is retained; the broader
prefetch experiment remains rejected.

### Preserve proof sharing across multi-leaf ranges (2026-09-11)

A follow-up host audit exposed a limitation of the two-page coalescing policy:
on a PageDevice without its own page cache, three ranges read the same proof
tree three times (three two-page requests). Prefetch used the content window,
which the next leaf replaced. QEMU's device cache masked the repeated logical
reads, so the earlier physical counter result alone did not cover this case.

Two-page coalescing now applies only to a single-leaf invocation. Multi-range
calls, a single range spanning multiple leaves, and unaligned ranges crossing
a leaf boundary use the existing hash-page LRU. The new test verifies returned
bytes and exact proof-page requests for all four cases: the first three read
each proof page once (two one-page requests); the single-leaf case retains one
two-page request. The three-range uncached-device case falls from 24 KiB to
8 KiB of proof reads. This is a PageDevice-level regression fix, not a claimed
additional physical-I/O saving on the already-cached QEMU backend.

Evidence is `target/storage-proof-batch-audit-20260911/`; `test.log` captures
the pre-fix repeated reads, and the final regression test asserts bounded
reuse. First-read segment validation and Merkle authentication remain unchanged.

The selected final suite passes 236 tests, one ignored. QEMU firmware builds
and Duo file-tree compilation passes. Four matched throttled QEMU 360 KiB
range-get samples all pass and retain 18 physical reads / 144 KiB, exactly the
previous two-page implementation's counters. Thus the single-leaf coalescing
benefit remains while multi-leaf proof sharing is restored. ELF/hash, JSONL,
serial log and `summary.json` are included in the evidence directory.
No real device was accessed; no new physical-SD latency gain is claimed.

The production three-boot gate also passes GC pressure, cold recovery and
powered-off verification. The multi-leaf cache-sharing correction is retained.

### Proof working-set qualification through 4 MiB (2026-09-11)

The uncached PageDevice regression now covers native CAS blobs of 360 KiB,
1 MiB and 4 MiB, with three adjacent ranges, one three-leaf range, a two-byte
boundary-crossing range, one leaf, and 32 descending dispersed ranges. It
computes the union of pages containing required sibling hashes and compares
it with every observed proof-page read, including duplicates. All returned
bytes are also checked. This makes both unnecessary prefetch and repeated
proof reads observable independently of the kernel page cache.

| Native CAS size | Tree pages | One-leaf proof pages / requests | 32 dispersed ranges: proof pages / requests |
|---|---:|---:|---:|
| 360 KiB | 2 | 2 / 1 | 2 / 2 |
| 1 MiB | 4 | 3 / 3 | 4 / 4 |
| 4 MiB | 16 | 5 / 5 | 16 / 16 |

These are proof-region-only host counts, not the public nested-envelope QEMU
get totals above. The largest case reaches the 16-page hash-cache budget;
working sets above that budget are not qualified by this test. Native CAS
geometry differs from the public service's additional blob envelope.

The expanded test also flips a required leaf-level sibling and a required
upper-level sibling for each object size. Each read must fail; restoring the
byte must restore successful exact readback, even with segment proofs memoized.
Evidence is `target/storage-proof-working-set-20260911/`. This round expands
regression coverage and attribution without changing the runtime algorithm.

The focused final test passes all 15 range configurations and six corruption /
restore cases. No physical device was accessed or modified.

### Current large-file scaling checkpoint (2026-09-11)

The current default-capacity firmware, with `storage-bench-128m` (not the
16-segment small-store profile), passes fresh-VM 16 MiB and 64 MiB unique
file-sequential samples. Each sample writes, fully verifies and removes the
file. Seed 14476452505690153217, one VM / one un-warmed sample per size,
128 MiB guest RAM, and the existing 4/2 MiB/s, 400/200 read/write IOPS throttle
are retained. This is a whole-workload observation, not pure write throughput.

| File | Whole workload | Read bytes | Write bytes | Read requests | Write requests | Flushes |
|---|---:|---:|---:|---:|---:|---:|
| 16 MiB | 13.249455 s | 17,850,368 | 18,157,568 | 314 | 213 | 16 |
| 64 MiB | 53.848149 s | 73,154,560 | 71,442,432 | 1,645 | 786 | 35 |

Relative to logical file bytes, read/write amplification is 1.064 / 1.082
for 16 MiB and 1.090 / 1.065 for 64 MiB. The serial transfer estimate
`read_bytes / read_bps + write_bytes / write_bps` gives 12.914 and 51.508 s.
Its proximity to observed elapsed time suggests configured bandwidth dominates
these runs. This estimate is not measured CPU time or a strict lower bound:
QEMU throttling can burst, and flush and execution costs are not modeled.
Reducing a handful of metadata requests is unlikely to transform these
bandwidth-limited large-file results; small-object mutation amplification
and unthrottled CPU attribution remain separate optimization targets.

These single samples neither establish latency distributions nor isolate the
benefit of one recent patch. They refresh current-state correctness and I/O
scaling through 64 MiB; the older 256 MiB result is not a current-ELF rerun.
Evidence is `target/storage-file-scale-20260911/`: ELF/hash, build log, JSONL,
serial transcripts and `summary.json`. No runtime algorithm changed in this
measurement round and no real device was accessed or modified.

### Unthrottled file timing: inconclusive under run-to-run drift (2026-09-11)

An unthrottled 16 MiB write/verify/delete comparison uses the same blank image,
seed 14476452505690153217, 128 MiB RAM, one warmup and three retained samples
per fresh VM. No builds or other agent-started CPU work overlap these runs.
Three alternating pairs compare the historical owned-sink ELF with the current
file-scale ELF; two further opposite-order pairs use the closer quiescent
compaction default ELF. All 40 workloads (10 warmups, 30 retained) pass.

| Pair | Baseline ELF | Baseline median | Current median |
|---|---|---:|---:|
| 0 | owned-sink | 1.789376 s | 1.961283 s |
| 1 | owned-sink | 1.844904 s | 1.920773 s |
| 2 | owned-sink | 1.765495 s | 2.262468 s |
| near-0 | quiescent default | 1.998212 s | 1.742823 s |
| near-1 | quiescent default | 1.673176 s | 1.748661 s |

The same current ELF's run medians span 1.743–2.262 s despite the same seeds
and reproducible device counters. The closer baseline also changes relative
ordering between pairs. Therefore this experiment does not establish a CPU
speedup or a causal regression from the allocation/copy changes. QEMU TCG,
host I/O and scheduling remain in the measurement; removing rate limits does
not isolate CPU execution. A post-run load-average observation cannot explain
or reconstruct scheduling during individual samples.

No implementation was reverted on this timing evidence. Future CPU work needs
more stable attribution or per-phase operation counts; physical I/O savings
already verified under throttling remain separate claims. Evidence is
`target/storage-unthrottled-file-20260911/`, with every run's JSONL, ELF hashes
in provenance, transcripts and per-seed `summary.json`. Both historical ELFs
include multiple differences from current, so this is not a one-patch A/B test.
No real device was accessed or modified.

### Machine-readable sequential-file phase counters (2026-09-11)

Successful QEMU `file-sequential` samples now include seven device counters
for each of four phases: `file_stage_*`, `file_publish_*`, `file_verify_*`,
and `file_remove_*`. Stage includes content generation, stager pushes and
finish; publish switches the durable file-tree root; verify reads and checks
all file content; remove durably deletes the file. Counter snapshots are taken
at these boundaries. JSON formatting occurs after timing and total counter
capture. These are I/O attribution counters, not CPU timings.

The converter preserves them in `phases` and requires a complete nonnegative
integer set whose sums equal the aggregate device counters. Its selftest
covers valid data, missing/negative/boolean fields, inconsistent sums, incorrect
workload tagging and compatibility with old samples without phase fields.
Failed samples do not publish a misleading completed-phase breakdown.

A matched fresh 16 MiB sample, same seed and 4/2 MiB/s, 400/200 IOPS limits,
passes exact content verification and reproduces every pre-instrumentation
aggregate counter:

| Phase | Read requests | Write requests | Flushes | Read bytes | Write bytes |
|---|---:|---:|---:|---:|---:|
| Stage | 25 | 201 | 10 | 196,608 | 17,854,464 |
| Publish | 1 | 6 | 3 | 4,096 | 151,552 |
| Verify | 286 | 0 | 0 | 17,612,800 | 0 |
| Remove | 2 | 6 | 3 | 36,864 | 151,552 |

This identifies staging as the dominant writer and verification as the dominant
reader for this case. Evidence: `target/storage-file-phases-20260911/`, including
ELF/hash, build and converter-test logs, JSONL, transcript and summary. No real
device was accessed or modified; storage publication semantics are unchanged.

QEMU benchmark firmware builds, and Duo `file-tree,legacy-shell` compilation
also passes, covering the non-QEMU branch of the added output code. The phase
instrumentation and converter validation are retained.

### Pair hash-page reads during full streaming verification (2026-09-11)

The full streaming verifier now fetches separate Merkle-tree extents in
aligned two-page runs. Its hash cache uses eight windows of up to two pages,
retaining the existing 16-page total budget. Content read-ahead stays separate.
Compact envelopes use demand reads, and range-read policy is unchanged. Failed
transfers still invalidate the window before awaiting; only successful reads
publish a cache address. All hash emissions and the final root remain checked.

The uncached host fixture now verifies full content and exact two-page runs
for 1 MiB and 4 MiB native CAS blobs, as well as range behavior. The 360 KiB
case continues through the existing small-blob reader. Required leaf-level
and upper-level hash corruption must also fail full reads. The selected suite
passes 236 tests, one ignored; Duo compilation and QEMU firmware build pass.

A matched 16 MiB QEMU file workload passes. Verify-stage requests decrease
286 → 262 (8.4%), with exactly 17,612,800 bytes read in both runs. All stage,
publish and remove counters remain identical. Total reads decrease 314 → 290,
with read/write bytes, write requests and flushes unchanged. This is fewer
physical requests, not a wall-clock or physical-SD speedup claim.

The matched 64 MiB file control also passes: total reads fall 1,645 → 1,557
(5.3%), while read bytes, write bytes, write requests and flushes exactly match
baseline. Both sizes use fresh VMs, 128 MiB RAM, the same seed/template, one
un-warmed sample and 4/2 MiB/s, 400/200 IOPS limits. They establish request-count
savings for these workloads, not latency distributions. Individual native CAS
proof working sets larger than the 16-page hash cache need separate attribution.

Evidence is `target/storage-full-proof-runs-20260911/`, with the candidate
ELF/hash, exact patch, test/build logs, phase-bearing JSONL, transcripts and
matched counter summary. The measured ELF and final runtime algorithm match;
test expectations were corrected separately after the build. No physical
device was accessed or modified.

The production three-boot file-tree gate passes GC pressure, cold recovery
and powered-off verification. The full-verification hash-page batching is retained.

### Full verification beyond the hash-cache budget (2026-09-11)

The uncached host fixture now includes native 8 MiB and 16 MiB CAS objects,
whose separate proof trees contain 32 and 64 pages, respectively. Full streaming
verification reads each tree page exactly once in aligned two-page requests:
32 pages / 16 requests and 64 pages / 32 requests. The cache remains 16 pages;
these workloads stream a proof tree larger than the resident cache.

Exact request-set assertions now cover all five object sizes through 16 MiB.
The existing five range shapes per size (including 32 descending dispersed
ranges), exact content checks, and required lower/upper sibling corruption
checks also run for the larger objects. These results qualify the tested access
orders; they do not imply arbitrary randomized range orders avoid LRU eviction
or establish a physical-SD timing benefit.

Evidence is `target/storage-large-proof-audit-20260911/`. This round expands
regression qualification only; the runtime algorithm and cache budget are
unchanged. No real device was accessed or modified.

The final focused test passes all 25 range configurations, five full-object
checks and ten corruption cases; the runtime prefix is byte-identical to the
pre-turn source. Logs and `summary.json` record the results.

### Current 256 MiB file qualification with phase attribution (2026-09-12)

The current full-proof-run ELF passes a fresh 256 MiB file write, exact full
readback and durable removal in a 128 MiB guest. The benchmark generates and
checks bounded chunks rather than allocating a whole-file test buffer. One
un-warmed sample uses seed 14476452505690153217 and the same blank template,
4/2 MiB/s bandwidth and 400/200 read/write IOPS limits. Total workload time is
222.233878 s; this is a capacity/correctness observation, not a latency distribution.

| Phase | Read requests | Write requests | Flushes | Read bytes | Write bytes |
|---|---:|---:|---:|---:|---:|
| Stage | 3,684 | 3,039 | 84 | 23,961,600 | 284,196,864 |
| Publish | 1 | 7 | 3 | 4,096 | 172,032 |
| Verify | 5,546 | 0 | 0 | 288,587,776 | 0 |
| Remove | 2 | 7 | 3 | 36,864 | 172,032 |
| Total | 9,233 | 3,053 | 90 | 312,590,336 | 284,540,928 |

All phase sums reconcile. Read/write amplification relative to logical file
bytes is 1.1645 / 1.0600. Three capacity-growth messages are present in the
transcript; do not infer a GC count solely from phase totals. Staging's 3,684
read requests averaging about 6.4 KiB each suggest a useful next attribution
point for metadata work; the counters alone do not identify the call sites.

This refreshes the older 256 MiB qualification on the current implementation,
without claiming one recent change caused the difference from historical data.
Evidence is `target/storage-file256-phases-20260911/`, containing JSONL, serial
transcript, exact ELF provenance and `summary.json`. No runtime changes were
made this round, and no physical device was accessed or modified.

### Physical-page attribution of 256 MiB staging (2026-09-12)

A diagnostic ELF records physical misses only while the sequential-file stager
runs, including each returned page's Storage v2 body/seal magic and record kind.
The unthrottled diagnostic completes exact file verification and reproduces
all seven staging counters of the throttled baseline: 3,684 reads, 5,850 pages,
23,961,600 bytes, with the same writes/flushes. Request lengths and page logs
reconcile exactly. Serial instrumentation makes its elapsed time unsuitable
for performance comparison. Both kernel files were restored to their exact
pre-instrumentation snapshots after building the diagnostic ELF.

| Recognized on-media category | Pages read (body + seal) | Distinct body / seal addresses |
|---|---:|---:|
| Superblock | 88 | 2 / 2 |
| Checkpoint | 68 | 2 / 2 |
| Segment header | 372 | 85 / 85 |
| Extent descriptor | 2,204 | 502 / 502 |
| Segment summary | 372 | 85 / 85 |
| Segment final seal record | 372 | 85 / 85 |
| No recognized record magic | 2,374 | 773 |

Recognized record pages account for 59.4% of staging read bytes; extent bodies
and seals alone account for 37.7%. The remaining 40.6% includes untyped pages
and must not be equated with file content (it can include catalog/allocation
payloads or cleared pages). Tags describe returned bytes, not an additional
independent authentication step; the successful workload supplies its normal
storage checks.

The trace touches 2,225 distinct physical page numbers but reads 5,850 pages.
Repeated addresses are not automatically redundant: checkpoint/superblock
updates and possible generation changes require fresh checks. Segment headers
appear 186 times across 85 addresses, and extent bodies 1,102 times across
502 addresses. This motivates investigating bounded scan-proof retention and
metadata working-set pressure, rather than enlarging content read-ahead. The
trace did not record generations, so it does not prove repeated proof identities.

Evidence: `target/storage-stage-trace-20260912/`, containing diagnostic ELF/hash,
patches, serial transcript, JSONL, reconciled categories and restore verification.
The historical log tag `payload` means unrecognized record magic, not verified
user payload. No production instrumentation remains and no real device was accessed.

### Scan-proof capacity experiment: 48 versus 96 entries (2026-09-12)

A temporary build changes only `VERIFIED_SEGMENT_SCAN_CAPACITY` from 48 to 96.
Both uninstrumented ELFs pass a fresh 256 MiB file write, exact full readback
and durable removal with 128 MiB guest RAM, seed 14476452505690153217 and the
same blank disk template. Each runs one un-warmed, unthrottled sample. The
48-entry control reproduces all aggregate counters of the preceding baseline.

| Counter | 48 entries | 96 entries |
|---|---:|---:|
| Total read requests | 9,233 | 8,946 |
| Total read bytes | 312,590,336 | 309,567,488 |
| Staging read requests | 3,684 | 3,572 |
| Staging read bytes | 23,961,600 | 22,781,952 |
| Verification read requests | 5,546 | 5,371 |
| Verification read bytes | 288,587,776 | 286,744,576 |

Both runs retain 3,053 write requests, 284,540,928 write bytes and 90 flushes.
Doubling the entry limit saves 3.11% of total read requests and 0.97% of total
read bytes (2.88 MiB); staging read bytes fall 4.92%. This establishes a modest
capacity benefit for this workload, not a latency improvement or a complete
explanation of repeated metadata reads. Single unthrottled timings do not
support a causal timing claim.

The production limit remains 48: the modest reduction does not yet justify
raising the retained-memory ceiling, especially for smaller guests. A future
capacity change should measure resident allocation and enforce a byte budget
for variable-length extent vectors as well as an entry bound. The source was
restored byte-for-byte before building the 48-entry control. Evidence lives in
`target/storage-scan-capacity-trial-20260912/`: both ELFs and hashes, build logs,
JSONL, serial logs, counter comparison and source-restoration check. This trial
adds no runtime change.

### Page-cache intrusive LRU trial, not retained (2026-09-12)

The current cache finds a replacement by scanning up to 512 entry timestamps.
A trial replaces timestamps with previous/next page keys and head/tail keys,
eliminating the victim scan while preserving exact LRU and page-buffer reuse.
Its cost is additional BTreeMap lookups on ordinary hits and a larger entry:
the host representation grows from 16 to 40 bytes, excluding map-node overhead.

An extracted-source host fixture using a mutex shim passes the existing 256
hit-mask combinations and buffer-reuse tests, plus 6,000 operations checked
against an independent map/deque LRU model. It checks bytes, both link directions,
eviction, overwrites, range reads, invalidation, clear and allocation-time
competing inserts. QEMU and Duo `file-tree,legacy-shell` builds/checks pass.
The 256 MiB fresh file workload passes and exactly preserves all aggregate
and file-phase I/O counters of the 48-entry scan-cache control.

Four unthrottled 16 MiB runs use before/after/after/before order, each with one
warmup and three retained samples. All 16 workloads pass and corresponding
aggregate/phase I/O counters match. Retained medians are 2.271, 5.088, 4.665 and
4.851 seconds. The large drift in the unchanged control prevents a causal
end-to-end timing conclusion.

An isolated host microbenchmark (100,000 operations, five trials) observes
replacement-plus-hit medians of 98.87 to 40.10 ms, but hit-only medians of 14.00
to 22.70 ms. These are host/mutex observations, not SD or guest CPU measurements.
They expose the tradeoff rather than establish a storage speedup. The trial is
not retained: it increases hit-path map work and resident metadata without a
demonstrated end-to-end benefit. Any follow-up should avoid repeated map lookups
for recency updates, for example by evaluating bounded indexed links.

Evidence is `target/storage-page-cache-linked-lru-20260912/`: saved before/trial
sources, exact patch, extracted tests, microbenchmark sources/results, firmware,
build logs, QEMU JSONL/transcripts and summaries. Production source was restored
byte-for-byte to its pre-trial snapshot. No production recovery gate was run
for this rejected candidate; its workload checks do not substitute for that gate.

### Indexed page-cache LRU, retained (2026-09-12)

The follow-up keeps the page-key BTreeMap but replaces timestamps with compact
slot indices. A bounded array stores each slot's page key and previous/next
indices. Recency updates use array accesses after the existing map lookup;
victim selection uses the oldest slot rather than scanning all cache entries.
Map insertion/removal still costs O(log N). Removed slots are reused through
a free list; replacement continues to reuse the victim's boxed page buffer.

The map entry remains 16 bytes on the measured 64-bit host. Link slots are
16 bytes each, with at most 512 slots (64 for the Duo Python configuration):
8 KiB / 1 KiB of slot storage, excluding allocator overhead. Clearing the cache
resets the live/free lists and retains the bounded vector allocation. Page
capacity, exact LRU order, write invalidation and physical-proof cache clearing
are unchanged.

Extracted-source host tests with a mutex shim pass at both 512 and 64 entries.
They include 256 hit-mask combinations, buffer reuse and competing insertion
checks, plus 6,000 mixed operations against an independent map/deque model.
Each step checks cached bytes, live links, free slots and list coverage.
The host microbenchmark uses 100,000 operations per trial, five trials:

| Host median | Timestamp scan | Indexed links |
|---|---:|---:|
| Replacement followed by hit | 62.11 ms | 23.67 ms |
| Hit only | 10.33 ms | 9.53 ms |

These measurements isolate cache work with a host mutex; they do not measure
SD latency or establish a guest end-to-end speedup. The structural benefit is
removing the full victim scan without adding map lookups to cache hits.

The fresh 256 MiB file workload passes in a 128 MiB QEMU guest. Every aggregate
and file-phase I/O counter matches the timestamp control: 9,233 reads /
312,590,336 bytes, 3,053 writes / 284,540,928 bytes, and 90 flushes. The production
three-boot gate passes durable links, recursive removal, GC pressure, cold
recovery and powered-off verification. Duo `file-tree,legacy-shell` compilation
also passes. No physical device has been measured.

Evidence is `target/storage-page-cache-indexed-lru-20260912/`: before/final
sources, exact patch, host fixtures and logs, microbenchmark sources/results,
benchmark ELF/hash, QEMU JSONL/transcript, firmware build logs and three-boot
recovery evidence. The indexed LRU implementation is retained.

### Indexed LRU under small-store GC pressure (2026-09-12)

Matched small-store ELFs differ only in the page-cache implementation and its
tests. Both start fresh with 16 provisioned segments, 128 MiB guest RAM, seed
32 and 128 retained 4 KiB `object-durable-put-get` samples, without warmups.
QEMU limits reads/writes to 4/2 MiB/s and 400/200 IOPS. The timestamp control
was built from the saved pre-indexed source; the indexed source was restored
byte-for-byte before either workload ran.

Both runs pass every sample and complete 43 GC rounds. The seven I/O counters
match for each corresponding sample, not just in aggregate. Each GC report's
read/write requests, live object/blob counts, copied bytes and reclaimed
segments also match (pause timing is excluded from this equality check).
Both totals are 6,487 reads / 32,575,488 bytes, 2,321 writes / 88,788,992 bytes
and 745 flushes. This additionally reproduces the earlier retained-object
baseline under repeated page invalidation, eviction and slot reuse.

The sum of measured workload times is 49.54 s for the timestamp control and
52.02 s for indexed LRU; sample medians are 36.69 and 57.43 ms. These are one
ordered pair of growing-store runs with mixed ordinary/GC operations. They
do not demonstrate an end-to-end speedup or isolate the cause of the timing
difference. Retaining the cache optimization is supported by its structural
and isolated-host improvement plus correctness qualification, not by a claim
that this QEMU workload became faster.

Evidence: `target/storage-indexed-lru-small-store-20260912/`, including both
ELFs/hashes, build logs, JSONL and serial transcripts, source-restoration
verification and a reproducible `analyze.py` that checks sample identity,
geometry, throttle configuration, per-sample I/O and per-round GC reports.
This qualification adds no runtime changes and makes no physical-SD claim.

### Reverse-order timing check for indexed LRU (2026-09-12)

The exact same ELF hashes were rerun in candidate/control order with the same
fresh disk, seed, 128 samples, 16-segment geometry and SD-style QEMU limits.
All four runs pass: per-sample I/O and every GC report match across both orders.

| Run order | Timestamp total | Indexed total |
|---|---:|---:|
| Timestamp then indexed | 49.54 s | 52.02 s |
| Indexed then timestamp | 41.43 s | 41.26 s |

The earlier approximately 5% difference does not reproduce. The unchanged
ELFs vary substantially between runs, so these observations establish neither
a stable regression nor an end-to-end speedup. Keep the distinction between
isolated cache work and workload wall time; further identical timing reruns
alone would not resolve the source of this variability.

Serial attribution identifies 42 GC-containing samples (43 GC rounds) and
86 samples without GC in every run. In the reverse pair, GC-containing samples
sum to 39.17 / 39.19 seconds for timestamp/indexed, versus 2.25 / 2.07 seconds
without GC. Thus roughly 95% of measured time belongs to GC-containing
workloads. This is not a measurement of time exclusively inside the collector:
those samples also perform their ordinary put/get work. It prioritizes further
GC-path attribution over additional LRU timing tuning.

Evidence is under `target/storage-indexed-lru-small-store-20260912/reverse/`,
with `analyze_reverse.py` and `reverse-summary.json` in its parent directory.
No runtime changes were made for this check.

### GC phase I/O attribution (2026-09-12)

A temporary PageDevice diagnostic hook snapshots physical block counters at
GC phase boundaries. The diagnostic small-store ELF completes the same 128
retained-object samples and 43 GC rounds unthrottled. Every sample's seven I/O
counters matches the indexed-LRU throttled control. Phase differences reconcile
with each GC report and the aggregate; serial-instrumented timings are not used.

| Completed phase | Reads | Read bytes | Writes | Write bytes | Flushes |
|---|---:|---:|---:|---:|---:|
| Typed children, manifests and planning | 0 | 0 | 0 | 0 | 0 |
| Blob relocation and manifest staging | 2,382 | 10,321,920 | 522 | 51,363,840 | 2 |
| Remaining target metadata and segment finish | 0 | 0 | 153 | 10,575,872 | 0 |
| Staged checkpoint-root verification | 1,169 | 9,666,560 | 0 | 0 | 0 |
| Manifest and copied-blob verification | 2,905 | 11,898,880 | 0 | 0 | 0 |
| G+1 publication and successor mount | 23 | 655,360 | 129 | 528,384 | 129 |
| Old checkpoint seal clear | 0 | 0 | 43 | 176,128 | 43 |
| G+2 allocation staging and verification | 0 | 0 | 129 | 1,761,280 | 43 |
| G+2 publication and successor mount | 0 | 0 | 86 | 352,256 | 86 |
| Total | 6,479 | 32,542,720 | 1,062 | 64,757,760 | 303 |

These are physical requests submitted within each interval. Buffered writes
can be issued when a later stage drains the builder, so the phase name does
not independently classify every transferred byte's record type. Zero physical
reads likewise does not mean zero logical reads or CPU work.

Target verification accounts for 4,074 reads (62.9% of GC reads) and 21,565,440
read bytes (66.3%). Relocation contributes 2,382 reads (36.8%). The absence of
physical reads during manifest loading argues against adding a manifest cache
for this workload. The next useful attribution is target layout and repeated
reads during staged-root/copied-blob verification, while preserving all
integrity checks. This measurement does not justify skipping target readback.

Evidence is `target/storage-gc-phase-trace-20260912/`: diagnostic ELF/hash,
three exact patches and before/diagnostic snapshots, build log, serial trace,
JSONL and reproducible phase reconciliation. `device.rs`, `gc.rs` and platform
source were restored byte-for-byte immediately after the build. No diagnostic
hook remains in production source and no physical device was accessed.

### Verify relocated blobs from newest to oldest (2026-09-12)

GC now traverses the relocated snapshot's blob table in reverse order during
target verification. Manifest staging and the snapshot are both BlobKey ordered,
so this visits newer target pages before an older-to-newer scan can evict them.
Every existing manifest, copied-payload hash, padding and Merkle check remains
in place before G+1 publication. The change adds no cache or on-media format.

In the 16-segment retained-object workload (128 fresh 4 KiB samples, seed 32,
128 MiB guest), all samples pass. Compared with the forward-order baseline:

| Counter | Forward verification | Reverse verification |
|---|---:|---:|
| Read requests | 6,487 | 5,125 |
| Read bytes | 32,575,488 | 26,996,736 |
| Write requests | 2,321 | 2,321 |
| Write bytes | 88,788,992 | 88,788,992 |
| Flushes | 745 | 745 |
| GC rounds | 43 | 43 |

Reads fall 21.0% by request count and 17.1% by bytes. Each corresponding
sample's writes/flushes and every GC round's live counts, copied bytes,
reclaimed segments and write requests remain identical. This trial is
unthrottled and compared by deterministic I/O counters, not elapsed time.

The default-capacity 256 MiB file write/full verification/durable removal
also passes in 128 MiB RAM. All aggregate and file-phase counters match the
previous implementation exactly: 9,233 reads / 312,590,336 bytes, 3,053 writes /
284,540,928 bytes and 90 flushes. The selected host suite passes 236 tests with
one existing ignore, including acknowledged copied-payload/padding corruption
and GC recovery tests. Duo `file-tree,legacy-shell` compilation passes.

Evidence is `target/storage-gc-reverse-verify-20260912/`: before/final source,
patch, small/default ELF hashes, build/test logs, JSONL, serial transcripts
and counter reconciliation. The small-store ELF was built before explanatory
comments were added; its runtime change is the same reverse traversal.
These results do not measure physical-SD latency.

The production three-boot file-tree gate passes GC pressure, cold recovery
and powered-off verification. Reverse target verification is retained.

### Reverse verification under SD-style QEMU limits (2026-09-12)

The retained reverse-order ELF and the forward-order control were run
consecutively in that order, each on a fresh 16-segment store with 128 MiB RAM,
128 retained 4 KiB samples, seed 32 and no warmups. Limits were 4/2 MiB/s and
400/200 read/write IOPS. Both complete every sample and 43 GC rounds.

Each corresponding sample reproduces its implementation's earlier I/O counters.
Reverse order retains 5,125 reads / 26,996,736 bytes versus 6,487 reads /
32,575,488 bytes for forward order: 21.0% fewer reads and 17.1% fewer read bytes.
Both still issue 2,321 writes / 88,788,992 bytes and 745 flushes. GC live counts,
copied bytes, reclaimed segments and write requests are unchanged per round.

The sums of guest workload intervals are 41.60 s (reverse) and 46.28 s (forward),
with sample medians of 48.01 and 54.67 ms. The approximately 10% lower sum is
an observation from this ordered pair, not a stable latency estimate: earlier
identical-ELF runs showed substantial timing variation. These sums also exclude
host/UART command turnaround between samples. The repeatable result is the
physical I/O reduction under both unthrottled and throttled configurations.

Evidence is `target/storage-gc-reverse-verify-20260912/throttled/`: JSONL and
serial transcripts for both runs, run logs, `analyze.py` and `summary.json`
including ELF hashes and per-sample reconciliation. No runtime code changed
for this qualification. Physical SD performance remains unmeasured.

### Default-capacity write cost and early-compaction trial (2026-09-12)

The current default-capacity ELF passes 128 retained 4 KiB put/get samples
(seed 32, 128 MiB RAM, fresh disk, unthrottled). It exposes 223 provisioned
segments, admits more space on five growth requests, and performs eight GC
rounds. Total physical writes are 38,924,288 bytes for 524,288 user bytes
(74.24x for this complete workload), versus 88,788,992 bytes in the deliberately
constrained 16-segment pressure test. This is workload-level write amplification,
not a general estimate for arbitrary stores. The last ordinary 4 KiB sample
writes 266,240 bytes and reports 255 authority records.

A temporary build lowers `STORAGE_V2_COMPACT_MIN_RECORDS` from 2048 to 128;
this shared constant affects both steady-state and boot compaction eligibility.
The fresh workload exercises steady-state compaction twice, reducing streams
129 -> 66 and 128 -> 97. All 128 samples pass, but total cost increases:

| Counter | Default threshold | Threshold 128 trial |
|---|---:|---:|
| Read requests | 3,626 | 3,729 |
| Read bytes | 39,096,320 | 39,399,424 |
| Write requests | 1,392 | 1,475 |
| Write bytes | 38,924,288 | 43,319,296 |
| Flushes | 469 | 509 |
| GC rounds | 8 | 12 |
| Final authority records | 255 | 161 |

The shorter stream does not compensate for the extra compaction/GC work in
this sequence: write bytes rise about 11.3%. The threshold change is rejected;
the original source was restored byte-for-byte immediately after building
the trial. No additional cold-recovery qualification is claimed for this
rejected build.

Every GC report in both default-capacity runs records zero copied blob bytes.
Inspection shows `relocate_live_state` still emits all live manifests and
`required_gc_segments` budgets all of them unconditionally. This identifies a
more direct next investigation: retain an existing manifest only if both its
own segment and all referenced extents remain outside the selected sources.
Any such optimization must update reservation planning and preserve recovery
validation; the observations alone do not authorize reusing a pointer into
a reclaimed segment.

Evidence is `target/storage-default-retained-20260912/`: baseline/trial JSONL,
serial logs, summaries, trial ELF/hash, before/trial platform snapshots and
restoration verification. The original reverse-GC verification and indexed
LRU remain in place. This round retains no new runtime change.

### Unconditional reuse of unselected manifests: prototype rejected (2026-09-12)

A prototype shares one decision between reservation planning and relocation:
retain a manifest only when its own segment and every referenced extent are
outside the selected sources. It still reads/validates the resulting manifests
before publication. Metadata telemetry counts only manifests actually written;
memory estimates remain conservative. No extra persistent cache is introduced.

The selected host suite passes 238 tests with one existing ignore. A new
integration fixture retains the exact manifest pointer and bytes across two GC
rounds with intervening segment reuse, checks that its segment stays Allocated,
passes the powered-off image verifier after both rounds, then cold-mounts and
reads all 128 KiB through the original handle. Planner fixtures were updated to
supply sorted catalog mappings; classification tests cover selected manifest
records, selected extents, missing mappings and null pointers. Duo compilation
passes.

Default-capacity QEMU results for 128 retained 4 KiB objects are mixed:

| Counter | Before | Manifest reuse prototype |
|---|---:|---:|
| Read requests | 3,626 | 7,601 |
| Read bytes | 39,096,320 | 77,828,096 |
| Write requests | 1,392 | 1,295 |
| Write bytes | 38,924,288 | 30,310,400 |
| Flushes | 469 | 469 |
| GC rounds | 8 | 8 |
| Blob bytes copied by GC | 0 | 0 |

All 128 samples pass. Writes fall 22.1%, but read bytes nearly double and read
requests more than double. Retained manifests remain spread across historical
segments, making increased scan/verification work a likely explanation; this
trial does not separately attribute that extra read traffic. The prototype is
not retained. Follow-up needs to consider metadata locality and scan-proof
working sets, rather than optimize write bytes in isolation.

Three stdio runs were rejected by the strict parser because serial JSON keys
lost characters; the first stopped before any GC. Adding 100 ms between samples
did not eliminate the issue. A temporary runner using a local Unix-socket
serial backend completed the workload with the same ELF. The precise cause of
the stdio losses is not established. No missing counter was inferred or repaired,
and no timing comparison is claimed across transports. The wrapper appends the
serial argument after the standard runner constructs its environment metadata;
the wrapper source documents this additional actual launch argument.

Evidence is `target/storage-gc-manifest-reuse-20260912/`: prototype source/patch,
new test fixture, successful test/build logs, rejected stdio runs, socket runner,
successful `retained-socket3.jsonl` and transcript, counters and ELF hash. Both
modified source files were restored to their pre-trial contents; the accepted
reverse-verification optimization remains. The rejected prototype did not run
the production three-boot gate or the large-file QEMU qualification.

### Manifest reuse versus scan-proof capacity (2026-09-12)

All 3,975 extra read requests in the 48-entry reuse prototype occur inside GC:
GC reads rise from 727 to 4,702, while reads outside GC remain 2,899. Two
diagnostic ELFs raise only the verified-segment scan cache's entry limit to 192,
one with the original manifest rewriting and one with the reuse prototype.
Both complete the same fresh 223-segment, 128 MiB, 128-object workload using
the local Unix-socket serial wrapper. The 48-entry results are the earlier
matched workloads; all four runs pass every sample and perform eight GC rounds.

| Implementation / scan-cache entries | Read requests | Read bytes | Write bytes |
|---|---:|---:|---:|
| Original / 48 | 3,626 | 39,096,320 | 38,924,288 |
| Original / 192 | 3,626 | 39,096,320 | 38,924,288 |
| Manifest reuse / 48 | 7,601 | 77,828,096 | 30,310,400 |
| Manifest reuse / 192 | 3,690 | 39,276,544 | 30,310,400 |

Increasing capacity changes neither writes/flushes nor GC round counts within
either implementation. With reuse, GC reads fall from 4,702 to 791; the original
stays at 727. This isolates scan-proof cache pressure as the main source of the
reuse prototype's extra reads in this workload. At 192 entries, reuse saves
22.1% of write bytes while adding about 0.46% of read bytes versus the original.
No elapsed-time improvement is claimed.

Neither diagnostic change is retained. A production design must account for
the bytes retained by variable-length extent vectors and queue storage, rather
than simply quadrupling an entry limit. Candidate directions are an explicit
cache byte budget or a reuse policy constrained by its scan working set.

Evidence is `target/storage-gc-reuse-proof-capacity-20260912/`: build logs,
both ELFs/hashes, socket-backed JSONL/transcripts, `analyze.py`, factorial
counter summary and exact source-restoration verification. `store.rs` and
`gc.rs` were restored before either diagnostic workload ran. The launcher uses
the same temporary socket wrapper documented in the preceding experiment.

### Bounded scan-proof cache and manifest reuse retained (2026-09-12)

GC now retains an existing manifest when its record and every referenced extent
are outside the selected source segments. Reservation planning uses the same
classification; metadata telemetry counts only manifests actually written.
All resulting manifests remain validated before publication, and recovery
memory estimates remain conservative.

The verified-segment scan memo allows at most 192 entries and 256 KiB of
requested resident heap capacity per memo. The budget includes actual deque
capacity and each extent vector's capacity, including unused slots. It excludes
allocator bookkeeping/rounding and transient caller scan workspace. Oversized
proofs are not retained; allocation failure declines optional caching. LRU
removal enforces both bounds. Exact segment/generation keys, checkpoint horizon
checks and retired-segment invalidation remain intact.

Fresh single-hart TCG QEMU runs use 128 MiB RAM, a private 1 GiB image and
unthrottled block I/O. Object workloads retain 128 distinct 4 KiB objects with
seed 32. The comparison baseline is the accepted reverse-verification code
with 48 scan entries and unconditional manifest rewriting.

| Workload / counter | Before | Bounded cache + reuse |
|---|---:|---:|
| Default 223 segments: read bytes | 39,096,320 | 39,276,544 |
| Default 223 segments: write bytes | 38,924,288 | 30,310,400 |
| Small 16 segments: read bytes | 26,996,736 | 15,933,440 |
| Small 16 segments: write bytes | 88,788,992 | 71,536,640 |
| 256 MiB file: read bytes | 312,590,336 | 303,964,160 |
| 256 MiB file: write bytes | 284,540,928 | 284,540,928 |

Default writes fall 22.1% with 0.46% more read bytes; the bounded implementation
matches the prior 192-entry diagnostic's I/O exactly. Small-store read bytes
fall 41.0% and write bytes 19.4%. Flush counts remain 469, 745 and 90 respectively;
GC rounds remain eight and 43 for the object runs. The file workload includes
write, full readback and durable deletion, and performs no GC. All samples pass.
These are block-traffic measurements, not elapsed-time or physical SD results.

Validation passes 240 selected host tests with one existing ignore, default
and small QEMU release builds, Duo compilation, and the production three-boot
file-tree gate including cold recovery and powered-off verification. New tests
exercise cache capacity charging, byte-pressure LRU eviction, replacement,
clear/retain and oversized-proof rejection. The manifest fixture verifies exact
pointer/byte retention across two GC rounds with segment reuse, offline image
verification and cold reads through the original handle.

Evidence is `target/storage-gc-bounded-proof-cache-20260912/`: source snapshots
and scoped patches, test/build logs, saved ELFs and hashes, all three JSONL runs,
serial transcripts, counter summaries and retained gate logs. Benchmarks use
`target/storage-gc-manifest-reuse-20260912/socket-runner.py`; as documented above,
the wrapper adds a local Unix-socket serial argument after runner environment
metadata construction. Strict sample validation remains enabled. This combined
change is retained, superseding the earlier rejected unbounded prototypes.

### Bounded-cache reuse under QEMU device limits (2026-09-12)

A serial A/B/B/A qualification compares the saved pre-change reverse-GC ELF
with the retained bounded-cache/manifest-reuse ELF. Each run starts from a
fresh private disk with 16 provisioned segments, one TCG hart and 128 MiB RAM,
then retains 128 unique 4 KiB objects (seeds 32 through 159). Both versions use
the same Unix-socket serial wrapper. Disk limits are 4 MiB/s reads, 2 MiB/s
writes, 400 read IOPS and 200 write IOPS, with cache=none and aio=threads.

| Run order | Implementation | Sum of guest operation times | Slowest operation |
|---|---|---:|---:|
| 1 | Before | 37.723 s | 1.986 s |
| 2 | Bounded cache + reuse | 27.095 s | 1.281 s |
| 3 | Bounded cache + reuse | 27.163 s | 1.279 s |
| 4 | Before | 38.116 s | 1.973 s |

The mean summed guest operation time falls from 37.919 s to 27.129 s (28.46%).
This excludes boot and host/serial delays between commands. All 512 samples
pass strict validation; every run performs 43 GC rounds and 745 flushes.
Repeated runs of each ELF have identical block counters, also matching the
preceding unthrottled qualification: reads fall from 26,996,736 to 15,933,440
bytes and writes from 88,788,992 to 71,536,640 bytes. Median individual operation
latency remains approximately 24 ms; the improvement includes lower long
operations during the pressure workload, rather than a comparable reduction
for every ordinary operation.

These two repetitions per ELF support a benefit under this specific QEMU rate
profile. They do not establish physical SD performance or simulate flash
translation, erase-block garbage collection or card-specific flush latency.
The unthrottled baseline remains separate. No runtime code changes in this
qualification. Evidence is `target/storage-bounded-cache-throttled-20260912/`:
ordered launcher, exact command files, ELF paths/hashes, wrapper snapshot, four
JSONL/transcript pairs, validation and counter assertions in `analyze.py`, and
`summary.json`. The wrapper's additional serial argument remains outside the
standard runner's pre-launch environment metadata, as documented above.

### Manifest-reuse scaling to 256 retained objects (2026-09-12)

Two fresh default-capacity QEMU runs extend the unique 4 KiB retained-object
sequence to 256 objects (seeds 32 through 287). The saved reverse-verification
ELF is compared with the retained bounded-cache/manifest-reuse ELF, using one
TCG hart, 128 MiB RAM, 223 provisioned segments, no device throttling and the
same Unix-socket serial transport. Every sample passes in both runs.

| Counter | Before | Bounded cache + reuse |
|---|---:|---:|
| Read requests | 17,510 | 8,642 |
| Read bytes | 127,737,856 | 68,399,104 |
| Write requests | 4,446 | 3,733 |
| Write bytes | 200,523,776 | 133,787,648 |
| Flushes | 1,205 | 1,205 |
| GC rounds | 52 | 52 |

Reads fall 46.5% and writes 33.3%. Comparing successive 32-object windows
shows no late reversal: the final window reads 6,123,520 versus 45,871,104
bytes and writes 19,509,248 versus 52,908,032 bytes. This covers a larger
working set but does not prove cache behavior at every capacity. GC may
select different physical content after the optimized layout diverges.

Substantial metadata amplification remains: the candidate's final ordinary
4 KiB put reports 397,312 write bytes, three flushes and 511 authority records.
This motivates further attribution of authority history and checkpoint writes;
it is not evidence that these writes can safely be omitted. No runtime change
is introduced in this qualification and no elapsed-time comparison is claimed.
Evidence is `target/storage-reuse-256-retained-20260912/`: ordered launcher,
commands, ELF hashes, two JSONL/transcript pairs, per-32-object counters and
GC counts in `summary.json`, and the analysis script. The Unix-socket launch
argument provenance follows the earlier wrapper qualification.

### Ordinary-put authority write attribution (2026-09-12)

A repeat of the candidate's 256-retained-object run preserves its powered-off
QEMU disk through a cleanup wrapper. All 256 samples pass, and every sample's
block counters match the preceding run exactly. The V2 region starts at logical
block 2048; raw dense-image tools must not be pointed at the whole disk.
The independent framing parser validates the final generation's sealed record
pairs and SHA-256 of each extent payload. At checkpoint generation 367:

| Extent | Payload bytes | Descriptor pair + padded payload bytes |
|---|---:|---:|
| Encoded 4 KiB blob | 4,480 | 16,384 |
| Manifest | 256 | 12,288 |
| Catalog delta | 416 | 12,288 |
| Authority | 262,848 | 274,432 |
| Allocation | 184 | 12,288 |

Authority is the dominant component, about 69.1% of the measured 397,312 write
bytes including its descriptor pair and page padding. The catalog already uses
an increment rather than a full snapshot. Authority contains 513 records of
512 bytes, one 64-byte principal and a 128-byte header; there are no object
bindings or external roots. The benchmark's 511-record field is the pre-append
observation, not the final on-media count. The five framed extents sum to
327,680 bytes. Two segment header/summary/seal sets account for 49,152 bytes;
checkpoint publication writes three pages (12,288 bytes), leaving 8,192 bytes
outside this static accounting. Static final-state inspection alone does not
attribute transient zero/preclear writes, so those remaining bytes are not
assigned a measured cause here.

The whole-disk migration verifier rejects this image with `persistent authority
record stream length is invalid`: `recover_record_stream` still caps the stream
at the legacy M4 journal's 512 sectors, while production Storage V2 admits a
larger bounded authority payload. This is a verifier coverage gap, not a passed
cold-recovery result. Record and payload validation do not substitute for full
logical recovery. Extend and qualify that verifier before using it to accept
larger authority histories; separately investigate bounded authority deltas or
safe compaction to reduce the identified write cost.

Evidence is `target/storage-authority-write-attribution-20260912/`: capture
wrapper, 256-sample JSONL/transcript, final disk, attribution script/summary,
and rejected verifier outputs. No runtime code is changed by this experiment.

### Offline recovery of extended authority histories (2026-09-12)

The independent migration verifier now recovers a bounded logical record stream
directly, sharing the existing sequence/CRC-chain validation and semantic
recovery engine. It no longer copies that stream into the fixed 512-sector M4
journal. Raw M4 image recovery still scans exactly the original physical region.
The authority payload/record bounds match production's 64 MiB encoded payload
ceiling, including the header deduction for the record-count limit. This is an
admission ceiling, not evidence of qualification at the maximum size.

The saved 256-object disk with 513 authority records now passes the complete
native migration verifier, superseding the previous capacity rejection. The
retained production file-tree disk also passes native/file-tree verification.
New fixtures prove that the 513th record affects logical recovery while it is
outside fixed M4 image recovery; they reject truncation, corruption after the
old boundary, reordered/duplicated records and an exceeded caller record budget,
and accept the exact budget. Migration selftests pass 25,129 cases; the legacy
strict-prefix suite passes 19 records times 512 cuts. Python compilation and
diff whitespace checks pass. Firmware and on-media formats are unchanged.

Evidence is `target/storage-authority-verifier-20260912/`: before/after verifier
sources, source hashes, selftest logs, the previously rejected native disk's
successful full report, and the retained file-tree disk's successful report.

### Foreground authority compaction at 256 records: candidate (2026-09-12)

A diagnostic ELF changes only the default-capacity foreground compaction
threshold from 2,048 to 256 records. The small-store threshold, cold-boot
threshold, policy validation, record-reduction admission rule and all other
runtime code remain unchanged. Its source was restored before benchmarking.
The comparison uses the retained bounded-cache/manifest-reuse baseline and the
same 256 unique retained 4 KiB object sequence, default 223-segment provisioning,
128 MiB RAM, single-hart TCG and unthrottled Unix-socket serial runner.

| Counter | Baseline | Foreground threshold 256 |
|---|---:|---:|
| Read bytes | 68,399,104 | 64,811,008 |
| Read requests | 8,642 | 8,109 |
| Write bytes | 133,787,648 | 120,111,104 |
| Write requests | 3,733 | 3,642 |
| Flushes | 1,205 | 1,213 |
| GC rounds | 52 | 52 |

All 256 samples pass strict validation. Writes fall about 10.2%, reads about
5.2%, with eight additional flushes. Two compactions reduce 257 records to 130
and 256 to 193; the final pre-put record observation falls from 511 to 321.
This is promising but not yet retained: rate-limited timing, cold recovery and
broader workload qualification remain necessary, especially because extra
flushes can matter on real devices. It does not supersede the earlier rejected
128-record threshold trial, which used a different runtime and workload length.

Evidence is `target/storage-authority-compact256-20260912/`: before/trial source,
build log, saved ELF/hash, 256-sample JSONL/transcript, analysis and summary.
The working source is verified identical to the pre-trial snapshot; the default
foreground threshold remains 2,048. No elapsed-time benefit is claimed.

### Foreground 256-record compaction: rate-limited qualification (2026-09-12)

The saved baseline and candidate ELFs each run the same 256-object workload on
a fresh disk, in that order, at 4 MiB/s reads, 2 MiB/s writes, 400 read IOPS and
200 write IOPS. Both use default 223-segment provisioning, single-hart TCG,
128 MiB RAM and Unix-socket serial capture. All 512 samples pass. Each ELF's
complete I/O counters match its earlier unthrottled run exactly, including
52 GC rounds; candidate flushes remain 1,213 versus baseline 1,205.

Summed guest operation time is 65.260 s before and 56.711 s with the candidate,
a 13.1% reduction in this single pair. Median operation time is 60.600 versus
41.325 ms and maximum is 6.940 versus 6.292 s. Timing excludes boot and host
inter-command delays. This is one pair under a specific QEMU rate profile,
not a physical-card performance estimate or a repeated statistical result.

The candidate's final disk is retained after QEMU exits. It passes the complete
native migration verifier using the original blank image as unmanaged-prefix
baseline, covering the final state after both foreground compactions. This is
powered-off independent recovery validation, not a firmware reboot test.
The candidate remains unretained pending file-tree and firmware cold-start
qualification; working source still uses the 2,048-record foreground default.

Evidence is `target/storage-compact256-throttled-20260912/`: launcher, commands,
ELF hashes, capture-wrapper source, two JSONL/transcript pairs, final candidate
disk, counter/timing analysis and successful `native-verifier.json`. The wrapper
appends its Unix serial argument after normal runner metadata construction.

### Foreground compaction threshold retained (2026-09-12)

The default-capacity foreground threshold is now a named 256-record constant.
Cold compaction remains at 2,048 records; regions of at most 16 segments remain
at 128. Existing policy validation, reduction admission and watermark behavior
are unchanged. This retains the candidate evaluated in the preceding two
experiments: 10.2% fewer write bytes and 5.2% fewer read bytes for the 256-object
workload, with eight additional flushes, and 13.1% lower accumulated guest time
in one rate-limited QEMU pair. Those timing limits still apply.

The saved candidate ELF passes 256 MiB file write/full-readback/durable-delete
qualification with exactly unchanged counters: 303,964,160 read bytes,
284,540,928 write bytes and 90 flushes. The final named-constant source passes
the production three-boot file-tree gate, including hard links, symlink,
recursive removal, GC pressure, cold recovery and powered-off verification.
Duo compilation passes from its firmware directory. An initial root-directory
check omitted the firmware target configuration and failed; its log is retained
separately and is not counted as target validation. No real-board execution is
claimed. The preceding captured compacted image also passed the full independent
native verifier; this gate is additional file-tree/reboot regression coverage.

Evidence is `target/storage-compact256-qualification-20260912/`: file JSONL and
counter comparison, gate build/transcript and retained boot reports, successful
`duo-target.log`, source snapshots/hash and retained-decision summary. The
working tree keeps the new foreground constant. Python sample validation and
diff whitespace checks pass.

### Sixteen-source GC rounds: diagnostic candidate (2026-09-12)

A saved diagnostic ELF raises only `GC_MAX_SOURCES_PER_ROUND` from eight to
sixteen, on top of the retained 256-record foreground compaction and bounded
scan-proof cache. Existing source-memory and target-space admission checks stay
in force. Source is restored before running the candidate. Both workloads retain
256 unique 4 KiB objects on fresh default-capacity QEMU disks with 223 provisioned
segments, 128 MiB RAM, one TCG hart and unthrottled Unix-socket serial transport.

| Counter | Eight sources | Sixteen sources |
|---|---:|---:|
| Read bytes | 64,811,008 | 56,627,200 |
| Read requests | 8,109 | 6,626 |
| Write bytes | 120,111,104 | 83,046,400 |
| Write requests | 3,642 | 2,931 |
| Flushes | 1,213 | 973 |
| GC rounds | 52 | 22 |
| GC copied blob bytes | 322,560 | 300,160 |
| Total reclaimed segments | 416 | 352 |

All 256 samples pass. Write bytes fall 30.9%, read bytes 12.6%, and flushes 19.8%.
The reduction does not come from copying more live blob content. Fewer rounds
also avoid generating as much new metadata garbage, although physical source
selection and final free-space states differ. This finite-workload comparison
is not proof of identical steady-state capacity or lower worst-case pause.
Rate-limited latency, small-store pressure and recovery qualification are still
required before retaining the change. The production source limit remains eight.

Evidence is `target/storage-gc-source16-20260912/`: source snapshots, build log,
ELF/hash, complete JSONL and transcript, counter/GC analysis and verified source
restoration. No elapsed-time result is claimed for this diagnostic run.

### Sixteen-source GC: small-store and host qualification (2026-09-12)

The same candidate is built with the 16-segment small-store feature and run
with 128 unique retained 4 KiB objects, seeds 32 through 159, 128 MiB RAM and
a fresh unthrottled single-hart QEMU disk. All samples pass strict validation.
Compared with the retained eight-source small-store baseline, read bytes change
from 15,933,440 to 15,978,496 (+0.28%), writes from 71,536,640 to 71,249,920
(-0.40%), flushes from 745 to 737, and GC rounds from 43 to 42. Copied blob
bytes decline slightly from 6,173,440 to 6,160,000. The small-store foreground
compaction threshold is unchanged between these ELFs. The larger-store gain
does not generalize to a substantial small-store gain in this sequence.

Host qualification is incomplete: the library suite reports 204 passed,
one existing ignore, and one failed fixture precondition in
`gc_after_batched_staging_preserves_the_id_high_water`: the candidate no longer
produces the isolated free hole that fixture requires. This is not a reported
data mismatch, but it removes intended fragmented-placement coverage and must
be addressed without weakening the assertion. Cargo stops before the requested
integration suites, so those are not claimed to have passed for this candidate.

The candidate remains unretained; source is restored to eight sources per
round. Next qualification must restore meaningful fragmented-placement coverage
and measure rate-limited pauses before considering a production policy.
Evidence is `target/storage-gc-source16-small-20260912/`: before/trial source,
small-store ELF/build, complete failed host log, passing QEMU JSONL/transcript
and comparison summary. This run introduces no production runtime change.

### GC fixture coverage across eight/sixteen-source policies (2026-09-12)

Two fixtures now provision enough dead data to exercise their intended partial
collection cases under either source bound. The high-water fixture uses nine
rather than three dropped two-segment commits per round. Its isolated-hole
precondition remains, and an additional assertion compares every stored page
in the occupied neighbor before/after reuse. It still checks ID high-water
across GC/cold mount and reads the pinned staged stream afterward.

The manifest-retention fixture uses 64 test segments and ten dropped objects
before each collection, so a sixteen-source round has sufficient dead sources
without selecting the protected live manifest. Exact pointer/byte retention,
Allocated state, both offline verifications and cold payload reads remain
required. The earlier failed pointer equality was caused by the fixture's live
manifest entering the selected set; no assertion is weakened to accept it.

With sixteen-source runtime code, the final fixtures pass alongside 205 library,
five fused recovery, 24 GC recovery and six steady-state tests (240 passes and
one existing ignore across the completed runs). Restoring the eight-source
runtime and rerunning both modified fixtures also passes. Test improvements
are retained; the production runtime source limit remains eight pending latency
and firmware qualification. Evidence is `target/storage-gc-fragment-fixture-20260912/`:
before/final fixture sources, intermediate failure logs, successful candidate
suites, baseline fixture runs and source-restoration summary.

### Sixteen-source GC under QEMU rate limits (2026-09-12)

A fresh baseline/candidate pair runs 256 unique retained 4 KiB objects with the
same seeds, 223 provisioned segments, 128 MiB RAM, one TCG hart and Unix-socket
serial transport. Device limits are 4 MiB/s reads, 2 MiB/s writes, 400 read IOPS
and 200 write IOPS. All 512 samples pass; both ELFs reproduce their respective
unthrottled block counters exactly, including 52 versus 22 GC rounds.

| Guest operation metric | Eight-source baseline | Sixteen-source candidate |
|---|---:|---:|
| Summed time | 56.854 s | 36.727 s |
| Median | 42.234 ms | 41.660 ms |
| P95, nearest rank | 1.604 s | 1.054 s |
| P99, nearest rank | 4.569 s | 2.556 s |
| Maximum | 6.252 s | 3.890 s |
| Operations over one second | 16 | 14 |

Summed operation time falls 35.4%; the observed tail improves in this pair.
These are finite-workload sample statistics, not population quantiles or a
worst-case pause bound. Boot and host inter-command delays are excluded; the
QEMU limits do not model physical flash behavior. Larger source sets can still
have different copying costs for other live/dead layouts.

The powered-off candidate disk passes the complete native migration verifier
with the original blank image as unmanaged-prefix baseline. This qualifies its
final compacted state independently; firmware reboot/file-tree qualification
remains before retaining the source-limit change. Runtime source remains eight.
Evidence is `target/storage-gc-source16-throttled-20260912/`: exact command files,
ELF hashes, capture wrapper, both JSONL/transcripts, final disk, analysis/summary
and successful native verifier report. The wrapper's extra Unix serial argument
is added after standard runner environment metadata, as in preceding runs.

### Sixteen-source GC retained after firmware qualification (2026-09-12)

`GC_MAX_SOURCES_PER_ROUND` is now sixteen. Existing source-memory accounting,
relocation target admission, source ranking and checkpoint/recovery protocols
remain unchanged. The preceding default-capacity qualification measured 30.9%
fewer write bytes, 12.6% fewer read bytes and 19.8% fewer flushes for 256 retained
objects; a single rate-limited QEMU pair measured 35.4% less accumulated guest
time and a lower observed tail. The 16-segment workload was approximately flat
(-0.40% write bytes, +0.28% reads). These results retain their finite-workload
and QEMU-only limits; a sixteen-source bound is not a wall-clock pause bound.

The candidate passes 256 MiB file write/full readback/durable deletion with
identical counters to eight sources: 303,964,160 read bytes, 284,540,928 write
bytes and 90 flushes. Current firmware passes the production three-boot
file-tree gate (hard links, symlink, recursive removal, GC pressure, cold
recovery and powered-off verification), and Duo target compilation passes.
The earlier 240 host tests plus one existing ignore and independently verified
compacted disk supply the candidate's additional recovery evidence. The improved
fragmented-placement and retained-manifest fixtures remain in the worktree.

Evidence is `target/storage-gc-source16-qualified-20260912/`: file sample and
counter comparison, gate/build log and retained boot reports, Duo check log,
before/final GC source, hash and retained-decision summary. Strict sample
validation and whitespace checks pass. This supersedes the preceding temporary
source-restoration notes: production now retains the sixteen-source bound.

### Retained-object scaling hits quota-candidate capacity (2026-09-12)

An attempted extension to 512 retained unique 4 KiB objects stops at the same
boundary in both saved eight-source and sixteen-source ELFs: samples 0..255
pass, then sample 256 (seed 288, the 257th object) fails closed. Both runs use
fresh default-capacity disks, 128 MiB RAM and the same unthrottled serial runner.
The runner honors stop-on-failure; the second ELF is dispatched separately
after the first failure. No 512-object performance result is claimed.

Both transcripts report `InvalidQuotaPolicy` after publication, with 257 CAS
objects already present. Free segments remain 14 for eight sources and 10 for
sixteen sources, so this boundary is not disk exhaustion. Code inspection
identifies the matching 256-entry `MAX_PENDING_PERSISTENT_CHARGES` table:
`bind_persistent_candidate` returns `PrincipalCapacity` when its preallocated
vector is full; the fused authority path invokes this after
`publish_staged_object_with_authority` and maps the error to
`InvalidQuotaPolicy`. The candidates have live charges because the workload
retains its handles. This explains why earlier 256-object qualifications pass
but cannot establish behavior beyond that bound.

Further work must address capacity admission before publication and preserve
quota accounting, rather than silently increasing the table or interpreting
this failed attempt as completed benchmark work. Error reporting also needs
to distinguish quota-candidate capacity from corrupt policy. No runtime change
is introduced in this diagnosis. Evidence is
`target/storage-gc-512-retained-20260912/`: exact commands/ELF hashes, both
257-record JSONL/transcripts including failures, and `boundary-summary.json`.
The original full-length analysis script intentionally cannot accept these
incomplete runs as successful 512-object measurements.

### Candidate-table admission before publication retained (2026-09-12)

Persistent quota reservations now also reserve one candidate-table slot before
promotion or publication I/O. A table-wide reserved count prevents other
reservations or unreserved binders from stealing that capacity. Commitment
transfers ownership of the slot to the committed charge; binding consumes it.
Cancellation and dropping an unbound charge return only unused table capacity,
never committed byte charges. The table remains bounded at 256 entries, and
binding performs no allocation under the quota lock.

A distinct `PersistentCandidateCapacity` quota error reaches the runtime as a
proved pre-append admission rejection. The object facade reports
`InsufficientMemory`, rather than `Corrupt`, and retains its valid predecessor
proof. Other ambiguous append failures still invalidate recovery state. This
does not increase the retained-object ceiling or make the 512-object benchmark
possible; it removes the post-publication failure and misleading corruption
classification at that boundary.

Validation passes 241 selected host tests plus one existing ignore, covering
slot exhaustion, idempotent reservation/binding, exclusion of unreserved binders,
reservation cancellation, committed-unbound slot release without byte-quota
release, and existing mutation/cancellation recovery tests. In QEMU, the first
256 operations reproduce the prior I/O counters exactly. The expected 257th
rejection now reports `InsufficientMemory`, with object count still 256 and
generation 309 (previously 257 objects at generation 310 before failure).
The rejected-operation disk passes full independent native verification; its
report equals the earlier successful 256-object final-state report. The
production three-boot file-tree gate and Duo target compilation also pass.

Evidence is `target/storage-quota-candidate-admission-20260912/`: before/final
source and hashes, test/build logs, saved ELF, boundary JSONL/transcript with
its expected failed sample, captured disk, independent verifier result, retained
boot reports and summary. JSONL validation checks record validity, not a claim
that all 257 operations succeeded. The change is retained; no media format or
quota byte limit changes.

### Long-running create/read/revoke baseline (2026-09-12)

The existing `object-revoke` workload completes 512 sequential 4 KiB operations
with the retained runtime, including early candidate-slot admission. Each
operation publishes and verifies its payload, revokes the capability and checks
lookup denial; it is not a durable object-deletion benchmark. This keeps the
number of simultaneously retained capabilities bounded and confirms that the
256-candidate ceiling does not limit the lifetime count of such operations.
All 512 samples pass in fresh default-capacity, single-hart TCG QEMU with
128 MiB RAM and no device throttling.

The legacy object byte generator repeats every 256 seeds (the seed term is
truncated to one byte), so seeds 32..543 exercise two cycles of content. Despite
the legacy `unique` label, this is not a 512-distinct-content run. The earlier
256-retained-object runs use one complete cycle and are unaffected by this
cross-cycle distinction. A longer unique-content experiment needs a different,
explicitly versioned pattern before meaningful comparison.

| Operations | Write bytes | Flushes |
|---|---:|---:|
| 1–128 | 27,049,984 | 440 |
| 129–256 | 36,618,240 | 533 |
| 257–384 | 48,738,304 | 548 |
| 385–512 | 58,679,296 | 532 |

Total writes are 171,085,824 bytes with 2,053 flushes and 60 GC rounds. All
32,231,424 physical read bytes occur in the first block of 128 operations.
Foreground history compaction runs four times, but quiescent compaction never
runs and the final pre-put authority record count is 588. The write increase
supports investigating quiescent orphan-history compaction for larger regions:
its current runtime guard enables that path only at sixteen segments or below.
Safety still depends on the existing exact-policy and empty-root-admission
checks; workload behavior alone cannot justify discarding history.

Evidence is `target/storage-revoke-longrun-20260912/`: complete JSONL/transcript,
strict validation, analysis and per-128-operation summary. No runtime change or
elapsed-time performance claim is introduced in this baseline measurement.

### Large-region quiescent history compaction: candidate (2026-09-12)

A diagnostic ELF enables the existing exact-policy, empty-root-admission
compaction path for larger regions at 256 authority records. Small regions keep
128. All pin exclusion, minimum record savings and publication checks remain
unchanged. The working source is restored before benchmarking.

The same 512-operation create/read/capability-revoke workload passes every
sample on fresh default-capacity QEMU with 128 MiB RAM and one TCG hart. Content
still follows the documented 256-seed cycle. Total write bytes fall from
171,085,824 to 121,778,176 (28.82%); reads remain 32,231,424 bytes and GC rounds
remain 60. Flushes rise from 2,053 to 2,061. Candidate writes per 128 operations
are 27,049,984 / 31,879,168 / 32,247,808 / 30,601,216 bytes, rather than the
baseline's increasing 27,049,984 / 36,618,240 / 48,738,304 / 58,679,296.

Quiescent compaction executes twice. Maximum observed pre-put authority records
are 257 and the final observation is 132 versus the baseline's 588. The final
captured disk passes the full independent native migration verifier. These
results support the intended history-bounding effect, but do not establish
rate-limited latency, held-object behavior or firmware reboot qualification for
the expanded policy. The candidate is not yet retained and no elapsed-time
benefit is claimed.

Evidence is `target/storage-quiescent-large-20260912/`: before/trial platform
source, build and ELF, capture wrapper, 512-sample JSONL/transcript, final disk,
per-window counters and successful `native.json`. Source restoration and strict
sample validation pass; Unix-socket launch provenance follows earlier runs.

### Expanded quiescent compaction with held objects (2026-09-12)

The saved expanded-policy ELF completes 256 retained 4 KiB object operations
on a fresh default-capacity, 128 MiB, single-hart TCG QEMU disk. Every sample
passes, no quiescent compaction is reported, and every sample's complete block
counters equals the corresponding pre-change candidate-admission baseline.
This verifies that the expanded runtime call path does not compact this held
working set or introduce physical I/O in the tested sequence. It is not an
additional read of every older handle after every operation; the existing
live-witness and GC recovery tests cover their separate invariants.

Accumulated operation time is 11.639 s versus the prior baseline's 11.374 s;
last-half totals are 6.666 versus 6.402 s. These non-contemporaneous unthrottled
observations do not isolate a small CPU regression. Source inspection shows
that the facade constructs the authority import before the core rejects a
nonempty pin set; a future early negative hint could avoid that work, but must
never replace the core admission guard. No new API or optimization is added
from this observation alone.

Evidence is `target/storage-quiescent-held-20260912/`: JSONL, serial transcript,
run log and per-sample equality/timing summary. Strict sample validation passes.
The expanded policy remains an unretained candidate pending rate-limited timing
and firmware reboot/file-tree qualification; source stays at the existing
small-region-only quiescent policy.

### Expanded quiescent compaction under device rate limits (2026-09-12)

A fresh baseline/candidate pair each completes 512 create/read/capability-revoke
cycles at 4 MiB/s reads, 2 MiB/s writes, 400 read IOPS and 200 write IOPS, with
128 MiB RAM and one TCG hart. All 1,024 samples pass strict validation, and each
ELF's complete I/O totals exactly match its preceding unthrottled workload.
The cyclic-content and capability-revocation semantics remain as documented.

The reported latency field is explicitly put time plus get time: it includes
foreground maintenance charged to put, but excludes subsequent capability
revocation, boot and host inter-command delays. Summed put/get time changes
from 59.613 s to 32.125 s (-46.1%). Median changes from 83.528 to 33.716 ms;
nearest-rank P95 from 310.173 to 188.841 ms. Maximum remains approximately
3.89 s (3.884 before, 3.888 after), so this pair does not improve the worst
observed operation. Write bytes remain 171,085,824 versus 121,778,176; reads
are identical and flushes increase from 2,053 to 2,061.

This is one pair under QEMU rate limits, not a physical SD estimate or a
statistical bound. Evidence is `target/storage-quiescent-throttled-20260912/`:
ordered launcher, exact commands and ELF hashes, both JSONL/transcripts,
counter-equality assertions and timing summary. The candidate remains
unretained pending firmware/file-tree reboot qualification. No runtime changes
are made in this measurement turn.

### Expanded quiescent history compaction retained (2026-09-12)

The existing baseline-policy quiescent compaction path now applies to larger
regions at 256 records; regions of at most sixteen segments retain their
128-record threshold. The core exact-policy, empty root/reader admission and
minimum-saving checks are unchanged. A held-object workload already passed
without any quiescent compaction and with identical per-operation block counts.
The 512-cycle create/read/capability-revoke qualification measured 28.82% fewer
write bytes; one rate-limited pair measured 46.1% less accumulated put/get time.
Revocation is outside that latency field, and worst observed latency remained
approximately 3.89 seconds. These measurement limits continue to apply.

Final firmware qualification passes the production three-boot file-tree gate,
including hard links, symlink, recursive removal, GC pressure, cold recovery and
powered-off verification. Duo target compilation passes. The saved candidate
also completes 256 MiB file write/full readback/durable deletion with exactly
unchanged counters: 303,964,160 read bytes, 284,540,928 write bytes and 90 flushes.
The earlier independently verified compacted disk supplies additional final-state
recovery evidence. The expanded policy is retained, superseding earlier source
restoration notes; firmware and media-format safety checks remain in force.

Evidence is `target/storage-quiescent-qualified-20260912/`: file JSONL and counter
comparison, gate build/transcript and retained boot reports, Duo check log,
source snapshots/hash and retained-decision summary. Strict sample validation
and whitespace checks pass. Physical SD behavior remains unmeasured.

### Skip import reconstruction when pins exclude compaction (2026-09-12)

A bounded allocation-free scheduling hint now checks the current mount, root
registry and reader quiescence before the kernel constructs a complete authority
import for optional history compaction. A negative result skips that optional
work. A positive result can immediately become stale and does not authorize
history removal: the core still validates the import and closes empty-root
admission atomically before publication. No memory, media or policy limits are
changed. This avoids decoding/allocation work on held-object writes once the
history crosses the compaction threshold.

The existing live-witness test now also asserts hint behavior with live objects,
after release, and with/without an active reader. It and the compaction mutation/
cancellation atomicity test pass. A fresh 256-retained-object QEMU run passes
every sample with per-sample I/O exactly equal to the expanded-policy baseline.
Summed time is 11.603 versus the earlier 11.639 seconds; this small difference
is not a demonstrated speed improvement. The retained benefit is avoiding the
known unnecessary import reconstruction, not an asserted latency percentage.

The production three-boot file-tree gate and Duo target compilation pass.
Evidence is `target/storage-quiescent-hint-20260912/`: source snapshots, focused
test/build logs, saved benchmark ELF, held-object JSONL/transcript and comparison,
retained boot reports and Duo log. Strict sample validation and whitespace checks
pass. The hint is retained; the core compaction safety guard remains mandatory.

### Four-page full-verification hash windows rejected (2026-09-12)

The page adapter and both block backends already admit 128 KiB transfers;
there is no additional adapter-level split below that ceiling. A bounded host
experiment increased separate-tree full-verification hash fetches from two to
four aligned pages while preserving the sixteen-page hash budget (four windows
instead of eight). Range-proof behavior was left unchanged. The existing exact
read-set test was adjusted only to expect four-page runs for complete verification.

The candidate failed that test: a 64-page tree caused 1,280 requests and 5,120
page reads, rather than sixteen four-page requests. Fewer independently retained
windows caused repeated reads across interleaved tree levels. This is host
uncached-device evidence, not measured QEMU or SD latency. The candidate was
rejected before firmware qualification and the exact previous source restored.
Evidence is `target/storage-hash-window4-20260912/`: before/trial snapshots,
failing trial, restored regression log and machine-readable counter summary.

### Tiered hash windows: bounded host candidate (2026-09-12)

A follow-up experiment reserves one four-page window for leaf hashes and six
two-page windows for upper levels, preserving the sixteen-page hash budget.
Complete uncached verification of 16/32 MiB objects reads exactly 64/128 tree
pages in 24/48 requests, versus the original 32/64 requests. Existing range
read-set assertions and required-sibling corruption detection pass. The
unbounded policy regresses at 64 MiB: 928 requests and 1,920 page reads for a
256-page tree. The forty-segment test fixture supplies sufficient space; an
initial twenty-segment attempt stopped at cleaner reserve before verification.

Restricting tiered windows to 4–64 leaf-hash pages passes the extended test,
including the original policy at 64 MiB (256 pages in 128 requests). This is a
candidate for QEMU measurement, not an end-to-end speed claim. Runtime source
was restored; only the expanded 32/64 MiB exact-read/corruption regression and
its fixture capacity remain. No firmware or SD qualification is claimed.
Evidence is `target/storage-hash-tiered-20260912/`: original, unbounded and
bounded source snapshots; all trial logs; restored larger-object regression
and structured summary. Next qualification must also check firmware memory
bounds and end-to-end counters before considering runtime retention.

### Bounded tiered hash prefetch retained after QEMU qualification (2026-09-12)

The bounded candidate above is now retained. Full verification uses one
four-page leaf-hash window and six two-page upper-level windows when padded
leaf hashes occupy 4–64 pages. Other geometries retain the original windows;
range proofs are unchanged. The sixteen-page hash budget is preserved, and
geometry for the tiered policy is computed only on separate-tree hash reads.

A sequential QEMU pair completes 256 MiB file staging, publication, complete
readback and durable removal. Read requests decrease from 8,414 to 8,243
(171 fewer, 2.03%); every saved request is in complete readback, whose requests
decrease from 4,839 to 4,668. Read bytes remain 303,964,160, write bytes
284,540,928, write requests 3,053 and flushes 90. Staging, publication and
removal counters are exactly unchanged. Total interrupts decrease by 171.
One unthrottled timing pair measures 24.660378 versus 23.905744 seconds; this
is not evidence of a stable latency percentage or physical SD speedup.

Qualification passes 241 selected host tests (one existing ignored test),
including extended uncached 32/64 MiB read-set and corruption checks, GC and
fused-append recovery. The production three-boot file-tree gate passes cold
recovery and powered-off verification; Duo target compilation passes.
Strict JSONL and whitespace checks pass. Evidence is
`target/storage-hash-tiered-qemu-20260912/`: exact ordered commands and ELF
hashes, saved candidate, before/after JSONL and serial logs, per-phase deltas,
source snapshots, host/build/gate/Duo logs and retained-decision summary.

### Small-cache ABBA withdraws tiered runtime retention (2026-09-12)

Matched QEMU ELFs temporarily use a 64-page kernel cache, corresponding only
to the cache capacity of the Duo `milkv-python` configuration. All other
benchmark parameters remain unchanged. This is not an SD controller/card model.
Four fresh-disk 256 MiB file samples run in before/after/after/before order.
All pass. Each implementation repeats its exact I/O counters: tiered reads
9,008 versus 9,179 requests, with identical 311,455,744 read bytes, 284,540,928
write bytes, 3,053 write requests and 90 flushes. Savings remain exclusively
in complete readback.

Elapsed seconds are 24.300106 / 25.399294 / 25.121716 / 24.709728. Tiered mean
25.260505 seconds exceeds the original 24.504917 seconds by about 3.08%.
Two samples per implementation do not establish a universal regression, but
both orders fail to support retention for the small-cache workload. The tiered
runtime is withdrawn pending CPU/latency investigation, superseding the prior
retention decision. The original two-page policy and normal cache configuration
are restored; expanded 32/64 MiB read-set/corruption regressions remain.

Evidence is `target/storage-tiered-cache64-20260912/`: both saved ELFs, ordered
launchers/commands/hashes, four validated JSONL and serial logs, build logs,
source snapshots and ABBA/counter summary. Sources were restored before QEMU
execution, so runtime JSONL git metadata describes the restored working tree;
the saved ELF hashes and build-source snapshots identify the tested overrides.
No new hardware claim or memory-limit change is made.

### Inline hash output buffer experiment rejected (2026-09-12)

Inspection found a temporary 32-byte Vec for each hash-node read. An experiment
shared the existing reader through a generic output-buffer factory: normal
reads returned Vecs, while sibling and full-verification hash reads returned
inline arrays. Range/pointer validation remained ahead of buffer creation;
read-ahead, integrity checks and media ordering were unchanged. The selected
241 host tests pass (one existing ignored test), including uncached exact-read
sets, corruption detection and recovery.

A fresh-disk 64-page-cache QEMU ABBA test of the 256 MiB file workload passes
all four samples with exactly identical I/O: 9,179 reads / 311,455,744 bytes,
3,053 writes / 284,540,928 bytes and 90 flushes. Seconds in execution order
are 25.249669 / 25.917186 / 25.545376 / 24.147676. Candidate mean 25.731281
exceeds baseline mean 24.698673 by about 4.18%. This small sample does not
attribute the difference to allocation removal or the new async helper, but
does not justify retaining this implementation. The exact previous source is
restored; no firmware gate is claimed for the rejected implementation.

Evidence is `target/storage-hash-inline-buffer-20260912/`: before/trial source,
build/cache overrides, saved ELF and ordered commands/hashes, host log, four
validated benchmark outputs/transcripts and decision summary. Runtime source
metadata was collected after restoring the normal cache configuration; saved
ELF hashes and source snapshots identify the 64-page test build. Physical SD
behavior remains unmeasured.

### File workload phase elapsed ticks (2026-09-12)

QEMU file-sequential samples now expose `file_{stage,publish,verify,remove}_elapsed_ticks`.
Three additional timer reads divide the existing workload interval; removal
includes final async-scope cleanup through the original total-time endpoint.
These measure elapsed time including I/O waits, not CPU cycles. The converter
accepts old samples without times, but requires all four nonnegative integer
fields and an exact sum to elapsed_ticks when any is present. Selftests reject
missing, negative, boolean and inconsistent values.

A 256 MiB QEMU run passes with unchanged baseline I/O (8,414 reads,
303,964,160 read bytes; 3,053 writes, 284,540,928 write bytes; 90 flushes).
Phase ticks sum exactly to total time: staging 159,254,280 (63.63%), publication
143,340 (0.057%), verification 90,763,340 (36.27%), removal 102,960 (0.041%).
This single sample prioritizes staging for further attribution; it does not
explain earlier candidate regressions or demonstrate a performance improvement.
Evidence is `target/storage-file-phase-time-20260912/`: prior source snapshots,
build log and saved ELF, actual JSONL/transcript, phase summary and Duo check.
The timer instrumentation is retained; storage algorithms are unchanged.

### Separate staging workload generation from storage elapsed time (2026-09-12)

QEMU file-sequential samples additionally expose `file_stage_{pattern,push,finish,other}_ticks`.
Pattern measures SplitMix64 input generation, push measures awaited stager
push calls, and finish measures awaited stager finalization. Other is the
remaining staging interval, including setup, loop and timer overhead. These
are elapsed intervals, including I/O waits, not CPU-cycle attribution. Their
sum must exactly equal `file_stage_elapsed_ticks`; old samples remain accepted.
Converter selftests reject missing, negative, boolean and inconsistent values.

A fresh 256 MiB QEMU run passes with I/O exactly matching the prior baseline.
Staging ticks are pattern 46,029,130 (31.14%), push 100,172,280 (67.76%), finish
1,518,870 (1.03%) and other 109,500 (0.074%). Input generation therefore consumes
a substantial part of measured staging. This identifies push internals as the
next storage attribution target; optimizing the benchmark generator would not
by itself demonstrate improved storage. The pattern and total workload timing
semantics remain unchanged. Instrumentation is retained.

Evidence is `target/storage-stage-time-20260912/`: prior source snapshots,
QEMU build/saved ELF, validated JSONL and transcript, I/O equality and staging
summary, plus Duo target check log. This single run is not a stable timing
estimate or a physical SD measurement.

### Batch staging poll-time diagnostic (2026-09-12)

A temporary kernel-only probe times capacity preparation and wraps each
`stage_fs_data_chunks_for_maintenance` future poll. It records awaited batch
elapsed ticks, the sum of elapsed ticks inside polls and poll count. This
separates active poll intervals from suspended intervals; neither is pure CPU
or device time. Active intervals can include preemption, while suspended time
includes backend execution, I/O wait and scheduling. Diagnostic printing occurs
after the recorded batch interval and affects the enclosing workload timing.

A 256 MiB QEMU file test passes with exactly unchanged baseline I/O. Twenty-two
batch reports cover all 268,435,456 bytes, including the final partial batch.
Capacity preparation totals 8,522,200 ticks, batch elapsed 90,388,290 ticks,
active-poll elapsed 77,756,020 ticks and 5,578 polls. Active poll intervals occupy
86.02% of batch elapsed. This points next attribution toward synchronous encoding,
hashing and metadata work; it does not establish their individual shares.

The exact pre-probe kernel source is restored. Evidence is
`target/storage-push-poll-profile-20260912/`: before/probe source snapshots,
QEMU build and saved diagnostic ELF, validated JSONL/serial log, all batch rows
and aggregate summary. Runtime git metadata reflects restored source, so the
saved diagnostic source/ELF identify the probe. No production instrumentation,
algorithm change, latency improvement or physical SD claim is retained.

### File batch internal elapsed attribution (2026-09-12)

A temporary diagnostic splits maintenance file-data staging into node encoding
(including input clone, codec, metadata construction and decoded-buffer drop),
awaited `stage_blob_in_batch`, and awaited `publish_staged_batch`. Remaining
batch elapsed includes admission, ancestry recovery and bookkeeping. Temporary
RISC-V timer/accumulator hooks and kernel poll instrumentation are saved only
as evidence and are fully removed from production source after building.

All twenty-two batches covering 256 MiB pass; each batch's measured subintervals
fit inside its wall interval. I/O is exactly unchanged from the baseline.
Aggregate batch wall is 87,106,730 ticks: encoding 15,383,720 (17.66%), blob
staging 64,885,460 (74.49%), publication 2,393,580 (2.75%), remainder 4,443,970
(5.10%). Blob staging is the next attribution priority. Awaited sections include
I/O/scheduling waits, and timer/diagnostic overhead prevents treating this as an
uninstrumented latency comparison or a CPU-only breakdown.

Evidence is `target/storage-stage-internal-profile-20260912/`: before/probe
sources, build and saved ELF, validated JSONL/serial transcript, every batch's
nested timing and aggregate summary. Normal sources were restored before the
run; the saved source/ELF identify the temporary probe rather than runtime git
metadata. No algorithm change or physical SD performance claim is made.

### Complete streaming leaf borrowing: first implementation rejected (2026-09-12)

Streaming BlobWriter::write_chunk normally allocates/zeros a temporary 4 KiB
page, copies a complete leaf into it, then copies it into the owned scratch
batch. A candidate borrowed complete input pages directly, retaining padding
for short final leaves and the same failure/barrier path. The first implementation
placed an awaited write_exact_page call in each full/partial branch.

All 241 selected host tests pass (one existing ignored), including recovery and
corruption checks. Four 256 MiB QEMU samples in ABBA order pass with identical
I/O counters. Mean push ticks decrease 103,716,400 to 99,664,850 (3.91%), but
mean verification ticks increase 95,012,140 to 106,573,960 (12.17%). Total mean
seconds increase 24.863055 to 25.845784 (3.95%). No read algorithm was deliberately
changed; this experiment does not attribute the cross-phase timing difference
to code layout, async-state changes or another cause. Two samples per version
do not establish a universal regression, but fail to justify retaining this
implementation. Exact prior runtime source is restored.

Evidence is `target/storage-stream-borrow-page-20260912/`: before/trial source,
build and saved candidate, exact ordered commands/ELF hashes, host log, four
validated JSONL/transcripts and per-phase/total mean summary. The staged timing
fields expose a tradeoff that total I/O counts alone would miss. No physical SD
claim or production qualification is made for this rejected candidate.

### Baseline reproducibility and selected code-generation audit (2026-09-12)

Rebuilding the restored runtime with storage-bench-128m produces a byte-identical
ELF to `storage-stage-time-20260912/candidate.elf` (SHA-256
c091abc28e400f89540aaeccace5e3870fd79acb562654b24623a1a0666f1af3).
This rules out stale baseline build content in the complete-leaf borrowing ABBA
comparison. The earlier source-before snapshot of legacy_shell naturally differs
by retained stage-detail instrumentation; ELF equality is the authoritative
reproducibility check here.

LLVM symbol/disassembly comparison of that baseline and the rejected borrowing
candidate shows the selected write_chunk future body grows 690 to 738 bytes
(229 to 246 decoded instructions). The selected read_verified_blob body, two
ManifestRangeReader read bodies and kernel file read_chunk future retain sizes
4,288 / 1,094 / 1,306 / 652 bytes and identical instruction-mnemonic sequences.
Their addresses move. This is not byte/operand equivalence or coverage of every
callee, and does not establish a cause for the readback timing difference.
A shared await after choosing the input page is a concrete next candidate to
reduce write-state expansion; no runtime optimization is retained by this audit.

Evidence is `target/storage-baseline-rebuild-20260912/`: rebuild log/hash result,
both complete symbol tables, selected symbols, paired disassembly and instruction
sequence summary. It supports build reproducibility and the stated narrow code
comparison, not a physical SD or stable QEMU latency conclusion.

### Shared-await streaming page borrowing rejected (2026-09-12)

A second complete-leaf borrowing implementation selects a borrowed page or
owned padded tail before a single shared write_exact_page await. It retains
one source-level await but its selected compiled write_chunk future remains
738 bytes, versus baseline 690; source simplification did not shrink that body.
All 241 selected host tests pass (one existing ignored).

Four fresh-disk 256 MiB QEMU samples in ABBA order pass with identical I/O.
Mean push ticks are 101,574,445 versus 99,636,435 (candidate 1.91% lower),
verification ticks 95,348,675 versus 100,853,965 (5.77% higher), and total seconds
24.612369 versus 25.823085 (4.92% higher). Two samples per version do not
establish a universal regression, but fail to support end-to-end retention.
The exact prior source is restored. Further branch-shape variants are deprioritized
in favor of attribution inside blob hashing/encoding; no timing cause is claimed.

Evidence is `target/storage-stream-single-await-20260912/`: before/trial source,
host/build logs, compiled symbols and saved ELF, exact ordered commands/hashes,
four validated JSONL/transcripts and per-phase summary. No production gate or
physical SD result is claimed for the rejected candidate.

### Blob writer component timing identifies hashing priority (2026-09-12)

A temporary QEMU probe accumulates four disjoint regions: Merkle push plus
content-extent hasher update; content-page copying/buffering and awaited writes;
write_chunk tree-emission draining; and awaited stage_commit. The normal batched
staging probe supplies the enclosing wall interval. Hash timing also includes
small index/bookkeeping operations; page/commit intervals include waits. Timers
run per leaf and add overhead, so these are diagnostic proportions, not an
uninstrumented CPU profile or a performance comparison.

Twenty-two batches cover all 256 MiB and pass with unchanged baseline I/O.
Batch wall totals 88,493,550 ticks. Hash regions total 45,403,900 (51.31% of
batch wall), pages 15,678,840 (17.72%), tree emissions 1,443,740 (1.63%), and
stage_commit 2,402,060 (2.71%). The remaining 23,565,010 ticks (26.63%) include
file encoding, batch publication, preparation, ancestry and other bookkeeping.
These percentages use whole-batch wall, not blob-only time. Every batch's
measured regions fit its wall interval. Hash implementation and repeated work
are the next priority; integrity checks remain required.

Exact pre-probe source is restored. Evidence is
`target/storage-blob-component-profile-20260912/`: before/probe sources,
QEMU build and saved ELF, validated JSONL/serial transcript, batch records and
summary. Saved sources/ELF identify the temporary instrumentation; runtime git
metadata reflects restored source. No runtime optimization or physical SD
claim is retained by this diagnostic.

### SHA software backend audit and compact screening (2026-09-12)

The pinned sha2 0.11.0 RISC-V build uses its unrolled software SHA-256 backend,
already compiled at opt-level 3. Merkle leaf hashes include domain, object kind,
leaf index and leaf length before content. Content-extent hashes cover the
exact payload independently; these are different integrity commitments and
cannot be substituted for one another.

A temporary target rustflag `sha2_backend_soft="compact"` selects sha2's bundled
compact software implementation without adding ISA requirements or changing
storage source. This cfg selects software backend variants across sha2, not a
new hardware accelerator. The selected compress256 body shrinks from 14,842
to 1,422 bytes. A sequential 256 MiB QEMU screening pair passes complete
readback/removal with identical I/O. Total seconds are 24.563940 versus
26.908408; push ticks 102,786,030 versus 109,664,810 and verification ticks
94,340,660 versus 108,872,320. One pair does not prove a universal slowdown,
but provides no performance reason to retain this backend. Default build
configuration is restored; no hardware or production qualification is claimed.

Evidence is `target/storage-sha-compact-20260912/`: original/trial target config,
build and saved ELF, symbol table, ordered launcher/commands/hashes, validated
before/after JSONL and transcripts, and decision summary. Runtime metadata sees
the restored configuration; saved config/ELF identify the test. Smaller code
alone is not treated as storage performance improvement.

### Borrowed file-node encoding retained (2026-09-12)

The maintenance batch staging path now encodes node content from the input
slice directly, instead of cloning it into an owned FsDataNodeV1 first.
A crate-private parts encoder shares the original validation and canonical
encoding implementation with the public owned-node API. Metadata takes the
existing ancestor vector after encoding, avoiding its extra clone too. Normal
3 MiB staging chunks no longer allocate a second 3 MiB content Vec during
encoding. This is a source-level temporary-allocation reduction, not a measured
whole-guest peak-memory bound. Disk format, hashes and publication barriers
are unchanged; no integrity check is removed.

Four fresh-disk 256 MiB QEMU samples in ABBA order pass with identical I/O.
Mean push ticks decrease 101,807,965 to 88,370,445 (13.20%). Mean total seconds
decrease 24.601213 to 22.492182 (8.57%). Mean readback ticks also change from
94,868,220 to 85,300,625 although its algorithm was not changed; the complete
timing difference is not attributed solely to saved copies. Both orders favor
the candidate, but two samples per implementation are not a population bound
or a physical SD result.

All 241 selected host tests pass (one existing ignored), covering codecs,
corruption checks, GC/fused recovery and steady-state behavior. Production
three-boot file-tree verification passes hard links, symlink, recursive removal,
GC pressure, cold recovery and powered-off checking. Duo target compilation,
strict JSONL validation and whitespace checks pass. The change is retained.
Evidence is `target/storage-fs-borrow-encode-20260912/`: before/final sources,
compiled candidate and exact ABBA commands/hashes, host/build/gate/Duo logs,
retained boot reports, four JSONL/transcripts and decision/phase summary.

### Borrowed encoding under a 64-page cache (2026-09-12)

Freshly rebuilt before/after firmware both use a temporary 64-page kernel cache
and the same retained phase instrumentation. Four fresh-disk 256 MiB file tests
in ABBA order pass. All I/O counters match: 9,179 reads / 311,455,744 bytes;
3,053 writes / 284,540,928 bytes; 90 flushes. Mean push ticks decrease
102,771,230 to 94,032,505 (8.50%). Verification ticks decrease 93,592,525 to
91,937,825. However input-pattern ticks increase 46,993,545 to 64,408,615, and
total mean seconds increase 24.522069 to 25.217461 (2.84%).

These results support the observed push-time reduction, not a small-cache
end-to-end speedup. The pattern-generation increase is recorded without causal
attribution; it must not be hidden by reporting only favorable phases. The prior
borrowed-encoding change remains retained for its avoided temporary content
allocation and measured staging benefit. This cache experiment changes no
production limits and makes no physical SD performance claim.

Evidence is `target/storage-fs-borrow-cache64-20260912/`: before/after source and
build logs, both ELFs, exact ABBA launcher/commands/hashes, four validated
JSONL/transcripts and full per-phase summary. Normal cache configuration and
retained optimized sources are restored and byte-compared to their saved
snapshots. Runtime metadata reflects restored source; saved builds identify
the 64-page override used for both measured versions.

### Pattern-generation anomaly audit; icount diagnostic invalid (2026-09-12)

The small-cache borrowed-encoding ELFs retain 142-byte pattern fill/matches
bodies and a 72-byte word generator; their addresses move by ten bytes. The
selected copy_from_slice helper bodies also retain sizes and instruction-mnemonic
sequences. Paired disassembly is archived. This does not cover every callee,
operand, runtime data placement or scheduling effect, and does not establish
why pattern elapsed ticks differ.

An attempted instruction-count virtual-clock run appended QEMU
`-icount shift=0,align=off,sleep=off` to the serial wrapper's actual arguments.
The baseline failed closed during file-tree root recovery before file staging;
the ordered launcher consequently did not start the candidate. There are zero
valid performance samples. The failure reason is retained without guessing its
underlying cause. No timeout, recovery check or production configuration was
changed to force the diagnostic to pass. Its clocks must not be interpreted as
real latency or physical SD behavior.

Evidence is `target/storage-pattern-icount-20260912/`: diagnostic wrapper and
launcher, command/ELF hash record, failed baseline transcript/output, complete
symbol tables, selected paired disassembly and audit summary. No runtime source
change is retained, and the generation-time anomaly remains unresolved. Existing
small-cache total-time results and their caveats remain in force.

### Current representative QEMU matrix (2026-09-12)

Nine scenarios on the retained borrowed-encoding ELF each run five samples in
one fresh-disk VM (seeds 32–36, no warmups), and all 45 pass strict validation.
Default cache is 512 pages with 128 MiB RAM and one TCG hart. Subsequent-four
medians, keeping the first sample separate, are: 4 KiB object put 16.677 ms/get
0.219 ms; 128 KiB put 24.623/get 5.321; 360 KiB put 35.435/get 12.816; 1 MiB
put 69.277/get 33.092. Range-get on a 360 KiB object is 2.132 ms with the normal
post-put cache and 4.334 ms after the existing data-cache clearing operation.
These are get fields, not totals that also include put.

File create/validate/remove medians are 12.718 ms for 4 KiB and 64.967 ms for
1 MiB. The 16 MiB sequential workload, including generation, write, full readback
and removal, is 1,407.985 ms. This is a short sequence, not a steady-state bound,
and there is no matched Linux/SD baseline. Different workloads retain their
existing content patterns and timing scopes; old-table ratios are not inferred.

The 4 KiB object workload writes a median 137,216 bytes (33.5 times logical
input) and issues three flushes. Its fixed metadata cost merits renewed
attribution; required publication ordering must remain intact. Evidence is
`target/storage-current-matrix-20260912/`: exact commands/ELF hash, nine complete
JSONL/transcripts, first/subsequent latency ranges and counters, and report.md.
No runtime code changes are made in this measurement turn.

### Small-put media and write-request attribution (2026-09-12)

A captured five-object 4 KiB QEMU run reproduces every sample's I/O from the
current matrix. Its final put writes 139,264 bytes (136 KiB); the preceding
matrix's four-sample median remains 137,216 bytes. Offline native verification
passes and verifies five unique blobs. Latest checkpoint generation is eight.

The final generation contains five extent records: canonical blob payload
4,480 bytes / 16 KiB framed; manifest 256 bytes / 12 KiB framed; CAS catalog
1,408 bytes / 12 KiB framed; authority 5,824 bytes (eleven records) / 16 KiB
framed; allocation 137 bytes / 12 KiB framed. Extents total 68 KiB. Two segment
header/summary/seal sets add 48 KiB. A second run with QEMU write tracing repeats
all counters and attributes all eight final write requests: the first three
write those 116 KiB, two 4 KiB writes preclear future segment seal pages, and
three 4 KiB writes clear/write/seal the checkpoint slot (sectors 2104/2096/2104).
The future seal positions and zero contents are checked against captured media.
The resulting 68 + 48 + 8 + 12 KiB exactly equals measured 136 KiB.

The duplicated segment structural overhead is a concrete next investigation:
small data and metadata currently occupy separate segments. Any packing change
must preserve pointer validation, free-space ownership and publication barriers;
this attribution does not authorize dropping flushes. Evidence is
`target/storage-small-write-attribution-20260912/`: captured disk and native
verification, decoded/hash-checked records, original and traced runs, QEMU trace,
wrappers, parser and exact byte accounting. No runtime changes are made.

### Compact single-object fused packing (2026-09-12)

Retain compact V2 single-object packing: the fused publisher reuses the existing
batch publication machinery to place payload and metadata in one segment when
they fit. Split/noncompact layouts retain their prior publication path; the
batch publisher falls back to a separate metadata segment when necessary.
Quota charges remain attached to the returned handle and checkpoint barriers
are preserved. A new cold-recovery test requires a 4 KiB append to allocate
exactly one segment and verifies recovered content.

Five-object QEMU measurements save 28 KiB and two write requests on every put;
normal subsequent puts still require three flushes. For 256 held 4 KiB objects,
read bytes rise from 56,627,200 to 76,550,144 (+35.2%), while write bytes fall
from 83,046,400 to 53,743,616 (-35.3%) and flushes from 973 to 829 (-14.8%).
Both unthrottled captured candidate images pass offline native verification.

One sequential before/after QEMU pair, throttled to 4/2 MiB/s read/write and
400/200 read/write IOPS, completes all 256 samples on each side. Cumulative
put+get latency is 36.949943 versus 30.120402 seconds (-18.5%). These are one
pair of simulated measurements, not an SD-card result or a stable latency
bound; the increased read traffic is a material tradeoff. Independent fresh
images, 128 MiB RAM, one hart and TCG single-thread are used on both sides.

Validation: 242 selected host tests pass, one ignored; fused append fault cuts,
GC recovery and quota tests are included. The production three-boot file-tree
gate passes (including offline verification), as does Duo file-tree/legacy-shell
release compilation. No hardware was accessed. Evidence:
`target/storage-single-object-pack-20260912/` contains source snapshots, saved
benchmark ELF, exact command/hashes, JSONL and serial logs, captured images and
native reports, comparison.json and qualification logs. The final source only
changes documentation from the measured candidate.

### Packed-segment scan memo capacity (2026-09-12)

Increase the verified immutable-segment scan memo from 192 entries / 256 KiB
to 256 entries / 320 KiB of requested resident allocations. This explicitly
trades up to 64 KiB additional allocation budget for fewer descriptor-chain
reads after compact single-object packing. Byte and entry limits, optional
allocation failure behavior, exact generation identity, checkpoint horizon,
and GC invalidation remain unchanged.

A 256-object 4 KiB held-object QEMU run passes at read/write limits of 4/2 MiB/s
and 400/200 IOPS. Relative to the preceding single-object packing run with the
same limits, reads fall from 76,550,144 to 69,320,704 bytes (-9.4%) and requests
from 8,274 to 7,439. Writes remain exactly 53,743,616 bytes / 1,874 requests and
829 flushes. Cumulative put+get time is 30.120402 versus 28.318166 seconds
(-6.0%): a sequential single comparison, not a replicated speed bound or SD
hardware measurement. Baseline: storage-single-object-pack-20260912/limited-after.

All read savings occur at the two GC episodes (sample indices 206 and 234).
Growth episodes at indices 22, 55, 110 and 164 have exactly unchanged reads;
inspection confirms grow() ends with a full mount(). This identifies growth
remount authentication as a separate follow-up; it is not changed here.

Qualification: 242 selected host tests pass / one ignored, including cache
budget, eviction, generation/horizon and GC invalidation coverage; captured
native disk verification reports status ok; the production three-boot file-tree
gate and Duo file-tree/legacy-shell release compilation pass. This retains the
bounded cache change. No hardware was accessed. Evidence and snapshots:
`target/storage-scan-cache320-20260912/`.

### Verified successor installation after growth (2026-09-12)

Replace grow()'s full remount with the existing verified-successor installation
protocol. Growth still reads back its new allocation extent, rereads/selects
both checkpoint slots and superblock pairs, checks the predecessor checkpoint,
and validates the exact growth allocation transition before publishing runtime
state. Existing catalog, authority and CAS state move into the successor; only
the old allocation moves into a transition witness. This avoids cloning the
live object catalog. No new all-content verification claim is manufactured:
the predecessor's CAS-verification flag is carried forward only if already set.
Cold mount/scrub still performs its original media validation.

The shared successor installer now accepts the compact predecessor witness.
Growth's measured transient memory peak is passed separately so the old bitmap
is not counted twice. The first implementation failed the existing exact-budget
267-byte empty-store test; this was corrected without increasing that budget.
The new regression compares 4 KiB and 128 KiB objects: growth I/O is identical,
content reads succeed after two successive growths and a cold mount succeeds.

All 256 held-object samples pass under QEMU's 4/2 MiB/s and 400/200 read/write
IOPS limits. Compared with storage-scan-cache320-20260912/run.jsonl:

| Metric | Before | After |
| --- | ---: | ---: |
| Cumulative put+get seconds | 28.318166 | 15.496130 |
| Read bytes | 69,320,704 | 18,550,784 |
| Read requests | 7,439 | 2,209 |
| Write bytes | 53,743,616 | 53,694,464 |
| Write requests | 1,874 | 1,862 |
| Flush requests | 829 | 825 |

Time decreases 45.3%, reads 73.2%. The only remaining read episodes are the
same GC samples 206 and 234, with byte counts exactly matching the baseline;
all growth-related device reads are served without additional block reads in
this cached QEMU workload. This is a single sequential comparison on 128 MiB,
one-hart TCG, not an SD-card result or a replicated latency bound.

Qualification: 242 existing selected host tests and the new growth regression
pass (243 total, one ignored). Includes exact-budget admission, all growth
mutation failure/cancellation boundaries, cold/offline recovery and shared
successor callers' fused-publication/GC tests. Captured native image verification
reports status ok; production three-boot file-tree gate and Duo compilation pass.
Retain this change. No hardware accessed. Commands/environment, candidate ELF,
source snapshots, JSONL, captured disk, verifier and qualification logs are in
`target/storage-growth-successor-20260912/`.

### Growth successor with a 64-page cache, ABBA (2026-09-12)

Qualify the retained growth-successor optimization with the block page cache
restricted to 64 pages (256 KiB). Total guest memory remains 128 MiB; this is
not a 64 MiB board simulation. Both ELFs contain compact single-object packing
and the 320 KiB scan memo; only growth-successor installation differs.
Independent images, one-hart TCG and 4/2 MiB/s plus 400/200 read/write IOPS are
used for four runs in before/after/after/before order. Each holds 256 4 KiB
objects using seeds 32..287. All 1,024 samples pass.

| Metric per 256 operations | Before | After |
| --- | ---: | ---: |
| Mean cumulative seconds, two runs | 33.326043 | 18.194337 |
| Read bytes | 86,618,112 | 26,492,928 |
| Read requests | 9,856 | 3,716 |
| Write bytes | 53,743,616 | 53,694,464 |
| Flush requests | 829 | 825 |

Every aggregate I/O count repeats exactly within each version. Time improves
45.4%, reads 69.4%. Individual totals are 33.337486 / 18.227043 / 18.161630 /
33.314600 seconds. Median operation latency changes only modestly, from
36.23–36.38 ms to 35.13–35.81 ms. The gain is principally removal of growth
spikes: the four growth samples together take 15.097542 seconds before versus
0.139274 after in the first pair. Each new growth sample reads 8 KiB, compared
with approximately 4.3/8.9/19.3/24.8 MiB before.

GC remains: samples 206 and 234 take 8.855605 versus 8.851243 seconds in that
pair, about 49% of the improved total. The maximum candidate operation remains
about 5.51 seconds. The next bottleneck is therefore foreground collection,
not residual content-proportional reads during growth. These QEMU measurements
do not establish actual SD-card latency.

Build provenance: copying saved sources with preserved timestamps initially
caused Cargo to reuse an unsuitable artifact. No timed run used that pair.
Both versions were rebuilt after updating source timestamps; compilation logs
and distinct ELF hashes are saved. The unqualified ELF and logs are retained
and explicitly named unqualified/stale. Runtime sources and normal page-cache
configuration were restored before measurement and checked byte-for-byte.
The saved source snapshots, commands.json, socket wrapper and ELF hashes are
the authority for the compared code; runtime Git metadata reflects the restored
worktree. This turn changes benchmark documentation only; the temporary 64-page
cache override is not retained. Prior growth safety qualification remains in
storage-growth-successor-20260912; these runs provide performance/readback
coverage, not a new powered-off image verification.

Evidence: `target/storage-growth-cache64-20260912/`, including all four JSONL
files, serial logs, exact commands, builds, snapshots, analyze.py and summary.json.

### Foreground GC phase I/O attribution, 64-page cache (2026-09-12)

A temporary RISC-V hook records cumulative virtio counters at eight GC phase
boundaries. The QEMU workload is the retained growth-successor runtime with a
64-page block cache, 128 MiB guest, one-hart TCG, 256 held 4 KiB objects and
4/2 MiB/s plus 400/200 read/write IOPS limits. All samples pass, and every
sample's complete I/O counters match storage-growth-cache64-20260912/after.jsonl
exactly. Diagnostic latency is not used as a performance comparison.

Four collections occur in two foreground episodes. Their combined I/O is:

| Phase | Read bytes | Read requests |
| --- | ---: | ---: |
| Typed-child decoding and mark | 0 | 0 |
| Live manifest loading and planning | 18,612,224 | 2,204 |
| Relocation writes, including source reads | 442,368 | 108 |
| Staged root readback | 1,732,608 | 139 |
| Manifest / relocated blob readback | 4,038,656 | 986 |
| Publication and reuse barrier | 98,304 | 4 |

Total GC reads are 24,924,160 bytes: manifest loading accounts for 74.7%,
relocation source reads only 1.8%. The first collection alone reads 14,344,192
bytes while loading live manifests/planning. Source inspection establishes
that code between completed load_live_manifests and relocation contains no
device reads, so the combined measured phase's I/O belongs to manifest loading.
That path uses read_pointer_payload, which authenticates the containing segment
chain on a scan-memo miss. This identifies metadata/segment proof access as the
next target; reducing copied data alone cannot remove most of this workload's
foreground read cost. The phase trace does not by itself distinguish memo
miss reasons or prove a safe way to skip validation.

No runtime optimization is added here. The hooks and cache override were
restored before the run, using a saved instrumented ELF; source comparisons
confirm normal runtime restoration. Snapshot source files and the saved ELF,
not restored-worktree Git metadata, define the profiled implementation.
Evidence: `target/storage-gc-phases-20260912/`, with before/trial sources,
build, ELF, socket runner, environment, JSONL, phase serial trace and summary.json.
This is QEMU evidence only; no hardware or new crash-recovery claim.

### Rejected reverse GC manifest traversal (2026-09-12)

Trial: load live manifests in reverse BlobKey order, then reverse the resulting
Vec to preserve every downstream ordering invariant. All pointer/segment and
payload validation, memory limits and publication behavior remain unchanged.
243 host tests pass / one ignored. With 64-page block cache, 128 MiB guest,
one-hart QEMU TCG and 4/2 MiB/s plus 400/200 read/write IOPS limits, all 256
held 4 KiB objects pass.

Compared with storage-growth-cache64-20260912/after.jsonl, total reads worsen
from 26,492,928 to 26,796,032 bytes (+303,104), and read requests from 3,716 to
3,794. Writes remain 53,694,464 bytes / 1,862 requests with 825 flushes. Single
run cumulative latency changes from 18.227043 to 18.420752 seconds; this small
timing difference is not independently established as a stable regression,
but the trial does not reduce the targeted I/O. Reject and restore the original
traversal. No new runtime change remains. The next diagnostic should count
scan-memo hits/misses and evictions rather than infer them from traversal order.

Evidence: `target/storage-gc-manifest-order-20260912/`, including before/trial
source, host/build logs, saved trial ELF, wrapper, JSONL, serial output,
environment and comparison.json. The measured cache override was temporary
and restored; the saved ELF defines the experiment. No hardware accessed.

### GC scan-memo miss classification (2026-09-12)

Temporary counters classify scan-memo hits, missing keys, checkpoint-horizon
mismatches, LRU evictions and oversized proofs. Last-observed resident entry
count/requested allocation bytes are sampled at lookup. GC phase boundaries
print cumulative counters; the hooks and 64-page cache override are restored
before running the saved ELF. All 256 QEMU samples pass and each sample's full
I/O counters exactly match storage-growth-cache64-20260912/after.jsonl.
The same 128 MiB, one-hart TCG and 4/2 MiB/s plus 400/200 IOPS limits apply.
Diagnostic timing is not a performance result.

| Collection | Manifest hits | Manifest missing keys | Evictions | Horizon mismatches |
| --- | ---: | ---: | ---: | ---: |
| 1 | 0 | 206 | 0 | 0 |
| 2 | 206 | 0 | 0 | 0 |
| 3 | 206 | 28 | 0 | 0 |
| 4 | 234 | 0 | 0 | 0 |

All memo counters are zero at the first collection: no memo lookup occurred
before GC in this workload. No oversized proof was refused and no eviction or
horizon mismatch occurred throughout the measured run. The greatest observed
phase-end resident footprint is 248,856 bytes, below the retained 320 KiB
budget. Reported residence is a last-lookup observation, not an allocation
high-water measurement. GC pruning can change it between samples.

This resolves the remaining manifest-read cause: first-use segment proofs,
not insufficient retained memo capacity. The two later 28-miss additions match
new objects since the first collection. Reverse ordering cannot remove these
mandatory first authentications. A next candidate is performing the identical
segment scan for newly packed segments immediately after publication while
pages are still cached, inserting only the genuinely validated proof. It must
be measured for total I/O, ordinary put overhead and GC pauses; simply moving
uncached reads earlier would not satisfy the optimization goal. No proof may
be seeded from unverified transaction intent or used to bypass payload checks.

No runtime code change remains. Evidence:
`target/storage-scan-memo-probe-20260912/`: before/trial source snapshots,
build log, instrumented ELF, socket runner, environment, JSONL, complete phase
serial trace and summary.json. No hardware or new crash-recovery claim.

### Authenticate packed segments while hot (2026-09-12)

Retain eager segment-proof validation after compact single-object publication.
For a new uniquely stored compact blob whose allocation root shares the packed
segment, run the existing device-backed scan_segment before installing the
successor/returning the handle. Only the actual scanner result enters the
bounded verified-scans memo. Deduplicated objects and separate metadata-segment
fallbacks do not use this new step. Descriptor, summary, seal and pointer checks
are preserved; payload authentication remains independent. No checkpoint or
flush ordering is removed and no unverified transaction data seeds the memo.

The aim is to perform the first proof while recently written pages remain in
the device cache, instead of waiting until foreground GC. In a 64-page-cache,
128 MiB one-hart TCG QEMU run, all 256 held 4 KiB object operations pass under
4/2 MiB/s and 400/200 read/write IOPS limits. Baseline is
storage-growth-cache64-20260912/after.jsonl.

| Metric | Before | After |
| --- | ---: | ---: |
| Cumulative put+get seconds | 18.227043 | 15.128103 |
| Read bytes | 26,492,928 | 11,186,176 |
| Read requests | 3,716 | 2,319 |
| Write bytes | 53,694,464 | 53,694,464 |
| Write requests | 1,862 | 1,862 |
| Flush requests | 825 | 825 |
| Median operation ms | 35.8125 | 37.2635 |
| P95 operation ms (nearest rank) | 67.033 | 67.678 |
| Maximum operation ms | 5,508.278 | 2,936.415 |
| Two GC-episode operations, seconds | 8.851243 | 5.359543 |

Total reads decrease 57.8%, cumulative time 17.0%. Median rises about 4.1%:
this spreads real validation work into ordinary commits rather than making
all operations faster. The GC episode and maximum latency improvements matter
for foreground responsiveness, while reduced total reads show this is more
than merely moving uncached I/O earlier. Timing is a single sequential
comparison; no physical SD-card claim is made.

Qualification: 243 selected host tests pass / one ignored, including fused
append failure/cut recovery, GC and quota coverage. The captured native image
verifier reports status ok; production three-boot file-tree gate and Duo
file-tree/legacy-shell release compilation pass. The temporary 64-page cache
override was restored; normal configuration remains 512 pages except its
existing milkv-python setting. Source snapshots and the saved ELF define the
measured candidate; environment Git metadata sees the restored configuration.
Evidence: `target/storage-hot-segment-proof-20260912/`, with source snapshots,
build/host/gate logs, saved ELF, wrapper, JSONL, serial log, captured disk,
native report and comparison.json. No hardware accessed.

### Larger-object check of eager packed-segment proofs (2026-09-12)

Run 256 held 128 KiB objects on each side of eager packed-segment validation.
Both saved ELFs use a 64-page block cache, 128 MiB guest, one-hart TCG and
4/2 MiB/s plus 400/200 read/write IOPS limits. The before ELF is the retained
growth-successor implementation; the after ELF adds eager proof validation.
Both complete all samples and four GC rounds. Exact commands and hashes are
in commands.json.

| Metric | Before | After |
| --- | ---: | ---: |
| Cumulative seconds | 36.112948 | 36.303049 |
| Put seconds | 33.693725 | 34.283908 |
| Get seconds | 2.419223 | 2.019141 |
| Read bytes | 60,280,832 | 59,428,864 |
| Read requests | 3,781 | 3,699 |
| Median operation ms | 111.7160 | 113.3305 |
| P95 operation ms | 149.941 | 151.209 |
| Maximum operation ms | 5,052.535 | 5,045.230 |

Writes are identical: 94,195,712 bytes / 2,181 requests / 825 flushes.
Read savings are only 1.4%; cumulative time increases 0.5%. This single pair
is not evidence of a stable timing regression, but clearly does not reproduce
the much larger 4 KiB benefit. Eager validation adds put work and reduces get
work, with little effect on the maximum pause. The implementation should next
be scoped using actual inline-versus-external content handling rather than
assuming all compact objects benefit equally. persistent_authority.rs retains
that distinction via recovered.external_root when constructing the fused
publication; it is not currently passed into FusedAuthorityPublication.

This turn adds measurement documentation only, with no new runtime change.
The broad eager-proof implementation remains as previously qualified pending
that refinement; these results explicitly limit its benefit claim to tested
workloads. No hardware or additional power-cut validation is claimed.
Evidence: `target/storage-hot-proof-128k-20260912/`, including commands/hashes,
runner, both JSONL/transcripts and summary.json.

### Rejected persistent-inline proof policy (2026-09-12)

Trial: pass recovered.external_root.is_none() through FusedAuthorityPublication
as the condition for eager packed-segment validation. File-tree batch
publications set this flag false. The policy compiles in the ordinary QEMU
configuration and 243 host tests pass / one ignored. Two 64-page-cache QEMU
runs of 256 operations each pass under the existing 128 MiB / single-hart TCG /
4/2 MiB/s / 400/200 IOPS configuration.

The behavioral result rejects the premise: 4 KiB benchmark objects also have
external content roots. The trial disables their eager proof, increasing total
reads back to 26,492,928 bytes versus 11,186,176 with the retained eager path.
128 KiB per-sample counters exactly match its pre-eager baseline, as intended,
but preserving that behavior while losing the principal 4 KiB benefit is not
an acceptable refinement. Restore all three runtime files; the broad eager
proof change from storage-hot-segment-proof-20260912 remains retained.

Source inspection identifies the actual bypass: kernel HotReadCache accepts
objects up to STORAGE_V2_HOT_READ_MAX_OBJECT_BYTES (72 KiB), with total 256 KiB
and 64-entry bounds, and caches external payloads too. On-disk inline/external
classification is therefore not a proxy for whether later reads touch CAS.
The next refinement should explicitly communicate the platform's hot-content
cache policy, rather than depend on persistent format classification. The
previous 128 KiB measurement's proposed inline/external split is superseded
by this result; these data do not justify that split.

Evidence: `target/storage-inline-proof-policy-20260912/`, with before/trial
sources, ordinary and 64-page candidate ELFs, build/host logs, exact commands,
JSONL/transcripts and summary.json. Labels inline4k/external128k preserve the
original experiment labels; inline4k is not a proven on-disk classification.
The candidate and cache override are fully restored. No hardware or new
power-cut qualification is claimed.

### Scope eager proofs to platform hot-content admission (2026-09-12)

Retain an explicit runtime performance policy:
SegmentStore::set_hot_content_proof_max_bytes(max_bytes). Zero is the default
and disables proactive scans. The kernel configures the store with the same
STORAGE_V2_HOT_READ_MAX_OBJECT_BYTES constant used by HotReadCache (72 KiB),
so eligible newly packed objects get an eager segment proof and larger objects
do not. Dedup/separate-metadata fallback conditions stay unchanged. The policy
is independent of persistent inline/external format; it changes when the
existing device-backed scan runs, not what it validates. No new wire format,
checkpoint protocol or proof trust assumption is introduced.

Fused-append recovery tests explicitly select the 72 KiB policy, covering
objects on either side using the existing mutation-cut sweeps. 243 selected
host tests pass / one ignored. The production three-boot file-tree gate
(including cold/powered-off verification) and Duo compilation pass.

Two 256-operation QEMU runs use the same 64-page block cache, 128 MiB guest,
one-hart TCG and 4/2 MiB/s plus 400/200 read/write IOPS settings as the previous
experiments. Every sample passes. For 4 KiB objects, every sample's full I/O
counter record exactly equals the retained broad-eager experiment in
storage-hot-segment-proof-20260912/run.jsonl: 11,186,176 total read bytes.
For 128 KiB objects, every sample's counters exactly equal the pre-eager
baseline in storage-hot-proof-128k-20260912/before.jsonl: 60,280,832 read bytes.
Thus the small-object benefit is retained and the larger-object proactive
scan is removed. Cumulative times are 15.041471 and 36.068836 seconds,
respectively; these individual runs do not establish further timing gains.

Temporary page-cache reduction is restored; the kernel retains its usual
512-page setting and existing milkv-python 64-page setting. This refinement
supersedes the broad eager-proof policy and the rejected format-inline policy.
It does not claim a physical SD benchmark or bounded GC worst-case latency.
Evidence: `target/storage-hot-proof-policy-20260912/`, with source snapshots,
host/build logs, saved 64-page ELF, exact commands/hashes, JSONL/transcripts,
summary.json and gate/Duo logs. No hardware accessed.

### GC phase attribution after platform-scoped eager proofs (2026-09-12)

Repeat the previous phase I/O diagnostic on the latest retained runtime:
platform-scoped eager packed-segment proofs, 64-page block cache, 128 MiB guest,
one-hart TCG and 4/2 MiB/s plus 400/200 read/write IOPS limits. All 256 held
4 KiB operations pass. Every sample's full counters exactly match
storage-hot-proof-policy-20260912/cached4k.jsonl. Diagnostic prints are excluded
from performance claims, not from measured workload wall time.

| Four collections combined | Read bytes | Read requests |
| --- | ---: | ---: |
| Typed decoding / mark | 0 | 0 |
| Manifest loading / planning | 3,276,800 | 800 |
| Relocation source reads | 442,368 | 108 |
| Staged root readback | 1,732,608 | 139 |
| Manifest / blob readback | 4,038,656 | 986 |
| Publication / reuse barrier | 98,304 | 4 |

GC reads total 9,588,736 bytes versus 24,924,160 before eager proofs.
Manifest loading drops from 18,612,224 to 3,276,800 bytes; every other phase's
I/O is exactly unchanged from storage-gc-phases-20260912. Thus the measured
benefit specifically eliminates first-use descriptor-chain reads in manifest
loading. GC writes remain 2,748,416 bytes across 68 requests and 30 flushes.

The remaining root plus manifest/blob readback is 5,771,264 bytes (60.2% of
GC reads). The next investigation should distinguish fresh relocated metadata
from unchanged retained manifests already authenticated earlier in the same
collection. Any reuse must preserve pointer identity, source/target ownership,
corruption detection and publication failure behavior; this diagnostic does
not prove that removing any existing check is safe. Cache-capacity increases
are not supported as the next action by these data.

This turn adds evidence only. Temporary hooks and cache override were restored
before running the saved instrumented ELF, and source comparisons verify that
restoration. Evidence: `target/storage-gc-phases-hot-20260912/`, with before/trial
sources, build log, instrumented ELF, runner, environment, JSONL, full phase
trace and summary.json. No hardware or new crash-recovery qualification.

### Reuse retained manifest verification within one GC (2026-09-12)

Retain bounded reuse of manifests already authenticated by load_live_manifests
in the same frozen collection. The successor mapping must retain exactly the
original physical pointer; the manifest and every content extent must be
outside the source set and outside the target set. Only then omit the second
read of the unchanged manifest after relocation. Fresh/rewritten manifests,
copied extents and their Merkle contents still receive the existing device
readback checks before publication. No cross-collection manifest byte cache is
introduced, and the staged catalog/root readback remains unchanged.

Strengthen the existing retained-manifest recovery test: before each of two
collections, corrupt the retained manifest payload (including after a prior
collection has memoized its segment chain), require collection failure with
exactly unchanged damaged media, restore the byte, and continue successful GC
and cold recovery. Existing copied-payload/padding corruption and mutation-cut
coverage also pass. This preserves per-collection input authentication and
fresh-write validation while avoiding redundant reads of immutable data that
the transaction does not write.

All 256 held 4 KiB operations pass in 64-page-cache / 128 MiB / one-hart TCG
QEMU with 4/2 MiB/s and 400/200 read/write IOPS limits. Compared with
storage-hot-proof-policy-20260912/cached4k.jsonl:

| Metric | Before | After |
| --- | ---: | ---: |
| Cumulative seconds | 15.041471 | 13.201704 |
| Read bytes | 11,186,176 | 8,097,792 |
| Read requests | 2,319 | 1,565 |
| Write bytes | 53,694,464 | 53,694,464 |
| Write requests | 1,862 | 1,862 |
| Flush requests | 825 | 825 |
| Median operation ms | 37.6295 | 37.5335 |
| Maximum operation ms | 2,934.442 | 1,900.145 |
| Two GC-episode operations, seconds | 5.352097 | 3.450243 |

Reads decrease 27.6%, cumulative time 12.2%, GC-episode time 35.5%. Timing is
a single sequential comparison, not a replicated bound or SD-card result.

Qualification: 243 selected host tests pass / one ignored; captured native
image verification reports status ok; production three-boot file-tree gate
and Duo release compilation pass. The temporary small-cache override is
restored. Evidence: `target/storage-gc-retained-proof-20260912/`, including
before/final source, build and host logs, saved 64-page ELF, runner, JSONL,
serial log, environment, captured disk and native report, comparison.json,
and gate/Duo logs. No hardware accessed.

### Retained-manifest reuse at 128 KiB (2026-09-12)

Compare the current within-collection retained-manifest reuse against the
immediately preceding platform-scoped hot-proof implementation. Both saved
ELFs use 64 block-cache pages, 128 MiB guest, one-hart TCG and 4/2 MiB/s plus
400/200 read/write IOPS. Each independently runs 256 held 128 KiB objects,
seeds 32..287. All 512 operations pass and both runs perform four GC rounds.

| Metric | Before | After |
| --- | ---: | ---: |
| Cumulative seconds | 35.983091 | 35.319078 |
| Read bytes | 60,280,832 | 57,008,128 |
| Read requests | 3,781 | 2,982 |
| Write bytes | 94,195,712 | 94,195,712 |
| Write requests | 2,181 | 2,181 |
| Flush requests | 825 | 825 |
| Median operation ms | 111.642 | 111.638 |
| P95 operation ms | 148.809 | 150.937 |
| Maximum operation ms | 5,045.079 | 4,624.435 |
| Two GC-episode operations, seconds | 9.159215 | 8.237250 |

Only sample indices 206 and 234 have changed I/O counters. Every other sample
is identical. This directly attributes the saved 3,272,704 bytes / 799 read
requests to collection, without moving I/O into ordinary operations. Reads
decrease 5.4%, GC-episode elapsed time 10.1%, cumulative time 1.8%. Timing is
one sequential comparison and P95 is slightly higher; do not claim uniform
latency improvement. Larger-object transfer costs dominate more than in the
4 KiB workload. The measured benefit is consistent with retaining the change.

No runtime edits this turn. Prior corruption, mutation-cut, offline and
three-boot qualification remains in storage-gc-retained-proof-20260912; these
runs extend performance/readback evidence, not power-cut coverage. No hardware
access or SD-card result. Evidence: `target/storage-retained-proof-128k-20260912/`,
including exact commands/ELF hashes, runner, JSONL/transcripts and summary.json.

### File-tree sweep after accumulated storage changes (2026-09-12)

Compare saved 64-page-cache ELFs: the earlier borrowed-file-encoder build
(storage-fs-borrow-cache64-20260912/after.elf) against the latest retained
GC-manifest-reuse build (storage-gc-retained-proof-20260912/candidate.elf).
This evaluates the accumulated changes, not one isolated commit. Each size
uses a fresh independent image, 128 MiB guest, one-hart TCG and one sample;
there is no throughput/IOPS throttle in this sweep. The file-sequential workload
includes SplitMix pattern generation, staging/publication, complete readback
verification and removal. All six records pass.

| Size | Seconds before/after | Read bytes before/after | Flushes before/after |
| --- | ---: | ---: | ---: |
| 16 MiB | 1.531722 / 1.550266 | 17,907,712 / 17,907,712 | 16 / 16 |
| 64 MiB | 6.391966 / 5.854749 | 76,001,280 / 72,392,704 | 35 / 32 |
| 256 MiB | 25.412108 / 23.930725 | 311,455,744 / 296,534,016 | 90 / 84 |

The 16 MiB counters are identical. At 64 MiB, reads save 3,608,576 bytes / 398
requests, writes save 12,288 bytes / three requests, and three flushes disappear.
At 256 MiB, reads save 14,921,728 bytes / 1,576 requests, writes save 24,576
bytes / six requests, and six flushes disappear. These extend the measured
I/O benefit to file-tree workloads beyond small-object benchmarks.

Single-run elapsed changes are +1.2%, -8.4% and -5.8%; do not treat them as
replicated speed bounds. Pattern generation timings also vary despite no
algorithm change in this comparison, and full readback phases take longer in
the new ELF in all three samples. The strongest evidence is reduced physical
I/O at the two larger sizes. This sweep is not directly comparable to the
user's original write-only table or physical SD timings. Large-file readback
CPU/verification work remains a significant separate target.

No runtime edits this turn. The previous correctness qualification still
applies; this is extra complete-content readback/performance evidence, not a
new power-cut test. Evidence: `target/storage-file-current-20260912/`, with
exact commands and ELF hashes, runner, all JSONL/transcripts, and summary.json
including phase ticks. No hardware accessed.

### Reuse the verified file-node read buffer (2026-09-12)

Retain in-place removal of the verified file-data node prefix. Previously,
Vec::split_off allocated a second content-sized buffer while the full encoded
node allocation was still live. Check the suffix length, copy the suffix to
the start of the original Vec, and truncate its length instead. The complete
blob is still verified before any transformation. The returned content bytes
are unchanged; the returned capacity now retains the small prefix allowance.
This removes one full-content temporary allocation per streamed data-node read,
not the byte movement itself. Whole-guest peak RAM was not measured.

243 selected host tests pass / one ignored. An ABBA QEMU sweep runs a complete
256 MiB file generation/write/publication/readback/removal on each independent
image, with 64-page block cache, 128 MiB RAM, one-hart TCG and no storage
throttle. All four runs pass and every I/O counter is identical:
296,534,016 read bytes / 7,603 requests; 284,516,352 write bytes / 3,047 requests;
84 flushes. Runs before/after/after/before take 24.386781 / 23.470111 /
23.233375 / 23.400109 seconds. Means are 23.893445 versus 23.351743 seconds
(-2.3%). Mean full-readback ticks are 98,696,290 versus 97,701,165 (-1.0%).
The end-to-end difference includes unchanged phases and is not wholly
attributable to this small allocation change. The concrete allocation removal
and unchanged I/O/content behavior are stronger evidence than the small timing
difference; no physical SD-card speed claim is made.

Production three-boot file-tree recovery (including powered-off verification)
and Duo file-tree/legacy-shell compilation pass. The temporary cache override
is restored. Evidence: `target/storage-file-read-buffer-20260912/`, with
before/final source, build and host logs, saved candidate ELF, exact commands/
hashes, four JSONL/transcripts, phase summary.json and gate/Duo logs.
No hardware accessed.

### File readback component profile (2026-09-12)

Temporary successful-call timers surround structural metadata reads, whole
content read/verification, and verified-buffer prefix removal. Counters reset
immediately before opening the benchmark file reader and print after its full
read loop. The 256 MiB QEMU file-sequential workload uses 64 page-cache pages,
128 MiB guest, one-hart TCG and no storage throttle. Complete content validation
passes. Every I/O counter exactly matches the uninstrumented retained buffer
reuse candidate in storage-file-read-buffer-20260912/after.jsonl.

| Component | Calls | Elapsed ticks | Fraction of readback phase |
| --- | ---: | ---: | ---: |
| Data-node structural metadata | 259 | 3,202,690 | 3.2% |
| Complete content read/verification | 86 | 49,332,510 | 48.9% |
| Prefix validation/removal | 86 | 548,420 | 0.5% |
| Remaining benchmark/framework work | — | 47,778,580 | 47.4% |

Full readback phase is 100,862,200 ticks. These are elapsed rdtime intervals,
including suspension/scheduling where an operation awaits, not CPU-cycle
measurements. The outer phase also includes diagnostic print overhead and
loop/framework work. In particular, the remaining time includes the benchmark's
SplitMix content-pattern check, which regenerates expected content. It must
not all be attributed to storage, nor all to pattern generation without a
separate timer. Metadata traversal is a small fraction, so adding skip-list
caches is not supported as the primary next optimization. First separate the
benchmark's pattern check from actual reader time; then profile the roughly
half spent in read_verified_blob if needed.

This turn adds measurement evidence only. All three instrumented source files
are restored and checked against saved baselines; the saved ELF and trial
sources define the measurement. No latency comparison or hardware claim.
Evidence: `target/storage-file-read-profile-20260912/`, with before/trial
sources, build/ELF, runner, JSONL, serial profile, environment and summary.json.

### Separate file reader time from benchmark pattern matching (2026-09-12)

Retain optional file-sequential telemetry fields:
file_verify_reader_ticks surrounds awaited reader.read_chunk calls;
file_verify_pattern_ticks surrounds the benchmark's empty/content-pattern
check; file_verify_other_ticks is the remainder of the existing verify phase.
The three must sum exactly to file_verify_elapsed_ticks. Reader time includes
normal filesystem lookup, device waits, content authentication and result
construction; it is not a raw-block or pure CPU metric. The benchmark still
checks every content byte and the total length before reporting success.

The converter accepts old records without this group. If any new field occurs,
all three and the enclosing phase are required, must be nonnegative exact
integers (not bools), and must sum correctly. Selftests cover malformed groups,
negative/bool values, missing phase and inconsistent sums. Selftest and explicit
validation of both old/new records pass; QEMU release build and Duo release
compilation pass.

A 256 MiB full file lifecycle in 64-page-cache / 128 MiB / one-hart TCG QEMU,
without storage throttle, completes content verification. Physical counters
exactly equal storage-file-read-buffer-20260912/after.jsonl. New ticks:

| Component | Ticks | Approximate share |
| --- | ---: | ---: |
| Reader calls | 54,013,840 | 63.0% |
| Benchmark pattern match | 31,676,950 | 37.0% |
| Other | 4,890 | 0.006% |
| Verify phase | 85,695,680 | 100% |

These new fields establish the boundary for future optimization comparisons.
Differences from prior instrumented phase totals are not a speedup claim:
pattern timing has varied across QEMU builds. Four extra timer reads per chunk
add small measurement overhead, included in the enclosing phase. No storage
algorithm change or hardware result is claimed here. Temporary cache override
is restored; the telemetry remains for future QEMU benchmarks.

Evidence: `target/storage-file-verify-timing-20260912/`, with before/final
benchmark sources, selftest/build/Duo logs, saved ELF, runner, JSONL/serial,
environment and summary.json. No new crash-recovery gate is claimed for this
benchmark-only change.

### Rejected direct-output Blob reads (2026-09-12)

Trial: add ManifestRangeReader::read_into and fill the final output Vec's leaf
slice directly in read_and_verify_resolved_blob. The existing Vec-returning
reader becomes a wrapper. This eliminates the per-leaf temporary Vec and
copy into the final output while preserving range/pointer/window checks,
streaming Merkle reconstruction and on-media tree comparisons. The final
output is initialized before filling rather than extended per leaf.
243 selected host tests pass / one ignored.

Four complete 256 MiB file lifecycle runs (before/after/after/before) on
independent 64-page-cache, 128 MiB, one-hart TCG QEMU images all pass. No storage
throttle is used. Every I/O counter is identical: 296,534,016 read bytes /
7,603 requests, 284,516,352 write bytes / 3,047 requests, 84 flushes.

| Mean of two runs | Before | After |
| --- | ---: | ---: |
| Total seconds | 21.647103 | 22.770781 |
| Reader ticks | 52,672,885 | 52,865,690 |
| Pattern-check ticks | 31,449,280 | 43,521,930 |

Reader time does not improve (+0.4%); total time worsens 5.2%, predominantly
alongside a large change in the unchanged benchmark pattern check. Do not
attribute that change to an identified mechanism: code-layout/TCG or other
causes are unproven. Crucially, the new independent reader metric also shows
no benefit. Reject and restore the original reader rather than retaining a
larger refactor on allocation-count intuition alone. Existing file-buffer
reuse and all earlier retained runtime changes remain intact.

Evidence: `target/storage-blob-read-into-20260912/`, with before/trial source,
host/build logs, saved ELF, exact commands/hashes, four JSONL/transcripts and
summary.json. Temporary page-cache override is restored. No hardware or
additional recovery qualification is claimed for this rejected trial.

### Whole-Blob reader component profile (2026-09-12)

A temporary diagnostic build times the full-content leaf loop's range read,
StreamingMerkle::push_chunk, output extension and tree-emission verification.
A separate nested timer measures awaited PageDevice::read_pages calls in
ManifestRangeReader, including its metadata/directed readers. All counters
reset before the file reader opens. No on-media validation is removed.

The 256 MiB file lifecycle passes on a fresh disk, 64-page cache, 128 MiB RAM,
one-hart TCG, without throttling. Reader elapsed is 52,757,190 ticks (10 MHz).

| Component | Elapsed ticks | Calls | Fraction of reader |
| --- | ---: | ---: | ---: |
| Content range reads | 15,442,110 | 65,622 | 29.3% |
| Merkle push (hashing/frontier/emission generation) | 23,195,020 | 65,622 | 44.0% |
| Output extension/copy | 792,370 | 65,622 | 1.5% |
| Tree-emission checks after content leaves | 6,405,410 | 65,622 | 12.1% |
| Nested device reads, overlaps above | 12,652,200 | 4,717 | 24.0% |

The first four components total 45,834,910 ticks. The unassigned reader time
includes metadata traversal, setup, padding/finalization, buffer prefix removal,
loop and instrumentation overhead. Padding tree checks are not in the fourth
row. Device reads overlap the first/fourth rows and also include other
ManifestRangeReader uses; do not add the fifth row to the others or subtract it
from just one component. These are elapsed rdtime intervals, not CPU counters.
The outer reader excludes the benchmark pattern comparison.

All five I/O counters exactly equal the retained baseline: 296,534,016 read
bytes / 7,603 requests, 284,516,352 write bytes / 3,047 requests, 84 flushes.
The run supplies diagnostic evidence, not a speed comparison. It argues against
prioritizing result copies, and supports examining Merkle/hash CPU work next.
This is TCG evidence, not proof of the same balance on a physical SD device.

All temporary cas/shell/cache changes are restored and byte-compared with their
saved baselines. JSONL validation and diff whitespace checks pass. Source
snapshots, build log, ELF/hash, exact runner command, serial/JSONL and computed
summary are in `target/storage-blob-reader-profile-20260912/`. No new storage
algorithm, recovery qualification or hardware run is claimed this turn.

### Batched Merkle hash inputs rejected (2026-09-12)

Following the reader component profile, a trial consolidates the leaf's domain,
kind, index and length into one stack prefix passed to Sha256::update, followed
by content. Internal nodes concatenate domain, level and both hashes into one
stack input to Sha256::digest. Input bytes, hash algorithm, object format and
all storage verification remain identical; no hardware extensions are required.
All 17 blob-format tests pass, including fixed format vectors, checked-in disk
fixtures and streaming/canonical comparisons. The QEMU release build succeeds.

Four independent 256 MiB file lifecycles in before/after/after/before order all
pass on 64-page-cache, 128 MiB, one-hart TCG QEMU without storage throttling.
All I/O counters are identical: reads 296,534,016 bytes / 7,603 requests,
writes 284,516,352 bytes / 3,047 requests and 84 flushes.

| Mean of two runs | Before | Trial | Change |
| --- | ---: | ---: | ---: |
| Total seconds | 21.2717095 | 22.7363830 | +6.89% |
| File stage push ticks | 81,506,435 | 80,713,035 | -0.97% |
| Reader ticks | 52,103,515 | 52,760,160 | +1.26% |
| Pattern comparison ticks | 30,675,735 | 44,034,775 | +43.55% |

The targeted reader does not improve. The small write-stage difference does
not justify retaining this change; reject it. The unchanged benchmark pattern
again varies substantially across ELFs, so do not attribute the whole-workload
regression to hashing or claim a diagnosed code-layout mechanism. The separate
reader metric makes rejection independent of that unexplained pattern effect.
This rules out this short-update consolidation as a demonstrated optimization;
it does not rule out other SHA or Merkle optimizations.

Original blob source and page-cache configuration are restored and byte-checked.
All four JSONL validations and diff whitespace checks pass. No new algorithm
is retained; no storage recovery gate or physical SD validation is claimed.
Evidence in `target/storage-hash-input-batch-20260912/` contains before/trial
source, build/test logs, saved ELF and hashes, exact ABBA commands, transcripts,
JSONL and summary. Runtime Git metadata sees restored source; saved trial source
and ELF identify the experiment.

### Large-file SD-style throttled qualification (2026-09-12)

A fresh-disk pair compares the saved borrowed-encoder 64-page-cache baseline
(storage-fs-borrow-cache64-20260912/after.elf) with the retained current runtime
and independent verification timers (storage-file-verify-timing-20260912/
candidate.elf). This is a cumulative comparison, not an isolated new change.
Both 64 MiB file lifecycles pass complete pattern verification and removal.
QEMU uses one TCG hart, 128 MiB RAM, a 64-page cache, read/write bandwidth
limits of 4/2 MiB/s and read/write IOPS limits of 400/200. No physical SD card
is used; these limits do not simulate an SD controller or its latency tails.

| Measurement | Earlier baseline | Current |
| --- | ---: | ---: |
| Total seconds | 53.001419 | 51.476392 |
| Device read bytes | 76,001,280 | 72,392,704 |
| Device read requests | 1,855 | 1,457 |
| Device write bytes | 71,442,432 | 71,430,144 |
| Device write requests | 786 | 783 |
| Flushes | 35 | 32 |
| Staging seconds | 36.305246 | 34.785175 |
| Staging push seconds | 32.438027 | 31.428824 |
| Full verification seconds | 16.609208 | 16.604934 |

Total improves 2.88% in this one pair. All I/O savings occur in staging:
3,608,576 fewer read bytes / 398 requests, 12,288 fewer write bytes / three
requests and three fewer flushes. Publication, verification and removal I/O
remain identical. Pattern generation also drops from 1.773229 to 1.263299
seconds, so do not attribute the entire elapsed gain to storage changes.
The deterministic I/O difference is stronger evidence than this single timing
pair and reproduces the prior unthrottled comparison's saved reads/requests.

Current total write amplification is 1.0644 relative to the logical 64 MiB;
full verification read amplification is 1.04175. Verification reads 69,910,528
bytes in 1,078 requests, with 15.377464 seconds inside the reader and 1.226703
seconds in the pattern check. QEMU's throttled workload timing includes its
burst/scheduling semantics; do not infer an exact bandwidth lower bound.
The sequential payload path is already close to one write and one verification
read per logical byte. Subsequent SD-oriented work should prioritize small
object metadata and publication/GC I/O, where prior measurements show much
higher amplification, rather than assume a similar large-file opportunity.

No runtime source changes this turn. Both JSONL validations pass. Saved exact
commands/ELF hashes, runner logs, serial/JSONL, raw extracted samples and summary
are in `target/storage-file-sd-profile-20260912/`. No new power-cut or physical
hardware qualification is claimed.

### Current retained-small-object authority attribution (2026-09-12)

Reinspect the captured 256-held-object image from
storage-gc-retained-proof-20260912/final.raw using the independent framing
parser, and re-run the complete native migration verifier. Native status is
ok. This is read-only analysis of existing QEMU evidence, not a fresh latency
measurement. Subsequent retained file-buffer/timing changes do not affect this
object workload, but the named saved image is the exact evidence source.

The latest checkpoint is generation 273. Every current-generation descriptor
pair is sealed and every extent payload matches its SHA-256. The final 4 KiB
put/get sample passes, takes 72.272 ms under the saved throttle profile, and
writes 270,336 bytes in seven requests plus three flushes.

| Latest-generation extent | Payload bytes | Framed bytes |
| --- | ---: | ---: |
| Blob | 4,480 | 16,384 |
| Manifest | 256 | 12,288 |
| Catalog delta | 416 | 12,288 |
| Authority | 165,568 | 176,128 |
| Allocation | 184 | 12,288 |

Authority is 65.15% of the measured device write bytes. It contains 323 records
of 512 bytes, one principal, no explicit object bindings or external roots;
the sample's 321-record field is its pre-append observation. Existing safe
history compaction reduced history relative to the earlier 513-record image,
but full snapshot rewriting still dominates this later ordinary put.

Extents total 229,376 bytes. One segment header/summary/seal set adds 24,576
bytes; the existing checkpoint protocol writes 12,288 bytes, leaving 4,096
bytes not attributed by static final-state inspection. Do not assert an exact
transient-write cause without a write trace. Catalog is already a three-page
delta, so another catalog threshold change cannot address the dominant cost.

Next implementation target: a bounded authority append representation that
reuses an authenticated predecessor snapshot when its record stream is an exact
prefix and all non-stream state is represented without loss. It must bind the
predecessor identity and resulting canonical snapshot, validate record sequence
and CRC/hash chains, and fall back to a full snapshot on incompatible state or
replay limits. Recovery and the independent image verifier must reconstruct the
same complete authority before capability admission; GC must retain all chain
ancestors or materialize a full snapshot before reclaiming them. Growth, cold
mount, quiescent compaction, policy/principal updates and damaged/missing chain
links need qualification, alongside torn publication fault cuts. Existing
checkpoint barriers remain unchanged. This is an implementation direction,
not an implemented format or a measured future speedup.

Evidence: attribution script/decoded summary, final sample, and refreshed native
verification in `target/storage-current-authority-attribution-20260912/`.
No runtime changes, no hardware access, and no new benchmark result this turn.

### Authority append codec foundation (2026-09-12)

Add the experimental internal `authority_delta` module, compiled only under
cfg(test). No production publisher or reader admits its bytes yet. This is the
first implementation component for reducing full authority history rewrites;
it is not a shipped on-media format or a completed storage optimization.

The codec retains the entire successor snapshot prefix (header, object bindings,
principal/quota/policy state and external roots), followed by newly appended
records. It omits only a byte-identical complete predecessor record stream.
The 128-byte experimental header binds canonical predecessor/result SHA-256,
lengths and stream offsets. Reconstruction bounds lengths before output
reservation, requires a canonical fully decoded predecessor, checks the result
hash, decodes the complete result with existing record-chain validation and
requires increasing checkpoint generation. The caller must still validate
external authority policy. Non-appending/rewritten histories return full-snapshot
fallback, and an encoding with no byte saving is not selected.

Four new tests cover exact roundtrip with changed policy/principal/quota/object
bindings/external roots; non-appending/rewritten history fallback and wrong
predecessor; every strict byte prefix, every single-byte corruption of delta
and predecessor, and trailing garbage; integer bounds and a damaged record
whose result digest was recomputed. Existing selected store, fused append,
GC recovery and steady-state tests also pass (see host.log).

This prototype deliberately does not yet carry a physical predecessor pointer,
replay depth/budget, GC liveness or final disk-format admission. Those must be
implemented together with the production publisher, mount reconstruction and
independent Python verifier before enabling it. Publication fault cuts, cold
recovery, growth and compaction interaction still need qualification. Current
encode/reconstruct also materialize complete snapshots; recovery memory peak
must be accounted before integration. No QEMU speedup, physical SD result or
new production recovery coverage is claimed from these codec tests.

Source: `segment-store/src/authority_delta.rs`, registered as test-only in
`segment-store/src/lib.rs`. Evidence and test log:
`target/storage-authority-delta-codec-20260912/`.

### Authority delta predecessor envelope and depth checks (2026-09-12)

Extend the test-only authority_delta prototype with a 128-byte physical-link
envelope around the append payload. It contains a canonical 96-byte Authority
pointer, predecessor/result checkpoint generations and replay depth. Decode
requires a non-null pointer, matching store UUID, admitted segment, valid
pointer shape/kind, segment generation below the horizon, increasing nonzero
checkpoint generations and a result within the selected checkpoint horizon.
Reserved fields are checked. Experimental replay depth is limited to 32;
encoding the next increment at the limit falls back to a full snapshot.

apply_link requires the exact resolved pointer, the reconstructed predecessor
and its observed depth, then checks depth+1 and both checkpoint identities.
It retains the existing predecessor/result canonical hash and record-chain
checks. The caller must authenticate the actual on-media pointer payload and
segment before invoking it; matching input arguments alone are not device
proof. These bytes remain experimental and are not yet a frozen disk ABI.

Six codec tests pass. New coverage checks cross-store pointers, null/wrong-kind
references, segment admission and generation horizon, future checkpoints,
wrong predecessor identity, forged depths, and overflow. A generated chain
reconstructs all 32 increments exactly equal to independently encoded complete
snapshots, then requires full-snapshot fallback at increment 33. Existing
roundtrip, metadata preservation, corruption/truncation and record-chain tests
remain green. See tests.log. This is CPU-only codec testing, not a cold-mount
or crash-recovery claim.

Still required before production admission: a device-backed bounded chain
walker with cumulative byte/heap accounting and physical validation; mount and
checkpoint successor integration; append publication selection; GC retention
or materialization of all ancestors; Python offline verification; and cut-point,
growth/compaction, QEMU performance and recovery qualification. The depth cap
alone is not a sufficient memory or I/O bound. Production storage behavior is
unchanged because the module remains cfg(test).

### Authority delta bounded replay and device adapter (2026-09-12)

Extend the test-only prototype with an asynchronous AuthoritySource and replay
walker. Before each read it validates non-null Authority pointer shape, store,
admission and generation horizon, rejects repeated pointers, and supplies the
remaining cumulative payload-byte allowance. Returned payload length is checked
again. Each loaded extent target generation must match the envelope/snapshot;
child and observed predecessor depths/generations must agree. Replayed snapshots
are bounded separately from cumulative fetched payload bytes. A maximum of 32
links plus the full base is retained, then applied in reverse order. The result
includes depth, ancestor roots and payload byte count for subsequent integration.

DeviceAuthoritySource calls the existing read_pointer_authority_payload, including
segment/descriptor checks, extent chain validation and payload/Merkle hashes.
It rejects a root segment absent from the supplied allocated set. This preserves
multi-extent full-snapshot reading through the existing resolver, but does not
yet integrate the new chain with mount or publication.

Six codec/replay tests pass. The 32-link fixture now exercises actual asynchronous
chain walking through an authenticated in-memory source, all 33 roots, exact
cumulative byte accounting, one-byte-insufficient cumulative/result budgets,
damaged/missing ancestors and wrong target generations. A separate seventh test
formats a real store on the test PageDevice and imports authority through the
existing production writer, then reads that full snapshot through the new device
adapter. Exact-budget reading matches its canonical bytes; smaller budget and
physical payload corruption reject. Read attempts leave the test media unchanged.
This adapter test covers a full-snapshot base, not on-device delta chains.

The module remains cfg(test). No new bytes are published in production. The
payload budget is not a complete heap bound: snapshot decoder/preflight temporary
allocations and loader segment scans require separate accounting before enabling
mount. It also is not a complete physical-I/O budget, since segment scans add
reads. Next: account reconstruction memory, build on-device delta-chain fixtures,
then integrate mount/publisher, GC ancestor liveness/materialization and independent
verification before QEMU fault/performance qualification. No new speedup or
physical SD evidence is claimed.

Evidence: tests.log (six tests), device-tests.log (one test), and this note in
`target/storage-authority-delta-replay-20260912/`. Whitespace diff check passes.

### Authority replay duplicate decode removal (2026-09-12)

The experimental link application decoded predecessor and successor to check
their generations, while its reconstruction helper independently decoded both
again. Consolidate those checks: reconstruct_checked returns generations from
the same fully validated snapshots used to reconstruct the bytes. Each link
now performs two complete snapshot decodes rather than four; neither snapshot's
record-chain preflight, canonical encoding comparison nor digest validation is
removed. The raw byte helper remains a wrapper for codec tests.

After canonical predecessor validation, capture its generation and drop its
decoded tables/record stream before allocating the successor. The prefix check
uses the already-validated predecessor byte range, so it does not require the
owned decoded predecessor to remain live. This removes avoidable overlapping
snapshot storage and repeated preflight work. It is a source-level allocation/
call-lifetime improvement, not a measured heap peak or latency claim.

The authority-filtered host suite passes 37 tests, one ignored, including the
experimental codec/32-link replay/device-adapter tests and existing authority
fault/compaction coverage. Existing production tests still exercise the original
snapshot publisher, because the prototype remains cfg(test). Whitespace check
passes. Exact before source and tests.log are saved here.

Still pending: complete decoder/preflight/segment-scan heap accounting, on-device
delta-chain fixtures, production mount/publication and GC integration, independent
verifier support and QEMU performance/crash qualification. This change improves
the implementation being prepared; it does not yet reduce production SD writes.

### Sealed-media authority delta chain fixture (2026-09-12)

Add a host PageDevice fixture that writes a full authority snapshot and two
incremental successors into separate segments using production build_record,
write_payload_records_with_header and finalize_segment helpers. Every payload
has real descriptor pairs, payload hashes, segment header/summary/final seals.
The test supplies an explicit allocated set and generation context to the
existing device-backed authority resolver; no checkpoint publisher is changed.

The new replay walker follows tip -> middle -> full base through actual page
reads and reconstructs the exact independently encoded final snapshot, reporting
depth two, all three ancestor roots and exact cumulative payload bytes. It
rejects corruption in the base descriptor body/seal, payload, summary seal and
final segment seal. Removing the intermediate payload page also rejects, as
does excluding the base from the allocated set. Replay does not perform device
writes in successful or failing cases.

The authority-filtered host suite passes 38 tests, one ignored; the new case is
sealed_device_delta_replays_and_rejects_damaged_ancestor_frames. This extends
codec-only chain coverage to framed test media. It is not a selected-checkpoint
cold mount, real hardware, torn-publication test or QEMU latency measurement.
The helper-generated segments are fixtures, not an enabled production format.

Still pending before runtime enablement: complete reconstruction/preflight heap
accounting; mount and publisher integration; GC ancestor liveness or snapshot
materialization; independent Python verification; and checkpoint fault/growth/
compaction/QEMU qualification. The experimental module remains cfg(test).
Evidence: tests.log in `target/storage-authority-delta-media-20260912/`.

### Bounded authority record preflight retained (2026-09-12)

Production authority snapshot validation previously copied its entire logical
record stream into a sector Vec and submitted all sectors to preflight_recovery,
which allocated an equally long probe array. Retain a bounded batch path using
the existing PreflightReplay API. A strict sealed-record pass still precedes
semantic replay; empty/torn records are rejected as before. The subsequent pass
feeds at most 32 records per append, preserving transaction/graph state across
batches, then runs the same finish and exact sequence-count validation.

The copied-sector buffer requests at most 16 KiB instead of a full stream, and
per-append probes cover at most 32 records. For the previously observed
323-record snapshot, the sector buffer's requested storage falls from 165,376
to 16,384 bytes. This is not an overall heap-peak measurement: transaction,
object and grant graph memory still scales with the stream. The change also
supports the experimental delta reader but does not enable its disk format.

A new regression compares every complete-record prefix of a 32 KiB object
transaction with whole-stream preflight, covering transactions across multiple
32-record boundaries. Reordered and damaged records around boundaries 32/64
reject. The selected host suite passes 251 tests / one ignored, and the added
boundary test passes separately (252 distinct passing tests). The production
three-boot file-tree gate passes including cold recovery, GC pressure and offline
verification. Duo file-tree/legacy-shell release compilation passes.

Four independent fresh-disk QEMU runs (before/after/after/before) each complete
256 retained 4 KiB put/get operations. 64-page cache, 128 MiB, one TCG hart,
4/2 MiB/s read/write limits and 400/200 IOPS; no builds run alongside timings.
Total seconds: 13.121577 / 12.871951 / 12.938500 / 12.997146. Means are
13.0593615 -> 12.9052255 (-1.18%); this small sample establishes no universal
speedup. Every per-sample I/O counter is identical. Each run reads 8,097,792
bytes / 1,565 requests, writes 53,694,464 bytes / 1,862 requests, and flushes
825 times. Retain for bounded temporary allocation with no observed regression.

Evidence in `target/storage-authority-preflight-batch-20260912/`: before/final
source, host/boundary/build/Duo/gate logs and retained boot artifacts, saved
64-page ELF, exact ABBA commands/hashes, four validated JSONL/transcripts and
summary. Normal page-cache configuration is restored. No physical SD access.

### Independent Python authority delta byte oracle (2026-09-12)

Add scripts/authority-delta-codec.py as an experimental, independent byte-level
oracle. It imports no Rust format constants or decoder. It checks envelope
size/magic/reserved fields, expected physical predecessor, pointer geometry and
store/generation context, observed depth, canonical snapshot table offsets,
record counts, predecessor/result lengths and SHA-256. Logical records are
validated through the independent strict CSpace record/CRC/sequence/semantic
parser. External policy and complete snapshot table/graph admission remain the
production snapshot verifier's responsibility; this tool is not disk admission.

The Rust sealed-device fixture optionally exports base, first delta, intermediate
snapshot, second delta and result when VIBE_AUTHORITY_DELTA_FIXTURES is set.
Python independently reconstructs both links exactly equal to the Rust canonical
snapshots and rejects 1,923 cases: every strict first-link byte prefix, each
single-byte corruption, trailing garbage, a damaged record with recomputed
result SHA, and an incorrect expected logical StoreId. Fixture generation's
Rust test passes. Optional fixture export is absent from production builds.

The existing logical-stream parser previously fixed StoreId to the platform
constant. Add an explicit expected_store_id keyword to decode_sector and
recover_record_stream while keeping the platform value as default. The oracle
passes the test StoreId explicitly; it does not infer trusted identity from
untrusted input or disable that check. Existing strict-prefix selftests pass
(19 records x 512 cuts). The default production verifier behavior is unchanged.

Evidence: rust.log, five binary fixtures, python.json and legacy.log in
`target/storage-authority-delta-python-20260912/`. Whitespace check passes.
Still needed: full snapshot policy validation and physical chain integration in
the migration verifier, production mount/publisher and GC support, recovery heap
accounting, and QEMU checkpoint/fault/performance qualification. No production
authority deltas are published and no new speedup is claimed.

### Independent delta metadata validation (2026-09-12)

Extend the Python experimental byte oracle from table-layout checks to canonical
table-entry checks. Object bindings require nonzero and strictly ordered stable
IDs, unique nonzero backend IDs, valid commit generations/kinds and zero reserved
bytes. Principal entries require ordered nonzero IDs, positive limits, usage
within limits, canonical boolean flags and zero padding. External roots require
ordered nonzero IDs, valid generations/kinds and zero reserved bytes. These are
structural snapshot constraints, not admission against an external root policy.

The Rust codec test optionally exports an additional linked snapshot containing
object bindings, a principal and an external root. Seven Rust prototype tests
pass. Python reconstructs all three exported links exactly and rejects 1,940
cases. New cases modify principal/policy/binding/root metadata and recompute the
result SHA-256, proving that these failures are caught beyond digest mismatch.
The fixtures include zero IDs/limits, over-limit usage, future/zero generations,
zero kinds, invalid boolean flags and nonzero reserved bytes.

Evidence in `target/storage-authority-delta-metadata-20260912/`: Rust log, eight
binary fixtures and Python result JSON. Run:
`python3 scripts/authority-delta-codec.py target/storage-authority-delta-metadata-20260912/fixtures`.
The expanded selftest now expects the rich fixtures as well as the two-link
chain fixtures. Whitespace check passes. Production snapshot publishing/mount
remains unchanged; the incremental format is still test-only. External policy,
physical full-image/GC integration and performance qualification remain pending.

### Authority chain materialization and resumed append fixture (2026-09-12)

Inspection confirms production GC relocation already calls authority.relocated()
and encode_persistent_authority_snapshot, emitting a complete authority root.
This supports truncating an admitted delta chain at GC rather than copying its
links indefinitely. Existing checkpoint retirement/reuse ordering must remain
unchanged; this observation does not alone qualify the integration.

Extend the sealed-media fixture after its two-link chain: relocate its final
snapshot to generation six using the same relocated() method and write a full
sealed authority extent in a new segment. The old tip still reconstructs while
all old segments are present. The new full root reconstructs with only its own
segment in the supplied allocated set, reports depth zero and one ancestor.
After physically removing the three old segments from fixture media, the old
tip rejects while the full root remains readable. A further append at generation
seven uses the materialized full root at depth zero; replay succeeds at depth
one with only the two new segments and matches a complete canonical snapshot.

All seven prototype tests pass. This is a framed PageDevice fixture, not an
actual GC checkpoint switch or power-cut proof. It establishes byte/pointer
independence after materialization and the resumed depth rule. Production GC,
mount and publication are unchanged, and the format remains test-only.

Integration direction: preserve GC's full-snapshot output; ensure chain recovery
runs before obtaining the authoritative in-memory snapshot; protect the old
checkpoint's referenced media until the existing retirement/reuse barrier.
Still required: production selection/mount, complete memory accounting, full
independent image verification, real GC/fault/growth/compaction tests and QEMU
performance qualification. No new performance claim.
Evidence: `target/storage-authority-delta-materialize-20260912/tests.log`.

### Reuse validated authority stream during relocation (2026-09-12)

Retain a production reduction in redundant semantic replay. Snapshot relocated()
previously called new(), which replayed its record chain, then with_external_roots(),
which replayed the same unchanged chain again. It now uses the existing trusted
parts constructor with the full cloned tables and stream, performing structural
validation once against the requested generation. The private record stream has
no mutable public/crate accessor; it was validated by snapshot construction or
validated import. Object bindings are crate-visible and still structurally checked.
No decoder of newly read media skips record validation as a result of this change.

A regression confirms that relocation preserves all encoded bytes except the
checkpoint generation, roundtrips through the full decoder, and rejects zero or
too-early generations and an invalid object binding. External roots, principals,
quota fields and policy commitment are preserved. This removes two complete
preflight walks and their temporary allocations per relocated() call; it does
not eliminate snapshot cloning or change encoded media bytes/publication ordering.

253 selected host tests pass / one ignored (217 library, six fused recovery,
24 GC recovery, six steady-state). The three-boot production file-tree gate
passes cold recovery, GC pressure and offline verification. Duo file-tree/
legacy-shell release check passes. No new timed benchmark was run, so no elapsed
speedup or heap-peak percentage is claimed. This is a verified removal of
redundant work in the existing runtime, separate from the test-only delta format.

Evidence: `target/storage-authority-relocate-validation-20260912/` contains
before/final source, host/gate/Duo logs and boot verification artifacts.
Whitespace check passes. Production authority deltas still require mount/
publisher/GC qualification and complete recovery memory accounting before enabling.

### Account for decoded authority external roots (2026-09-12)

During delta mount integration review, the existing production snapshot decode
capacity estimate was found to include object bindings, principal policies and
record bytes, but omit the decoded external-root table. Add checked root-count
multiplication by size_of::<PersistentRootEntry>() to that estimate. The V1 field
is canonically zero; V2 carries the root count. Version and reserved-field
validation remain in the complete decoder.

A regression builds a valid two-root authority snapshot, compares the additional
estimate with its decoded root storage, and demonstrates that a budget one byte
short was accepted with the old estimate but now rejects before decode allocation.
The exact estimated budget passes. This fixes one component of recovery budget
admission; it is not a complete preflight graph/temporary heap bound, and does
not establish the full budget safety of the experimental delta reader.

254 selected host tests pass / one ignored (218 library plus 36 integrations).
The production three-boot file-tree gate passes cold recovery, GC pressure and
offline verification. Duo release file-tree/legacy-shell check passes. No limits
are raised and no on-media format changes. Near-limit images may now correctly
report MemoryLimit where the incomplete estimate previously allowed allocation.
No throughput or latency improvement is claimed; this supports bounded recovery
on small-memory devices and subsequent incremental-authority integration.

Evidence in `target/storage-authority-root-budget-20260912/`: before/final store
source, host/gate/Duo logs and retained boot verification files. Whitespace check
passes. Incremental authority publishing/mount remains disabled pending complete
memory, GC, verifier and fault/performance qualification.

### Preallocate and budget recovered authority roots (2026-09-12)

Retain an exact-sized root construction path during production authority mount.
Previously objects were collected into a Vec, then external roots appended,
which could grow the vector. The new helper checked-adds both counts, reserves
once, appends both sets, sorts and applies the same PersistentRootSet validation.
The pre-decode budget now includes this root array, which remains live alongside
the decoded authority snapshot. Snapshot table/record storage and the separate
root array are both counted; this still does not account every semantic preflight
or segment-scan temporary allocation.

Regression coverage constructs a mixed object/external-root snapshot, checks
ordering and exact requested root capacity, demonstrates the formerly admitted
one-byte-short combined budget now rejects, and checks exact-budget acceptance.
An initial test incorrectly expected the snapshot constructor to permit a root
collision; its existing validator already rejects it. Correct the fixture and
also test the root helper defensively with a crate-mutated conflicting binding.
This inspection exposed the same missing cross-table collision check in the
experimental Python oracle; add it and a rehashed-invalid-root case.

Final selected host suite passes 255 tests / one ignored (219 library and 36
integrations). The earlier failed test log is retained alongside host-final.log.
Production three-boot file-tree gate and Duo release check pass; subsequent
changes were test correction and Python-only validation, not runtime changes.
Python independently reconstructs three links and rejects 1,941 malformed cases.
No timed performance claim is made. The improvement is predictable root allocation
and earlier accurate budget admission for that storage. No disk format changes.

Evidence: `target/storage-authority-recovery-roots-20260912/` with before/final
source, both host logs, gate/Duo/boot reports and Python result. Whitespace check
passes. Incremental authority remains test-only; complete recovery memory and
production checkpoint/GC/verifier qualification remain pending.

### Current authority runtime QEMU qualification (2026-09-12)

Compare the saved bounded-preflight baseline ELF with the current runtime after
relocation validation reuse and recovery root-budget/preallocation changes.
The experimental authority-delta module remains cfg(test) and is absent from
both firmware builds. This is a cumulative comparison; it cannot identify which
individual change or layout effect causes a latency difference.

Four fresh-disk runs in before/after/after/before order each pass 256 retained
4 KiB put/get operations. Same 64-page cache, 128 MiB, one-hart TCG, 4/2 MiB/s
read/write limits and 400/200 IOPS. No builds run during timed measurements.

| Metric | Baseline mean | Current mean | Change |
| --- | ---: | ---: | ---: |
| Total seconds | 11.3541415 | 11.5483665 | +1.71% |
| Per-run median ms | 28.49575 | 28.96575 | +1.65% |
| Per-run maximum seconds | 1.8935665 | 1.9026735 | +0.48% |
| Operations at indices 206/234, seconds | 3.419845 | 3.438946 | +0.56% |

Totals in run order are 11.340800 / 11.649559 / 11.447174 / 11.367483 seconds.
The two indexed operations contain the GC episodes in this workload. Every
per-sample I/O counter is identical: 8,097,792 bytes / 1,565 read requests,
53,694,464 bytes / 1,862 write requests and 825 flushes per run. Current changes
do not establish an end-to-end speedup and show a small slowdown in this sample.
Do not compare the absolute times directly with older sessions, whose identical
baseline ELF ran more slowly. Use this within-session ABBA comparison.

The root-budget fixes have independent correctness justification and remain.
Relocation validation reuse removes redundant replay, but has no demonstrated
latency benefit here; isolate it from budget/preallocation changes before making
an attribution or further performance decision. No runtime changes are made in
this qualification turn. Normal page-cache configuration is restored and checked.
The major write amplification from full authority snapshots remains unresolved.

Evidence: exact commands/ELF hashes, saved current ELF, source snapshots/hashes,
build log, four validated JSONL/transcripts and summary.json under
`target/storage-authority-current-qemu-20260912/`. All 1,024 operations pass.
No new physical SD measurement or power-cut qualification is claimed.

### Isolated authority relocation validation comparison (2026-09-12)

Build an old-checks variant by restoring only relocated()'s former new()+
with_external_roots() implementation. It retains all current recovery root
budget/preallocation fixes and bounded preflight. Compare it with the saved
current 64-page ELF; source hashes confirm the restored current sources match
that ELF's saved source snapshot. Normal cache/source are restored before runs.

Four independent fresh-disk QEMU runs each pass 256 retained 4 KiB put/get
operations, in old/current/current/old order. Same 128 MiB, one-hart TCG,
64-page cache, 4/2 MiB/s read/write and 400/200 IOPS limits. No builds overlap.
Seconds: 11.865101 / 11.506376 / 11.581362 / 11.523970.

| Metric | Old checks mean | Current mean | Change |
| --- | ---: | ---: | ---: |
| Total seconds | 11.6945355 | 11.5438690 | -1.29% |
| Per-run median ms | 29.2490 | 29.0255 | -0.76% |
| Per-run maximum seconds | 1.9096600 | 1.9002885 | -0.49% |
| GC-episode operations 206/234, seconds | 3.437789 | 3.432738 | -0.15% |

Every per-sample I/O counter matches: per run reads 8,097,792 bytes / 1,565
requests, writes 53,694,464 bytes / 1,862 requests and flushes 825 times.
The small mean improvement and near-identical GC episodes do not prove a stable
speedup; baseline repetitions themselves vary. They also do not support blaming
relocation validation reuse for the earlier cumulative +1.71% result. Retain its
verified removal of redundant replay, without a universal latency claim. Root
budget correctness fixes remain. The dominant full-authority write amplification
is unchanged and incremental publication remains unfinished.

All 1,024 operations pass and all four JSONL validations pass. Source and cache
restoration are byte-checked; no runtime changes this turn. Evidence includes
current/old-checks source snapshots, build/variant ELF, exact commands/hashes,
serial/JSONL and summary under `target/storage-relocate-isolated-20260912/`.
Existing recovery qualification still applies; no new crash or hardware claim.


### Experimental authority delta streaming digest (2026-09-12)

The test-only delta encoder now encodes canonical metadata prefixes and hashes
metadata plus borrowed record streams incrementally. It no longer serializes
both full snapshots merely to obtain digests and payload slices. Physical-link
size selection uses the allocation-free encoded-length helper instead of a
third full snapshot encoding. Hashing still processes the complete histories;
this removes temporary history copies, not the linear hashing work.

The production full-snapshot encoder shares the same metadata implementation
and continues to emit the complete frozen-format bytes. Metadata-only output
retains full snapshot lengths in its header and is not independently decodable.
The metadata-only entry point and delta codec remain test-only. Publication,
mount admission, complete recovery memory accounting and delta GC qualification
remain unfinished; no production I/O reduction or latency improvement is claimed.

All eight exported fixtures are byte-identical to the prior encoder, including
changed principal, policy, binding and external-root tables. Seven delta tests
pass; the independent Python oracle reconstructs three links and rejects 1,941
invalid cases. The selected host suite passes 255 tests with one ignored. QEMU
file-tree three-boot recovery/GC/offline verification passes; Duo release check
passes without hardware execution. Evidence is retained under
`target/storage-authority-delta-stream-20260912/`, including fixture hashes,
Python results and build/test logs.


### Bound retained authority scan history (2026-09-12)

Production multi-extent authority recovery previously appended every authority
record from scanned allocated segments and filtered old checkpoint generations
only after all scans. Filter each scanned batch before retaining it instead,
using the once-reserved declared chain count. Reject excess same-generation
records before pushing, and release the first scan result before scanning other
segments. The accumulated descriptor vector no longer grows with unrelated
historical authority generations. Per-segment scan buffers and the allocated
segment list remain separate costs; this is not a complete recovery heap bound.

The scan still visits subsequent allocated segments after finding the expected
count, preserving rejection of extra same-generation records; final chain and
payload authentication remain unchanged. No media-format, publication, read-I/O
or latency improvement is claimed. The experimental delta codec remains outside
production admission.

A regression supplies 10,000 historical descriptors, verifies constant retained
capacity and correct selection, and rejects an extra matching sibling without
buffer growth. The final selected suite passes 256 tests with one ignored,
including multi-extent cold recovery and 1 MiB append cut-boundary recovery.
QEMU's three-boot file-tree/GC/cold-recovery/offline gate and Duo release check
pass. Earlier new-fixture construction failures were fixed (valid StoreUuid,
nonzero ordinal/object kind); authoritative results are host-pass.log and
collection.log. Evidence: `target/storage-authority-scan-retention-20260912/`.


### Lazy allocation enumeration during authority recovery (2026-09-12)

Production recovery now passes a borrowed allocation-bitmap iterator into the
multi-extent authority reader. Previously it counted all allocated segments,
reserved a u64 vector, enumerated the bitmap again, and kept that vector alive
alongside payload/decode buffers. The reader only needs other segment numbers
when the root segment does not contain the complete chain. Lazy enumeration
removes the temporary N * size_of::<u64>() requested allocation and the eager
count/enumeration passes; single-segment authority recovery never advances the
iterator. Cross-segment reads enumerate the same allocated segments in the same
order and retain full segment/chain authentication. This closes the unaccounted
segment-list residency by eliminating it, rather than increasing the budget.
Other decoder/preflight/scan allocations still require independent accounting.

The sealed-device recovery test passes a panic-on-next iterator to a complete
root-segment payload and verifies exact recovered bytes, proving no eager walk.
The selected host suite passes 256 tests with one ignored, including multi-extent
cold recovery and append cut boundaries; the strengthened sealed-device test
also passes separately. QEMU three-boot file-tree, GC pressure, cold recovery and
powered-off verification pass; Duo release check passes without device execution.
No end-to-end timing or SD I/O reduction is claimed. Incremental authority
publication remains unfinished. Evidence: `target/storage-authority-lazy-segments-20260912/`.


### Borrow authority preflight record batches (2026-09-12)

The production authority record-chain validator now uses slice::as_chunks to
borrow fixed-size sectors from its existing contiguous stream, then passes
borrowed batches of at most 32 records to PreflightReplay. This removes the
previous min(record_count, 32) * 512-byte temporary sector allocation (up to
16 KiB) and the per-record copy. The strict sealed-record pass, bounded replay
probe batches, semantic graph state across boundaries and final sequence check
remain. No unsafe conversion or on-media change is introduced. The eliminated
buffer is one component of peak memory, not a measurement of total guest heap;
semantic replay state remains a separate accounting problem.

The strengthened boundary test compares every complete-record prefix against
whole-stream preflight, rejects swaps/corruption at boundaries 32 and 64,
accepts a borrowed stream starting at byte offset one, and rejects each partial
final-record truncation of 1 through 511 bytes. The selected host suite passes
256 tests with one ignored; the strengthened boundary test passes separately.
QEMU three-boot file-tree/GC/cold-recovery/powered-off verification and Duo
release check pass. No timed benchmark or SD I/O improvement is claimed.
Incremental authority publication and complete replay heap accounting remain
unfinished. Evidence: `target/storage-authority-borrowed-preflight-20260912/`.


### Experimental delta selection binds reconstructed base encoding (2026-09-12)

Add an experimental writer-selection helper accepting ReplayedAuthority rather
than only its decoded snapshot. Recovery accepts V1 full snapshots, but the
encoder always produces canonical V2. Computing a delta against a decoded V1
snapshot therefore hashes different predecessor bytes than exist on media.
The new helper compares the actual reconstructed bytes with canonical metadata
plus the decoded record stream. A valid legacy full base selects full-snapshot
materialization (None); canonical V2 remains eligible for delta encoding. Invalid
bytes, non-increasing/out-of-context generations and inconsistent replay depth
are rejected. The existing depth-32 fallback and size/prefix checks still apply.
The helper remains test-only and does not change production publication or GC.

A regression recovers both V1 and V2 through the authenticated mock source,
reproduces failed reconstruction of a directly encoded delta over V1, verifies
safe V1 fallback and exact V2 delta reconstruction, and rejects damaged input
and stale generations. The 32-link replay fixture also verifies selection falls
back at the depth limit. All eight delta tests pass; independent Python recovery
reconstructs three fixture links and rejects 1,941 invalid cases. Production
sources are unchanged this turn, so no new QEMU timing or recovery claim is made.
Publication integration, ancestor GC lifetime and full replay memory budgeting
remain unfinished. Evidence: `target/storage-authority-legacy-base-20260912/`.


### Cumulative authority recovery ABBA qualification (2026-09-12)

Compare the saved `storage-authority-current-qemu-20260912/candidate.elf` with a
fresh current ELF. Current includes early filtering of historical authority
scan descriptors, lazy allocation enumeration, borrowed preflight batches and
the shared full/metadata encoding helper; test-only delta changes are inactive.
Saved source diffs and hashes identify the comparison. The initial build from
the repository root missed firmware target configuration and failed; only the
successful build from firmware/qemu-virt is used. Normal cache source is restored
and byte-checked before running. No build overlaps the timed runs.

Four independent fresh disks, old/current/current/old, each retain 256 unique
4 KiB objects under 128 MiB, 64-page cache, one-hart TCG, 4/2 MiB/s read/write
and 400/200 IOPS limits. All 1,024 samples and four JSONL validations pass.
Summed operation seconds: 12.951374 / 13.151162 / 12.218738 / 11.935168.

| Metric | Old mean | Current mean | Change |
| --- | ---: | ---: | ---: |
| Total seconds | 12.443271 | 12.684950 | +1.94% |
| Per-run median ms | 32.6815 | 33.9335 | +3.83% |
| Per-run maximum seconds | 1.9024085 | 1.9086850 | +0.33% |
| GC-episode operations 206/234, seconds | 3.440773 | 3.454297 | +0.39% |

Every per-sample I/O counter matches across all four runs. Each run reads
8,097,792 bytes in 1,565 requests, writes 53,694,464 bytes in 1,862 requests and
flushes 825 times. These results do not establish a speedup: current is slightly
slower on average, while baseline repetitions themselves vary by about 7.85%.
Do not attribute the cumulative difference to an individual change or compare
absolute latency against older sessions. Retain the verified bounded-memory
changes without a latency claim. Full authority snapshot write amplification
remains the main unresolved cost; further work should prioritize incremental
publication rather than claiming these recovery changes solve SD throughput.

Evidence: `target/storage-authority-recovery-abba-20260912/` contains current ELF,
source snapshots/diffs/hashes, exact commands/ELF hashes, four serial/JSONL logs,
validation output and summary.json. No production edits in this qualification
turn and no physical SD measurement or new crash-qualification claim.


### Test-only incremental checkpoint mount and GC integration (2026-09-12)

Connect the experimental delta selector to the existing persistent snapshot
publisher via a cfg(test) wrapper, and connect cold checkpoint recovery to the
experimental replayer only in cfg(test) builds. Normal builds still reject
VIBEAUL1 authority roots. This harness deliberately does not establish complete
heap budgeting or production admission; its bridge uses a copied allocation
list and rereads the tip, so it is not a performance implementation.

A new integration test publishes three incremental authority checkpoints through
the actual segment/allocation/checkpoint writer, confirms each on-media root is
VIBEAUL1, and cold-mounts the resulting image to the exact expected snapshot.
Before GC, independently corrupting each ancestor/tip payload rejects cold mount
without writing media. The real collect_garbage path then materializes VIBEAUT2,
retains the record stream, and a subsequent cold mount succeeds even after all
old ancestor payloads are damaged. This establishes that the existing full
materialization GC path can detach the chain in this successful execution.
It does not prove delta publication/GC power-cut atomicity, physical reuse safety
at every cut, nonempty capability graphs or independent full-image admission.

The selected host suite passes 258 tests with one ignored (222 library, 6 fused,
24 GC, 6 steady-state). Production cargo check passes separately. Existing
integration suites exercise their normal full-snapshot paths; they must not be
counted as delta-specific fault qualification. No QEMU delta timing or SD
performance claim is made. Next work must cover incremental checkpoint fault
injection and complete replay memory accounting before production enablement.
Evidence: `target/storage-authority-delta-mount-gc-20260912/`.


### Experimental incremental publication mutation/cancellation matrix (2026-09-12)

Extend the test-only checkpoint integration with actual publisher fault injection.
Start from a durable generation-3 delta over a generation-2 full snapshot, then
publish a generation-4 delta. A successful probe confirms VIBEAUL1 on media and
measures 20 write/flush mutation points. At each point inject not-submitted failure,
ambiguous failure (no effect / visible-only / durable), or cancellation while
pending (the same three effects): 140 independent cases from the same durable
base image. This exercises continuation of an existing delta chain.

After discarding volatile state, cold recovery must equal the complete encoded
old or new snapshot and its exact checkpoint generation, and must perform zero
mutations. Results: 136 old and 4 new, no mixed snapshots or mount failures.
Every old outcome successfully retries publication; another power cycle and
cold mount confirms the exact new snapshot in all 140 cases. This covers
page-write/flush effects exposed by this host fault device, not arbitrary torn
sectors, nonempty capability graphs, multi-extent deltas, GC cut boundaries or
real SD power loss. Those remain separate qualification requirements.

Three experimental integration tests and all eight codec tests pass. Production
code is unchanged this turn; no new QEMU or latency claim. Incremental admission
remains cfg(test), with production memory budgeting/offline verification and
GC fault qualification unfinished. Evidence, including counted outcomes:
`target/storage-authority-delta-publish-cuts-20260912/experimental.log` and
`codec.log`. The earlier cuts.log records the first matrix without retry checks.


### Experimental delta GC mutation/cancellation matrix (2026-09-12)

Start from generation 5 containing three incremental authority checkpoints over
a full base. Run the real GC materialization and reuse-barrier protocol. The
successful probe has 40 write/flush mutation points; each is tested with the same
seven failure/cancellation effects as the incremental publication matrix, for
280 independent cases. All effects begin from an identical durable image.

Cold recovery returns exactly the old encoded snapshot at generation 5 or the
complete materialized snapshot at generation 6/7. Outcomes are 157 / 119 / 4
respectively. Mount performs zero mutations. Generation 5 keeps every ancestor
allocated; generation 6 allows allocated/retired ancestors but none free before
the reuse barrier. Retrying or resuming GC from either interrupted stage succeeds,
and another power cycle recovers the materialized snapshot at generation 7 in
all 280 cases. No mixed authority state or premature ancestor reuse was observed
within this matrix. Four experimental integration tests pass together, including
the prior 140-case incremental publisher matrix.

This is cfg(test) host qualification with empty object/grant graphs and short
single-extent deltas. It does not cover nonempty graph GC relocation, arbitrary
torn sectors, large delta extents, bounded replay heap, independent full-image
admission, or real SD power failure. Production delta admission remains disabled;
no throughput claim is made. Evidence: `target/storage-authority-delta-gc-cuts-20260912/`.
`experimental.log` includes the final ancestor-allocation/barrier assertions;
`cuts.log` is the initial successful matrix before those assertions were added.


### Live object/grant incremental GC fault qualification (2026-09-12)

Generalize the experimental GC fault harness to keep both empty-graph coverage
and a live 4 KiB patterned object with a root grant. The object and grant are
initially imported through the normal full-snapshot path; three subsequent
deltas preserve those bindings while appending high-water records. The GC
matrix now exercises a nonempty catalog, manifest and authority graph.

The live-object probe has 45 write/flush mutation points, yielding 315 fault or
cancellation cases. Cold outcomes: 192 old incremental checkpoints, 119 complete
materializations before the barrier, 4 completed reuse barriers. Every case
recovers the exact encoded authority snapshot for its phase without writing
media, then retries/resumes GC and cold-mounts the completed checkpoint.
Before retry and after final recovery, independently replay the record stream
against the exact external root grant, compare the complete grant record, read
and compare all object bytes, and verify logical/physical quota usage. All pass.
Ancestor allocation/barrier assertions remain active in both graph variants.

Five experimental integration tests pass together: 140 publication fault cases,
280 empty-graph GC cases and 315 live-graph GC cases, plus successful recovery
fixtures. This covers one preexisting live root grant; it does not establish
correctness for grant/revoke mutations in deltas, multi-object graph topologies,
large/multi-extent chains, arbitrary torn sectors, or real SD power failure.
Production code is unchanged. Bounded replay memory, independent image admission
and production incremental enablement remain unfinished; no speedup is claimed.
Evidence: `target/storage-authority-delta-live-gc-20260912/experimental.log` and
`cuts-final.log`. Initial cuts.log records a test field-name compile error fixed
before running the matrix.


### Independent experimental checkpoint-region reconstruction (2026-09-12)

The independent migration verifier's reconstruct_v2_checkpoint API now has an
explicit allow_experimental_delta=False parameter. Default behavior still rejects
delta roots; no CLI or migration-container enablement is added. In opt-in mode,
resolve/authenticate each predecessor through RawImageResolver (including segment
framing and Allocated membership), bound the chain to 32 links and 64 MiB cumulative
payload, and reconstruct with the separately implemented Python delta codec.
Each physical target generation is checked; canonical snapshot policy, catalog,
blob and object-graph verification then follows the existing path. All dependency
pointers are recorded. This first bridge accepts single-extent payloads only.
AuthorityPolicy also carries an explicit record-store ID with the existing ID as
default, avoiding global mutation for Rust test fixtures.

The Rust successful checkpoint/GC fixture optionally exports raw V2 regions via
VIBE_DELTA_IMAGE_FIXTURES. scripts/test-authority-delta-image.py verifies exported
generation 5 at depth 3 and generation 7 at depth 0 under an explicit empty-graph
fixture policy. It rejects default-disabled delta admission, wrong external policy,
wrong record-store identity, and corruption of each of the four physical authority
payloads: nine rejection cases. An explicit corruption-count assertion prevents a
vacuous loop over the nested structural parser output. Earlier image.json preceded
that fix; image-final.json is authoritative. Existing byte-oracle reconstruction
still passes three links/1,941 rejections, and the production verifier selftest
passes 25,129 cases. Rust export test passes.

This is independent checkpoint-region validation, not yet full migration-container
or retained-checkpoint fallback admission, multi-extent delta support, live-object
fixture verification, or a bounded Rust heap proof. Production delta mount remains
cfg(test). No QEMU/SD speedup is claimed. Evidence:
`target/storage-authority-delta-image-20260912/` (fixtures, export.log,
image-final.json, codec.json and selftest.json).


### Independent live-object incremental image verification (2026-09-12)

Extend the Rust live-object GC fixture export to include live-delta.raw and
live-materialized.raw alongside the empty-graph pair. The independent Python
fixture policy requires exactly the expected root grant (identity, parent,
object, slot/generation, rights, resource kind and flags), live slot membership,
object-before-grant ordering, raw kind and all 4 KiB patterned content bytes.
Then call the existing verify_authority_bindings path for every region, including
the empty fixtures, to check exact policy-selected object sets, CAS mappings,
commit generations, kinds, reference codec, content and principal quota totals.

All four exported V2 regions verify: generations 5/7 with depths 3/0; the live
pair each has one verified object and 4,096 logical bytes. Nineteen rejection
cases cover default-disabled incremental admission, foreign policy/store ID,
every authority ancestor payload and live canonical Blob payload corruption.
Explicit counters ensure both ancestry and Blob corruption loops execute.
The Rust export run also passes all five experimental integration tests,
including the 140/280/315-case publication and GC fault matrices.

No production code changes this turn. This verifies the specified live root in
raw V2 checkpoint regions, not arbitrary authority policies, grant/revoke changes,
full migration-container/fallback admission, multi-extent deltas, or bounded Rust
replay heap. Production incremental admission remains disabled. Evidence:
`target/storage-authority-delta-live-image-20260912/` (fixtures, export.log,
image.json). No performance claim is made.


### Experimental replay owned-buffer budget (2026-09-12)

Add a separate buffer_bytes limit to the test-only replay engine. Cumulative
payload traffic and maximum individual snapshot length do not bound the overlap
of retained ancestor payloads, an old reconstructed snapshot and its successor.
Track capacities of fetched payload Vecs, constrain each source read by remaining
buffer budget, and precheck resident_buffers + declared successor length before
apply_link can allocate the next output. Release accounted predecessor/delta
capacity as each link is consumed. Report the peak of this accounting separately.

The 32-link fixture reports 34,432 bytes for these owned buffers. Exactly that
budget succeeds with identical output; one byte less rejects with Memory before
the corresponding successor allocation. A cap smaller than the known tip payload
rejects before any source call. All eight codec tests and five integration tests
pass, retaining the 140/280/315 publication and GC fault cases.

This is deliberately NOT a total heap bound: decoded snapshot copies, canonical
re-encoding, semantic graph/preflight state, Vec descriptor tables, source scan
workspace and allocator overhead are excluded. A source must also honor its
supplied maximum; returned capacity is defensively checked after reading. Existing
test bridges use generous explicit buffer caps and do not claim to enforce the
production recovery_memory_bytes budget. The remaining costs must be bounded or
removed before production enablement. No production source, media encoding or
performance claim changes. Evidence:
`target/storage-authority-delta-buffer-budget-20260912/codec-final.log` and
`integration.log`.


### Avoid full canonical re-encoding during delta replay (2026-09-12)

Experimental delta reconstruction previously encoded the fully decoded predecessor
and successor into separate complete temporary payloads to check canonical byte
equality. Share a canonical_snapshot_matches helper which encodes metadata only
and compares that prefix plus the decoded record stream directly against the
original bytes. The writer's replayed-base selection uses the same helper.
This removes the record-stream copy from both canonical checks per link; full
snapshot decoding, graph validation, result digests and exact byte equality remain.
The legacy-base full-snapshot fallback is unchanged. Production code is unchanged.

For both rich-table snapshots, compare canonical output successfully and reject
every truncation, each single-byte flip and a trailing byte. Existing corruption,
legacy and 32-link tests pass: eight codec tests total. Five integration tests
also pass, retaining 140 publication, 280 empty GC and 315 live-object GC fault
cases. The previously reported owned-buffer peak remains 34,432 bytes because
that accounting excluded canonical encoding scratch; this is not a measured
whole-heap reduction or latency claim. Metadata encoding, decoded record copies,
semantic replay and scan workspace still need complete budgeting before release.
Evidence: `target/storage-authority-delta-canonical-borrow-20260912/`.


### Actual page-I/O comparison of experimental delta publication (2026-09-12)

Instrument the host fault device with read-page, write-page and flush counters
without changing its failure semantics. From the same durable 321-record empty
object-graph authority history, publish the same eight one-record successors
using either the existing full snapshot publisher or the experimental selector
plus that publisher. Count actual PageDevice operations after mount and before
final cold verification, including publication verification reads. Both final
cold mounts reproduce the exact same snapshot. This is authority-only metadata
traffic; it is not an object workload or a QEMU timing result.

| Eight publications | Full snapshots | Experimental deltas | Change |
| --- | ---: | ---: | ---: |
| Read bytes | 2,105,344 | 3,784,704 | +79.77% |
| Write bytes | 1,843,200 | 524,288 | -71.56% |
| Flush calls | 32 | 32 | unchanged |

The format reduces actual page writes substantially while preserving flush
boundaries. However, the test-only bridge rereads and reconstructs the ancestry
before every append, producing a large read penalty; total transferred bytes
also increase. Do not claim end-to-end speedup. Production integration should
retain verified base provenance/state across successful publications instead of
copying this deliberately inefficient test bridge, while preserving invalidation
on mount/generation changes and legacy full-snapshot fallback. Full recovery heap
budgeting and remaining admission work still gate enablement.

Six experimental tests pass, including the I/O comparison and prior fault matrices.
The selected host suite passes 262 tests with one ignored (226 library, 6 fused,
24 GC, 6 steady-state). Production code is unchanged. Evidence:
`target/storage-authority-delta-io-20260912/` (io.log, summary.json, integration.log,
host.log). No real-device or QEMU latency claim is made.


### Verified base provenance cache for experimental publication (2026-09-12)

The test-only delta publisher now retains a small provenance witness after a
successful verified publication: store UUID, checkpoint generation, authority
pointer, admitted/next-segment horizons, canonical snapshot digest and observed
chain depth. It stores no duplicate history/ancestor buffers. The next append
checks all identities and hashes the current in-memory snapshot before reusing
the verified base; a mismatch falls back to device replay. Full publication
fallback resets depth. The witness is taken before fallible encoding/publication,
installed only after verified success, and cleared on mount. GC/growth/ordinary
publications change the bound context so a retained stale witness cannot match.
This remains cfg(test), not a production feature or total heap budget solution.

Tests reject changes to each of six bound context/snapshot components and check
cold-mount clearing. Both cold and warm-cache publication fault matrices pass
140 cases each; every failure/cancellation leaves no cached witness, and recovery
plus retry remains exact. Empty/live GC matrices still pass 280/315 cases.

For the same actual host page-I/O test (321-record base, eight metadata appends):

| Metric | Full snapshots | Cached experimental delta | Change |
| --- | ---: | ---: | ---: |
| Read bytes | 2,105,344 | 1,003,520 | -52.33% |
| Write bytes | 1,843,200 | 524,288 | -71.56% |
| Flush calls | 32 | 32 | unchanged |

This removes the earlier uncached bridge read penalty (3,784,704 read bytes).
It includes the initial cold-base read and verification reads, excludes setup
and final cold validation, and makes no QEMU/SD latency claim. Final snapshots
remain byte-identical. Seven experimental tests pass; selected host suite passes
263 tests with one ignored, and production cargo check passes. Full recovery
budgeting and production admission remain unfinished. Evidence:
`target/storage-authority-delta-base-cache-20260912/verified.log`, summary.json,
host.log and production.log. integration-final.log is an intermediate failed
compile from accessing a private test field; verified.log uses public construction.


### Borrowed record validation during snapshot decode (2026-09-12)

Factor authority snapshot parsing so metadata tables are decoded first and the
record stream is validated directly from input bytes. Production full decoding
copies the record stream only after full semantic/structural validation finishes,
so that copy no longer overlaps the preflight graph workspace. A test-only
canonical-V2 validation entry point returns generation/record offset without
retaining any record copy. Experimental delta reconstruction uses that entry
point for both predecessor and successor, eliminating their decoded-stream
copies as well as the already removed canonical re-encoding copies. Record
chain, graph, tables, offsets, reserved fields and generation checks remain.
Only the private parsing helper can temporarily hold metadata without records;
public full decoding continues returning an owned, validated snapshot.

Differential tests compare borrowed canonical admission with owned decode plus
canonical re-encoding equality for rich snapshots, every truncation and each
single-byte mutation. Existing corruption/legacy/depth and publication/GC matrices
pass. The selected host suite passes 263 tests with one ignored. QEMU three-boot
file-tree/GC/cold recovery/powered-off verification and Duo release check pass.

This changes production decode allocation lifetime but not its bytes or accepted
format. No timing/whole-heap measurement is claimed. Metadata tables, semantic
BTree/transaction state and source scanning still require complete accounting
before production delta admission. Evidence:
`target/storage-authority-borrowed-decode-20260912/` (host.log, codec.log,
gate.log, gate-evidence and duo.log).


### Validation-only semantic replay without retained object content (2026-09-12)

Add durable-format PreflightValidator as a wrapper with a private replay builder.
It shares the existing record/transaction/CRC/graph validation, but skips storing
ObjectChunk bytes in PreparedObject. Length and content CRC continue accumulating;
committed metadata uses validated byte_len rather than retained Vec length. The
wrapper returns only the final validated sequence, never recovered objects or a
RecoveryPreflight, so missing content cannot escape as a recovered object.
PreflightReplay::new continues retaining complete content for ordinary recovery.
Production authority snapshot validation now uses PreflightValidator.

A 32 KiB inline-object test checks zero content-buffer capacity in both prepared
and committed validator state at every batch, compares every complete-record
prefix against ordinary recovery, verifies poisoning after error, and confirms
ordinary recovery still returns exact object bytes. Durable-format's 37 tests
pass; the selected segment-store suite passes 263 with one ignored. QEMU
three-boot file-tree/GC/cold-recovery/powered-off verification and Duo release
check pass. Existing authority corruption/graph and delta fault cases remain
covered by the library suite.

This removes retained inline content from semantic validation, including content
of incomplete transactions, without skipping digest work. It is not a measured
whole-heap peak or timing result. Metadata BTree/graph entries and scan workspace
still require budgeting before production incremental admission. Evidence:
`target/storage-authority-validator-content-20260912/` (durable.log, host.log,
gate.log, gate-evidence, duo.log).


### Release append-time replay indexes before graph construction (2026-09-12)

PreflightReplay::finish now drops transaction, ID-class, seen-derivation and
seen-object indexes after append-time validation has completed and before
allocating the recovered graph and slot maps. This also releases any unfinished
inline-object buffers in ordinary recovery. The temporary object-kind map is
released after grant validation, before slot construction. Committed content and
all existing transaction, identity, graph and slot validation remain intact.

Durable-format passes 37 tests; selected segment-store suites pass 263 with one
ignored. QEMU three-boot file-tree, GC pressure, cold recovery and powered-off
verification pass. Duo release check passes (compile only; no real device used).
This reduces overlapping allocation lifetimes; no measured heap peak or latency
improvement is claimed. Full recovery memory budgeting and production delta
admission remain unfinished. Evidence:
`target/storage-preflight-index-lifetime-20260912/` (durable.log, host.log,
gate.log, gate-evidence and duo.log).


### Experimental replay table allocation budget (2026-09-12)

Extend the test-only authority delta replay owned-allocation budget to include
ancestor and pending-link Vec storage. Growth checks conservatively allow for
the old table and its full replacement to coexist before reserving; actual
capacity is checked after reservation as well. Pending table capacity remains
charged after entries are popped. This closes a bookkeeping gap rather than
increasing the chain's allocations or changing the on-media format. Allocator
internal overhead, semantic decoder/preflight allocations and source scan
workspace remain outside this budget, so production admission is still pending.

The 32-link fixture's accounted peak changes from 34,432 to 41,440 bytes. Exact
budget succeeds and one byte less rejects. A targeted test verifies rejection
before table allocation/growth, retained contents on rejection, reallocation
overlap, and reuse after pop without charging another allocation. Selected host
suites pass 264 tests with one ignored, including publication/GC fault matrices.
No QEMU timing or real-device claim: this change is confined to cfg(test) replay.
Evidence: `target/storage-delta-table-budget-20260912/codec.log` (initial eight
codec tests and peak output), `host.log` (final suite including the new test).


### Borrowed full-base validation in experimental delta replay (2026-09-12)

Experimental cold replay now validates its full-snapshot base through a borrowed
record-stream helper instead of constructing an owned record-stream copy solely
to check the generation. The helper accepts both supported V1 and V2 snapshots,
runs the existing full metadata/record/graph validation, and returns only the
validated generation and record offset. Canonical delta reconstruction wraps
that helper with its existing V2-only requirement; legacy bases still require
full materialization before a delta can be published.

The legacy/current-base test now compares exact success/error results against
owned decoding for valid fixtures, every truncation and every single-byte
mutation. Selected host suites pass 264 tests with one ignored, including cold
recovery and publication/GC fault matrices. No latency or total-heap result is
claimed, and these entry points remain cfg(test). Decoder metadata/graph and
source scan budgeting remain required before production delta admission.
Evidence: `target/storage-delta-borrowed-base-20260912/host.log`.


### Independent multi-extent authority reconstruction (2026-09-12)

The migration verifier now reconstructs authority payloads across extents and
segments instead of requiring a single extent. Every member resolves through
the sealed-segment/pointer verifier in Allocated media. Reconstruction checks
index/count, generation, offsets, shared metadata, per-extent SHA-256, total
length and complete-payload SHA-256. All physical members participate in the
existing overlap checks. Matching extent accumulation and payload reads are
bounded. Experimental delta ancestors use the same resolver; delta admission
remains explicitly opt-in and disabled in the normal CLI.

A new Rust test publishes an 8,193-record base (>4 MiB, five extents across
multiple 4 MiB segments), appends one incremental checkpoint and verifies exact
cold-recovered bytes. It exports multi-base.raw and multi-delta.raw for the
independent scripts/test-authority-multi-image.py check. Both regions pass;
corrupting every authority payload individually yields 11 rejected cases. The
existing four delta/live/GC-materialized regions still pass their 19 rejection
cases. Selected Rust suites pass 265 tests with one ignored; migration verifier
selftest passes 25,129 cases.

This adds offline coverage for multi-extent full bases beneath delta links. It
does not yet establish coverage of a multi-extent delta payload, full-container
checkpoint fallback, or production incremental admission/heap budgeting. No
QEMU latency or SD-device result is claimed. Evidence:
`target/storage-authority-multi-image-20260912/` (host.log, multi.json,
existing.json, selftest.json and fixtures). rust.log is the initial smaller
fixture; the final cross-segment test is in host.log.


### Cross-segment delta payload and remaining-read budget (2026-09-12)

Extend the multi-extent fixture with a second incremental publication containing
8,192 additional high-water records. Its delta payload spans five extents and
multiple segments; the reconstructed snapshot contains 16,386 records. The Rust
test checks the physical VIBEAUL1 magic to rule out full-snapshot fallback, then
cold-mounts and compares the exact canonical snapshot. This is host simulation
with a 32 MiB configured recovery budget, not proof of full heap accounting or
SD-device suitability.

Independent Python verification now covers the full base, small delta and large
delta at depths 0/1/2. All 22 individual physical authority-payload corruptions
are rejected across the three images. Six short-budget checks also reject: known
first-extent overflow before any resolver read, and declared multi-extent total
overflow after the first extent but before sibling reads. Exact payload budgets
succeed. Ancestor resolution now receives the chain's remaining cumulative
payload budget before reading, rather than checking only after loading it.

Selected Rust suites pass 265 tests with one ignored; migration selftest passes
25,129 cases. Evidence: `target/storage-authority-large-delta-image-20260912/`
(rust.log, host.log, multi.json, selftest.json, fixtures). Production incremental
admission, complete heap budgeting and full-container fallback remain pending;
no new QEMU timing or physical-device measurement is claimed.


### Transfer the already verified tip into experimental replay (2026-09-12)

The experimental mount bridge previously discarded the authority tip bytes that
read_recovery_authority_payload had just authenticated, then read the tip again
as the first replay step. It now transfers that owned buffer and its verified
extent generation into a one-use DeviceAuthoritySource slot. The slot requires
the exact pointer and an Allocated segment, checks capacity against the read
budget, and is consumed once. Normal replay pointer, generation, depth and
cumulative buffer/payload checks still apply. Nothing is retained across mount
attempts, and production format admission remains unchanged.

The sealed three-payload fixture compares ordinary replay with replay supplied
the preceding authenticated read. Replay-stage reads fall from 27 to 18 pages
(36 KiB avoided); both measurements exclude the common initial mount read.
Reconstructed bytes and cumulative logical payload accounting match, and the
one-use slot is empty afterward. Selected host suites pass 265 tests with one
ignored, including publication/GC fault matrices and the cross-segment large
delta. Evidence: `target/storage-delta-reuse-tip-20260912/host.log` and reads.log.
This is an experimental host I/O result, not a QEMU timing or SD measurement.
Repeated ancestor segment scans and complete replay heap accounting remain.


### Borrow the allocation bitmap in experimental device replay (2026-09-12)

Remove allocated-segment Vec construction from the experimental mount bridge,
cold-base publisher path and device replay adapter. DeviceAuthoritySource now
borrows AllocationV2 directly for membership checks and lazily enumerates
admitted segment numbers only when a cross-segment authority chain requests
them. Small sealed-media codec fixtures retain a borrowed-slice adapter. This
eliminates the separate u64 array proportional to allocated segment count; no
new cache or persistent state is introduced.

The selected host suite passes 265 tests with one ignored, including the large
cross-segment delta and fault matrices. A subsequently added 4,096-segment sparse
bitmap test checks Free/Retired exclusions, membership beyond the map (including
u64::MAX), and iteration at empty, partial and excessive admitted bounds. All
10 codec tests pass, retaining the verified-tip read result and 32-link budget
boundary. Evidence: `target/storage-delta-borrowed-allocation-20260912/host.log`
and codec.log. No new latency or whole-heap result is claimed; scan workspace
and semantic graph allocations still need accounting for production admission.


### Filter authority generation before scan-result allocation (2026-09-12)

Production cross-segment authority recovery now passes the requested generation
and descriptor-count cap into the shared verified-segment interpreter. Previously
scan_segment_authority_records copied every historical Authority descriptor, then
compared the unfiltered result count to the selected chain's extent count. This
could allocate unnecessary result storage and reject a valid selected generation
when unrelated historical records exceeded that cap. Collection now filters kind
and generation first and checks the count before reserving each matching entry.
Segment descriptor/summary/seal verification is unchanged; later chain-wide
collection still rejects excess matching siblings across segments.

The targeted test sends 10,000 unrelated records through the collection helper
and observes zero result capacity, then verifies an excess matching record is
rejected without further allocation. Selected host suites pass 266 tests with
one ignored. QEMU three-boot file-tree/GC pressure/cold recovery/powered-off
verification and Duo release compilation pass. Evidence:
`target/storage-authority-scan-filter-20260912/` (host.log, gate.log,
gate-evidence, duo.log). This reduces the filtered result allocation; the full
verified descriptor table still exists and needs separate memory accounting.
No timing or physical SD measurement is claimed.


### Bound declared authority chains before descriptor reservation (2026-09-12)

Production authority resolution now checks the authenticated first extent before
reserving the chain descriptor array: index/offset zero, nonzero count and stride,
matching logical/encoded length, fixed-stride/nonempty-tail length bounds, and
declared payload within the supplied budget. Variable descriptor-array bytes
are independently capped by that budget (one descriptor remains fixed overhead
for tiny payloads). This prevents small declared fragments from inducing a huge
descriptor reservation even when their payload total fits. After gathering all
extents, the actual byte sum must also match the declared total.

Tests cover exact descriptor budget, one byte less, payload overflow, impossible
length/count combinations and u32::MAX declared extent counts. Selected host
suites pass 267 tests with one ignored; QEMU three-boot file-tree/GC pressure/
cold-recovery/powered-off verification and Duo release compilation pass.
Evidence: `target/storage-authority-declared-budget-20260912/` (host.log,
gate.log, gate-evidence and duo.log). These checks separately bound payload and
variable descriptor storage; they do not yet sum all overlapping scan, decoder
and graph allocations into a complete recovery heap budget. No timing or
physical-device improvement is claimed.


### Include cold recovery in the authority delta I/O comparison (2026-09-12)

Extend the existing 321-record base / eight high-water appends comparison with
separately reset device counters around the final power-cycle and mount. Both
paths recover byte-identical canonical snapshots and perform zero writes/flushes
during mount. Complete publication counters remain unchanged: full versus delta
reads 2,105,344 / 1,003,520 bytes, writes 1,843,200 / 524,288 bytes, flushes 32 / 32.

Cold mount reads are 716,800 bytes for full snapshots and 1,400,832 for the delta
chain (+95.43%). Publication plus one cold mount reads 2,822,144 / 2,404,352 bytes
(-14.80%). Arithmetic using two identical cold mounts reverses the read advantage
(3,538,944 / 3,805,184 bytes, +7.52%); that two-mount figure is an extrapolation,
not a second measured execution. Write savings remain 71.56%. This identifies
ancestor replay/read amplification as the next optimization target and argues
for evaluating periodic materialization against expected reboot frequency.

The instrumented comparison test passes. Evidence:
`target/storage-delta-cold-io-20260912/io.log` and summary.json. This is a host
metadata-only workload, not QEMU timing, an object workload, or an SD benchmark.
Experimental production admission and complete heap budgeting remain unfinished.


### Attribute cold reads and model finite page caches (2026-09-12)

The authority comparison's fault device can now optionally record per-page
counts and read order during cold mount; other tests leave tracing disabled.
Full recovery reads 175 pages / 134 unique pages, versus delta recovery's
342 / 159. The delta base segment alone accounts for 132 reads / 54 unique
pages. Code inspection confirms mount strictly reconstructs both sealed
checkpoint slots, so shared ancestors are revisited; removing the older-slot
validation would change the recovery contract.

Replaying the observed read order through an initially empty ideal LRU gives
full/delta misses of 154/321 at 64 pages and 134/159 at 512 pages. Zero-capacity
misses equal all reads; a cache larger than the footprint equals unique pages.
These are offline trace simulations, not measurements of the kernel cache or
QEMU, and exclude other concurrent cache users/prefetch behavior. They show
that the small-cache configuration does not absorb most repeated reads. The
next candidate is budgeted reuse of authenticated shared state across the two
checkpoint reconstructions, preserving strict validation.

Selected host suites pass 267 tests with one ignored. No production runtime
change was made this step. Evidence:
`target/storage-delta-cold-page-attribution-20260912/io.log`, host.log and
summary.json. Full production delta admission remains unfinished.


### Configurable bounded verified-segment memo (2026-09-12)

VerifiedSegmentScans now accepts explicit byte and entry limits (clamped to the
existing 320 KiB / 256-entry session maxima) and reports owned allocation bytes.
The default constructor preserves the existing session-cache limits. Zero or
undersized budgets disable admission; oversized proofs are still verified but
not cached; eviction continues using the configured allocation limit and exact
segment-generation/checkpoint-horizon checks.

A new 8 KiB memo test covers zero allocation when disabled, repeated insertion
and eviction within budget, oversized proofs, wrong segment generation and
future checkpoint proofs. Selected host suites pass 268 tests with one ignored.
QEMU three-boot file-tree/GC pressure/cold recovery/powered-off verification and
Duo release compilation pass. Evidence:
`target/storage-recovery-memo-budget-20260912/` (host.log, gate.log,
gate-evidence, duo.log).

This is infrastructure for a recovery-local memo, not yet cross-checkpoint cold
recovery reuse. Integration must reserve its memory and fall back without the
optional memo if that reservation would prevent an otherwise valid recovery.
No cold-read reduction or timing improvement is claimed for this step.


### Mount-local memo across both checkpoint reconstructions (2026-09-12)

Mount now reserves a 64 KiB / 32-entry verified-segment memo for authority reads
across both strictly reconstructed checkpoint slots. The memo is local to this
mount, keyed by sealed segment identity and constrained by checkpoint horizon.
All pointer/allocation, authority payload hashes, graph and checkpoint-transition
validation remain. Scrub and standalone recover_state use the uncached path.
Experimental delta ancestor reads share the same local memo.

The full reservation is subtracted before recovery and included in the reported
conservative peak. A MemoryLimit result drops the memo and retries the entire
pair uncached under the original budget; other failures are not retried. The
retry conservatively reports the original limit as its peak. This avoids losing
otherwise valid images to optional cache reservation, at the cost of extra reads
when that retry is needed. Both full/delta fixtures exercise this fallback at
369,920 bytes, recover exact snapshots and perform no writes.

For the 321-record base / eight append host fixture, delta cold reads decrease
from 1,400,832 to 1,064,960 bytes (-23.98%, 342 to 260 pages). Full snapshot cold
reads stay at 716,800 bytes. Publication I/O remains unchanged; publication plus
one cold mount totals 2,822,144 full versus 2,068,480 delta read bytes. Offline
64-page LRU simulation of the new delta trace gives 239 misses (previously321);
512-page misses remain159. These cache figures are simulations, not kernel
measurements.

Selected host suites pass 268 tests with one ignored. QEMU three-boot file-tree,
GC pressure, cold recovery and powered-off verification pass; Duo release
compilation passes. A scrub test's comparison between mount and scrub peaks was
removed because mount now has an optional cache reservation absent from scrub;
its stronger tight-budget assertion remains: mount succeeds where typed scrub
fails for lack of aggregate scratch. Evidence:
`target/storage-cold-recovery-memo-20260912/` (host.log, io.log, summary.json,
gate.log, gate-evidence, duo.log). No QEMU timing/physical SD speedup is claimed.
Production delta admission and complete semantic replay heap accounting remain.


### Verify mount-local memo lifetime on same-instance remount (2026-09-12)

Extend the delta checkpoint integration test beyond fresh-instance corruption.
For each of four physical authority generations, a store first mounts intact
media, then the payload, descriptor or segment-seal body is corrupted before
mounting again on that same instance. All 12 remounts reject, clear the admitted
state and leave the damaged image unchanged. Restoring the exact original page
allows another mount whose canonical snapshot equals the expected result.
This verifies that shared-ancestor proofs from a successful mount do not survive
into a new mount attempt and that failure does not prevent a valid repaired
retry. The targeted test, including its existing cold/GC materialization checks,
passes. Evidence: `target/storage-cold-memo-remount-20260912/remount.log`.
No production code or timing result changed in this step.


### Current production firmware QEMU ABBA recheck (2026-09-12)

Compare the previous storage-authority-recovery-abba candidate ELF with a fresh
current production build, both with 64 cached pages. The current source was
temporarily overridden only for the build and restored byte-for-byte afterward;
the ELF was saved before restoration. Four runs use old/new/new/old order, each
256 unique 4 KiB durable object put+get samples, fresh cloned 1 GiB template,
128 MiB guest, one TCG hart, cache=none/aio=threads and 4/2 MiB/s, 400/200 IOPS
read/write throttles. No other builds/tests ran during timed sampling.

Total sample time is 12.191378 / 13.343220 / 11.563796 / 10.930814 seconds.
Mean old/new is 11.561096 / 12.453508 seconds (+7.72% slower for the candidate).
Old repeats differ by 10.34% relative to the first old run; new repeats differ
by 13.34%. This is not evidence of improvement and leaves possible steady-state
CPU regression versus environmental variation unresolved. GC episode sums at
samples 206/234 are 3.440943 / 3.441864 / 3.417276 / 3.419118 seconds.

All 1,024 records pass schema/status validation. Every per-sample counter is
identical across all four runs: per run 8,097,792 read bytes / 1,565 reads,
53,694,464 write bytes / 1,862 writes and 825 flushes. The experiment therefore
shows no device-I/O reduction in this workload. Experimental authority deltas
remain disabled in firmware; the prior host delta cold-mount savings are not
being measured here. Follow-up needs a dedicated cold-mount measurement and
isolation of CPU-path changes rather than a throughput speedup claim.

Evidence: `target/storage-current-production-abba-20260912/` contains candidate
ELF, source hashes, restoration check, exact commands/ELF hashes, four JSONL and
serial logs, validation logs, analysis script and summary.json. This comparison
covers cumulative production changes since the baseline ELF, not one isolated
cache patch.


### Dedicated benchmark-build mount telemetry (2026-09-12)

QEMU storage-bench builds now emit VIBE_STORAGE_MOUNT JSON around the mount
inside cold_recover_and_scrub, after clearing the page/recovery caches and before
authority recovery/scrub. Each record includes status, checkpoint generation,
elapsed ticks/timebase, block read/write requests and bytes, flushes and reported
recovery peak. Both successful and failed mount attempts are recorded. UART
formatting happens after timing and counter snapshots, so logging is excluded
from the mount sample. Ordinary non-benchmark firmware does not emit the record.
The existing object sample format is unchanged.

A fresh 128 MiB / 64-cache-page QEMU boot with the usual SD-like throttles
produces an initial unformatted-media failure (3.123 ms, 16 KiB read), followed
by generation-2 successful mount after native initialization (23.009 ms, 120 KiB
read, 19 read requests, reported peak 66,812 bytes). Both attempts have zero
writes and flushes. These tiny fresh-store numbers only validate telemetry;
they do not measure a prepopulated cold boot or prove a cache speedup. The
subsequent 4 KiB object sample passes schema validation.

Evidence: `target/storage-mount-telemetry-20260912/` (candidate.elf, build.log,
sources.json, restored.json, serial.log, mount.json, sample.jsonl). The temporary
64-page build override was restored byte-for-byte. Dedicated populated-image
mount comparisons remain the next measurement step.


### Populated QEMU mount: reuse CAS segment verification (2026-09-12)

Add optional run-vibeos --retain-images DIR support. Images are copied only
after QEMU stops, named vm-NNN.raw, and opened exclusively so existing fixtures
are never overwritten. Retention is not itself verification. A fresh QEMU run
created and content-checked 32 unique 4 KiB files using file-batch-create-unique.
The retained image passes the independent native migration verifier, including
32 data nodes, 32 dirents, 33 inodes and 35 CAS objects. The runner selftest and
seed sample validation pass. Fixture and verification evidence reside under
`target/storage-populated-mount-20260912/`.

An initial memo-off/on ABBA comparison showed authority-only memoization does
not reduce this fixture's mount reads: all four read 45,985,792 bytes in 5,515
requests. Inspection found CAS manifest and Blob-descriptor recovery still
passed None to the existing verified-segment memo. Production recovery now
threads the same already-reserved mount-local memo through allocation/catalog/
manifest/delta payload reads and CAS Blob descriptor validation. Individual
payload SHA checks, pointer/allocation checks, strict old/new checkpoint
reconstruction, transition validation and uncached scrub remain. No additional
cache reservation is introduced; the existing 64 KiB fallback policy applies.

A second isolated ABBA run compares the authority-only memo firmware with the
CAS-enabled memo firmware, using the same verified generation-4 image hash,
128 MiB guest, 64 cached pages, one TCG hart and 4/2 MiB/s plus 400/200 IOPS
throttles. No builds or other tests run concurrently with timed boots. Mount
seconds are 13.792193 / 0.466847 / 0.468221 / 13.787285. Mean decreases from
13.789739 to 0.467534 seconds (29.49x, -96.61%). Both baseline runs read
45,985,792 bytes / 5,515 requests; both candidates read 1,159,168 / 187
(-97.48% bytes). All mount samples have zero writes/flushes and report the same
82,482-byte conservative recovery peak.

Selected host suites pass 268 tests with one ignored, including fallback and
remount corruption checks. QEMU three-boot file-tree/GC/cold-recovery/powered-off
verification and Duo release compilation pass. The four cold-boot runs also
complete boot and pass their subsequent object sample validation. Evidence:
`target/storage-cas-recovery-memo-20260912/` contains exact commands and ELF
hashes, source/restoration hashes, four serial/JSONL files, analysis script,
summary.json, host.log, gate.log/gate-evidence and duo.log.

This speedup is for the mount phase of this populated QEMU fixture, excluding
subsequent authority recovery and full scrub. It is not a real SD benchmark or
a steady-state put/get claim. Production delta admission and total semantic
replay heap accounting remain unfinished.

### Populated QEMU cold-recovery phase baseline (2026-09-12)

The storage-bench QEMU build additionally emits VIBE_STORAGE_COLD_PHASE JSON
for authority reconstruction/policy validation (including any boot compaction)
and independent scrub. Each phase captures its elapsed time and block counters
before emitting its UART record. Authority errors that return early do not emit
an authority record; missing records must not be interpreted as zero work.
Scrub status describes the scrub result, before the caller's final authority
generation and policy checks. Ordinary firmware does not emit these records.

Two isolated boots reuse the independently verified generation-4, 32-file image
and the same 128 MiB / 64-page cache / single-hart TCG / throttled-device setup.
Both complete their subsequent object put/get sample and JSONL validation.

| Phase | Mean seconds | Read requests per boot | Read bytes per boot |
| --- | ---: | ---: | ---: |
| Mount | 0.467270 | 187 | 1,159,168 |
| Authority | 0.003530 | 0 | 0 |
| Scrub | 48.785980 | 19,516 | 160,686,080 |

All three phases perform zero writes and flushes on this fixture. Scrub takes
48.786543 / 48.785416 seconds, or 99.04% of the summed measured phases
(49.256779 seconds). The sum is not whole-boot wall time: UART output and gaps
between phases are excluded. This confirms the remaining cold-proof bottleneck
without claiming an additional performance improvement. The next optimization
must preserve scrub's fresh independent proof, payload checks, checkpoint
transition checks and memory limits. This small file-tree fixture has no
persistent authority objects, so its authority timing does not characterize a
large authority graph.

Evidence: `target/storage-cold-phases-20260912/` contains candidate ELF, build
and source-restoration evidence, serial log, sample JSONL, analysis script and
summary with the recorded QEMU environment. No builds or tests ran concurrently
with these timed boots.

### Scrub checkpoint reconstruction memo (2026-09-12)

Scrub now creates a fresh 64 KiB / 32-entry verified-segment memo for each
checkpoint reconstruction. It does not reuse mount or previous scrub proofs,
and drops the memo before independent content, padding and authority-closure
checks. The candidate recovery budget already excludes the mounted state and
any predecessor witness; the helper additionally reserves the memo, reports
that reservation in its peak, and drops/retries uncached on MemoryLimit.
Other errors are returned without retry. Tight budgets below the reservation
continue directly through uncached recovery.

Host tests pass 233 cases with one ignored. A dedicated test verifies fewer
checkpoint-recovery reads, no writes and successful uncached fallback under
an insufficient cache budget. The typed scrub scratch-boundary test derives
the mandatory peak without optional caching and still rejects one byte less.
The corruption matrix now performs a healthy scrub before corrupting media,
then requires the same instance's next scrub to detect each corruption.
QEMU three-boot file-tree/GC/cold-recovery/powered-off verification passes,
as does Duo release compilation.

Two isolated runs on the same verified 32-file image and previous controlled
QEMU setup measure scrub at 35.466881 / 35.465441 seconds. Compared with the
preceding two-run baseline, the mean decreases from 48.785980 to 35.466161
seconds (27.3%). Reads decrease from 160,686,080 bytes / 19,516 requests to
115,859,456 / 14,188 (27.9% fewer bytes). Mount remains 0.467003 seconds;
authority averages 0.003313 seconds. The measured phase sum decreases from
49.256779 to 35.936477 seconds. All phases perform zero writes and flushes;
both subsequent object samples pass validation. These are sequential baseline
and candidate pairs, not an interleaved ABBA trial or a real SD measurement.

Evidence is under `target/storage-scrub-recovery-memo-20260912/`: candidate ELF,
source/restoration hashes, build/host/gate/Duo logs, retained gate evidence,
serial log, samples and analysis summary. No builds or tests overlapped timed
boots. Scrub still accounts for 98.7% of measured cold-recovery time; remaining
content-validation scans and production delta admission remain open work.

### Scrub content-pass segment memo (2026-09-12)

Each independent content-verification pass now owns a fresh 64 KiB / 32-entry
segment proof memo, shared by CAS delta/manifest reads and Blob descriptor
validation. The memo is not shared with mount, checkpoint reconstruction,
another content pass or another scrub. Payload SHA, Merkle-tree validation,
zero-padding checks and allocation/generation bindings remain intact.

The reservation is included in the pass's base resident bytes, alongside any
retained current state and predecessor witness. Obvious insufficient budgets
skip caching; MemoryLimit during a cached pass drops the memo and retries
uncached, reporting a conservative peak. Other failures are not retried.
The content pass now records its initial streaming workspace peak even before
entering a manifest loop.

Host tests pass 234 cases with one ignored. A dedicated eight-object packed
batch test compares cached/uncached content checks: identical diagnostic
results apart from memory peak, fewer reads, no writes, successful tight-budget
fallback, and rejection one byte below mandatory scratch. Existing repeated
scrub corruption tests, strict typed-closure memory boundary, QEMU three-boot
file-tree/GC/cold-recovery/powered-off verification and Duo compilation pass.

Two isolated runs on the same verified 32-file image and controlled QEMU
configuration measure mean scrub at 9.427953 seconds, down from 35.466161
seconds (73.4%). Both runs read 29,114,368 bytes in 3,774 requests, down from
115,859,456 bytes / 14,188 requests (74.9% fewer bytes). Mount averages
0.467619 seconds; authority 0.004976 seconds; the measured phase sum is
9.900547 seconds. All measured phases perform zero writes/flushes, and both
subsequent object samples validate. The two scrub improvements together reduce
the earlier 48.785980-second scrub baseline by approximately 5.17x.

Evidence: `target/storage-scrub-content-memo-20260912/` contains source/build
and restoration evidence, ELF, host/gate/Duo logs, retained gate evidence,
serial log, JSONL, analysis and comparison summaries. No builds/tests overlap
timed boots. This is a sequential two-run comparison on one QEMU fixture, not
real SD performance or whole-boot latency. Scrub still dominates the measured
phase sum; production delta admission and complete heap accounting remain
unfinished.

### Scrub authority-closure segment memo (2026-09-12)

The independent typed/file-tree semantic closure walk now uses its own fresh
64 KiB / 32-entry verified-segment memo. The reservation is subtracted from
the remaining graph decode budget after mounted state and semantic roots are
accounted. Its peak is included in the reported decode peak; it is dropped
before retaining the decoded result. On MemoryLimit, the memo is dropped and
the original uncached decode retries with its full budget. Other errors are
returned directly. No prior mount, content or scrub proof is reused, and no
typed-edge cache is introduced.

Host tests pass 235 cases with one ignored. A packed graph with four distinct
typed-parent/raw-child pairs checks reduced reads, identical diagnostics
apart from memory peak, low-budget uncached admission, optional-cache fallback
and rejection below retained-root memory. Existing dangling-child, malformed
typed content, repeated-media-corruption and mandatory typed-scratch boundary
tests pass. QEMU three-boot file-tree/GC/cold-recovery/powered-off verification
and Duo release compilation also pass.

On the same verified 32-file image, with 128 MiB guest, 64 cached pages, one TCG
hart and 4/2 MiB/s plus 400/200 IOPS limits, two isolated scrub measurements are
2.581303 / 2.584533 seconds. Mean falls from 9.427953 to 2.582918 seconds
(72.6%); reads fall from 29,114,368 bytes / 3,774 requests to 6,078,464 / 1,036
(79.1% fewer bytes). Mount averages 0.467857 seconds and authority 0.006028;
the measured phase sum is 3.056803 seconds. Both subsequent object samples
validate, and all cold phases perform zero writes/flushes.

Across the three scoped scrub memo changes, mean scrub falls from 48.785980
to 2.582918 seconds (18.89x); the measured cold-phase sum falls from 49.256779
to 3.056803 seconds (93.8%). These remain sequential two-run comparisons on
one populated QEMU fixture, excluding between-phase gaps and whole boot time;
they are not real SD measurements or general steady-state throughput claims.
Evidence is in `target/storage-scrub-closure-memo-20260912/`: source/restoration
hashes, ELF, build/host/gate/Duo logs, gate evidence, serial log, samples and
analysis/comparison summaries. No builds or tests overlapped timed boots.

### 128-file scaling and memo-capacity experiment (2026-09-12)

The current unique-file benchmark rejects a single 128-file transaction before
storage work because its per-transaction cap is 100. Preserve this admission
limit. Instead, two 64-file unique batches with seeds 128/129 create and read
back 128 distinct 4 KiB files. The independent native image verifier confirms
128 data nodes, 128 dirents, 129 inodes, 8 tree nodes and 142 CAS objects.
The retained image selects checkpoint generation 5; its predecessor retains
the earlier 64-file publication, unlike the previous 32-file fixture. Thus
raw ratios against that fixture do not isolate file-count scaling alone.

Two controlled cold boots with the production 64 KiB scoped memos yield mean
mount 1.439442 seconds (576 requests, 3,641,344 bytes), authority 0.003616
seconds and scrub 13.449823 seconds (5,382 requests, 31,547,392 bytes).
The measured phase sum is 14.892880 seconds; mount reports a 133,842-byte peak.
Both subsequent object samples validate and all cold phases perform zero
writes/flushes.

A temporary experiment doubles only the four phase-local memo reservations
to 128 KiB, preserving the 32-entry limit and the same 64-page block cache,
128 MiB guest, image, hart and device throttles. Two boots yield mount
1.440365 seconds and scrub 13.492389 seconds. Every phase's read request and
byte count is identical to the 64 KiB version, while the mount-reported peak
increases to 199,378 bytes. Both object samples validate. There is no measured
I/O benefit from doubling these memos on this fixture; retain production
64 KiB limits. All temporary source changes were restored after building.

This does not establish cache sufficiency for every layout or device, but
rules out a byte-capacity benefit from this specific doubling experiment.
Further scaling work should separate predecessor/current verification costs
and physical layout from current live-file count. Evidence lives under
`target/storage-populated-128-20260912/`: rejected single-batch attempt,
two-batch samples and retained image, independent verification, production
cold samples/summary and the memo128 experiment/build/restoration evidence
with memo-comparison.json. No builds/tests overlapped timed boots.

### Reuse current content proof after exact publication equality (2026-09-12)

Scrub already freshly verifies current contents before reconstructing both
checkpoint slots. After recovering the newer checkpoint, it checks the strict
predecessor transition and same_publication equality, including all catalog
and CAS mappings, physical roots, allocation state and generations used by
content verification. It no longer repeats the identical newer content pass
after that equality succeeds. Older checkpoint contents remain independently
verified; proofs are not reused between scrub invocations. No cache capacity
or durable format changes.

Host suites pass 236 tests with one ignored. A new regression removes one of
two in-memory object mappings that deduplicate to the same valid Blob: the
remaining mapping is content-valid and closed, but scrub must reject it as
different from the independently reconstructed durable publication. Existing
media-corruption and memory-boundary tests pass, along with QEMU three-boot
file-tree/GC/cold-recovery/powered-off verification and Duo compilation.

On the verified 128-file/two-batch image with the existing controlled QEMU
setup, two scrub runs take 11.652875 / 11.652324 seconds. Mean decreases from
13.449823 to 11.652600 seconds (13.36%). Reads decrease from 31,547,392 bytes /
5,382 requests to 27,373,568 / 4,663 (13.23% fewer bytes). Both subsequent
object samples validate; all cold phases perform zero writes and flushes.
Mount averages 1.508318 seconds with unchanged 576 requests / 3,641,344 bytes;
the measured phase sum is 13.164648 seconds. This is a sequential two-run
comparison on one QEMU image, not a real SD or whole-boot measurement.

Evidence: `target/storage-scrub-publication-reuse-20260912/` contains the ELF,
build/source-restoration records, host/gate/Duo logs, retained gate evidence,
serial log, samples, analysis and comparison summaries. No builds or tests
overlapped timed boots.

### Scrub adjacent metadata reads (2026-09-12)

Segment header/seal and extent descriptor/seal verification now reads each
adjacent pair through PageDevice::read_pages with the same two-page workspace.
Both pages still pass the existing sealed-record decoder and binding checks.
The pair buffer is dropped before payload streaming; exact payload hashing
reuses one page buffer instead of allocating it anew for every page. No cache
budget increase or change to SHA, zero-padding, semantic or fallback checks.
Backends without a batched override retain the ordered read_page fallback.

All 236 host tests pass with one ignored, including corrupt data/seals/padding
and device-read errors. QEMU three-boot file-tree/GC/cold-recovery/powered-off
verification and Duo release compilation pass. Two controlled boots from the
verified 128-file image produce mean scrub 10.544453 seconds, versus 11.652600
seconds previously (9.5% lower). Read bytes remain exactly 27,373,568, while
requests decrease from 4,663 to 4,221 (9.5%). This isolates a request-count
benefit under the existing 400 read-IOPS cap rather than reduced verification
coverage. Both subsequent object samples validate, and cold phases perform
zero writes/flushes. The measured phase sum is 11.991378 seconds.

Evidence: `target/storage-scrub-pair-read-20260912/` contains candidate/build
and source-restoration records, host/gate/Duo logs, retained gate evidence,
serial log, samples and analysis/comparison summaries. No builds or tests
overlap timed boots. These are sequential two-run QEMU comparisons; actual SD
request latency and throughput remain unmeasured.

### Return to steady object-write amplification (2026-09-12)

The current firmware (including scoped scrub memos, publication proof reuse
and adjacent metadata reads) completes two runs of 256 unique 4 KiB durable
put/get samples on fresh images. All 512 samples validate. The setup retains
the 128 MiB guest, 64-page block cache, single TCG hart and existing device
throttles. Per-sample block counters are identical to the earlier production
run in `target/storage-current-production-abba-20260912/after.jsonl`.

Each run reads 8,097,792 bytes / 1,565 requests and writes 53,694,464 bytes /
1,862 requests with 825 flushes. User payload is 1 MiB per run, giving 51.207x
host block-write amplification (not SD-internal NAND/FTL amplification).
Measured sample-latency sums are 11.573399 / 11.643028 seconds, median
29.274 / 29.2765 ms. These sums exclude shell/runner gaps, during which QEMU
throttle credit can replenish; they must not be converted into sustained
device throughput or compared directly with whole-run bandwidth limits.

Samples 206 and 234 coincide with two GC rounds each and take approximately
1.54 and 1.90 seconds in both runs. In the first run they consume 29.7% of
summed sample latency but only 3,252,224 of 53,694,464 written bytes. The
remaining 254 samples still write 50,442,240 bytes. Thus GC dominates the
largest observed latency spikes, while reducing total write amplification
requires attention to ordinary publication as well. Cold-recovery gains do
not establish a steady-write improvement; no such improvement is claimed.

Evidence: `target/storage-steady-current-20260912/` contains serial log,
512 JSONL samples, analysis/summary and attribution.json. No builds or tests
overlapped the timed runs. Production delta publication and its full memory
accounting/admission requirements remain open work.

### Experimental authority delta across growth (2026-09-12)

Add a host regression for the test-only authority delta prototype on the
growable fault-media device. Starting with eight admitted segments and twelve
available, publish a full authority base and a delta, grow by four segments,
power-cycle and cold-mount with the expanded parent range, then append another
delta without a warm predecessor witness. A second cold mount must reproduce
the complete encoded authority snapshot exactly and scrub Healthy.

The test checks that both appends physically contain VIBEAUL1, that growth
retains the original delta root rather than silently materializing a snapshot,
and that cold mount performs no mutations. It uses a governed runtime with
the same quota-policy admission as existing authority tests. All 237 host
tests pass with one ignored; evidence is in
`target/storage-delta-growth-20260912/host.log`.

This closes a successful-growth/context-change coverage gap only. It does not
qualify delta-specific power cuts during growth, full replay heap budgeting,
production format admission or real-device performance. No production delta
writer was enabled and no write-amplification improvement is claimed here.

### Experimental delta growth failure and cancellation matrix (2026-09-12)

Extend the growth regression across all 17 mutation boundaries of the actual
growth operation. At each boundary inject not-submitted failure, ambiguous
failure with no/visible/durable effect, and cancellation with no/visible/durable
effect: 119 cases. Every injected boundary must be reached, and the interrupted
store must require recovery. After power cycling and exposing the full parent
range, recovery must match the complete old or new StoreInfo state, retain the
delta root, and reconstruct the exact encoded authority snapshot. Cold mount
and scrub must leave the durable image unchanged and perform no mutations.

Every recovered case then publishes another experimental delta and cold-mounts
again, requiring exact successor authority bytes. This checks continued writer
usability after both old-state and new-state recovery, not just readability.
The full host suite passes 237 tests with one ignored; the matrix extends an
existing test. Evidence: `target/storage-delta-growth-cuts-20260912/` contains
the targeted boundary-count run and final host.log including resumed appends.

The fixture contains Format/IdHighWater authority records, so this matrix does
not establish live-object/grant behavior across growth cuts. The prototype is
still test-only; production admission, total replay heap accounting and real
SD measurements remain unfinished. No performance claim is made this turn.

### Live object and grant across delta growth cuts (2026-09-12)

Parameterize the experimental delta growth matrix and add a live fixture with
a distinct-pattern 4 KiB object, one root READ grant and governed quota policy.
Both metadata-only and live fixtures still cover 17 growth boundaries with
seven failure/cancellation effects, now 238 cases total. Every live case
checks exact authority reconstruction, the unchanged root grant, persistent
handle resolution, complete payload bytes and canonical logical/physical quota
usage after recovery. It then appends another delta, cold-recovers and repeats
the object/grant/quota checks. Recovery remains read-only and must select the
complete old or new growth state; scrub must be Healthy.

The live fixture physically publishes VIBEAUL1 before and after growth, so
the test does not accidentally qualify only full-snapshot fallback. A shared
host-test fixture helper derives the same object/grant records used by the
existing live delta GC test. All 238 host tests pass with one ignored. Evidence:
`target/storage-delta-growth-live-20260912/live.log` records the live matrix's
119 cases; host.log contains the full suite including the metadata matrix.

This closes the previously documented live-object growth-cut coverage gap
for this fixture. It does not enable production delta admission or establish
complete replay heap bounds, arbitrary graph coverage or SD performance.

### Single-buffer experimental delta envelope (2026-09-12)

Physical-link encoding previously allocated an inner delta Vec, then a second
Vec for the physical header plus a copy of that delta. The shared encoder now
accepts reserved prefix space and emits the payload directly after it. Link
encoding fills the prefix in place, eliminating the separately owned complete
inner payload and its copy. Raw codec encoding uses a zero-length prefix. The
physical-size saving/fallback decision still includes the link header.

A regression compares raw payload bytes against prefixed output and decoded
physical-link payload, checks zeroed reserved prefix bytes, exact no-saving
fallback and overflowing prefix rejection. Existing multi-extent, corruption,
publication/GC and live growth-cut tests pass. Replay additionally checks the
actual successor Vec capacity while predecessor and delta are still live,
instead of relying only on requested length for the overlap peak. An allocator
over-reservation is detected after allocation; this is not an allocator-level
hard cap. All 239 host tests pass with one ignored; evidence:
`target/storage-delta-single-buffer-20260912/host.log`.

This reduces an explicit encoder temporary allocation and strengthens owned
buffer accounting. Semantic decoder/preflight allocations and source scan
workspace remain outside that budget, so total replay heap bounds and
production delta admission are still incomplete. No QEMU/SD speedup is claimed.
