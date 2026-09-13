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

### Authority metadata-vector budget foundation (2026-09-12)

Snapshot decoding now preflights the combined in-memory object-binding,
principal-policy and external-root table sizes before allocating any table.
Each exact reservation subsequently checks actual Vec capacity against the
remaining table budget. Ordinary decoding retains its existing unrestricted
table budget; a test-only bounded validator returns the observed table bytes
without retaining a record-stream copy. Initial full-base validation during
experimental delta replay uses the remaining owned-buffer budget and records
the metadata overlap in its peak. Table-budget exhaustion maps to MemoryLimit.

The regression includes all three table types, exact-budget acceptance,
one-byte-less rejection, and a malformed first table item that proves the
budget preflight precedes table decoding. All 240 host tests pass with one
ignored. QEMU three-boot file-tree/GC/cold-recovery/powered-off verification
and Duo release compilation pass. Evidence:
`target/storage-authority-metadata-budget-20260912/` contains host/gate/Duo logs
and retained gate evidence.

This is a table-vector budget, not a total semantic heap bound. Per-link
snapshot validation, preflight maps/sets and device segment-scan workspace
still require accounting; allocator over-reservation is checked after it
occurs. Production delta admission remains disabled. No performance claim is
made for this budget change.

### Per-link authority metadata overlap budget (2026-09-12)

Experimental delta reconstruction now accepts the remaining owned-memory
budget for each link. It validates predecessor metadata within that budget,
checks successor output length before reservation, subtracts actual output
capacity before successor metadata allocation, and reports the larger of
predecessor metadata or simultaneous successor bytes plus metadata. Replay
adds this extra peak to its retained input buffers and ancestor/pending tables.
Canonical V2, SHA, sequence, observed-depth, pointer and generation checks are
unchanged; metadata exhaustion reports MemoryLimit.

The new direct link test compares exact reconstructed bytes, accepts the
measured overlap peak, rejects one byte less, and rejects a budget that covers
the output alone but not its simultaneous metadata. Existing 32-link replay,
large multi-extent, corruption and publication/GC/growth fault matrices pass.
All 241 host tests pass with one ignored. Evidence:
`target/storage-delta-link-metadata-budget-20260912/host.log`.

This extends metadata-vector accounting from the initial base to every link;
it does not yet count semantic preflight map/set allocations, source scan
workspace or allocator overhead. Production delta format admission remains
disabled, and no runtime performance improvement is claimed.

### Bound segment scan count before allocation (2026-09-12)

The production segment scanner previously reserved its extent vector from an
individually sealed summary's record_count before proving that count fits in
the segment. Individual summary decoding checked fields/checksums but not the
complete page accounting. Add a pre-allocation geometry check: each extent
requires two descriptor/seal pages and at least one payload page; their sum
must equal next_free_page minus DATA_FIRST_PAGE and stay within DATA_END_PAGE.
Impossible summaries now return Corrupt before sizing the extent allocation,
including arithmetic overflow. Subsequent complete chain validation remains.

An end-to-end scrub regression rewrites and reseals three summaries: a count
of u32::MAX - 1, too few payload pages, and inconsistent next_free_page. All
remain individually decodable but scrub rejects them as segment metadata
corruption without modifying media. All 242 host tests pass with one ignored;
QEMU three-boot file-tree/GC/cold-recovery/powered-off verification and Duo
compilation pass. Evidence: `target/storage-scan-geometry-bound-20260912/`.

This establishes a physical upper bound on the descriptor vector request and
closes a potential oversized allocation path. It does not yet charge valid
scan workspace against the whole recovery budget, nor does it establish a
performance improvement on healthy media. Production delta remains disabled.

### Shorten segment scan page-buffer lifetimes (2026-09-12)

VerifiedRecord owns decoded fields and body digests. Once summary and segment
seal decoding completes, the scanner now drops the four-page trailer buffer
before allocating/growing the extent proof vector. After the descriptor walk,
it drops the four-page header/descriptor window before interpreting requested
matches or inserting the proof into the memo. Later checks continue using the
owned decoded records, digests and accumulated descriptor/payload chains.

This removes 16 KiB of raw-page overlap during extent collection and another
16 KiB window during result construction; these phase-local savings must not
be added into a claimed fixed whole-operation peak reduction. Initial header
and trailer reads still overlap, and complete scan-budget integration remains
unfinished. No read requests, payload checks or format semantics change.

All 242 host tests pass with one ignored. QEMU three-boot file-tree/GC/cold
recovery/powered-off verification and Duo compilation pass. Evidence is in
`target/storage-scan-buffer-lifetime-20260912/`, including retained gate logs.
No timing or whole-heap measurement is claimed for this change.

### Stream metadata-only segment probes (2026-09-12)

An uncached ordinal-zero segment probe requests only verified aggregate
metadata, not an extent match. When it also requests no additional pointers,
authority siblings or authority-generation collection, the scanner now feeds
each decoded extent through the complete chain/geometry/statistics checks
without reserving or populating the extent proof Vec. Its resulting empty
extent list never enters a memo. Ordinary pointer lookup, authority collection
and any scan that populates a memo retain the existing full descriptor table.

This removes the count-dependent descriptor allocation from scrub's whole
segment probe, while still reading and validating every descriptor. Raw page
windows and all final summary/seal comparisons remain. It does not yet bound
the entire scrub/recovery heap or remove tables from authority pointer reads.
All 242 host tests pass with one ignored, including sealed impossible summary
counts and repeated media-corruption cases. QEMU three-boot file-tree/GC/cold
recovery/powered-off verification and Duo compilation pass. Evidence is under
`target/storage-streaming-segment-probe-20260912/`. No timing claim is made.

### Budget scrub segment-probe page workspace (2026-09-12)

The streaming, uncached ordinal-zero segment probe has two simultaneous
four-page I/O windows and no retained descriptor table. Scrub now admits its
32 KiB page workspace together with the mounted state before the first device
read. Predecessor verification additionally charges the current resident
state. Both passes contribute to the memory high-water mark; predecessor
verification does not duplicate the current publication's diagnostic counts.
Free segments require no probe workspace.

A boundary test rejects a budget one byte below the required peak with zero
I/O, then proves that the exact budget reaches an injected first-read failure.
All 243 host tests pass with one ignored, and Duo compilation passes. Evidence
is under `target/storage-scrub-probe-budget-20260912/`. This bounds the probe's
page buffers only, not the complete recovery heap, allocator overhead or
device-backend allocations. No timing improvement is claimed.

QEMU three-boot file-tree/GC/cold recovery and powered-off verification also
pass; the gate logs and JSON reports are retained in the same evidence folder.

### Omit recovery slot output during authority validation (2026-09-12)

`PreflightValidator` previously completed ordinary recovery, including a
`RecoveredSlot` Vec and the final ancestor/tombstone walk for each slot,
then immediately discarded that output. Its shared finish implementation now
omits just this output materialization in validation mode. All fallible graph,
rights, slot-generation and prior-tombstone checks still execute; public
`PreflightReplay::finish` continues to produce the complete recovered slots.
The partial internal result is private and validation exposes only its sequence.

A differential test covers all record prefixes of valid/invalid slot reuse,
missing parents, a parent without grant rights and a 64-slot journal. Exact
results, including errors, match full preflight recovery. This removes a
slot-count-dependent result allocation and final graph walks; it does not
bound the remaining semantic maps or enable experimental authority deltas.
QEMU three-boot file-tree/GC/cold recovery and powered-off verification and
Duo compilation pass. Evidence is in
`target/storage-validation-slot-output-20260912/`. No end-to-end latency or
SD-card performance improvement is claimed from this change.

The broader host run exposed three stale crash-recovery memory assertions
from before optional mount memo admission. They now distinguish cached peak
reservation, successful uncached fallback and mandatory uncached workspace.
Both dense and replay-merge fixtures must recover at the exact mandatory
peak and reject one byte less. All 13 crash-recovery tests pass after this
correction; the initial failed log is retained alongside the successful rerun.

All remaining fused-append, GC codec/recovery and steady-state integration
tests pass. Per-suite counts are retained in `test-summary.json`; the broad
run also passed all 243 segment-store unit tests (one ignored) and all durable
format tests, including the new semantic differential test.

### Reuse validated predecessors within experimental delta replay (2026-09-12)

Experimental replay previously validated the initial full snapshot and then
validated both predecessor and successor for every link. It now retains the
validated generation, record offset and canonical-version fact alongside the
owned immutable reconstructed bytes. A borrowed proof can only refer to those
bytes within this replay. Each successor still receives complete metadata and
record/graph validation, including the checks after recomputed payload digests.
Physical predecessor, depth, generation and both snapshot hashes remain checked.
Legacy V1 full bases remain readable but cannot become delta predecessors.

The maximum-depth test counts exactly 33 full snapshot validation passes for
32 links, replacing the former 65 calls. A new differential test compares
ordinary and proof-based link application for every truncation and single-byte
mutation, plus exact and one-byte-short workspace admission. The existing
base/link retention, successor metadata budget and crash/growth/GC tests remain.
This is test-only experimental code: production delta admission and total
semantic/source-workspace accounting remain incomplete. It does not change
on-media bytes or claim an end-to-end speedup. Evidence is under
`target/storage-delta-validation-reuse-20260912/`.

Final host verification passes all 244 segment-store unit tests (one ignored),
including experimental publication, GC and growth fault matrices. No QEMU
timing run was performed because the changed delta path is not production-enabled.

### Avoid copied V2 ID index for ordered authority bindings (2026-09-12)

Authority snapshot validation previously copied every V2 ObjectId to a Vec and
sorted it even when bindings were already strictly ordered by both stable and
V2 IDs. The validator now checks both orders in its binding pass. Strict V2
order proves uniqueness and permits external-root collision checks directly
against the binding slice. That path avoids the temporary ID Vec (16 bytes
requested per binding) and its sort. Non-monotonic V2 mappings remain supported
through the original copied/sorted index, including non-adjacent duplicates.

A test enumerates all 27 three-ID combinations and four external-root IDs per
combination, checking accepted permutations, duplicates, collisions and exact
encode/decode round trips. It also verifies that ordered and empty tables need
no fallback index. The fallback allocation and semantic replay maps are still
separate costs pending full budget accounting. No end-to-end timing or SD-card
speedup is claimed. Evidence is in
`target/storage-authority-binding-index-20260912/`.

All 245 segment-store unit tests pass (one ignored). QEMU three-boot file-tree,
GC, cold recovery and powered-off verification and Duo compilation also pass;
gate logs and independent verifier JSON are retained in the evidence folder.

### Current production cold-recovery recheck, 128 live files (2026-09-12)

Compared the preserved `storage-scrub-pair-read-20260912/candidate.elf` with
current production, using the same retained two-batch 128-file image and
64-page cache, 128 MiB guest, single-hart TCG, 4/2 MiB/s and 400/200 IOPS.
No compilation/tests overlapped timed runs. Ran control/current/current/control,
then the reverse order after the first comparison showed stage-dependent
latency variation. All eight cold recoveries and following object checks pass;
all measured cold phases perform zero writes and flushes.

Across four boots per build, control/current mount means are 1.422553/1.486454 s,
authority 0.006523/0.006407 s, scrub 10.608201/10.765774 s. Phase sums average
12.037276/12.258635 s: current is 1.84% slower in this sample, not a measured
end-to-end improvement. Per-boot sums span 11.926055–12.174586 s for control and
12.065189–12.498314 s for current; this does not isolate a particular code change.

Every boot has identical mount 576 reads / 3,641,344 bytes and scrub 4,221 reads /
27,373,568 bytes. Mount's reported peak remains 133,842 bytes (not whole-heap
measurement). Scrub latency is close to the 4,221 / 400 IOPS time, suggesting
request count is the useful next target. `verify_exact_payload_and_padding`
still reads payload pages individually; batching those reads warrants a
workspace-preserving experiment. No actual SD-card result is implied.
Evidence, source hashes, restored cache configuration, individual serial logs,
ABBA/reverse summaries and `comparison.json` are under
`target/storage-current-cold-128-20260912/`.

### Batch scrub payload verification in two-page reads (2026-09-12)

`verify_exact_payload_and_padding` now reads up to two adjacent payload pages
per device request. The final request is shortened at the extent boundary;
every byte still contributes to the SHA-256 or zero-padding check in order.
The buffer grows from one page to two, within the existing 8 KiB scrub streaming
workspace and below the already admitted segment-probe workspace. No extent
is skipped and no proof is reused across scrub invocations. This targets the
per-request limit observed in the 128-file QEMU cold-recovery fixture.
Evidence is in `target/storage-scrub-payload-pairs-20260912/`.

All 245 host unit tests pass (one ignored), along with QEMU three-boot file-tree,
GC, cold recovery, powered-off verification and Duo compilation. The preserved
pre-change current-production ELF is the control. In control/candidate/candidate/
control order with the same 128-file image, 64-page cache, 128 MiB RAM, single-hart
TCG and 4/2 MiB/s, 400/200 IOPS limits, scrub means are 10.543396 / 9.521581 s
(9.69% lower). Scrub reads fall from 4,221 to 3,811 (9.71% fewer); bytes remain
27,373,568 in every boot. All measured cold phases have zero writes/flushes and
all four post-boot object validations pass.

Phase sums average 12.137424 / 10.968381 s, but mount also fluctuated despite
identical 576 reads / 3,641,344 bytes and no mount-path change. Attribute the
result to the reproducible scrub request reduction rather than claiming the
mount timing difference as a benefit. Mount's reported peak remains 133,842
bytes; this is not an actual whole-heap measurement. Builds and tests finished
before timing. No actual SD-card speedup is established by this QEMU experiment.

### Rejected: reuse full-segment payload checks within scrub (2026-09-12)

A trial returned a private device/state-bound proof from the complete segment
pass, then omitted duplicate CAS manifest/extent payload-padding checks in the
content pass. Root/replay checks and all semantic/pointer/Merkle checks remained.
The trial passed 246 unit tests (one ignored), including identical-report and
fewer-logical-reads comparison, plus QEMU three-boot verification and Duo compile.

However, logical-read savings did not translate to physical I/O savings under
the production cache. A controlled ABBA comparison against the two-page-batch
baseline on the same 128-file image increased scrub requests from 3,811 to 4,008,
while bytes fell only from 27,373,568 to 27,369,472 (one page). The removed reads
appear to have served as useful batched cache prefetch ahead of semantic reads;
this is an inference from I/O counters, not a traced attribution. The trial was
rejected and production scrub restored to the exact pre-trial source hash. The
prior two-page batching optimization remains. Any future elimination of these
logical duplicate reads must preserve downstream physical read coalescing.

Trial sources, successful functional checks, ABBA logs, comparison and exact
restoration evidence are retained under `target/storage-scrub-payload-proof-20260912/`.

Measured scrub means were 9.520875 s baseline and 10.035747 s trial (+5.41%). No SD-card performance claim is made.

### Retain the header window during full CAS verification (2026-09-12)

`verify_blob` and scrub's `verify_manifest_blob` now use one invocation-local
read-ahead reader for both header authentication and the complete Merkle walk.
Previously the header used a demand reader and full verification created a
second reader, losing the header's page window. Complete validation still
checks descriptors, headers, every content leaf and all emitted tree hashes.
Range-reading policy is unchanged; only whole-Blob validation starts read-ahead
while reading the header. This does not reuse any observation across calls or
remove scrub's payload/padding checks.

The no-device-cache proof test now exercises both full-verification entry points
and requires every page of the first payload extent to be fetched exactly once,
for each existing large-object fixture. Evidence is in
`target/storage-cas-full-reader-reuse-20260912/`.

All 245 unit tests (one ignored), 12 CAS streaming integration tests, QEMU
three-boot file-tree/GC/cold recovery/powered-off verification and Duo compile
pass. A control/candidate/candidate/control measurement on the same 128-file
image, 64-page cache, 128 MiB single-hart TCG, 4/2 MiB/s and 400/200 IOPS yields
scrub means 9.546825 / 9.560049 s
(+0.14%). Both versions still have exactly 3,811 scrub
reads / 27,373,568 bytes and 576 mount reads / 3,641,344 bytes. All four cold
recoveries and subsequent object validations pass with zero cold writes/flushes.
No scrub speedup is established; cached physical I/O is unchanged. The benefit
proved here is removal of duplicate first-extent page fetches in the uncached
whole-Blob verification paths. Actual SD-card behavior remains unmeasured.

### Fuse scrub descriptor and payload scanning (2026-09-12)

The whole-segment scrub pass previously scanned all descriptor pairs for chain
and summary validation, then reread each pair to locate payloads for hash/padding
validation. A dedicated uncached scanner entry point now performs the payload
check immediately after validating each descriptor. It still compares final
counts, geometry, descriptor/payload chains and segment seal before success.
An extent's end is checked against the sealed summary and segment data boundary
before reading its payload. All ordinary scan callers remain metadata-only.
Full payload mode rejects memo/match/collection requests so it cannot accidentally
return success from a metadata-only cached proof.

The existing two-page hash/padding verifier is shared between the scanner and
scrub pointer checks; the duplicate descriptor pass is removed. Trailer buffers
are dropped before the loop, so the 16 KiB descriptor window overlaps only the
8 KiB payload window, below the already budgeted 32 KiB probe page workspace.
This is a page-buffer bound, not a claim about the complete recovery heap.
Evidence is in `target/storage-scrub-fused-scan-20260912/`.

All 245 unit tests pass (one ignored), including stale/retired payload and
padding corruption. QEMU three-boot file-tree/GC/cold recovery/powered-off
verification and Duo compilation pass. In control/candidate/candidate/control
order on the same 128-file image, 64-page cache, 128 MiB single-hart TCG,
4/2 MiB/s and 400/200 IOPS, scrub means are
9.623144 / 8.447482 s
(-12.22%). Requests fall from 3,811 to 3,376
(-11.41%), and bytes from 27,373,568 to 23,810,048
(-13.02%), identical across both boots per build.
All measured cold phases have zero writes/flushes; all four subsequent object
validations pass. Phase sums are 11.039985 / 9.893111 s.
Builds/tests completed before timing. This is a QEMU result, not a measured
SD-card performance claim.

### Independently verify retained delta checkpoints (2026-09-12)

The opt-in experimental region verifier now propagates delta admission into
`verify_v2_checkpoint_fallbacks`, so both retained checkpoints and their allocation
transition can be checked independently. The default remains disabled and the
normal CLI still does not admit experimental delta images. Four empty/live and
three multi-extent Rust-exported fixtures now verify both checkpoint copies,
including older delta predecessors. Default-denial checks cover fallback replay
as well as selected-tip replay; mutation and payload-budget checks remain.

This exposed an existing offline-verifier error: allocation-v1 conversion
incorrectly required the allocation carrier to have the first newly assigned
segment generation. The Rust multi-extent authority publisher may write payloads
into several new segments before the allocation record. The verifier now requires
the carrier's segment to be newly allocated and its generation to lie in the
exact newly consumed generation interval. Existing stale-carrier checks and new
old/future-generation cases still reject. The original failed multi-extent log
is retained; the fix does not bypass transition validation.

All seven fixtures pass (21 empty/live rejection cases; 29 multi-extent rejection
cases). The normal verifier passes all 25,134 selftest cases and independently
accepts the retained native 128-file image using the default CLI. Evidence is
in `target/storage-delta-fallback-verifier-20260912/`. This improves delta recovery
validation coverage and fixes a full-snapshot verifier false rejection; it does
not enable production delta writes or establish a performance improvement.

### Charge the temporary authority ID index to metadata budgets (2026-09-12)

Bounded snapshot decoding now accounts for the temporary sorted V2 ObjectId
index alongside all simultaneously retained metadata tables. The non-monotonic
path checks requested and actual reserved index capacity against the remaining
budget before populating/sorting it. Decoder metadata peaks propagate through
the existing base/per-link experimental delta buffer accounting. Ordered-ID
validation still uses the binding table directly and requests no index memory.

A boundary test requires exact table-plus-index admission, rejects one byte less,
checks the table-only budget for ordered mappings, and confirms duplicate IDs
remain invalid once index memory is admitted. All 246 unit tests (one ignored),
QEMU three-boot file-tree/GC/cold recovery/powered-off verification and Duo compile
pass. Evidence is in `target/storage-authority-index-budget-20260912/`.
This closes the metadata-index overlap only: semantic replay maps/sets and source
scan workspaces still need comprehensive accounting before production delta
admission. Ordinary public decoding retains its existing unbounded metadata
policy; no performance or total-heap claim is made for this budget correction.

### Compact retained transaction states during replay (2026-09-12)

Prepared grant/object states now live in boxes, keeping transaction-map values
small after commit. Finished transaction IDs remain retained to reject reuse;
transaction validation and recovery semantics are unchanged. This trades an
additional allocation per pending prepared state for smaller retained map nodes.

An isolated allocator measurement replays 2,048 sequential grant transactions.
Append-phase retained allocation falls from 1,064,272 to 645,392 bytes (39.36%);
peak requested allocation falls from 1,064,272 to 645,520 bytes. Input records are
allocated before measurement; finish-time graph materialization, stack, allocator
bookkeeping and RSS are excluded. This is not a complete recovery heap budget or
a timing/SD-card performance claim. Run the ignored integration measurement alone:
`cargo test -p vibeos-durable-format --test replay_memory -- --ignored --nocapture --test-threads=1`.

The full durable-format suite, 246 segment-store unit tests (one ignored), QEMU
three-boot file-tree/GC/cold recovery/powered-off verification and Duo compilation
pass. Before/after logs, source hashes and gate evidence are retained in
`target/storage-replay-compact-transactions-20260912/`.

### Share replay ID classification and consumption state (2026-09-12)

Replay now stores the object/derivation consumption bit alongside the existing
ID class, eliminating separate seen-object and seen-derivation BTreeSets. Merely
referencing an ID does not consume it. Later references preserve consumption,
and prepare/orphan-commit/external-object records retain their original
duplicate checks and error order. Class claims use a single entry lookup.

The isolated 2,048 sequential grant-transaction measurement drops retained
append-phase requested allocation from 645,392 to 586,400 bytes (9.14%), with
peak decreasing from 645,520 to 586,528 bytes. This comparison starts after the
boxed transaction-state change. It excludes input records, finish-time graph
materialization, stack and allocator overhead; neither whole-heap nor timing
improvement is claimed.

Full durable-format tests (including reference/consumption, cloning and class
collision checks), 246 segment-store unit tests (one ignored), QEMU three-boot
file-tree/GC/cold recovery/powered-off verification and Duo compilation pass.
Evidence and source hashes: `target/storage-replay-id-state-20260912/`.

### Recheck current replay changes under throttled cold recovery (2026-09-12)

Compare the retained fused-scrub firmware with current metadata-index budgeting,
boxed transaction states and shared ID consumption state. Eight sequential boots
run ABBA then BAAB using the same 128-file image, 64-page cache, 128 MiB
single-hart TCG and 4/2 MiB/s, 400/200 IOPS. Builds complete before timing.
All eight object samples validate; every measured cold phase has zero writes
and flushes. Both builds use 576 mount reads / 3,641,344 bytes and 3,376 scrub
reads / 23,810,048 bytes on every boot.

Control/current scrub means are 8.576423 / 8.447337 seconds, but the first
control boot takes 9.007072 seconds while the other control boots take about
8.432–8.434 seconds. Medians are 8.433200 / 8.445470 seconds. Mount medians
are 1.439916 / 1.439828 seconds. The mean difference does not establish a
repeatable speedup; retained allocation savings remain the supported benefit
of the replay changes. Further SD-oriented work should target physical I/O
and full authority publication writes. Evidence, source hashes, firmware,
per-boot samples and comparison: `target/storage-replay-current-cold-20260912/`.

### Discover scrub segment generation in the full header read (2026-09-12)

Full scrub scanning now obtains the segment generation from its authenticated
four-page header/first-descriptor read, eliminating the separate two-page
header pre-read. UUID, segment number, nonzero generation, next-generation
upper bound and checkpoint bound still validate before scanning descriptors.
Ordinary pointer-based scanning retains its exact generation match and memo
behavior; scrub remains uncached at the metadata-proof layer. Page workspace
budgeting is unchanged.

A no-device-cache regression verifies that each header page is read once and
that discovered generation at the exclusive upper bound and corrupt headers
reject. The original fixture failed because an empty formatted store had no
allocated data segment; the corrected fixture first publishes an object. The
failed log is retained. All 247 unit tests (one ignored), QEMU three-boot
file-tree/GC/cold recovery/powered-off verification and Duo compilation pass.

ABBA comparison against the immediately preceding replay firmware uses the
same 128-file image, 64-page cache, 128 MiB single-hart TCG, 4/2 MiB/s and
400/200 IOPS. Scrub requests fall from 3,376 to 3,369 on both candidate boots
(0.21%); bytes remain 23,810,048. Control/candidate mean scrub times are
8.504894 / 8.515483 seconds, so no latency improvement is claimed. Mount I/O
is unchanged. All four object samples pass and all cold phases have zero
writes/flushes. Builds/tests completed before timing. Evidence is retained in
`target/storage-scrub-header-single-read-20260912/`.

### Reject four-page full-scan payload batches (2026-09-12)

A trial increased only full-segment payload batches from two to four pages;
other pointer verifiers kept two pages. The 16 KiB descriptor plus 16 KiB
payload overlap stayed inside the existing 32 KiB probe page budget. Boundary
tests covered 1/3/4/5/8/9 pages, full/partial final pages, exact read coverage,
content hashes and nonzero padding rejection. All 248 trial unit tests (one
ignored), QEMU three-boot recovery/GC/offline checks and Duo compilation passed.

ABBA under the established 128-file, 64-page-cache, 128 MiB single-hart TCG,
4/2 MiB/s and 400/200 IOPS setup reduced scrub requests only from 3,369 to
3,365 (0.12%). Bytes stayed 23,810,048. Mean scrub times were 8.469257 /
8.408403 seconds; this small difference does not establish a repeatable
latency gain. All four object samples passed; all cold phases had zero writes
and flushes. Builds/tests completed before timing.

The trial is rejected: doubling the payload buffer for four fewer requests is
not compelling for memory-constrained targets. Production source and tests
were restored byte-for-byte to the preceding two-page implementation; trial
source, results and restoration hashes remain in
`target/storage-scrub-four-page-payload-20260912/`. No four-page optimization
is present in production.

### Initialize only the authority metadata prefix when encoding (2026-09-12)

The encoder reserves capacity for the entire output, zero-initializes only the
metadata prefix (including all reserved fields), then appends the canonical
record stream into the reserved suffix. Previously the full buffer was zeroed
before the record suffix was overwritten. This removes explicit initialization
of `record_stream.len()` bytes per full encoding without unsafe code or changing
encoded length, metadata-only encoding, capacity requirements or physical I/O.
No allocator-specific memory-bandwidth or end-to-end timing claim is made.

All 247 segment-store unit tests (one ignored), QEMU three-boot recovery/GC/
powered-off checks and Duo compilation pass. Newly exported empty/live delta
and materialized images are byte-identical to all four pre-change fixtures;
the independent verifier accepts them and rejects all 21 mutation/default-
admission cases. Fixture generation includes the live GC power-cut matrix.
The initial verification attempt lacked the separately generated live fixtures;
complete results are in `independent-final.log`. Evidence and source hashes:
`target/storage-authority-encode-prefix-20260912/`. This is an encoding-path
change, not a reduction of authority snapshot write amplification.

### Charge fixed source page buffers during experimental delta replay (2026-09-12)

Before each source read, replay subtracts the source-declared fixed page
workspace from its explicit remaining buffer budget. The reported peak includes
retained ancestors/payloads, newly returned payload capacity and those page
buffers. Device reads declare the existing 32 KiB segment-probe page workspace;
a one-time transfer of the already verified tip declares zero additional pages.
The page charge is conservative across sequential scan/payload-read phases.

A 32-link regression rejects payload-plus-pages minus one byte before calling
the source, validates exact reported-peak admission and rejects one byte less.
All 247 unit tests (one ignored), including experimental publication/GC/growth
fault matrices, pass. The initial full run exposed a test adapter that derived
its buffer allowance solely as three times a payload maximum. Test adapters now
explicitly add fixed source pages to that derived allowance; caller-supplied
ReplayLimits are never expanded. The original failure is retained. Evidence:
`target/storage-delta-source-pages-20260912/`.

This module remains test-only, so no production firmware behavior or timing
claim changes. Dynamic source descriptor tables, semantic replay structures,
external caches and allocator overhead are not covered by this fixed-page
charge; comprehensive heap admission remains unfinished before production
authority delta can be enabled.

### Reuse same-segment authority chain descriptor storage (2026-09-12)

Authority sibling collection reserves an additional slot for extent zero,
bounded by the authenticated segment's available descriptor count as well as
the declared chain count. The authority payload reader takes ownership of the
sibling vector and adds the first extent, avoiding a separate complete-chain
allocation/copy for same-segment chains with sufficient capacity. Oversized
sibling capacity falls back to an exact reservation; cross-segment collection
and final sorting/chain validation remain intact. Actual retained descriptor
capacity is checked against the existing descriptor allowance after reservation.

All 247 unit tests (one ignored), including multi-extent recovery and delta
publication/GC/growth fault matrices, pass. Final QEMU three-boot file-tree/GC/
cold recovery/powered-off verification and Duo compilation pass. Final logs and
source hashes are in `target/storage-authority-chain-reuse-20260912/`.
No device-I/O, write-amplification or end-to-end latency gain is claimed. This
reduces duplicate descriptor ownership but does not yet bound all simultaneous
dynamic source allocations or enable production authority deltas.

### Exercise descriptor allocation reuse during real cold recovery (2026-09-12)

A regression imports 3,001 authority sectors (about 1.5 MiB), drops the mounted
store and cold mounts it again. Test-only thread-local observations report one
read with same-segment siblings and one reuse preserving both the allocation
address and capacity. Recovered canonical snapshot bytes match the published
snapshot, and the complete sparse device image remains unchanged. The assertion
requires the optimized path to execute, rather than accepting a fixture that
only exercises single-extent authority.

The targeted test and full 248-unit suite (one ignored) pass. Evidence is in
`target/storage-authority-chain-evidence-20260912/`. These observations add no
production counters or behavior. They verify allocation reuse, not a complete
heap peak, reduced physical I/O or SD latency improvement.

### Reuse the observed digest for single-extent authority payloads (2026-09-12)

A single-extent authority read now compares its computed payload SHA-256 with
both the extent commitment and complete logical-payload root, avoiding a second
hash of identical bytes. Multi-extent reads still hash the full concatenation.
Descriptor storage is released before final whole-payload verification. Extent
count/length, chain validation and both digest commitments remain enforced.

All 248 unit tests (one ignored), QEMU three-boot recovery/GC/powered-off checks
and Duo compilation pass. An exact pre-change control and candidate were built
with only store.rs differing among the recorded production source hashes. ABBA
uses the established 128-file image, 64-page cache, 128 MiB single-hart TCG,
4/2 MiB/s and 400/200 IOPS; builds/tests completed before timing. All four object
samples pass and all cold phases have zero writes/flushes. Both versions have
576 mount requests / 3,641,344 bytes and 3,369 scrub requests / 23,810,048 bytes.
Control/candidate scrub means are 8.498607 / 8.414900 seconds, and mount means
1.439804 / 1.439496 seconds. The small timing difference is not established as
a repeatable latency gain; eliminated duplicate hashing is the retained change.
Evidence: `target/storage-authority-single-hash-20260912/`.

### Admit payload plus final authority descriptor-chain overlap (2026-09-12)

A bounded authority reader now accepts separate payload and payload-plus-chain
limits. Once the complete descriptor chain has been validated, it checks requested
payload length plus actual chain capacity before reserving the payload. Actual
returned capacity is checked again before filling it. The reader returns chain
capacity bytes to experimental delta replay, which charges them alongside retained
ancestors, the loaded payload and fixed source pages in its read-phase peak.
Payload quota and buffer quota are passed independently; verified-tip transfer
reports no additional descriptor chain. Existing ordinary callers use an unbounded
overlap allowance, preserving their payload-only policy.

The real 3,001-sector fixture reports 1,537,072 bytes of payload/chain overlap,
including 368 descriptor bytes. Exact overlap passes; one byte less and payload-
only allowance fail with MemoryLimit; the device image is unchanged. All 248
unit tests (one ignored), QEMU three-boot recovery/GC/powered-off verification
and Duo compilation pass. Initial compile failures from outdated test call
signatures are retained; final unit evidence is `segment-fixed.log`. Evidence:
`target/storage-authority-payload-overlap-20260912/`.

This closes only final-chain/payload overlap. Earlier segment-scan temporary
tables, caller-owned memo capacity, semantic replay structures and allocator
overhead remain outside this source constraint. No total-heap, performance or
production-delta-admission claim is made.

### Release discovery header pages before cross-segment authority scans (2026-09-12)

The cross-segment authority scanner previously retained its boxed two-page
discovery header while awaiting a full segment scan with four header/descriptor
and four trailer pages. Explicitly dropping the discovery pair before that
await prevents the extra 8 KiB page-buffer overlap. VerifiedRecord owns its
decoded header fields and digests, so subsequent generation/binding checks do
not borrow the released pages. This makes the source path consistent with the
previously charged 32 KiB fixed probe page workspace, rather than potentially
retaining 40 KiB of page buffers. Dynamic descriptor tables remain separate.

All 248 unit tests (one ignored), including multi-segment authority and delta
fault recovery, QEMU three-boot recovery/GC/powered-off checks and Duo compilation
pass. Evidence: `target/storage-authority-header-lifetime-20260912/`. This is
a source-lifetime correction supporting the fixed-page budget, not an observed
whole-heap peak measurement or an I/O/performance improvement claim.

### Bound retained segment descriptor tables before allocation (2026-09-12)

The segment scanner accepts a descriptor-table limit and checks the validated
summary record count times ExtentRecord size before reserving its retained
table, then checks actual capacity. Bounded authority reads supply their
remaining buffer allowance; cross-segment reads subtract the already retained
final-chain capacity first. Declared final-chain size is also checked against
the buffer limit before its reservation, with a post-reservation capacity check.
Ordinary scan callers retain their unbounded table policy. Existing memo-owned
proof storage remains an external cost.

A regression verifies that one-byte-short and arithmetic-overflow requests leave
the table capacity at zero, while exact capacity succeeds. All 249 unit tests
(one ignored), final QEMU three-boot recovery/GC/powered-off verification and
Duo compilation pass. Evidence: `target/storage-scan-descriptor-budget-20260912/`.
These checks bound the full scan table and final-chain reservations; overlapping
scan result lists, reallocation overlap, external memo capacity and semantic
replay still need aggregate accounting. They do not establish a total source
heap bound or enable production authority delta writes.

### Bound scan-table/result-list and result-reallocation overlap (2026-09-12)

Interpretation now receives the scan descriptor limit and charges actual
verified-table capacity together with additional-match and authority-sibling
result capacity. Result reservation checks retained tables plus existing result
capacity; growth conservatively admits old and requested new capacity together,
then checks the actual new capacity. Existing spare capacity remains charged.
Historical generations are filtered before reserving result space. The same
interpretation path handles fresh scans and memo hits; counting the referenced
proof table on a memo hit is conservative, not an external-cache ownership bound.

A boundary test verifies first-reservation failure with zero capacity, exact
admission, failure without capacity change at one byte below growth overlap,
and charging of existing spare capacity. All 250 unit tests (one ignored),
QEMU three-boot recovery/GC/powered-off verification and Duo compilation pass.
Evidence: `target/storage-scan-result-overlap-20260912/`. Final-chain takeover/
growth overlap, external memo aggregate ownership, semantic replay and complete
peak reporting remain to be checked before production delta admission. No
performance or total-heap claim is made by these local overlap checks.

### Bound final authority-chain growth and replacement overlap (2026-09-12)

Final-chain storage preparation now uses the same checked reservation path as
scan results. Taking a sibling allocation with enough space charges its existing
capacity only. Growing it admits old plus new capacity together. Replacing an
oversized sibling allocation charges the old list while the exact-size replacement
is created and filled; only then can the old list be released. Sorting and complete
chain validation remain unchanged.

A regression covers one-slot-to-two-slot growth (three slots of overlap),
four-slot-to-two-slot replacement (six slots of overlap), exact/one-byte-short
budgets and pointer-preserving two-slot reuse. All 251 unit tests (one ignored),
QEMU three-boot recovery/GC/powered-off verification and Duo compilation pass.
Evidence: `target/storage-authority-chain-overlap-20260912/`. Local reservations
are constrained; complete source-phase peak reporting, external memo aggregate
ownership and semantic replay budgeting remain unfinished. No production delta
admission or performance claim is made.

### Propagate source allocation phase peaks into delta replay (2026-09-12)

Checked result reservations now return their admitted peak, including old/new
capacity overlap. Segment interpretation reports table/result peaks; authority
chain preparation reports reuse/growth/replacement peaks. Cross-segment scans
add the caller's retained chain capacity. The authority reader returns the
maximum of these descriptor phases and final payload/chain overlap. Delta replay
combines this source peak with previously retained replay buffers and separately
reserved fixed pages, rejecting reports smaller than the returned payload or
exceeding the explicit budget. Verified-tip transfer reports just its capacity.

Tests assert reported chain reuse/growth/replacement peaks, retain the real
source exact/one-byte-short boundary, and verify nonzero spare scan capacity
is reported even without matching extents. All 252 unit tests (one ignored),
QEMU three-boot recovery/GC/powered-off checks and Duo compilation pass. Evidence:
`target/storage-source-peak-report-20260912/`. This reports conservative owned
source vector/payload peaks, not total recovery heap: aggregate external memo
ownership, semantic replay maps/sets, allocator overhead and stack are still
outside this accounting. Production authority delta remains disabled.

### Reserve the source memo growth allowance across delta replay (2026-09-12)

The experimental source declares its retained-buffer reservation. Device sources
reserve the supplied memo's complete bounded byte allowance, even when empty,
so later population remains covered. Replay includes that allowance in its
initial resident/peak count and all subsequent read, validation and rebuild
phases. Insufficient reservation rejects before any read. A test adapter taking
a payload maximum explicitly adds the memo allowance to its derived buffer
limit; explicitly supplied ReplayLimits are never increased.

Tests verify empty/populated memo reservation stability and a 32-link source
with both retained buffers and fixed read pages, including zero-read rejection,
reported-peak exact admission and one-byte-short failure. All 252 unit tests
(one ignored), including device delta recovery and publication/GC/growth fault
matrices, pass. Evidence: `target/storage-delta-memo-reservation-20260912/`.
This turn changes only test-enabled delta accounting/accessors, not production
firmware behavior. Reservation counts are conservative allowances, not measured
live heap. Semantic replay maps/sets, stack and allocator overhead remain outside
the accounting; production authority delta remains disabled.

### Borrow grant records while validating the recovery graph (2026-09-12)

Finish-time graph checks now build a map of references to committed grants
instead of cloning every RecoveredGrant into that temporary map. Validation-only
finish drops the borrowed graph after all fallible checks; complete recovery
materializes an owned graph for its public result. Tombstone traversal is shared
for owned and borrowed nodes. Parent rights/object checks and slot/revocation
history checks retain their original order. No borrowed graph escapes finish.

The isolated 2,048-grant allocator measurement now records finish peaks separately
from append peaks. Validation finish requested-allocation peak drops from
1,152,768 to 646,848 bytes (43.89%). Complete recovery finish peak drops from
1,283,840 to 1,091,056 bytes (15.02%); append retained/peak bytes are unchanged
at 586,400 / 586,528. Finish figures include replay state live at entry but
exclude input records, allocator bookkeeping, RSS and stack. These are measured
fixture results, not a hard semantic replay budget or SD latency claim.

Full durable-format tests, 252 segment-store unit tests (one ignored), QEMU
three-boot recovery/GC/powered-off checks and Duo compilation pass. Evidence,
source hashes and before/after measurements are in
`target/storage-validation-borrowed-graph-20260912/`.

### Omit committed object output during validation-only replay (2026-09-12)

PreflightValidator now omits the committed RecoveredObject output vector as
well as inline content. Full recovery retains both. Transaction completion,
object identity consumption, chunk lengths and content/commit CRC checks still
run before the optional output insertion. Mixed inline/external prefix tests
assert zero output-vector capacity while complete recovery returns both objects;
a repeated external object ID remains invalid.

An isolated 2,048-external-object fixture reduces validation retained and peak
requested allocation from 553,088 to 290,944 bytes (47.40%). Input records,
stack, allocator bookkeeping and RSS are excluded. The complete durable-format
suite, 252 segment-store unit tests (one ignored), QEMU three-boot recovery/GC/
powered-off verification and Duo compilation pass. Evidence and source hashes:
`target/storage-validation-object-output-20260912/`. This is a measured memory
reduction, not a semantic replay hard budget or a demonstrated SD latency gain.

### Omit tombstone transaction output during validation-only replay (2026-09-12)

Validation retains each derivation's earliest tombstone sequence for graph and
slot-history checks, but no longer builds the separate first-tombstone transaction
map used only by complete recovery output/rewriting. Stable transaction identity
consumption and duplicate checks remain in the transaction map. Full recovery
still records the first revoking transaction. The private output-retention flag
now covers both object and tombstone-transaction output.

Mixed-prefix tests include repeated revocation, assert an empty validation output
map and confirm complete recovery retains the earliest sequence/transaction.
For 2,048 tombstones, isolated retained and peak requested allocation drops from
523,200 to 393,472 bytes (24.79%). Input records, stack, allocator bookkeeping
and RSS are excluded. Full durable-format tests, 252 segment-store unit tests
(one ignored), QEMU three-boot recovery/GC/powered-off verification and Duo
compilation pass. Evidence: `target/storage-validation-tombstone-output-20260912/`.
This reduces retained validation state but does not yet enforce a complete
semantic replay heap budget or demonstrate SD latency improvement.


### Stream replay chain probes without a batch-sized array (2026-09-12)

Incremental replay now checks the chain during its existing decode pass, retaining
only the first chain error. It still decodes later sectors before returning that
error, preserving sealed-record error precedence and absolute sector offsets.
Semantic mutation starts only after the entire decode/chain pass succeeds. This
removes the temporary Vec<Option<ChainProbe>> without adding another decoding
pass. Both complete recovery and validation use this path.

An isolated batch of 65,536 empty sectors after a valid format record reduces
additional allocator-requested peak from 3,145,728 bytes to zero. This fixture
isolates the probe array; the existing completed-grant, external-object and
tombstone fixtures have unchanged peaks because their later semantic state
already dominates. A new 2,048-pending-grant fixture retains/peaks at 553,632
bytes before finish in both versions. Measurements exclude input records,
allocator bookkeeping, RSS and stack; they are not an SD latency result.

The kernel allocator's owner quota cannot by itself make semantic replay
fallible: quota rejection returns null, while BTreeMap insertion and Box::new
still use infallible allocation. Replacing these structures with explicitly
capacity-accounted fallible storage is required before claiming a complete hard
budget. Admission must include prepared transactions, retained identities,
committed grants, tombstone indexes, finish-time graph/slot storage and growth
overlap. Returning a budget error must poison the replay and prevent publication;
it must not silently discard unfinished transactions or identity history.
Production authority delta remains disabled.

Evidence: `target/storage-replay-streaming-probe-20260912/`. A regression covers
later sealed errors versus earlier chain errors, absolute offsets after a prior
append, and poisoned replay/validator behavior. Full durable-format tests and
252 segment-store unit tests (one ignored) pass.
QEMU three-boot recovery/GC/powered-off verification and Duo compilation also
pass; gate logs are retained alongside the allocation measurements.

### Fallible contiguous stable-ID index (2026-09-12)

Replay's append-only identity/class/consumption index now uses AVL nodes in one
Vec instead of BTreeMap nodes. Sorted, reverse and shuffled IDs retain logarithmic
lookup/insert depth, without relying on randomized hashes or standard-library
BTreeMap node layout. The same class-collision and identity-consumption checks
remain shared by complete recovery and validation; cloning preserves consumed
bits. No journal or authority payload bytes change.

New node capacity is reserved with try_reserve_exact before changing tree links.
The private insertion API admits an explicit node-buffer allowance, charging old
and replacement capacities during growth and allowing smaller growth near the
limit. Boundary tests cover exact admission, one-byte-short rejection, preserved
entries after rejection, all rotation shapes and 4,096 IDs in three orders.
Production callers currently pass an unrestricted allowance: this is a fallible,
capacity-accountable building block, not an enabled total semantic replay budget.
Cloning, transaction boxes/maps, output vectors and finish-time maps still need
separate treatment before that budget can be claimed. Allocator bookkeeping and
stack are outside node-buffer accounting; production authority delta stays off.

Isolated 2,048-entry allocation fixtures show these retained-byte changes:

| Fixture | Before | After | Reduction |
| --- | ---: | ---: | ---: |
| completed grants | 586,400 | 557,248 | 4.97% |
| external objects | 290,944 | 262,336 | 9.83% |
| pending grants | 553,632 | 524,480 | 5.27% |
| tombstones | 393,472 | 364,864 | 7.27% |

The completed-grant finish peaks are unchanged because the identity index is
released before graph construction. Input storage, allocator bookkeeping, RSS
and stack are excluded from these fixture measurements. Full durable-format
coverage, 252 segment-store unit tests (one ignored), QEMU three-boot recovery/
GC/powered-off verification and Duo compilation pass. Evidence and exact source
control/candidate builds: `target/storage-replay-fallible-ids-20260912/`.

Controlled 128-file cold-image ABBA runs (cache 64, 128 MiB, one hart, TCG single,
4/2 MiB/s and 400/200 IOPS limits) produce essentially unchanged phase sums:
9.8615335 s control versus 9.8617595 s candidate. Mount remains 576 reads /
3,641,344 bytes; scrub remains 3,369 reads / 23,810,048 bytes. All cold phases
report zero writes/flushes and all four object samples pass. This supports
retaining the memory/accounting change without claiming a latency improvement
or extrapolating to real SD hardware.

### Fallible transaction index and in-place completion (2026-09-12)

The contiguous AVL index is now generic over its value and also stores replay
transaction states. Keys remain permanently retained to reject transaction ID
reuse. Grant/object commits transfer the prepared value out with mem::replace,
leaving Finished in the same node; they no longer remove and reinsert map nodes.
Orphan grant commits still consume their stable transaction/derivation IDs, and
invalid or repeated commits still poison replay. Prepared object content is
transferred without cloning. Existing recovery and validator checks are shared.

Node growth remains fallible and capacity-accountable. A focused test confirms
that replacing an owned value returns the original contents with unchanged node
pointer/capacity even under zero growth allowance. Production node allowances
remain unrestricted; prepared-state boxes, cloning, other buffers and finish
indexes still need admission before a full semantic memory limit can be enabled.
Authority delta is still test-only.

For 2,048 completed grants, append allocation/reallocation calls decrease from
2,751 to 2,085 (24.21%). This includes prepared boxes and committed-vector growth,
not just index allocations. There is a retained-capacity tradeoff: the measured
completed, pending, external-object and tombstone fixtures each retain 2,896 more
bytes (0.5–1.1%) than the prior index implementation. Completed-grant retained
bytes are 557,248 -> 560,144; append peak is 557,376 -> 560,272. Finish peaks are
unchanged. Measurements exclude input storage, stack, allocator bookkeeping and
RSS, and do not establish SD latency or physical write amplification gains.

Full durable-format coverage, 252 segment-store unit tests (one ignored), QEMU
three-boot recovery/GC/powered-off verification and Duo compilation pass.
Evidence: `target/storage-replay-fallible-transactions-20260912/`.

Controlled cold-image ABBA (cache 64, 128 MiB, one hart, TCG single, 4/2 MiB/s
and 400/200 IOPS limits) yields phase sums of 9.8619760 s control
and 9.8601925 s candidate, effectively unchanged. Mount remains
576 requests / 3,641,344 bytes; scrub remains 3,369 / 23,810,048. All cold
phases have zero writes/flushes and all four object samples pass. Retain the
change for fallible node growth and fewer allocation calls, without claiming
a measured latency improvement or real-SD result.

### Return prepared-state allocation failures instead of aborting (2026-09-12)

Prepared grant/object boxes now allocate the same Layout through a small checked
helper and return RecoveryError::AllocationFailed on null. A successful allocation
is initialized before Box takes ownership; zero-sized values use allocation-free
Box construction. Replay also calls try_reserve before growing committed-grant,
committed-object and retained inline-content vectors. Any append error continues
to poison the builder, preventing publication of partially applied state.

A separate integration-test process uses thread-local allocator fault injection
to reject every allocation/reallocation in a mixed 32-grant, empty-object and
external-object append. All 45 complete-replay and 44 validation-only failure
points return AllocationFailed, and subsequent append/finish return ReplayPoisoned.
The sweep then reaches a successful append and finish. Thread-local injection
keeps test-harness allocations outside the failure window. This fixture explicitly
contains no ObjectChunk records: chunk decoding still constructs its own Vec,
and its failure handling is a remaining task, as are tombstone/finish maps and
cloning. No total semantic quota or production authority delta is enabled.

Isolated successful replay allocation measurements are unchanged from the prior
transaction-index change: 2,048 completed grants use 2,085 append allocation calls,
560,144 retained bytes and 560,272 peak bytes. This is failure-path work, not a
claim of lower SD latency or write amplification. Evidence:
`target/storage-replay-fallible-prepared-20260912/`.
Full durable-format coverage, 252 segment-store unit tests (one ignored), QEMU
three-boot recovery/GC/powered-off verification and Duo compilation pass.

### Borrow sealed inline chunks during replay (2026-09-12)

Both replay decoding passes now omit the temporary owned ObjectChunk.data Vec.
The private decoder still validates chunk length, zero padding, CRC, seal and
envelope exactly as the public decoder does; semantic replay borrows the checked
payload slice from the input sector for chunk/content CRC and optional output
copying. Public LogRecord::decode retains its original owned-data contract.
No borrowed content escapes append. Full recovery still retains object bytes;
validation retains only counters/digests.

For one 32 KiB inline object (92 chunks), append allocation calls decrease from
196 to 12 for complete replay and from 187 to 3 for validation: both avoid 184
short-lived chunk allocations across the two passes. Complete replay retained/
peak bytes stay 47,872 / 47,984. Validation retained bytes stay 1,280 and peak
drops from 1,752 to 1,392. Figures exclude input storage, stack, allocator
bookkeeping and RSS. These measurements do not establish SD latency or physical
write-amplification improvement.

Decoder parity tests cover valid lengths 1, 359 and 360 plus every byte position
mutated before and after refreshing CRC (3,072 mutation comparisons), asserting
the same decoded metadata/errors and zero internal chunk capacity. Allocation
fault injection now includes a 4 KiB nonempty inline object: all 51 complete-
replay and 45 validation append allocation points return AllocationFailed and
poison subsequent append/finish. A successful recovery also checks exact content.
Tombstone and finish indexes, cloning and total semantic admission remain work
items; authority delta remains test-only. Evidence:
`target/storage-replay-borrowed-chunks-20260912/`.
Full durable-format coverage, 252 segment-store unit tests (one ignored), QEMU
three-boot recovery/GC/powered-off verification and Duo compilation pass.

### Fallible tombstone indexes (2026-09-12)

Replay and recovered-preflight tombstone sequence/transaction indexes now use
capacity-accountable AVL storage. Repeated revocations preserve the earliest
sequence and original transaction; validation still omits the transaction-only
output index. Retaining the indexes in RecoveryPreflight avoids re-materializing
BTreeMaps at finish. Read-only lookup shares the same index search as updates.

Index iteration follows insertion order. Compaction events still sort by record
sequence, and the public recovered tombstone vector explicitly sorts by ID to
preserve its prior ordering. A regression covers out-of-order and duplicate
revocations; existing rewrite/equivalence and earliest-tombstone tests pass.

The 2,048-tombstone validation fixture reduces append allocation calls from 367
to 40, with a capacity tradeoff: retained/peak bytes increase from 367,760 to
397,856 (8.18%). These requested-allocation figures exclude input storage, stack,
allocator bookkeeping and RSS. Keep the change for fallible admission building
blocks and fewer allocator calls, not as a memory reduction or measured SD
latency improvement. Production allowances are not yet bounded globally.

Fault injection includes 32 reverse-ordered orphan tombstones and a repeat:
all 58 complete-replay and 50 validation append allocation failures return
AllocationFailed and poison append/finish. Successful recovery still verifies
inline content. Finish graph/slot indexes, cloning and total semantic admission
remain outstanding; production authority delta remains disabled. Evidence:
`target/storage-replay-fallible-tombstones-20260912/`.
Full durable-format coverage, 252 segment-store unit tests (one ignored), QEMU
three-boot recovery/GC/powered-off verification and Duo compilation pass.

### Index committed grants by position and make finish growth fallible (2026-09-12)

The recovery graph now maps derivation IDs to positions in the immutable
committed-grant vector. Complete RecoveryPreflight keeps that index instead of
cloning every grant into a second owned graph; validation drops it after checks.
Parent lookups only see previously inserted grants, preserving missing-parent,
rights and object-kind error order. Compaction and root selection use the same
indexed vector. Applying root policy computes fallible liveness flags before
consuming/compacting that vector, so positions cannot become stale mid-traversal.

ReplayIndex now accepts copyable ordered keys as well as u128 IDs. Finish's
object-kind and compound (space, slot) indexes use fallible node growth; output
slots reserve fallibly and sort by (space, slot), preserving public order.
Graph/slot/ancestor checks still run in their original commit order. A regression
covers slots inserted out of order across spaces.

For 2,048 completed grants, builder finish requested-allocation peak decreases
from 1,091,056 to 779,648 bytes (28.54%). Validation finish peak increases slightly
from 646,848 to 648,576 bytes (0.27%). Append retained/peak bytes and calls remain
560,144 / 560,272 and 2,085. These fixture measurements include replay state live
at finish entry but exclude input storage, stack, allocator bookkeeping and RSS;
they are not a whole-system or real-SD latency measurement.

The mixed grant/inline-object/tombstone fault fixture now sweeps finish as well:
all six complete-builder and five validator finish allocation points return
AllocationFailed. The 58/50 append failure points still poison replay. Public
root-policy finalization, arbitrary cloning/rewriting and a coordinated total
semantic byte allowance are not covered by that finish sweep. Production
allowances remain unrestricted and authority delta remains test-only. Evidence:
`target/storage-replay-fallible-finish-20260912/`.
Full durable-format coverage, 252 segment-store unit tests (one ignored), QEMU
three-boot recovery/GC/powered-off verification and Duo compilation pass.

Fixed-image cold ABBA (cache 64, 128 MiB, one hart, TCG single, 4/2 MiB/s
and 400/200 IOPS limits) yields phase sums 9.8617495 s control
and 9.8618190 s candidate, effectively unchanged. Mount retains
576 reads / 3,641,344 bytes, scrub 3,369 / 23,810,048; all cold phases report
zero writes/flushes and all four object samples pass. No latency improvement
is claimed from this comparison.

### Share index capacity admission across replay phases (2026-09-12)

A replay-local requested-capacity ledger now spans ID, transaction, tombstone,
graph, object-kind and slot indexes. Index growth charges the replacement while
all other retained indexes and the old capacity remain charged, then releases
the old capacity. Allocation failure rolls back the reserved charge. Finish
releases append-only and temporary index charges when their buffers are dropped.
The ledger itself allocates no heap storage.

A shared-index boundary test admits two retained 16-node indexes plus a minimum
17-node replacement at exactly 49 node sizes and rejects one byte less before
mutation. It also checks that another index stays readable and releasing indexes
returns usage to zero. A 64-byte validator index allowance rejects append and
poisons append/finish. Builder clones reconcile the ledger against actual Vec
capacities before the next append/finish, since cloning may shrink spare capacity;
a regression verifies reconciliation and successful independent finish.

This limit is deliberately private and index-only. Production constructors still
use an unrestricted allowance. Prepared boxes, committed/output vectors, inline
content, allocator bookkeeping and stack are outside this ledger; it must not
be presented as the complete semantic heap budget. Clone allocations themselves
are not admitted by the ledger. Production authority delta remains disabled.

All existing 58/50 append and 6/5 finish allocation-failure points still reject
safely. Successful 2,048-grant measurements remain 2,085 append calls, 560,144 /
560,272 retained/peak bytes, and 779,648 / 648,576 complete/validation finish peaks.
There is no newly demonstrated latency or SD I/O improvement in this step.
Evidence: `target/storage-replay-shared-index-budget-20260912/`.
Full durable-format coverage, 252 segment-store unit tests (one ignored), QEMU
three-boot recovery/GC/powered-off verification and Duo compilation pass.

### Bound validation's requested semantic allocation capacity (2026-09-12)

PreflightValidator::with_memory_limit now applies one allowance across append
and finish to all validation-owned indexes, prepared grant/object boxes and the
committed-grant vector. Growth admits replacement capacity while old buffers
remain charged; committed transactions and finish release prepared-box charges.
Validation borrows chunk input and omits content/object/tombstone-transaction/
slot output, so those output allocations are absent from the limited path.
Normal PreflightReplay remains unrestricted and its recovery output, cloning
and root-policy finalization are not covered by this validation-only contract.

memory_usage returns retained/peak accounted bytes for an unpoisoned validator;
finish_with_memory_usage returns the validated sequence, zero retained bytes and
the conservative requested-capacity peak after dropping all validation state.
Allocation/admission failure returns AllocationFailed; failed append poisons all
subsequent operations, including usage queries. The allowance excludes input
sectors, stack and allocator bookkeeping/RSS. It is not a whole-heap/device quota.

A mixed grant/inline/external-object/tombstone fixture scans 286 allowances:
13 succeed and 273 reject. The unrestricted reference retains 14,784 bytes with
an 18,240-byte admitted peak; that peak succeeds as an explicit limit. Batches
of 1, 3 and 17 records also succeed within it. Zero allowance accepts a format-only
journal. Box and vector tests cover exact admission and one-byte-short rejection,
including another retained buffer and old/new vector overlap. All 58/50 append
and 6/5 finish injected allocator-failure points continue to fail closed.

Independent allocator measurements now assert that ledger-retained bytes equal
actual requested live bytes for completed/pending grants, external objects,
inline validation and tombstones. Successful fixture allocation counts and peaks
are unchanged: 2,048 grants use 2,085 append allocations, 560,144 / 560,272 retained/
peak bytes and 779,648 / 648,576 complete/validation finish peaks. There is no new
SD latency or physical-I/O claim. Authority delta is still disabled: its enclosing
payload/metadata/source budget must pass the remaining allowance into this API
and account for the reported semantic peak before production admission.
Evidence: `target/storage-validator-memory-limit-20260912/`.
Full durable-format coverage, 252 segment-store unit tests (one ignored), QEMU
three-boot recovery/GC/powered-off verification and Duo compilation pass.

### Include semantic validation in authority delta admission (2026-09-12)

Delta's base and successor validation now receive the workspace allowance left
after resident source/payload/reconstruction buffers. Snapshot decoding first
charges retained metadata tables, then gives the remainder to PreflightValidator.
The returned workspace peak is retained metadata plus the larger of semantic
replay and temporary binding-ID index peaks; these scratch phases do not overlap.
The delta reader adds that workspace to resident buffers and propagates semantic
AllocationFailed as its Memory error. Physical pointer/hash/depth checks remain.

Strict snapshot-sector inspection now uses an allocation-free LogRecord API
that validates canonical bodies/seals/envelopes and returns store/sequence only.
It rejects empty/torn sectors and preserves sealed-record error precedence without
allocating temporary inline chunk Vecs outside the semantic budget. Public owned
decoding remains unchanged. Mutation parity and allocator-denial tests cover this
inspection path, including inline records.

A 4 KiB inline-object successor has 8,832 output bytes and 1,392 semantic workspace
bytes: reconstruction reports 10,224 extra bytes. Output-only allowance rejects;
the reported combined peak succeeds and reproduces exact canonical bytes. Another
assertion exercises the outer reader with loaded base and ancestor table still
resident, checking their sum with semantic peak and refusal when no semantic
allowance remains. An unordered metadata fixture checks metadata + max(semantic,
ID-index) and sealed-error precedence under insufficient semantic space.

All 254 segment-store unit tests (one ignored), durable-format coverage, QEMU
three-boot recovery/GC/powered-off verification and Duo compilation pass.
Evidence: `target/storage-delta-semantic-budget-20260912/`. This is requested
buffer/workspace-capacity admission, not allocator bookkeeping, stack or total
process memory. Authority delta remains test-only pending production admission
review; no new SD latency or write-amplification measurement is claimed here.

### Honor the checkpoint caller's remaining delta allowance (2026-09-12)

The experimental checkpoint bridge previously treated recovery's remaining byte
allowance as a payload maximum, expanding it to three payloads plus source pages
and memo reservation. It now passes that exact allowance as the replay buffer
limit. Pages, memo, metadata and semantic state must fit inside it. Standalone
writer/device test adapters still have their documented derived allowances and
are not production admission paths.

The bridge also returns its transient peak; mount adds the pre-existing resident
state and observes the total in recovery_peak. This prevents delta reconstruction
workspace from disappearing from recovery telemetry after only the resulting
snapshot remains. The source's verified-tip reuse remains intact.

A regression checks zero/small/maximum allowance preservation. A 1,152-byte
snapshot cannot replay with only 1,152 bytes available; its measured covered peak
is 1,248 bytes, which succeeds as the exact allowance. All 255 segment-store unit
tests (one ignored) pass. Fresh empty/live delta and GC-materialized images pass
the independent offline verifier and its 21 rejection cases. Evidence:
`target/storage-delta-checkpoint-budget-20260912/`. This turn changes test-enabled
checkpoint integration only; the production format gate remains closed.

The admission review identified remaining work before enabling production:
normal post-replay snapshot decoding still uses a retained-record/table capacity
estimate and an unrestricted semantic decoder; it should use the bounded decoder
with observed workspace. Publication's cold-read adapter still derives a larger
allowance and maps replay failures too broadly. Offline admission is explicitly
opt-in and must be coordinated with any writer/reader feature rollout. Existing
fault/GC proofs do not by themselves resolve these integration conditions.

### Bound owned authority decoding during cold recovery (2026-09-12)

Production VIBEAUT2 recovery now passes its remaining allowance to the owned
snapshot decoder, charging the input buffer and existing recovery state
separately. The decoder admits retained metadata, semantic/index scratch and the
final record-stream copy, and mount observes their peak overlap. The existing
final snapshot/root capacity preflight remains in place. Record copying now uses
fallible reservation instead of an unchecked allocation.

Memory admission/allocation failures have a distinct MemoryLimit error; fixed
format bounds remain OutOfBounds and mount treats them as corruption. The
experimental delta validator uses the same distinction. Tests cover an oversized
principal count, record-copy admission one byte below its requirement, semantic
workspace overlap and successful smaller index reservations under a tight budget.
One fixture retains 1,640 bytes but uses 2,152 bytes at unconstrained decode peak;
with a 1,640-byte allowance it successfully limits that peak to 1,640 bytes.

All 257 segment-store unit tests pass (one ignored). QEMU three-boot recovery,
GC pressure and powered-off verification pass, as does Duo firmware compilation
(no real-device execution). Evidence is in
`target/storage-bounded-authority-decode-20260912/`. These figures count requested
buffer capacity, excluding caller-owned input, stack and allocator bookkeeping;
they do not describe total heap/RSS or establish a latency improvement. Authority
delta remains test-only. Writer cold-read budget integration and coordinated
production/offline admission remain outstanding before enabling it.

### Honor cold writer replay allowance and preserve errors (2026-09-12)

The experimental authority publisher's cold path no longer expands the supplied
replay allowance to three payloads plus fixed source pages. It now shares the
checkpoint reader's exact allowance conversion, including source/reconstruction
workspace within that limit. The parameter is explicitly named cold_replay_bytes:
this does not yet bound caller-owned mounted state, the successor snapshot or the
subsequent encoding phase. The standalone device fixture adapter still accepts a
payload bound and derives a larger workspace allowance.

Cold replay now preserves source device errors and maps workspace exhaustion to
MemoryLimit, keeping corrupt bytes classified as Corrupt. Codec allocation errors
are likewise preserved through the publisher. A regression exercises zero and
snapshot-only allowances, injected device read failure, corrupted predecessor
media, and exact warm/cold output equality. A valid warm provenance witness works
with zero cold-read allowance against a device that refuses every read. All these
encoding attempts leave media unchanged.

All 258 segment-store unit tests pass (one ignored). Fresh full/delta and
GC-materialized empty/live images pass independent offline verification and its
21 rejection cases. Evidence: `target/storage-delta-writer-cold-budget-20260912/`.
These edits are test-only and do not change the QEMU production firmware, so no
new firmware latency or SD write-amplification result is claimed. Production delta
admission is still closed: the full writer encoding/ownership budget and the
coordinated writer/reader/offline format rollout remain to be completed.

### Bound authority encoding and release predecessor metadata earlier (2026-09-12)

The shared full/metadata snapshot encoder now reserves output fallibly and offers
an explicit requested-capacity allowance. Its peak is max(structural ID-index
scratch, output capacity): structural validation finishes and drops scratch before
output allocation. The public production encoder retains its existing unlimited
API but allocation failure now returns MemoryLimit rather than using infallible
Vec::with_capacity. Canonical output bytes are unchanged.

Experimental delta encoding now offers a bounded variant that includes both
metadata encoders' scratch/capacities and final output overlap. Once the old
metadata digest is computed, that buffer is dropped before delta output is
allocated. The physical-link fixture's former simultaneous capacity was 1,280
bytes; the new covered peak is 1,152 bytes (10% lower). Without the physical header,
it is 1,152 to 1,024 bytes. Exact peak allowances succeed and peak minus one fails
for these fixtures. Reconstruction produces the same successor bytes. These small
fixture values are not a bound on arbitrary workloads or total process RSS.

All 260 segment-store unit tests pass (one ignored). An isolated allocator-fault
integration test denies the production output allocation and observes MemoryLimit;
retry returns the original independently constructed canonical fixture. QEMU
three-boot recovery/GC/powered-off verification and Duo compilation pass. Fresh
empty/live delta and GC-materialized fixtures pass independent offline validation
and its 21 rejection cases. Evidence: `target/storage-authority-encode-budget-20260912/`.

The bounded encoder primitives are available, but the experimental publisher has
not yet combined mounted input ownership, cold decode, encoding and publication
into one writer budget; its existing encoding wrapper remains unlimited. Authority
delta stays test-only pending that integration and coordinated format admission.
No SD throughput, latency or additional write-amplification gain is claimed here.

### Integrate one encoder workspace allowance across delta paths (2026-09-12)

The experimental writer now applies its workspace allowance beyond cold replay.
Warm provenance validation uses bounded metadata encoding; warm physical-link
encoding and full-snapshot fallback use the bounded encoders. Cold link selection
charges reconstructed byte capacity and retained ancestor capacity before owned
snapshot decoding. It then subtracts the decoded snapshot's actual capacity
before canonical metadata comparison and link encoding. Canonical comparison
still checks exact bytes and releases its metadata before encoding the output.
A full-snapshot fallback releases the recovered predecessor before allocating its
replacement. Device errors and memory/corruption classification remain distinct.

A cold fixture retains 1,248 replay bytes/ancestor bytes plus a 1,024-byte decoded
snapshot and needs 1,152 bytes of encoding workspace, for a covered peak of 3,424
bytes. The exact combined allowance succeeds; resident-only, resident+decoded,
and peak-minus-one allowances refuse. The warm path now correctly refuses zero
and output-only workspace even with a valid witness. Full-snapshot warm fallback
succeeds at exact output size and refuses one byte less. Warm encoding still
makes no reads and produces the same bytes as cold encoding.

All 261 segment-store unit tests pass (one ignored). Fresh empty/live delta and
GC-materialized images pass the independent offline verifier and its 21 rejection
cases. Evidence: `target/storage-delta-encode-integration-20260912/`. This change is
within test-only authority delta; the production firmware was not changed and no
new QEMU timing/SD performance claim is made.

This is an encoder-owned workspace limit, not a total writer heap limit. The
publisher still owns the mounted state, a cloned publication state, and the next
snapshot outside this allowance; publication buffers and installation of the new
witness also require admission. MountedState::resident_heap_bytes is available to
account for the mounted snapshot, and cloning can be delayed until after encoding.
Those caller ownership/publication phases plus coordinated format rollout remain
before production delta admission. The production gate stays closed.

### Charge caller snapshot residency and defer the publication clone (2026-09-12)

Experimental delta publication now borrows the mounted state throughout encoding
instead of cloning it before replay begins. It subtracts the mounted state's
tracked resident capacities and the next snapshot's actual capacities from the
allowance passed to the encoder. After encoding, it checks the tracked overlap of
both input snapshots, output capacity and publication clone before creating that
clone. The original next snapshot is dropped after publication and before the new
provenance witness is built.

A 33-record predecessor fixture defers 16,956 tracked bytes of state cloning
until after encoding a 960-byte delta. This removes that clone from the encoder's
live buffers; it is not a measured reduction in the whole publication peak.
Regression cases deny admission below input residency, with no workspace left,
and when encoding fits but its output plus the clone does not. They check zero
mutations, unchanged durable media/generation, no poisoned store, cleared witness,
and successful retry after restoring the normal allowance.

All 262 segment-store unit tests pass (one ignored). Fresh empty/live delta and
GC-materialized images pass independent offline verification and 21 rejection
cases. Evidence: `target/storage-delta-caller-budget-20260912/`. These changes are
inside the experimental test-only publisher; production QEMU firmware is unchanged.

The existing resident_heap_bytes accounting covers the Vec-backed mounted tables;
it excludes runtime BTreeSet proof nodes, other store caches, allocator bookkeeping
and stack. Clone reservation is still an estimate using tracked capacities, not
fallible admission for every underlying allocation. Publication itself additionally
allocates free-segment lists, successor allocation state/encoding, framed payloads
and mounted successor state; those phases and witness construction remain to be
integrated before production authority delta admission. No new SD performance or
write-amplification result is claimed.

### Prepare publication descriptors before mutation and release verified bytes (2026-09-12)

Production authority publication now reserves the exact number of payload
descriptors: authority extent count plus allocation and optional empty catalog.
The old fixed reservation of three could trigger infallible Vec growth after
SegmentBuilder had started writing a multi-extent publication. Both payload and
readback descriptor tables are now reserved fallibly and assembled/admitted as
appropriate before quota installation, clearing mounted state or beginning I/O.
The readback table uses the same exact descriptor count instead of count+3.

After checkpoint durability and staged payload verification, the publisher drops
both descriptor tables, physical pointers, encoded authority bytes, allocation
bytes and optional catalog bytes before constructing roots and cloning successor
state. No reader needs those buffers afterward. The successor still records whether
an empty CAS catalog was published via a saved boolean. On-media framing, write
order, checkpoint barrier and readback validation remain unchanged.

All 262 segment-store unit tests pass (one ignored), including publication and GC
mutation/cancellation fault cases and multi-extent authority cases. QEMU three-boot
file-tree recovery/GC/powered-off verification and Duo compilation pass. Evidence:
`target/storage-publication-buffer-lifetime-20260912/`. There is no new latency or
whole-operation peak-memory measurement. Readback descriptors are now resident
earlier during writes; the large encoded payloads are released earlier during
successor installation. Authority delta remains test-only, and complete publication
allocation admission is still outstanding.

### Measure publication allocations; reject naive mid-batch draining (2026-09-12)

A new isolated host probe, `authority_publication_memory`, uses a preallocated
page device so media writes do not allocate BTreeMap nodes. It imports format and
high-water records with no object payloads at 32, 2,048 and 4,096 records. The input
journal, import and device are prepared before the baseline. It measures extra
live allocator-requested bytes, allocation/reallocation calls, I/O-boundary live
bytes, written pages, write requests and flushes. Each case cold-mounts and compares
the exact recovered record stream. Run alone:

```sh
cargo test -p vibeos-segment-store --test authority_publication_memory -- --ignored --nocapture --test-threads=1
```

The preceding descriptor/lifetime change did **not** lower whole-operation peak.
For 32/2,048/4,096 records, control extra peaks were 199,280/2,358,648/4,480,704
bytes; the current implementation reports 199,640/2,358,952/4,481,216. Large cases
save one allocation, with identical page I/O and flush counts. Earlier descriptor
reservation shifts a few hundred bytes into the peak; earlier payload release
helps a later phase that did not set this maximum. The change retains its
pre-mutation allocation benefit, but is not claimed as a peak-memory improvement.

Inspection found SegmentBuilder checks its 64-page drain threshold only after a
whole payload batch is staged. A trial draining during payload fill reduced peak
but split coalesced header/descriptor/payload writes:

| Journal records | Current extra peak | Trial extra peak | Current/trial allocations | Current/trial write requests |
| --- | ---: | ---: | ---: | ---: |
| 32 | 199,640 | 199,640 | 93 / 93 | 6 / 6 |
| 2,048 | 2,358,952 | 2,131,564 | 357 / 374 | 14 / 17 |
| 4,096 | 4,481,216 | 4,229,708 | 619 / 659 | 22 / 27 |

Written pages stay 23/277/535 and flushes stay four in all cases. The trial passed
262 storage unit tests, but was **reverted**: a 9.6%/5.6% peak saving came with
21.4%/22.7% more write requests, an undesirable unmeasured SD latency tradeoff.
A better streaming design should retain contiguous header/descriptor/payload
coalescing and the checkpoint durability protocol. The production writer is back
to its prior batching behavior. No QEMU timing or real SD result is claimed.

Evidence: `target/storage-publication-allocation-measure-20260912/`. Control and
candidate measurements were repeated; final restored measurements confirm original
request counts. This is requested live allocation accounting, excluding baseline
storage, allocator bookkeeping, stack and transient allocator-internal realloc
copies. The synthetic authority-only workload is not an object-store throughput
benchmark. Authority delta remains test-only.

### Stream deferred records in physical order without extra write requests (2026-09-12)

The deferred-barrier sink path now stages the header, each descriptor body/seal,
and its payload in physical record order, draining at 64 queued pages while
filling the batch. Previously the sink eventually sorted this same set of pages
into physical order, but had to retain the entire batch first. Simply draining
payloads earlier split descriptor/header runs (the rejected preceding trial).
Ordered staging preserves coalescing in the measured publication cases. The
non-deferred path retains its original payload/body/seal barrier phases.

Drains issue writes only, with the same 32-page/128-KiB request ceiling and no
extra flush. A complete segment summary/checkpoint still must be published before
these pages are admissible. The 64-page threshold bounds this staging loop, not
all caller-owned buffers or the temporary contiguous drain buffer.

Repeated host publication allocation results against the preceding implementation:

| Journal records | Prior extra peak bytes | Ordered extra peak bytes | Write requests, both | Flushes, both |
| --- | ---: | ---: | ---: | ---: |
| 32 | 199,640 | 199,640 | 6 | 4 |
| 2,048 (1 MiB journal) | 2,358,952 | 2,131,564 | 14 | 4 |
| 4,096 (2 MiB journal) | 4,481,216 | 4,229,708 | 22 | 4 |

The large cases reduce whole-operation extra requested-live peaks by 9.6% and
5.6%; page reads/writes are unchanged. Allocation calls rise from 357/619 to
374/659 because each bounded drain recreates its small tables/run buffer. These
are memory/request measurements, not an SD throughput or latency result, and do
not imply request-count equivalence for every possible caller page ordering.

A dedicated regression compares exact page bytes and request grouping with an
independently assembled full sink across multiple extents, including partial-page
padding. Injected failures on writes one/three and cancellation on write three
stop at the corresponding reference prefix without flushes or subsequent writes.
All 263 unit tests pass (one ignored). The c74 publication, CAS streaming, crash
recovery, fused append and GC recovery integration suites pass 64 tests. QEMU
three-boot recovery/GC/powered-off verification and Duo compilation pass. Evidence:
`target/storage-ordered-sink-20260912/`; the earlier control is in
`target/storage-publication-allocation-measure-20260912/`. This production change
is retained. Authority delta remains test-only and SD hardware validation remains
outstanding under the user's QEMU-first instruction.

### Reuse entry capacity across bounded sink drains (2026-09-12)

Bounded deferred drains now retain the small PageSink entry Vec rather than
recreating it after every 64 staged pages. The draining iterator removes owned
pages while preserving that Vec's capacity. The public consuming drain uses the
same implementation, dropping capacity at final consumption. The contiguous
32-page write buffer remains temporary rather than retaining another 128 KiB
between fills.

The iterator is created before reserving the contiguous run, so any subsequent
allocation error, write failure or cancelled future drops all remaining queued
pages. Tests now explicitly require an empty queue and retained table capacity
after injected failure/cancellation, in addition to exact write-prefix/content
comparison. Retaining capacity must never retain pending writes for accidental
replay. The injected cases cover write failure/cancellation; a separate allocation
fault injection for this private drain was not added.

Repeated host publication measurements show allocation calls for 32/2,048/4,096
records of 93/355/620, compared with 93/374/659 before table reuse and 93/357/619
before bounded streaming. Extra requested-live peaks stay 199,640/2,131,564/4,229,708
bytes. Write requests stay 6/14/22, pages written 23/277/535, and flushes four.
Thus the preceding peak savings are retained while most extra allocation calls
are removed. These measurements do not establish SD throughput or latency gains.

All 263 unit tests pass (one ignored), CAS streaming/GC integration suites pass
36 tests, and QEMU three-boot recovery/GC/powered-off verification and Duo
compilation pass. Evidence: `target/storage-sink-table-reuse-20260912/`. Authority
delta remains test-only; the overall storage/SD performance goal is still active.

### QEMU ABBA check of ordered streaming and table reuse (2026-09-12)

Compared the pre-ordered-streaming PageSink against current ordered streaming plus
entry-table reuse, keeping every other current source unchanged. Each ELF used
the same temporary 64-page cache override, 128 MiB guest, one-hart single-thread
TCG and a fresh clone of the same zero-filled disk. Both source overrides were
restored and SHA-256 checked after building. Runs were serial with no overlapping
build/test load, in control/candidate/candidate/control order, seed 71, one 64 MiB
file-sequential write/read/remove workload per boot, no warmup. The backend was
limited to 4 MiB/s reads, 2 MiB/s writes, 400 read IOPS and 200 write IOPS.

| Order | Version | Workload seconds | Write requests | Read requests | Flushes |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Control | 51.545480 | 783 | 1,457 | 32 |
| 2 | Candidate | 51.666502 | 788 | 1,457 | 32 |
| 3 | Candidate | 51.626074 | 788 | 1,457 | 32 |
| 4 | Control | 51.510825 | 783 | 1,457 | 32 |

Mean times are 51.528153 s control and 51.646288 s candidate (+0.229%). Every run
writes 71,430,144 bytes and reads 72,392,704 bytes, for host-block write amplification
of 1.064392 against 64 MiB of file data. That write-amplification level belongs to
the full current stack; this change does not reduce it. All normalized records
validate successfully and the workload's content readback succeeds.

The host authority-only probe's identical request counts did not generalize to
this file workload. The five extra writes occur entirely in the stage phase:
771 to 776 writes, unchanged 71,118,848 written bytes and 26 flushes. Mean staging
time rises from 34.838956 to 34.948774 s. Publish/verify/remove request counts are
unchanged. This is a concrete request-coalescing regression to investigate at
bounded-drain boundaries. It is not evidence of a throughput improvement; two
samples per version are insufficient for broad statistical or SD-hardware claims.

Evidence: `target/storage-ordered-sink-qemu-20260912/` contains reproducible build,
run and analysis scripts, source/ELF identities, raw UART logs, validated JSONL and
`summary.json`. Current source was left restored with ordered streaming/table
reuse retained for its measured memory benefit, with the additional file-stage
requests explicitly outstanding. Authority delta remains test-only. No real SD
benchmark or Linux/ext4 re-comparison was performed in this experiment.

### Retain incomplete physical tails across bounded drains (2026-09-12)

Threshold drains now keep the incomplete suffix of the final contiguous physical
run (at most 31 pages), rather than writing a short request that the next payload
could extend. Complete preceding runs are submitted; final consuming drains still
write every page. Selection follows physical continuity, not simply a page-count
suffix across gaps. Stable sorting/latest-page selection remains in place.

A guard clears both the selected prefix and retained suffix unless the drain
finishes successfully. It is installed before run allocation; dropping a pending
future or returning a write error cannot leave stale tail pages for replay. A new
gap-bearing test stages three isolated pages plus a 61-page run, retains 29 pages,
then extends them into a full 32-page request. Error/cancellation cases explicitly
check an empty queue and no writes after the stopping request.

All 264 unit tests (one ignored), 36 CAS streaming/GC integration tests, QEMU
three-boot recovery/GC/powered-off verification and Duo compilation pass. Host
allocation measurements remain 199,640/2,131,564/4,229,708 extra peak bytes and
93/355/620 allocation calls for 32/2,048/4,096 records. Evidence:
`target/storage-sink-tail-20260912/`.

Repeated the preceding 64 MiB file-sequential QEMU ABBA experiment with the same
seed 71, blank template, 128 MiB guest, 64-page cache, single-hart single-thread
TCG, 4/2 MiB/s read/write limits and 400/200 read/write IOPS. Only the tail policy
and its guard differ between these builds. No concurrent build/test load ran
during timing, and source overrides were restored and hash-checked.

| Order | Version | Seconds | Write requests |
| --- | --- | ---: | ---: |
| 1 | Control, drain entire queue | 51.712115 | 788 |
| 2 | Candidate, retain tail | 51.659862 | 783 |
| 3 | Candidate, retain tail | 51.651019 | 783 |
| 4 | Control, drain entire queue | 51.616087 | 788 |

Both candidates eliminate exactly five stage-phase write requests (776 to 771),
restoring the 783 total writes observed before ordered streaming. All other I/O
is unchanged: 1,457 reads, 32 flushes, 71,430,144 written bytes and 72,392,704 read
bytes. Write amplification remains 1.064392, not an improvement from this change.
Mean time is 51.664101 s control versus 51.655441 s candidate (-0.0168%); this is
not evidence of a meaningful latency gain. The proven result is removal of the
request-coalescing regression while retaining bounded staging and its measured
memory savings. All four records validate and content verification succeeds.

Benchmark evidence: `target/storage-sink-tail-qemu-20260912/`, including source/ELF
identities, build/run/analysis scripts, raw UART logs, JSONL and `summary.json`.
The change is retained in production code. Authority delta remains test-only;
actual SD throughput/latency and the broader storage performance goal remain
unresolved.

### Borrow single-extent bytes for full small-object verification (2026-09-12)

Small verified reads previously held resolved extent payloads, a second contiguous
copy of the complete encoded envelope, and decoded output. After checking every
extent's identity, offset and length, the single-extent path now borrows its
already-owned payload directly for BlobView decoding and complete Merkle
verification. Multi-extent input still assembles a contiguous buffer. Logical
output remains independently owned; no validation is skipped and no borrowed
bytes escape the call. The existing conservative batched-read limit is unchanged.

The allocation harness now also exercises public read_persistent_object after
importing a rooted object. Its preallocated device, prepared input and mounted
state are outside the baseline. Read output is checked byte-for-byte, and writes
and flushes must remain zero. Run this probe alone:

```sh
cargo test -p vibeos-segment-store --test authority_publication_memory persistent_object_read_requested_allocation -- --ignored --nocapture --test-threads=1
```

| Object bytes | Prior extra peak | Borrowed extra peak | Prior/new allocation calls | Read pages, both |
| --- | ---: | ---: | ---: | ---: |
| 4,096 | 37,808 | 37,808 | 15 / 14 | 11 |
| 65,536 | 204,072 | 137,416 | 15 / 14 | 26 |
| 131,072 | 402,728 | 269,512 | 15 / 14 | 42 |
| 368,640 | 1,129,144 | 1,129,144 | 20 / 20 | 106 |

The 64/128 KiB cases reduce extra requested-live peaks by about one third. The
4 KiB case saves a copy/allocation without lowering its earlier peak; the 360 KiB
multi-extent case is unchanged. These are after-import host measurements, not
cold-device latency, total RSS or SD throughput. Existing proof/manifest state is
identical on both sides; firmware code was restored after the control measurement.

All 264 storage unit tests pass (one ignored), including full-object corruption
checks; 12 CAS streaming integration tests pass. QEMU three-boot recovery/GC/
powered-off verification and Duo compilation pass. Evidence:
`target/storage-small-verified-borrow-20260912/`. Production keeps this change;
authority delta remains test-only and the broader SD performance work continues.

### Consume resolved extents before allocating verified output (2026-09-12)

The small verified-read path now moves the single extent's encoded Vec directly,
and consumes multiple resolved extents while concatenating their payloads. Extent
identity/offset/length checks still finish before this step. Complete BlobView
and Merkle verification still precede independently owned logical output. This
releases resolved payloads and their descriptor table before allocating output;
the conservative batching limit remains unchanged.

Controlled host measurements against the preceding single-extent borrowing change:

| Object bytes | Previous extra peak | Consuming extra peak | Allocation calls, both | Read pages, both |
| --- | ---: | ---: | ---: | ---: |
| 4,096 | 37,808 | 37,808 | 14 | 11 |
| 65,536 | 137,416 | 137,120 | 14 | 26 |
| 131,072 | 269,512 | 269,216 | 14 | 42 |
| 368,640 | 1,129,144 | 760,504 | 20 | 106 |

The 360 KiB case reduces additional requested-live allocation peak by 32.6%.
The encoding reserve still temporarily overlaps all input payloads; this does
not remove every overlapping buffer or reduce the number of allocations. These
measurements use the existing after-import, preallocated-device probe, exclude
resident mounted state from baseline, and are not RSS or SD latency measurements.
No reads were eliminated; writes and flushes remain zero.

Validation: 264 unit tests pass (one ignored), 12 CAS streaming integration tests
pass, including existing complete-object corruption checks in the unit suite.
QEMU three-boot recovery/GC/powered-off verification and Duo compilation pass.
The controlled source swap was restored and verified. Evidence, source snapshots,
allocation logs and QEMU logs: `target/storage-verified-owned-20260912/`.
No timed performance comparison or real SD run was performed for this change.
Authority delta remains test-only; the broader storage performance work continues.

### Prepare the experimental successor witness before publication (2026-09-12)

The test-only delta writer previously encoded successor metadata without a
workspace limit after the checkpoint had already been published and verified.
That allocation could fail after durable success and was classified as corruption.
It now prepares a fixed-size generation/digest value before delta encoding or
media mutation, using the recovery budget remaining after the mounted state and
input snapshot's tracked allocations. Encoder scratch and metadata are released
before delta encoding, so their workspaces do not overlap the delta output.

After successful publication/read-back, preparation binds the actual physical
root, store and generation into the cache without heap allocation. Preparation
alone is not a verified-base witness. Binding checks the published generation
and depth; the caller must publish the exact prepared snapshot. Existing cached
writer crash/cancellation tests continue to check that failures discard the cache.
The unlimited from_published helper remains only for already-published test
fixtures; the experimental writer no longer calls it.

A new boundary regression uses a 1,152-byte canonical snapshot with empty tables:
128 bytes of metadata workspace succeeds, 127 and zero return MemoryLimit, and
the prepared digest equals SHA-256 of the complete canonical snapshot. The caller
regression also rejects binding a successor preparation to predecessor state;
its budget refusals leave mutation count zero, old generation/media unchanged,
store unpoisoned and cache absent, and a restored budget permits retry.

Validation: 265 unit tests pass (one ignored), including both cached/uncached
publication cut and cancellation suites; freshly exported delta fixtures pass
the offline verifier's four regions and 21 rejection cases. Evidence:
`target/storage-delta-witness-admission-20260912/`.

This removes one memory-admission gap on the path toward lower-write-amplification
authority publication. It does not change production I/O or establish latency
savings. Full publication-buffer accounting, fallible state cloning/runtime
proof allocation, and coordinated format rollout remain unresolved. Delta remains
cfg(test); no firmware or QEMU timing change is claimed for this test-only step.

### Stream authority view digests over the existing record buffer (2026-09-12)

Production build_persistent_view previously encoded the complete authority
snapshot into a temporary Vec solely to hash it. It now encodes only canonical
metadata (whose lengths still describe the full snapshot), then updates SHA-256
with that prefix and the existing record stream. This preserves the exact
canonical digest and structural validation while removing the temporary log copy.
No on-media format, publication barrier or authority-delta enablement changes.

The isolated host allocation probe now counts gross allocator-requested bytes:
alloc requests add their requested size and realloc requests add their new size.
This is allocation traffic, not simultaneous residency or physical memory usage.
Preparation/device storage and cold recovery are outside the measured import.
Both control and candidate also compare the view digest with cold recovery.

| Log records | Previous requested bytes | Streaming requested bytes | Saved | Extra live peak, both |
| --- | ---: | ---: | ---: | ---: |
| 32 | 471,432 | 455,048 | 16,384 | 199,640 |
| 2,048 | 6,167,584 | 5,119,008 | 1,048,576 | 2,131,564 |
| 4,096 | 11,961,016 | 9,863,864 | 2,097,152 | 4,229,708 |

Allocation counts remain 93/355/620. Read pages remain 31/285/543; written pages
23/277/535, write requests 6/14/22, and flushes four in every case. The saving is
exactly one log-stream copy per view construction. The whole-operation peak is
unchanged because it occurs earlier; no latency or SD throughput gain is claimed.

Validation: 266 unit tests pass (one ignored), including a new digest comparison
against complete canonical bytes with object/principal tables, changed generation,
external roots and invalid metadata rejection. The controlled allocation probes,
QEMU three-boot recovery/GC/powered-off verification and Duo compilation pass.
Source overrides were restored and verified; removal of the now-unused SHA import
was the only cleanup after the firmware build. Evidence:
`target/storage-view-streaming-digest-20260912/`.

The remaining post-publication root/state allocations still need attention;
this change does not claim to complete publication memory admission. Delta stays
test-only, and ordinary authority snapshot write amplification remains open.

### Recheck current production small-object writes in QEMU (2026-09-12)

An ABBA comparison runs the saved production ELF from
`storage-current-production-abba-20260912/candidate.elf` against a freshly built
current worktree ELF. This is an aggregate comparison of intervening changes,
not isolated attribution to the view digest or any individual memory change.
Each fresh image runs 256 unique 4 KiB durable put/get samples, seed 32, with a
128 MiB guest, 64-page cache, one TCG hart and read/write limits of 4/2 MiB/s and
400/200 IOPS. No builds or tests overlapped the timed runs. All 1,024 samples
validate; the temporary cache override was restored and its hash checked.

| Order | Version | Sum of sample seconds | Median ms | Write requests |
| --- | --- | ---: | ---: | ---: |
| A1 | Saved production | 12.279777 | 32.2335 | 1,862 |
| B1 | Current | 13.111390 | 36.8445 | 1,857 |
| B2 | Current | 13.127196 | 36.6940 | 1,857 |
| A2 | Saved production | 13.081828 | 36.6230 | 1,862 |

Means are 12.6808025 versus 13.119293 seconds (+3.46%). However, the same control
binary varies by 6.53% between its two runs; this evidence does not establish a
speedup or a stable regression. Sums exclude command/runner gaps, including the
guest's pre-command quiet interval, during which throttle credit can replenish;
do not interpret these sums as sustained throughput.

Every run reads 8,097,792 bytes in 1,565 requests, writes 53,694,464 bytes and
flushes 825 times. Write amplification remains 51.207x relative to 1 MiB of user
payload. Per-sample counters agree within each version. Cross-version differences
are confined to samples 206 and 234, the known GC episodes: current firmware
saves three and two write requests respectively, with no byte or flush change.
Their combined latency stays about 3.45 seconds. Ordinary publications retain
exactly the previous I/O counts.

Every get phase performs zero device reads: this workload measures cached get
and durable put, not cold object-read performance. Current put time accounts for
13.071096/13.086988 seconds; get for only 0.040294/0.040208 seconds. Consequently,
recent read-memory improvements cannot be evaluated as cold-read gains here.

Evidence: `target/storage-current-small-qemu-20260912/` contains build/run/analysis
scripts, source and ELF identities, raw UART logs, validated JSONL, summary and
per-sample attribution. The result redirects performance work to ordinary full
authority publication/write amplification; allocation savings alone have not
established a steady-write latency benefit. Authority delta remains test-only,
and actual SD measurement remains pending under the user's QEMU-first scope.

### Prepare authority roots before publication mutation (2026-09-12)

publish_persistent_snapshot previously collected object roots, extended the Vec
with external roots and validated their combined set after publishing and reading
back the checkpoint. It now checks the combined table's requested size against
the recovery-memory limit, reserves the exact combined count fallibly, sorts by
physical object ID and validates PersistentRootSet before quota installation,
poisoning or media writes. A root allocation/validation failure cannot leave this
publication durably committed but reported as failed. The root set is retained
and moved into the verified successor after publication.

This admission checks the root table alone, not the sum of all live publication
buffers. Earlier root preparation overlaps roots with the write buffers; snapshot,
catalog/CAS cloning and other finalization allocations still require attention.
No format, I/O ordering, barrier or production-delta enablement changes are made.

New regressions verify exact combined-root budget and physical ordering across
object/external roots, one-byte-short MemoryLimit, and invalid generation refusal.
A rooted publication under a one-entry-minus-one-byte budget performs zero
mutations, preserves the durable image and mounted generation, stays unpoisoned,
and succeeds after restoring its budget; its object remains readable.

The allocation probe now also reports the preceding rooted import. Controlled
measurements for 4/64/128/360 KiB objects have identical additional requested-live
peaks of 344,232 / 687,840 / 1,158,560 / 2,926,512 bytes, and identical allocation
counts 172 / 225 / 281 / 407. Subsequent read measurements also remain unchanged.
These one-root fixtures do not prove unchanged peak for arbitrarily large root
tables. This is publication-admission work, not a latency or write-volume gain.

Validation: 268 unit tests pass (one ignored), including existing publication
power-cut/cancellation coverage; QEMU three-boot recovery/GC/powered-off image
verification and Duo compilation pass. Source overrides were restored and
verified. Evidence: `target/storage-root-preparation-20260912/`.
Full authority snapshot write amplification and complete delta admission remain
open; delta stays test-only.

### Reuse standalone authority encoding for the installed successor (2026-09-12)

The standalone authority publisher previously cloned the successor snapshot after
checkpoint publication/read-back. It now prepares its object/principal/external
root tables with fallible, bounded reservations before mutation. A private prepared
value owns the exact encoded Vec throughout publication. After successful read-back,
it repurposes that buffer for the installed record stream if its capacity suffices.
Otherwise, as for a short experimental delta, it reserves the complete log capacity
before publication. Finalization copies the source log into already-reserved space;
it performs no allocation. This saves allocation traffic, not the final log copy.

The preparation budget covers additional successor tables/fallback log plus the
prepared root table. It does not account for every caller, builder, catalog/CAS
clone or runtime proof allocation; full publication admission remains incomplete.
Reused full-encoding capacity includes metadata slack, so mounted residency can
increase slightly. The final mounted-state capacity check still runs.

Controlled standalone import measurements (preallocated host device):

| Records | Requested bytes before / after | Allocation calls before / after | Extra peak before / after |
| --- | ---: | ---: | ---: |
| 32 | 455,048 / 438,664 | 93 / 92 | 199,640 / 199,696 |
| 2,048 | 5,119,008 / 4,070,432 | 355 / 354 | 2,131,564 / 2,131,620 |
| 4,096 | 9,863,864 / 7,766,712 | 620 / 619 | 4,229,708 / 4,229,764 |

Each case removes one log-sized allocation. Earlier table preparation adds 56 bytes
to the observed peak; retained live allocation at return adds 192 bytes from encoded
metadata capacity. Read pages remain 31/285/543, written pages 23/277/535, write
requests 6/14/22 and flushes four. Rooted object-import probe counts/peaks are
unchanged: that fused publication path does not use this helper. These results
must not be generalized to every put, reduced media write amplification or SD
latency improvements.

New tests compare the complete successor snapshot, prove reuse by exact buffer
address/capacity, and prove the short-buffer fallback reserves before finalization.
One-byte-short table/fallback budgets return MemoryLimit. The publisher regression
also confirms successor-table refusal leaves zero mutations, unchanged durable
media/generation, an unpoisoned store and successful retry after budget restoration.

Validation: 269 unit tests pass (one ignored), including cached/uncached experimental
delta crash/cancellation cases. QEMU three-boot recovery/GC/powered-off verification
and Duo compilation pass; fresh delta fixtures pass all 21 offline rejection cases.
Controlled source overrides were restored and verified. Evidence:
`target/storage-successor-buffer-reuse-20260912/`.
Production authority delta stays disabled. Fused publication, its full admission,
and ordinary full-snapshot write amplification remain the next major work.

### Move fused authority state into the verified successor (2026-09-12)

Both single-object and batch CAS commit functions now own the optional fused
authority publication instead of borrowing it. Encoding is borrowed only for
record construction/write/read-back; afterwards its Vec is released and the
already-owned authority snapshot and root set are moved into the successor.
Previously both were cloned after publication, while the originals remained
owned by the outer caller. Non-fused commits retain their existing predecessor
state-clone behavior. Validation, conditional read-back policy, checkpoint order
and durable format remain unchanged.

The rooted-import probe exercises this production path. Gross requested bytes
count allocator requests, not simultaneous residency, RSS or physical SD writes:

| Object bytes | Allocations before / after | Requested bytes before / after | Extra live peak, both |
| --- | ---: | ---: | ---: |
| 4,096 | 172 / 168 | 823,976 / 814,624 | 344,232 |
| 65,536 | 225 / 221 | 1,730,920 / 1,634,016 | 687,840 |
| 131,072 | 281 / 277 | 2,835,816 / 2,645,728 | 1,158,560 |
| 368,640 | 407 / 403 | 5,891,344 / 5,363,848 | 2,926,512 |

All four save four allocations; the 360 KiB case saves 527,496 requested bytes.
Overall peaks occur elsewhere and do not decrease. Read pages remain
43/79/118/264, written pages 35/71/110/256, write requests 8/9/10/19, and flushes
four for each fresh import. Subsequent verified read results/metrics and standalone
authority publication probes are unchanged. This fresh rooted-import workload is
not identical to the steady QEMU unrooted put/get sequence; no latency or media
write-amplification improvement is inferred from these allocation results.

Validation: 269 unit tests pass (one ignored), plus 43 integrations across CAS
streaming, the 128 KiB fused reproduction, fused append recovery and GC recovery.
Existing mutation-boundary, cancellation, cold-recovery and damaged-write checks
remain green. QEMU three-boot recovery/GC/powered-off verification and Duo
compilation pass. Controlled source swaps were restored and verified. Evidence:
`target/storage-fused-owned-state-20260912/`.

This removes one complete successor clone in the ordinary fused path. The caller's
view snapshot and other predecessor/catalog clones remain, as does the full
authority payload write. Production authority delta remains disabled.

### Release redundant staged predecessor states (2026-09-12)

StagedObjectCommit now carries an optional, private predecessor. The standalone
fused publisher takes it instead of cloning the entire mounted state. Entries
added to a batch release the temporary writer predecessor immediately; duplicate
entries never construct it. The batch already owns the exact base and current
planning state used for publication, so retaining a copy per entry was redundant.
The store remains poisoned between staging and publication/remount as before.

A new mixed-duplicate regression stages 16 objects, checks that every queued entry
has released its predecessor, publishes and verifies all contents, then cold-mounts
and checks 16 mappings / 8 blobs. Existing failure/cancellation/GC coverage passes.
This removes a per-entry retained state; it does not remove the temporary planning
clone needed while each writer stages its payload or the batch's shared base.

The host probe now covers fresh import and append against seeded authority history.
The seeded case first publishes 258 records (format, initial high-water, then 256
additional high-water records), drops the seed view and uses the public append
writer with its principal. Seed preparation is outside the measured interval.
Repeated import was initially rejected as AlreadyInitialized; the corrected probe
uses append for initialized state, preserving the API's transition rules.

| Appended object bytes | Previous extra peak | New extra peak | Allocation calls before / after |
| --- | ---: | ---: | ---: |
| 4,096 | 997,724 | 865,568 | 222 / 219 |
| 65,536 | 1,407,836 | 1,275,680 | 274 / 271 |
| 131,072 | 1,847,132 | 1,714,976 | 330 / 327 |
| 368,640 | 3,453,884 | 3,321,728 | 448 / 445 |

Each seeded case reduces extra requested-live peak and gross requested allocation
by 132,156 bytes (13.2% peak reduction for 4 KiB). Fresh imports save just the empty
predecessor's four-byte allocation bitmap and one allocation: their predecessor
has no authority history. This contrast is why the seeded measurement matters.
No claim about peak RSS, maximum batch size or SD latency follows from this probe.

Seeded read pages remain 68/104/143/296, written pages 64/106/145/292, write requests
11/16/17/24 and flushes four. Fresh-import and subsequent read I/O also match their
controls. No media write amplification reduction is claimed.

Validation: 270 unit tests pass (one ignored), 43 CAS/fused/GC integration tests
pass; QEMU three-boot recovery/GC/powered-off verification and Duo compilation
pass. Controlled source swaps were restored and verified; the final probe also
passes on the restored source. Evidence: `target/storage-staged-predecessor-20260912/`.
Authority delta remains test-only; ordinary authority payload write amplification
is still unresolved.

### Use a narrow metadata-placement view for fused commits (2026-09-12)

commit_batch_snapshot only used the planning MountedState to find a free metadata
segment when open-segment packing was unavailable. It now receives a borrowed
allocation plus the legacy sequential frontier. The standalone packed publisher
constructs only its provisional allocation transition rather than cloning the
whole authority/catalog state. General batches project the same two fields from
their existing planning state. The allocation is still searched lazily, only when
a dedicated metadata segment is required.

MountedState's original free-run implementation delegates to the same search with
its own allocation/frontier; the projected path supplies the provisional values.
Required capacity, extra headroom, cleaner reserve, V1 sequential placement, V2
first-fit placement and overflow handling retain the original policy. The base's
admitted range/allocation version/reserve are unchanged by batch planning.

A targeted regression independently checks provisional first-fit, cleaner-reserve
refusal/authorized reserve use, extra capacity and overflow, legacy frontier
selection, occupied frontier, range exhaustion and zero-size refusal.

Controlled append allocation measurements against the preceding worktree, after
258 seed records (256 additional high-water records):

| Object bytes | Extra peak before / after | Calls before / after | Requested bytes before / after |
| --- | ---: | ---: | ---: |
| 4,096 | 865,568 / 732,424 | 219 / 216 | 1,583,768 / 1,450,620 |
| 65,536 | 1,275,680 / 1,142,536 | 271 / 268 | 2,521,736 / 2,388,588 |
| 131,072 | 1,714,976 / 1,581,832 | 327 / 324 | 3,390,856 / 3,257,708 |
| 368,640 | 3,321,728 / 3,320,736 | 445 / 445 | 6,142,660 / 6,141,668 |

The first three cases reduce peak by 133,144 bytes (15.4% for 4 KiB) and gross
allocation requests by 133,148 bytes. The 360 KiB case only saves 992 bytes, and
fresh imports also save 992 bytes with unchanged allocation counts; do not
extrapolate the seeded packed-path saving to all objects. These are requested
allocation metrics including compiler-generated async storage, not RSS or SD
latency measurements.

All per-case read/write pages, write requests and flushes match the controls,
as do subsequent verified reads. No media write amplification reduction or timed
latency improvement is claimed. The full authority payload remains on the write
path, and production authority delta is still disabled.

Validation: 271 unit tests pass (one ignored), plus 43 CAS/fused/GC integrations.
QEMU three-boot recovery/GC/powered-off verification and Duo compilation pass.
Both temporarily overridden source files were restored and verified. Evidence:
`target/storage-placement-view-20260912/`.

### First test-only fused authority-delta publication (2026-09-12)

The existing delta prototype previously exercised standalone authority publication,
not the ordinary one-object fused path. A cfg(test)-only, default-false store toggle
now selects the existing bounded delta encoder for that path. It borrows the staged
object's exact predecessor, consumes the previous provenance cache, prepares the
successor digest under the remaining codec allowance, and supplies the encoded
link to the existing fused writer. Only after successful publication and view
construction does it bind/install the successor witness. Non-test builds retain
the original full-snapshot encoder; no production feature or disk admission is
turned on. The existing one-extent fused-size routing limit is unchanged.

A fresh host fault-device scenario first publishes 257 records (format plus 256
high-water records). It then performs three public rooted object appends with
4 KiB contents: new, duplicate of the first, then a distinct object. The full and
delta variants use identical input/grant histories. Page counts exclude seeding
and later GC:

| Append | Full page writes | Delta page writes | Flushes, both |
| --- | ---: | ---: | ---: |
| New object | 64 | 32 | 4 |
| Duplicate content, new object/grant | 55 | 21 | 3 |
| Distinct object | 64 | 28 | 3 |
| Total | 183 | 81 | 10 |

The prototype saves 102 page writes (417,792 bytes), or 55.7%, in these three
appends. It retains three logical objects backed by two blobs. Every appended
object is read and checked, the actual authority root contains VIBEAUL1, and
warm provenance matches the published state. Cold mounting recovers the exact
record stream and all three objects; GC subsequently materializes authority and
preserves those objects. This is host page-device evidence, not QEMU timing,
real SD NAND amplification, a long-running steady workload or production speedup.

The optional Rust export adds fused-delta.raw and fused-materialized.raw. The
independent Python verifier now checks these when either is present (then both
are required), while preserving compatibility with the earlier four-fixture set.
Its external policy permits exactly the known object/grant prefix at either
checkpoint, checks content, slots and rights, and rejects additional identities.
All six regions validate, including both checkpoint slots, three bound objects,
depth 3 before GC and depth 0 afterwards. Default delta rejection, foreign policy/
store rejection and corrupted ancestor/blob rejection total 33 cases.

Validation: 272 unit tests pass (one ignored); the new exported scenario passes;
production cargo check passes. Evidence: `target/storage-fused-delta-prototype-20260912/`.
No QEMU or physical SD run used this test-only toggle.

Outstanding: the new fused path needs its own exhaustive mutation/cancellation
matrix and long-chain/GC-pressure scenarios. Codec accounting currently subtracts
the tracked predecessor and input snapshot but does not cover all staging/runtime
buffers. Scratch staging has already occurred before encoding, so an encoding
refusal is not a zero-write operation. Full admission and coordinated writer,
reader, GC and offline rollout remain prerequisites to production enablement.

### Fault/cancellation coverage for the fused delta prototype (2026-09-12)

The new matrix starts from a durable fused delta containing one rooted object,
then appends either distinct content or duplicate content with a separate object
identity/root grant. Each is exercised with cold codec replay and a matching warm
provenance witness. A successful probe determines every write/flush mutation point.
At each point, the test injects not-submitted failure, ambiguous failure with no /
visible / durable effect, and cancellation after pending with those same effects.

The first run exposed a witness-lifetime bug: warm distinct-content mutation zero,
FailNotSubmitted, left the predecessor cache installed because the encoder only
consumed it after scratch staging. The test-only cache is now taken into a local
at install_persistent_import entry, before staging can mutate media. Failure or
cancellation drops that local. Encoding still uses it, and only a fully successful
publication/view construction installs a successor. Production encoding is unchanged.

| Content | Codec cache | Mutation points | Cases | Old state | New state |
| --- | --- | ---: | ---: | ---: | ---: |
| Distinct | Cold | 36 | 252 | 248 | 4 |
| Distinct | Warm | 36 | 252 | 248 | 4 |
| Duplicate | Cold | 29 | 203 | 199 | 4 |
| Duplicate | Warm | 29 | 203 | 199 | 4 |
| Total | | | 910 | 894 | 16 |

Every injected operation returns an error or suspends exactly as requested;
dropping it leaves no experimental provenance cache. A fresh runtime/power cycle
must recover exactly the old or new canonical authority snapshot and generation.
Object mappings, deduplicated blob counts, all object bytes and principal logical/
physical quota totals are checked. The canonical comparison includes bindings,
recorded grants and policy metadata. Recovery performs zero media mutations and
leaves the durable image byte-identical. Each old-state outcome is retried; another
power cycle then confirms the exact new snapshot and readable objects.

Validation: 273 unit tests pass (one ignored), including the 910-case matrix.
Fresh exports of all six offline regions pass the 33 rejection cases; the earlier
three-append write counts remain 64/55/64 full versus 32/21/28 delta pages.
Production cargo check passes. Evidence, including the initial failure:
`target/storage-fused-delta-cuts-20260912/`.

This is host fault-device evidence for write/flush mutation points; it does not
cover allocation failures, every possible asynchronous read cancellation, long
chains under GC pressure, or actual SD behavior. Full fused memory admission and
coordinated format rollout remain open. The fused delta toggle stays cfg(test),
default false; no QEMU firmware or production writer has enabled it.

### Repeated fused delta append and GC pressure (2026-09-12)

The host fault-device regression now compares 48 rooted 4 KiB appends on a
16-segment region. Consecutive pairs share content, leaving 48 object identities
and 24 blobs. Both runs start with the same 257-record authority seed and use a
16 MiB recovery budget to exercise space reclamation independently of the small
codec-budget boundary tests. Every eight appends, a fresh runtime cold-mounts the
durable image and verifies the complete record stream, every object's contents,
and logical/physical quota totals. Recovery performs zero mutations and preserves
the durable image byte-for-byte.

| Encoding | Appends | Page writes | Flushes | Extra checkpoint generations |
| --- | ---: | ---: | ---: | ---: |
| Full | 48 | 6,486 | 198 | 12 |
| Experimental fused delta | 48 | 2,279 | 198 | 12 |

Counts exclude initial seeding and include foreground GC during the appends.
The delta run writes 4,207 fewer pages (17,231,872 bytes), a 64.9% reduction.
Every delta append publishes an actual VIBEAUL1 tip. Both paths advance twelve
additional checkpoint generations under allocation pressure. This exercises
repeated short chains across collection and cold mounts; it does not establish
the maximum uninterrupted chain-depth boundary or inject faults during this
entire sustained workload.

Evidence: `target/storage-fused-delta-pressure-20260912/pressure.log`.
Validation: 274 unit tests pass (one ignored). The default-production QEMU
file-tree gate passes all three boots, covering durable links, recursive removal,
GC pressure, cold recovery and powered-off verification. Logs and JSON evidence
are retained alongside the pressure log; this QEMU run does not enable delta.
These are host simulated page-device counts, not QEMU latency, sustained SD
throughput, or NAND write amplification. The toggle remains test-only and off by
default; full memory admission and coordinated format rollout remain open.

### Fused publication root-table admission (2026-09-12)

Fused object/authority publication now uses the same fallible, combined root-table
preparation as standalone authority publication. It reserves space for object and
external roots once, checks the configured root-table budget, and preserves the
existing physical-object ordering and root validation. This replaces collecting
object roots and subsequently extending the allocation for external roots.
The table is prepared before encoding; experimental delta codec workspace now
subtracts its allocated bytes as well as the predecessor and input snapshot.

This is partial admission: scratch staging has already occurred, the full encoder
and successor snapshot clone still need broader accounting, and an admission
error is not guaranteed to perform zero writes. Production format, flush ordering,
and default delta rejection are unchanged.

Validation: 274 unit tests pass (one ignored), including combined-root exact-budget
and sorting coverage, fused mutation/cancellation coverage, and repeated append/GC
pressure. The default-production QEMU three-boot file-tree gate and Duo release
compilation pass. The production allocation probe passes for fresh imports and
seeded appends at 4/64/128/360 KiB, including content verification. Seeded append
extra peaks are 732,392 / 1,142,504 / 1,581,800 / 3,320,704 bytes. These are current
host measurements, not a controlled latency or memory-reduction claim. Evidence:
`target/storage-fused-root-admission-20260912/`. No real SD test was performed.

### Reuse fused authority encoding for the successor log (2026-09-12)

The object/authority fused path now prepares successor metadata fallibly before
publication instead of cloning the complete canonical snapshot. After successful
read-back, the full encoding's allocation becomes the installed record-stream
buffer: it is cleared and filled from the original canonical log without another
allocation. A small delta encoding uses a separately pre-reserved fallback log.
The same prepared-snapshot implementation already used by standalone publication
handles both cases. The source snapshot remains available for constructing the
returned authority view. Namespace-root switches retain their existing owned
snapshot path through the shared CAS publisher.

| History records | Object bytes | Before extra peak | After extra peak |
| ---: | ---: | ---: | ---: |
| 0 | 4,096 | 343,204 | 334,052 |
| 0 | 65,536 | 686,812 | 590,108 |
| 0 | 131,072 | 1,157,532 | 967,644 |
| 0 | 368,640 | 2,925,484 | 2,398,188 |
| 256 | 4,096 | 732,392 | 592,168 |
| 256 | 65,536 | 1,142,504 | 914,728 |
| 256 | 131,072 | 1,581,800 | 1,260,840 |
| 256 | 368,640 | 3,320,704 | 2,662,336 |

These production-path host allocation probes compare the preceding root-admission
implementation with this change. Each case makes one fewer allocation; reductions
in gross requested bytes equal the listed peak differences. Read/write page
counts, request counts and flush counts match in every case. The retained log may
keep encoding metadata capacity, and log bytes are still copied; this removes an
allocation and its overlap, not the copy or media traffic. Successor workspace
admission remains partial and occurs after scratch staging.

Validation: 274 unit tests pass (one ignored), including fused failure/cancellation
and GC/cold-mount regressions. The allocation probe verifies object contents.
Default-production QEMU passes the three-boot file-tree gate; Duo release checking
passes. Evidence: `target/storage-fused-buffer-reuse-20260912/`, including the
previous source files and machine-readable memory comparison. No timed QEMU or
real SD performance claim is made; experimental delta remains disabled by default.

### QEMU timing check for fused buffer reuse (2026-09-12)

An isolated ABBA run compares the immediately preceding root-admission source
with fused-buffer reuse. Both ELFs are built from the same remaining worktree,
with the same 64-page cache override; all overridden source bytes are restored
and hash-checked. Each fresh VM runs 256 unique 4 KiB object-durable-put-get
samples, seed 32, no warmups, 128 MiB RAM and one TCG hart. Read limits are
4 MiB/s and 400 IOPS; write limits are 2 MiB/s and 200 IOPS. Builds and tests do
not overlap timed runs.

| Run | Sum of operation seconds | Median operation ms |
| --- | ---: | ---: |
| Before | 13.159832 | 37.1205 |
| After | 13.196447 | 37.2560 |
| After, repeat | 13.106225 | 36.8880 |
| Before, repeat | 13.089145 | 36.4685 |

All 1,024 samples validate. Mean summed time changes from 13.124489 to
13.151336 seconds (+0.205%), smaller than the respective two-run spreads of
0.539% and 0.686%. This run does not demonstrate a distinguishable latency
improvement or regression; it does not negate the host allocation reduction.
Every per-sample I/O counter matches across all four runs. Each run reads
8,097,792 bytes in 1,565 requests and writes 53,694,464 bytes in 1,857 requests,
with 825 flushes. Device write bytes/user payload remain 51.207x.

This shell workload publishes boot-local capabilities; each sample starts with
zero admitted authority objects, unlike the rooted-object host allocation probe.
Authority journal history still grows, and collection occurs during the run.
Every get has zero device requests, so this is not a cold-read comparison.
Operation sums exclude boot and shell gaps, and throttle credit can accumulate
between commands; they are not sustained throughput. No actual SD or new ext4
comparison was performed. The result keeps media write-volume reduction as the
next performance priority. Experimental delta remains test-only and off.

Evidence: `target/storage-fused-buffer-qemu-20260912/`, including build/run/analysis
scripts, source and ELF hashes, raw JSONL, serial logs and `summary.json`.

### Exact single-extent admission for fused authority (2026-09-12)

Ordinary single-object authority append previously required the log length plus
a fixed 128 KiB metadata allowance to fit one extent. That rejected some snapshots
whose actual encoding fits, causing a separate CAS publication followed by
authority publication. Routing now uses the final admitted-object, principal and
external-root counts plus log bytes and frozen-format widths. Physical binding
values are assigned later but cannot affect these widths. The existing snapshot
length helper delegates to the same checked calculation. Overflow or an encoding
above the single-extent ceiling continues to select the general path.

The regression seeds a canonical high-water journal, appends a rooted 4 KiB
object, compares the predicted size to the actual encoding, checks checkpoint
advances and content, then cold-mounts and verifies the entire log and object.
Recovery performs no mutations and leaves the durable image unchanged. A control
run temporarily restores the preceding routing implementation, then restores and
hash-checks current source bytes. Counts below exclude seed creation.

| Seed high-water records | Encoded snapshot bytes | Old commits / pages / flushes | New commits / pages / flushes |
| ---: | ---: | --- | --- |
| 1,800 | 931,568 | 2 / 276 / 7 | 1 / 263 / 4 |
| 2,100 | 1,085,168 | 2 / 315 / 7 | 2 / 315 / 7 |

The fitting case removes 13 page writes (53,248 bytes, 4.7%) and three flushes.
The oversize case retains the multi-extent fallback. This is a production routing
change with no format or delta-admission change. It applies to the former slack
rejection band, not all 4 KiB operations. Host fault-device counts use a 16 MiB
recovery budget; no timed QEMU or actual SD speedup is inferred. Evidence:
`target/storage-exact-fused-fit-20260912/`.

Validation: 275 unit tests pass (one ignored), including existing publication
fault/cancellation matrices and the new fit/fallback cold-recovery regression.
The default-production QEMU three-boot file-tree gate and Duo release compilation
pass. The new near-ceiling fixture itself is a success/recovery test, not a new
exhaustive power-cut matrix at that size.

### File-tree root-switch sizing without encoding (2026-09-12)

File-tree route selection no longer encodes the complete current authority
snapshot merely to obtain its length. It counts the successor's object,
principal and external-root tables using the shared checked frozen-format size
calculation. Its external-root count mirrors the builder: preserve non-file-tree
roots and replace file-tree roots with one successor entry. Replacement therefore
does not add the old unconditional 64-byte allowance. The actual successor builder
still validates and encodes before publication; the sizing helper trusts the
already validated mounted snapshot and is not an independent validator.

Tests compare predicted lengths with actual successor encoding for addition and
replacement, both with and without unrelated roots. A canonical 2,047-record log
with twelve external roots produces an exact 1 MiB successor on replacement. The new
predicate accepts it; the previous length-plus-64 predicate rejects it. This
boundary test verifies sizing and encoding, not a full near-ceiling media commit.

This removes the route-selection encoding allocation and its validation work,
and avoids that replacement-boundary fallback. It does not change disk format or
enable delta. No end-to-end timing, allocation-peak reduction, or SD improvement
is inferred from these tests. Evidence: `target/storage-fs-root-fit-20260912/`.

Validation: 277 unit tests pass (one ignored), and the default-production QEMU
three-boot file-tree gate and Duo release check pass. The initial ceiling fixture
incorrectly assumed 64-byte roots; correcting it to twelve actual 32-byte entries
made the exact-boundary assertion valid. The initial failure and corrected full
test run are both retained. Only test-fixture code changed after the QEMU gate.

### Near-ceiling fused publication fault/cancellation matrix (2026-09-12)

The newly admitted 931,568-byte full authority snapshot now has a dedicated host
fault-device matrix. It seeds 1,800 high-water records and appends one rooted
4 KiB object with a 16 MiB recovery budget. The success probe asserts the actual
canonical encoding length and exactly one checkpoint generation advance, so this
exercises the former fixed-slack rejection band on the default full-encoding path.

All 267 write/flush mutation points are exercised with seven actions:
not-submitted failure; ambiguous failure with no, visible or durable effect; and
pending/cancellation with those same three effects. All 1,869 cases pass: 1,865
recover the old canonical snapshot and four recover the new snapshot. Each case
checks the returned error/pending state, drops the operation, power-cycles into a
fresh runtime and compares the entire canonical snapshot and generation. Object
and blob counts, object contents and principal logical/physical usage must agree.
Recovery makes zero mutations and preserves the durable image byte-for-byte.
Every old-state outcome is retried, then another power cycle confirms the exact
new snapshot and readable content.

The targeted matrix passed in 104.78 seconds. Evidence:
`target/storage-near-ceiling-cuts-20260912/cuts.log`. This turn adds test coverage
only; it does not change production code or rerun the unchanged QEMU firmware.
This is not allocation-failure or arbitrary asynchronous-read cancellation
coverage, and does not model actual SD power-loss behavior. Delta remains off.

### Reuse metadata payload digests during CAS publication (2026-09-12)

Both single-object and batch metadata publishers previously invoked SHA-256
twice consecutively on each identical immutable metadata payload, supplying the
result as both payload and logical-object digests. Ten construction sites now
compute a local digest once and copy it into both fields: manifests, CAS deltas,
CAS snapshots, fused authority and allocation payloads in each publisher.

The reuse is local to record construction. It does not cache across publications,
change digest inputs or fields, or remove read-back/integrity checks. No record
layout, I/O ordering or delta-admission behavior changes. The saved source calls
include a full authority-buffer hash on fused publication; generated-code savings
and end-to-end latency have not yet been measured, so this is not a quantified
CPU or SD speedup. Evidence: `target/storage-metadata-digest-reuse-20260912/`.

Validation: 278 unit tests pass (one ignored), including the near-ceiling fused
mutation/cancellation matrix. The default-production QEMU three-boot file-tree
gate and Duo release check pass. The preceding CAS source is retained for a
subsequent isolated performance comparison.

### QEMU comparison for metadata digest reuse (2026-09-12)

An ABBA comparison builds the immediately preceding CAS source and the digest
reuse source against identical remaining code. Each fresh VM runs 32 unique
128 KiB object-durable-put-get samples, seed 32, no warmups, with 128 MiB RAM,
a 64-page cache and one TCG hart. Read limits are 4 MiB/s and 400 IOPS; write
limits are 2 MiB/s and 200 IOPS. All source overrides are restored and checked
by hash; compilation/tests finish before the timed runs.

| Run | Sum of operation seconds | Median operation ms |
| --- | ---: | ---: |
| Before | 1.750608 | 54.9395 |
| After | 1.659696 | 51.2700 |
| After, repeat | 1.662086 | 53.0745 |
| Before, repeat | 1.755301 | 53.6735 |

All 128 samples validate. Mean summed operation time falls from 1.752955 to
1.660891 seconds, 5.25% in this configuration. The two-run spreads are 0.268%
for the control and 0.144% for the candidate. Every per-sample I/O counter is
identical across all four runs. Each run reads 1,961,984 bytes in 168 requests,
writes 8,216,576 bytes in 240 requests, and issues 104 flushes.

Mean summed put time is 1.537075 versus 1.470794 seconds; mean get time is
0.215880 versus 0.190098 seconds. Gets perform 917,504 read bytes in 104 requests
per run with this cache size, with no writes or flushes. Since get timing also
changes despite unchanged get code and counters, the complete observed gain
cannot be identified as direct hashing CPU savings. These are short, cache-
dependent QEMU runs; operation sums exclude shell gaps and throttle-credit
accumulation. This is not sustained throughput, a cold-remount read test, a new
ext4 comparison or an actual SD speedup. Delta remains off.

Evidence: `target/storage-digest-qemu-20260912/`, including build/run/analysis
scripts, source and ELF hashes, raw JSONL, serial logs, `summary.json` and phase
totals in `phases.json`.

### Reuse full metadata digests in GC relocation (2026-09-12)

GC relocation now writes complete manifest, CAS snapshot and allocation payloads
through a private metadata entry point. Previously each caller hashed its buffer
for the logical root, then the segment writer hashed it again for the payload
digest. The new entry point derives both from one hash inside the writer.
The general payload API still supplies a separate content root and hashes the
individual payload, preserving fragmented object/authority semantics. The common
record writer uses an optional root internally; absence is only requested by the
complete-metadata wrapper, which fixes index/count/offset and byte lengths.

No bytes, barriers, recovery validation or delta admission are intentionally
changed. This removes duplicate source-level work at three GC construction sites
(the manifest site runs per relocated blob). GC latency and generated-code
savings have not yet been measured. Evidence:
`target/storage-gc-digest-reuse-20260912/`, with the prior GC source retained.

Validation: the changed-source full suite passes 278 unit tests (one ignored),
including GC and near-ceiling mutation/cancellation coverage. QEMU passes the
three-boot file-tree gate with GC pressure and cold recovery; Duo release checking
passes. The changed-source result is `changed-unit.log`; the earlier `unit.log`
was started before the source edit and is not the candidate validation result.

### QEMU check of GC metadata digest reuse (2026-09-12)

An isolated ABBA comparison uses the immediately preceding GC source versus its
complete-metadata digest wrapper, with identical other source. Four fresh VMs
each execute 256 unique 4 KiB durable put+get samples (seed 32, no warmups),
128 MiB RAM, a 64-page cache and one TCG hart. Limits remain 4 MiB/s and 400 read
IOPS, 2 MiB/s and 200 write IOPS. No build or test overlaps measurement. All
overridden sources are restored and hash-checked.

| Run | Sum of operation seconds | High-I/O sample seconds |
| --- | ---: | ---: |
| Before | 12.777347 | 3.450961 |
| After | 12.739108 | 3.456154 |
| After, repeat | 12.737619 | 3.445815 |
| Before, repeat | 12.714902 | 3.446718 |

All 1,024 records validate. Mean total time changes from 12.746125 to 12.738364
seconds (-0.061%), smaller than the control's 0.490% two-run spread. Candidate
spread is 0.012%. High-I/O samples are selected from the control by at least
1 MiB of reads: indices 206 and 234, reading 2,961,408 and 3,559,424 bytes. Their
mean combined time changes from 3.448840 to 3.450985 seconds (+0.062%). Neither
comparison demonstrates a distinguishable improvement. The high-I/O samples
include complete operations, not isolated GC CPU time.

All per-sample I/O counters match. Each run reads 8,097,792 bytes in 1,565
requests and writes 53,694,464 bytes in 1,857 requests, with 825 flushes. Thus
the workload still writes 51.207 times its user payload. This leaves reducing
media traffic as the performance priority. Operation sums omit shell gaps and
throttle-credit accumulation; this is not sustained throughput or real SD data.
The single-extent authority batch path was inspected but left unchanged to avoid
altering request grouping as part of digest reuse. Delta remains disabled.

Evidence: `target/storage-gc-digest-qemu-20260912/`, with source/build manifests,
run commands, serial logs, raw JSONL, analysis script and `summary.json`.

### Explicit experimental delta build feature (2026-09-12)

`experimental-authority-delta` now compiles the codec, bounded recovery bridge,
provenance state and fused writer outside cfg(test). It is forwarded through the
kernel and QEMU firmware feature tables, with no default-feature change. A
feature build accepts experimental delta during mount, but constructors still
leave delta writing off. The feature-only
`SegmentStore::enable_experimental_authority_delta` API requires an initialized
authority snapshot and explicitly opts that instance into fused delta writes.
It clears the previous witness. With no physical predecessor, fused publication
uses the existing full encoder rather than attempting to replay a null root.

The first non-test build identified a missing feature gate on the verified-scan
memo's reservation accounting method. That interface and codec-specific snapshot
helpers now compile under the same explicit feature; test instrumentation and
fixture mutation helpers remain test-only. The QEMU firmware release check with
`storage-bench-128m,experimental-authority-delta` succeeds on the RISC-V target.
The feature's positive object/dedup/cold-mount/GC test invokes the public opt-in
API and retains the earlier 64/55/64 versus 32/21/28 page counts.

This is build and API plumbing, not a production rollout or a guest timing result.
QEMU startup has not yet opted into writes. Default builds still reject delta;
feature-enabled recovery acceptance must not be confused with default admission.
Full publication-memory accounting is incomplete and encoding refusals can follow
scratch writes. Coordinated writer/reader/offline deployment and guest recovery
testing remain open. Evidence: `target/storage-delta-feature-20260912/`, including
the initial compile error, corrected checks and feature test logs.

Validation: feature-enabled full unit suite passes 278 tests (one ignored),
including the fused delta fault/cancellation and append/GC-pressure regressions.
Both default and feature-enabled library checks pass. The QEMU/RISC-V check is
a compilation check only; no feature-enabled QEMU boot was performed this turn.

### First guest delta writes and depth-limit cold recovery (2026-09-12)

The feature-enabled kernel facade now opts into experimental fused delta writes
at append entry, after authority initialization. Library opt-in is idempotent:
repeated calls retain valid warm provenance instead of clearing it. The host
positive scenario calls opt-in again after publication and verifies the witness
still matches. Default feature selection and default writer behavior are unchanged.

A QEMU image built with `storage-bench-128m,experimental-authority-delta` completes
32 unique 4 KiB durable put+get operations (seed 32, one TCG hart, 128 MiB RAM,
the normal 512-page cache configuration). This is a functional run without the
previous performance throttle configuration, not a timing comparison. The
powered-off image contains actual VIBEAUL1 records. Independent reconstruction
selects generation 36 with delta depth 32 and validates both checkpoint copies.
The default fallback verifier rejects the experimental history as intended.

A new VM boots from a copy of that image and successfully appends/reads seed 64.
The resulting image selects generation 37, depth 0: the depth limit causes full
materialization. Both checkpoint copies validate with explicit experimental
admission, while default history verification still rejects the older delta
checkpoint. This workload has no durably granted authority objects: it retains
32, then 33 CAS mappings/blobs, but does not prove old capability-backed payload
reads after reboot. Each new payload is verified in its originating guest run.

The initial 32 measured operations write 3,530,752 bytes with 104 flushes. The
post-reboot append reads 1,875,968 bytes in 173 requests and writes 155,648 bytes
in 10 requests with four flushes. These counters expose cold replay overhead;
they are not a controlled improvement estimate. Write savings must be evaluated
alongside that replay cost. Full memory admission, rooted guest recovery/GC
coverage and controlled performance comparison remain open; no SD run was made.

Evidence: `target/storage-delta-guest-20260912/`, including the ELF/source hashes,
idempotent API test, guest records and serial logs, retained images, and the
explicit-admission verifier wrapper/results (`offline.json`,
`reboot-offline.json`). The experimental build now writes delta through the
facade; this supersedes the preceding build-only status.

### Reuse verified cold-mount delta provenance (2026-09-12)

Feature-enabled mount can now retain the depth established by successful delta
replay and prepare a fixed-size provenance witness from the decoded canonical
snapshot. This avoids replaying the same chain on the first subsequent append.
The temporary depth is consumed during mount and absent from constructed commit
successors. The witness binds generation, physical authority pointer, admitted
range, segment frontier, store UUID, canonical digest and depth; later encoding
still checks that binding against its actual predecessor. Enabling writes does
not discard this validated witness.

Preparation uses the budget remaining after mounted resident allocations. Its
workspace peak is included in recovery telemetry; the optional scan memo is
explicitly dropped beforehand. A memory refusal skips caching and leaves the
original cold-encode path available. The first feature test run exposed valid
growth checkpoints referencing an older authority generation: these now skip
witness preparation rather than treating the generation difference as corruption.
Mount clears any old witness before recovery and installs the new one only after
runtime generation publication succeeds. Default builds do not seed this cache.
Fault matrices explicitly clear or install witnesses to preserve separate cold
and warm coverage despite the new feature behavior.

| Same depth-32 image, first append after reboot | Before | After |
| --- | ---: | ---: |
| Read bytes | 1,875,968 | 32,768 |
| Read requests | 173 | 1 |
| Write bytes | 155,648 | 155,648 |
| Write requests | 10 | 10 |
| Flushes | 4 | 4 |

Both QEMU runs start from the preceding guest's identical retained depth-32 image,
append/read the same 4 KiB seed-64 payload with 128 MiB RAM and the normal cache,
then power off. Both resulting full disk images have identical SHA-256:
`81d24c872b714362a250051f00e634496c2a7c4f4580cd6e7b360252ab3f4ba6`.
Independent verification selects generation 37, depth 0 and verifies both
checkpoint copies; default history verification still rejects the older delta.
This is an I/O comparison for that cold-append case, not repeated timing or actual
SD throughput. Mount now performs additional bounded hashing to prepare the
witness; its time must be included in future boot-plus-append timing comparisons.

Validation: corrected feature suite passes 278 tests (one ignored), including
growth, budget, cold/warm cancellation and near-ceiling cases. Default library
checking and experimental QEMU firmware build pass. Evidence, including initial
growth failures and final logs, images and `comparison.json`:
`target/storage-mounted-delta-witness-20260912/`. Full publication-memory
admission and broader guest workload qualification remain open.

### Full versus experimental delta QEMU ABBA (2026-09-12)

The same current source is built with default full authority writes and with
`experimental-authority-delta`. Each fresh VM runs 256 unique 4 KiB durable
put+get samples, seed 32, no warmups, 128 MiB RAM, a 64-page cache and one TCG
hart. Limits are 4 MiB/s and 400 read IOPS, 2 MiB/s and 200 write IOPS. Source
overrides are restored; builds/tests finish before the timed runs.

| Run | Sum of operation seconds | Median operation ms |
| --- | ---: | ---: |
| Full | 12.840072 | 36.2145 |
| Delta | 13.637503 | 38.5325 |
| Delta, repeat | 13.558370 | 38.6110 |
| Full, repeat | 12.721952 | 34.8240 |

All 1,024 samples validate. Mean operation sum rises from 12.781012 to
13.597937 seconds (+6.39%), exceeding the respective two-run spreads of 0.924%
and 0.582%. Per-sample counters repeat exactly within each build.

| Per-run device work | Full | Delta | Change |
| --- | ---: | ---: | ---: |
| Read bytes | 8,097,792 | 12,541,952 | +54.88% |
| Write bytes | 53,694,464 | 31,084,544 | -42.11% |
| Read requests | 1,565 | 1,989 | +27.09% |
| Write requests | 1,857 | 1,662 | -10.50% |
| Flushes | 825 | 825 | unchanged |

Device write bytes/user payload fall from 51.207x to 29.645x, but this workload
is slower. The candidate adds high-read samples at indices 22 and 55 (1,486,848
and 1,536,000 bytes); samples 206 and 234 also read more than full encoding.
Those four samples repeat across candidate runs. This identifies concrete
follow-up points for replay/invalidation investigation, not proof of their exact
cause. Lower write volume alone is not an end-to-end performance win here.

The retained candidate image independently verifies generation 273, delta depth
22 and both checkpoint copies. Default verification rejects the delta history.
It contains 256 CAS objects/blobs but no durably granted authority objects; guest
get verifies each newly published object during its run. Operation sums exclude
shell gaps and throttle-credit recovery, so this is not sustained throughput or
actual SD performance. The experiment stays opt-in pending replay-cost work,
complete memory admission and broader qualification.

Evidence: `target/storage-delta-abba-20260912/`, including build/command/source
manifests, raw JSONL and serial logs, `summary.json`, `io-comparison.json`, retained
candidate image and `offline.json`.

### Preserve verified delta provenance across online growth (2026-09-12)

Serial capacity diagnostics identify samples 22 and 55 as online growth. Growth
preserves the physical authority root and canonical snapshot while changing the
checkpoint generation, admitted range and segment frontier. Those changes made
the former provenance witness miss and forced complete delta replay on append.

The experimental path now takes the witness before growth can mutate media.
Only after growth checkpoint/read-back and successor verification succeed may it
rebind: generation must advance exactly once, admitted range and segment frontier
must increase, and store UUID and physical authority pointer must be unchanged.
A bounded canonical digest/depth check then verifies the successor snapshot.
Budget failure or any mismatch leaves caching disabled. Failed or cancelled
growth drops the local witness. This does not relax cold-mount generation checks
or change any on-media data; default builds do not use the rebinding path.

The existing empty/live growth matrices now assert successful cache preservation,
zero-budget and changed-root rejection, and absence of cache after each failed or
cancelled growth. The full feature suite passed 278 tests (one ignored), and the
augmented empty/live matrix tests pass separately. Default checking and QEMU
experimental firmware builds pass.

| Matched 64-operation QEMU prefix | Before | After |
| --- | ---: | ---: |
| Read bytes | 3,264,512 | 258,048 |
| Read requests | 358 | 63 |
| Write bytes | 7,036,928 | 7,036,928 |
| Write requests | 406 | 406 |
| Flushes | 203 | 203 |

Both runs use 64 unique 4 KiB operations, seed 32, 128 MiB RAM, a 64-page cache,
one TCG hart and the same read/write limits as the previous ABBA. Builds and
tests finish before measurement. Sample 22 drops from 1,486,848 bytes/148 reads
to 8,192 bytes/two reads; sample 55 drops from 1,536,000 bytes/151 reads to the
same 8,192 bytes/two reads. Per-sample write and flush counters all match. The
two powered-off images have identical SHA-256:
`1002c5f5fe00fae4e62463b9278ee2b7ea5dadf4e668623edb1efb87d0b5185e`.

Observed operation sums are 2.121284 versus 1.508586 seconds, but this is one
prefix comparison, not repeated timing or the complete 256-operation workload.
The later pressure samples still need remeasurement. Independent explicit-
admission image verification passes; default verification rejects delta history.
No SD throughput claim is made. Evidence:
`target/storage-growth-delta-witness-20260912/`, including source/build manifests,
test logs, matched commands, JSONL, retained images and `comparison.json`.

### Complete delta ABBA after growth-witness preservation (2026-09-12)

Fresh full and experimental-delta ELFs from the current source repeat the same
256-operation 4 KiB workload, seed 32, ABBA order, 128 MiB RAM, 64-page cache,
one TCG hart, read 4 MiB/s/400 IOPS and write 2 MiB/s/200 IOPS. No builds or
tests overlap measurement; all 1,024 records validate.

| Run | Operation sum seconds | Median operation ms |
| --- | ---: | ---: |
| Full | 12.834312 | 35.1490 |
| Delta | 12.908250 | 38.9525 |
| Delta, repeat | 12.817783 | 38.6740 |
| Full, repeat | 12.651473 | 34.9355 |

Mean operation sums are 12.742893 and 12.863017 seconds (+0.943%). This is smaller
than the full build's 1.435% two-run spread (delta spread 0.703%), so overall
timing does not establish a stable improvement. The average of run medians,
however, rises from 35.04225 to 38.81325 ms (+10.76%); reporting only the total
would hide this ordinary-operation cost. The first three 64-operation quarters
are slower for delta, while the last quarter is faster overall. Further work
should examine warm append encoding/validation, not assume the latency problem
is resolved by eliminating growth replay.

Within each build, every per-sample I/O counter repeats exactly. Full still reads
8,097,792 bytes and writes 53,694,464 bytes per run. Delta now reads 8,437,760
bytes (+4.20%) and writes 31,084,544 bytes (-42.11%); read requests are 1,606
versus 1,565, write requests 1,662 versus 1,857, and both issue 825 flushes.
Growth samples 22/55 read only 8 KiB. The remaining high-read samples are 206/234;
their combined mean time is 3.577508 versus 3.452452 seconds.

The candidate disk is byte-identical to the pre-growth-fix candidate disk from
the preceding complete ABBA (SHA-256
`84f2d929240dd64dd3f1d7f725d245b86496044fdca3f640092ea8fffc97352c`).
Independent verification again accepts generation 273, depth 22 and both
checkpoint copies with explicit admission; default verification rejects it.
There remain no durably granted authority objects in this shell workload.
Command gaps and throttle-credit recovery are excluded from operation sums;
these results are not sustained throughput or real SD behavior. Experimental
delta remains opt-in and full memory admission remains incomplete.

Evidence: `target/storage-delta-growth-abba-20260912/`, including raw records,
serial logs, source/build/command manifests, `summary.json`, quarter/phase data
and image hashes in `phases.json`, retained image and `offline.json`.

### Reuse the encoded successor digest (2026-09-12)

The experimental fused and standalone publishers previously prepared the next
snapshot witness by encoding its metadata and hashing the canonical snapshot,
then repeated that work during delta encoding. A private encoder wrapper now
returns the prepared witness with its freshly encoded output: delta output
already contains the computed successor digest; full fallback hashes the encoded
snapshot. It accepts no external encoded bytes. Physical binding still happens
only after successful publication and read-back. Snapshot validation, delta
replay, cache matching and checkpoint ordering remain in place. This removes one
successor metadata validation/allocation pass and, on delta output, one complete
successor hash. It does not complete publication-memory admission.

Cold and warm encoding tests compare returned witnesses with independent
canonical preparation; full fallback receives the same check. The feature unit
suite passes 278 tests (one ignored), including mutation/cancellation matrices.
Default compilation and the feature QEMU firmware build pass.

An isolated old/new/new/old QEMU comparison repeats the preceding 256-operation
4 KiB configuration. Both versions enable delta and use a 64-page cache. All
1,024 samples pass, and every per-sample I/O counter matches across all runs:
8,437,760 read bytes, 31,084,544 write bytes, 1,606 read requests, 1,662 write
requests and 825 flushes per run.

| Run | Operation sum seconds | Median operation ms |
| --- | ---: | ---: |
| Before | 13.678071 | 34.7230 |
| After | 11.201048 | 31.6285 |
| After, repeat | 11.393334 | 31.7485 |
| Before, repeat | 11.619467 | 29.3805 |

The mean operation sum falls 10.69%, but the control spread is 16.28% and the
last control median is lower than either candidate median. This run therefore
does not establish a stable latency improvement. It is evidence of unchanged
I/O and correct output, not a reliable speedup estimate or real SD performance.
The candidate image is byte-identical to the preceding candidate image (SHA-256
`84f2d929240dd64dd3f1d7f725d245b86496044fdca3f640092ea8fffc97352c`). Independent
verification accepts both checkpoint copies with explicit delta admission;
default verification rejects delta history. Evidence, including source backups,
builds, commands, tests, raw timings and image checks:
`target/storage-delta-encoded-witness-20260912/`.

### Reuse the matched predecessor encoding (2026-09-12)

Warm delta encoding previously validated and encoded the predecessor metadata
and hashed its canonical bytes for cache matching, then repeated those steps
to construct the delta. Matching now returns a transient `CanonicalBase` that
borrows the exact immutable snapshot and owns its validated metadata, digest
and preparation peak. The same invocation consumes that proof while encoding
the successor. Physical-root, generation, geometry, UUID, depth and canonical
digest matching still run. The retained predecessor metadata remains charged
against successor encoding; it is dropped before reserving output or entering
full fallback. No persistent proof is broadened to authorize another state.

A test-only thread-local counter verifies exactly two canonical snapshot hashes
on a warm append: one predecessor check and one successor hash. A failing-read
device proves that this path does not perform replay I/O. Cold/warm output
equivalence, fallback, tiny-budget failures and corrupted media remain covered.
The first implementation passes the 278-test feature suite (one ignored). After
removing a duplicate prefix comparison and adding the counter assertion, the
final source passes all 15 experimental tests and 18 codec tests; default check
and feature firmware build also pass.

A 64-operation QEMU functional run uses the same 4 KiB/seed-32/64-page-cache and
throttled configuration as the preceding growth-prefix fixture. All records
pass, including the two growth boundaries. Every per-sample I/O counter matches
that fixture: 258,048 read bytes/63 requests, 7,036,928 write bytes/406 requests,
and 203 flushes. The resulting image is byte-identical, SHA-256
`1002c5f5fe00fae4e62463b9278ee2b7ea5dadf4e668623edb1efb87d0b5185e`.
Independent verification accepts generation 69, depth 31, both checkpoints and
64 CAS objects with explicit delta admission; default verification rejects
delta history. This establishes reduced duplicate computation and unchanged
output, not a latency estimate or SD performance result. Evidence:
`target/storage-delta-base-proof-20260912/`.

### Complete ABBA after both digest reuse changes (2026-09-12)

The full firmware was rebuilt from current source and the current delta ELF's
source manifest rechecked. The same 256-operation, seed-32, 4 KiB, 64-page-cache,
128 MiB, single-TCG-hart throttled workload runs full/delta/delta/full, without
overlapping builds or tests. All 1,024 samples pass, but timing is inconclusive:

| Run | Operation sum seconds | Median operation ms |
| --- | ---: | ---: |
| Full | 12.979442 | 34.4535 |
| Delta | 72.656521 | 32.3960 |
| Delta, repeat | 11.139142 | 29.7175 |
| Full, repeat | 11.621434 | 29.0730 |

The first delta run slows markedly through samples 196–234, including ordinary
operations. High-I/O samples 206/234 take 15.838849/19.512670 seconds versus
1.592152/1.938308 seconds in the repeated delta run. Even the full controls have
an 11.04% spread. No run or sample is excluded, and no stable latency improvement
is established. This anomaly needs contemporaneous host scheduling/CPU evidence;
the current data do not identify its cause. QEMU arguments match between delta
runs except for their fresh temporary disk paths.

Within each build, all per-sample I/O counters repeat exactly. Full reads
8,097,792 and writes 53,694,464 bytes; delta reads 8,437,760 (+4.20%) and writes
31,084,544 (-42.11%) bytes. Both flush 825 times. The final delta image again
matches the earlier candidate byte-for-byte, SHA-256
`84f2d929240dd64dd3f1d7f725d245b86496044fdca3f640092ea8fffc97352c`.
Independent verification accepts generation 273, depth 22, both checkpoints and
256 CAS objects with explicit admission; default verification rejects delta
history. No SD performance claim is made. Raw records, commands, manifests,
phase/quartile sums, diagnostic anomaly indices and offline results are in
`target/storage-delta-digest-abba-20260912/`.

### Opt-in host telemetry for latency diagnosis (2026-09-12)

`scripts/storage-bench.py run-vibeos --host-telemetry PATH` writes a separate
JSONL diagnostic timeline. It records run/VM/QEMU PID coordinates, monotonic and
wall timestamps, sample-begin/sample-received markers with seed and warmup
coordinates, and approximately one poll per second of QEMU cumulative `ps TIME`,
process state and host load averages. Poll duration and errors are explicit;
missing CPU values are not replaced with zero. Polling stops during cleanup.
The ordinary benchmark environment records that telemetry was enabled. It is
off by default and does not change the guest metrics or exclude slow samples.

Sampling has overhead: use the same setting on both sides of a diagnostic
comparison, and do not mix it silently with ordinary baseline runs. Host command
intervals include serial transport and other runner/guest work outside the guest
timer. CPU windows bracketed by one-second polls include adjacent operations and
idle gaps; they are not precise per-operation CPU costs or direct proof of a
scheduling/storage cause. Large monotonic/wall or CPU-time differences are clues
for follow-up, not automatic reasons to discard samples.

The runner selftest passes, including CPU-time parsing. A live 64-operation
check verifies all marker coordinates, monotonic timestamps, nondecreasing CPU
time, successful lifecycle cleanup and 20 error-free polls. Its per-sample I/O
and final disk match the earlier 64-operation fixture exactly. The independent
image verifier passes. Evidence: `target/storage-host-telemetry-20260912/`.

A full 256-operation diagnostic run also passes, with 80 error-free polls,
maximum poll gap 1.024 seconds and median collection duration 5.85 ms. The prior
multi-second anomaly does not recur: samples 206/234 take 1.605667/1.958959 guest
seconds. Their approximately 3.04-second bracketing poll windows accumulate
0.77/0.83 QEMU CPU seconds, including nearby work; this does not identify the
cause of the earlier anomalous run. Operation sum 11.849230 seconds and median
33.7805 ms are diagnostic observations, not an uninstrumented speedup estimate.
Every per-sample I/O counter matches the earlier delta run, and the final image
is byte-identical (SHA-256
`84f2d929240dd64dd3f1d7f725d245b86496044fdca3f640092ea8fffc97352c`). Independent
verification accepts both checkpoints with explicit admission; default rejects
delta history. Evidence and the timeline analysis script:
`target/storage-host-telemetry-pressure-20260912/`.

### Charge the experimental successor preparation overlap (2026-09-12)

Experimental fused publication previously subtracted only the root table before
reserving successor snapshot tables and, for short deltas, a complete log buffer.
It now also charges the still-live predecessor state's tracked resident heap,
the source snapshot's allocated capacities and the encoded output's capacity.
Checked addition/subtraction refuses an overflowing or exhausted budget before
reserving successor storage. This applies when the experimental fused encoder
prepared a successor witness, including its full-materialization fallback;
default publication behavior is unchanged.

This is one publication-phase overlap check, not whole-operation admission.
Scratch staging may already have written media. Staged extent/manifest/sink
buffers, runtime proof structures and later publisher workspace still need
their own complete accounting. The change does not establish a throughput or
latency improvement; it closes an undercount needed for bounded experimental
publication on constrained guests.

Boundary tests cover full output, short delta output and output with spare
capacity; exact budgets succeed, one byte less fails and overflow fails. The
complete feature unit suite passes 279 tests (one ignored), including the
mutation/cancellation matrices. Default compilation and feature QEMU firmware
build pass. A 256-operation QEMU pressure run accepts every sample under the
existing configuration. Every per-sample I/O counter matches the prior delta
run, and the final image is byte-identical (SHA-256
`84f2d929240dd64dd3f1d7f725d245b86496044fdca3f640092ea8fffc97352c`). Independent
verification accepts both checkpoints with explicit admission and rejects the
delta history by default. Evidence:
`target/storage-delta-publication-overlap-20260912/`.

### Charge staged buffers during experimental encoding/preparation (2026-09-12)

The experimental fused path now includes the staged object's owned buffers in
both its delta-codec allowance and successor-preparation overlap check. The
tracked amount adds manifest extents, scratch extents, scratch segments and
payload-hash Vec capacities to the predecessor state's tracked resident heap.
PageSink charges its entry-array capacity plus each live boxed page. Empty
reserved arrays still count; clearing sink entries releases the boxes without
pretending that retained entry capacity disappeared. All arithmetic is checked.
Batch entries without an owned predecessor report only their own buffers; their
shared base must be charged separately by any future caller.

The capacity/lifetime test covers empty-but-reserved arrays, adding boxed pages
and clearing them while retaining slots. The full feature suite passes 280
tests (one ignored), default compilation and feature firmware build pass. The
existing 256-operation QEMU pressure configuration still accepts every sample.
All per-sample I/O counters match the preceding delta run and the final disk is
byte-identical, SHA-256
`84f2d929240dd64dd3f1d7f725d245b86496044fdca3f640092ea8fffc97352c`.
Independent image verification accepts both checkpoints with explicit delta
admission; default verification rejects delta history. Evidence:
`target/storage-staged-resident-20260912/`.

This extends tracked overlap admission, not the full operation limit: shared
quota/runtime proof structures, caller-owned import/index buffers, allocator
overhead and subsequent publisher temporaries remain outside this check. No
latency or SD performance improvement is inferred from this admission change.

### Release single-publication scratch buffers before read-back (2026-09-12)

The default single-object publisher now drops its two 4 KiB segment-header
buffers and temporary payload-reference Vec once their writes have completed
(or have been copied into PageSink). They no longer overlap segment finalization,
checkpoint I/O and the larger read-back capture. Read-back verification also
borrows the exact published manifest encoding instead of allocating a second
identical encoding. Staged-blob verification and observed-versus-expected byte
comparison remain intact.

The preallocated-device allocation probe measures the following import peaks
in bytes, with all read/write page counts, write requests and flushes unchanged:

| Prior history records | Object bytes | Before peak | After peak |
| ---: | ---: | ---: | ---: |
| 0 | 4,096 | 334,052 | 325,764 |
| 0 | 65,536 | 590,108 | 581,564 |
| 0 | 131,072 | 967,644 | 959,356 |
| 0 | 368,640 | 2,398,188 | 2,389,900 |
| 256 | 4,096 | 592,168 | 592,168 |
| 256 | 65,536 | 914,728 | 914,728 |
| 256 | 131,072 | 1,260,840 | 1,260,840 |
| 256 | 368,640 | 2,662,336 | 2,654,048 |

The affected cases also make one fewer allocation (256 or 512 fewer gross
requested bytes for the manifest); other peaks/call counts are unchanged. Early
release reduces live overlap rather than total header allocation volume. This
is a measured host allocation improvement, not a latency or SD throughput claim.

The complete feature unit suite passes 280 tests (one ignored). Default QEMU
file-tree acceptance passes all three boots, including links, removal, GC
pressure, cold recovery and powered-off image verification. Duo compilation
passes; no physical SD test was run. Evidence, before-source snapshot, allocation
logs/comparison and retained QEMU verification logs:
`target/storage-publication-buffer-lifetime-20260912/`.

### Reserve the complete batch read-back table (2026-09-12)

Batch read-back previously reserved `manifest count + 2` slots for both requests
and expected byte slices, then pushed catalog, allocation and optional authority
entries. Authority-bearing batches could therefore trigger implicit Vec growth
after the fallible reservation. Both tables now reserve the checked sum of all
actual entries once. The dedicated-metadata branch also drops its two header
pages before segment finalization; the open-segment branch already consumes its
temporary reference table promptly. Verification requests and byte comparisons
are unchanged.

The same allocation probe shows two fewer allocation calls and 640 fewer gross
requested bytes for each 4/64/128 KiB append with 256 prior history records.
Their peaks fall by 256 bytes: 592,168 to 591,912; 914,728 to 914,472; and
1,260,840 to 1,260,584. Other measured shapes are unchanged. All read/write page
counts, write requests and flushes match. This is a small measured allocation
improvement and removal of implicit growth, not evidence of latency or SD gains.

The complete feature suite passes 280 tests (one ignored), the default QEMU
file-tree gate passes its three boots including GC/cold recovery/offline image
verification, and Duo compilation passes. The allocation probe finishes before
the correctness gates; the gates are not timing experiments. Evidence:
`target/storage-batch-readback-reserve-20260912/`.

### Current 128 KiB full-versus-delta diagnostic ABBA (2026-09-12)

Fresh current-source ELFs run full/delta/delta/full with 64 unique 128 KiB
durable put+get operations per run, seed 32, no warmups, 128 MiB RAM, a 64-page
cache and one TCG hart. Read/write limits remain 4/2 MiB/s and 400/200 IOPS.
Host telemetry is enabled equally on both builds. Builds finish before timing;
all 256 samples validate and every per-sample I/O counter repeats within its
build. All host polls succeed; maximum observed poll gap is 1.023 seconds.

| Run | Operation sum seconds | Median operation ms |
| --- | ---: | ---: |
| Full | 3.933482 | 57.8970 |
| Delta | 3.011933 | 42.4895 |
| Delta, repeat | 3.051257 | 45.0685 |
| Full, repeat | 4.177144 | 67.5995 |

Mean sums fall from 4.055313 to 3.031595 seconds (-25.24%); both delta runs are
below both full runs. Full/delta two-run spreads are 6.01%/1.30%. The average of
run medians falls 30.23%. Put sums average 3.539362 versus 2.620655 seconds
(-25.96%), get sums 0.515951 versus 0.410940 seconds (-20.35%). These are results
for this short, instrumented workload, not sustained throughput or an SD result.

| Per-run I/O | Full | Delta |
| --- | ---: | ---: |
| Read bytes | 5,251,072 | 2,174,976 |
| Write bytes | 17,424,384 | 15,425,536 |
| Read requests | 362 | 140 |
| Write requests | 476 | 470 |
| Flushes | 203 | 203 |
| Put read bytes | 2,121,728 | 2,072,576 |
| Get read bytes | 3,129,344 | 102,400 |

Writes fall 11.47%, total reads 58.58%; most avoided reads belong to get directly
following put. Reduced cache displacement by smaller metadata is a plausible
explanation under this 256 KiB cache, not a separately established causal result.
The gain must not be attributed entirely to hashing/encoding or extrapolated to
larger caches, cold reads, longer GC pressure, Linux comparison or real SD media.
Command gaps still permit throttle-credit recovery and are excluded from sums.

Independent verification accepts generation 69, depth 31, both checkpoints and
64 CAS objects with explicit delta admission; default verification rejects its
delta history. The workload has no durably granted authority objects. Evidence,
including manifests, commands, raw samples, host timelines, phase analysis and
retained image: `target/storage-medium-delta-20260912/`.

### 128 KiB cache-capacity sensitivity: default 512 pages (2026-09-12)

Repeat the preceding full/delta/delta/full experiment at the default 512-page
cache (2 MiB). The workload, source, 128 MiB guest, single TCG hart, read/write
limits and telemetry setting are unchanged. Both ELFs are freshly built with
the unmodified cache declaration. All 256 samples and timeline coordinates
validate; all host polls succeed, maximum poll gap 1.021 seconds.

| Run | Operation sum seconds | Median operation ms |
| --- | ---: | ---: |
| Full | 3.972144 | 61.8835 |
| Delta | 2.862710 | 42.3840 |
| Delta, repeat | 2.856221 | 42.1920 |
| Full, repeat | 3.931664 | 59.5330 |

Mean operation sums are 3.951904 versus 2.859466 seconds (-27.64%), with
full/delta two-run spreads of 1.02%/0.23%. The average of run medians falls
30.34%. Mean put sums fall 3.563207 to 2.517691 seconds (-29.34%); get sums fall
0.388698 to 0.341775 seconds (-12.07%). This is a short instrumented QEMU result,
not a sustained-throughput, cold-read or real-SD result.

Both builds now perform zero device reads during the measured samples. Writes
remain 17,424,384 versus 15,425,536 bytes (-11.47%), 476 versus 470 write requests,
and 203 flushes each, with exact per-sample repeatability within each build.
The latency advantage therefore survives removal of the device-read difference
seen at 64 pages. Cache displacement explains the earlier read-count difference
but cannot alone explain the observed latency advantage; further attribution
must examine writes and metadata processing rather than assume a pure cache
effect. This experiment does not isolate those two remaining contributions.

The delta disk is byte-identical across cache capacities, SHA-256
`fc7f600a7b8069c6a10d39055bf70c2fab7577adbd4265e56add356156f35542`.
Independent verification accepts generation 69, depth 31, both checkpoints and
64 CAS objects with explicit delta admission; default rejects its delta history.
No durably granted authority objects are present in this workload. Evidence:
`target/storage-medium-cache512-20260912/`.

### 128 KiB sensitivity without QEMU rate limits (2026-09-12)

Reuse the exact preceding 512-page-cache ELFs after checking their source
manifest, and repeat full/delta/delta/full with the same 64 unique 128 KiB
operations, seed 32, 128 MiB, one TCG hart and telemetry. Only QEMU's bandwidth
and IOPS limit arguments are removed. All 256 records and timeline coordinates
validate, all polls succeed, and each build's per-sample I/O repeats exactly.

| Run | Operation sum seconds | Median operation ms |
| --- | ---: | ---: |
| Full | 2.147781 | 32.1710 |
| Delta | 2.190479 | 32.6105 |
| Delta, repeat | 2.203788 | 32.7400 |
| Full, repeat | 2.197204 | 32.1390 |

Mean sums are 2.172493 versus 2.197133 seconds (+1.13%), with full/delta two-run
spreads of 2.27%/0.61%. This does not establish a latency improvement. Mean put
sums rise from 1.816396 to 1.862667 seconds (+2.55%); get sums fall from 0.356097
to 0.334467 seconds (-6.07%). The experiment still includes device/host/flush
and diagnostic overhead and must not be treated as pure CPU timing.

Both builds still perform zero measured device reads. Writes remain 17,424,384
versus 15,425,536 bytes (-11.47%), 476 versus 470 write requests, and 203 flushes
each. The preceding limited-run latency advantage therefore does not survive
removal of the rate limits in this workload. This supports prioritizing reduced
write amplification under constrained storage and longer pressure testing,
rather than assuming a general execution-time advantage. It does not isolate
bandwidth from IOPS effects or predict a specific SD card's behavior.

The candidate image is byte-identical to the limited 512-page run, SHA-256
`fc7f600a7b8069c6a10d39055bf70c2fab7577adbd4265e56add356156f35542`.
Independent verification accepts generation 69, depth 31, both checkpoints and
64 CAS objects with explicit admission; default rejects delta history. Evidence:
`target/storage-medium-unthrottled-20260912/`.

### 256-operation 128 KiB growth/GC pressure (2026-09-12)

Extend the 64-page-cache limited workload to 256 unique 128 KiB operations
(32 MiB logical payload) using the same verified ELFs. Full and delta run once
each, with telemetry, seed 32, 128 MiB, single TCG hart and the earlier 4/2 MiB/s,
400/200 IOPS limits. Both runs validate all records and timeline coordinates;
host polls report no errors, maximum gap 1.040 seconds. This is a longer
functional/I/O comparison, not a repeated timing-effect estimate.

| Entire run | Full | Delta |
| --- | ---: | ---: |
| Write bytes | 98,754,560 | 71,634,944 |
| Read bytes | 53,751,808 | 30,846,976 |
| Write requests | 2,882 | 1,979 |
| Flushes | 825 | 825 |
| Write bytes / logical payload bytes | 2.9431 | 2.1349 |
| Observed operation sum seconds | 36.847987 | 23.254118 |

Writes fall 27.46% and reads 42.61%, including growth, full-materialization
fallbacks and collection. The first 64 operations' I/O matches the preceding
short run. Per-64-operation write bytes are full 17,424,384 / 23,138,304 /
23,298,048 / 34,893,824 and delta 15,425,536 / 15,622,144 / 15,654,912 /
24,932,352. Flush counts per quarter match: 203 / 198 / 200 / 224. Get reads
fall from 24,895,488 to 1,003,520 bytes; put reads instead rise from 28,856,320
to 29,843,456 bytes. Total read savings must not hide that distinction.

Long-tail samples 206/234 remain: full 3.629416/4.611288 seconds, delta
3.622509/4.617275 seconds. Serial evidence identifies two GC rounds at each
point after growth is exhausted. Both builds report identical per-round GC
read requests (287, 350, 380, 378), write requests (22, 31, 31, 32), copied bytes
(1,099,264 then 2,061,120 three times), and 16 reclaimed segments per round.
The second round follows the existing free-space hysteresis, deliberately
reclaiming past the floor to amortize later collections. Removing it blindly
would trade pause size for collection frequency; the next useful target is
per-round scanning/relocation cost. Ordinary append improvements have not
removed these maintenance pauses.

Independent verification accepts generation 273, depth 22, both checkpoints
and 256 CAS objects with explicit admission; default rejects delta history.
No physical SD test or sustained-throughput claim is made. Evidence:
`target/storage-medium-pressure-20260912/`.

### Linear manifest-capacity accounting during GC (2026-09-12)

`load_live_manifests` previously rescanned every already-loaded manifest to
recompute retained extent capacity before reading the next one. With B live
blobs, that accounting alone revisited B(B-1)/2 entries. Since loaded manifests
and their capacities are immutable, it now maintains the checked sum once per
decoded manifest. Actual Vec capacities, not logical lengths, remain charged;
payload/decoder admission and overflow checks are preserved. This changes the
accounting work to B updates without changing manifest reads or verification.

The full feature suite passes 280 tests (one ignored), the default three-boot
QEMU file-tree gate passes GC pressure/cold recovery/offline verification, and
Duo compilation passes. No latency or I/O improvement was measured in this
turn, and the multi-second relocation tails are not claimed resolved. The
copied-extent digest/padding checks and whole-blob Merkle verification still
perform their existing reads; safely sharing a read-back snapshot requires
separate bounded-memory work. Evidence:
`target/storage-gc-manifest-accounting-20260912/`.

### Rejected physical-order GC manifest loading (2026-09-12)

Trial: reserve a budgeted Vec of live CAS indices, sort it by physical segment
and descriptor location, load/authenticate manifests in that order, then restore
canonical BlobKey ordering before planning. Charge the index/manifest overlap
before releasing the index. This differs from the earlier rejected reverse-key
traversal, but targets the same cache-locality hypothesis.

An initial full feature suite passes 280 tests (one ignored); after correcting
the telemetry accounting order, all 22 GC-filtered tests pass. A 256-operation
128 KiB limited QEMU run per build, 64-page cache/128 MiB/single TCG hart with
host telemetry, validates all 512 records. Both ELFs use the default full writer.
The control ELF predates the linear-capacity accounting change as well, so this
is not an isolated CPU-timing comparison for physical sorting.

| Entire run | Control | Trial |
| --- | ---: | ---: |
| Read bytes | 53,751,808 | 53,755,904 |
| Read requests | 2,758 | 2,759 |
| Write bytes | 98,754,560 | 98,754,560 |
| Write requests | 2,882 | 2,882 |
| Flushes | 825 | 825 |
| Observed operation sum seconds | 37.876519 | 37.054141 |

The only I/O difference is one additional 4 KiB read at sample 234. GC-episode
times remain about 3.6/4.6 seconds. A one-pair timing change with differing host
variation and the control's older accounting does not establish a benefit.
Reject the added sorting/index allocation because targeted I/O does not improve.
The source is restored byte-for-byte to this experiment's baseline, preserving
the preceding linear-capacity accounting optimization.

The stopped trial image passes the independent default verifier with its
unmanaged-prefix baseline; default checkpoint recovery accepts generation 273,
both copies and 256 CAS objects. Evidence: `target/storage-gc-physical-order-20260912/`.
This directory separates the physical-order experiment from the older
`storage-gc-manifest-order-20260912` reverse-key trial; see its provenance note
for build scratch names briefly reused before the separation. No runtime
physical-order optimization remains and no SD performance claim is made.

### GC single-envelope readback reuse and allocation-free Merkle verification (2026-09-12)

`BlobView::verify_all` now authenticates every real/padded leaf and then every
parent against the immutable encoded tree. Each parent uses children already
verified at the preceding level; decoding still binds the final root to the
header. This retains complete tree validation while removing the second tree
allocation. A thread-local allocator test observes zero allocations during
verification for empty, boundary, padded and large objects through 4 MiB.
Existing prefix/tree-node mutation and streaming tests also pass.

GC reuses an authenticated copied payload for complete verification when the
object has one extent. It checks manifest/extent identity and geometry, the blob
header, all Merkle nodes and the existing final-page zero padding. Physical
pointer, segment-seal and payload-hash validation still run. Multi-extent
objects retain the previous streaming verification path. No new payload copy
or cache is introduced.

A limited QEMU comparison uses the default full writer, 64 cache pages, 128 MiB,
one TCG hart, 256 unique 128 KiB durable put/get operations per build, and host
telemetry. Read/write limits are 4/2 MiB/s and 400/200 IOPS. Both runs validate all
256 samples. The control ELF also predates linear GC manifest accounting, so
CPU timing does not isolate the single-envelope change.

| Entire run | Control | Candidate |
| --- | ---: | ---: |
| Read bytes | 53,751,808 | 53,751,808 |
| Read requests | 2,758 | 2,758 |
| Write bytes | 98,754,560 | 98,754,560 |
| Write requests | 2,882 | 2,882 |
| Flushes | 825 | 825 |
| Observed operation sum seconds | 59.284375 | 58.820141 |
| Median operation milliseconds | 152.9575 | 186.8400 |

There is **no measured physical I/O reduction**. The single pair is noisy:
control sample 234 takes 11.899512 seconds versus 5.085942 for the candidate,
while sample 206 changes from 3.657797 to 4.556343 seconds. Neither the operation
sum nor these tails establish a speedup. The retained benefit is removal of
redundant logical verification work/buffers and the independently tested
allocation-free tree walk; SD performance is unmeasured.

The feature-enabled segment-store suite passes 280 tests (one ignored). The
stopped default-format candidate image passes the independent migration
verifier with its unmanaged-prefix baseline, including 256 CAS objects.
Evidence: `target/storage-gc-single-envelope-20260912/`, including commands,
ELF/source hashes, raw samples, host telemetry and offline verification.
`formatted-source.json` records whitespace-only formatting after the measured
firmware build; the original build hashes remain in their original manifests.

Final gates pass: default QEMU file-tree across three boots (hard links,
symlink, recursive removal, GC pressure, cold recovery and powered-off
verification), plus the Milk-V Duo release compile check. This is compile
coverage for Duo, not a real-device benchmark.

### Current 128 KiB GC phase attribution (2026-09-12)

Temporary phase hooks on the current single-envelope runtime isolate physical
I/O across four collections in 256 unique 128 KiB durable put/get samples.
Configuration remains default full metadata, 64 cache pages, 128 MiB, one TCG
hart, 4/2 MiB/s and 400/200 read/write IOPS. All samples pass; every sample's
seven counters exactly matches the preceding uninstrumented candidate.
Diagnostic times are not used. Both source files are restored byte-for-byte
before running the instrumented ELF.

| Four rounds combined | Read requests | Read bytes |
| --- | ---: | ---: |
| Typed children / mark | 0 | 0 |
| Manifest loading / planning | 879 | 3,600,384 |
| Relocation staging | 161 | 7,389,184 |
| Root readback | 139 | 1,732,608 |
| Manifest / blob readback | 212 | 7,598,080 |
| Publication / reuse | 4 | 98,304 |
| Total | 1,395 | 20,418,560 |

GC writes total 9,695,232 bytes / 116 requests / 30 flushes. Manifest loading
accounts for 63.0% of read requests but 17.6% of read bytes; source plus object
readback accounts for 73.4% of read bytes. Thus small manifest accesses dominate
request count even after avoiding duplicate single-envelope verification.
Current source selection caps each round at 16 source segments; each pressure
episode executes two rounds and reloads the live manifests. The next bounded
experiment tests 32 sources per round to measure whether fewer passes outweigh
larger round work. This does not yet justify changing the production pause cap.
Evidence: `target/storage-medium-gc-phases-current-20260912/`, including exact
before/trial sources, ELF, source restoration hashes, commands, serial phase
trace, raw samples and reconciled per-round/combined counters.

### Temporary 32-source GC round trial (2026-09-12)

Build a trial with only `GC_MAX_SOURCES_PER_ROUND` changed from 16 to 32,
then restore the runtime source before execution. Use the same 256 unique
128 KiB pressure workload/configuration as the phase diagnostic above, without
phase hooks. The control is the preceding single-envelope candidate, not the
older pre-accounting ELF. All 256 trial samples pass.

| Entire workload | 16-source control | 32-source trial |
| --- | ---: | ---: |
| GC rounds | 4 | 2 |
| Source segments reclaimed | 64 | 64 |
| GC copied blob bytes | 7,282,624 | 7,557,440 |
| Read requests | 2,758 | 2,322 |
| Read bytes | 53,751,808 | 52,068,352 |
| Write requests | 2,882 | 2,858 |
| Write bytes | 98,754,560 | 98,484,224 |
| Flushes | 825 | 809 |

Total read requests decrease 15.81%, read bytes 3.13%, write bytes 0.27% and
flushes 1.94%. GC read requests alone decrease from 1,395 to 959. Both reclaim
64 source segments, but the trial copies 274,816 additional blob bytes and
moves the second pressure event from sample 234 to 236. This is a whole-run
comparison with changed GC scheduling, not identical per-round work.

Observed operation sums are 58.820141 versus 34.266323 seconds. The control's
host variation and unrepeated sequential measurements prevent attributing this
large timing difference to the change. Trial pressure operations take 3.300692
and 4.216592 seconds; larger individual rounds can still worsen pause bounds
on other liveness distributions or slow devices. The trial stopped image
passes the independent default verifier with 256 CAS objects and its unmanaged
prefix baseline.

**Production source remains capped at 16.** The evidence supports investigating
amortized manifest loading/round overhead with a bound on copied bytes or an
explicit maintenance budget. It does not qualify an unconditional larger pause
cap, and no new 32-source fault-injection or real-SD qualification is claimed.
Evidence: `target/storage-gc-source32-trial-20260912/`, including the exact
one-line trial, restoration hashes, build/ELF, commands, telemetry, raw samples,
GC records, comparison and independent image verification.

### Bounded extension of low-copy GC rounds (2026-09-13)

Retain a bounded version of the preceding 32-source experiment. Ordinary
prefixes through 16 sources retain their previous selection rules. A larger
prefix may contain at most 32 sources, at most 4 MiB of authoritative live Blob
payload, and at most six relocation target segments. Exact placement includes
rewritten manifests, catalog/authority/allocation roots, record framing and
padding; the separate G+2 barrier reservation remains additional. The running
Blob-byte sum uses checked arithmetic over the existing authoritative ranking.
All existing target-capacity, memory admission and net-yield checks remain.
No extra allocation is introduced for the byte sum. These are work bounds,
not a millisecond deadline or a universal 4 MiB bound for ordinary dense rounds.

The added integration test retains 40 unique objects for both 4 KiB and
512 KiB payloads, runs three collections each and cold-mounts/reads the first
and last chunk of every object after every round. It proves that the fixture
actually exercises both >16-source bounded extension and >4 MiB ordinary
fallback. Existing retained-manifest corruption/pointer-stability coverage is
preserved with 20 dead writes instead of ten per round. That fixture now uses
full CAS snapshots explicitly because its raw helper reads the checkpoint's
base snapshot rather than replaying catalog deltas. The initial failures and
corrected runs remain in evidence; no integrity assertion was removed.

All 25 GC integration tests pass, including existing mutation/cancellation
recovery coverage; all 280 feature-enabled unit tests pass (one ignored).
Default QEMU file-tree passes three boots, GC/cold recovery and powered-off
verification. Duo release compile check passes. These do not establish SD
latency or exhaustive large-source fault coverage.

| 256 unique 128 KiB operations | 16-source control | Bounded extension |
| --- | ---: | ---: |
| GC rounds | 4 | 2 |
| Source segments reclaimed | 64 | 63 |
| GC copied blob bytes | 7,282,624 | 7,420,032 |
| Read requests | 2,758 | 2,313 |
| Read bytes | 53,751,808 | 51,748,864 |
| Write requests | 2,882 | 2,857 |
| Write bytes | 98,754,560 | 98,324,480 |
| Flushes | 825 | 809 |

Default full writer, 64 cache pages, 128 MiB, one TCG hart, 4/2 MiB/s and
400/200 read/write IOPS, with host telemetry. No heavy build/test overlaps this
performance run. All 256 samples pass; the stopped image passes independent
verification with 256 CAS objects and its unmanaged-prefix baseline. Total
read requests decrease 16.13%, read bytes 3.73%, write bytes 0.44%. GC reads
alone fall from 1,395 to 950 requests. The new rounds select 32 and 31 sources,
copying 3,297,792 and 4,122,240 bytes: the second stops before exceeding 4 MiB.
The second pressure event moves from sample 234 to 236, and total reclaimed
sources differ by one; this is an end-to-end workload comparison, not an equal
source-set microbenchmark. Free segments after the final pressure event are 37
in both cases.

Observed operation sums are 58.820141 versus 34.559880 seconds and candidate
pressure operations take 3.306981/4.108337 seconds. The noisy historical control
and single candidate run do not support a replicated latency claim. The
request-count result is the retained performance evidence; real SD behavior
and latency tails remain unmeasured.

Evidence: `target/storage-gc-bounded-round-20260912/` (started before midnight),
including the before source, build/ELF, commands, raw samples/telemetry, GC
records, comparison, independent image report, all test logs and saved
file-tree evidence. `final-source.json` records the comment-only clarification
after the measured build and tests. Production now uses the bounded extension;
the earlier unconditional 32-source trial remains unretained.

### Extended-round mutation and cancellation recovery matrix (2026-09-13)

Strengthen the retained bounded-GC optimization with an integration fault
matrix that actually selects 32 sources and copies live Blob payloads. The
96-segment fixture retains 20 distinct 4 KiB objects and copies 46,816 encoded
Blob bytes across 145 write/flush mutation boundaries. Seven failure modes at
every boundary produce 1,015 cases: not-submitted failure, ambiguous failure
with no/visible/durable effects, and pending cancellation with the same three
effects. The ordinary fixture still exercises all three allocated sources,
47 boundaries and 329 cases.

For every case, require the failed/cancelled instance to demand recovery; cold
mount must select G, G+1 or G+2. Selected sources must respectively be Allocated,
Retired with the correct generation, or Free. Unselected allocated segments
must remain allocated. Resume incomplete collections through G+2, cold-mount
again, compare all original object-to-Blob bindings, and compare each complete
encoded object (including Merkle tree) with an independently encoded expected
value. The matrix uses full input CAS snapshots for direct binding comparison;
it does not claim catalog-delta-specific fault coverage.

The first harness revision shared a runtime context across independent fault
cases and correctly encountered RecoveryRequired from prior poison state.
The final harness gives every instance an independent context and verifies
content directly from the cold recovered image. A temporary test compile error
used BlobKey from the wrong crate; corrected logs are retained alongside the
initial attempts. No runtime correction was necessary.

Final full GC integration suite: 26 passed, zero failed, including the extended
1,015-case matrix, ordinary 329-case matrix, and existing acknowledged-corruption
checks. This adds large-source boundary coverage for failure/cancellation;
acknowledged-corrupt-media coverage remains the existing separate fixture.
No new runtime change, QEMU timing run or SD performance claim in this turn.
Evidence: `target/storage-gc-extended-faults-20260913/`, including before/final
test source hashes and complete final test output.

### Bounded GC on 4 KiB objects, limited QEMU ABBA (2026-09-13)

Run saved single-envelope/16-source and bounded-extension ELFs in A-B-B-A
order, each from the same blank template with 256 unique 4 KiB durable put/get
samples (seeds 32..287). Default full writer, 64 cache pages, 128 MiB, one TCG
hart, 4/2 MiB/s and 400/200 read/write IOPS, host telemetry on, zero warmups.
Current GC source hash matches the bounded build's final manifest; subsequent
changes are tests/docs. No build or heavy verification overlaps timed runs.
All 1,024 samples pass. Each version's two repetitions have exactly identical
per-sample seven I/O counters and GC records.

| Per 256-operation run | 16-source | Bounded extension |
| --- | ---: | ---: |
| Read requests | 1,565 | 1,130 |
| Read bytes | 8,097,792 | 5,935,104 |
| Write requests | 1,857 | 1,830 |
| Write bytes | 53,694,464 | 53,137,408 |
| Flushes | 825 | 809 |
| GC rounds | 4 | 2 |
| Source segments reclaimed | 64 | 64 |
| GC copied encoded Blob bytes | 237,440 | 246,400 |

Read requests decrease 27.80%, read bytes 26.71%, write bytes 1.04% and flushes
1.94%. GC read requests alone decrease from 1,283 to 848. Candidate GC copies
107,520/138,880 bytes per round, well inside the 4 MiB extension bound. The
second pressure sample moves from 234 to 236; this is the complete workload's
I/O outcome, not identical per-round source selection. The retained candidate
image independently verifies status ok with 256 CAS objects and its unmanaged
prefix baseline.

| Observed timing | A1 | B1 | B2 | A2 |
| --- | ---: | ---: | ---: | ---: |
| Operation sum seconds | 11.946225 | 38.455633 | 11.424816 | 15.483013 |
| Median operation ms | 28.876 | 101.505 | 34.395 | 43.063 |
| Pre-first-GC sum, samples 0..205, seconds | 6.243298 | 33.562477 | 6.466178 | 8.871970 |

Do not discard B1. All-run means are 13.714619 versus 24.9402245 seconds; the
candidate mean is worse by 81.85%, with within-version spreads of 25.79% for A
and 108.38% for B. These runs do not establish an overall latency improvement.
The first 206 samples have identical physical counters across all four runs,
before this GC selection change is exercised. B1's QEMU CPU accumulation
between first/last polls is 9.04 seconds (others 9.17/10.31/10.46), while its
host load-1 peaks near 33 and its poll interval spans 116.16 seconds (others
78.80–83.00). These coarse intervals include boot and quiet gaps; this is
correlation supporting environmental variation, not per-operation CPU or a
causal scheduling diagnosis. No SD latency claim is made.

Evidence: `target/storage-gc-bounded-4k-abba-20260913/`: commands/ELF hashes,
all raw samples and serial logs, telemetry, exact repeated-counter assertions,
summary, timing diagnostic and independent stopped-image report. This turn
adds repeatable small-object I/O evidence and retains the noisy timing result;
no additional runtime change.

### GC live-byte ranking uses existing sorted IDs (2026-09-13)

`ranked_gc_sources` previously located the allocated segment for each live
extent with a linear `iter_mut().find`. The table is constructed in strictly
ascending segment-number order and is sorted by live bytes only after all
accumulation completes. Use binary search on that existing segment-number
order, then update the same entry with checked byte addition.

For E live extents and S allocated segments, the lookup component changes from
O(E*S) to O(E*log S). Initial allocation traversal and final live-byte sort are
unchanged. No second index, allocation, cache or device operation is added.
Missing/free/out-of-range source references still report corruption; byte-sum
overflow still fails. Final ordering remains (live bytes, segment number),
including deterministic equal-byte ties.

Both ranking tests pass. The new case uses sparse allocated IDs, several
extents on one source, zero-live segments, equal-live ties, invalid source IDs
and overflow. All 26 GC integration tests pass, including extended 32-source
failure/cancellation recovery and complete object/binding checks. Default QEMU
file-tree passes three boots with GC, cold recovery and powered-off validation;
Duo release compile check passes. No timing benchmark or new physical-I/O
reduction is claimed for this CPU-work optimization.

Evidence: `target/storage-gc-rank-lookup-20260913/`, with before/after source,
hash, ranking and full GC logs, default QEMU gate/evidence, and Duo compile log.

### Fixed-size output for streaming Merkle node reads (2026-09-13)

Full streaming verification and single-chunk proofs previously allocated a
32-byte Vec for every stored Merkle node read. `ManifestRangeReader` now shares
its existing range/pointer validation and page-window logic through a private
generic output constructor: ordinary reads still create a fallible Vec after
validation, while `read_hash` returns a fixed `[u8; 32]`. Tree emission checking
and proof sibling gathering consume that array directly. Hash/content window
selection, read-ahead, failed-read invalidation and every hash comparison are
unchanged; no new cache or weaker verification path is introduced.

An isolated host allocator probe uses a preallocated page device, creates the
object outside measurement, then measures public full verification and the
first verified chunk separately. Before/after read page counts are identical;
all calls perform zero writes/flushes. The full-mode allocation reductions equal
all padded tree nodes, and chunk-mode reductions equal proof height.

| Operation / size | Allocation calls before → after | Requested bytes before → after | Peak extra bytes before → after | Read pages |
| --- | ---: | ---: | ---: | ---: |
| Full / 4 KiB | 11 → 10 | 54,400 → 54,464 | 37,416 → 37,512 | 11 |
| Full / 128 KiB | 105 → 42 | 310,336 → 308,416 | 144,128 → 144,192 | 43 |
| Full / 1 MiB | 779 → 268 | 1,259,424 → 1,243,168 | 157,024 → 157,088 | 274 |
| Chunk / 4 KiB | 7 → 7 | 16,824 → 16,824 | 12,344 → 12,344 | 3 |
| Chunk / 128 KiB | 14 → 9 | 21,240 → 21,080 | 16,632 → 16,600 | 4 |
| Chunk / 1 MiB | 19 → 11 | 30,120 → 29,864 | 25,160 → 25,128 | 6 |

This removes 511 node allocations from a 1 MiB full verification, but does not
reduce its peak: the measured host peak rises by 64 bytes (96 for 4 KiB full).
For 4 KiB full verification, gross requested bytes also rise by 64 despite one
fewer allocation. Retain as a reduction in repeated allocation work for larger
trees, not a universal memory-footprint improvement. These are host requested
allocations, not a guest heap watermark, device throughput or SD latency result.

All 281 feature-enabled unit tests pass (one ignored), including streaming and
proof corruption coverage. All 26 GC integration tests pass, including the
extended failure/cancellation matrix. Default QEMU file-tree passes three boots,
GC pressure, cold recovery and powered-off verification; Duo compile check
passes. No performance timing run in this turn.

Evidence: `target/storage-merkle-node-buffer-20260913/`, including before/after
source, exact allocation probe logs, parsed differences/assertions, source
hashes, unit/GC logs, QEMU evidence and Duo build log. The reproducible ignored
probe is `streaming_blob_verification_requested_allocation` in
`segment-store/tests/authority_publication_memory.rs`; run it alone with
`--ignored --nocapture --test-threads=1`.

### Fill the verified large-object result directly (2026-09-13)

`read_and_verify_resolved_blob` already reserved the complete logical output,
but allocated a temporary Vec for each leaf and copied that leaf into the
output after hashing. Initialize the reserved result and pass each checked
output slice to the existing range reader's output constructor. Stream the
same slice into the Merkle builder, then verify all emitted tree nodes as
before. Checked filled/end offsets and the final filled-length assertion cover
short final leaves. The buffer stays private until the complete tree and final
descriptor pass; failures/cancellation cannot return partial unverified data.

Extend the isolated persistent-object allocation probe with a 512 KiB object,
whose encoded envelope exceeds the 512 KiB batched-read threshold. For both
zero and 256 historical records, full read allocation calls decrease from 140
to 12, exactly removing 128 leaf allocations. Requested extra peak decreases
from 673,168 to 669,056 bytes (4,112 bytes). Read pages remain 144; writes and
flushes remain zero. At 4/64/128/360 KiB, the existing batched path keeps identical
allocation-call/page counts; measured peak decreases by 16 bytes in each case.
These are host requested-allocation measurements, not guest heap/RSS or SD
latency. No performance timing claim is made.

The existing proof/full-read test now includes 512 KiB + 37 bytes to exercise
an incomplete final leaf alongside its existing 360 KiB through 64 MiB cases,
exact proof-page checks and corruption rejection. All 281 feature-enabled unit
tests pass (one ignored); all 26 GC integration tests pass. Default QEMU
file-tree passes three boots, GC pressure, cold recovery and powered-off image
verification; Duo release compile check passes.

Evidence: `target/storage-direct-read-output-20260913/`: before/after source,
allocation logs and parsed differences, source hashes, full test logs, QEMU
logs/evidence and Duo check. The probe remains
`persistent_object_read_requested_allocation` with
`--ignored --nocapture --test-threads=1`. Runtime changes are confined to the
large-object read/output path; no durable format or device-I/O change.

### 1 MiB QEMU timing for the two read-allocation optimizations (2026-09-13)

Build both ELFs from the current runtime, changing only CAS read code between
the pre-node-array/pre-direct-output source and the current two optimizations.
Other runtime code, including bounded GC and ranked-source lookup, is common.
Temporary source switches and the 64-page cache override are restored exactly
before execution. Each A-B-B-A sequence performs 16 unique 1 MiB
`object-v2-large` samples per fresh image, seeds 32..47, 128 MiB, one TCG hart,
zero warmups and host telemetry. One sequence uses 4/2 MiB/s and 400/200
read/write IOPS; the other removes only those four limits and reuses the same
ELFs. No build/heavy verification overlaps timing. All 128 samples pass; there
are no GC rounds in these runs.

All seven physical counters match for each sample between builds and repeats.
Aggregate I/O is also identical between throttle modes: 256 reads / 18,239,488
read bytes, 368 writes / 20,357,120 write bytes, and 56 flushes per 16 samples.
Both retained stopped images independently verify status ok and 16 CAS objects
with their unmanaged-prefix baseline. Telemetry reports no polling errors.

| Mean operation sum for 16 samples | Control seconds | Current seconds | Change |
| --- | ---: | ---: | ---: |
| Limited | 12.088393 | 12.0541975 | -0.28% |
| No configured I/O limits | 3.2946185 | 2.9353395 | -10.91% |

Limited totals are 12.025968/12.150818 for A and 11.993798/12.114597 for B;
within-pair spreads are 1.03%/1.00%. Put means change 8.9687655→8.873950 seconds
(-1.06%) while get means change 3.1196275→3.1802475 seconds (+1.94%). Thus this
limited run does not demonstrate a read or overall latency improvement.

Without configured limits, totals are 3.254848/3.334389 for A and
2.901644/2.969035 for B; spreads are 2.41%/2.30%. Put means change
2.085164→1.8560675 seconds (-10.99%) and get means change
1.2094545→1.079272 seconds (-10.76%). These repeated local QEMU observations
support a runtime benefit when I/O limits do not dominate. They are not a
pure CPU measurement, sustained throughput or real-SD latency qualification.
Operation sums exclude runner quiet gaps. The combined comparison does not
attribute the timing effect separately to node arrays versus direct output.

Evidence: `target/storage-large-read-abba-20260913/` and
`target/storage-large-read-unthrottled-20260913/`, with exact before/after source,
source restoration hashes, build logs, ELFs/command hashes, raw samples,
serial/host telemetry, repeated-counter assertions, phase-effect summaries
and independent image reports. No additional runtime change in this turn.

### Physical write-size trace for 1 MiB objects (2026-09-13)

Use QEMU's `virtio_blk_handle_write`, `virtio_blk_handle_read` and
`blk_co_pwritev` tracing on the saved current 1 MiB ELF. Four unique
`object-v2-large` samples use the same 64-page-cache/128 MiB/single-hart limited
configuration as the preceding timing comparison. All four samples pass and
every sample's seven counters exactly matches the untraced current run.
Diagnostic timings are excluded.

The trace contains 113 writes / 5,218,304 bytes. Exclude the leading 15 boot
writes / 114,688 bytes, ending with control activation writes; the remaining
98 requests / 5,103,616 bytes reconcile with the workload. Partition this
ordered suffix by each sample's request count and independently assert every
sample's byte sum. QEMU's text trace has no timestamps here, so this is ordered
counter reconciliation, not time-based attribution. The exact wrapper and
actual injected QEMU arguments are saved.

Sample 1 (zero-based, after the first growth/setup sample) has 22 write requests:

| Request bytes | Count |
| ---: | ---: |
| 4,096 | 6 |
| 8,192 | 3 |
| 16,384 | 2 |
| 20,480 | 1 |
| 32,768 | 1 |
| 73,728 | 1 |
| 131,072 | 8 |

The eight 128 KiB writes are contiguous. They already meet the configured
single-request limit: virtio-core `BLOCK_MAX_TRANSFER_SIZE` is 128 KiB and
SDHCI `MAX_TRANSFER_BLOCKS` is 256 × 512 bytes. The platform splits writes at
`MAX_PAGES_PER_REQUEST`, so increasing only the CAS streaming buffer cannot
reduce those physical requests. These are software-configured bounds, not a
claim about the controller's hardware maximum.

The final three 4 KiB writes target sectors 2088, 2080, 2088: checkpoint slot
0's clear-seal/body/seal protocol (V2 starts at sector 2048). Required intervening
flush/readback ordering prevents blindly coalescing them. The remaining smaller
writes include noncontiguous layout/framing work; the trace does not justify
removing durability boundaries or adding a larger generic write buffer. Further
request reduction needs a specific ordering-safe metadata batching change or
a separately qualified device transfer-limit change.

The stopped image independently verifies status ok with four CAS objects and
its unmanaged-prefix baseline. No runtime change in this turn. Evidence:
`target/storage-large-write-trace-20260913/`: event list, tracing wrapper,
actual QEMU arguments, raw trace, raw benchmark/serial/host logs, per-sample
write profile, counter reconciliation and independent image report.

### Staged large-object canonical header batching (2026-09-13)

Retain the canonical 4 KiB header in the existing staged-publication PageSink,
only after streaming content/tree buffers have drained. Physical sorting then
combines this page with its adjacent descriptor pages. The ordinary public
streaming `BlobWriter::commit` retains its prior header submission behavior;
this change must not create a metadata sink for that path. Compact encoding
is unchanged. Dedup comparison reads the retained header through the existing
sink overlay, and publication still drains and authenticates the target before
checkpointing. Checkpoint clear/body/seal and flush ordering are unchanged.

Compare four unique 1 MiB `object-v2-large` samples (seeds 32–35) against the
preceding physical-write trace, using the same 64-page cache, 128 MiB, one-hart
QEMU configuration and 4/2 MiB/s, 400/200 IOPS read/write limits. Each sample
passes and saves exactly two physical write requests. Aggregate writes fall
98 → 90 at identical 5,103,616 bytes; all read counters and flush counts are
unchanged. Stable sample 1 falls 22 → 20 writes (9.1%). Its separate 4 KiB
header at sector 34976, 16 KiB prefix at 34944 and 8 KiB descriptor pair at
34984 become one 28 KiB request at 34944. The final checkpoint writes remain
sectors 2088 / 2080 / 2088. Trace reconciliation excludes the same 15 boot
writes and checks each sample's byte sum. These are request-count results;
traced timings are excluded and no real SD latency benefit is claimed.

Four additional all-duplicate 1 MiB samples pass on a fresh image. Independent
powered-off verification accepts both images: unique run has four CAS objects
and four blobs; duplicate run has four CAS objects and one blob. These are
boot-local benchmark handles, not four persisted authority grants. The mixed
batch regression now includes both 4 KiB and 512 KiB + 37 byte pairs, exercises
same-batch duplicate scratch disposal, verifies all returned content and checks
cold-mount object/blob counts.

The existing isolated allocation probe, at histories 0 and 256 and sizes
4/64/128/360/512 KiB, reports identical allocation calls, requested bytes and
peak extra heap against the preceding direct-read-output baseline. This is
an observed whole-operation peak, not a claim that retaining one header costs
no resident memory. For 360 and 512 KiB imports, write requests fall by two
at each history length; read/write pages and flushes are unchanged. Full-read
allocation and read-page measurements are unchanged.

Validation: final runtime passes 281 feature-enabled unit tests (one ignored),
26 GC recovery tests, all six fused-append recovery tests (including large,
1 MiB, external 2 MiB and small external cut-boundary scenarios), the separately
rerun expanded mixed-batch test, default three-boot QEMU file-tree regression,
and Duo release compile check. The unit suite preceded the test-only mixed-batch
expansion; that expanded test then passed separately. Temporary cache override
is restored and hash-checked. No real-device test or durability relaxation.

Evidence: `target/storage-large-header-batch-20260913/` contains before-source,
build/source manifests, ELF, trace/actual QEMU arguments, request profile and
reconciliation, unique/duplicate serial and benchmark logs, retained images,
independent image reports, allocation output, final test/build logs and copied
QEMU functional evidence. Intermediate `unit.log`/`gc-recovery.log` belong to an
earlier broader buffering trial; use `unit-final.log`/`gc-recovery-final.log`
for the retained runtime. The benchmark ELF precedes only the test-only fixture
expansion recorded by `final-source.json`.

### Bounded first-dedup comparison reads (2026-09-13)

The same-layout first-dedup path in `compare_manifests` previously alternated
single-page reads of scratch and existing payloads. It now compares up to eight
adjacent pages per side, with fallible buffers bounded to 64 KiB total (previous
simultaneous page buffers: 8 KiB). It still scans existing segment descriptors,
compares every exact payload byte, hashes the entire existing payload, and checks
both the pointer hash and freshly computed scratch hash. Short-tail handling and
cross-layout fallback are unchanged. Overlay reads preserve the staged header
from the preceding optimization. No successful-verification cache policy changes.

Four all-duplicate 1 MiB QEMU samples use the preceding header-batching ELF as
control and the same fresh image template, seeds 32–35, 64-page cache, 128 MiB,
one hart, and 4/2 MiB/s / 400/200 IOPS limits. All pass. At sample 1, the first
actual dedup comparison, physical reads fall 573 → 101 (82.4%) and read bytes
3,530,752 → 3,518,464. Its 16 writes / 1,179,648 bytes and three flushes remain
identical. Samples 0, 2 and 3 have identical physical counters: new content and
subsequent verified dedup hits are unaffected. The small byte-count difference
is observed with the platform cache; it is not a reduction in required comparison
coverage. A single pair does not establish latency improvement or real SD
performance. No timing claim is made.

Independent stopped-image verification reports status ok, four CAS objects and
one unique blob. All 13 CAS streaming tests pass, including a new corruption
regression at pages 0, 7, 8, 255 and short-tail page 256 of a 1 MiB + 37-byte
object before its first dedup attempt. The existing mixed compact/large staged
batch test and all six fused-append cut-boundary tests pass. Default three-boot
QEMU file-tree regression also passes.

Evidence: `target/storage-dedup-compare-batch-20260913/` contains the before source,
candidate build and source manifests, benchmark/serial/host logs, comparison
JSON, retained disk, independent verifier report, functional logs and an isolated
requested-allocation comparison. The added allocation probe measures commit after
writer content has already been buffered; its baseline is not total heap usage.

The isolated allocation probe compares identical new test code against before
and after runtime source, restoring the candidate by byte equality and hash.
For first duplicate commits, allocation calls are 88 → 86 at 4 KiB,
216 → 152 at 128 KiB, and 617 → 93 at 1 MiB + 37. Requested bytes at the latter
size fall 2,644,980 → 613,364. Extra commit peaks are respectively unchanged
130,348; **181,968 → 214,736 (+32,768 bytes)**; and unchanged 28,864. The last
number is relative to live allocations after streaming, including buffers freed
during commit; it does not contradict the 64 KiB simultaneous comparison bound.
Host read-page counts are identical in each pair, and all nonduplicate commit
measurements are unchanged. The higher 128 KiB peak is an accepted bounded cost
of reducing device requests. The initial new probe compilation used a private
read API and failed; the retained probe uses the public full verifier and passes.

Duo release `file-tree,legacy-shell` compile check passes. Both temporary source
substitution and cache configuration are restored and hash-checked. Real SD
hardware qualification remains outstanding.

### ABBA timing qualification of first-dedup batching (2026-09-13)

Run saved header-batching control and dedup-read-batching candidate ELFs in
ABBA order, each on a fresh disk with four all-duplicate 1 MiB samples, seeds
32–35, 64-page cache, 128 MiB and one hart. Repeat the same ABBA sequence with
only QEMU throttling removed. Limited mode uses 4/2 MiB/s and 400/200 read/write
IOPS. Host telemetry is enabled consistently; no build or heavy verification
runs overlap either sequence. There are 32 successful samples total, but only
**two first-dedup observations per build per mode**. This is a small paired
qualification, not a distribution or p99 claim.

| First-dedup phase mean | Limited before | Limited after | Unthrottled before | Unthrottled after |
| --- | ---: | ---: | ---: | ---: |
| put | 1,746.421 ms | 929.291 ms | 153.5665 ms | 98.576 ms |
| following get | 188.1905 ms | 280.082 ms | 34.593 ms | 33.7765 ms |
| put + get | 1,934.6115 ms | 1,209.373 ms | 188.1595 ms | 132.3525 ms |

Limited first-dedup put improves 46.79%, but its following get regresses 48.83%;
combined latency improves 37.49%. The before/after pair spreads for combined
latency are 0.69% / 0.36%. Unthrottled combined latency improves 29.66%, with
pair spreads 8.94% / 2.50%; get's 2.36% mean improvement is smaller than its
repeat spread, so it is not a demonstrated independent get speedup. The get
regression is associated with the throttled execution here; throttle-credit
interaction is a hypothesis, not a measured causal attribution.

Every per-sample physical counter repeats exactly within each build and also
matches across throttle modes. First-dedup put reads fall 558 → 88 at identical
2,424,832 bytes. The following get reads fall 15 → 13 and 1,105,920 → 1,093,632
bytes; reporting only overall reads would conflate this small cache effect with
the comparison batching. New content and subsequent verified-hit samples have
unchanged physical counters. Independent stopped-image verifiers accept both
candidate images. Current runtime source is hash-checked against the benchmark
candidate; no runtime change in this qualification turn.

Evidence: `target/storage-dedup-limited-abba-20260913/` and
`target/storage-dedup-unthrottled-abba-20260913/` retain commands and ELF hashes,
all serial/sample/host logs, analysis scripts and raw phase/counter summaries,
candidate images and offline verifier results. These timings apply to this
QEMU configuration, not real SD hardware or sustained mixed-workload service.

### Comparison-local segment proof reuse (2026-09-13)

Same-layout multi-extent dedup comparison now uses a single-entry
`VerifiedSegmentScans` memo, bounded to 4 KiB, created and discarded within the
comparison. Adjacent extents of the same sealed segment reuse its freshly
verified descriptor/summary/seal chain. Single-extent objects skip memo creation;
cross-layout fallback is unchanged. Oversized proofs or failed optional memo
allocation still use the ordinary scanner. Each pointer is interpreted against
the verified proof, and every payload remains independently read, byte-compared
and hashed. No proof carries trust into a subsequent comparison invocation.

Four all-duplicate 1 MiB samples, on the same 64-page-cache / 128 MiB / one-hart
QEMU setup with 4/2 MiB/s and 400/200 IOPS limits, pass. Against the preceding
batched-read candidate, first-dedup put reads decrease 88 → 83 requests and
2,424,832 → 2,367,488 bytes (five requests / 56 KiB saved). Its get counters stay
13 requests / 1,093,632 bytes; write counters and flushes are unchanged. The
other three samples have identical physical counters. Overall first-dedup reads
are 101 → 96. This single counter comparison is not a latency claim.

The existing isolated requested-allocation probe, at 1 MiB + 37 bytes, reports
first-dedup commit read pages 624 → 582, calls 93 → 85, requested bytes
613,364 → 513,004, and unchanged extra peak 28,864. Peak is relative to the
already-buffered writer and is not total heap use. All measurements for
4/128 KiB and for nonduplicate commits are unchanged. Initial trial memoized
single-extent objects too; the retained version explicitly skips them. Use
`memory-final.log`, `cas-streaming-final.log`, `final.elf` and
`sources-final.json` for retained-code evidence, not the initial trial logs.

All 13 streaming tests pass, including first-dedup payload corruption at batch
boundaries and a short tail. Independent powered-off image verification accepts
four CAS objects sharing one blob. Evidence:
`target/storage-dedup-local-scan-20260913/`, including before/trial/final source
provenance, build/benchmark logs, retained image, comparison script and JSON,
allocation results and offline verifier output. Temporary cache configuration
and current source hashes are checked against the final build manifest.

Final gates also pass: 11 memo-filtered unit tests (including budget/horizon
coverage), the mixed compact/large duplicate batch test, all six fused-append
recovery tests, default three-boot QEMU file-tree regression and Duo release
`file-tree,legacy-shell` compile check. QEMU functional logs/reports are copied
into the evidence directory. Real SD validation remains outstanding.

### Multi-segment qualification of local dedup proofs (2026-09-13)

Compare the preceding batched-read ELF with the comparison-local proof ELF at
4 MiB + 37 and 16 MiB + 37 logical bytes. Each fresh QEMU VM performs three
all-duplicate operations: new content, first dedup, subsequent verified hit.
Order is before4 / after4 / after16 / before16. Configuration is unchanged:
64-page cache, 128 MiB, one hart, 4/2 MiB/s and 400/200 read/write IOPS, with
consistent host telemetry. No build or heavy verifier overlaps the benchmark.
All 12 operations pass exact guest content/descriptor readback. This is one
counter comparison per size, not a latency distribution or ABBA timing claim.

| Logical bytes | First-dedup put read requests | First-dedup put read bytes | Saved |
| ---: | ---: | ---: | --- |
| 4,194,341 | 312 → 294 | 9,351,168 → 9,138,176 | 18 requests / 208 KiB |
| 16,777,253 | 1,173 → 1,123 | 36,667,392 → 36,061,184 | 50 requests / 592 KiB |

Every get counter, write counter and flush count is unchanged. New-content and
subsequent verified-hit operations have identical physical counters. The bounded
one-entry memo therefore continues reducing repeated segment proof reads across
these larger layouts; it does not need a whole-object proof cache to do so.
Both stopped candidate images independently verify status ok, each with three
CAS objects sharing one blob. These are boot-local benchmark object identities.

Extend the existing isolated first-dedup allocation probe with 4 MiB + 37, running
identical probe code against before/after runtime and restoring the candidate by
byte equality plus hash. First-dedup commit read pages fall 2,244 → 2,178;
allocation calls 144 → 130; requested bytes 1,058,620 → 891,620. Extra commit peak
is unchanged at 78,016 bytes. Nonduplicate measurements are unchanged. The probe
baseline includes the already-buffered writer; this is neither total heap nor a
16 MiB memory measurement. The 16 MiB QEMU run demonstrates successful execution
within this guest configuration, not precise peak allocation accounting.

Evidence: `target/storage-dedup-multisegment-20260913/` retains saved-ELF hashes,
commands, all sample/serial/host logs, comparison script and JSON, both candidate
images and offline verifier reports, before/after memory logs and restored source
hashes. Runtime source is unchanged in this turn; only the ignored allocation
probe gains the larger case. Real SD performance qualification remains pending.

### Current file-tree phase profile and recent CAS comparison (2026-09-13)

Profile current 16/64 MiB `file-sequential` on fresh QEMU disks, then compare
64 MiB with the saved pre-header-batching ELF from
`storage-large-read-abba-20260913/after.elf`. Current ELF is the final local-dedup
proof candidate. Both include the preceding direct full-read improvements;
recent differences are header batching and the two dedup comparison optimizations.
Use seed 71, 64-page cache, 128 MiB, one hart, no warmup, one sample per fresh VM,
4/2 MiB/s / 400/200 read/write IOPS and consistent host telemetry. No heavy work
overlaps benchmark runs. All three samples validate and perform exact full
content readback before deleting the file. This is not a write-only workload,
and the single pair supports physical-counter comparison, not a speed bound.

| Current workload phase | 16 MiB reads/writes/flushes | 64 MiB reads/writes/flushes |
| --- | ---: | ---: |
| stage | 31 / 189 / 10 | 376 / 727 / 26 |
| publish | 1 / 6 / 3 | 1 / 6 / 3 |
| verify | 262 / 0 / 0 | 1,078 / 0 / 0 |
| remove | 2 / 6 / 3 | 2 / 6 / 3 |

Current totals are 201 writes / 18,157,568 bytes at 16 MiB and 739 writes /
71,430,144 bytes at 64 MiB. Host-block write amplification against logical file
bytes is 1.082275 and 1.064392 respectively, including publication and removal.
This excludes any internal SD-card FTL amplification. Read totals are 296 /
17,907,712 bytes and 1,457 / 72,392,704 bytes.

At 64 MiB the control has 783 writes and the candidate 739 (44 fewer, 5.62%).
All savings occur in stage: 771 → 727 requests at identical 71,118,848 bytes.
Every read counter, total write bytes and all 32 flushes remain identical;
publish/verify/remove physical counters are identical. The 44 saved writes are
consistent with two header-adjacent requests per each of 22 staged chunks;
this phase-level experiment does not separately trace their addresses.

The stager uses 3 MiB persistent chunks and four-chunk batches, bounded to 12 MiB
of content capacity. At 64 MiB, verification alone reads 69,910,528 bytes in
1,078 requests, while all pre-verification staging reads total 2,449,408 bytes.
A future request-size trace should therefore examine full file-data verification,
rather than assume that another write-buffer increase will reduce byte traffic.
Current stage buffering and durability boundaries are unchanged in this turn.

Evidence: `target/storage-file-current-profile-20260913/` retains source/ELF
hashes, commands, sample/serial/host logs, per-phase comparison JSON, retained
images and independent verifier reports. Since the workload removes its file,
powered-off image validation is complementary format/recovery evidence, not a
replacement for the guest's complete live content comparison. Real SD hardware
performance remains unverified.

### Physical read trace of full file verification (2026-09-13)

Trace one current 64 MiB `file-sequential` run with the same ELF/configuration
as the preceding phase profile. All seven physical counters exactly match that
untraced run and guest full-content verification passes. Exclude leading boot
reads, partition the remaining ordered read stream by existing stage/publish/
verify/remove request counters, and independently check every phase's byte sum.
QEMU text events have no timestamps here: this is ordered counter reconciliation,
not time-based attribution. Timings from this diagnostic are excluded.

Verification accounts for 1,078 reads / 69,910,528 bytes. Use the existing raw-image
parser to verify all 28 touched segments, including descriptor chains and payload
hashes, and classify read pages by their physical extent ranges; all parse checks
pass. Canonical header/content/tree labels follow the split extent indices, and
non-payload pages are grouped as framing/anchor. Result:

| Physical extent category | Requests by size | Total bytes |
| --- | --- | ---: |
| canonical content | 67 × 4 KiB; 21 × 124 KiB; 491 × 128 KiB | 67,297,280 |
| canonical header | 46 × 4 KiB | 188,416 |
| canonical tree | 288 × 4 KiB; 88 × 8 KiB | 1,900,544 |
| catalog | 46 × 4 KiB | 188,416 |
| framing/anchor | 21 × 8 KiB; 10 × 16 KiB | 335,872 |

Repeated physical page reads within the verification phase total 192 pages /
768 KiB: tree pages 480 KiB, and catalog/header/content pages 96 KiB each. These
are actual backend repeat reads, not merely repeated logical cache accesses.
Content bulk requests already use 128 KiB or extent-boundary tails; tree requests
are a more specific target than increasing the general content read-ahead window.

Source inspection finds a candidate redundant operation in
`read_fs_data_chunk`: each skip-list hop recovers a node with
`read_fs_data_node_meta` (directed first-leaf verification for large nodes), then
the final target goes through `read_fs_data_node_content` and full verification.
A proposed follow-up is to decode and validate the final target metadata from
its fully verified bytes, while keeping directed verification for intermediate
hops and preserving all index/total-length/reference checks. The trace does not
assign every small request to this caller, and this proposal is not implemented
or claimed as a measured saving in this turn.

Evidence: `target/storage-file-read-trace-20260913/` retains the event list,
tracing wrapper and actual QEMU arguments, raw trace/sample/serial/host logs,
ordered reconciliation script/profile, extent classification script/report,
stopped image and independent format verifier report. No runtime change or
real SD measurement in this diagnostic.

### Verify the final file-data target once (2026-09-13)

`read_fs_data_chunk` now treats the final skip-list hop separately. It resolves
the target through the existing reference/kind/codec checks, reads and fully
verifies the blob once, decodes the structural prefix from those verified bytes,
and checks encoded length, target index and parent/child total-length relations.
Only then is the prefix removed in place and content returned. Intermediate
hops retain directed first-leaf verification, and reading an already-held tail
uses the prior path. No new full-content copy or persistent verification cache
is introduced. Invalid final-node metadata is rejected after full verification;
intermediate nodes are still rejected using their bounded prefix read.

Compare current 16/64 MiB file-sequential samples with the immediately preceding
file profile, at seed 71, 64-page cache, 128 MiB, one hart and 4/2 MiB/s / 400/200
read/write IOPS. Both pass exact full content readback. Only verification-phase
requests change:

| Workload | Verify read requests | Verify read bytes | Whole-workload read requests |
| --- | ---: | ---: | ---: |
| 16 MiB | 262 → 237 | 17,612,800 unchanged | 296 → 271 |
| 64 MiB | 1,078 → 973 | 69,910,528 unchanged | 1,457 → 1,352 |

The 25/105 saved requests are 9.54%/9.74% of verification reads. Every stage,
publish and remove physical counter, all write counters and flush counts remain
identical. In this cached QEMU run the benefit is fewer requests, not fewer
physical read bytes. Timings are excluded: this is a single counter comparison,
and the initial test compilation was allowed alongside benchmark startup. No
real SD latency claim is made.

All 19 file API tests pass. The new focused regression warms the same metadata
state and asserts that a final-hop read uses exactly as many device pages as a
direct full target read. It separately rejects wrong target indices, invalid
parent/child total lengths and content corruption beyond the structural prefix
after a successful read. Existing mixed-size/skip-list, cold recovery and
publication cut-boundary tests also pass.

The broader file-service suite exposed a stale GC pressure fixture: eight
create/unlink pairs now cause only one collection under the previously retained
extended-source GC policy. Replacing this turn's file API with its saved prior
source reproduces the exact same failure (one observed round, 8,636 read pages,
zero cache hits). Adjust only the fixture to allow at most 32 pairs and stop
when two rounds are observed; preserve all hit/reduced-read assertions. The
final suite passes 28 tests with five ignored. GC runtime policy is unchanged.

Default QEMU three-boot file-tree regression, Duo release file-tree/legacy-shell
compile check and independent stopped-image verification at both sizes pass.
The benchmark ELF precedes only test additions/fixture changes; runtime source
substitution and temporary cache configuration are restored and hash-checked.

Evidence: `target/storage-file-target-verify-20260913/` contains before/runtime
source manifests, final test-source hashes, ELF and commands, all benchmark and
phase-counter reports, initial/final tests, the baseline GC-fixture reproduction,
QEMU functional evidence, retained images and offline verifier reports. Deleted
benchmark files were verified in the guest before removal; offline image checks
are complementary structural recovery evidence.

### ABBA qualification of single-pass file targets (2026-09-13)

Run the preceding and current target-verification ELFs in ABBA order for one
64 MiB `file-sequential` operation per fresh VM, seed 71, no warmup, 64-page
cache, 128 MiB, one hart and consistent host telemetry. Repeat the full sequence
with only QEMU throttling removed. Limited mode uses 4/2 MiB/s and 400/200
read/write IOPS. No compilation/tests/heavy verification overlap these timed
sequences. All eight samples pass; both candidate stopped images independently
verify. Every physical counter repeats exactly within a build and matches
between throttle modes (whole-workload reads 1,457 → 1,352, same bytes).

| Mean seconds | Limited before | Limited after | Unthrottled before | Unthrottled after |
| --- | ---: | ---: | ---: | ---: |
| staging | 34.9277585 | 34.9435955 | 3.6060855 | 3.592059 |
| verification, including pattern check | 16.598778 | 16.6110815 | 2.4769065 | 2.4510465 |
| verification reader only | 15.4071955 | 15.2016755 | 1.3852275 | 1.353481 |
| whole write/read/remove operation | 51.6114345 | 51.641816 | 6.1027305 | 6.063049 |

Limited total changes +0.059%, smaller than before/after pair spreads
0.239%/0.083%; it demonstrates no overall latency improvement. Unthrottled total
changes -0.650%, smaller than the candidate pair spread of 3.333% (control
0.617%), also insufficient for an overall speed claim. Unthrottled reader-only
mean changes -2.292%, with pair spreads 0.655%/1.073%; this is a small positive
reader observation with only two measurements per version, not a robust speed
bound. Full verification includes independent pattern-check work and has a
larger candidate spread. No samples or phases are discarded.

Keep the optimization for verified request-count reduction and preserved
correctness, rather than claim a broad throughput improvement. Byte traffic and
configured bandwidth limits are unchanged. These results do not establish real
SD latency or sustained mixed-workload gains.

Evidence: `target/storage-file-target-limited-abba-20260913/` and
`target/storage-file-target-unthrottled-abba-20260913/` retain commands/ELF hashes,
all serial/sample/host logs, analysis scripts and per-run phase/counter summaries,
retained candidate images and offline verifier reports. Current source hashes
match the qualified runtime/test state. No runtime changes in this turn.

### Verify duplicate imports before scratch payload writes (2026-09-13)

The single-fresh-object fused persistent-authority import now uses its candidate
content root to look up an existing Blob before streaming the scratch copy. A
hit must pass fresh manifest/envelope validation, byte-for-byte comparison with
the entire input, full Merkle verification and exact per-extent payload SHA-256
verification. The declared external root is only a lookup selector. An ordered
tree pass completes the extent hashes without rereading all content. Normal
scratch preparation/seal clearing, independent object identity, authority
publication and checkpoint barriers remain in force. No-hit imports retain the
streaming path; generic streaming commits and multi-fresh-object imports are
unchanged. Every hit rechecks media; there is no new verified-content cache.

Failed read-only preflight can restore the mounted predecessor without writing.
A regression exposed a stale logical-root cache on retry with changed inline
content under the same uncommitted ID. Restrict cache reuse to committed IDs;
speculative roots are recomputed on retry. The regression failed with
`Cas(HashCollision)` before the fix and passes afterward. False input and
corrupted existing media leave the complete test-device image, generation and
principal quota usage unchanged at 128 KiB + 37 and 1 MiB + 37.

Admission remains conservative: scratch capacity and full canonical quota are
reserved before the preflight. Principal logical/physical charges remain the
original full per-object charges, even for duplicates; only the existing
anonymous unique-byte telemetry receives the dedup discount. This change does
not establish reduced peak heap usage or admit previously out-of-budget work.

QEMU uses 128 MiB, one hart, a 64-page cache and temporary cloned disks with
4/2 MiB/s and 400/200 read/write IOPS. Four 1 MiB `object-v2-large` samples,
all-duplicate content, seed 32 and no warmup cover new/first-repeat/later-repeat
imports. Compare against `storage-dedup-local-scan-20260913/final.elf`; the
intervening file-target-only change does not enter this object workload.
The final retry-fixed build passes all samples and exactly matches the previous
qualified build's seven whole-workload I/O counters in every sample.

| 1 MiB put + get sample | Before | After |
| --- | ---: | ---: |
| first duplicate write requests | 16 | 6 |
| first duplicate write bytes | 1,179,648 | 77,824 |
| first duplicate read requests | 96 | 44 |
| first duplicate read bytes | 3,461,120 | 2,400,256 |
| first duplicate flush requests | 3 | 3 |
| next duplicate write bytes | 1,179,648 | 77,824 |
| next duplicate read bytes | 1,142,784 | 2,392,064 |

Each repeat saves 1,101,824 write bytes (93.4% for the first two repeats);
the fourth sample's metadata grows by one page on both versions. New unique
content has identical physical counters. Later duplicates incur more reads:
the old path can trust its process-local dedup comparison cache after writing
scratch, whereas this path verifies the existing payload afresh before skipping
those writes. Therefore this is a write-traffic reduction with a read tradeoff,
not a universal I/O or throughput improvement. Tests/builds overlap these
counter-only diagnostics; timings are excluded, and no SD latency or FTL write
amplification claim is made.

Evidence: `target/storage-import-preflight-dedup-20260913/`. The retained final
firmware is `retry-fixed.elf`, with source hashes, restored cache configuration,
commands, serial/host/sample logs and stopped images under matching names.
`comparison-qualified.json` remains numerically valid because all final counters
match. `after.elf` is an early prototype without restored preparation/exact
extent checks; `final.elf` adds preparation; `qualified.elf` adds exact checks
but precedes the retry-cache fix. These superseded prototypes are not final
qualification. Initial quota-test failures used an incorrect discounted
principal-charge expectation; the corrected test enforces original semantics.

The final build also passes three 16 MiB + 37 multi-segment samples against
`storage-dedup-multisegment-20260913/after16.jsonl` with matching configuration.
Unique content's counters remain identical. Each duplicate drops from 150 to
13 write requests and 17,936,384 to 106,496 write bytes (99.406% reduction),
with four flushes unchanged. First-duplicate reads drop from 1,322 / 53,899,264
bytes to 433 / 36,519,936 bytes; the later duplicate rises from 200 / 17,862,656
to 433 / 36,511,744. This confirms the same read/write tradeoff across segments.
Both final stopped images independently verify with status `ok`.

Final validation: 284 segment-store unit tests pass (one ignored), seven fused
append recovery tests pass, 26 GC recovery tests pass and 28 file-service tests
pass (five ignored). The new duplicate publication fault matrix covers every
one of its 29 write/flush mutation boundaries: cold recovery selects exactly
the predecessor or complete successor record stream/object count, verifies all
admitted payload bytes, and retries predecessor outcomes to the exact successor.
Exact-payload checker tests cover arbitrary input splits, wrong hashes,
noncontiguous extents and truncation. The final default QEMU three-boot
file-tree/powered-off regression and Duo release compile check also pass.
`retry-before-fix.log` retains the reproduced retry failure;
`retry-fixed-test.log` and the `*-retry-fixed.log` suites qualify the correction.
All runtime source hashes match `sources-retry-fixed.json`; the temporary
64-page firmware override is restored. `git diff --check` passes.

### ABBA timing of duplicate-import preflight (2026-09-13)

Qualify the preceding change with isolated ABBA runs of the local-scan control
and final `retry-fixed.elf`, each fresh VM executing four 1 MiB all-duplicate
samples with seed 32, no warmup, 128 MiB and a 64-page cache. Run limited mode
(4/2 MiB/s, 400/200 read/write IOPS), then repeat with only the limits removed.
No compiler or QEMU process was present before launch; no builds/tests/heavy
verification overlap either timed sequence. All 32 samples pass, both candidate
stopped images independently verify, and all seven physical counters repeat
exactly within versions and across modes. Runtime source hashes remain unchanged.

| Mean put + get seconds by sample position | Limited before | Limited after | Change | Unthrottled before | Unthrottled after | Change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| new unique | 0.765679 | 0.7816435 | +2.09% | 0.1444345 | 0.1250225 | -13.44% |
| first duplicate | 1.2027735 | 0.5345585 | -55.56% | 0.1222365 | 0.1120085 | -8.37% |
| next duplicate | 0.7001695 | 0.530058 | -24.30% | 0.096072 | 0.102657 | +6.85% |
| final duplicate | 0.698077 | 0.53472 | -23.40% | 0.103406 | 0.1086055 | +5.03% |

There are only two observations per version per position. Limited duplicate
combined reductions substantially exceed pair spreads (all below 1.30%). Unique
content's apparent changes are within control spread (limited 3.10%,
unthrottled 29.53%) and do not establish a gain/regression. Unthrottled first
repeat's 8.37% reduction exceeds its pair spreads (2.22%/0.98%); later combined
regressions are smaller than at least one pair spread (5.33%/11.35% and
6.81%/0.73%), so their exact magnitude remains uncertain.

Preserve phase regressions rather than hide them in combined times. Limited
later get rises 0.196916 -> 0.290195 seconds (+47.37%) and 0.195104 ->
0.2939115 (+50.64%), while corresponding put falls about 52%. Additional
preflight reads may consume shared throttle credits before get; this is an
explanation to investigate, not established causal attribution. In unthrottled
mode the last put rises 0.0604545 -> 0.076115 seconds (+25.90%), exceeding both
pair spreads (2.86%/0.69%); the preceding put's +10.22% is within candidate
spread (17.29%). This confirms an actual fast-backend CPU/read tradeoff and
motivates reducing preflight verification overhead next. Every observation,
including the slow initial unthrottled control sample, is retained.

Keep the optimization for its large write-traffic savings and measured limited
combined benefit; do not claim universal throughput improvement or transfer
QEMU timings to real SD media. Evidence directories:
`target/storage-import-preflight-limited-abba-20260913/` and
`target/storage-import-preflight-unthrottled-abba-20260913/` include scripts,
commands/ELF hashes, all serial/host/sample logs, per-position analysis with raw
values and pair spreads, candidate images and independent verifier results.
This turn changes qualification evidence and documentation, not runtime code.

### Rejected verifier leaf-buffer reuse trial (2026-09-13)

Try replacing `verify_resolved_blob`'s per-leaf Vec with one fallibly allocated
buffer bounded by min(content length, 4 KiB), released before the ordered exact
payload tree pass. Byte comparison, Merkle emissions and extent SHA verification
remain unchanged. The shared verifier serves ordinary full verification as well
as duplicate-import preflight. No other runtime edits enter this trial.

An isolated host full-verification allocation probe shows:

| Content | Allocation calls before -> trial | Requested bytes before -> trial | Extra peak bytes before -> trial | Read pages |
| --- | ---: | ---: | ---: | ---: |
| 4 KiB | 10 -> 10 | 54,640 -> 54,672 | 37,688 -> 37,720 | 11 |
| 128 KiB | 42 -> 11 | 308,592 -> 181,648 | 144,368 -> 144,400 | 43 |
| 1 MiB | 268 -> 13 | 1,243,344 -> 198,896 | 157,264 -> 157,296 | 274 |

Directed-read measurements are unchanged. The extra 32 peak bytes are measured,
not omitted; this is a whole ordinary-verifier probe, not a measurement of whole
persistent-import heap admission. It confirms lower allocation traffic, not a
latency improvement.

Run isolated limited and unthrottled ABBA comparisons against the retained
preflight `retry-fixed.elf`: four 1 MiB all-duplicate samples per fresh VM,
seed 32, no warmup, one hart, 128 MiB, 64-page cache; limits 4/2 MiB/s and
400/200 read/write IOPS. All 32 samples pass. Every physical counter is identical
before/after, repeats within each version and matches across throttle modes.
No build/test/heavy offline verification overlaps timing.

| Mean put + get seconds | Limited before | Limited trial | Unthrottled before | Unthrottled trial |
| --- | ---: | ---: | ---: | ---: |
| new unique | 0.7760375 | 0.775547 | 0.124948 | 0.149451 |
| first duplicate | 0.5322195 | 0.5285345 | 0.1103285 | 0.110701 |
| next duplicate | 0.5334175 | 0.5326925 | 0.106498 | 0.109276 |
| final duplicate | 0.533964 | 0.536666 | 0.108203 | 0.108954 |

Limited combined changes are all smaller than at least one pair spread.
Unthrottled unique put rises 0.0873405 -> 0.1120655 seconds (+28.31%);
combined rises 19.61%, exceeding before/trial pair spreads 2.88%/0.19%.
Unthrottled next-duplicate combined rises 2.61%, exceeding spreads 1.32%/1.22%.
Other repeated combined changes (+0.34%, +0.69%) are within at least one spread.
Each position has only two observations per build. These observations do not
establish a cause for the regression, and should not be generalized to SD
hardware. In particular, reduced allocations alone do not justify this build.

Reject the trial: it offers no stable measured duplicate latency gain and has a
substantial repeatable unique-content regression in this comparison. Preserve
`cas.rejected.rs`, the exact runtime diff and candidate ELF, then restore the
saved source byte-for-byte. All retained runtime hashes again match
`storage-import-preflight-dedup-20260913/sources-retry-fixed.json`; no change
from this trial remains in runtime code. Do not use `after.elf` from this trial
as a qualified performance candidate.

Correctness tests on the trial passed: adversarial preflight/retry regression,
13 CAS streaming tests (including empty blobs, corruption and cancellation),
seven fused publication recovery tests, default QEMU three-boot file-tree test,
Duo release compile check and both independent stopped-image verifications.
No tests are rerun on the exact restored runtime because it is byte-identical
to the already-qualified prior build. Evidence, allocation logs, source hashes,
trial diff, ABBA commands/raw timings/analysis and recovery artifacts are in
`target/storage-verifier-reuse-buffer-20260913/`, with timing subdirectories
`limited/` and `unthrottled/`. The next optimization needs evidence on verification
CPU/read cost beyond the allocator; this rejected experiment narrows that search.

### Reuse proof windows for ordered tree hashing (2026-09-13)

Trace the retained duplicate-import implementation before changing it. The four
1 MiB samples reproduce all untraced counters. Partition the ordered physical
read suffix by guest put/get request counts and reconcile every phase's read
bytes independently. Parse the accessed segments from the stopped image using
the independent storage layout parser: four segments, no parse errors. First
repeat put reads 1,069,056 content bytes, 65,536 tree bytes, 4,096 header bytes,
4,096 catalog bytes and 155,648 framing/anchor bytes. Exactly 32,768 tree bytes
repeat: four 8 KiB Merkle-proof reads followed by one 32 KiB ordered extent-hash
read. Trace evidence is `target/storage-preflight-read-trace-20260913/`; the
stopped image also independently verifies. Trace ordering identifies requests,
not CPU-time attribution.

The retained `ManifestRangeReader::read_buffer` change searches invocation-local
proof windows for tree-extent reads as well as 32-byte hash reads. Ordinary
content/header reads retain the direct slot-zero path. Misses still choose the
original content/proof slots and preserve read-ahead and cache budgets. The exact
extent-hash pass can consume tree snapshots just used by full Merkle verification.
There is no cache across invocations, no new page allocation, and byte/root/extent
validation and failure invalidation remain in force. The leaf-buffer reuse trial
remains reverted. The broader initial experiment is distinguished below.

At 1 MiB each repeat put drops 29 -> 28 reads and saves exactly 32 KiB. Following
get reads 8 KiB more in the first two repeats due to changed device-cache state;
whole put/get therefore saves 24 KiB in those positions and 32 KiB in the final
repeat (44 -> 43 requests). New content has identical counters; all writes and
flushes are identical. At 16 MiB + 37, where the tree exceeds the proof-window
budget, all three samples have identical before/after counters and phases.
Do not generalize the small-tree savings to larger trees. These initial runs
are counter diagnostics and overlap compilation/tests; their timings are excluded.

The existing proof-batch regression now also performs full Merkle plus exact
extent verification on a 1 MiB object without a device cache, asserts that each
tree page appears in exactly one physical read, and checks the complete result.
The regression passes along with 284 segment-store unit tests (one ignored),
13 CAS streaming tests, seven fused recovery tests and 28 file-service tests
(five ignored). Adversarial preflight/retry, corruption, empty input and cold
recovery coverage remains intact. Default QEMU three-boot file-tree/powered-off
validation, Duo release compile check and independent 1/16 MiB image verification
pass.

Evidence: `target/storage-preflight-tree-cache-20260913/` contains saved prior
source, runtime/test diff, ELF/build/source manifests, counter comparisons,
all tests and functional evidence, commands, retained images and verifier output.
The benchmark ELF precedes only a comment correction and the new test assertion;
`final-source-hashes.json` records current source. The temporary 64-page build
override is restored. No real SD timing or flash write-amplification claim is made.

The initial broad cache-search variant (`after.elf`) is not qualified for
retention. Its isolated 32-sample ABBA comparison preserves the read savings and
passes both offline image checks, but unthrottled duplicate put/get regresses
11.79%, 11.71% and 13.53%, exceeding pair spreads in each position. Unique
put/get regresses 9.62%. Limited duplicate combined changes are -1.33%, -1.57%
and -0.60%, with only the first exceeding both spreads; unique combined rises
1.25%. Preserve all phases/raw observations in `limited/` and `unthrottled/`.
The broad variant's correctness results above remain valid, but lower read
traffic does not justify its CPU-side regression. A follow-up variant limits
cross-window lookup to tree extents and preserves direct slot-zero content
selection; `cas.broad.rs` records the original broad trial.

Retain the tree-only variant as `scoped.elf`, with matching
`sources-scoped.json` / `final-source-hashes.json`. Unlike the initial ELF it
includes the new regression assertion and corrected comment. Its dedicated
proof/preflight, 13 streaming and seven fused recovery tests pass. All 48 scoped
ABBA samples pass, and their counters repeat exactly across limited mode and
two unthrottled ABBA sequences. Scoped 16 MiB + 37 also passes all three samples
with identical counters to the prior implementation. All four scoped candidate
images independently verify. No compilation/test/heavy verification overlaps
any timing sequence; the later 16 MiB diagnostic is counter-only.

| Scoped mean put + get seconds | Limited before | Limited after | Unthrottled before (4 observations) | Unthrottled after (4 observations) |
| --- | ---: | ---: | ---: | ---: |
| new unique | 0.7649745 | 0.776173 | 0.12377875 | 0.12357575 |
| first duplicate | 0.529027 | 0.5266185 | 0.110610 | 0.110101 |
| next duplicate | 0.5311415 | 0.522117 | 0.1086805 | 0.11225625 |
| final duplicate | 0.524079 | 0.524869 | 0.1083715 | 0.11227975 |

Limited next-repeat improves 1.70%, exceeding pair spreads 0.28%/0.13%; other
limited changes are within at least one pair spread. The scoped fast-backend
results do not reproduce the broad variant's consistent double-digit regression,
but are not a general speedup: pooled changes are -0.16%, -0.46%, +3.29% and
+3.61%. Keep the slow 133.114 ms next-repeat and 122.782 ms final-repeat candidate
observations; their cause is unproven. Candidate ranges span 33.395 ms and
15.060 ms in these positions. This evidence supports stable I/O reduction, not
a guarantee of improved average/tail latency on fast backends. The remaining
variation warrants future qualification rather than selectively discarding
samples. Timing evidence is in `scoped-limited/`, `scoped-unthrottled/` and
`scoped-unthrottled-repeat/`; pooled raw values are preserved separately.

Final scoped regression completes successfully: 284 segment-store unit tests
(one ignored), 28 file-service tests (five ignored), default QEMU three-boot
recovery/powered-off verification and Duo release compile check all pass.
`unit-scoped.log`, `file-scoped.log`, `qemu-scoped.log` and `duo-scoped.log`
qualify the retained variant; hashes still match and `git diff --check` passes.

### Current unique-object write amplification (2026-09-13)

Reprofile unique content with the retained tree-only cache firmware
`storage-preflight-tree-cache-20260913/scoped.elf`. Use fresh cloned disks,
128 MiB, one hart, 64-page cache, `object-v2-large`, unique content, seed 32,
no warmup and three samples per VM at 4 KiB, 128 KiB, 360 KiB, 1 MiB and
16 MiB. Limits are 4/2 MiB/s and 400/200 read/write IOPS. All 15 samples and
all five stopped-image verifications pass. This is a physical-counter baseline,
not an ABBA latency comparison or cold-read baseline; small payloads remain in
the device cache after put (4 KiB samples have zero physical read requests).

| User payload | Stable write bytes (samples 1/2) | Write / user bytes | Write requests | Flushes |
| --- | ---: | ---: | ---: | ---: |
| 4 KiB | 106,496 | 26.000x | 6 | 3 |
| 128 KiB | 237,568 | 1.8125x | 7 | 3 |
| 360 KiB | 536,576 | 1.4556x | 13 | 3 |
| 1 MiB | 1,257,472 | 1.1992x | 20 | 3 |
| 16 MiB | 18,006,016 | 1.0732x | 169 | 4 |

Both stable positions match these write/flush counters at every size. First
samples include initialization/activation overhead and have eight flushes;
retain them separately in `profile.json` rather than mix them into steady writes.
The ratio is host-visible logical device traffic divided by benchmark user
payload, including its wrapper, formatting, metadata and checkpoint writes.
It is not SD controller/FTL physical write amplification. In particular, the
4 KiB benchmark's stored logical object is 4,256 bytes including a 160-byte
wrapper; its canonical blob is 4,480 bytes and occupies two 4 KiB pages.

Trace a separate fresh 4 KiB three-sample run. All counters exactly match the
untraced baseline. Split the ordered write suffix by sample request counts and
independently reconcile bytes. Sample 1 consists of a 72 KiB front run, 16 KiB
segment-tail run, one 4 KiB preclear, and three 4 KiB checkpoint writes. The
independent layout parser validates the corresponding sealed segment without
errors, finding five extents. The traced stopped image independently verifies.

| Stable 4 KiB put's physical writes | Bytes |
| --- | ---: |
| Five extent body/seal pairs | 40,960 |
| Segment header plus summary/seal records | 24,576 |
| Canonical blob payload pages | 8,192 |
| Four metadata payload pages | 16,384 |
| Checkpoint clear/body/seal | 12,288 |
| Next scratch-seal preclear | 4,096 |
| Total | 106,496 |

The four metadata payloads are the 256-byte blob manifest, 640-byte CAS catalog,
2,752-byte persistent-authority snapshot and 137-byte allocation map, each
rounded to one 4 KiB page. Their independent extent envelopes cost another
32 KiB within the 40 KiB above. Fixed segment/extent framing alone accounts for
64 KiB, or 61.5% of the total. Preclear contributes only 3.8%; eliminating its
single page is neither a complete solution nor permission to weaken its crash
protocol. Reducing the authority snapshot's encoded bytes alone cannot remove
a page in this small fixture; compact metadata framing or amortizing durable
publication across admitted batches is the larger opportunity. Either needs an
explicit compatibility/recovery design: this evidence does not authorize silently
changing record interpretation or relaxing per-operation durability.

Next prioritize the fixed metadata-envelope cost for small unique objects over
further dedup-read micro-optimizations. Larger-object traffic is already much
closer to content size in this short workload; long histories, GC pressure,
concurrent batches and actual SD behavior remain outside this baseline.

Evidence: `target/storage-unique-current-profile-20260913/` preserves matching
source/ELF hashes, all commands/serial/sample/host logs, retained images, verifier
results and `analyze.py` to reproduce both profiles and the trace reconciliation.
`trace4k/` includes actual QEMU arguments, trace, per-sample writes, parsed extent
records and exact write breakdown. Current runtime hashes remain unchanged;
this turn adds measurements and diagnosis, with no runtime modification.

### Complete batch prefixes before bounded drains (2026-09-13)

Measure the existing `file-batch-create-unique` path before changing disk format.
Small content remains inline until the trusted-service fused transaction stages
its data, inode/dirent nodes, namespace root and authority switch under one
checkpoint. Batch-created files are verified byte-for-byte by the guest. Fresh
QEMU VMs use 128 MiB, one hart, a 64-page cache, 4 KiB unique content, seed 32,
no warmup and two samples at 1/8/32/100 files. This is a file workload including
namespace construction and verification, not the preceding raw-object workload.
All eight baseline samples and all four stopped images verify.

The baseline already amortizes publication cost, but writing grows unexpectedly
fragmented at 32 and 100 files. `commit_staged_batch_snapshot` initially merges
content pages into its sink, then appends metadata with bounded drains, and only
later adds the open segment's header and content descriptors in
`seal_batch_segment`. A full sink thus drains sparse content before its missing
prefix pages arrive. Metadata descriptor pages can also drain before being
restaged by the final full-record prefix, causing duplicate physical writes.

Extract `stage_batch_prefix` from `seal_batch_segment`. For the shared-open
publication path only, stage its header and existing content descriptors before
appending metadata in physical order. The bounded drain can now submit complete
content runs and carry its final incomplete run forward. Finish using the same
`finalize_segment` over all content and metadata records, without restaging the
prefix. Other closed/dedicated-segment paths keep their existing behavior through
the extracted helper. On-disk bytes/record identities and the checkpoint protocol
are unchanged. The 64-page drain threshold, 32-page request ceiling, last-write
selection and error/cancellation guard are retained; total heap peak is not
claimed unchanged merely from retaining those thresholds.

| Unique 4 KiB files | Sample | Write requests before -> after | Write bytes before -> after |
| --- | --- | ---: | ---: |
| 1 | initial / next | 11 -> 11 / 7 -> 7 | 196,608 -> 196,608 / 180,224 -> 180,224 |
| 8 | initial / next | 12 -> 12 / 8 -> 8 | 397,312 -> 397,312 / 385,024 -> 385,024 |
| 32 | initial | 103 -> 17 | 1,265,664 -> 1,093,632 |
| 32 | next | 128 -> 14 | 1,527,808 -> 1,191,936 |
| 100 | initial | 343 -> 34 | 4,096,000 -> 3,223,552 |
| 100 | next | 339 -> 30 | 4,108,288 -> 3,235,840 |

At 100 files the next sample saves 91.15% of write requests and 21.24% of write
bytes (872,448 bytes); flush counts remain four initially / three subsequently.
Initial activation and namespace shape affect totals, so retain both positions.
This is less redundant device traffic, not a claim that fixed extent framing
has been removed. As a larger-content guard, 100 unique 128 KiB files pass on
both builds in the same 128 MiB VM: writes 291 -> 138, bytes 17,289,216 ->
16,416,768, reads 625 / 16,252,928 bytes and seven flushes unchanged. This proves
that fixture remains admitted, not a universal whole-operation heap bound.
Counter diagnostics overlap correctness builds/tests; their timings are excluded.

Correctness: 284 existing segment-store unit tests, 28 file-service tests and
seven fused append recovery tests pass. Add a 32-chunk V2 test whose content
fills the sink: interrupt every individual page/flush mutation using not-submitted,
ambiguous-not-durable and ambiguous-durable failures, cold-mount the old or whole
new batch, then retry and read all 32 chunks. It passes. The first fixture failed
at a completed publication's retry because the old 64-entry test limit could
not hold the namespace root plus two 32-object batches; raise only this fixture
to 128 entries, preserve every fault point and all retry assertions, and keep
the failed log. Default QEMU three-boot recovery/powered-off test and Duo release
compile check pass. All candidate 4 KiB batch images independently verify.

The larger baseline image exposed an existing offline-verifier bug:
`parse_fs_data` still capped content at one page, while the retained Rust format
admits up to 4 MiB per node. Align the independent verifier's explicit ceiling
with `FS_DATA_CHUNK_MAX_LEN`; preserve all framing, ancestor, exact-length and
cumulative-length checks. Add eight positive/negative parser selftests including
4 KiB + 1, 128 KiB, the 4 MiB boundary, over-limit content, truncation and trailing
bytes. The verifier passes 25,142 selftest cases, then independently validates
both old and new 100×128 KiB images. The original baseline rejection is retained;
this is a tooling compatibility fix, not a relaxation of runtime format rules.

Evidence: `target/storage-small-batch-profile-20260913/` holds the baseline;
`target/storage-batch-prefix-order-20260913/` holds prior source, extracted runtime
diff, final source hashes, firmware/build log, all sample/serial/host logs,
comparisons, temporary retained images and recovery/verification evidence. The
firmware precedes only new test additions; runtime hashes match, and the temporary
cache override is restored. The independent verifier source and its prior copy
are recorded. No actual SD device was used.

Isolated ABBA timing qualification (all builds/tests/offline checks completed
before timing) uses one 100-file create-and-verify operation per fresh VM, two
observations per build per mode. All eight samples pass, physical counters repeat
exactly within builds and across modes, and both candidate stopped images verify.

| Mean whole-operation seconds | Before | After | Change | Before/after pair spread |
| --- | ---: | ---: | ---: | ---: |
| 4/2 MiB/s, 400/200 read/write IOPS | 3.272093 | 2.7684425 | -15.39% | 0.029% / 0.130% |
| unthrottled | 0.246420 | 0.255144 | +3.54% | 0.133% / 1.971% |

Both changes exceed the observed pair spreads; do not hide the fast-backend
regression. Retain this optimization for its large repeatable request/byte
reduction and slow-backend benefit, while recording the additional fast-backend
cost. It does not demonstrate universal latency gains or real SD performance.
Exact timing/commands/raw counters and verifier results are in `limited/` and
`unthrottled/`. `git diff --check` passes; final hashes include the new fault
fixture and independent-verifier correction. The disk format, authority semantics
and durability barriers remain unchanged.

### Heap qualification of batch-prefix ordering (2026-09-13)

Add an ignored isolated host probe, `batch_publication_requested_allocation`,
using the existing allocation meter and preallocated device. A governed runtime
registers the file reference kinds, imports an empty authority, creates/drops
three maintenance data objects and collects them before measurement, entering
the allocation-V2 path. Input chunks and device backing are allocated before the
baseline. Measure the complete `stage_fs_data_chunks_for_maintenance` call, then
verify every returned chunk outside the allocation window. This covers shared
batch publication of a skip-linked data stream, not full file namespace/authority
root-switch construction or a real asynchronous device driver.

Run six cases alone against the retained runtime, temporarily substitute the
saved preceding CAS source for the identical probe, then restore the retained
source byte-for-byte and repeat. Every allocation and I/O counter in all six
retained cases repeats exactly. No concurrency, firmware/cache override or
runtime policy change enters this probe.

| Chunks × bytes | Extra heap peak before | After | Change | Allocation calls before -> after |
| --- | ---: | ---: | ---: | ---: |
| 1 × 4 KiB | 214,180 | 214,180 | 0 | 142 -> 136 |
| 8 × 4 KiB | 587,836 | 592,204 | +4,368 | 476 -> 456 |
| 32 × 4 KiB | 1,463,260 | 1,359,532 | -103,728 | 1,669 -> 1,601 |
| 100 × 4 KiB | 4,082,780 | 3,902,988 | -179,792 | 5,149 -> 4,946 |
| 32 × 128 KiB | 5,602,204 | 5,602,204 | 0 | 3,869 -> 3,801 |
| 100 × 128 KiB | 16,813,100 | 16,813,100 | 0 | 12,024 -> 11,819 |

Requested allocation bytes fall in every case. For 100 × 4 KiB they fall
21,813,272 -> 21,050,312; for 100 × 128 KiB, 111,104,748 -> 110,264,844.
These are cumulative allocation traffic, not retained heap or device traffic.
The small 8-chunk peak increase is retained and is not described as zero-cost.

The live heap observed at device API entry changes differently from whole-call
peak: 8 × 4 KiB rises 348,996 -> 465,228; 32 × 4 KiB rises 1,111,764 ->
1,232,556; 100 × 4 KiB rises 3,358,164 -> 3,776,012. Filling prefixes earlier
changes what is held while I/O begins. Actual driver/DMA allocations or concurrent
work could add to that live set; the immediate host device does not measure such
an overlap. Thus the evidence supports bounded behavior in these fixtures, not
whole-operation admission on every target or a proof that unchanged drain
thresholds imply unchanged heap peaks. The 64 MiB probe recovery budget is
permissive and does not replace target-budget testing.

Write counters also confirm the same mechanism: 32 × 4 KiB data chunks drop
288 -> 246 written pages / 96 -> 17 requests; 100 × 4 KiB drops 896 -> 726
pages / 302 -> 32 requests. At 100 × 128 KiB, 4,117 -> 3,947 pages and
250 -> 136 requests. Flush counts are identical within each pair. These data-
stream counts differ from the preceding namespace benchmark and must not be
combined with it as if they measured the same operation.

Evidence: `target/storage-batch-prefix-memory-20260913/` has source/probe hashes,
original/candidate allocation logs, exact-repeat log, comparison script/results
and restoration evidence. Initial fixture attempts used the wrong authority
composition (ungoverned import, then unprincipaled raw writes); the qualified
fixture uses governed maintenance operations throughout. `after-qualified.log`,
`before.log` and `after-repeat.log` are the comparison evidence. This turn adds
the reusable probe and qualification; retained runtime source is unchanged and
`git diff --check` passes. No SD performance claim follows from host allocation
measurements.

### Transfer encoded segment pages into deferred sinks (2026-09-13)

Remove redundant page allocations/copies while preserving the preceding batch
publication order. `stage_batch_prefix` transfers its two newly encoded header
pages with `push_owned`; it no longer copies those boxes into another pair.
`finalize_segment`, only when both deferred barriers and a sink are present,
transfers its four newly encoded summary/segment-seal pages into that sink and
returns the same seal identity. The original direct-write/non-deferred path is
unchanged. Page order, encodings and the caller's checkpoint barrier remain
identical; ownership transfer neither submits an early write nor skips a barrier.

The isolated six-case batch allocation probe passes and confirms exact savings:

| Batch data | Fewer allocations | Fewer cumulative requested bytes |
| --- | ---: | ---: |
| 1 / 8 / 32 / 100 × 4 KiB (each fixture) | 6 | 24,576 |
| 32 × 128 KiB | 12 | 49,152 |
| 100 × 128 KiB | 24 | 98,304 |

This is six avoided page copies per sealed batch segment (two header plus four
summary/seal pages). Every measured whole-call heap peak, device-entry live-heap
peak, written-page count, write-request count and flush count is exactly the same
as the preceding retained probe. Do not claim a peak-memory reduction: those
peaks occur outside the eliminated temporary overlap. All returned content is
verified. The reduction is cumulative allocation/copy traffic, not on-disk bytes.

QEMU counter diagnostics at 1/8/32/100 unique 4 KiB files, two samples each, all
pass with every physical counter identical to the preceding build. All four
stopped images independently verify. Default three-boot file-tree/powered-off
recovery and Duo release compile check pass. These initial diagnostics overlap
correctness builds/tests, so their timings are excluded.

Evidence: `target/storage-owned-seal-pages-20260913/` includes saved preceding
CAS source, exact runtime diff, matching firmware/source/probe hashes, allocation
comparison, benchmark logs/commands, stopped images and verifier/recovery output.
Temporary cache configuration is restored. No additional memory-budget admission
or real SD performance claim follows from this ownership change.

Final correctness qualification passes 285 segment-store unit tests (one ignored),
26 GC recovery tests, seven fused append recovery tests and 28 file-service tests
(five ignored), including the full-sink per-page fault matrix. All source hashes
still match the firmware/probe manifest; `git diff --check` passes.

Isolated ABBA runs compare the preceding prefix-order firmware with this build
for one 100-file create-and-verify workload per fresh VM. Use 128 MiB, one hart,
64-page cache, 4 KiB unique content and seed 32. No build/test/heavy verifier runs
overlap timing. All eight samples pass, all physical counters repeat exactly
within builds and across limited/unthrottled modes, and both timed candidate
images independently verify.

| Mean seconds | Before | After | Change | Before/after pair spread |
| --- | ---: | ---: | ---: | ---: |
| 4/2 MiB/s, 400/200 read/write IOPS | 2.7657695 | 2.721449 | -1.60% | 0.060% / 0.002% |
| Unthrottled | 0.262613 | 0.2053035 | -21.82% | 5.955% / 3.507% |

Both reductions exceed observed pair spreads, but each version has only two
observations per mode. These are whole-build QEMU results; they do not isolate
how much comes from allocation, copying or compiler-generated async code, and
do not establish real SD gains. Retain the ownership transfer for eliminated
redundant allocation/copy work, preserved correctness and this measured result.
All timing values, including the slower control repetition, remain in `limited/`
and `unthrottled/` with commands/ELF hashes, raw logs and analysis.

### Owned segment pages: sequential-file qualification (2026-09-13)

Extend the preceding ownership-transfer comparison to one 16 MiB
`file-sequential` workload per fresh VM, seed 71, no warmup. Compare
`storage-batch-prefix-order-20260913/after.elf` with
`storage-owned-seal-pages-20260913/after.elf`; both already contain prefix
ordering and proof-window reuse. Use ABBA, 128 MiB, one hart and a 64-page
firmware cache. Limited mode uses 4/2 MiB/s and 400/200 read/write IOPS;
unthrottled mode removes only those limits. No builds, tests or heavy offline
verification overlap timed runs. This qualification changes no runtime source.

| Mean seconds, limited | Before | After | Change | Before/after pair spread |
| --- | ---: | ---: | ---: | ---: |
| Stage data | 8.958654 | 8.6792735 | -3.12% | 0.537% / 0.180% |
| Publish | 0.073969 | 0.0744355 | +0.63% | 3.090% / 3.935% |
| Full verification | 4.1339365 | 4.135031 | +0.03% | 0.160% / 0.049% |
| Remove | 0.008918 | 0.0064805 | -27.33% | 1.413% / 1.373% |
| Whole workload | 13.1754775 | 12.8952205 | -2.13% | 0.434% / 0.115% |

| Mean seconds, unthrottled | Before | After | Change | Before/after pair spread |
| --- | ---: | ---: | ---: | ---: |
| Stage data | 1.0893855 | 0.7963325 | -26.90% | 1.742% / 5.788% |
| Publish | 0.0129825 | 0.010791 | -16.88% | 1.040% / 0.815% |
| Full verification | 0.6187355 | 0.582729 | -5.82% | 0.424% / 1.923% |
| Remove | 0.008718 | 0.0064985 | -25.46% | 0.665% / 0.539% |
| Whole workload | 1.7298215 | 1.396351 | -19.28% | 0.941% / 4.107% |

Whole-workload and staging reductions exceed observed pair spreads in both
modes, with only two observations per version per mode. Limited publication and
full verification changes are within spreads. Within limited verification,
reader time rises 3.8395335 -> 3.8574905 s (+0.47%, spreads 0.240% / 0.108%);
retain this small regression. Pattern checking falls 0.2938835 -> 0.2770105 s
(-5.74%, spreads 5.370% / 0.744%), leaving total verification essentially flat.
Unthrottled reader time falls 0.336636 -> 0.318858 s (-5.28%, spreads
0.648% / 1.108%), and pattern checking falls 0.281837 -> 0.263622 s (-6.46%,
spreads 1.711% / 2.906%). These subphases are included in verification, not
additional whole-workload costs. Removal gains are only about 2.2–2.4 ms.

All eight guest samples pass full-content checks. Every physical counter is
identical across both versions and both modes: 17,907,712 read bytes in 271
requests, 18,157,568 write bytes in 201 requests, 16 flushes, and 488 total
requests/used interrupts. Both retained candidate images independently verify
with an unchanged unmanaged prefix. The workload removes its file, so final
image structural verification complements rather than replaces the guest's
content verification. Source hashes remain unchanged.

Evidence: `target/storage-owned-seal-sequential-limited-20260913/` and
`target/storage-owned-seal-sequential-unthrottled-20260913/` contain runners,
commands/ELF hashes, all raw timings, phase analysis, source manifests, retained
candidate images, offline results and cross-mode `qualification.json` checks.
These are whole-build QEMU observations, not a causal attribution of every saved
cycle to page copying, a peak-memory reduction, or a real SD performance result.

### Rejected isolated-page sink submission trial (2026-09-13)

Trial a direct borrow of the sink's owned page for one-page physical runs,
allocating the contiguous run buffer only when a multi-page run occurs. Keep
`write_pages`, ascending last-write-wins ordering, the 32-page request ceiling,
64-page bounded drain threshold and failure/cancellation cleanup unchanged.
The rationale was to avoid copying isolated preclear/tail pages into a run buffer.

The six batch-publication allocation fixtures (1/8/32/100 × 4 KiB and
32/100 × 128 KiB) pass, but every allocation count, requested-byte total,
whole-call peak, device-entry live-heap peak and I/O counter is identical to the
retained owned-seal build. These workloads still allocate a multi-page buffer.
No measured memory or device-traffic gain supports the additional async branch.

An isolated unthrottled ABBA compares the retained owned-seal firmware with the
candidate: 100 unique 4 KiB files, seed 32, 128 MiB, one hart, 64-page cache,
one sample and no warmup per fresh VM. Builds/tests finish before timing.
All four guest content checks pass, and every physical counter is identical:
522 reads / 3,072,000 bytes, 34 writes / 3,223,552 bytes, four flushes and
560 total requests/interrupts. Before times are 202.951 and 206.152 ms;
candidate times are 208.909 and 208.225 ms. Means rise 204.5515 -> 208.567 ms
(+1.96%), versus pair spreads 1.565% / 0.328%. Only two samples per version
are available; this is insufficient to generalize the regression, but gives no
reason to retain the speculative copy optimization. No limited-backend speedup
or real SD benefit is inferred from unchanged I/O.

Reject and restore the runtime exactly. Retain only the drain test expansion
from failure at request 2 to every request 1–6, including both singleton tails.
The candidate also passes bounded-drain singleton cancellation, ordered-stream
failure/cancellation and full-sink per-page publication recovery. Evidence lives
in `target/storage-sink-single-page-20260913/`: saved before/rejected source,
allocation logs, candidate build/source hashes, ABBA commands and raw logs,
analysis, fault-test logs and runtime restoration assertion. Its `after.elf` is
an experimental rejected build, not the retained implementation.

The retained expanded drain test passes after restoration. The stopped candidate
image independently verifies with an unchanged unmanaged prefix. Cross-build
allocation/I/O equality checks and `git diff --check` pass.

### SD command demand behind page-level counters (2026-09-13)

Audit the current SD backend before interpreting QEMU request savings as card
command savings. `kernel/src/sdhci_blk.rs::Card::read_blocks` can permanently
fall back to CMD17 per sector for a session. Its write path can use an unsplit
qualified multiblock mode, adaptive blind CMD25 bursts, or CMD24 per sector.
The blind safe floor is eight sectors (4 KiB), versus the advertised maximum
256 sectors (128 KiB). `write_sector_tracked` in the hardware driver also calls
`flush`, which issues at least one CMD13; the multiblock path leaves readiness
barriers to explicit Flush requests. Thus page requests and hardware commands
are different quantities even when the same bytes reach the device.

The following is a conditional command model, not a hardware measurement:
replay the same aligned, at-most-128-KiB requests from retained QEMU evidence,
with successful steady-state transfers and no probes, retries or readback.
Exclude CMD12/CMD23, bus configuration and controller reset traffic. CMD13
counts are lower bounds because readiness can require repeated polls. Real SD
cache behavior may change the request stream. The source evidence identifies
which historical optimization each comparison isolates.

| Workload | Unsplit write data commands | Blind 4 KiB CMD25 bursts | Fallback CMD24 | Fallback minimum CMD13 |
| --- | ---: | ---: | ---: | ---: |
| Stable unique 4 KiB object | 6 | 26 | 208 | 211 |
| 100 files before prefix ordering | 343 | 1,000 | 8,000 | 8,004 |
| 100 files after prefix ordering | 34 | 787 | 6,296 | 6,300 |
| Current 16 MiB sequential file workflow | 201 | 4,433 | 35,464 | 35,480 |

Prefix ordering reduces unsplit write commands by 90.09% in this first-sample
batch comparison, but blind-floor/fallback data commands by only 21.30%, matching
the saved bytes. This differs from the previously reported subsequent-sample
counts (339 -> 30 requests); do not mix those populations. Conversely, the owned
page transfer leaves all modeled commands unchanged. It improves software work,
not the SD protocol. For sequential files, fallback reads would also expand
271 requests to 34,976 CMD17 commands; the 100-file read stream expands 522 to
6,000. These counts do not predict latency or internal flash write amplification.

This evidence prioritizes reducing metadata bytes for small writes, retaining
large qualified transfers, and exposing actual backend mode/command counts in
future card qualification. Removing per-sector status checks is a distinct
protocol change: existing host tests deliberately fail at MMIO publication and
do not prove successful card readiness/error behavior. QEMU virtio timings
cannot qualify that change, so this audit does not silently remove those checks.

`target/storage-sd-command-model-20260913/analyze.py` reproduces the projection
from four identified JSONL samples with input/driver SHA-256 hashes. It checks
4 KiB/128 KiB command geometry and rejects malformed aggregate geometry;
`analysis.json` records assumptions and all counters. No runtime changes.

The current SD driver host suite passes all 17 tests; these cover range checks,
command publication and failure paths, not successful physical-card transfers.
`git diff --check` passes.

### Batch scale and the metadata-segment boundary (2026-09-13)

Extend the maintenance data-stream allocation fixture beyond 100 chunks before
raising the unique-file benchmark guard. Use the existing 16-segment in-memory
device, governed maintenance authority, allocation-v2 setup after GC and a
permissive 64 MiB recovery budget. Inputs are allocated before measurement;
returned stream chunks are fully read and compared after measurement. This is
a data-stream batch, not a namespace transaction or a 128 MiB guest admission.
The one-byte content pattern wraps at 256; FsData indices/ancestor references
still make different stream nodes distinct. Do not describe it as 330 unique
raw user buffers.

| 4 KiB chunks | Extra heap peak | Live heap at device entry | Allocations | Written pages / requests / flushes |
| --- | ---: | ---: | ---: | ---: |
| 128 | 4,907,652 B | 4,780,676 B | 6,331 | 924 / 38 / 4 |
| 256 | 8,866,000 B | 8,458,004 B | 12,826 | 1,835 / 68 / 5 |
| 330 | 14,419,376 B | 13,894,532 B | 16,656 | 2,363 / 84 / 5 |

331, 332 and 512 chunks fail at `stage_fs_data_chunks_for_maintenance` with
`Store(Store(Format(InvalidField)))`, not `MemoryLimit`. In this fixture 330/331
brackets the metadata-layout boundary: `commit_staged_batch_snapshot` places all
new manifests, the catalog and allocation record into one metadata segment;
its data area is pages 2 through 1019. `build_record` encodes each record before
the final capacity check, so crossing the boundary is exposed as a format error.
The successful large batches use about 7.22 / 7.17 / 7.16 written pages per
4 KiB chunk; additional batching barely reduces that per-item framing cost.
There is no evidence here that simply removing the shell's 100-file guard will
support 1,000 unique files, or that more memory alone solves the boundary.

Keep the 128/256/330 cases in the ignored allocation probe, with wrapping pattern
generation to avoid arithmetic overflow above 255. Existing six cases retain
their content bytes. No runtime format, publication semantics, guest guard or
memory budget is changed. Supporting substantially larger atomic batches needs
metadata spread across segments (or a versioned compact representation), with
all roots published by the same checkpoint and recovery qualification; splitting
one atomic namespace transaction into separately visible commits is not an
acceptable substitute.

Evidence: `target/storage-batch-scale-20260913/` retains baseline probe source,
isolated per-size logs, exact temporary-source hashes, restoration assertions,
runner scripts, boundary failures and the final expanded probe log. Temporary
probes restore source byte-for-byte before the retained test-only edit. These
host allocation counters do not measure real SD timing or driver/DMA overlap.

The expanded nine-case probe passes; all allocation and I/O counters exactly
repeat the isolated scale runs and the original six retained cases.
`git diff --check` passes.

### Multi-segment metadata layout prototype (2026-09-13)

Add a test-only, allocation-free `MetadataCursor` in
`segment-store/src/metadata_layout.rs` as the first implementation step toward
removing the preceding batch boundary. It places indivisible descriptor/payload
records within pages 2..1020, starts a new relative segment and resets ordinals
when the remaining space is insufficient, and rejects exhausted segment budgets
without changing cursor state. Relative indices must be bound to reserved physical
segments before encoding pointers; the prototype does not allocate device space.

Three tests pass: all 1,019 starting tail positions × 1,016 valid record spans;
malformed records/cursors and exhausted-budget state preservation; and 1,000
three-page manifest records followed by a 65-page catalog span, three-page
authority and three-page allocation records. The last model occupies four
metadata segments with no record crossing a boundary. Its catalog size is a
geometry fixture, not an assertion about every 1,000-object authority state.

This remains `cfg(test)` and is not called by publication. The 331-chunk runtime
failure remains unresolved; no capacity, timing, write-byte or memory-admission
improvement is claimed. Integration must reserve/bind all metadata segments,
update allocation and generation accounting, seal the complete chain, capture
all readback ranges, and publish one checkpoint. Atomic namespace publication
must remain intact. The current allocation helper checks cleaner/root-policy
headroom; blindly allocating segments independently would bypass that reservation
requirement. Fragmented free-space policy also needs explicit handling.

`target/storage-metadata-layout-20260913/` contains passing test output, source
hashes and a source-based integration checklist covering recovery, faults, retry,
GC, fragmentation, memory and QEMU qualification. Runtime implementation and
its qualification remain pending. `git diff --check` passes.

### Multi-segment batch metadata publication candidate (2026-09-13)

Integrate `MetadataCursor` into `commit_batch_snapshot`. Preflight the ordered
manifest, catalog/delta, optional authority and allocation record spans; records
remain indivisible. Keep the shared-open-segment path when the entire metadata
set fits. Otherwise reserve all dedicated metadata segments before encoding
physical pointers, respecting cleaner reserve and root-policy headroom. V1
extends its contiguous prefix; V2 selects free segments in ascending physical
order and can bind a fragmented set. Account for every added segment in the
allocation transition and generation frontier.

Each dedicated segment gets its own header, ordinals, summary and seals, chained
from the preceding data/metadata segment. The allocation record remains last.
Update the successor's final/predecessor chain entries and include all metadata
segments in readback ranges. One checkpoint publishes the entire batch; no
transaction is split into separately visible commits. The existing record ABI
is unchanged. The old v1 allocation-size estimate of zero is also corrected to
the actual fixed payload length when planning record geometry.

Host maintenance-stream results (4 KiB chunks, permissive 64 MiB recovery budget):

| Chunks / device segments | Result | Extra heap peak | Written pages / requests / flushes |
| --- | --- | ---: | ---: |
| 331 / 16 | Full content check passes | 14,361,996 B | 2,376 / 85 / 5 |
| 512 / 16 | Full content check passes | 21,701,448 B | 3,662 / 126 / 6 |
| 1,000 / 16 | Capacity(Payload) | Not measured | Not a successful run |
| 1,000 / 64 | Full content check passes | 42,054,536 B | 7,127 / 237 / 7 |

The 331/512 cases previously failed with `Format(InvalidField)`. The larger
1,000-chunk device is explicit and does not prove admission in a 128 MiB guest;
its input buffers are outside the measured peak. These are data-stream chunks,
not a complete 1,000-file namespace transaction. Per-item metadata framing still
costs pages; this change removes a batch capacity boundary, not those bytes.

All nine original allocation cases pass with unchanged write pages, requests
and flushes. Most add one 16-byte allocation and 16 bytes of measured heap peak;
330 × 4 KiB adds eight cumulative requested bytes / 16 peak bytes, and
100 × 128 KiB has unchanged allocation count, 24 fewer cumulative requested
bytes and eight more peak bytes. Do not describe this as zero-overhead.
The QEMU 100-unique-file diagnostic passes with counters identical to the
retained owned-seal build. Diagnostic timing overlaps correctness work and is
excluded. The release benchmark firmware builds and its temporary cache override
is restored. The pre-existing unit suite plus layout tests passes 288 tests,
one ignored (before registering the new ignored cross-segment fault smoke test).

Evidence: `target/storage-metadata-multisegment-20260913/` contains saved runtime
source/diff, build manifests, original and enlarged-device probe runs, restored
probe hashes, nine-case comparison, QEMU logs and the sampled fault test output.
The new ignored recovery test samples 26 of 2,381 mutation positions with three
failure outcomes, including the last 16 positions and distributed early writes.
This is explicitly not exhaustive multi-segment fault qualification. Further
work remains on exhaustive cut coverage, fragmented-space recovery/GC, complete
namespace batches in QEMU, isolated timing and target-budget admission. Treat the
implementation as a candidate until that qualification is complete.

The 78 sampled failure cases pass cold-mount old-or-complete recovery, retry
and selected chunk checks. This does not replace full-content cold verification
or exhaustive cuts. The QEMU stopped image independently verifies, the Duo
release compile check passes, source hashes match the build manifest and
`git diff --check` passes. No actual SD device was exercised.

### Full cold reads and large QEMU namespace batches (2026-09-13)

The retained ignored `multi_segment_batch_cold_mount_reads_every_chunk` test
publishes 331, 512 and 1,000 unique-index 4 KiB chunks, both immediately after
namespace setup and after GC. All six cases pass (3,686 chunks checked after
cold mount). Destroy the original handles/store, power-cycle the device, create
a fresh runtime, recover the tail from its typed identity, then compare every
chunk. Assert one checkpoint-generation advance, the complete object count,
and actual new metadata pointers spanning two segments (331/512) or four
(1,000). The 64-segment host fixture uses a permissive 64 MiB recovery budget;
this is not a whole-operation memory-admission proof.

An initial fixture assumption incorrectly treated the no-GC case as allocation
v1. The current formatter already produces v2; that assertion failed before the
batch operation. The corrected test explicitly asserts v2 and names the two
cases by GC history. It does not cover legacy v1 images. Preserve the initial
logs rather than presenting them as a runtime regression or v1 qualification.

Run real namespace create-and-full-verify diagnostics on fresh temporary disks
in 128 MiB QEMU, one hart, 64-page cache, seed 32 and unique 4 KiB file content:

| Files | Status | Read bytes / requests | Write bytes / requests | Flushes |
| --- | --- | ---: | ---: | ---: |
| 331 | Pass | 9,809,920 / 1,686 | 10,272,768 / 90 | 5 |
| 512 | Pass | 15,294,464 / 2,623 | 15,769,600 / 132 | 6 |
| 1,000 | Pass | 29,138,944 / 5,041 | 30,629,888 / 248 | 8 |

All three stopped images independently verify, including their live file trees
and unchanged unmanaged prefixes. This extends beyond the maintenance-stream
fixture: the guest stages separate files, commits the namespace transaction and
checks each file's complete byte pattern. The initial 331/512 diagnostics overlap
correctness/verification work; no timing comparison is derived from these runs.

The shell's unique-file benchmark now admits up to 1,000 files when each is at
most 4 KiB; counts up to 100 retain the previous 128 KiB per-file bound. The
initial experiments temporarily widened the guard in separately recorded builds,
then restored it byte-for-byte. The final qualified build uses the retained,
narrower guard with no temporary shell edit. This guard is a tested diagnostic
range, not a promise that every populated volume or concurrent workload has
sufficient capacity/memory. No SD latency claim follows from QEMU results.

Evidence: `target/storage-metadata-cold-read-20260913/`,
`target/storage-metadata-qemu-large-20260913/` (331 and `512/`), and
`target/storage-metadata-qemu-1000-20260913/` (initial experiment and final
`qualified/`). Commands, firmware/source hashes, content-check logs, preserved
images and independent verifier results are retained. Exhaustive multi-segment
fault coverage, fragmented-space recovery/GC, legacy-v1 compatibility and
isolated before/after performance remain outstanding.

The final qualified 1,000-file firmware passes full guest verification and
independent stopped-image verification. All counters exactly repeat the initial
1,000-file experiment, source hashes match the build manifest (including the
retained shell guard), the cache override is restored and `git diff --check`
passes. No processes from this qualification remain running.

### Resumable exhaustive cross-segment fault qualification (2026-09-13)

Retain the sampled fault test and add an ignored exhaustive variant sharing the
same 331-chunk publication fixture. By default it visits every one of 2,381
page-write/flush mutation positions. Explicit `VIBEOS_MULTI_FAULT_START` and
`VIBEOS_MULTI_FAULT_END` select a nonempty half-open shard; malformed/out-of-range
bounds fail. Each position tests NotSubmitted, AmbiguousNone and AmbiguousDurable.
Cold recovery must have the exact old or complete object count and matching
checkpoint generation. Whenever recovery exposes the new batch, recover its tail
by typed identity and compare all 331 chunks before retrying publication. Retry
still checks chunks 0/127/255/330. Thus full content is checked for a fault-exposed
new batch, while retry verification remains sampled; do not conflate the two.

The strengthened tail shard [2365, 2381) passes all 48 outcomes. The allocation
reservation policy test also passes an alternating allocated/free 64-segment map:
there is no contiguous two-segment run, but a one-slot request plus the remaining
slots can reserve the complete fragmented set up to the cleaner/root-policy
floor. Requesting one additional slot is refused. This validates the reservation
gate, not physical fragmented publication, GC or cold recovery on such a volume.

The full campaign is launched from
`target/storage-metadata-fault-exhaustive-20260913/full/run.py` using a copied,
SHA-256-pinned test executable and source manifest. It runs disjoint 64-position
shards and checks successful exit plus every expected per-position result before
recording coverage. A missing/duplicate/out-of-range result or test failure stops
the campaign. Final success requires all 2,381 positions / 7,143 outcomes; the
48-outcome tail shard alone does not satisfy this requirement. The runner refuses
to overwrite existing evidence. Test bounds allow a separately recorded shard
to be rerun without redefining the required full coverage.

At this entry's creation the full campaign is still running; `full/coverage.json`
records completed shards and the active range, and each shard has its raw log.
A running-state file alone does not prove a live process; monitor the actual exec
session and use terminal results for completion. No runtime code changes in this
qualification turn. Timed QEMU comparisons must wait until the campaign is idle.
Full fragmented-space recovery/GC, legacy-v1 compatibility and performance
qualification remain outstanding. `git diff --check` passes.

### Live cross-segment batch relocation and cold recovery (2026-09-13)

Add the ignored `multi_segment_batch_survives_gc_and_cold_namespace_recovery`
test. Publish a 331-chunk stream using the multi-segment metadata writer, attach
it to an inode-tree entry and persist its Fs namespace root. Release all stream,
root and maintenance handles before collection; only the persistent root keeps
the stream live. Add dead objects to provide collection work, and require actual
relocation of data manifests before accepting the fixture. After destroying the
store and power-cycling its device, create a new runtime, recover the namespace
and its data reference, then compare every chunk.

The retained test passes: all 331 data manifests move and all 331 chunks verify
after cold mount. Its relocation predicate filters `FS_DATA_V1_KIND`, so moving
only an inode/dirent/root manifest cannot satisfy the assertion. The first run
counted all 334 manifests, including three structural objects; the strengthened
run explicitly reports the 331 data manifests. Evidence preserves both logs.
The 64-segment host fixture uses a permissive 64 MiB recovery budget. This is
successful live relocation of a typed Fs namespace, not a GC power-cut matrix,
a deliberately fragmented allocation fixture, or guest memory admission.

Evidence: `target/storage-metadata-gc-20260913/` contains build/test output,
source hash and qualification results. No runtime source changes. An in-memory
comparison removes only the newly added GC test from the current source and
matches every file hash in the already-running exhaustive fault campaign's pinned
manifest, confirming that this test addition does not invalidate that runtime
qualification. `git diff --check` passes.

The 2,381-position / 7,143-outcome fault campaign remains in progress in its
original exec session. Per-position progress in an active shard is provisional
until that shard exits successfully and the runner validates complete coverage.
Its completion, fragmented-space recovery, legacy-v1 compatibility and isolated
performance comparisons remain outstanding; no new QEMU timing is collected
while it runs.

### Legacy allocation-v1 cross-segment publication (2026-09-13)

Generalize the existing M7.4 legacy-image fixture to optionally leave ordinary
free space beyond the cleaner reserve. The original full-prefix helper passes
zero extra space and retains its old callers. The new case starts from encoded
media: a legacy allocation extent and checkpoint, not a patched in-memory
`allocation_version`. A 64-segment image starts with a 10-segment allocated
prefix and a six-segment cleaner reserve. Existing CAS content remains unchanged.

The ignored `legacy_v1_multi_segment_batch_publishes_and_cold_reads` test mounts
that image, publishes 331 unique-index 4 KiB stream chunks under one checkpoint,
and decodes the newly written allocation payload with the v1 decoder. Its prefix
grows 10 -> 14. Decode the published CAS snapshot and require new manifest/catalog/
allocation pointers to occupy exactly metadata segments 12 and 13, the final two
contiguous segments of that prefix. Thus this exercises the v1 dedicated-segment
branch across the old single-metadata-segment boundary.

Attach the stream to a persistent Fs namespace, destroy all handles and the
store, create a fresh runtime, recover the namespace and compare all 331 chunks.
The new test passes together with all four pre-existing tests selected by
`legacy_`, including the legacy GC bootstrap mutation matrix. This is successful
v1 publication plus cold namespace reading, not a new per-write fault matrix for
the legacy multi-segment branch. The fixture uses a permissive 64 MiB host
recovery budget and makes no SD timing or guest memory-admission claim.

Evidence: `target/storage-metadata-legacy-20260913/` retains initial and qualified
logs, test-source hash and result summary. No runtime code changes. The pinned
v2 exhaustive fault campaign remains running in its original session; its first
64-position shard has completed and its 192 outcomes/log hash were independently
checked. Active-shard results are not counted as completed coverage. Full v2 fault
coverage, deliberately fragmented physical publication/recovery and isolated
performance qualification remain outstanding. `git diff --check` passes.

### Physical fragmented metadata publication and cold recovery (2026-09-13)

Add the ignored `multi_segment_batch_uses_fragmented_free_segments_and_cold_recovers`
test. Build a real 96-segment test volume using five rounds of normal 4 KiB /
128 KiB object commits and collection. Retain selected runtime handles during
fixture construction and release older ones to create holes. Consume the leading
contiguous free range with additional real commits, leaving room for packed batch
data ahead of the isolated metadata slots. No allocation bitmap or physical
record is patched to fabricate fragmentation.

Publish 331 unique-index 4 KiB stream chunks. Inspect the actual new manifest,
catalog and allocation pointers and require at least two metadata segments with
a physical gap. The passing fixture places metadata in segments **26 and 28**;
segment 27 is occupied. A run that accidentally chooses a contiguous set fails the
fixture assertion and cannot count as fragmented coverage. Attach the stream to
the persistent Fs namespace, release all construction handles, destroy the store,
power-cycle the device and recover through a fresh runtime and namespace root.
All 331 chunks compare equal after cold mount.

This validates physical fragmented placement plus successful cold recovery. It
complements the earlier reservation-policy test and live GC relocation test;
it does not replace a power-cut matrix on this particular fragmented layout.
The fixture uses a permissive 64 MiB host recovery budget and is not a guest
memory-admission or SD timing result.

Evidence: `target/storage-fragmentation-probe-20260913/` records the initial
normal-GC free-space observations, exact restoration of the temporary exploratory
source, final publication/cold-read log and qualification/source hash. The retained
test includes the complete fixture construction. Removing only the subsequently
added GC and fragmentation tests from current source reproduces every source hash
of the running pinned fault campaign; runtime and campaign test logic are unchanged.
`git diff --check` passes.

The exhaustive 2,381-position campaign remains live in its original session.
Full fault coverage and isolated before/after performance qualification remain
pending; successful fragmented cold recovery does not establish either.

### Independent fault-coverage audit (2026-09-13)

`target/storage-metadata-fault-exhaustive-20260913/full/audit.py` independently
checks the pinned executable hash, completed-log hashes, contiguous shard ranges,
exact shard headers, every expected position with three outcomes, and successful
test termination. Its negative checks reject duplicate/missing positions, wrong
outcome counts, wrong range headers and truncated terminal results. Active-shard
progress is excluded. `--require-complete` exits 2 for partial coverage and can
succeed only after all 2,381 positions / 7,143 outcomes pass; a failed runner exits
1. Runner-state reporting does not establish process liveness, which is checked
through the original exec session.

The current partial audit verifies 192 positions / 576 outcomes. The strict
completion invocation correctly exits 2. The original campaign remains running;
no runtime source or benchmark timings change during this audit.
