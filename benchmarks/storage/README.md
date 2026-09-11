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
