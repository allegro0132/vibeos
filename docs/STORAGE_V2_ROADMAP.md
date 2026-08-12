# Storage V2 roadmap

Storage V2 replaces the fixed M4 journal backend with a scalable
capability-addressed Blob CAS over managed logical-block devices. It preserves
the existing `StoredObject` authority boundary and Merkle verification semantics
while adding bounded recovery, segment cleaning, garbage collection, quotas, and
online growth.

This roadmap is ordered by proof dependencies rather than calendar dates. A
later stage must not weaken an earlier stage's crash, authority, cancellation,
or memory-bound acceptance evidence.

## Scope and fixed decisions

Storage V2 supports block devices that expose logical blocks and a truthful
ordered-durability operation. The initial backends are virtio-blk and the
managed-flash microSD path; eMMC and NVMe may implement the same contract later.

The following decisions are fixed for M7:

- The public namespace remains capability-only. A digest identifies bytes but
  never authorizes access; there is no `open(digest)`, path lookup, or ambient
  object enumeration.
- A durable `ObjectId` remains distinct from a physical `BlobKey`. Multiple
  independently revocable objects may share one Blob without sharing authority.
- `BlobKey` is the tagged tuple `(hash algorithm, object kind, exact byte length,
  Merkle root)`. The initial deduplication unit is a complete Blob, not an
  individual 4 KiB leaf.
- The existing SHA-256 Merkle format remains the logical content format. Its
  implementation moves to the pure-Rust `sha2` crate with default features
  disabled; the byte format and all existing roots must remain unchanged.
- Storage uses immutable data records, copy-on-write metadata, and an atomically
  selected checkpoint. It does not introduce a POSIX filesystem underneath the
  object store.
- Partition discovery and resizing remain image/provisioning policy. The store
  grows only by consuming an exact, non-overlapping `BlockRange` capability.
- Correctness depends on write ordering plus flush or FUA. Discard is an optional
  post-reclamation optimization and is never a commit primitive.
- The first implementation remains single-device and single-metadata-writer.
  Reads and garbage collection may overlap only after the read-pin protocol is
  proven.

Explicit non-goals are raw NOR/NAND, an FTL, directories, mutable in-place files,
chunk-level deduplication, compression, encryption, rollback resistance,
multi-device RAID, online shrink, and a general concurrent-writer protocol.

## Open-source reuse boundary

The production data path directly adopts `sha2`; it does not embed `redb`,
`fjall`, `littlefs`, or another filesystem/KV engine. Those engines assume a
host filesystem or solve raw-flash concerns outside this milestone, while none
understands VibeOS capability publication and root liveness. Host-only tools may
use ordinary Rust storage crates as independent models, but powered-off
acceptance must still parse the canonical VibeOS format without trusting the
guest implementation.

Small general-purpose dependencies are admitted only behind narrow interfaces,
with `no_std` firmware builds, license/provenance review, bounded-allocation
tests, and on-media compatibility fixtures. Serialization of authority,
checkpoints, and physical pointers remains an explicit canonical codec rather
than a derived Rust object representation.

## Target architecture

```text
application or optional typed manifest service
                       |
                 StoredObject Cap
                       |
        persistent authority and root policy
                       |
        ObjectId -> BlobKey capability catalog
                       |
       Blob CAS: hash, verify, deduplicate, range read
                       |
       segment store: extents, checkpoint, GC, grow
                       |
       BlockRange Cap over a managed block device
```

The crates should converge on these boundaries:

| Crate | Responsibility |
|---|---|
| `blob-format` | Canonical logical Blob descriptor, Merkle tree, proofs, and `BlobKey` construction |
| `storage-device` | Block geometry, bounded range I/O, flush/FUA, and optional discard contracts |
| `segment-format` | Zero-allocation encoders/decoders for superblocks, checkpoints, segment summaries, and extent records |
| `segment-store` | Allocation, append, recovery, index checkpoints, cleaning, quotas, and growth |
| `object-store` | Capability checks, `ObjectId -> BlobKey`, durable authority ordering, and publication |

`segment-format` must remain independent of the kernel and block drivers so host
tests and powered-off image verifiers can exercise the exact production decoder.

## On-media direction

The format is versioned independently from the M4 journal. Exact field layouts
are frozen in M7.2, but the structural direction is:

```text
reserved anchor area
  superblock A
  superblock B

checkpoint
  store UUID and format version
  committed generation
  catalog root
  authority root
  allocation root
  admitted device ranges and segment count

segments
  immutable segment header
  immutable Blob/extent records
  immutable segment summary
  segment seal
```

Every physical pointer is bound to a store UUID, segment number, segment
generation, offset, and exact length. A stale pointer into a recycled segment
must fail validation rather than read unrelated new content.

A commit follows this ordering:

1. Write new Blob data and its segment records.
2. Flush the data dependency.
3. Write the catalog and authority deltas that reference that data.
4. Flush the metadata dependency.
5. Write and durably select a new checkpoint generation.
6. Reread and validate the committed result.
7. Publish the live capability into the unchanged target CSpace incarnation.

No old segment becomes reusable before step 5 is durable. The previous
checkpoint remains a valid fallback throughout a torn checkpoint switch.

## Milestones

### M7.0 — Freeze compatibility and adopt `sha2`

**Status: complete (2026-08-12).** The frozen M4 fixtures, dependency audit,
firmware-size and portable-throughput measurements are recorded in
[STORAGE_V2_EVIDENCE.md](STORAGE_V2_EVIDENCE.md).

**Outcome:** Storage V2 starts from an unchanged, independently verified Blob
identity.

Work:

- Add `sha2` with default features disabled to `blob-format`.
- Replace the production private SHA-256 implementation with `sha2::Sha256`.
- Keep the current implementation temporarily as a test-only differential
  oracle, then remove it after the compatibility gate is committed.
- Record dependency license/provenance and keep the Cargo lock pin authoritative.
- Capture M4 fixtures containing empty, one-leaf, multi-leaf, and maximum-sized
  canonical Blobs for permanent compatibility tests.
- Measure firmware size and portable hashing throughput before and after the
  change; performance is recorded but byte compatibility is the gate.

Acceptance:

- Every existing Blob encoding, descriptor, Merkle root, and proof remains
  byte-identical.
- `cargo test -p vibeos-blob-format -p vibeos-object-store` and the existing
  `blob` QEMU/raw-image acceptance remain green.
- Firmware builds prove that the selected `sha2` configuration is `no_std` and
  introduces no runtime CPU-feature detection dependency.

### M7.1 — Capability-scoped block contract

**Status: complete (2026-08-12).** The accepted range, geometry, legacy
adapter, and mutation-ambiguity contract is recorded in
[STORAGE_DEVICE.md](STORAGE_DEVICE.md).

**Outcome:** storage consumes an explicitly authorized block range and can make
correct decisions from device geometry without knowing board or partition
details.

Work:

- Introduce `BlockRange { device_id, first_block, block_count }` as a resource
  that can be granted and attenuated but not widened.
- Replace the fixed-sector service interface with bounded range reads/writes and
  a reported logical block size.
- Report physical block size, preferred write size/alignment, maximum transfer,
  volatile-write-cache state, flush/FUA support, and optional discard geometry.
- Preserve a 512-byte adapter for the M4 store during migration.
- Specify the exact failure and ambiguity semantics of write, flush, FUA,
  cancellation, driver restart, and revocation.

Acceptance:

- Host models reject overflow, out-of-range I/O, overlapping grants, stale
  device incarnations, and rights amplification.
- The store cannot address the boot partition or any byte outside its
  `BlockRange` capability.
- Existing virtio-blk and Milk-V block acceptance stays green through the
  compatibility adapter.

### M7.2 — Canonical segment format and crash model

**Status: complete (2026-08-12).** The frozen page ABI, independent powered-off
parser, strict seal-prefix crash model, opaque verified-record API, checked
geometry, and cross-language fixture are recorded in
[STORAGE_V2_FORMAT.md](STORAGE_V2_FORMAT.md) and
[STORAGE_V2_EVIDENCE.md](STORAGE_V2_EVIDENCE.md).

**Outcome:** a pure `no_std` format crate can encode, reject, and recover every
Storage V2 structural record without performing I/O or allocating.

Work:

- Freeze the dual-superblock, checkpoint, segment header, extent, summary, and
  seal formats with explicit endianness and checked arithmetic.
- Bind every record to store UUID, format version, segment identity, generation,
  and record kind.
- Define the device atomicity requirement. If one logical block is not a proven
  atomic write unit, use a separately flushed body plus seal instead of assuming
  CRC supplies atomicity.
- Build an independent host image parser before the kernel writer.
- Generate corruptions, strict byte-prefix tears, reordered completions, stale
  generations, duplicate records, pointer overlap, and allocation amplification
  cases.

Acceptance:

- Every write and flush boundary recovers either the previous checkpoint or the
  exact new checkpoint, never a mixed state.
- Every sealed malformed structure fails closed.
- Decoder memory is constant in the media size; index rebuilding is explicitly
  budgeted by later checkpoints rather than hidden allocation.

### M7.3 — Append-only segment store

**Status: complete (2026-08-12).** The bounded `no_std + alloc` writer,
catalog/allocation payload ABI, exhaustive mutation-boundary model, and
powered-off Rust-to-Python reconstruction gate are recorded in
[STORAGE_V2_STORE.md](STORAGE_V2_STORE.md) and
[STORAGE_V2_EVIDENCE.md](STORAGE_V2_EVIDENCE.md).

**Outcome:** the current object API can persist immutable extents in a scalable
region without GC.

Work:

- Implement segment allocation, append, sealing, summaries, and dual-checkpoint
  selection in a separate `segment-store` crate.
- Reserve cleaner headroom from format time even though cleaning is not yet
  enabled. Admission must preserve enough free segments for one future maximum
  evacuation transaction.
- Add an on-media catalog checkpoint plus bounded delta replay so normal boot
  does not scan every Blob byte.
- Keep one metadata writer, do not hold a capability or store lock across an
  await, and invalidate all cached cursors after ambiguous I/O.
- Provide the old `put/get` surface through an adapter to isolate the backend
  replacement from authority logic.

Acceptance:

- Dense multi-segment recovery has a measured and enforced memory ceiling.
- All cancellation, component fault, driver restart, and out-of-space points
  preserve the preceding committed checkpoint.
- Powered-off host verification reconstructs every committed object and rejects
  all extents outside the admitted range.
- `JournalFull` is replaced by a truthful distinction between payload capacity,
  metadata capacity, and reserved cleaner capacity.

### M7.4 — Streaming Blob CAS and deduplication

**Outcome:** large Blobs no longer require one contiguous caller allocation, and
identical content shares physical storage without sharing authority.

Work:

- Add a bounded `BlobWriter` transaction: `begin(kind, exact_len)`, ordered chunk
  writes, and `commit(target_cspace)`. Dropping or cancelling a normal writer
  releases its volatile claim, but correctness never relies on `Drop`: an
  abandoned fault-domain writer leaves only unpublished records which recovery
  classifies as reclaimable.
- Compute the existing SHA-256 Merkle structure incrementally with bounded
  working storage.
- Persist `BlobKey -> extents` and `ObjectId -> BlobKey` separately.
- Deduplicate only complete verified Blobs. A caller-supplied digest is a
  verification hint, never lookup authority.
- Make `get_blob_chunk` issue only the required extent reads plus proof reads;
  retain whole-Blob verification as an explicit operation.
- Define collision handling as a full descriptor and byte verification before
  reusing an existing physical Blob.

Acceptance:

- Two identical puts allocate one physical Blob but return independently
  revocable object capabilities.
- Revoking one object does not invalidate another object backed by the same Blob.
- No API permits obtaining a capability from `BlobKey` alone or distinguishes
  an unauthorized present Blob from an absent one.
- Interrupted writers publish no capability; their records are reclaimable by
  M7.5 without being treated as corruption.
- Peak RAM is bounded independently of Blob length.

### M7.5 — Root-based GC and segment cleaning

**Outcome:** unreachable storage is reclaimed without racing live capabilities,
readers, persistent authority, or crash recovery.

The mark root set is the union of:

- objects admitted by external persistent root policy;
- typed child references reachable from admitted immutable manifests;
- live in-memory object resources and their invocation leases;
- active Blob readers and explicit snapshots;
- committed objects protected by in-flight authority or migration transactions.

Work:

- Define which `ObjectKind` values may contain references and give each a
  canonical, fail-closed child parser. Arbitrary Blob bytes never become GC
  edges.
- Snapshot roots into a GC epoch and pin every reader to an extent-map
  generation.
- Select low-live-ratio segments, copy live records, verify them, publish a new
  catalog/checkpoint, wait for old reader generations to quiesce, and only then
  recycle the source segments.
- Treat reference counts and live-byte estimates as hints; mark reachability is
  authoritative.
- Add foreground incremental cleaning before admission failure. Background
  cleaning is optional and must have explicit I/O, CPU, and memory budgets.
- Issue optional discard only after a segment is logically free and checkpoint
  fallback no longer references it.

Acceptance:

- Power failure at every copy, flush, checkpoint, quiescence, and reclaim
  boundary loses no reachable object and resurrects no revoked authority.
- Reads concurrent with cleaning return the old verified bytes or retry through
  the new mapping; they never observe a recycled extent.
- A shared Blob remains live until every authorized object and runtime pin is
  gone.
- Repeated put/revoke/GC cycles reach stable space, heap, and task counts.
- Cleaner write amplification, reclaimed bytes, pause time, and reserve pressure
  are exported as bounded telemetry.

### M7.6 — Online growth, quotas, and scrub

**Outcome:** an authorized administrator can add capacity without reboot-time
formatting or partition-table mutation, and one client cannot consume the
cleaner's safety margin.

Work:

- Add a distinct attenuable `StoreMaintenance` capability resource for `grow`,
  `scrub`, and explicit maintenance; ordinary Store `WRITE` cannot perform these
  operations.
- Implement `grow(additional: BlockRangeCap)` for an adjacent range on the same
  device identity. Record and checkpoint the new range before allocating from it.
- Keep partition-table edits in image tooling or external provisioning.
- Add logical-byte and physical-byte quotas per admitted storage principal;
  report dedup savings separately rather than letting dedup change authority
  accounting accidentally.
- Add online verification of segment summaries, catalog mappings, Blob trees,
  and checkpoint fallback without granting object read authority to the caller.
- Add high-water, GC-pressure, corruption, and device-health diagnostics without
  exposing object identities.

Acceptance:

- A power cut at every grow boundary exposes either exactly the old range set or
  exactly the enlarged set.
- Growth rejects overlap, gaps forbidden by policy, a changed device identity,
  arithmetic overflow, and a range not covered by the supplied capability.
- Quota exhaustion cannot consume cleaner reserve or block unrelated principals
  from reading existing data.
- Scrub detects every injected data, tree, summary, mapping, and checkpoint
  corruption and never silently repairs authority.

### M7.7 — M4 migration and default cutover

**Outcome:** existing persistent programs and admitted capabilities migrate once
to Storage V2 with independent powered-off evidence and a recoverable rollback
window.

Work:

- Detect M4 and Storage V2 formats without treating an arbitrary corrupt image as
  either one.
- Add an explicit migration operation requiring `StoreMaintenance`; never
  migrate automatically merely because an old journal is present.
- Recover the M4 journal through its existing strict decoder, select only the
  objects and authority graph admitted by external root policy, and write them to
  a disjoint Storage V2 range.
- Commit and independently verify Storage V2 before changing boot preference.
- Keep the M4 area read-only during one release/format generation. Final removal
  or reuse requires a separate explicit operation after rollback is no longer
  required.
- Switch program persistence, SSH identity, and persistent CSpace recovery to the
  same Storage V2 checkpoint.

Acceptance:

- One image completes old boot, interrupted migration, successful migration,
  Storage V2 boot, and capability-equivalent program execution.
- Every interruption before the Storage V2 checkpoint leaves M4 authoritative;
  every interruption after boot preference changes leaves a complete verified
  Storage V2 state.
- A host verifier proves object bytes, Blob roots, admitted authority, range
  isolation, and absence of extra roots on the powered-off image.
- The legacy `store`, `blob`, persistent CSpace, and program-persistence gates
  remain as compatibility tests until the rollback window closes.

## Cross-cutting evidence and performance gates

Every milestone includes host unit tests, format fuzzing, a fake-block power-cut
model, QEMU raw-image verification, and at least one shell-visible diagnostic.
Milk-V acceptance is required for changes to the durability contract or data
partition policy, not for pure format helpers.

Storage V2 publishes these measurements with device, geometry, build profile,
and dataset recorded:

| Metric | Required interpretation |
|---|---|
| Put/read throughput by Blob size | Separate hashing, device I/O, and commit latency |
| Commit latency distribution | Include every flush and reread required for publication |
| Recovery time and bytes read | Distinguish checkpoint load, delta replay, and fallback scan |
| Peak heap and fixed scratch | Report against Blob count, segment count, and Blob size |
| Logical/physical bytes | Expose metadata, padding, dedup savings, and reserved capacity |
| GC write amplification | Bytes written by cleaner divided by newly admitted logical bytes |
| GC pause and reader retries | Show foreground and background cleaning separately |
| Hash throughput and code size | Preserve the M7.0 `sha2` baseline |

An optimization does not land solely because it improves a synthetic throughput
number. It must preserve the power-cut matrix, authority checks, bounded recovery,
and tail-latency budgets.

## Dependency order

```text
M7.0 SHA compatibility
  |
M7.1 block contract
  |
M7.2 segment format
  |
M7.3 append-only segment store
  |
M7.4 streaming CAS
  |
M7.5 GC and cleaning
  |
M7.6 grow, quota, scrub
  |
M7.7 migration and cutover
```

M7 is complete only when the fixed 512-sector journal is no longer the default
backend, a full-capacity/revoke/GC/grow/reboot cycle is independently verified,
and no digest or persistent media identifier has become ambient authority.

## Risk register

| Risk | Mitigation |
|---|---|
| A digest becomes lookup authority | Keep `ObjectId -> BlobKey` private, require an object capability on every read, and test indistinguishable unauthorized/missing results |
| GC reclaims a live shared Blob | Mark from persistent roots plus runtime pins, bind readers to generations, and delay reuse until quiescence |
| Cleaner deadlocks on a full device | Reserve evacuation capacity at format time and exclude it from ordinary quota admission |
| Device durability claims are weaker than the format assumes | Admit only an explicit flush/FUA contract, retain reread verification, and use body-plus-seal when atomicity is unproven |
| Catalog checkpoints make recovery memory scale without a bound | Measure and reject configurations beyond declared index/replay budgets; keep a streaming fallback verifier |
| Dedup lets accounting cross authority boundaries | Charge logical bytes to principals and account physical sharing separately |
| Interrupted migration leaves two plausible authorities | Require disjoint ranges, an explicit boot-preference commit, and keep M4 read-only through the rollback window |
| A dependency update changes hashes or target behavior | Pin through Cargo.lock, retain permanent byte fixtures, and run host/QEMU/firmware compatibility gates before updates |
