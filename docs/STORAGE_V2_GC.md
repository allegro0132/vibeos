# Storage V2 root-based GC and segment cleaning

This document freezes the M7.5 contract for root discovery, typed traversal,
reader pins, live-Blob marking, relocation, and safe segment reuse. It builds on
the immutable record/checkpoint rules in
[STORAGE_V2_FORMAT.md](STORAGE_V2_FORMAT.md), the segment-store contract in
[STORAGE_V2_STORE.md](STORAGE_V2_STORE.md), and the Object/Blob split in
[STORAGE_V2_CAS.md](STORAGE_V2_CAS.md).

This is the normative format and acceptance specification implemented by M7.5.
The corresponding host, power-cut, independent-codec, lint, and firmware-build
results are recorded in `STORAGE_V2_EVIDENCE.md`.

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

## Scope and safety invariant

M7.5 remains single-device and single-metadata-writer. It does not add ambient
ObjectId lookup, concurrent writers, rollback protection, online shrink,
discard-based correctness, or mutable in-place Blob data.

A segment may change from Retired to Free only when all of these conditions are
true:

1. the selected `G+1` catalog and root set no longer contain a current pointer
   into the segment;
2. every Blob reachable from the complete root union was marked, copied when
   needed, reread, and authenticated before `G+1` was sealed;
3. every reader pin through extent-map generation `G` has drained;
4. the old checkpoint `G` seal was cleared, flushed, and read back as one exact
   all-zero page; and
5. a `G+2` checkpoint durably publishes the Retired-to-Free allocation
   transition.

Reference counts, owner counts, live-byte estimates, and live-ratio estimates
are scheduling hints only. The mark closure is the liveness authority. An
ObjectId, BlobKey, typed reference, root entry, allocation entry, or telemetry
record never grants read authority.

## Frozen media boundary

M7.5 adds no generic `VIBEGC*` root snapshot, mark snapshot, relocation ledger,
phase header, or other persistent GC-evidence payload. The persistent contract
is exactly the following existing codecs:

- allocation v2: `VIBEALC2`, version 2;
- persistent root set: `VIBERST2`, version 1;
- typed child references: `VIBEREF1`, version 1; and
- CAS snapshot/delta version 2's `ObjectMapping.reference_codec` tag.

Runtime-root snapshots, mark sets, relocation worklists, and pin state are
bounded in-memory state. Crash recovery infers progress only from valid sealed
checkpoints, allocation-v2 segment states, the retirement-generation table,
and the exact-zero old checkpoint seal.

## Allocation v2 (`VIBEALC2`)

Allocation v2 is the payload of one `ExtentKind::Allocation` extent. It has a
`0x80`-byte header, an exact two-bit state bitmap, and a canonical retirement
table. Its maximum encoded length is one metadata extent (`256 * 4096` bytes).

### Header (`0x80` bytes)

| Offset | Size | Field | Canonical value or constraint |
|---:|---:|---|---|
| `0x00` | 8 | magic | ASCII `VIBEALC2` |
| `0x08` | 2 | version | 2 |
| `0x0a` | 2 | header length | `0x80` |
| `0x0c` | 4 | flags | 0 |
| `0x10` | 8 | checkpoint generation | Non-zero; owning checkpoint generation |
| `0x18` | 8 | admitted segment count | Non-zero |
| `0x20` | 8 | next segment generation | Non-zero |
| `0x28` | 4 | cleaner reserve segments | New M7.5 format: at least 2 and less than admitted count; older values remain decodable |
| `0x2c` | 2 | state bits per segment | 2 |
| `0x2e` | 2 | retired entry length | `0x10` |
| `0x30` | 8 | bitmap offset | `0x80` |
| `0x38` | 8 | bitmap byte length | `ceil(admitted_segments / 4)` |
| `0x40` | 8 | retirement table offset | `0x80 + bitmap_byte_len` |
| `0x48` | 8 | retirement entry count | Exact table count |
| `0x50` | 8 | Free count | Exact bitmap population |
| `0x58` | 8 | Allocated count | Exact bitmap population |
| `0x60` | 8 | Retired count | Exact bitmap population and table count |
| `0x68` | 8 | encoded length | Header + bitmap + retirement table |
| `0x70` | 16 | reserved | All zero |

Segment `4 * byte_index + n` occupies bits `2*n..2*n+1`, least-significant
pair first:

| Bits | State | Meaning |
|---:|---|---|
| `00` | Free | Eligible for allocation only through the normal seal-clear reuse path |
| `01` | Allocated | May be the target of a current pointer |
| `10` | Retired | Preserved for an older checkpoint or pinned reader; never allocate |
| `11` | invalid | Decoder fails closed |

All unused high bits in the final bitmap byte MUST be zero. The three state
counts MUST sum to the admitted segment count, and `Free + Retired` MUST remain
at least the cleaner reserve. Retired capacity counts toward the cleaner's
recoverable reserve but remains unavailable to allocation until G+2. With no
retired entries, the structural bitmap
limit is `(1 MiB - 0x80) * 4 = 4,193,792` admitted segments; the one-extent
encoded-length bound is authoritative when a retirement table is present.

A new M7.5 format MUST reserve at least two segments because every relocation
needs one non-empty G+1 target set and one distinct G+2 barrier segment.
Historical reserve-one media remains mountable and readable, but every cleaner
entry point returns `Capacity` before its first media mutation.

Each retirement entry is:

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x00` | 8 | segment number | In range and in Retired state |
| `0x08` | 8 | retire generation | Non-zero and no newer than the allocation checkpoint |

Entries are strictly increasing by segment number. There is exactly one entry
for every Retired segment and no entry for a Free or Allocated segment.

An immutable allocation transition accepts only these declared changes:

| Old state | New state | Operation | Additional rule |
|---|---|---|---|
| Free | Allocated | allocate | `next_segment_generation` strictly advances |
| Allocated | Retired | retire | retire generation equals the new checkpoint generation |
| Retired | Free | reclaim | allowed only after the reuse barrier below |

The allocate, retire, and reclaim lists are individually strictly ordered,
unique, mutually disjoint, and in range. All undeclared map entries remain
unchanged. The new checkpoint generation is strictly newer; the next segment
generation never regresses; admitted count and cleaner reserve remain equal.

The M7.3 prefix allocation payload may be converted deterministically in
memory: the prefix becomes Allocated, the exact suffix becomes Free, and no
segment becomes Retired. A cleaner MUST publish allocation v2 before relying on
holes or retirement generations.

Checkpoint generation is also the frozen native ObjectId high-water floor.
The production invariant is `next ObjectId == checkpoint generation`: an
Object commit issues at most one ID and advances the checkpoint generation,
while root-policy and cleaner checkpoints advance generation without issuing
an ID. Mount therefore chooses `max(last live ObjectId + 1, checkpoint
generation)`. If an imported catalog carries an ObjectId high-water above that
generation-backed floor, it remains readable, but GC MUST fail with
`ObjectIdHighWaterUnavailable` before its first media write. Bulk import in a
future format must persist an independent high-water instead of relying on this
native-production invariant.

Every physical pointer reachable from the selected checkpoint MUST target an
Allocated segment, match the store UUID, remain below the admitted count, and
have `segment_generation < next_segment_generation`. A current pointer into a
Free segment and a current pointer into a Retired segment both fail closed. The
retirement table is metadata about old segments; it is not a current physical
pointer exception.

## Persistent roots (`VIBERST2`)

The selected checkpoint's non-Null `authority_root` points to one canonical
`VIBERST2` payload in an Allocated segment. A zero-entry payload is a real empty
persistent-policy root set. It is deliberately different from a Null physical
pointer: Null authority, malformed authority, or an authority-policy mismatch
leaves normal recovery/read behavior to the authority layer but disables GC.

The root-set payload is bounded to one metadata extent.

### Header (`0x40` bytes)

| Offset | Size | Field | Canonical value or constraint |
|---:|---:|---|---|
| `0x00` | 8 | magic | ASCII `VIBERST2` |
| `0x08` | 2 | version | 1 |
| `0x0a` | 2 | header length | `0x40` |
| `0x0c` | 4 | flags | 0 |
| `0x10` | 8 | checkpoint generation | Non-zero; no newer than the selected checkpoint |
| `0x18` | 4 | entry count | Exact table count |
| `0x1c` | 4 | entry length | `0x20` |
| `0x20` | 8 | table offset | `0x40` |
| `0x28` | 8 | encoded length | `0x40 + count * 0x20` |
| `0x30` | 16 | reserved | All zero |

### Entry (`0x20` bytes)

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x00` | 16 | ObjectId | Non-zero private identity |
| `0x10` | 8 | commit generation | Non-zero and no newer than the root-set checkpoint |
| `0x18` | 4 | ObjectKind | Non-zero |
| `0x1c` | 4 | flags | 0 |

Entries are strictly increasing by ObjectId and unique. The structural maximum
is 32,766 entries. Before marking, every entry MUST resolve to the exact
`(ObjectId, commit_generation, ObjectKind)` in the selected CAS catalog. A root
entry retains an already-authorized object; it cannot be used as an ObjectId
lookup or capability-minting surface.

A newly materialized root set carries its publication checkpoint generation.
A later checkpoint may reuse that authenticated payload unchanged—for example,
G+2 may keep G+1 catalog and authority roots—so equality with the selected
checkpoint is not required. A root-set generation newer than the selected
checkpoint is invalid.

Persistent roots come only from trusted authority policy. The cleaner MUST NOT
substitute all catalog objects, all Blob mappings, the previous successful root
set, or a partial authority parse when the current root set is unavailable.

## CAS reference tag and typed references (`VIBEREF1`)

CAS snapshot/delta codec version 2 keeps each Object mapping at `0x60` bytes.
Bytes `0x58..0x59` contain the closed reference-codec tag and `0x5a..0x5f` are
zero:

| Tag | Meaning |
|---:|---|
| 0 | raw bytes; GC discovers no child edges |
| 1 | canonical refs-v1 payload, admitted by trusted ObjectKind policy |

In CAS codec version 1, all bytes `0x58..0x5f` are zero and the object is raw.
An unknown tag fails closed. The tag belongs to the Object mapping, not the
deduplicated Blob mapping: two objects may interpret identical Blob bytes
differently without changing Blob identity.

Tag 1 selects the following complete logical Blob payload.

### Refs-v1 header (`0x60` bytes)

| Offset | Size | Field | Canonical value or constraint |
|---:|---:|---|---|
| `0x00` | 8 | magic | ASCII `VIBEREF1` |
| `0x08` | 2 | version | 1 |
| `0x0a` | 2 | header length | `0x60` |
| `0x0c` | 4 | flags | 0 |
| `0x10` | 16 | admission tag | Exact bytes `vibe.refs-v1\0\0\0\0` |
| `0x20` | 4 | manifest ObjectKind | Non-zero; equals the Object mapping kind |
| `0x24` | 4 | reserved | Zero |
| `0x28` | 8 | manifest commit generation | Non-zero; equals the Object mapping generation |
| `0x30` | 4 | reference count | Exact table count |
| `0x34` | 4 | entry length | `0x28` |
| `0x38` | 8 | table offset | `0x60` |
| `0x40` | 8 | encoded length | `0x60 + count * 0x28` |
| `0x48` | 24 | reserved | All zero |

### Typed reference entry (`0x28` bytes)

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x00` | 16 | child ObjectId | Non-zero |
| `0x10` | 8 | child commit generation | Non-zero and no newer than the manifest generation |
| `0x18` | 4 | expected child ObjectKind | Non-zero |
| `0x1c` | 4 | flags | 0 |
| `0x20` | 8 | reserved | All zero |

References are strictly increasing by child ObjectId and unique; the
structural maximum is 26,212. Every edge names an exact
`(ObjectId, commit_generation, ObjectKind)`. Missing objects, stale generations,
kind mismatches, and missing Blob mappings abort marking.

Valid-looking bytes do not admit a parser. Trusted boot policy MUST first
register refs-v1 for the parent's non-zero ObjectKind; the CAS mapping MUST
carry tag 1; the actual Blob and manifest kind MUST equal that admitted kind;
and the entire authenticated payload MUST pass the canonical decoder. An
unregistered ObjectKind is raw even if its bytes begin with `VIBEREF1`.

## Runtime roots and generation pins

The mark root union contains:

- all persistent-policy entries from the verified `VIBERST2` root set;
- every live runtime object resource and invocation lease;
- active Blob readers and explicit storage snapshots; and
- in-flight authority or migration operations that must complete safely.

Every runtime root captures the exact ObjectId, commit generation, and
ObjectKind after existing authority has resolved it. Runtime root class is for
audit/telemetry only; every class is equally authoritative for liveness.

The registry has fixed root and reader-slot capacities plus configured reserve
slots. Ordinary work cannot consume the reserve. Completion-critical authority
or migration work may use it, but can never exceed physical slot capacity.
Exhaustion fails acquisition; it never silently drops a root or reader pin.

A Blob reader follows this sequence:

1. resolve existing authority, the exact object identity, and extent-map
   generation;
2. acquire both its runtime root and reader-generation pin;
3. resolve authority and the current generation again;
4. require both identities still match before starting media I/O; and
5. release both pins when the read is complete.

The GC runtime-root snapshot uses a bounded revision/retry protocol over a
preallocated destination. Concurrent changes cause a retry. Retry exhaustion
returns busy and postpones GC; it never accepts a torn or partial root set.

A cleaner may reclaim generation `G` only when every live reader-generation pin
is greater than `G`. Fault cleanup may release an owner's pins only after the
scheduler supplies proof that the fault domain has synchronously stopped.
Timeouts and wall-clock age are never proof of quiescence.

Runtime root/pin snapshots are not written as a new media payload. After a
crash, volatile pins disappear and the sealed checkpoint plus allocation-v2
retirement state remains the recovery authority.

## Bounded mark closure

Marking is pure planning over one authenticated, strictly ordered catalog view
at generation `G`; it performs no media mutation. It starts from the complete
persistent/runtime/snapshot/authority root union and computes:

- the sorted unique set of exact live Object mappings; and
- the sorted unique set of BlobKeys named by those live objects.

Raw objects contribute no child edges. A typed object is traversed only through
the admitted refs-v1 decoder. Cycles and diamonds terminate because an exact
Object mapping is marked once. A shared Blob is marked once even when many live
objects name it.

The pass fails closed and discards any partial plan on an unsorted catalog,
missing object, stale generation, ObjectKind mismatch, missing Blob mapping,
unknown reference codec, malformed typed payload, authentication error, or
budget exhaustion. Refcounts and live-byte estimates do not alter membership.

The implementation preallocates these maxima before traversal:

- root snapshot entries;
- pending/live Object entries;
- live BlobKey entries; and
- typed children decoded from one object, plus an explicitly accounted bounded
  aggregate edge table for the reachable typed closure.

Only typed objects reachable from the captured root union are decoded.
Typed-manifest admission rejects a child count larger than the per-object GC
window; unreachable typed payloads cannot exhaust or poison a live collection.

The configured `roots`, `objects`, `blobs`, and `children_per_object` budgets
are non-zero and checked on every insertion. The pin arrays are fixed-capacity,
the allocation payload is at most one metadata extent, and the cleaner's copy
buffers and relocation worklist have explicit fixed maxima. No queue or vector
may reserve from a media-derived count without an exact checked byte preflight
against the remaining ceiling; retained aggregate edge tables are accounted.
Memory acceptance records configured capacities and accounted/enforced
high-water bytes rather than assuming Rust structure padding is a stable media
property.

## Relocation and the three-state reuse barrier

The M7.5 cleaner serializes one deterministic incremental cycle. It ranks every
Allocated segment by authoritative live Blob bytes and then segment number,
grows a low-live-ratio prefix until relocation plus the G+2 barrier fit the
cleaner reserve and produce net segment reclamation, and uses the complete set
only as a conservative fallback. Unselected live extents retain their already
authenticated old pointers; selected live extents are copied. All manifests,
the CAS snapshot, root set, and allocation metadata are rebuilt canonically.
The non-empty target list and the single G+2 barrier metadata segment are
distinct Free segments at G.
Every copied extent is read and authenticated before use; its new copy is
reread and MUST bind the same BlobKey, extent index/count, exact encoded range,
extent kind, payload length, and payload SHA-256. CAS manifests and catalog
metadata are rebuilt canonically. There is no persistent relocation ledger.

The protocol is:

1. **G — base:** select and fully validate checkpoint `G`; normally require a
   non-Null authority root; capture the bounded root union; compute the complete mark
   plan; bind the exact selected Allocated source set, non-empty Free target set, and one
   distinct Free barrier metadata segment without mutating `G`.
2. Copy marked live extents, verify every new copy, and build new CAS snapshot,
   manifests, persistent root set, and allocation v2 payloads. Unpublished
   targets grant no recovery state.
3. **G+1 — relocated:** seal checkpoint `G+1`. Its current mappings point only
   into Allocated segments. Newly used target/metadata segments are Allocated;
   every selected source is Retired with `retire_generation == G+1`; no source
   is Free. Every unselected source remains Allocated. A current pointer whose
   G location was selected MUST change to an authenticated target pointer; a
   current pointer whose G location was unselected MUST remain byte-for-byte
   unchanged. Cold recovery of `G+1` MUST succeed before reuse continues.
4. Wait until the pin registry is quiescent through `G`. A racing reader either
   holds an old pin observed by this scan or fails its post-pin recheck and
   retries on the new mapping.
5. Clear checkpoint `G`'s publication seal, flush it, read back the entire seal
   page, and require exact zero. A partial clear is invalid, never sufficient.
6. **G+2 — reusable:** allocate the one reserved barrier segment for G+2
   metadata, publish an allocation-v2 transition that changes exactly this
   cycle's Retired sources to Free, and seal checkpoint `G+2`. Catalog and
   authority roots may continue to name authenticated `G+1` payloads in
   Allocated segments. Cold recovery of `G+2` MUST succeed before reporting
   reclaimed capacity.
7. A later allocation of those Free segments still performs the M7.2 final
   segment-seal clear, flush, exact-zero readback, and new segment generation
   write. `discard`/TRIM is only a performance hint.

No G+2 checkpoint may be constructed before both quiescence through `G` and
the exact-zero checkpoint-G seal readback. Merely writing G+1, waiting for a
timeout, observing no current requests, or preparing G+2 metadata is not a
reuse barrier.

### Legacy initial-root bootstrap

A pre-M7.5 CAS checkpoint may legitimately have a Null authority root and only
the historical cleaner reserve free. It cannot first write a root-policy
checkpoint without deadlocking admission. The sole exception to the non-Null
rule is `collect_garbage_with_initial_roots`: trusted code supplies existing
`AuthorizedObject` witnesses issued by the exact store runtime. The cleaner
resolves every opaque witness against the selected CAS catalog before any
media mutation, includes the same runtime-pin union, and publishes the
canonical non-Null `VIBERST2` root set inside the same G+1 relocation as the
rebuilt CAS and allocation-v2 payloads.

This bootstrap API rejects cross-store or stale witnesses and rejects any
phase whose authority root is already non-Null. A crash that selects G requires
the trusted caller to supply the witnesses again; a crash that selects G+1
resumes through ordinary `collect_garbage` to G+2. No ObjectId or BlobKey read
from media can enter this path as authority.

## Crash recovery

Recovery uses the existing sealed-checkpoint selector and accepts only states
which independently validate:

| Durable state | Selected result | Reuse rule |
|---|---|---|
| Before valid G+1 seal | G | Staged targets have no authority; sources remain Allocated |
| Valid G+1, G seal still present | G+1 | Sources remain Retired; never reuse |
| Valid G+1, G seal exactly zero | G+1 | G is absent; sources remain Retired; never reuse |
| Valid G+1, G seal torn but still marker-bearing | Explicit recovery error | Never reinterpret a torn publication marker as absent |
| G+2 body/payload written but seal invalid | G+1 | Sources remain Retired; never reuse |
| Valid G+2 after exact G clear | G+2 | Declared sources are Free and may enter normal reuse |

A valid G+1 is therefore a complete steady recovery point, not an incomplete
transaction requiring a ledger replay. Re-running the cleaner may resume by
waiting for quiescence and clearing the old seal, or may conservatively leave
the Retired segments unavailable. It MUST NOT infer Free from copied data,
missing pins after reboot, an invalid G+2 record, or absence of a current CAS
reference.

If allocation v2, persistent roots, typed references, current-pointer state, or
checkpoint ordering is inconsistent, recovery fails closed for GC. It never
repairs the bitmap by scanning, fabricates a root set, or promotes Retired to
Free without a new sealed checkpoint.

## Telemetry

Cleaner telemetry is bounded and non-authorizing. At minimum one cycle reports:

- `epoch_generation` (`G`), `relocation_generation` (`G+1`), and
  `reuse_generation` (`G+2`, or zero until sealed);
- total captured root count;
- live Object and unique live Blob counts;
- copied and reclaimed byte counts;
- retired, reclaimed, and target segment counts;
- quiescence scan/retry count;
- metadata bytes written;
- cleaner-reserve pressure in parts per million; and
- accounted/enforced memory high-water bytes;
- foreground cycle count and caller-clock monotonic pause nanoseconds; and
- derived write amplification in parts per million, using saturating telemetry
  arithmetic and returning zero when no reclaimed byte denominator exists.

Counters use checked arithmetic and declared maxima. Errors report a bounded
reason code and the protocol stage, but MUST NOT expose private ObjectIds,
BlobKeys, authority contents, or raw typed references to untrusted callers.
Capacity exhaustion, snapshot contention, missing authority, and failure to
reach quiescence are safe postponements rather than reasons to weaken marking
or reuse rules.

## Independent verifier

`scripts/verify-storage-v2-gc.py` duplicates the allocation, root, typed
reference, VIBECAS2, VIBEBMF2, and canonical Blob layouts plus the barrier
invariants without calling Rust. It imports only the frozen M7.2 physical
record, segment, checkpoint, and pointer parser. It does not invoke the legacy
M7.3 store-payload reconstruction path. Its synthetic check is:

```sh
python3 scripts/verify-storage-v2-gc.py --selftest
```

The selftest MUST exercise allocation-v2 golden decoding, Free current
pointers, Retired current pointers, tail bits and exact counts, canonical root
sets, Null-authority GC denial, typed tags/malformed payloads, and all three
G/G+1/G+2 barrier states including partial source selection, omitted/extra or
unsorted source declarations, selected pointers that were not moved,
unselected pointers that were rewritten, a selected metadata-only source, an
empty live-Blob table, reserve-one cleaner rejection, zero-seal failures, and
pin failures. Allocation-v2 decoding remains compatible with historical
reserve-one media, but any supplied G+1 trajectory requires reserve at least
two.

For Rust/Python interoperability, `--abi-fixture DIR` reads `DIR/context.json`
with `format: "vibeos-storage-v2-gc-abi"` and `version: 1`. The manifest names
the selected allocation/root payloads, a hexadecimal authority pointer,
optional current pointers, typed payload/ObjectMapping pairs with trusted
admitted ObjectKinds, and an optional barrier block. A barrier block names its
G/G+1/G+2 allocation payloads, exact transition lists, active pin generations,
and the one-page old-checkpoint seal readback. A partial barrier additionally
provides a strictly ordered `live_blob_keys` array plus complete, identically
ordered `g_blob_extent_pointers` and `g1_blob_extent_pointers` arrays. Each
extent entry binds the full BlobKey, canonical encoded Blob length, extent
index/count, encoded offset, payload byte length, and authenticated physical
pointer. Every live BlobKey must have its complete canonical extent table in
both arrays; an empty key set has two empty arrays. The verifier requires every
live extent from a selected source to move into a declared G+1 target, every live extent from an
unselected source to retain the byte-identical pointer, and every G+1 pointer
to target an Allocated segment. A selected source may be metadata-only and
therefore need not appear in the Blob extent table. Fixture filenames are
relative to the fixture directory and cannot contain `..`.

A powered-off dense image is checked with:

```sh
python3 scripts/verify-storage-v2-gc.py --raw-image storage.img
```

The raw-image mode independently selects and authenticates the physical
checkpoint and sealed segments, then parses the selected `VIBEALC2`,
`VIBERST2`, `VIBECAS2`, every `VIBEBMF2`, and every canonical Blob. It requires
a non-Null authority root, cleaner reserve at least two, no replay tail, every
current checkpoint/manifest/Blob pointer in an Allocated segment, exact
manifest-pointer SHA and descriptor identity, exact canonical header/content/
Merkle-tree bytes, persistent-root closure contained in the CAS Object table,
and the BlobKey set referenced by all CAS ObjectMappings equal to the complete
CAS Blob table. CAS objects retained only by a runtime root before power loss
are valid non-authorizing extras and are counted separately; runtime roots are
never fabricated or persisted by the verifier. Every retained object whose
typed parser is trusted must nevertheless have all direct child identities
present exactly, so runtime-retained typed subtrees cannot bypass closure
validation.
Unregistered refs-v1-tagged ObjectKinds remain opaque leaves, matching
production GC. Trusted parsers are an external policy and may be supplied only
with repeatable `--typed-reference-kind KIND`; a media tag never self-admits a
typed parser. The verifier emits `status: "ok"` only after all checks and exits
non-zero with `status: "corrupt"` for any mismatch.

This fixture is test interchange, not a new Storage V2 media record.

## M7.5 acceptance gates

M7.5 is complete only when all applicable gates below have fresh evidence:

1. Rust golden/corruption/max-boundary tests cover `VIBEALC2` v2, `VIBERST2`,
   `VIBEREF1`, CAS reference-codec tags, and exact transition rules.
2. The independent verifier selftest passes and Rust-produced ABI fixtures are
   accepted; mutations of every closed tag, length, count, reserved range,
   state, retirement generation, and transition list fail closed.
3. Mark tests cover raw objects, admitted typed objects, unregistered
   valid-looking bytes, missing/stale/kind-mismatched children, missing Blobs,
   cycles, diamonds, shared Blobs, and every budget boundary.
4. Pin tests cover reserve admission, acquisition rollback, post-pin recheck,
   concurrent root-snapshot retries, synchronous fault-domain cleanup, and
   `is_quiescent_through(G)` boundary behavior.
5. End-to-end cleaning verifies copied payload hashes, canonical rebuilt CAS,
   G+1 recovery with Retired sources, exact old-checkpoint seal clear/readback,
   G+2 recovery, and later reuse with a fresh segment generation.
6. Power cuts are injected before and after every write/flush/seal boundary in
   the protocol; recovery selects only G, G+1, or G+2 and never exposes a
   source as Free early.
7. A deterministic workload larger than initial ordinary capacity completes
   through multiple cleaner cycles without violating the configured reserve.
8. Fixed-capacity memory high-water marks and telemetry counter bounds are
   measured at maximum admitted fixtures, including exhausted-root, object,
   Blob, child, copy-buffer, and relocation-worklist cases.
9. Normal tests, strict lint, the RISC-V `no_std` build, and powered-off
   verification complete with exact commands and artifacts recorded in the
   evidence document.

The fresh results for these gates are recorded under M7.5 in
`STORAGE_V2_EVIDENCE.md`.
