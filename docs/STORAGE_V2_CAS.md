# Storage V2 streaming Blob CAS

This document is the normative M7.4 contract for streaming canonical Blobs,
complete-Blob deduplication, directed authenticated reads, and capability
publication on top of the M7.3 append-only segment store. It refines
[STORAGE_V2_STORE.md](STORAGE_V2_STORE.md) without changing the M7.2 physical
record ABI in [STORAGE_V2_FORMAT.md](STORAGE_V2_FORMAT.md).

This is a contract, not an evidence report. The results that accepted M7.4 are
recorded separately in [STORAGE_V2_EVIDENCE.md](STORAGE_V2_EVIDENCE.md); the
extended matrix at the end remains the regression and follow-up target.

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

## Scope and fixed limits

M7.4 adds a single-metadata-writer Blob CAS. It retains the capability-only
namespace and the immutable, copy-on-write, checkpoint-selected storage model.
It does not add paths, object enumeration, digest lookup, mutable files,
chunk-level deduplication, compression, encryption, rollback resistance, or a
concurrent metadata-writer protocol.

The fixed limits used by the canonical codecs are:

| Quantity | Value | Source |
|---|---:|---|
| Format page and logical Blob leaf | 4,096 bytes | `PAGE_SIZE`, `LEAF_SIZE` |
| Maximum logical Blob content | 64 MiB (`67,108,864` bytes) | `MAX_BLOB_CONTENT_LEN`, `MAX_BLOB_SIZE` |
| Maximum extent payload | 256 pages = 1 MiB (`1,048,576` bytes) | `MAX_EXTENT_PAYLOAD_PAGES` |
| Physical pointer encoding | `0x60` bytes | `POINTER_SIZE` |
| Maximum real leaves | 16,384 | `MAX_LEAF_COUNT` |
| Maximum Merkle height | 14 | `MAX_MERKLE_HEIGHT` |
| Streaming frontier slots | 15 | `STREAMING_FRONTIER_SLOTS` |
| Maximum hash emissions per streaming step | 15 | `MAX_STREAMING_EMISSIONS_PER_STEP` |

All integer fields below are unsigned little-endian. Encoders MUST zero every
reserved byte. Decoders MUST require exact lengths, known versions and kinds,
zero reserved bytes, checked arithmetic, and exact pointer bindings. They MUST
reject trailing suffixes as well as truncation.

## Canonical logical Blob

The logical content format remains the frozen `blob-format` v1 encoding:

```text
128-byte header | exact content bytes | bottom-up indexed SHA-256 tree
```

The tree suffix stores all padded leaf hashes first, followed by every parent
level from bottom to top; the final hash is the tree root. For exact content
length `L`:

```text
leaf_count        = if L == 0 { 1 } else { ceil(L / 4096) }
padded_leaf_count = leaf_count.next_power_of_two()
tree_node_count   = 2 * padded_leaf_count - 1
tree_offset       = 128 + L
encoded_blob_len  = tree_offset + 32 * tree_node_count
```

The zero-length Blob therefore has one real empty leaf and an encoded length of
160 bytes. At the 64 MiB limit, the geometry is 16,384 leaves, 32,767 tree
nodes, 1,048,544 tree bytes, and an encoded length of 68,157,536 bytes.

### Blob header ABI (`0x80` bytes)

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x00` | 8 | magic | `VIBEBLB\0` |
| `0x08` | 2 | format version | 1 |
| `0x0a` | 2 | header length | `0x80` |
| `0x0c` | 2 | hash algorithm | 1, SHA-256 |
| `0x0e` | 1 | leaf size log2 | 12 |
| `0x0f` | 1 | flags | 0 |
| `0x10` | 4 | object kind | Non-zero |
| `0x14` | 4 | reserved | All zero |
| `0x18` | 8 | exact content length | At most 64 MiB |
| `0x20` | 4 | real leaf count | Exact canonical geometry |
| `0x24` | 4 | tree node count | Exact canonical geometry |
| `0x28` | 32 | bound Merkle root | Defined below |
| `0x48` | 8 | content offset | `0x80` |
| `0x50` | 8 | tree offset | `0x80 + exact_len` |
| `0x58` | 8 | encoded Blob length | Exact canonical length |
| `0x60` | 32 | reserved | All zero |

Hash domains and integer bindings MUST remain byte-identical to the existing
`blob-format` implementation:

```text
leaf(i, bytes) = SHA256(
    "VIBEBLOB-LEAF-v1\0" || kind:u32 || i:u32 || len(bytes):u32 || bytes)

padding(i) = SHA256("VIBEBLOB-EMPTY-v1\0" || kind:u32 || i:u32)

node(level, left, right) = SHA256(
    "VIBEBLOB-NODE-v1\0" || level:u32 || left || right)

root = SHA256(
    "VIBEBLOB-ROOT-v1\0" || kind:u32 || exact_len:u64 ||
    4096:u32 || leaf_count:u32 || tree_root)
```

`level` is 1 for parents of leaves. A zero-length object uses `leaf(0, "")`,
not `padding(0)`.

### Canonical physical extent partition

The canonical encoded byte range is partitioned at its three semantic regions,
not by slicing the whole envelope into one-MiB pieces. Extents MUST be ordered
and gap-free from encoded offset zero through `encoded_blob_len`; their
`extent_index` values are `0..extent_count`, and every entry repeats the same
`extent_count`:

1. Extent 0 is exactly the `0x80`-byte Blob header at encoded offset 0.
2. The exact content range starts at encoded offset `0x80`. It uses zero or
   more extents. Every content extent except the final content extent is exactly
   1 MiB; the final content extent is the non-zero remainder, or exactly 1 MiB
   when the content length is a multiple of 1 MiB.
3. The final extent is exactly the complete serialized Merkle tree. It starts at
   encoded offset `0x80 + exact_len` and carries
   `32 * tree_node_count` bytes in one extent.

Equivalently:

```text
content_extent_count = ceil(exact_len / 1,048,576)  // zero when exact_len is zero
extent_count         = content_extent_count + 2
```

The tree extent always fits: its size ranges from 32 bytes to 1,048,544 bytes.
An empty Blob therefore has exactly two extents (header and tree). A 64 MiB Blob
has 64 content extents between those two fixed extents, for the maximum of 66.
Every admitted M7.4 manifest consequently has 2 through 66 entries and is at
most `0x2180` (8,576) bytes. Segment tail space MAY be left unused rather than
merging semantic regions or creating a non-canonical content split.

The `cas_codec.rs` constant `MAX_MANIFEST_EXTENTS` is derived from the one-MiB
metadata payload envelope and equals 8,191 table entries. That is only the
structural capacity of an arbitrary fixed-width manifest table.
`MAX_BLOB_EXTENTS` is the canonical M7.4 limit of 66; Blob-mapping and manifest
validation MUST derive the exact `content_extent_count + 2` from the BlobKey and
reject every other count or partition. A merely length-shaped 67--8,191-entry
manifest is not an admitted M7.4 Blob.

## BlobKey is identity, never authority

A `BlobKey` is the tagged tuple:

```text
(hash_algorithm, object_kind, exact_content_len, bound_merkle_root)
```

It identifies canonical bytes for internal deduplication. It is not a
capability, cannot be converted into one by public code, and MUST NOT be
accepted by a public read, open, resolve, or enumeration API. A caller-supplied
digest is only a verification hint checked against the completed stream.

### BlobKey ABI (`0x40` bytes)

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x00` | 2 | hash algorithm | 1, SHA-256 |
| `0x02` | 2 | reserved | All zero |
| `0x04` | 4 | object kind | Non-zero |
| `0x08` | 8 | exact content length | At most 64 MiB |
| `0x10` | 32 | bound Merkle root | Blob header root |
| `0x30` | 16 | reserved | All zero |

The BlobKey root is neither `SHA256(content)` nor `SHA256(canonical_envelope)`.
In particular, an M7.3 raw-content SHA-256 value MUST NOT be reinterpreted as a
BlobKey Merkle root.

## Storage V2 CAS catalog ABI

Storage V2 CAS uses codec version 1 within the Storage V2 format. The `2` in
`VIBECAS2` and `VIBEBMF2` names the Storage V2 family; it does not make the
encoded version field equal to 2.

The checkpoint catalog contains two logically separate indexes:

```text
ObjectId -> BlobKey
BlobKey  -> Blob manifest pointer -> ordered Blob extent pointers
```

Every successful put allocates a fresh, non-zero ObjectId independently of the
BlobKey. ObjectId MUST NOT be a digest truncation or other derivation of content.
Deduplication may omit a new Blob mapping, but it never omits the new Object
mapping.

The M7.4 writer emits a complete canonical CAS snapshot at each checkpoint and
sets replay depth to zero. The delta ABI below is frozen for a later bounded
replay optimization; a writer MUST NOT start emitting deltas until mount and the
independent verifier enforce the documented chain rules.

Every `PhysicalPointer` field below uses the frozen `0x60`-byte M7.2 encoding.
Mount MUST validate store UUID, admitted segment range, non-zero and historical
segment generation, record kind, exact byte length, payload digest, and absence
of duplicate or overlapping records before admitting the pointer.

### Object mapping ABI (`0x60` bytes)

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x00` | 16 | ObjectId | Non-zero `u128` |
| `0x10` | `0x40` | BlobKey | Canonical and admitted |
| `0x50` | 8 | commit generation | Non-zero and not newer than the checkpoint |
| `0x58` | 8 | reserved | All zero |

In a delta, `commit_generation` MUST equal that delta's checkpoint generation.
In a snapshot, ObjectIds MUST be strictly increasing and unique.

### Blob mapping ABI (`0xa0` bytes)

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x00` | `0x40` | BlobKey | Canonical and admitted |
| `0x40` | `0x60` | manifest pointer | Non-null Catalog pointer to exact manifest bytes |

Snapshot Blob mappings MUST be strictly ordered and unique by the BlobKey tuple
`(algorithm, kind, length, root)`. Every snapshot Object mapping MUST resolve to
exactly one Blob mapping.

### Blob manifest header ABI (`0x80` bytes)

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x00` | 8 | magic | `VIBEBMF2` |
| `0x08` | 2 | codec version | 1 |
| `0x0a` | 2 | header length | `0x80` |
| `0x0c` | 2 | extent entry length | `0x80` |
| `0x0e` | 2 | reserved | All zero |
| `0x10` | `0x40` | BlobKey | Must match the owning Blob mapping |
| `0x50` | 8 | encoded Blob length | Exact canonical geometry |
| `0x58` | 4 | extent count | Exactly `ceil(exact_len / 1 MiB) + 2`; 2 through 66 |
| `0x5c` | 4 | reserved | All zero |
| `0x60` | 8 | extent table offset | `0x80` |
| `0x68` | 8 | manifest encoded length | `0x80 + count * 0x80` |
| `0x70` | 16 | reserved | All zero |

The manifest is stored as an `ExtentKind::Catalog` payload. Its extent table
immediately follows the header, with no prefix, gap, or suffix.

### Manifest extent ABI (`0x80` bytes)

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x00` | 4 | extent index | Zero-based, equal to table position |
| `0x04` | 4 | extent count | Equal to manifest extent count |
| `0x08` | 8 | encoded offset | Exact cumulative preceding payload length |
| `0x10` | 8 | payload byte length | Exact position-derived header, content, or tree length |
| `0x18` | `0x60` | Blob pointer | Non-null `ExtentKind::Blob`, exact length match |
| `0x78` | 8 | reserved | All zero |

All manifest pointers MUST be pairwise non-conflicting. Their exact logical
ranges MUST cover `[0, encoded_blob_len)` once, in order, without overlap, gap,
or suffix. Entry 0 MUST be the 128-byte header; entries 1 through
`content_extent_count` MUST be the canonical content split; the final entry
MUST be the complete tree and no other bytes.

### CAS snapshot header ABI (`0x80` bytes)

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x00` | 8 | magic | `VIBECAS2` |
| `0x08` | 2 | codec version | 1 |
| `0x0a` | 2 | kind | 1, Snapshot |
| `0x0c` | 4 | header length | `0x80` |
| `0x10` | 8 | checkpoint generation | Non-zero |
| `0x18` | 4 | Object mapping count | Bounded by exact payload length and limits |
| `0x1c` | 4 | Blob mapping count | Bounded by exact payload length and limits |
| `0x20` | 4 | Object mapping length | `0x60` |
| `0x24` | 4 | Blob mapping length | `0xa0` |
| `0x28` | 8 | Object table offset | `0x80` |
| `0x30` | 8 | Blob table offset | `0x80 + object_count * 0x60` |
| `0x38` | 8 | encoded payload length | End of Blob table; at most 1 MiB |
| `0x40` | 64 | reserved | All zero |

The Object table precedes the Blob table exactly. Besides their independent
ordering rules, the snapshot MUST reject any Object mapping whose BlobKey is
absent from the Blob table.

### CAS delta header ABI (`0xa0` bytes)

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x00` | 8 | magic | `VIBECAS2` |
| `0x08` | 2 | codec version | 1 |
| `0x0a` | 2 | kind | 2, Delta |
| `0x0c` | 4 | header length | `0xa0` |
| `0x10` | 8 | checkpoint generation | Non-zero |
| `0x18` | 4 | chain count | Non-zero replay depth including this node |
| `0x1c` | 4 | flags | 0 for reuse; 1 for a new Blob mapping |
| `0x20` | 4 | Object mapping length | `0x60` |
| `0x24` | 4 | Blob mapping length | `0xa0` |
| `0x28` | 8 | reserved | All zero |
| `0x30` | `0x60` | previous delta | Null at depth 1; otherwise CatalogDelta pointer |
| `0x90` | 8 | encoded payload length | `0x100` or `0x1a0` |
| `0x98` | 8 | reserved | All zero |
| `0xa0` | `0x60` | new Object mapping | Always present |
| `0x100` | `0xa0` | optional new Blob mapping | Present exactly when flags = 1 |

A reuse delta is exactly `0x100` bytes; a new-Blob delta is exactly `0x1a0`
bytes. A new Blob mapping's key MUST equal the Object mapping's key. During
replay, a reuse delta MUST resolve its key in the base snapshot or an earlier
delta. Following `previous_delta` MUST reduce the chain depth by one and
terminate at null within the checkpoint's replay limit. Duplicate ObjectIds,
conflicting Blob mappings, and mixed generations fail closed.

## BlobWriter state machine

The public transaction shape is conceptually:

```text
begin(kind, exact_len) -> ordered push_chunk(index, bytes) -> commit(target)
```

The implementation MAY expose padding or finalization as internal operations,
but it MUST obey this state machine:

| State | Admitted operation | Required transition |
|---|---|---|
| `Created` | preflight and `begin` | Validate kind/length/budgets, capture target incarnation, acquire one writer claim, then `Receiving` |
| `Receiving` | next content chunk only | Exact next index; 4 KiB except the final partial chunk; after exact content, `Padding` |
| `Padding` | canonical empty/padding leaf steps | Emit at most one leaf step at a time; after all padded leaves, `Finalizing` |
| `Finalizing` | finish descriptor/header and drain staged writes | Require exact length and complete tree, then `Staged` |
| `Staged` | verify candidate and dedup | Full staged verification, then `Checkpointing` with either an existing or new Blob mapping |
| `Checkpointing` | durable CAS transaction | Select and reread the exact new checkpoint, then `Publishing` |
| `Publishing` | synchronous capability installation | Same-incarnation fresh-root publish, then `Complete` or `CommittedUnpublished` |
| `Poisoned` | cold recovery only | No resume after an ambiguous sink or device mutation |

Chunks cannot be skipped, repeated, reordered, shortened, or extended. Empty
content accepts no caller chunk; its zero-length real leaf is produced during
padding. Finalization with missing content or padding MUST fail. If an indexed
tree sink may have accepted only a prefix of one step, the writer becomes
poisoned and cannot continue.

No capability-space lock, segment-store lock, device-session guard, or borrowed
caller buffer may be retained across an await. A long-lived intent may contain
only owned stable state such as an `Arc` target, captured incarnation, opaque
claim token, and fixed-size codec state. Physical cursor state is invalidated
after any ambiguous mutation.

### Memory ceiling

The writer MUST NOT retain the complete content or complete Merkle tree. Its
Blob-length-dependent state is bounded as follows:

- one borrowed logical chunk of at most 4 KiB;
- the 15-slot `StreamingMerkle` frontier (`STREAMING_FRONTIER_BYTES`, which is
  less than one leaf);
- at most 15 indexed hash emissions for one step before the sink is drained;
- at most 66 in-memory manifest entries plus the `0x80` header (`0x2180` bytes
  when encoded);
- a configured fixed I/O/compare window and fixed metadata/replay budget.

The sink and compare path MUST drain incrementally. Peak admitted RAM MUST be a
checked function of these fixed limits and configured catalog/replay ceilings,
not of `exact_len`. Admission MUST fail before durable mutation when that budget
cannot be reserved. Caller-owned input and device-owned queue memory must be
reported separately rather than hidden in the writer measurement.

## Complete-Blob deduplication and collision handling

Deduplication occurs only after the stream has produced and verified the full
canonical Blob and recomputed its BlobKey. The unit is the complete canonical
envelope; leaves and extents are not independently deduplicated in M7.4.

For a candidate BlobKey:

1. Resolve the internal Blob mapping without exposing the result to the caller.
2. Validate the manifest pointer, manifest ABI, canonical 2--66 extent
   partition, every physical pointer, and the Blob header binding.
3. Stream and compare every canonical byte—header, exact content, and complete
   serialized tree—against the staged Blob using bounded buffers.
4. Reuse the existing mapping only if the descriptor and every byte are equal.
5. Regardless of reuse, allocate a fresh ObjectId and persist a new Object
   mapping.

A same-key candidate that is malformed or unreadable is store corruption, not
a dedup miss. A fully valid candidate whose bytes differ is a hash collision.
Both cases fail closed: the old mapping is not overwritten, a second value is
not inserted under the same key, no capability is published, and newly staged
records remain unpublished for later reclamation. The public error and result
MUST NOT disclose whether a same-key candidate existed or whether physical
storage was reused.

## Durable checkpoint and publication order

The target `Arc` and its incarnation are captured before the first await. The
CAS transaction then follows the M7.3 dependency and flush rules:

1. Preflight fixed memory, catalog, payload, metadata, and cleaner-reserve
   capacity; acquire the one volatile metadata-writer claim.
2. Stream canonical Blob bytes and indexed tree writes into new immutable Blob
   extents. No staged record is discoverable through a public namespace.
3. Finalize, flush, reread, and verify every staged Blob extent and its sealed
   segment bindings.
4. Perform the complete-byte dedup check. On a miss, write and verify a new Blob
   manifest; on a verified hit, reuse only the old manifest mapping.
5. Allocate a fresh ObjectId. Write a complete CAS snapshot containing its
   Object mapping and, only on a miss, the new Blob mapping. A future bounded
   replay implementation MAY use the frozen delta form instead. Write allocation
   and any authority metadata for the same target checkpoint generation.
6. Finalize and flush all referenced segments in the M7.3 order. The Blob data
   dependency precedes manifests and catalog/authority metadata.
7. Replace the alternate checkpoint using the frozen clear, flush, exact-zero
   reread, body, seal, and flush sequence.
8. Reread both slots, select the exact new checkpoint, and validate every root,
   replay record, mapping, manifest, pointer, and newly committed object.
9. Only now construct the private backend `ObjectHandle` and its opaque
   `AuthorizedObject` publication token.
10. Synchronously install a fresh capability derivation root using the captured
    incarnation. Never redirect or retry publication into a newer incarnation.

The writer claim is released on ordinary success or error. It is not the
durability mechanism. The selected checkpoint is the only CAS commit boundary,
and capability installation is the only live authority publication boundary.

For a transient CSpace, step 10 is an atomic incarnation comparison plus fresh
root mint. For a persistent CSpace, a simple post-checkpoint mint is
insufficient: the service MUST use its opaque slot reservation, persist the
matching durable grant/authority record in step 5, and install against the same
reservation after step 8. If durable authority commit succeeds but installation
cannot be completed, the persistent target is quarantined until recovery; the
implementation MUST NOT guess whether to cancel or republish the grant.

## Cancellation, faults, and orphan classification

Correctness MUST NOT depend on `Drop`. Dropping or cancelling a normal writer
releases its volatile claim when ordinary unwinding runs, but recovery remains
correct if a fault-domain exit skips destructors.

- Before a new checkpoint is durably selected, the preceding checkpoint and
  object set remain authoritative. Written data, manifests, deltas, and sealed
  segments unreachable from it are unpublished orphans, not objects.
- A verified dedup hit can leave the newly staged physical copy unreachable.
  It is also an orphan, not corruption.
- Once the new checkpoint is selected, its Object mapping is durable even if
  the caller is cancelled, the target incarnation changed, or capability
  installation fails. Such an object is committed but unpublished; no public
  ObjectId or BlobKey lookup may recover authority to it.
- After a submitted mutation has an ambiguous outcome, the writer and cached
  allocation state are poisoned. A cold mount must reread media and select a
  checkpoint before another mutation is admitted.
- Recovery MUST accept a valid selected checkpoint followed by a non-empty
  unpublished tail. It MUST not overwrite, reclaim, or treat that tail as free
  space in M7.4. M7.5 alone may reclaim it after the root and reader-pin proof.
- Discard is never used as commit evidence or as proof that an orphan is safe to
  reuse.

At every write, seal, flush, and checkpoint prefix, cold recovery must yield the
exact preceding checkpoint, the exact new checkpoint, or an explicit fail-closed
recovery error—never a mixture of their indexes or allocation frontiers.

## Directed chunk and proof reads

`get_blob_chunk` first resolves a live object capability to its private Object
mapping and then resolves the corresponding internal Blob manifest. Neither
ObjectId nor BlobKey is accepted from the caller.

For authorized chunk index `i`, the reader computes:

```text
content_offset = 0x80 + i * 4096
chunk_len      = min(4096, exact_len - i * 4096)
tree_offset    = 0x80 + exact_len
```

For each Merkle level, it computes the sibling's indexed-tree position using
the same bottom-up level bases as `blob-format`, then reads the 32-byte range at
`tree_offset + sibling_index * 32`. At most 14 sibling hashes are needed. Chunk
zero of an empty Blob is the canonical zero-length leaf and has an empty proof;
larger indices are out of range.

The reader maps the header, chunk, and sibling ranges through the manifest and
issues reads only for physical pages/extents overlapping those ranges. Adjacent
or repeated ranges SHOULD be coalesced. A range crossing an extent boundary is
split exactly; unrelated Blob extents MUST NOT be read merely to implement the
chunk API.

Before returning, the reader MUST:

- validate the manifest and physical range mapping;
- strictly decode the `0x80` header and bind kind, length, and root to the
  authorized BlobKey;
- reconstruct the proof root from the exact chunk and sibling hashes; and
- return only a verified descriptor, chunk index, chunk bytes, and proof.

Corruption of any required range fails the read. Reading and checking every
content chunk and every serialized tree node remains a separate explicit
whole-Blob verification operation; the directed API MUST NOT silently perform
that full scan.

## Capability and non-probing rules

Public reads require both Store READ authority and a live StoredObject READ
capability. A missing slot, revoked derivation, stale generation, insufficient
object rights, wrong resource type, foreign store, missing private Object
mapping, and unavailable backend Blob MUST collapse to one externally
observable object-unavailable result. Error shape must not reveal whether bytes
with a guessed digest are present. Store-service admission errors may be
reported before object resolution, but must not depend on candidate presence.

There is no public operation to:

- open, resolve, or mint from a BlobKey, Merkle root, digest, or ObjectId;
- enumerate ObjectIds, BlobKeys, manifests, or physical pointers;
- learn whether a put reused existing physical bytes; or
- distinguish an unauthorized present object from an absent object.

Administrative scrub, migration, and GC may traverse internal mappings only
under their own maintenance authority and MUST NOT return a StoredObject
capability as a side effect.

Every successful put creates a new ObjectId, a distinct StoredObject resource,
and a fresh derivation root. Two roots may hold opaque handles that resolve to
the same BlobKey and manifest, but neither root is derived from the other.
Revoking one root kills only its descendants and cannot invalidate the other
root or the shared physical Blob while another root remains live.

## M7.3 compatibility rules

M7.4 does not rewrite or reinterpret the frozen M7.3 payload ABI:

- M7.3 catalog snapshot, delta, entry, and allocation sizes remain `0x40`,
  `0xa0`, `0xb0`, and `0x40`, with `VIBECAT2`/`VIBEALC2` magic and their existing
  strict validation rules.
- M7.4 CAS uses distinct `VIBECAS2` and `VIBEBMF2` payloads. A replay chain and
  selected catalog root MUST use one coherent schema; legacy and CAS deltas are
  never mixed.
- M7.3 `content_root` is SHA-256 of raw object bytes. It is not a domain-separated
  canonical Blob root. M7.3 empty objects use a null Blob pointer plus
  `SHA256(empty)`, whereas an M7.4 empty Blob is a non-null 160-byte canonical
  envelope. Neither representation may be silently cast into the other.
- The M7.2 physical pointer, segment, checkpoint, allocation, reserve,
  generation, cancellation, and cold-recovery rules remain mandatory.
- The compatibility `put/get` surface remains capability/opaque-handle based;
  adding the CAS backend must not introduce digest or ObjectId lookup.

Mount MUST classify a catalog by its exact magic and schema. Until an explicit
converter is implemented and accepted, an M7.3 catalog may be mounted by the
legacy compatibility path, but CAS mutation must return an explicit
upgrade-required result rather than partially modifying it.

An eventual in-place M7.3-to-CAS conversion is a copy-on-write checkpoint
transaction: verify each legacy entry and exact payload with the M7.3 codec,
canonicalize its logical bytes, preserve its private ObjectId and object kind,
build a complete CAS snapshot and any matching authority metadata, select and
reread a new checkpoint, and only then expose the CAS state. Every interruption
must leave either the complete M7.3 checkpoint or the complete CAS checkpoint
selected. No checkpoint may combine a legacy catalog root with CAS replay or
authority metadata. Legacy extents remain quarantined until later GC proves
them unreachable.

## Extended verification matrix

The focused results that satisfy the M7.4 roadmap acceptance are recorded in
`STORAGE_V2_EVIDENCE.md`. Rows below also include broader regression, QEMU,
persistent-authority, and adversarial follow-up gates; a row is not evidence by
itself.

| Area | Required evidence | Pass criterion |
|---|---|---|
| Canonical Blob compatibility | Frozen empty, one-leaf, partial, multi-leaf, and 64 MiB vectors checked by independent code | Header, tree bytes, roots, proofs, and encoded lengths are byte-identical to `blob-format` v1 |
| CAS ABI | Golden vectors for BlobKey, Object/Blob mappings, manifests, snapshots, and both delta forms | Every documented offset and exact length matches; unknown fields, non-zero reserve, prefix, suffix, and arithmetic overflow fail closed |
| Pointer admission | Mutate UUID, segment/generation, kind, exact length, digest, ordinal, and ranges | Every stale, future, foreign, duplicate, or overlapping pointer is rejected before mount |
| Maximum geometry | Empty through 64 MiB, including the maximum tree and partition | Empty uses header + tree (2 extents); 64 MiB uses header + 64 content + tree (66); merged regions, alternate content splits, oversized values, and all other counts fail before commit |
| Streaming equivalence | Differential streaming vs `encode_blob` over all chunk prefixes and boundary sizes | Descriptor, header, indexed tree, BlobKey, and final bytes are identical |
| Writer ordering | Skip, duplicate, reorder, short/long final chunk, incomplete padding, and sink-prefix faults | Invalid sequences touch no later state; ambiguous sink state is permanently poisoned |
| Peak RAM | Instrument empty, boundary, and 64 MiB streams under the declared allocator budget | Peak writer RAM stays within the published fixed formula and does not grow with Blob length |
| Dedup hit | Put identical canonical bytes twice | One durable Blob mapping/manifest remains, two fresh ObjectIds and two object capabilities are returned, and public output does not disclose the hit |
| Collision handling | Deterministic test oracle forces one BlobKey for unequal complete Blobs | Existing mapping is never overwritten, no second value is admitted under the key, no capability is published, and recovery remains valid |
| Independent revocation | Revoke either of two object roots sharing one Blob | The revoked root and descendants fail; the unrelated root still reads and verifies the Blob |
| Namespace non-probing | Probe absent, revoked, wrong-type, wrong-rights, stale, and backend-missing cases | Public object resolution has one unavailable result and no BlobKey/ObjectId lookup or enumeration symbol exists |
| Stale target | Restart/reset the target at every await boundary | Durable commit may remain, but no capability is installed into the new incarnation |
| Persistent publication | Fault reservation, durable grant, reread, install, and quarantine boundaries | A graph is atomically installed after commit, or the exact persistent CSpace is quarantined until recovery |
| Cancellation and crash | Stop before/after every Blob, manifest, delta, allocation, segment, flush, and checkpoint mutation | Cold mount selects the exact old or new checkpoint; unpublished tails are accepted but never reused |
| Bounded replay/recovery | Dense snapshots and replay chains at and one beyond configured ceilings | At the ceiling recovery meets its measured budget; beyond it fails closed without scanning Blob content for discovery |
| Directed reads | Instrument page/extent reads for first, middle, final, empty, and boundary-crossing chunks | Only header/chunk/proof-overlapping ranges and required metadata are read; returned proofs verify independently |
| Directed corruption | Flip every requested chunk/header/proof hash position | No corrupted chunk is returned; unrelated extents are not fetched as an implicit whole-Blob scan |
| Whole verification | Mutate every content and serialized-tree position | Explicit whole verification detects every mutation and checks the exact canonical length |
| M7.3 compatibility | Existing M7.3 images plus prefix cuts of a conversion checkpoint | Legacy read behavior remains capability-only; recovery selects complete legacy or complete CAS state, never a mixed schema |
| Independent powered-off verifier | Parse a raw image starting only from the selected checkpoint | Reconstruct all Object and Blob mappings, manifests, extents, roots, dedup sharing, and orphan classification without guest state |
| Build profile | Focused host tests, strict clippy/rustdoc, `no_std` firmware build, and QEMU/raw-image gate | No default-`std` dependency enters firmware and all recorded M7.4 gates complete successfully |
