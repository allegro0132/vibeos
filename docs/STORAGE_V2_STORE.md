# Storage V2 append-only store

This document records the M7.3 implementation contract between
`segment-store`, `segment-format`, `storage-device`, and the independent
powered-off image verifier.  It refines the frozen structural ABI in
`STORAGE_V2_FORMAT.md`; it does not change any M7.2 structural field or turn a
media identifier into authority.

## Scope

M7.3 provides a single-writer, append-only object store.  A committed object is
an immutable Blob extent named internally by a monotonically allocated
`ObjectId`.  Callers receive an opaque object handle; the store has no public
digest lookup, object enumeration, or physical-pointer constructor.

The implementation deliberately has no recycling path.  Segments made
unreachable by an interrupted transaction are quarantined until M7.5 proves
the cleaner protocol.  Format time reserves complete segments for one future
maximum evacuation transaction, and ordinary writes cannot consume that
reserve.

## Device boundary

The store addresses only format pages relative to one admitted `BlockRange`.
The page adapter validates every request against the current device session and
splits one 4096-byte format page into the exact number of logical blocks
reported by `storage-device`.  It never rounds a request outside the range.

Mutation outcomes preserve the M7.1 distinction between a request known not to
have been submitted and a request that may have reached media.  Once any write
or flush is submitted, cancellation, driver restart, timeout, or an ambiguous
result invalidates the mounted writer and every cached allocation cursor.  A
new operation is admitted only after a cold mount rereads the media.  No store
lock, range capability, or cached device session is retained across an await.

## Commit order

Each object transaction targets exactly the next checkpoint generation and
uses this dependency order:

1. Durably clear and reread the new segment's final-seal page.
2. Write and flush the segment-header body, then its seal.
3. For every extent, write and flush the exact payload, descriptor body, and
   descriptor seal in that dependency order. Blob precedes catalog, which
   precedes allocation metadata.
4. Write and flush the summary body and seal, segment-seal body, and final
   segment publication seal, with a flush after every structural write.
5. Reread and verify every exact payload and the complete finalized segment.
6. Clear only the old checkpoint seal, flush, and require an exact-zero reread.
7. Write the checkpoint body, flush, write its seal, flush, then reread both
   slots and verify the selected checkpoint and every root it names.
8. Only after step 7 may the opaque object handle be returned for publication
   by the authority layer.

At every prefix of this sequence, cold recovery selects either the preceding
checkpoint or the complete new checkpoint.  It never combines roots from two
generations.  A nonempty unpublished tail is not corruption and is never
overwritten by M7.3.

## Catalog and allocation recovery

Normal mount starts at the dual superblock and dual checkpoint copies.  It
resolves the selected checkpoint's catalog and allocation roots through sealed
segments, validates exact kind/generation/hash bindings, and applies at most the
superblock's `max_replay_records` catalog deltas.  Blob payload is not read to
discover objects.  A `get` resolves one already-authorized opaque handle and
then verifies only the extent and exact payload that handle names.

Catalog entries bind the private ObjectId, object kind, exact logical length,
commit generation, logical content root, and physical Blob pointer.  Allocation
metadata records the committed append frontier and next segment generation.
Both payload codecs use fixed-width little-endian fields, closed versions,
checked lengths, and mandatory zero reserved bytes. Their exact byte tables
below are duplicated in the independent Python verifier.

### Catalog snapshot

The snapshot header is `0x40` bytes and is followed by `entry_count` catalog
entries. Its exact payload length is `0x40 + entry_count * 0xb0`.

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x00` | 8 | magic | ASCII `VIBECAT2` |
| `0x08` | 2 | version | 1 |
| `0x0a` | 2 | kind | 1, Snapshot |
| `0x0c` | 4 | header length | `0x40` |
| `0x10` | 8 | checkpoint generation | Non-zero |
| `0x18` | 4 | entry count | Non-zero |
| `0x1c` | 4 | entry size | `0xb0` |
| `0x20` | 8 | chain count | Equal to entry count |
| `0x28` | 24 | reserved | All zero |

Snapshot ObjectIds are strictly increasing and unique.

### Catalog delta

A delta has one `0xb0` entry after its `0xa0`-byte header, so its exact length
is `0x150`.

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x00` | 8 | magic | ASCII `VIBECAT2` |
| `0x08` | 2 | version | 1 |
| `0x0a` | 2 | kind | 2, Delta |
| `0x0c` | 4 | header length | `0xa0` |
| `0x10` | 8 | checkpoint generation | Non-zero |
| `0x18` | 4 | entry count | 1 |
| `0x1c` | 4 | entry size | `0xb0` |
| `0x20` | 8 | chain count | Remaining replay depth, including this node |
| `0x28` | `0x60` | previous delta | Null at depth 1; otherwise CatalogDelta pointer |
| `0x88` | 24 | reserved | All zero |

Following `previous delta` must reduce the chain count by exactly one at each
node and terminate at null within checkpoint `replay_count`.

### Catalog entry

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x00` | 16 | ObjectId | Non-zero `u128` little-endian |
| `0x10` | 4 | object kind | Non-zero |
| `0x14` | 4 | flags | 0 |
| `0x18` | 8 | exact payload length | Exact raw object bytes |
| `0x20` | 8 | commit generation | Non-zero, not newer than catalog |
| `0x28` | 32 | content root | SHA-256 of exact raw object bytes |
| `0x48` | `0x60` | Blob pointer | Blob kind, exact length and digest binding |
| `0xa8` | 8 | reserved | All zero |

An empty object has the unique representation Null Blob pointer plus
`SHA256(empty)`. A non-empty object must have a non-null Blob pointer.

### Allocation payload

The Allocation payload is exactly `0x40` bytes.

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x00` | 8 | magic | ASCII `VIBEALC2` |
| `0x08` | 2 | version | 1 |
| `0x0a` | 2 | header length | `0x40` |
| `0x0c` | 4 | flags | 0 |
| `0x10` | 8 | checkpoint generation | Equal to owning checkpoint |
| `0x18` | 8 | admitted segments | Equal to owning checkpoint |
| `0x20` | 8 | allocated prefix segments | Unavailable physical prefix |
| `0x28` | 8 | next segment generation | Equal to owning checkpoint |
| `0x30` | 4 | cleaner reserve segments | Equal to superblock/checkpoint |
| `0x34` | 12 | reserved | All zero |

The allocated prefix plus cleaner reserve cannot exceed admitted segments.

Recovery allocation is explicit.  `StoreLimits` bounds catalog entries,
replayed deltas, compatibility-object size, and peak recovery bytes.  Mount
accounts for catalog and replay storage before allocating it and fails closed
if the configured ceiling is insufficient.  The reported recovery peak is a
measured value, not an estimate derived from total media size.

## Capacity reporting

Admission errors are classified by the resource that prevented a transaction:

- **payload capacity**: the object cannot fit the M7.3 one-extent compatibility
  profile;
- **metadata capacity**: catalog or bounded replay metadata cannot be admitted;
- **cleaner reserve**: enough physical segments exist, but using one would
  violate the format-time evacuation reserve.

The compatibility adapter maps the old `put/get` shape onto opaque handles but
does not collapse these classes back into `JournalFull`.

## Acceptance evidence

The host fault device maintains separate volatile and durable media.  Tests can
stop, fail before submission, or return an ambiguous result before or after
durability at every write and flush boundary.  Every resulting cold mount must
recover the exact old or new checkpoint and exact object set.  Dense recovery
is tested at the configured catalog/replay ceiling, and one byte less than the
measured requirement must fail closed.

The independent Python verifier runs on a powered-off raw image.  Starting only
from the selected checkpoint, it reconstructs every committed catalog entry,
verifies each referenced finalized segment and exact Blob payload, rejects
references outside the admitted range, and rejects unreferenced data as an
object discovery mechanism.
