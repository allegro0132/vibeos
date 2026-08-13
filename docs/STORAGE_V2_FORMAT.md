# Storage V2 canonical media format

This document freezes the Storage V2 version 1 media ABI and its crash
protocol. It is normative for the kernel writer, the pure `segment-format`
codec, and independent powered-off image verifiers. A decoder must not infer a
Rust layout, accept an unknown extension, or use a checksum as a publication
bit.

All offsets are hexadecimal byte offsets from the beginning of one 4096-byte
format page. All integer fields are unsigned little-endian values. Ranges are
half-open. UUIDs and SHA-256 values are byte arrays in the order shown; they are
not integer fields. Every reserved field and every padding byte in a structural
body or seal must be zero.

Version 1 assigns these values:

| Name | Value |
|---|---:|
| Format page size | 4096 bytes |
| Format version | 1 |
| SHA-256 algorithm identifier | 1 |
| Anchor size | 16 pages |
| Segment size | 1024 pages (4 MiB) |
| First append page in a segment | 2 |
| End of append area | 1020, exclusive |
| Summary body / seal | 1020 / 1021 |
| Segment-seal body / final seal | 1022 / 1023 |
| Maximum extent payload | 256 pages |
| Anchor segment number sentinel | `UINT64_MAX` |

CRC fields use CRC32C (Castagnoli): reflected polynomial `0x82f63b78`, initial
state `UINT32_MAX`, and final XOR `UINT32_MAX`.

## Store geometry

A format page is a Storage V2 addressing unit, not a device atomic-write
claim. The scoped block device's logical block size must be exactly 512, 1024,
2048, or 4096 bytes, and I/O maps a format page to the corresponding integral
number of logical blocks.
Version 1 remains correct when a device can tear a format-page write at an
arbitrary byte prefix.

The first 16 format pages form the anchor. Segment `n` begins at the checked
page address:

```text
segment_base_page(n) = 16 + n * 1024
admitted_range_pages = 16 + admitted_segments * 1024
```

Overflow in either expression is a format error. The anchor layout is fixed:

| Page | Contents |
|---:|---|
| 0 | Superblock A body |
| 1 | Superblock A seal |
| 2 | Superblock B body |
| 3 | Superblock B seal |
| 4 | Checkpoint A body |
| 5 | Checkpoint A seal |
| 6 | Checkpoint B body |
| 7 | Checkpoint B seal |
| 8..15 | Reserved; each page must be all zero |

Each segment has this fixed relative layout:

| Relative page | Contents |
|---:|---|
| 0 | Segment-header body |
| 1 | Segment-header seal |
| `[2, 1020)` | Contiguous extent descriptor pairs and payload pages |
| 1020 | Segment-summary body |
| 1021 | Segment-summary seal |
| 1022 | Segment-seal body |
| 1023 | Final segment seal and segment publication record |

An extent occupies its descriptor body, descriptor seal, then one to 256
payload pages. Descriptor ordinals start at 1 and are contiguous. There are no
holes between extents: the next descriptor starts at the previous extent's
payload end. The summary has ordinal `record_count + 1`, and the segment seal
has ordinal `record_count + 2`.

## Common structural body

Every superblock, checkpoint, segment header, extent descriptor, summary, and
segment-seal body uses the following 4096-byte envelope. `payload_len` is the
exact fixed length specified for its record kind below.

| Offset | Size | Field | Required value or meaning |
|---:|---:|---|---|
| `0x000` | 8 | body magic | ASCII `VIBESG2\0` |
| `0x008` | 2 | version | 1 |
| `0x00a` | 2 | header length | `0x80` |
| `0x00c` | 2 | record kind | Enumerated below |
| `0x00e` | 2 | flags | 0 |
| `0x010` | 4 | payload length | Exact length for the kind |
| `0x014` | 4 | reserved | 0 |
| `0x018` | 16 | store UUID | Non-zero store identity |
| `0x028` | 8 | generation | Non-zero checkpoint or segment generation |
| `0x030` | 8 | segment number | Segment identity, or anchor sentinel |
| `0x038` | 4 | ordinal | Record ordinal in its containing area |
| `0x03c` | 4 | reserved | 0 |
| `0x040` | 8 | self page | Exact store-relative body page |
| `0x048` | 8 | target checkpoint generation | Generation for which the record was built |
| `0x050` | `0x30` | reserved | All zero |
| `0x080` | `payload_len` | kind payload | Canonical payload below |
| `0x080 + payload_len` | through `0xfcf` | padding | All zero |
| `0xfd0` | 4 | body CRC32C | CRC32C of bytes `[0x000, 0xfd0)` |
| `0xfd4` | 4 | CRC complement | Bitwise complement of body CRC32C |
| `0xfd8` | 8 | self-page copy | Must equal `0x040` |
| `0xfe0` | 8 | generation copy | Must equal `0x028` |
| `0xfe8` | 8 | segment-number copy | Must equal `0x030` |
| `0xff0` | 4 | ordinal copy | Must equal `0x038` |
| `0xff4` | 2 | kind copy | Must equal `0x00c` |
| `0xff6` | 2 | version copy | 1 |
| `0xff8` | 4 | payload-length copy | Must equal `0x010` |
| `0xffc` | 2 | header-length copy | `0x80` |
| `0xffe` | 2 | flags copy | 0 |

The record-kind namespace is closed in version 1:

| Value | Record kind |
|---:|---|
| 1 | Superblock |
| 2 | Checkpoint |
| 3 | Segment header |
| 4 | Extent descriptor |
| 5 | Segment summary |
| 6 | Segment seal |

The SHA-256 of a body always means SHA-256 over all 4096 bytes of the completed
canonical body page, including its CRC and duplicated trailer.

## Common seal and publication rule

A structural body is published only by its separate seal page:

| Offset | Size | Field | Required value or meaning |
|---:|---:|---|---|
| `0x000` | 8 | seal magic | ASCII `VIBESL2\0` |
| `0x008` | 2 | version | 1 |
| `0x00a` | 2 | sealed record kind | Must match the body |
| `0x00c` | 2 | header length | `0x80` |
| `0x00e` | 2 | flags | 0 |
| `0x010` | 16 | store UUID | Must match the body |
| `0x020` | 8 | generation | Must match the body |
| `0x028` | 8 | segment number | Must match the body |
| `0x030` | 4 | ordinal | Must match the body |
| `0x034` | 4 | reserved | 0 |
| `0x038` | 8 | body page | Must equal the body's self page |
| `0x040` | 8 | target checkpoint generation | Must match the body |
| `0x048` | 4 | body CRC32C | Must equal the body trailer |
| `0x04c` | 4 | body CRC complement | Must equal the body trailer |
| `0x050` | 32 | body SHA-256 | SHA-256 of the entire body page |
| `0x070` | 4 | body payload length | Must match the body |
| `0x074` | `0xf5c` | reserved | All zero through `0xfcf` |
| `0xfd0` | 4 | seal CRC32C | CRC32C of bytes `[0x000, 0xfd0)` |
| `0xfd4` | 4 | CRC complement | Bitwise complement of seal CRC32C |
| `0xfd8` | 8 | body-page copy | Must equal `0x038` |
| `0xfe0` | 8 | generation copy | Must equal `0x020` |
| `0xfe8` | 8 | segment-number copy | Must equal `0x028` |
| `0xff0` | 16 | terminal marker | ASCII `VIBESG2-SEALED!!` |

Classification is deliberately asymmetric:

- A body/seal pair is `Empty` only when both complete pages are all zero.
- A pair whose seal does not contain the exact 16-byte terminal marker is
  `Unsealed`, regardless of non-zero unpublished body bytes.
- Once the exact terminal marker is present, every magic, version, kind,
  length, flag, reserved byte, binding, copy, CRC, complement, and SHA-256
  check is mandatory. Any mismatch is a fatal malformed-record error. It must
  never be downgraded to `Unsealed` or silently ignored.

The non-zero marker occupies the final 16 bytes. When the old seal is known to
be all zero, every strict prefix shorter than 4096 bytes of a new seal write
lacks the exact marker. CRC32C detects accidental corruption; the marker and
body digest establish publication. Neither supplies rollback resistance or an
atomic-write claim.

## Superblock payload

The Superblock payload length is `0x80`.

| Offset | Size | Field | Version 1 constraint |
|---:|---:|---|---|
| `0x080` | 1 | copy | 0 for A, 1 for B |
| `0x081` | 7 | reserved | 0 |
| `0x088` | 4 | format page size | 4096 |
| `0x08c` | 4 | anchor pages | 16 |
| `0x090` | 4 | segment pages | 1024 |
| `0x094` | 4 | append first page | 2 |
| `0x098` | 4 | append end page | 1020 |
| `0x09c` | 4 | summary body page | 1020 |
| `0x0a0` | 4 | summary seal page | 1021 |
| `0x0a4` | 4 | segment-seal body page | 1022 |
| `0x0a8` | 4 | final segment-seal page | 1023 |
| `0x0ac` | 4 | maximum extent payload pages | 256 |
| `0x0b0` | 4 | cleaner reserve segments | Non-zero and less than initial segments |
| `0x0b4` | 2 | hash algorithm | 1, SHA-256 |
| `0x0b6` | 2 | reserved | 0 |
| `0x0b8` | 8 | initial admitted range pages | Exact geometry equation |
| `0x0c0` | 8 | first segment page | 16 |
| `0x0c8` | 8 | initial admitted segments | Initial complete segment count |
| `0x0d0` | 16 | device ID | Non-zero exact managed-device identity |
| `0x0e0` | 8 | first logical block | Beginning of the scoped device range |
| `0x0e8` | 8 | initial logical-block count | Exact initial range length |
| `0x0f0` | 4 | logical-block size | 512, 1024, 2048, or 4096 |
| `0x0f4` | 4 | feature flags | 0 |
| `0x0f8` | 4 | maximum replay records | Non-zero explicit recovery budget |
| `0x0fc` | 4 | reserved | 0 |

Superblock A is bound to body page 0, ordinal/copy 0; B is bound to body page
2, ordinal/copy 1. Both use generation 1, the anchor segment-number sentinel,
and target checkpoint generation 0. Their semantic fields must be identical.
The device range must contain exactly
`initial_range_pages * 4096` bytes, and `initial_range_pages` must equal
`16 + initial_segments * 1024`, using checked arithmetic.

At mount, an absent or unsealed superblock copy may be ignored. A copy with a
complete marker but malformed data fails closed. If both copies are sealed,
they must agree after accounting only for their prescribed copy, ordinal, and
self-page differences. At least one canonical sealed copy is required.

## Physical pointer

A physical pointer is exactly `0x60` bytes. An all-zero pointer is the unique
null encoding. Every non-null encoding has this layout:

| Relative offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x00` | 16 | store UUID | Non-zero and equal to the selected store |
| `0x10` | 8 | segment number | Less than admitted segment count |
| `0x18` | 8 | segment generation | Non-zero and equal to the sealed segment |
| `0x20` | 4 | descriptor relative page | In the append area |
| `0x24` | 4 | payload relative page | Descriptor page plus 2 |
| `0x28` | 4 | payload pages | `ceil(exact_byte_len / 4096)`, in `1..=256` |
| `0x2c` | 4 | descriptor ordinal | Non-zero and equal to the extent |
| `0x30` | 8 | exact byte length | Non-zero exact payload length |
| `0x38` | 2 | extent kind | Closed enumeration below |
| `0x3a` | 2 | hash algorithm | 1, SHA-256 |
| `0x3c` | 4 | reserved | 0 |
| `0x40` | 32 | payload SHA-256 | Hash of exactly `exact_byte_len` bytes |

The extent-kind namespace is closed:

| Value | Extent kind |
|---:|---|
| 1 | Blob |
| 2 | Catalog |
| 3 | Authority |
| 4 | Allocation |
| 5 | Catalog delta |

The checked interval from the descriptor page through the payload end must lie
within `[2, 1020)`. A pointer is accepted only after its UUID, segment number,
segment generation, ordinal, kind, descriptor location, payload location,
exact length, page count, and payload digest agree with the sealed segment and
extent descriptor. Pointers in one checkpoint must not duplicate or overlap
one another. Binding the segment generation makes a pointer into a recycled
segment stale instead of retargeting it to unrelated bytes.

The unused tail of the final payload page is not a format field and need not be
zero. It is excluded from the payload hash and must never be exposed through an
exact-length pointer.

## Checkpoint payload

The Checkpoint payload length is `0x1c0`.

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x080` | 1 | slot | 0 for A, 1 for B |
| `0x081` | 7 | reserved | 0 |
| `0x088` | 8 | previous generation | Exact predecessor, or 0 for generation 1 |
| `0x090` | 8 | admitted range pages | `16 + admitted_segments * 1024` |
| `0x098` | 8 | admitted segments | Complete segments in the admitted range |
| `0x0a0` | 8 | next segment generation | Next non-zero generation to allocate |
| `0x0a8` | 4 | replay count | Bounded delta records after catalog root |
| `0x0ac` | 4 | maximum replay records | Must match the admitted budget |
| `0x0b0` | 4 | cleaner reserve segments | Must preserve configured headroom |
| `0x0b4` | 4 | flags | 0 |
| `0x0b8` | 8 | reserved | 0 |
| `0x0c0` | `0x60` | catalog root | Null or Catalog pointer |
| `0x120` | `0x60` | authority root | Null or Authority pointer |
| `0x180` | `0x60` | allocation root | Null or Allocation pointer |
| `0x1e0` | `0x60` | replay tail | Null or Catalog-delta pointer |

Checkpoint generation `g` belongs only in slot `(g - 1) & 1`. Its common
binding uses the anchor segment-number sentinel, ordinal equal to the slot,
self page `4 + 2 * slot`, and target checkpoint generation `g`.
`replay_count` must not exceed `max_replay_records`; it is zero exactly when the
replay-tail pointer is null. Cleaner reserve is non-zero and less than the
admitted segment count. Claimed range growth must fit the exact device range
capability; a checkpoint cannot amplify allocation by increasing a count
without the corresponding admitted pages and previously committed growth
record.

Every non-null root must resolve to a fully verified extent in a fully finalized
segment. Its segment generation must precede `next_segment_generation`. A
checkpoint must never cite an incomplete segment, an unsealed descriptor, a
payload digest mismatch, or a record built for an incompatible checkpoint
generation.

## Segment-header payload

The Segment-header payload length is `0x58`.

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x080` | 8 | segment base page | `16 + segment_no * 1024` |
| `0x088` | 4 | append first page | 2 |
| `0x08c` | 4 | append end page | 1020 |
| `0x090` | 4 | summary body page | 1020 |
| `0x094` | 4 | summary seal page | 1021 |
| `0x098` | 4 | segment-seal body page | 1022 |
| `0x09c` | 4 | final segment-seal page | 1023 |
| `0x0a0` | 4 | maximum extent payload pages | 256 |
| `0x0a4` | 2 | segment class | 1 |
| `0x0a6` | 2 | flags | 0 |
| `0x0a8` | 8 | previous segment number | Predecessor or `UINT64_MAX` |
| `0x0b0` | 8 | previous segment generation | Predecessor generation or 0 |
| `0x0b8` | 32 | previous segment-seal-body SHA-256 | Predecessor link or all zero |

The header's common generation is the segment generation, its ordinal is 0,
and its self page is the computed segment base. The first segment-chain member
uses previous number `UINT64_MAX`, previous generation 0, and an all-zero hash.
Otherwise all three predecessor fields must identify the exact previously
finalized segment and the SHA-256 of its full segment-seal body page.

## Extent-descriptor payload

The Extent-descriptor payload length is `0x80`.

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x080` | 2 | extent kind | 1 through 5 |
| `0x082` | 2 | hash algorithm | 1, SHA-256 |
| `0x084` | 4 | flags | 0 |
| `0x088` | 4 | object kind | Non-zero canonical object-kind identifier |
| `0x08c` | 4 | extent index | Zero-based index in the encoded object |
| `0x090` | 4 | extent count | Non-zero exact extent count |
| `0x094` | 4 | payload pages | 1 through 256, exact rounded-up count |
| `0x098` | 8 | content byte length | Non-zero exact logical object content length |
| `0x0a0` | 8 | encoded Blob length | Non-zero exact complete encoded length |
| `0x0a8` | 8 | encoded offset | Offset represented by this extent |
| `0x0b0` | 8 | payload byte length | Exact bytes in this extent |
| `0x0b8` | 4 | payload first relative page | Descriptor relative page plus 2 |
| `0x0bc` | 4 | record span pages | `2 + payload_pages` |
| `0x0c0` | 32 | Merkle root | Exact logical Blob root |
| `0x0e0` | 32 | payload SHA-256 | Hash of exactly `payload_byte_len` bytes |

The common binding supplies the segment identity, non-zero contiguous ordinal,
descriptor self page, and target checkpoint generation. All additions,
rounding, and range ends are checked. `extent_index` must be less than
`extent_count`; `encoded_offset + payload_byte_len` must not overflow or exceed
`encoded_blob_len`. The descriptor pair and payload must end at or before page
1020.

## Segment-summary payload

The Segment-summary payload length is `0xc8`. Count and byte arrays use extent
kind order: Blob, Catalog, Authority, Allocation, Catalog delta.

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x080` | 4 | record count | Number of extent descriptors |
| `0x084` | 4 | next free page | Exact streaming cursor after final extent |
| `0x088` | 4 | payload page count | Checked sum of extent payload pages |
| `0x08c` | 4 | reserved | 0 |
| `0x090` | 8 | total payload bytes | Checked sum of exact payload byte lengths |
| `0x098` | 8 | first target checkpoint generation | First descriptor target |
| `0x0a0` | 8 | last target checkpoint generation | Last descriptor target |
| `0x0a8` | 32 | header-body SHA-256 | Hash of the complete header body page |
| `0x0c8` | 32 | descriptor-chain SHA-256 | Final descriptor chain |
| `0x0e8` | 32 | data-chain SHA-256 | Final data chain |
| `0x108` | 20 | five kind counts | Checked per-kind counts |
| `0x11c` | 4 | reserved | 0 |
| `0x120` | 40 | five kind byte totals | Checked per-kind exact byte sums |

The verifier derives every field while streaming extents in ordinal and page
order. A finalized segment contains at least one extent. Extent target
checkpoint generations are non-zero and non-decreasing; the summary records
their exact first and last values. Kind counts must sum to `record_count`; kind
bytes must sum to `total_payload_bytes`. `next_free_page` must be in
`[2, 1020]`. The summary's common self page is segment-relative page 1020, its
ordinal is `record_count + 1`, and its common target checkpoint generation is
the last extent's target.

## Segment-seal payload

The Segment-seal payload length is `0xa0`.

| Offset | Size | Field | Constraint |
|---:|---:|---|---|
| `0x080` | 32 | header-body SHA-256 | Must match header and summary |
| `0x0a0` | 32 | summary-body SHA-256 | Hash of complete summary body page |
| `0x0c0` | 32 | final descriptor-chain SHA-256 | Must match summary and replay |
| `0x0e0` | 32 | final data-chain SHA-256 | Must match summary and payload replay |
| `0x100` | 4 | record count | Must match summary |
| `0x104` | 4 | next free page | Must match summary |
| `0x108` | 4 | payload page count | Must match summary |
| `0x10c` | 4 | reserved | 0 |
| `0x110` | 8 | total payload bytes | Must match summary |
| `0x118` | 8 | target checkpoint generation | Final segment publication target |

The segment-seal body's common self page is segment-relative page 1022, its
ordinal is `record_count + 2`, and its common target equals its payload target
and the summary's last target. Its separate generic seal is page 1023 and is the
publication record for the segment as a whole. A header, extent, or summary
seal never makes an otherwise incomplete segment admissible.

## Segment hash chains

The chain domain byte strings are exactly `VIBESG2-DESC-v1` and
`VIBESG2-DATA-v1`, without a terminating NUL. Concatenation below has no length
prefix or alignment padding. `LE64` and `LE32` denote fixed-width little-endian
encodings.

For store UUID `U`, segment number `N`, and segment generation `G`:

```text
desc_0 = SHA256("VIBESG2-DESC-v1" || U || LE64(N) || LE64(G))
data_0 = SHA256("VIBESG2-DATA-v1" || U || LE64(N) || LE64(G))
```

For each extent in ordinal order, where `D` is the SHA-256 of the complete
descriptor body, `P` is the SHA-256 of exactly the payload bytes, `O` is the
ordinal, and `L` is the exact payload byte length:

```text
desc_next = SHA256("VIBESG2-DESC-v1" || U || LE64(N) || LE64(G)
                   || desc_prev || LE32(O) || D || P)

data_next = SHA256("VIBESG2-DATA-v1" || U || LE64(N) || LE64(G)
                   || data_prev || LE32(O) || LE64(L) || P)
```

The summary stores the final values, and the segment seal repeats them. A
streaming verifier recomputes both. The descriptor chain binds canonical
metadata and payload identity; the data chain independently binds exact length
and payload identity. Neither permits skipping, reordering, duplicating, or
splicing an extent across store, segment, or segment generation.

## Write and flush protocol

No structural body is published by its body write. The minimum publication
sequence for a fresh, known-zero body/seal pair is:

1. Write the complete canonical body page.
2. Flush the body dependency.
3. Write the complete canonical seal page.
4. Flush the seal.
5. Reread both pages and decode them canonically.

An extent adds a payload dependency before that sequence: write its payload,
flush, then write and flush the descriptor body, then write and flush the
descriptor seal. Only the exact `payload_byte_len` bytes are hashed. The final
physical page's unused tail is neither read through the pointer nor interpreted
as format data.

A complete segment is written conservatively in this order:

1. Establish that the final-seal page 1023 is durably all zero, using the reuse
   protocol below when necessary.
2. Write and flush the segment-header body, then write and flush its seal.
3. For each extent, write and flush payload, descriptor body, and descriptor
   seal in dependency order, updating the two rolling hashes.
4. Write and flush the summary body, then write and flush its seal.
5. Write and flush the segment-seal body.
6. Write and flush the final seal at page 1023.
7. Reread and stream-verify the entire structural segment, exact payload
   digests, rolling chains, summary, and final seal.

A checkpoint may reference only segments that completed step 7. The ordering
across a transaction is therefore: finalize and flush new Blob data; finalize
and flush catalog, authority, and allocation metadata that cites it; publish a
new checkpoint; reread and verify the selected result; only then publish the
corresponding live capability.

FUA may replace a flush only when the admitted device contract proves the same
ordering and durability for the exact dependency. Discard is never part of
publication.

## Checkpoint replacement and selection

Checkpoint slots alternate. Before replacing a previously used target slot,
the writer must perform this exact protocol:

1. Overwrite the target slot's entire old seal page with zero.
2. Flush.
3. Reread the seal and require all 4096 bytes to be exactly zero.
4. Write the new checkpoint body.
5. Flush.
6. Write the new checkpoint seal.
7. Flush.
8. Reread both slots and run canonical selection.

The writer must not modify the target body before step 3. A torn zeroing write
can retain the old terminal marker while corrupting fields authenticated by it;
that state fails closed and normal mount must not silently select around it.
After the exact-zero gate, a torn body remains unpublished, and every strict
prefix of the new seal lacks the terminal marker. Thus each crash boundary
yields the preceding checkpoint, the exact new checkpoint, or an explicit
fail-closed recovery condition—never a mixed checkpoint.

Selection first classifies and fully validates each slot. It then applies these
rules:

- generation 1 has `previous_generation == 0`; every later generation has
  `previous_generation == generation - 1`, with checked arithmetic;
- the physical slot must equal `(generation - 1) & 1`;
- two sealed candidates claiming one generation must be byte-equivalent after
  their fixed slot binding, otherwise recovery reports a conflict;
- two different sealed generations must be strictly consecutive and the newer
  must name the older as its predecessor; gaps and forks fail closed; and
- only after all binding, allocation, pointer, replay-budget, and segment
  validations pass is the newer canonical candidate selected.

The pure format selector performs the first structural phase with an opaque
verified superblock and the maximum pages authorized by the scoped block
range. It rejects configuration drift, unauthorized growth, generation
rollback, and admission shrink. The I/O-owning `segment-store` recovery phase
must then resolve every non-null root through a fully finalized segment,
verified descriptor, and exact payload digest before treating the structurally
selected checkpoint as mounted. Structural selection alone is not a mounted
store and never authorizes publication.

An empty or unsealed target slot leaves the other canonical slot as the
previous checkpoint. A complete marker with malformed contents is an error,
not permission to fall back. The previous checkpoint and all segments it needs
remain intact until the new checkpoint has been durably selected and verified.

## Segment reuse

A segment is not reusable merely because a prospective checkpoint omits it.
The checkpoint making it logically free must first be durably selected, and any
required reader generation must quiesce. Before writing a new generation into
the physical segment, the writer must:

1. Overwrite the entire old final-seal page at relative page 1023 with zero.
2. Flush.
3. Reread and require the page to be exactly zero.
4. Only then write the new segment-header body and seal.

The new non-zero segment generation comes from the selected checkpoint's
`next_segment_generation`, is advanced with checked arithmetic, and is included
in every body, seal, pointer, and hash-chain seed. Until a new final seal is
durable, all residual or newly written internal records belong to an incomplete
segment and cannot satisfy a checkpoint pointer.

## Ambiguous mutation recovery

The device contract distinguishes a rejected-before-submission mutation from
one that may have reached media. After any ambiguous write, FUA, flush,
cancellation, timeout, revocation, or driver restart, the writer must stop. It
must discard cached append cursors, rolling-chain state, checkpoint selection,
and device session; it must not retry the mutation as though it were exactly
once.

Recovery reacquires the current device session, rereads canonical media, and
repeats classification, segment verification, and checkpoint selection. An
ambiguous clear permits progress only after reread proves the target seal is
exactly zero. An ambiguous publication is accepted only when reread proves the
exact intended body, seal, dependencies, and generation. Otherwise the
preceding selected checkpoint remains authoritative, or recovery fails closed
if a complete publication marker authenticates malformed state.

No segment reachable from the preceding checkpoint may be reclaimed based on
an ambiguous checkpoint result.

## Fail-closed, constant-memory decoding

The canonical format decoder is pure `no_std`: it performs no I/O and no
allocation. It accepts borrowed fixed-size pages and returns bounded scalar
records. A conforming decoder must:

- check every addition, multiplication, rounding operation, conversion, page
  end, byte end, generation increment, and count accumulation before use;
- reject unknown version, record kind, extent kind, hash algorithm, flag bit,
  non-zero reserved data, invalid copy, stale generation, wrong slot, wrong
  self address, invalid pointer kind, or binding mismatch;
- distinguish only `Empty`, `Unsealed`, and fully canonical `Sealed`; a sealed
  malformed object is always an error;
- reject range or allocation amplification, payload and record overlap,
  duplicate or skipped ordinal, cursor hole, pointer outside the admitted
  range, and any pointer into anchor or reserved segment pages;
- hash only the exact payload byte length while ensuring its rounded physical
  page span is bounded by 256 and `[2, 1020)`; and
- verify segment records in one forward pass with a fixed cursor, counters,
  five kind-count lanes, five kind-byte lanes, and two 32-byte rolling hashes.

Media-size-dependent indexes are not hidden inside format decoding. A later
catalog checkpoint may allocate only within its declared memory budget;
`replay_count` is bounded by `max_replay_records`, and exceeding that budget is
an admission or recovery error. The independent powered-off verifier applies
the same byte ABI and rejection rules without trusting kernel state.
