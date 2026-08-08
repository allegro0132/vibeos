# Durable capability log v1

This document is the normative M4.0 format and crash model for persistent
authority. M4.0 defines a pure `no_std` codec and recovery verifier; it does not
yet claim that a real block driver or a live `CSpace` is persistent. Those are
M4.1--M4.3.

The safety goal is narrower and stronger than “the file usually parses”:

> After a crash, recovered authority is a subset of an allowed transaction
> history. A crash must never invent a grant, widen rights, change the object
> behind a derivation, reuse stable identity, or revive a confirmed tombstone.

## Stable identity

The disk ABI uses non-zero, little-endian `u128` values with distinct Rust types:

- `StoreId`
- `ObjectId`
- `DerivationId`
- `SpaceId`
- `TransactionId`

`ObjectId`, `DerivationId`, `SpaceId`, and `TransactionId` share one monotonically
allocated numeric namespace. Zero is reserved for “none”. Before issuing any ID,
the writer appends and flushes an `IdHighWater { exclusive_end }` record; only IDs
strictly below the recovered exclusive end may appear later. High-water values
strictly increase and never wrap. Unused reserved IDs are skipped after reboot.

A durable mention consumes identity. A prepare, including an uncommitted prepare,
prevents reuse of its derivation ID. An orphan commit also consumes both its
transaction and derivation IDs. A tombstone may name an absent derivation, is
retained, and makes a later attempt to introduce that same derivation ID invalid.
Compaction must preserve these facts even after the original record is removed.

`StoreId` is a format-time trust anchor supplied by the platform. VibeOS currently
has no entropy source, so it must not pretend that a boot-local counter is a unique
store identity.

## Physical record

Every record occupies one aligned 512-byte sector. Integers are little-endian.
Unused and reserved bytes are zero. An encoder emits deterministic bytes.

| Offset | Size | Field |
|---:|---:|---|
| `0x000` | 8 | magic `VIBECAP\0` |
| `0x008` | 2 | version, currently `1` |
| `0x00a` | 2 | record kind |
| `0x00c` | 2 | header length, `80` |
| `0x00e` | 2 | exact payload length for the kind |
| `0x010` | 8 | sequence, beginning at `1` |
| `0x018` | 8 | previous valid sequence |
| `0x020` | 4 | CRC32C of the previous valid record |
| `0x024` | 4 | flags; v1 requires zero |
| `0x028` | 16 | `StoreId` |
| `0x038` | 16 | `TransactionId`, or zero for non-transaction records |
| `0x048` | 8 | reserved zero |
| `0x050` | 384 | payload and canonical zero padding |
| `0x1d0` | 4 | CRC32C of bytes `0x000..0x1cf` |
| `0x1d4` | 4 | bitwise complement of the CRC |
| `0x1d8` | 8 | repeated sequence |
| `0x1e0` | 16 | repeated transaction ID |
| `0x1f0` | 16 | seal `VIBECAP-COMMIT!!` |

CRC32C uses the reflected Castagnoli polynomial `0x82f63b78`; the standard
`123456789` check vector is `0xe3069283`. The CRC detects accidental corruption;
it is not authentication. The duplicate trailer fields bind the unchecksummed
trailer to the checksummed header.

### Record kinds

1. `Format` — zero-length payload. It is the first valid record, sequence 1,
   with no transaction or previous link.
2. `IdHighWater` — a 16-byte exclusive end.
3. `GrantPrepare` — the proposed derivation and destination.
4. `GrantCommit` — exact binding to a prepare.
5. `RevokeTombstone` — a durable deletion of one derivation subtree.

Unknown versions, kinds, flags, rights bits, non-zero padding, or malformed sealed
records reject the whole authority store. A future deletion record must never be
silently skipped by an older reader.

`GrantPrepare` payload:

```text
derivation_id       u128
parent_id           u128  // zero for a root
object_id           u128
target_space_id     u128
target_slot         u32
rights              u32   // v1 bits r,w,s,v,g,x only
generation          u64
resource_kind       u32   // stable non-zero numeric tag
grant_flags         u32   // bit 0 ROOT; all other bits zero
```

`GrantCommit` payload:

```text
prepare_sequence    u64
prepare_crc32c      u32
reserved            u32 = 0
derivation_id       u128
```

`RevokeTombstone` contains one `DerivationId`. `ResourceKind` is a stable disk
number, never a Rust `TypeId`, pointer, or display string.

## Media and crash model

M4.0 proves recovery only under this explicit device contract:

- one writer appends to never-before-written, all-zero, 512-byte-aligned sectors;
- a power loss during one sector write leaves either the old zero sector or an
  exact prefix of the intended new sector followed by old zero bytes;
- a successful flush makes all preceding writes complete, ordered, and durable;
- a flushed sector is never overwritten;
- later retries may use another physical sector and link around an unsealed slot.

The 16-byte seal contains no zero bytes. Therefore every strict prefix lacks the
exact seal and is classified as torn, while a full 512-byte prefix is precisely the
record the encoder intended. Empty and unsealed sectors are ignored. Any sector
with a complete seal but invalid canonical fields or CRC fails closed.

If the M4.1 device cannot provide the prefix-write/ordered-flush contract, the
format must change to a separately flushed body sector plus seal sector. CRC alone
does not make an arbitrary torn sector atomic.

Controller lies, maliciously recomputed CRCs, bit rot outside the model, rollback
to an old full-disk snapshot, and multi-writer races are not solved by v1. Rollback
resistance needs an authenticated checkpoint plus an external monotonic anchor.

## Transaction protocol

Grant:

1. Validate that the parent is live, carries `GRANT`, names the same object and
   stable resource kind, and that requested rights are a subset.
2. Persist and flush a high-water mark covering every new ID.
3. Append `GrantPrepare`; flush.
4. Append an exactly matching `GrantCommit`; flush.
5. Only now publish the cap in a live CSpace or report success.

An orphan prepare or commit creates no authority. Reusing or conflicting transaction
IDs is corruption, not retry semantics.

Revoke is tombstone-first:

1. Validate the caller's live revoke authority.
2. Append `RevokeTombstone`; flush.
3. Only now kill the live derivation, collect slots, and acknowledge success.

Killing memory state before the tombstone flush would allow an acknowledged revoke
to disappear after reboot. An invocation lease acquired before step 3 may finish,
as specified by M3.16; durable revoke does not retroactively interrupt an in-flight
operation.

No CSpace or service lock may be held across asynchronous write/flush. M4.3 needs a
pending slot reservation or a centralized authority transaction serializer, followed
by generation revalidation before publication.

## Recovery

Recovery scans physical sectors in order:

1. Ignore all-zero and unsealed sectors. Decode every sealed sector canonically.
2. Require one first `Format` record. Valid records must share `StoreId`, have
   strictly consecutive sequences, and match the previous sequence/CRC chain.
3. Apply strictly increasing high-water records. Reject any ID that was not already
   reserved when its record appeared.
4. Pair prepare/commit by transaction, prepare sequence, prepare CRC, and derivation.
   Only a complete exact pair becomes a candidate grant.
5. Validate each candidate in commit order. Roots must exactly match an external
   `RootPolicy`. A derived parent must already exist, carry `GRANT`, and have rights
   containing the child. Object and resource kind must match every ancestor. One
   `ObjectId` has one stable `ResourceKind` across all roots and derivations.
6. For each `(SpaceId, slot)`, generations strictly increase. Reuse is accepted only
   if the prior derivation or an ancestor had a tombstone before the new commit;
   generation `u64::MAX` retires the slot.
7. Collect tombstones independently of record order, then remove every node whose
   own ID or any ancestor ID is tombstoned. A tombstone always wins.

Recovery returns stable IDs and live `RecoveredGrant` records, not `Arc<Resource>`.
M4.2/M4.3 must resolve `ObjectId + ResourceKind` to a real object; missing or
type-mismatched objects are not installed.

## Crash-safety argument

1. **Record lemma.** Under the prefix model, a strict partial write has no complete
   seal and cannot be a valid record. A complete write is the encoder's exact record.
2. **Grant lemma.** Only an exact prepare/commit pair can create a candidate, and
   recovery independently rechecks root policy, ancestry, object, type, and rights.
   A crash can therefore omit a grant or recover the exact requested subset, never
   invent or widen one.
3. **Revoke lemma.** A torn tombstone occurs before flush/ack and may leave the old
   state. A complete flushed tombstone removes the entire subtree regardless of
   descendant record order. An acknowledged revoke cannot revive.
4. **Identity lemma.** High-water is flushed before publication. Every published ID
   is below the recovered exclusive end, so reboot skips it rather than reusing it.

The host suite enumerates all 0 through 512 prefix cuts for every record kind and
again at grant-prepare, grant-commit, and tombstone protocol boundaries. It also
checks CRC vectors, canonical round trips, torn holes, high-water ordering, exact
root policy, transaction binding, rights attenuation, object/type consistency,
cross-space ancestor tombstones, and slot-generation reuse.
