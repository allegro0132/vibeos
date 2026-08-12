# Storage V2 maintenance, growth, quota, and scrub contract

This document freezes the M7.6 authority, accounting, online-growth, scrub,
and diagnostic contract. It extends the immutable segment/checkpoint protocol
in [STORAGE_V2_FORMAT.md](STORAGE_V2_FORMAT.md), the streaming CAS in
[STORAGE_V2_CAS.md](STORAGE_V2_CAS.md), and the G/G+1/G+2 cleaner protocol in
[STORAGE_V2_GC.md](STORAGE_V2_GC.md). The words **MUST**, **MUST NOT**,
**SHOULD**, and **MAY** are normative.

## Maintenance authority

`StoreMaintenance` is a distinct, opaque capability resource. It is not a
`Store` write right, an Object capability, a device range, a BlobKey, or an
ObjectId. Its operation mask has three closed bits:

| Bit | Operation |
|---:|---|
| 0 | online growth |
| 1 | scrub and anonymous health reporting |
| 2 | explicit migration or destructive maintenance |

A root maintenance capability is bound to one store runtime and store UUID.
Attenuation may only intersect the operation mask and may never change the
store binding. Every operation rechecks the binding and required bit at the
point of use and then holds a non-cloneable operation lease through the entire
async operation. Revocation succeeds only when the active-lease count is zero;
while an operation is in flight it returns `OperationsInFlight` instead of
spinning, cancelling the operation, or racing past its mutation boundary. Once
revocation succeeds, every old root and attenuated child collapses to
`Unauthorized` before device mutation. A stale runtime is rejected the same
way. An ordinary writer has no method which constructs, widens, or extracts
maintenance authority.

The Rust crate seals the root mint inside `segment-store`. Trusted boot policy
creates one opaque provisioner together with the store runtime context; the
provisioner is domain-bound and can mint a root only through a mounted Store
which carries that same context. Cloning a runtime context or obtaining a Store
handle does not produce the provisioner. VibeOS production policy publishes
only already-attenuated resources through CSpace; untrusted components receive
neither the provisioner nor a raw token value.

## Online growth

Growth consumes an exact non-empty, session-bound `BlockRangeCapability`.
Partition-table
editing, filesystem resizing, device discovery, and range minting remain
outside the store. The candidate MUST:

- name the superblock's stable device identity;
- begin exactly at the committed admitted-range end;
- use the unchanged logical-block size and a whole-page, whole-segment length;
- be fully covered by the supplied capability and current device session;
- increase both admitted pages and admitted segments without overflow;
- remain within the frozen allocation-v2 bitmap and recovery-memory bounds;
  and
- leave the configured cleaner reserve and root-policy headroom available.

Overlap, a gap, a changed device identity, stale device incarnation, read-only
media, partial pages or segments, zero growth, arithmetic overflow, and a
candidate not covered by the supplied capability fail before the first media
mutation.

### Publication order

The selected checkpoint itself is the durable growth record. Its enlarged
`admitted_range_pages`, enlarged `admitted_segments`, and canonical
`VIBEALC2` payload are one indivisible claim. No superblock field changes.

1. Validate maintenance authority, the exact range capability, geometry,
   allocation size, memory ceiling, and generation arithmetic in memory.
2. Extend the volatile page-device view. This grants I/O reachability but does
   not make the suffix allocatable by the selected checkpoint.
3. Stage one immutable metadata segment and the enlarged allocation-v2 payload
   in one ordinary Free carrier from the old admitted range. Growth never
   writes the new suffix before its checkpoint is selected; an interrupted
   carrier remains an unreachable orphan under the old checkpoint.
4. Flush, reread, and authenticate the staged segment and allocation payload.
5. Clear the target checkpoint seal, flush, require exact-zero readback, write
   the new body, flush, write the terminal seal, and flush.
6. Structurally select and fully recover both the old state and the exact new
   state under the configured aggregate memory ceiling.
7. Install the enlarged mounted state. Only now may ordinary allocation use
   Free segments in the new suffix.

The growth checkpoint is exactly generation `G+1`, names `G` as predecessor,
does not change existing Object/Blob/authority roots, and preserves every old
allocation state except any explicitly staged metadata target. Every remaining
new suffix segment is Free. Retired segments do not become Free through growth.

A crash before the new checkpoint seal selects exactly `G`; a complete seal
selects exactly the enlarged `G+1`; a malformed complete marker fails closed.
An already-expanded device view with `G` still selected is a normal retry
state. Cold mount accepts a physical capability larger than the superblock's
initial range, but never treats its uncommitted tail as admitted capacity.

## Principal quotas

A `StoragePrincipal` is an opaque, non-authorizing boot-runtime accounting
resource. It does not grant object reads, expose a persistent ObjectId, or
permit catalog enumeration. Trusted policy receives the sole
`StorageQuotaProvisioner` with a governed runtime, installs non-zero logical
and physical ceilings, and may attenuate either ceiling only downward. A
governed runtime rejects raw, typed, foreground, and legacy Object writes that
omit a principal before device I/O. A principal account is scoped to the store runtime domain;
M7.6 does not encode a principal identifier in Object mappings. M7.7 must bind
restored persistent CSpace principals to stable quota policy before the V2
backend becomes the reboot default.

Admission reserves both charges before the first Blob page is written:

- **logical bytes** are the caller's exact immutable content bytes, charged
  independently for every authorized Object even when content deduplicates;
- **attributable physical bytes** are the canonical Blob envelope, extent and
  manifest metadata, and Object mapping attributable to that Object under the
  frozen accounting formula; and
- **dedup savings** are a separate checked cumulative diagnostic. Reusing a
  complete verified Blob never transfers authority or another principal's
  charge.

The version-1 accounting formula is deterministic before mutation and does not
inspect another principal's identity. Let `record(n) = ceil(n / 4096) * 4096 +
8192`, where the final term is the immutable extent descriptor/seal pair. For
the canonical Blob extents (header, every at-most-1-MiB content extent, and the
serialized Merkle tree), charge `record(payload_len)` for each. Charge the
manifest as `record(BLOB_MANIFEST_HEADER_LEN + extent_count *
MANIFEST_EXTENT_LEN)`, then add one full `ObjectMapping` and one full
`BlobMapping`. All additions, multiplications, ceiling operations, reserving,
committing, releasing, and rollback use checked arithmetic.
Every Object pays this full envelope even on a dedup hit. Anonymous cumulative
unique-byte telemetry attributes only the new `ObjectMapping` to a dedup hit
and records the remaining envelope as cumulative dedup savings. M7.6 does not
publish a "current unique bytes" gauge: without persistent attribution it
cannot distinguish boot-local charged media from pre-existing uncharged media
during GC.

A failed, cancelled, or dropped pre-publication transaction returns its
reservation exactly once. A committed charge remains owned by the runtime
Object-authority resource until its final object handle or derived runtime pin
is released; dropping a temporary future cannot release a live Object's
charge. A cold reboot destroys all runtime-only Object and principal resources
together. Persistent-root quota reconstruction is therefore an M7.7 cutover
requirement, not an implicit M7.6 media identity.
Quota-charged Objects therefore fail closed before entering persistent GC root
policy, and persistent publication targets reject them through a target-bound,
non-forgeable publication token. A runtime pin retains its Object authority in
the owner-scoped root slot itself, so synchronous fault-domain cleanup releases
both the leaked root and its quota charge even if task-local guard memory was
abandoned. A device-session remount using the same runtime context retains the
table and authority leases.

Quota denial occurs before store admission and therefore cannot consume a data
segment, metadata segment, root-policy headroom, or cleaner reserve. It does
not poison the store and cannot prevent unrelated principals from reading
already-authorized data. Quota diagnostics expose only aggregate limits,
current/high-water charges, denial counts, and dedup savings—never principal
keys, ObjectIds, BlobKeys, roots, or content lengths for individual objects.

## Scrub

Scrub requires the scrub maintenance bit and is read-only. It MUST NOT mint an
Object capability, return object content, expose ObjectIds or BlobKeys, update
authority, select a different checkpoint, rewrite a bad record, or reclaim an
orphan. It checks, in bounded memory:

1. both superblock copies and both checkpoint body/seal pairs, including the
   strict fallback/complete-marker rules;
2. every sealed checkpoint that remains structurally selectable and its exact
   allocation transition;
3. every Allocated or Retired segment header, descriptor chain, every extent's
   streaming payload SHA-256 and zero padding, payload hash chain, summary, and
   final seal;
4. selected allocation-v2 counts, retirement generations, and every current
   pointer's Allocated state;
5. the complete CAS Object/Blob mapping closure, every canonical manifest,
   every exact Blob extent payload hash, serialized Merkle tree, and Blob root;
   and
6. persistent-root closure plus every policy-admitted typed object and edge,
   including runtime-only objects when no persistent root exists, without
   treating a media tag as parser authority.

Scrub reports a closed anonymous `ScrubReport`: selected generation, admitted/
allocated/free/retired segment counts, object and Blob counts, verified byte
and record totals, checkpoint fallback state, corruption class counters,
device-I/O failures, recovery/scrub memory high-water, cleaner pressure, quota
aggregate high-water, and a saturated health status. Counts are bounded and
saturating telemetry, not authority.

Any injected data, tree, summary, mapping, allocation, authority, or checkpoint
corruption yields a non-healthy result or a fail-closed error. Scrub never
silently repairs authority. An I/O error is device health evidence and remains
distinguishable from authenticated-format corruption without exposing which
object was being checked.

## Independent evidence

M7.6 acceptance includes:

- a mutation-boundary growth matrix proving old-or-exact-new recovery;
- cold retry with an expanded device view and the old checkpoint selected;
- exact rejection tests for changed device, overlap, gap, partial geometry,
  missing capability coverage, and arithmetic/memory bounds;
- quota exact-limit and one-byte-over tests before any media mutation, two
  independent principals, dedup accounting, rollback, and cleaner-reserve
  isolation;
- scrub injection tests for data, tree, summary, mapping, allocation,
  authority, and both checkpoint copies; and
- a powered-off host verifier which reconstructs the enlarged range and emits
  only the closed anonymous diagnostic schema.

The full host suite, strict Clippy, pinned `riscv64imac-unknown-none-elf`
`no_std + alloc` build, and exact command output belong in
[STORAGE_V2_EVIDENCE.md](STORAGE_V2_EVIDENCE.md) only after they run.
