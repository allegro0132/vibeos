# Capability-addressed object store

M4.2 turns the supervised virtio block device into durable objects without
introducing a filesystem namespace. An object has a stable on-media identity,
but that number is private store metadata: clients can reach the object only by
holding a live `StoredObject` capability.

The public operation boundary is deliberately small:

```text
store.put(bytes, kind, target_cspace) -> object capability
store.get(store_cap, object_cap)       -> bytes
```

`put` requires `WRITE` on the store service. `get` requires `READ` on both the
store service and the object. There is no `open(ObjectId)`, path lookup, name
table, directory, or enumeration API. Revoking the object capability prevents
the next read even though the inert bytes remain durable.

## Disk region and journal

The object store owns sectors 64 through 575 of the first virtio block device.
It is a single-writer, append-only journal. The region uses the canonical
512-byte `VIBECAP` envelope from [DURABLE_FORMAT.md](DURABLE_FORMAT.md); object
records extend the common kind namespace:

| Kind | Record | Meaning |
|---:|---|---|
| 1 | `Format` | first valid record and store identity anchor |
| 2 | `IdHighWater` | flushed exclusive reservation for every stable ID class |
| 3--5 | authority records | M4.0/M4.3 grant and revoke records |
| 6 | `ObjectPrepare` | object kind, exact length, chunk count, and content CRC |
| 7 | `ObjectChunk` | ordered 360-byte-or-smaller content fragment |
| 8 | `ObjectCommit` | exact prepare and ordered chunk-digest binding |

Object, derivation, space, and transaction IDs share the one monotonic numeric
namespace. Recovery decodes the full record-kind set and rejects a number used
for two ID classes. The format marker, high-water record, object records, and
live M4.3 authority records therefore form one sequence/CRC chain rather than
independent logs that could disagree about identity.

The physical scan always covers the complete fixed region. A single fixed 256 KiB `.bss`
scratch buffer is reused and completely overwritten on every scan; per-invocation
decoder and transaction allocations belong to the caller's allocation domain,
and recovery streams decoded records instead of retaining a journal-sized set of
chunk allocations. A caller without the conservative 4 MiB recovery headroom is
refused before the single-writer claim is taken; the current shell and audited
fault probe each have an 8 MiB quota. If any task nevertheless faults,
the executor's non-allocating cleanup hook clears only the claim matching its exact
`TaskId` and allocation domain; an audited caller then also raw-reclaims its arena
instead of abandoning SYSTEM RAII. All-zero and
unsealed prefix-torn sectors are permanent holes; they do not terminate the
scan. Every sealed malformed record, broken sequence/CRC link, store-ID change,
unreserved ID, duplicate transaction/object, chunk splice, or commit mismatch
rejects recovery. Incomplete prepares and chunks consume identity but publish
no object.

## Publication protocol

One `put` performs these durable steps:

1. recover the current journal and select fresh object and transaction IDs;
2. append and flush an `IdHighWater` that covers both IDs;
3. append the prepare and chunks without exposing an object capability;
4. append and flush the commit;
5. rescan and verify the exact committed bytes from the block device;
6. mint `StoredObject` into the caller-selected CSpace only if that CSpace is
   still the same incarnation captured before the first await.

The final flush is the publication boundary. An I/O error, cancellation, or task
fault marks the in-memory cursor untrusted; the next operation rescans the complete
region.
No CSpace, store-state, or block-service lock is held across an await. If a
target component restarts while the write is in flight, the durable object may
exist but no capability is installed into the replacement incarnation.

The generic M4.2 object API still does not reopen every committed object after
reboot. Recovery first rebuilds an inert catalog. M4.3 then admits only the graph
for the fixed `persistent-test` SpaceId after external root-policy validation and
atomically reinstalls its typed `StoredObject` capabilities. There is still no
ambient `ObjectId` lookup or enumeration path. See
[PERSISTENT_CSPACE.md](PERSISTENT_CSPACE.md).

## Acceptance evidence

The harness seeds a valid 506-record journal containing one 180,720-byte object.
`store fault` then repeats four injected component faults after dense recovery and
transaction allocation but before any disk write. A monotonic reached counter
proves each panic came from that exact task/domain-bound hook rather than an early
quota failure. Teardown repairs the abandoned single-writer claim, raw-reclaims
the caller arena, and must reach a stable heap plateau across restarts. `store test`
then writes a deterministic 900-byte, three-chunk object into the final six slots,
reads it back
through two capabilities, proves a read-only store cap cannot write, and proves
revocation blocks a new object read. The QEMU harness then shuts the VM down and
independently parses the raw backing image with `scripts/store-image.py`; it
requires both exact committed payloads and validates the full sealed journal rather
than trusting the kernel's in-memory result.

Host tests enumerate every prefix cut and commit boundary, exercise torn holes,
multi-chunk and empty objects, malformed bindings, shared identity collisions,
and allocation-amplification attempts from incomplete maximum-size prepares.
The separate M4.3 acceptance reboots three times on one disk and independently
verifies the unified object/authority graph, ancestor tombstone, and generation-1
slot reuse; it does not change the M4.2 public store API.
