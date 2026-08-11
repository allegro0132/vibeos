# Persistent CSpace

The stable persistent-space identity, exact rights policy, lifecycle contract,
and public report/error types live in `services/authority-store`. Atomic CSpace
reservation and graph installation, block-online coordination, and exact-task
fault quarantine remain explicit kernel duties in
`kernel/src/authority_store_platform.rs`.

M4.3 restores one capability space from the same append-only journal that stores
immutable objects. It is deliberately a narrow end-to-end slice, not a general
checkpoint subsystem: the only admitted target is the boot-registered
`persistent-test` space with fixed `SpaceId = 0x5053`.

The target never receives a Store `WRITE` capability. `init` holds a separate
`DurableCSpaceService` capability, and that trusted service alone coordinates
journal appends, flushes, recovery policy, and live publication. The recovered
entries are typed `StoredObject` resources, so persistence does not introduce a
path, `open(ObjectId)`, or ambient object registry.

## One journal, two inert record families

Object and authority records occupy the object store's fixed sectors 64 through
575 and share one canonical `VIBECAP` stream:

- kinds 1--2 format the store and reserve the shared stable-ID high-water mark;
- kinds 3--5 prepare/commit grants and record revoke tombstones;
- kinds 6--8 prepare, chunk, and commit immutable objects.

The decoder, sequence/CRC chain, transaction table, and numeric ID-class map are
shared. An object record therefore cannot reuse an authority transaction or ID,
and authority recovery cannot skip malformed object records as unrelated bytes.
Every grant and object remains inert until its exact commit is present.

The implementation and proof are limited to the v1 media contract: one writer,
never-overwritten sectors, prefix-torn sector writes, and successful flushes that
make prior writes complete, ordered, and durable. CRC32C detects corruption within
that model; it is not authentication, rollback resistance, or multi-writer
coordination.

## External root policy

An on-media `ROOT` flag is only a candidate marker. Recovery admits a live root
only when exactly one final candidate matches the boot-owned policy:

- `SpaceId` is exactly `0x5053` and the target slot is exactly 0;
- generation is 0;
- the grant has no parent and carries exactly `READ | GRANT | REVOKE`;
- `ResourceKind` is the stable `StoredObject` kind `0x53544f52`;
- the referenced object was committed earlier in the same journal and has the
  allowed object kind `0x43535043`.

Any additional live root, missing root, ambiguous match, foreign space history,
wrong rights/kind, or object committed after the grant fails closed. The
acceptance object contains `VIBEOS-PERSISTENT-CSPACE-v1`, but its bytes are object
data rather than an authority oracle; the external policy binds its stable object
kind and the grant's resource shape.

The initial graph is deliberately small and monotone:

| slot | node | generation | rights |
|---:|---|---:|---|
| 0 | root | 0 | `READ | GRANT | REVOKE` |
| 1 | child of root | 0 | `READ | GRANT` |
| 2 | grandchild of child | 0 | `READ` |

Each node names the same committed object. A typed persistent witness retains the
exact object, derivation node, stable IDs, slot generation, resource kind, and
rights. Ordinary `derive`, cross-space `grant`, `revoke`, administrative slot
revoke, and CSpace reset paths refuse to mutate persistent nodes.

## Recovery and atomic installation

Boot recovery moves through `Cold -> WaitingBlock -> Recovering -> Ready`. Any
validation or installation error moves to `FailedClosed`. The existing block
supervisor owns this boot gate, so recovery consumes no new `TaskId`; its first
dependent `persistent-test` observation waits for `Ready` and cannot see a partial
graph.

The supervisor keeps one exact boot claim while the device is unavailable. It
checks driver terminal state before retrying recovery and shares the driver's
three-attempt exponential-backoff budget. `Offline`, `DriverFault`, and
`DriverRestarted` during a scan return the gate to `WaitingBlock`; after the
driver is online again, recovery discards the prior scratch result and starts at
sector 0. Format, policy, type, or installation failures remain permanently
fail-closed. This retry path is part of the existing block supervisor future, so
driver recovery does not consume or reorder global task identities.

Recovery has two publication phases:

1. A full journal scan produces an inert preflight result. It validates the
   canonical chain, global IDs and transactions, committed objects, grant graph,
   ancestor tombstones, and complete generation history for every `(SpaceId,
   slot)`.
2. The external root constraint selects the sole allowed root. Only then does
   `finish` produce the live grant subset. A typed SYSTEM-owned `StoredObject`
   witness is supplied for that root, and the CSpace builds the complete candidate
   slot table and derivation graph in the SYSTEM allocation domain.

The installer rechecks the target CSpace incarnation, exact stable identities,
parent `GRANT`, rights attenuation, object/resource equality, live-slot history,
and resource type. It swaps the candidate table into the CSpace only after every
check and allocation succeeds. An error leaves the old table authoritative and
publishes nothing.

Live grant creation uses an opaque pending slot reservation so no CSpace lock is
held across an asynchronous write or flush. The service reserves the exact
incarnation, slot, and generation; flushes the high-water and grant transaction;
rescans the real device; and only then installs the committed root or child against
the same reservation and typed parent witness.

Every live lifecycle operation also owns a SYSTEM-stable claim keyed by exact
`TaskId`, allocation domain, and monotonic token. Its single pending reservation
is copied directly into that fixed ledger before any await or allocation. A normal
success consumes the reservation and clears only the matching claim. An error,
async cancellation, or raw task fault is conservative because the last flush may
already have committed: it moves the service to `FailedClosed` and quarantines the
whole persistent CSpace until reboot.

Quarantine is enforced in the CSpace's generic lookup path as well as its durable
witness/install APIs, so holding a raw `Cap` cannot bypass the service gate. It
kills derivation nodes (therefore existing `Revocable` tokens fail) and clears
reservation tokens, but retains slot entries and their `Arc<Resource>` values.
Raw-fault cleanup first repairs only locks abandoned by the exact fault domain,
then quarantines without allocation, generation changes, or resource destructors.
An `InvocationLease` acquired before the boundary may finish under the M3.16
contract; no new invocation can resolve afterward.

## Tombstone and generation reuse

Revocation is tombstone-first. The root's exact `REVOKE` witness authorizes a
tombstone for slot-1 child. The service flushes that tombstone before killing the
live child derivation. Because slot 2 descends from the child, the same ancestor
tombstone removes the grandchild during both live collection and later recovery.

Recovery retains the maximum historical generation even when a slot has no live
derivation. The next reservation for slot 1 is therefore generation 1, never a
second generation-0 handle. Generation `u64::MAX` remains permanently retired.

## Acceptance evidence

`./scripts/qemu-test.sh persistent_cspace` uses one raw disk for three complete
QEMU boots:

1. Boot 1 persists the object and `root -> child -> grandchild` graph, reads the
   marker through the grandchild, and shuts down.
2. Boot 2 restores the graph before the first dependent observation, reads through
   the restored authority, flushes the child tombstone, and proves both child and
   grandchild absent.
3. Boot 3 proves the tombstoned nodes remain absent, reuses slot 1 only at
   generation 1, reads through the replacement child, and shuts down.

Every boot asserts that Store `WRITE` is absent from `persistent-test`. After the
third shutdown, `scripts/persistent-cspace-image.py` independently parses the raw
backing image and verifies the root, ancestor tombstone, and generation-1 reuse.
Its host self-test applies 512 strict byte-prefix cuts (0 through 511) to each of
19 canonical records: 9,728 cuts must recover exactly the preceding complete
record boundary. It separately rejects ID-class collisions, transaction reuse,
missing parents, rights amplification, pre-tombstoned derivations, extra roots,
kind mismatches, and foreign slot history.

## Deliberate limits

- Only the fixed `persistent-test` CSpace is restored. Other component, driver,
  MMIO, DMA, and init authority remains boot policy.
- Generic M4.2 object capabilities are not automatically reopened after reboot;
  only the graph admitted by this external policy is installed.
- Source and compiled-binary persistence remains M4.5. M4.3 does not implement
  `rustc save`, `run`, or the final M4 program-survives-reboot acceptance case.
- The journal has no compaction, authentication, rollback anchor, or concurrent
  writer protocol.

See [DURABLE_FORMAT.md](DURABLE_FORMAT.md) for the record ABI and crash proof and
[OBJECT_STORE.md](OBJECT_STORE.md) for the capability-addressed object boundary.
