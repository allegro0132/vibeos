# Capability-scoped storage device contract

Storage V2 does not give a client an ambient disk or an absolute sector API.
The pure `no_std` `storage-device` crate defines the checked identity, geometry,
range, request, and durability vocabulary; the kernel facade applies that
contract before either board backend sees an address. The crate performs no I/O
and allocates no memory.

## Identity and incarnation

`DeviceId` is a non-zero 128-bit stable identity selected by trusted image
policy. It identifies the same managed device across driver restarts.
`DeviceSession` pairs that identity with a non-zero 64-bit incarnation. Every
successful attach creates a new incarnation; a virtio reset and reinitialization
also advances it.

A `BlockRange` deliberately contains the stable `DeviceId`, not an incarnation.
The authority remains meaningful after a restart, but a cached `RangeSession`
does not: request validation compares both the device identity and incarnation
with the current `DeviceInfo` before translating an address. A changed device is
`WrongDevice`; a changed incarnation is `StaleIncarnation`. Neither case
discloses a translated backend address.

## `BlockRange` authority

`BlockRange` is the non-empty half-open interval
`[first_block, first_block + block_count)` in one device's logical-block
namespace. Its fields are private.

- Trusted discovery/image policy alone calls `BlockRange::root`. Construction
  rejects an empty range and checked-add overflow.
- Safe callers call `attenuate(relative_first, block_count)`. The child keeps
  the same `DeviceId`; both its relative end and translated first block are
  checked, and the child must be wholly contained by the parent.
- `CSpace::derive_scoped` combines that semantic subset check with ordinary
  capability rights attenuation and preserves derivation ancestry. A child
  cannot gain rights, widen its interval, change devices, or escape parent
  revocation.
- Independently admitted roots on the same device must not overlap. Adjacent
  half-open ranges and ranges on distinct devices do not overlap.
- `translate` checks the complete relative request before returning an absolute
  logical block. `byte_bounds` uses checked multiplication, so neither block nor
  byte arithmetic wraps.
- `DeviceInfo::admits` additionally proves that the range ends within the
  currently reported device capacity.

The private `block-policy` CSpace owns the full managed-range root plus raw
MMIO/PIO, DMA, and driver-service roots. Raw device authority is granted only to
the supervised driver component. The client layout is:

| Holder | Managed logical range | Rights | Can delegate or revoke? |
|---|---:|---|---|
| `init` diagnostics | `[0, 64)` | `READ | WRITE` | No |
| Store backend | `[64, 576)` | `READ | WRITE` | No |
| `block-policy` | complete admitted image range | policy root | Yes, only through checked attenuation |

The two client ranges are disjoint. Blocks `[576, capacity)` are not granted to
either client. On QEMU the admitted image range is `[0, 2048)`. On Milk-V the
managed range is `[0, 8192)` and the SDHCI backend alone translates it to
physical microSD sectors `[262145, 270337)`. Consequently neither `init` nor the
Store can name a boot-partition sector; the physical partition offset never
enters their CSpaces.

## Geometry and request validation

`DeviceGeometry` reports:

- logical block size;
- optional physical block size;
- preferred write size and alignment in logical blocks;
- maximum transfer in logical blocks;
- an optional proven atomic-write size;
- `WriteThrough`, `Volatile`, or `Unknown` write-cache state;
- Flush and FUA support; and
- optional Discard granularity, alignment, and maximum length.

Construction rejects a logical block smaller than 512 bytes or not a power of
two, a physical block that is smaller than or not divisible by the logical
block, zero preferred/max-transfer sizes, an invalid preferred alignment, an
atomic size outside `1..=max_transfer`, and invalid Discard geometry. Preferred
write values are performance guidance, not an atomicity claim.

`validate_request` first revalidates the range/session, then requires a non-zero
block count within `max_transfer_blocks`, checked byte length, exact caller
buffer length for Read/Write, and no buffer for Discard. It rejects writes and
Discard on read-only devices, unsupported FUA/Discard, and misaligned or
over-sized Discard. Only after all checks pass does it produce a
`ValidatedRequest` containing the current session and translated logical block.
The generic `BlockIo` interface performs data transfer through borrowed caller
slices; the validated request itself contains no caller pointer or ambient
address.

The current backends intentionally report only facts they can prove:

| Geometry field | QEMU virtio-blk | Milk-V SDHCI PIO |
|---|---|---|
| Logical block | 512 B | 512 B |
| Physical block | Unknown | Unknown |
| Preferred write | 1 block, alignment 0 | 1 block, alignment 0 |
| Maximum transfer | 1 block | 1 block |
| Atomic write | Not claimed | Not claimed |
| Cache | `Unknown` | `Unknown` |
| Flush | Negotiated virtio feature; required by the M4 adapter | Supported by the synchronous card flush path |
| FUA | Unsupported | Unsupported |
| Discard | Unsupported | Unsupported |
| Read-only | Negotiated device state | No |

An unknown cache is treated conservatively as volatile for durability: a plain
successful write still needs Flush. The Store refuses the compatibility backend
unless the current logical block size is exactly 512 bytes and Flush is
supported.

## M4 512-byte adapter

M4 uses historical absolute sector numbers `[64, 576)`, while the new kernel
facade accepts addresses relative to the caller's `BlockRange`.
`Legacy512Adapter` bridges only that numbering difference; it does not create or
widen authority.

The Store constructs the adapter from its exact `[64, 576)` range with legacy
base 64. Checked translation is therefore:

```text
legacy 64   -> range-relative 0   -> managed block 64
legacy 575  -> range-relative 511 -> managed block 575
legacy 63   -> rejected
legacy 576  -> rejected
```

The compatibility `BackendInfo` continues to report an end/capacity value of
576 because the M4 journal generates absolute sector numbers. Every read and
write first passes through `relative_sector`, so that descriptive value cannot
authorize sectors `[0, 64)` or any sector at or beyond 576. The adapter is
temporary migration machinery; new Storage V2 code uses range-relative logical
blocks directly.

Each M4 scan pins the `DeviceSession` returned with its scoped geometry. Each
durable sector append then holds one invocation lease and one `MutationSession`
across the data write and any required Flush. A restart cannot splice a write
from one device incarnation to a barrier from another. Once the write has been
submitted, any later barrier failure is promoted to `Ambiguous`, even when that
barrier itself was rejected before submission.

## Completion, durability, and ambiguity

Success and failure are separate from mutation certainty. The portable taxonomy
has `MutationCertainty::NotSubmitted` and `MutationCertainty::Ambiguous`; there
is intentionally no failed result that claims a submitted mutation was rolled
back.

| Event | Required interpretation |
|---|---|
| Validation, rights, range, stale-session, read-only, feature, or queue-full failure before device submission | `NotSubmitted`; no media effect from this request |
| Plain Write succeeds with `WriteThrough` cache | The exact write is `Durable` |
| Plain Write succeeds with `Volatile` or `Unknown` cache | Bytes were accepted, but durability is `RequiresFlush` |
| FUA Write succeeds | The exact write is `Durable`; FUA must have been advertised and validated |
| Flush succeeds | All writes completed before that Flush submission are durable under the backend's ordered contract |
| Cancellation while still queued | `NotSubmitted`; the request is removed before publication |
| Cancellation after publication | `Ambiguous`; the caller is detached, but the driver must finish or reset the device before reusing transport state |
| Timeout, device error, protocol error, driver fault/restart, quarantine, or authority loss after publication | `Ambiguous`; the mutation or durability transition may have completed |
| Cached incarnation rejected before publication after restart | `NotSubmitted`; reacquire current `DeviceInfo` and revalidate |
| Capability revoked before lease/request acquisition | `NotSubmitted`; no new request may begin |
| Capability or raw driver authority revoked after publication | Revocation prevents later use but is not rollback; the in-flight mutation is `Ambiguous` |

For a failed Flush, ambiguity concerns whether earlier completed writes reached
non-volatile media. For a failed FUA Write, both the bytes and their durability
are ambiguous. A retry is not evidence of exactly-once execution. Recovery must
reread and validate the canonical media state, then either accept the committed
generation or safely write a new one.

Invocation leases remain live until an admitted operation finishes. Revocation
blocks future acquisition; it does not pretend to cancel DMA or synchronous PIO
already in progress. Virtio revalidates incarnation and raw authority before
descriptor publication, and resets/quiesces the transport after timeout,
restart, fault, or post-publication revocation before DMA memory can be reused.
The synchronous SDHCI path performs the same identity/range validation before
entering its one-request PIO critical section.

## Public API and acceptance

The principal portable types and functions are `DeviceId`, `DeviceSession`,
`BlockRange`, `DeviceGeometry`, `DiscardGeometry`, `DeviceInfo`, `RangeSession`,
`Operation`, `ValidatedRequest`, `validate_request`, `validate_flush`,
`WriteDurability`, `MutationFailure`, `Legacy512Adapter`, and `BlockIo`.

Host contract tests cover checked arithmetic, out-of-range translation,
containment and overlap, stale identity/incarnation, rights and scope
amplification, caller-buffer length, feature/geometry validation, failure
certainty, and exact legacy translations. The QEMU `block` acceptance also
prints the admitted `[0, 64)` scope, rejects its upper boundary, and performs a
real write/Flush/readback against the backing image.

Run the focused gates with:

```sh
cargo test -p vibeos-storage-device -p vibeos-core
./scripts/qemu-test.sh block
```

Physical Milk-V microSD I/O evidence remains tracked separately in
[MILKV_DUO.md](MILKV_DUO.md); the same facade and conservative geometry compile
for that backend without granting the boot partition.
