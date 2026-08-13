# Storage V2 evidence

This file records the reproducible compatibility and performance evidence for
the ordered stages in [STORAGE_V2_ROADMAP.md](STORAGE_V2_ROADMAP.md). Results
are evidence for a named build and dataset, not timeless performance claims.

## M7.0 SHA-256 compatibility baseline

Measured on 2026-08-12 at commit `ab3a688555845c478172f7e9ab77202e97c45a33`
with the pinned `nightly-2026-08-01` toolchain on Apple arm64, macOS 26.5.2.
The release benchmark hashes one reused 4096-byte buffer 16,384 times (64 MiB)
through the public `vibeos_blob_format::sha256` entry point. The firmware is the
QEMU `legacy-shell` release ELF and sizes come from LLVM `size`; the on-disk ELF
includes debug information.

| implementation | elapsed | throughput | text | data | bss | ELF file |
|---|---:|---:|---:|---:|---:|---:|
| private M4 SHA-256 | 0.260158 s | 246.00 MiB/s | 712,704 B | 69,576 B | 7,034,624 B | 17,379,376 B |
| RustCrypto `sha2` 0.11.0 | 0.032964 s | 1,941.53 MiB/s | 724,992 B | 69,576 B | 7,034,624 B | 17,647,856 B |

The compatibility gate is byte identity, not these timings. Four blobs emitted
by the old implementation are permanently stored under
`blob-format/tests/fixtures/m4`: empty, 37-byte one-leaf, 12,305-byte
multi-leaf, and the 360,352-byte maximum content whose canonical 368,640-byte
envelope fits the M4 object limit. Tests compare every encoded byte and root.

Reproduce the focused measurements and target dependency check with:

```sh
cargo run -p vibeos-blob-format --release --example hash-throughput --locked --offline
./scripts/check-blob-sha2.sh
```

## M7.1 capability-scoped block contract

Accepted on 2026-08-12 at commit `1c3a983c722e418c05000319767f16389d191aa3`.
The portable contract tests cover checked range attenuation, complete disjoint
grant layouts, stale device incarnations, truthful geometry, exact M4 adapter
translation, and mutation certainty. Driver tests pin the publication boundary
to the VirtIO `avail.idx` store and the SDHCI CMD24/CMD13 `COMMAND` stores.

The QEMU `block`, `store`, and `block_recovery` cases passed against real raw
backing images. The exact Milk-V `milkv-duo-sd` firmware built with the pinned
nightly toolchain; its image verifier now requires the policy LBA 262145 and
131072-sector data partition.

Focused reproduction:

```sh
cargo test -p vibeos-storage-device -p vibeos-core \
  -p vibeos-driver-virtio-blk -p vibeos-driver-sdhci-blk \
  -p vibeos-object-store --locked --offline
./scripts/qemu-test.sh block
./scripts/qemu-test.sh store
./scripts/qemu-test.sh block_recovery
```

## M7.2 canonical segment format and crash model

Accepted on 2026-08-12. The `vibeos-segment-format` crate is `no_std`, uses no
allocator, and compiles for `riscv64imac-unknown-none-elf` with only `core`.
Its production tests cover every record kind, exact layout, opaque verified
records, checked geometry and pointer arithmetic, strict checkpoint selection,
payload hashing, segment hash chains, all 4096 strict seal prefixes, and every
possible single-byte corruption of a sealed checkpoint body.

M7.2 freezes and validates the allocation-free structural selection phase.
Resolving a selected checkpoint's roots against finalized segments is the
I/O-owning mount phase implemented and fault-injected by M7.3; a structural
selection is deliberately not exposed as a mounted store.

`scripts/storage-v2-image.py` is an independent Python parser with literal ABI
offsets, CRC32C, SHA-256, checkpoint/pointer/segment verification, stable JSON,
and negative image fixtures. A Rust integration test writes a canonical anchor
with the production encoder and requires that independent parser to accept it.

Focused reproduction:

```sh
cargo test -p vibeos-segment-format --locked --offline
cargo clippy -p vibeos-segment-format --all-targets --locked --offline -- -D warnings
python3 -B scripts/storage-v2-image.py --selftest
RUSTC="$(rustup which --toolchain nightly-2026-08-01 rustc)" \
RUSTDOC="$(rustup which --toolchain nightly-2026-08-01 rustdoc)" \
rustup run nightly-2026-08-01 cargo check -p vibeos-segment-format \
  --target riscv64imac-unknown-none-elf -Zbuild-std=core --locked --offline
```

## M7.3 append-only segment store

Accepted on 2026-08-12. `vibeos-segment-store` is a `no_std + alloc`,
single-writer implementation over the M7.1 `BlockRange`/`BlockIo` contract. It
formats dual superblocks/checkpoints, conservatively seals one immutable
transaction segment, maintains an on-media catalog snapshot plus bounded delta
chain, preserves cleaner reserve, and exposes only opaque object handles
through its transitional `put/get` adapter.

The host fault device keeps visible and durable media separate. Eight
integration tests inject not-submitted failure, ambiguous completion before or
after media effect, pending cancellation, and driver restart at every format
and put write/flush boundary. Cold recovery sees the preceding checkpoint or
the exact new checkpoint. The same suite covers sealed orphan quarantine,
three truthful capacity classes, read failures, and a measured recovery-memory
ceiling whose one-byte-under case fails closed.

The production Rust writer exports a powered-off raw image during the test and
requires `scripts/storage-v2-image.py` to reconstruct both committed objects.
The independent parser's 22 selftests cover catalog snapshot/delta and
allocation schemas, bounded replay, every sealed checkpoint, nested pointer
range and generation checks, orphan reporting, exact Blob reconstruction, and
the M7.2 structural corruption set. Object discovery starts only at the
selected catalog root; normal Rust mount reads metadata payloads and extent
descriptors without scanning Blob payload bytes.

The default QEMU backend remains the M4 compatibility journal until M7.7. Its
existing `./scripts/qemu-test.sh store` guest and independent 512-record raw
backing verifier remained green after adding `segment-store`; M7.3's scalable
raw-image acceptance is the host production-writer/Python-verifier gate above.

Focused reproduction:

```sh
cargo test -p vibeos-segment-store -p vibeos-segment-format --locked --offline
cargo clippy -p vibeos-segment-store -p vibeos-segment-format \
  --all-targets --locked --offline -- -D warnings
python3 -B scripts/storage-v2-image.py --selftest
RUSTC="$(rustup which --toolchain nightly-2026-08-01 rustc)" \
RUSTDOC="$(rustup which --toolchain nightly-2026-08-01 rustdoc)" \
rustup run nightly-2026-08-01 cargo check -p vibeos-segment-store \
  --target riscv64imac-unknown-none-elf -Zbuild-std=core,alloc --locked --offline
```

## M7.4 streaming Blob CAS and deduplication

Accepted on 2026-08-12. The focused host run covered both the new M7.4 path and
the retained M7.3 path. `vibeos-blob-format` passed its 11 canonical-format
integration tests and 6 streaming-builder integration tests. The streaming
tests compare the incremental descriptor, header, and indexed tree with the
non-streaming encoder at empty, leaf, and tree boundaries; the 64 MiB synthetic
case reaches the 15-emission maximum while retaining the fixed 15-slot frontier.
They also cover strict ordering and lengths, explicit resumable padding, exact
extent geometry, and permanent poisoning after an ambiguous sink failure.

`vibeos-segment-store` passed 21 unit tests, including the frozen M7.3 codecs,
the M7.4 BlobKey/manifest/snapshot/delta codecs, directed-range arithmetic, and
the authority boundary. Those authority tests give two objects the same
test-only content identity, revoke one independent root without affecting the
other, reject a stale publication incarnation, and return the same unavailable
error for missing and unauthorized resolution.

One Rust-to-Python ABI integration test emitted a canonical manifest, snapshot,
new-Blob delta, and reuse delta with the production Rust encoders. The
independent Python verifier accepted the exact files and their four-entry
header/content/content/tree manifest. Eight CAS streaming integration tests
covered strict chunk admission, canonical empty content, a 1 MiB-plus stream
across cold mount, directed chunk/proof reads, whole verification, required
content/proof corruption, expected-root mismatch, abandonment, cancellation
after a durable staging write, complete mutation-boundary fault injection, and
deduplication. The deduplication case produced two fresh independently
revocable object roots over one physical Blob; its powered-off image was parsed
as two Object mappings, one Blob mapping, and one deduplicated reference by the
independent verifier.

The same run retained all 8 M7.3 crash-recovery integration tests. Thus the CAS
changes did not replace the existing format/put boundary fault matrix, capacity
classification, dense recovery-memory ceiling, orphan handling, or powered-off
M7.3 reconstruction gate.

The standalone CAS verifier selftest reported `ok` for six named cases:
`duplicate-object-same-blob`, `gap`, `overlap`, `noncanonical-split`,
`bad-reserved`, and `bad-tree`. Strict all-target Clippy for `blob-format` and
`segment-store` completed with warnings denied.

Commands used for the recorded host results:

```sh
cargo test -p vibeos-blob-format -p vibeos-segment-store --locked --offline
cargo clippy -p vibeos-segment-store -p vibeos-blob-format \
  --all-targets --locked --offline -- -D warnings
python3 -B scripts/verify-storage-v2-cas.py --selftest
```

The same pinned-toolchain run compiled `vibeos-segment-store` for the
`riscv64imac-unknown-none-elf` firmware target with only `core` and `alloc`:

```sh
RUSTC="$(rustup which --toolchain nightly-2026-08-01 rustc)" \
RUSTDOC="$(rustup which --toolchain nightly-2026-08-01 rustdoc)" \
rustup run nightly-2026-08-01 cargo check -p vibeos-segment-store \
  --target riscv64imac-unknown-none-elf -Zbuild-std=core,alloc --locked --offline
```

## M7.5 root-based GC and segment cleaning

Accepted on 2026-08-12. M7.5 adds the frozen `VIBEALC2` allocation map,
`VIBERST2` persistent roots, `VIBEREF1` typed edges, reference-codec admission,
fixed-capacity root/reader pins, low-live partial relocation, and the
G/G+1/G+2 retirement barrier. New formats reserve at least two cleaner
segments; historical reserve-one media remains readable but cannot enter GC.
A full-prefix M7.4-style image at `free == reserve` bootstraps its first root
policy inside the same G+1 relocation from exact same-runtime authorized
witnesses.

The focused store run passed 77 library tests, 8 streaming-CAS tests, 12
append/recovery tests, and 22 GC integration tests. The GC tests include both
ordinary and legacy-bootstrap mutation-boundary matrices over not-submitted,
ambiguous, visible-only, durable, and pending/cancelled effects. They also
cover G+1 recovery/resume, exact-zero old-seal readback, G+2 cold recovery,
fresh-generation reuse, partial-pointer preservation, acknowledged copied
payload and padding corruption, typed traversal, ObjectId high-water,
fault-domain pin cleanup, catalog-triggered foreground cleaning, stable cycles
larger than initial ordinary capacity, and exact memory-limit/one-byte-under
admission with no media mutation.

The independent GC verifier duplicates all closed payload layouts and partial
transition rules. Its selftest reports 123 mutation cases and covers legitimate
opaque and trusted-typed objects retained only by a runtime root at power loss.
The Rust ABI test
exports production-codec payloads and requires Python acceptance, then corrupts
the typed payload and requires fail-closed rejection. The powered-off raw-image
test additionally runs a real production partial GC through G+2, exports the
dense durable page image, and requires the independent parser to select and
validate allocation-v2, roots, CAS, manifests, every live Blob extent, and
canonical Blob bytes/root. Persistent reachability is reported separately from
nonpersistent runtime-retained objects, while the complete CAS Object-to-Blob
set and every trusted typed object's direct child identities remain closed; a
raw payload mutation is rejected.

The complete host gate and strict lint were:

```sh
cargo test -p vibeos-segment-store -p vibeos-segment-format \
  -p vibeos-blob-format --locked --offline
cargo clippy -p vibeos-segment-store -p vibeos-segment-format \
  -p vibeos-blob-format --all-targets --locked --offline -- -D warnings
python3 -B scripts/storage-v2-image.py --selftest
python3 -B scripts/verify-storage-v2-cas.py --selftest
python3 -B scripts/verify-storage-v2-gc.py --selftest
./scripts/qemu-test.sh store
```

The pinned-toolchain firmware build remained allocator-bounded and `no_std`:

```sh
RUSTC="$(rustup which --toolchain nightly-2026-08-01 rustc)" \
RUSTDOC="$(rustup which --toolchain nightly-2026-08-01 rustdoc)" \
rustup run nightly-2026-08-01 cargo check -p vibeos-segment-store \
  --target riscv64imac-unknown-none-elf -Zbuild-std=core,alloc --locked --offline
```

The QEMU `store` case remains the M4 compatibility backend until M7.7; M7.5's
scalable media gate is the production Rust raw-image/Python verifier above.

## M7.6 online growth, quotas, and scrub

Accepted on 2026-08-12. M7.6 adds a distinct attenuable `StoreMaintenance`
resource, session-bound adjacent-range growth, boot-runtime storage principals,
pre-I/O logical and attributable-physical reservations, and read-only bounded
scrub. Maintenance invocations hold a counted lease for their whole async
operation; global revocation returns `OperationsInFlight` while a lease exists
and permanently rejects every prior token once it succeeds. Growth records the
enlarged allocation map in generation G+1 before the suffix becomes allocatable
and rechecks the exact device session, immutable geometry, read-only state, and
range capability before mutation.

The governed write path charges every Object the frozen canonical envelope even
on a dedup hit, reports cumulative unique bytes and dedup savings separately,
and excludes cleaner reserve plus root-policy headroom from admission. Quota
authority remains boot-local: persistent publication is blocked by a
target-type-bound publication token, while owner-scoped runtime pins retain the
charge inside the pin registry so synchronous fault cleanup releases forgotten
guards without leaking roots or quota.

Scrub independently rereads both anchors and checkpoint pairs, validates every
Allocated and Retired segment extent payload SHA-256 and zero padding, closes
both directions of the Object/Blob mapping relation, reconstructs every
canonical Blob, and parses every policy-admitted typed object including
runtime-only entries. It returns only the closed anonymous report schema and
performs no repair or capability publication.

The complete host run passed 11 canonical Blob tests, 6 streaming-Blob tests,
29 segment-format tests, 119 segment-store library tests, 44 segment-store
integration tests, and 12 storage-device contract tests. The store library set
includes exact/one-byte-under growth-memory admission, every grow mutation
boundary, real-device geometry/session/read-only drift, quota reserve isolation,
dedup and rollback, maintenance revocation concurrency, leaked-pin fault
cleanup, publication-persistence sealing, and ten scrub scenarios. Strict
all-target Clippy completed with warnings denied.

The four independent verifier selftests reported 22 base-image cases, 6 CAS
cases, 123 GC mutation cases, and 32 maintenance/growth cases. A production Rust
growth test exported its powered-off image and required the maintenance verifier
to accept the enlarged generation and anonymous schema. The retained QEMU M4
compatibility gate verified its 512-record chain, both objects, raw backing
journal, and negative parity fixtures.

Commands used for the recorded results:

```sh
cargo test -p vibeos-storage-device -p vibeos-segment-format \
  -p vibeos-blob-format -p vibeos-segment-store --locked --offline --no-fail-fast
cargo clippy -p vibeos-segment-store -p vibeos-storage-device \
  -p vibeos-segment-format -p vibeos-blob-format \
  --all-targets --locked --offline -- -D warnings
python3 -B scripts/storage-v2-image.py --selftest
python3 -B scripts/verify-storage-v2-cas.py --selftest
python3 -B scripts/verify-storage-v2-gc.py --selftest
python3 -B scripts/verify-storage-v2-maintenance.py --selftest
./scripts/qemu-test.sh store
```

The pinned firmware toolchain also compiled the complete store with only
`core` and `alloc`:

```sh
RUSTC="$(rustup which --toolchain nightly-2026-08-01 rustc)" \
RUSTDOC="$(rustup which --toolchain nightly-2026-08-01 rustdoc)" \
rustup run nightly-2026-08-01 cargo check -p vibeos-segment-store \
  --target riscv64imac-unknown-none-elf -Zbuild-std=core,alloc --locked --offline
```

## M7.7 migration and default cutover

Accepted on 2026-08-13. M7.7 installs one fail-closed object-store facade over
the frozen M4 reader and Storage V2, persists the exact externally admitted
authority and principal quota state as `VIBEAUT2`, and switches program,
persistent-CSpace, sealed-singleton, and ordinary object recovery together. A
Pending, corrupt, or ambiguous selector cannot fall through to M4. Migration
freezes and drains the logical M4 facade, revokes its private physical writer,
and retains only a sibling read capability for the rollback release.

The selector matrix covers Freeze, Stage, Activate, Rollback, and Close, each at
all six write/flush mutation boundaries with three failure effects and three
cancellation effects. All 180 interrupted transitions recovered the preceding
record or the exact successor. Native format and empty-authority import have
separate every-boundary failure/cancel matrices; generation-1 Closed control
publication has a separate every-boundary failure matrix. The
persistent-authority suite also covers exact stable/V2 bindings,
quota reconstruction and atomic rejection, delayed grants, singleton
replacement, byte-exact anonymous adoption, and foreground GC at the minimum
eight-segment geometry. The complete `segment-store` run passed 151 library
tests plus 45 integration tests.

The Rust-independent migration verifier selftest passed 24,588 mutation and
negative cases. It understands the production allocation-v1 to allocation-v2
fallback transition without weakening either decoder, independently recovers
both retained checkpoints, reconstructs every CAS byte and Blob root, validates
the exact authority/quota binding set and external policy, and rejects writes
outside the fixed ranges. Native mode additionally proves fixed UUID,
generation-1 `RollbackClosed`, activation floor 2, the canonical empty authority
commitment, strict subsequent logical history, and an all-zero M4 range.

One 64 MiB QEMU raw image completed seven powered-off boots:

| boot | observed durable result |
|---:|---|
| 1 | final writable M4 publication; capture exact rollback baseline |
| 2 | `V2Staged` generation 2 |
| 3 | explicit rollback to `FrozenM4` generation 3 |
| 4 | explicit re-stage to `V2Staged` generation 4 |
| 5 | explicit activation to `V2Active` generation 5 |
| 6 | explicit close to `RollbackClosed` generation 6 |
| 7 | Closed reboot; program/CSpace/store/Blob recovery and two terminal transition refusals |

After every boot the harness compared `[0,64)` and frozen `[64,576)` byte for
byte and independently verified the exact selector state and generation on the
powered-off image. A separate genuinely blank image completed two native V2
boots. It initialized directly to generation-1 Closed, preserved an all-zero M4
range, recovered the saved program and persistent CSpace, and completed ordinary
store and Blob writes after reboot. The saved-program recovery path remains
staged until both durable graphs are installed and the coordinator atomically
activates dependents; concurrent pre-activation waiters and failure races are
covered by host tests.

The Milk-V policy and image scripts now agree on a 131,072-sector (64 MiB) data
partition at physical LBA 262145. A local SDK package and two independent image
verifier runs accepted a 201,327,104-byte image with partition 1 `[1,262145)` and
partition 2 `[262145,393217)`. A complete scan proved the raw partition was zero
except for the canonical logical-sector-7 seed. The verified local artifact is
ignored build output, not repository source; physical boot remains a manual
hardware acceptance step. CI independently tests both QEMU and Milk-V policy
features, while the verifier selftest corrupts the prefix, seed/padding, suffix,
last byte, old 4 MiB geometry, and truncation.

Reproduction commands:

```sh
cargo test --workspace --exclude vibeos-kernel \
  --exclude vibeos-firmware-qemu-virt \
  --exclude vibeos-firmware-milkv-duo --locked --offline --no-fail-fast
cargo clippy -p vibeos-segment-store -p vibeos-object-store \
  -p vibeos-program-store --all-targets --no-deps --locked --offline -- -D warnings
python3 -B scripts/storage-v2-image.py --selftest
python3 -B scripts/verify-storage-v2-cas.py --selftest
python3 -B scripts/verify-storage-v2-gc.py --selftest
python3 -B scripts/verify-storage-v2-maintenance.py --selftest
python3 -B scripts/verify-storage-v2-migration.py --selftest
./scripts/verify-milkv-duo-image.sh --selftest
./scripts/qemu-test.sh storage_v2
./scripts/qemu-test.sh storage_v2_native
./scripts/build-milkv-duo.sh
```
