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
8192-sector data partition.

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
