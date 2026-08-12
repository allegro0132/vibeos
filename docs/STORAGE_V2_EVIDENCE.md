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
