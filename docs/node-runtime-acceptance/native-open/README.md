# Capability-native read-only files

QEMU RV64GC/LP64D, four harts, 128 MiB: PASS. The fixture creates a real 5000-byte
file in the in-device file tree and enters the protected native runner with an
explicit root capability. It verifies open, regular-file kind and size, byte
contents, reads crossing the 4096-byte content boundary, seek/invalid seek,
EOF, write rejection, close, stale-fd rejection, non-reused descriptor numbers,
and read/size/seek rejection after capability revocation. Denied read leaves
caller storage unchanged. All prior native prerequisites also pass.

The per-context table holds at most 64 open files. Read transfers are bounded
to 1024 bytes and stage backend data before copying to native storage, with
fresh READ admission and a second lease before delivery. No RefCell or CSpace
lock is held across the parked future. Close works after revocation. Dropping
the context releases remaining table entries, but repeated-run accounting has
not been qualified. Seek reads currently scan chunks from the start; there is
no index/cache optimization claim.

This first path is read-only and snapshot-based. Write/create/truncate flags
return ENOTSUP; symlinks are rejected by regular_reader. Live concurrent-file
mutation semantics, writable files, directories, symlinks/realpath, tool mounts,
per-invocation byte quotas, durable-device IO and 100-run lifecycle remain
pending. It is not full Node filesystem compatibility.

Target newlib adapter compilation and mock errno/metadata tests pass. The QEMU
fixture invokes Rust C ABI entries directly; actual newlib FILE operations and
V8/Node execution are not established by this result. M1 remains incomplete.
