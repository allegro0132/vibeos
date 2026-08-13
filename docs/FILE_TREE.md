# Capability-rooted file tree

`file-tree` is an opt-in VSH profile. It supplies Linux-shaped file commands
without adding Linux ambient authority.

## Authority and syntax

`@NAME/path` consists of two different things: `@NAME` is a literal capability
binding and `path` is a relative selector inside it. The lexer records these as
separate fields. Quotes and `$values` are accepted only in the selector:

```text
@home
@home/etc/config
@home/"file with spaces"
@home/$relative
```

`let x @home/a; cat $x` cannot work: `$x` is a value and expansion is never
reparsed as authority. Bare paths, `/`, `~`, cwd, globbing and `PATH` lookup do
not exist. Admission resolves every root, checks resource kind and rights, and
delegates an attenuated cap before any pipeline stage starts. A stage never
receives `GRANT` or `REVOKE`.

Selectors are UTF-8, at most 4096 bytes and 64 components; a component is at
most 255 bytes. Empty components and `.` normalize away. `..` cannot cross the
capability root. NUL, C0 controls, DEL, `/`, and stored `.`/`..` names are
rejected. Symlinks store only root-internal relative selectors and resolution
is bounded to 40 links.

## Namespace semantics

The service publishes immutable namespace versions. `begin()` pins a generation,
applies at most 4096 inode/dirent edits to private state, and `commit()` performs
a generation compare/exchange. Dropping or cancelling an uncommitted transaction
leaves the published version unchanged. Readers pin an `FsSnapshotLease`, so an
old version remains readable after a later commit.

`FileId` is namespace-local, non-zero, monotonic and never an input to lookup.
Regular files and symlinks may be hard-linked; directories may not. Directory
link count is `2 + direct child directories`; other link counts are the actual
number of dirents. Metadata deliberately contains only type, size, link count,
FileId and change generation—no invented uid/gid, mode or timestamps.

The feature currently installs `ls`, `stat`, `cat`, `write`, `mkdir`, `rm`,
`cp`, `mv`, `ln`, and `readlink`. Mutating multi-path commands validate a single
destination namespace and use one transaction. `mv` and hard `ln` reject
cross-namespace operands; `cp` may stream/clone from read-only source snapshots
into one writable destination namespace.

The local kernel profile binds RW `@home` only when the `file-tree` feature is
explicitly selected. Its VSH task waits for the boot probe to select and prove
Storage V2, cold-recovers the single policy-fixed namespace, and creates an
empty generation-zero tree only when that namespace has no persistent root.
Shared/SSH command installation does not bind a file root.

Unknown-length `write` input is split into 4 KiB `FsDataV1` nodes as it arrives.
Each immutable node carries a bounded binary-lifting ancestor table, so staging
retains one chunk and at most 64 opaque references independent of file size;
an inode publishes only the final node. Cancellation leaves those nodes
unreachable, while a successful command publishes data, COW namespace nodes,
and the new root through one persistent-root compare/exchange.

## Powered-off verification

The independent host verifier understands both legacy `VIBEAUT2` v1 snapshots
and v2 snapshots containing opaque service roots. For a file-tree image it
must be run while QEMU is stopped:

```sh
python3 -B scripts/verify-storage-v2-migration.py \
  --expect-native --expect-file-tree \
  --unmanaged-prefix-baseline target/file-tree-prefix.baseline \
  target/file-tree.raw
```

Besides the Storage V2 checkpoint, allocation, CAS, Blob, and authority
invariants, `--expect-file-tree` requires exactly one external `FsRootV1` and
walks its typed closure. It independently checks canonical B+tree ordering and
levels, inode/dirent structure, FileId bounds, link counts, directory acyclicity,
data skip edges, reconstructed file sizes, and UTF-8 relative symlink targets.
Unreachable transaction objects are not authority and may remain until GC.
