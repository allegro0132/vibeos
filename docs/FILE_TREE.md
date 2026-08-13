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
explicitly selected. Shared/SSH command installation does not bind a file root.
The current binding is volatile; Storage V2 persistent-root publication and
power-cut recovery remain the gate before enabling this feature by default.
