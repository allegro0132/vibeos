# Directory-bounded immutable file snapshots

FsSnapshotLease::directory pins a directory inode as the starting namespace
for every path lookup, canonical path, link read, directory listing and file
content read in the returned snapshot. Relative symlink expansion restarts
at this boundary, so an intermediate or final link cannot traverse above it.
Nested directory views narrow the boundary again. The underlying namespace
version remains pinned; replacing its directory path does not substitute new
content into an existing snapshot.

copy_from resolves both the selected source and recursively followed links
under the source snapshot's boundary. A failed traversal is not committed by
the tested transaction caller. Snapshot creation grants no mutation authority,
and callers must still revalidate capability authority for later operations.

Host tests: 34 passed, 5 ignored. Tests include allowed internal links, parent
escapes, chained/intermediate escapes, nested boundaries, hidden parent names,
relative canonical paths, link inspection without following, immutable identity
after replacement, and copying from a bounded source. The initial test tried
to create an absolute link, which is already rejected by the existing API; the
corrected test asserts that rejection instead. Both test logs are retained.

This is the read/snapshot foundation for --root @home/project. It is not yet
a live writable subtree capability or a Node/VSH launcher confinement claim.
Transaction scoping, inode-based mutation admission and production wiring
still need implementation and target adversarial qualification.

The ordinary Node main-file QEMU regression also passes after the shared
resolver change: CJS/ESM, files, stdin, async work, normal exit 0 and teardown
with zero waiters. This gate still grants the whole fixture tree; it does not
execute a Node invocation rooted in the new subdirectory view.
