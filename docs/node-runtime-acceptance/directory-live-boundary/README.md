# Live directory views and bounded transactions

FileTreeRoot::directory shares namespace state, writer admission and durable
backend with its parent while retaining one directory identity as its boundary.
Snapshots, path readers, inode readers, content staging and new transactions
resolve against that boundary. Directory replacement does not silently retarget
an existing view. A missing view root denies a new transaction.

FsTransaction::into_directory consumes an unmodified transaction and narrows
its boundary. Prior edits are rejected and discarded. Path mutations resolve
inside that boundary; writes/truncations by inode ID also require a real entry
in its subtree, without following symlinks. Existing hard links retain their
normal shared-inode semantics. Copy source and destination boundaries remain
independent. Publication commits the shared namespace through its existing
authoritative transaction mechanism, not a detached project copy.

Host suite: 37 passed, 5 ignored. Added checks cover path escape mutations,
outside inode write/truncate denial, protected root removal, nested mkdir,
renamed inode updates, prior-edit rejection, repeated narrowing, live visibility
of parent/view commits, and denial after root removal/replacement.

The QEMU fixture now grants a live project subdirectory with a protected sibling
and an outward symlink. Run 1 passes actual Node main-file execution with return 0, parks=196 and
zero waiters. JavaScript observes no sibling file and EACCES on escaping-link
read, write and realpath. The kernel independently verifies the protected
sibling bytes after Node teardown. Previous CJS/ESM, file/stream and async
runtime checks also pass. A subsequent change rejects content-stager admission
when a live view root was removed, before consulting or allocating backend
staging state; host tests cover that refusal.
This is not yet the production VSH node launcher or a derived-capability
revocation qualification; the fixture explicitly mints its directory-view cap.

Run 2 requalifies the final changes on QEMU, including all Node subtree and
prior runtime checks. Host tests additionally preserve ancestor-copy rejection
when the independently granted source snapshot is broader than the destination
view. The verifier now records storage.rs alongside the shared resolver sources.
