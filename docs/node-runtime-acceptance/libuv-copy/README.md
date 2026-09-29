# Atomic capability-rooted regular-file copies

Copy uses a READ|WRITE root lease, a writer transaction and an immutable source
snapshot. Source links are followed; directories are refused. Existing target
links are resolved, preserving target inode/hard-link identity on overwrite.
Same-inode copies fail, exclusive copies reject any existing directory entry,
and all paths remain in the granted virtual root. Optional reflink falls back
to the service's immutable-content copy; forced storage reflink is unsupported.
Dangling destination symlink creation is explicitly unsupported. Publication
awaits commit_authoritative on the protected native stack; asynchronous calls
are deferred with the same safe parking boundary as temporary-file creation.

statfs validates path readability/existence then returns ENOTSUP: the file-tree
service has no block-device capacity accounting contract. No fake space values
are produced. Queued requests remain cancellable.

QEMU verifies copied bytes, independent subsequent writes, existing target
hard-link identity through a symlink, same-inode/exclusive/force/invalid/path
refusal, async copied paths, queued cancellation with unchanged generation,
cleanup and permission revocation. Real V8/cumulative libuv tests pass with
162 parks, zero waiters, normal shutdown and 305733376-byte allocator peak.
Durable-backend faults and in-publication revocation remain unqualified; this
is not complete Node or TypeScript acceptance.
