# Capability-backed directory handles

uv_fs_opendir/readdir/closedir now own a stable sorted enumeration and canonical
virtual path plus inode identity. Each read revalidates the granted root's READ
authority and identity before copying entries. Closing releases the snapshot
even after permission revocation. No ambient host directory API is used.

QEMU verifies file/directory/symlink types, incremental cursor, EOF, request
cleanup, copied async open path, deferred open/read/close callbacks, queued
read/close cancellation, unchanged cursor after cancellation, root escape and
file-as-directory rejection. Replacing a directory at its original path is
refused without modifying output. A retained handle fails reads after grant
revocation and still closes successfully. Cumulative V8/libuv tests pass with
114 parks, zero waiters, normal shutdown and 305733248-byte allocator peak.

Like upstream libuv, callers must serialize directory operations and clean
readdir requests before changing the output array or closing the directory.
Enumeration is a snapshot: post-open additions are not included. Rename/removal
fails closed instead of preserving a POSIX open inode view. Concurrent mutation,
revocation between readiness and callback delivery, allocation failure injection,
and abandoned-handle reclamation across Node teardown are not qualified here.
The first firmware build was replaced before QEMU execution because its test
fixture left temporary entries that would affect existing root-count assertions;
the recorded second build removes them before continuing cumulative tests.

This is a libuv prerequisite. Node and TypeScript have not executed.
