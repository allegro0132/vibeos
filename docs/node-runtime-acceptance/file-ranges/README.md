# Inode-addressed range write and truncate primitives

File-tree transactions now provide write_file_range and truncate_file for an
existing file ID within their own root. These methods retain inode identity and
hard links across rename, do not overwrite a replacement at the old name, zero
fill holes/extension, and publish only on explicit transaction commit. Callers
must enforce their root capability before obtaining the transaction/identity.
No ambient object lookup is introduced. Dropping an unpublished edit leaves
the existing generation intact.

Host tests: 31 passed, 5 existing ignored tests. Added checks cover hard-link
visibility, path reuse, pinned snapshots, aborted truncation, cross-chunk sparse
writes, shrinking/extension, zero-length writes, overflowing ranges and invalid
inode kinds. An initial test invocation omitted hard_link's follow argument;
that compile failure is retained alongside the corrected passing test log.

QEMU runs the new primitives directly in the file-tree fixture: rename and reuse
the original path, write at byte 4095 across a chunk boundary, check hole bytes
and unchanged replacement content, truncate then zero-extend, and retain the
old snapshot. The cumulative real V8/libuv gate passes with 45 parks, zero
waiters and normal shutdown; peak allocator usage is 305728128 bytes.

Native writable descriptors, libuv write-open and fs.write integration remain
pending. The new service routines currently materialize existing file content
before changing it; resource limits and efficient large-file staging still need
integration. Persistent-reader code paths, durable range-write publication and
unlinked-open inode lifetime are not qualified by this volatile fixture. This
is foundation evidence, not Node/TypeScript write support or a new milestone.
