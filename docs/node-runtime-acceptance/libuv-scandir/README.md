# Capability-rooted directory scanning

uv_fs_scandir now enumerates a retained file-tree snapshot admitted by a fresh
READ lease. Entries arrive in the file store's bytewise name order; the C bridge
copies each name and type into owned records. The final path may follow a link,
but listed symlinks retain their own type. Deferred requests use the existing
loop queue, with no worker thread or ambient filesystem directory handle.
Upstream uv_fs_scandir_next performs iteration and frees consumed records;
cleanup handles partial iteration and repeated cleanup without double frees.
System malloc/free match the upstream iterator's allocator contract.

QEMU passes sorted file/directory/link enumeration, repeated EOF, partial and
complete cleanup, non-directory and missing-path errors, escape denial, invalid
flags, one deferred callback, and refusal after capability revocation. All
previous V8/libuv gates pass; 38 parks, zero waiters, normal shutdown, allocator
peak 305727104 bytes. The first archive build's missing stdlib.h failure is
preserved; the corrected second build succeeds.

Large and empty directories, allocation-failure injection, concurrent mutation,
and complete Node/TypeScript directory consumption remain unqualified. This is
a prerequisite implementation and does not establish the Node milestone.
