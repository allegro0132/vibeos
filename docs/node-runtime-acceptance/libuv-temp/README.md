# Capability-backed temporary files and directories

uv_fs_mkstemp/mkdtemp require a trailing XXXXXX template and copy its path into
the request. Six bytes from the invocation's granted entropy service select
six unbiased URL-safe base64 characters. Creation is exclusive: files use
O_RDWR|O_CREAT|O_EXCL; directories use the FileTreeRoot transaction's non-parents
mkdir, which rejects an existing entry. At most 128 collisions are retried;
other errors stop immediately. Failure restores the template suffix. Capability
rights govern access; this does not introduce Unix mode-bit permissions.

Synchronous creation parks native frames while awaiting entropy and authoritative
publication. Asynchronous requests are deferred but execute this same parked
operation from native-stack completion dispatch. Readiness polling only marks
them ready, never invokes their parking code from the Rust executor stack.
Queued cancellation calls back with ECANCELED and does not consume entropy or
mutate the filesystem. Started operations cannot be force-unwound.

QEMU verifies sync/async file and directory creation, copied input templates,
unique paths, returned descriptor writes, reopening and byte-exact readback of
the original file after a second creation, directory type, invalid templates,
root escape refusal, cancelled request generation stability, cleanup and both
operations' permission-revocation refusal. Real V8/cumulative libuv tests pass:
142 parks, zero waiters, normal shutdown and 305733376-byte allocator peak.

The recorded second firmware build adds byte-exact readback before QEMU;
the first build was not executed. Forced entropy failure/collision exhaustion,
revocation during publication and physical durable-storage failure injection
remain unqualified. Complete Node/TypeScript execution remains pending.
