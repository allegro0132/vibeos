# Capability-backed symlink target reads

The native readlink bridge requires a fresh READ lease, resolves the requested
path inside the invocation root without following its final symlink, and copies
the stored target from a retained snapshot. It preserves the destination on
insufficient capacity and appends a NUL on success. Reading a target string does
not grant access to the path it names. Libuv supports synchronous and deferred
asynchronous requests and frees target storage in uv_fs_req_cleanup.

QEMU verifies a self-referential link returns its literal target, ordinary files
return EINVAL, an escaped input path returns EACCES, a short buffer remains
unchanged, a deferred callback sees ../main.js, and revocation denies subsequent
access. Existing V8, file deletion/cancellation, synchronization, clocks and
stdio tests still pass: 36 parks, zero waiters, normal QEMU shutdown.

Long targets, Unicode target fixtures, cancellation specifically of readlink,
and full Node module resolution remain unqualified. No Node execution milestone
is established by this prerequisite.
