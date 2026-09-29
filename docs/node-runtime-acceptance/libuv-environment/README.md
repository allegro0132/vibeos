# Invocation-owned environment

NativeTls owns a bounded environment initialized empty. Trusted launcher setup
replaces it atomically with explicitly supplied entries before activation; no
host or kernel environment is imported. Limits are 64 entries, 255-byte names,
4096-byte values and 65536 total name/value bytes including terminators. Invalid
names, embedded NUL and over-limit updates are rejected before publication.
The single active native context owns borrowed getenv pointers until replacement,
unset or normal teardown. Enumeration allocates independent snapshots.

uv_os_getenv/setenv/unsetenv/environ and newlib getenv/setenv/unsetenv (including
reentrant entrypoints) share this state. Upstream uv_os_free_environ releases
snapshots. Environment mutation confers no filesystem/process authority.

QEMU passes an explicitly seeded value, absent previous-invocation mutation,
libuv/newlib interoperability, overwrite=false, short-buffer preservation,
snapshot independence, empty values, invalid names, oversized names/values,
entry-count limit with replacement at capacity, aggregate size limit and empty
enumeration after deletion. A separate earlier native context starts with zero
entries, stores a private value and exits; the V8 context cannot see that value.
Cumulative V8/libuv checks pass with 83 parks, zero waiters, normal shutdown,
305733248-byte allocator peak and unchanged 36162176-byte post-run live memory.

Full Node process.env behavior has not executed. Direct raw environ/putenv,
process-global newlib timezone caches and 100-invocation lifecycle stress remain
unqualified. The current launcher hook is used by the target fixture; VSH/SSH
invocation setup and separate tool-root capabilities remain outstanding.

Fresh preparation applies all 51 patches with zero fuzz; pinned configuration
and libuv build pass in native-qualified-13. Their reports are in fresh-build.
The existing host libc contract test also passes, with renamed getenv/setenv
wrappers so it does not interpose on the host runtime; its reentrant errno
checks use an injected minimal structure and are not target ABI evidence.
