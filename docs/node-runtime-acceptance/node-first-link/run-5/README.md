# Fifth Node firmware link

The actual Node firmware link still fails: 193 unresolved names,
118 libuv and 75 SQLite/session APIs. Since run 4, the
QEMU-qualified scandir/mkdir/rmdir/rename/ftruncate implementations resolve
5 names. Existing write/open symbols now provide additional implemented
behavior but do not reduce the missing-name count. Exact resolved names,
archive identities and full diagnostics are retained. Node execution and the
TypeScript toolchain have not run successfully; this is diagnostic evidence,
not milestone completion.
