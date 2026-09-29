# Fourth Node firmware link

Linking still fails with 198 unresolved symbols: 123 libuv APIs and
75 SQLite/session APIs. Since run 3, 8 names are resolved by
QEMU-qualified clock, access, readlink, unlink and cancellation implementations.
See resolved-since-run-3.json for exact names. Source/archive identities and the
complete linker diagnostics are retained here. No Node code has executed; the
Node runtime milestone and TypeScript toolchain acceptance remain pending.
