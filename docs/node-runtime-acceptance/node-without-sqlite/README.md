# Upstream optional SQLite exclusion

The reproducible configure command now includes --without-sqlite, and its
validator requires node_use_sqlite=false. SQLite is not used by the requested
offline TypeScript/tsx toolchain. The supported port scope explicitly excludes
node:sqlite and SQLite-backed Web Storage; neither is substituted by a fake
implementation. Runtime error qualification is still pending.

The incremental target libnode archive rebuild succeeds in 75.42 seconds. A
fresh verified source extraction accepts all 46 patches with zero fuzz, configures
with HAVE_SQLITE=0 and successfully builds the real libuv target from current
overlays. Prepared-input checksums, configure evidence and build logs are saved.
This verifies fresh preparation/configuration/libuv, not a full fresh Node/V8
rebuild. The subsequent actual Node firmware link has 118 unresolved libuv names
and no SQLite names (see ../node-first-link/run-6). No Node QEMU run occurred.
