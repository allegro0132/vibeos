Third real Node firmware link still FAILS, now with 206 missing symbols:
131 libuv APIs and 75 SQLite/session APIs. All 63 uvwasi references disappear
through the explicit unsupported Node WASI boundary; the independent esbuild
WASI service is unchanged. Nineteen libuv synchronization APIs and all three
newlib references disappear through the target-qualified implementations.
Input archives, thin members, probe source and extra objects were unchanged
while linking. No unresolved symbol outside libuv/SQLite is reported in this
attempt. This is diagnostic progress, not Node execution acceptance.

The Node probe now also requires the unsupported WASI error. None of its JS
checks has run because firmware linking is incomplete. Remaining libuv APIs
must receive real capability/scheduler integration where supported, and clear
unsupported-operation errors elsewhere. SQLite support is not yet provided.
