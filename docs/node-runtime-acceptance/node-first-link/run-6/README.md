# Sixth Node firmware link

Upstream --without-sqlite removes the optional SQLite dependency from the
VibeOS toolchain build. libnode build 20 succeeds, and the real firmware link
now reports 118 missing libuv symbols, with no SQLite/session symbols remaining.
All 75 resolved names are recorded. This is genuine upstream feature selection,
not replacement implementations of SQLite entry points. node:sqlite and
SQLite-backed Web Storage are unavailable in this build; their exact runtime
error behavior remains unqualified until Node executes.

The source/archive input hashes and full diagnostics are retained. The Node
firmware still does not link, so no Node runtime milestone is established.
