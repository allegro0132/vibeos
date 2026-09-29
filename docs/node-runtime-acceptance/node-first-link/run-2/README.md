The genuine histogram, zlib, llhttp, nghttp2, ada, merve, simdjson,
brotli, zstd and nbytes target archives now build successfully. Zstd uses its
upstream single-threaded mode on VibeOS. Generated zstd and Node makefiles
contain no ZSTD_MULTITHREAD definition. Patches 41–42 apply with zero fuzz.
The Node gate now also compiles/links upstream node_snapshot_stub.cc, as Node's
own no-snapshot embedder does. No invented snapshot symbol implementation.

The second firmware link still FAILS: unresolved symbols decrease from 500 to
291. Remaining: 150 libuv APIs, 75 SQLite/session APIs, 63 uvwasi APIs, and
newlib _link/_stat/sleep. Input archive/member and added-object hashes remain
unchanged throughout linking. Node has NOT executed; the probe is not qualified.
The build script adds a reproducible node-deps phase for the ten libraries.
Node WASI (with V8 WebAssembly disabled) is distinct from the existing VibeOS
WASI execution service used by esbuild; that service must remain functional.
