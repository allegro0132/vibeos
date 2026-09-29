# Explicit unsupported process, watch and host signal APIs

The libuv backend returns ENOTSUP for child process spawning/signalling, file
event watching, file polling and host signal subscriptions. Invalid required
pointers return EINVAL. Failure admits no handle/request, invokes no callback,
alters no output buffer and performs no platform operation. The upstream
fs_event_getpath helper is retained; the new backend supplies only missing
platform entry points.

QEMU calls 14 excluded APIs and checks all error returns, zeroed handle storage,
unchanged getpath output and size, no callbacks, no active loop work, and clean
loop close. Cumulative V8/libuv gates pass: 63 parks, zero waiters, normal
shutdown and allocator peak 305728128 bytes.

Node signal/stat-watcher constructors otherwise CHECK that libuv initialization
succeeds, and its process wrapper marks a failed spawn initialized. Patch 48
therefore throws ERR_VIBEOS_UNSUPPORTED before these native objects are created.
All three files compile into target libnode build 21. The embedding probe now
asserts these JS errors, but it has NOT executed; QEMU evidence here covers only
the libuv layer. Patch 47/48 dry-runs apply without fuzz to a separately prepared
46-patch source tree. These exclusions do not implement native JS cancellation,
and no Node runtime milestone is claimed.
