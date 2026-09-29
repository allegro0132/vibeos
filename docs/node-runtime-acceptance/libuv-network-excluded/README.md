# Explicit Node network-capability boundary

This first Node invocation model grants files and standard streams, not socket
capabilities. The backend therefore returns ENOTSUP for TCP/UDP initialization,
import, bind/connect, send/receive, membership/options, address queries, listen
and accept. All 32 supplied platform entry points return failure without
mutating handle, request or output storage. Pure upstream IP conversion remains
available. These exclusions are scoped to Node/libuv and do not change VibeOS
network services or the authorized SSH/VSH path.

QEMU exercises all 32 entry points with dummy handles/requests, checks ENOTSUP,
unchanged storage and address length, zero active loop work and clean close.
The cumulative real V8/libuv gate passes with 68 parks, zero waiters, normal
shutdown and allocator peak 305729152 bytes.

Node TCP/UDP constructors CHECK successful libuv init, so patch 49 throws
ERR_VIBEOS_UNSUPPORTED before constructing those objects. Their target sources
compile into libnode, and the patch applies without fuzz to an independently
prepared source tree. The Node probe includes net.connect/dgram creation
rejection assertions, but those JS checks have NOT executed. This is network
boundary evidence, not Node startup or full toolchain acceptance.
