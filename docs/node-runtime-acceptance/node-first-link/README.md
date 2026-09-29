# First real Node embedding link attempt

The target-only node-smoke.cc entry uses real Node process initialization,
Node isolate settings, a cppgc heap, Node environment and LoadEnvironment.
It uses the already-qualified single-threaded V8 platform, with no Node worker
platform. The custom event loop is intended to check Buffer, Promise, timer
and normal environment teardown. It is a one-shot probe, not the VSH launcher.
Its target C++ compilation passed, but firmware linking FAILED with 500
unresolved symbols. Therefore none of its Node checks have executed.
The linked input archives/members were unchanged during the attempt.

Missing symbols include bundled Node dependencies not built by the libnode
archive target, 150 libuv APIs, newlib file/process helpers and the upstream
no-snapshot source. Full raw diagnostics and the machine-readable symbol list
are preserved. No linker stubs or host execution substitute are used.

The next action is to build genuine bundled libraries, integrate Node's
upstream no-snapshot source, and implement or explicitly reject platform APIs.
The existing V8-only QEMU verifier is not sufficient for this Node gate:
Node-specific markers and lifecycle/resource checks are still required.

Dependency attempts: build 1 used incorrect make aliases (libhistogram rather
than histogram). Build 2 reached nghttp2's Unix byte-order header dependency.
Patch 41 selects its existing portable byte-order functions for VibeOS rather
than supplying socket headers. Build 3 proceeds through parsers/compression
sources and next fails in zstd's enabled pthread worker pool. Select upstream
single-threaded zstd for the target before repeating the dependency build.
No build process remains running at this evidence checkpoint.
