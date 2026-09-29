# Worker-thread exclusion boundary

The single admitted native execution remains the only supported native thread.
uv_thread_create/create_ex/join/setname return ENOTSUP for valid arguments and
EINVAL for missing required pointers. Rejection does not initialize thread
identifiers, mutate options, invoke the thread entry or enqueue work.

Node Worker::New now throws ERR_VIBEOS_UNSUPPORTED before native Worker/message
port/isolate allocation. This applies to user and internal worker constructors;
thread-based custom ESM loaders are not supported by this path. The planned tsx
in-instance loading adaptation remains necessary. A prospective JavaScript
Worker test is present but has not executed. The libnode archive builds; patch
53 applies without fuzz to the locked unmodified source.

QEMU tests all four rejection APIs, unchanged identifier/options, invalid
pointers, zero entry invocations and stable native identity across a subsequent
sleep. Real V8 expressions/exceptions/GC and cumulative libuv tests pass with
118 parks, zero waiters, normal shutdown and 305733376-byte allocator peak.
These results do not establish Node JavaScript worker behavior, complete Node
execution, general worker-pool support or the TypeScript toolchain milestone.
