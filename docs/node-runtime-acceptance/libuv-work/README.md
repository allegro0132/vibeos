# Serialized native work queue

uv_queue_work now registers requests in a loop-owned queue separate from file
requests. It never starts a thread. uv_run processes at most one CPU job per
iteration on the protected native stack, then gives filesystem/timer/stream
phases a turn. Readiness predicates inspect queue presence without invoking work
callbacks from Rust executor polls. Work completion unregisters before its
callback, permitting request release or resubmission. Missing after callbacks
are supported. Queued cancellation delivers ECANCELED without executing work;
started/completed/already-cancelled requests report EBUSY.

This is deliberately serial within the native invocation. A long synchronous
C/C++ work callback delays that invocation's event loop until it returns or
parks through the native bridge. Cancellation does not unwind a running native
callback. There is no general worker pool or background user execution.

QEMU covers deferred callbacks, one-job NOWAIT progress, three executions with
two completion-driven resubmissions, queued cancellation, busy self-cancel and
loop-close refusal, no-after completion, callback-owned free, coexisting async
filesystem completion and repeating timers. Work sleeps through the native
bridge and verifies stable invocation identity. Cumulative real-V8/libuv tests
pass with 122 parks, zero waiters and 305733376-byte allocator peak.

A prospective Node asynchronous gzip/gunzip roundtrip test is added to exercise
actual ThreadPoolWork users; it has not executed. Complete Node, TypeScript and
running-native-code cancellation qualification remain pending.
