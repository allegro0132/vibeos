# Owned asynchronous regular-file reads

The native read-begin operation admits the descriptor under READ authority and
captures its identity, position and current content snapshot. A bounded pending
read table owns the backend future and retained admission lease. The future
contains no caller output pointer. Libuv polls it through the existing request
queue and native notification waker; no synchronous native park runs inside
this async file operation. Delivery obtains a fresh READ lease before polling
or copying bytes; denial consumes and drops the request without changing caller
memory or the descriptor cursor. Successful delivery advances the cursor.

QEMU passes deferred three-byte delivery, EOF completion, queued cancellation
with preserved buffer/cursor, a too-small native delivery buffer followed by a
successful retry, and stale request-ID rejection. It also begins a read before
capability revocation, then verifies delivery is denied, output untouched, and
the request consumed. Invocation teardown checks no read future remains.
All cumulative V8/libuv checks pass: 64 parks, zero waiters, normal shutdown,
allocator peak 305729152 bytes.

The fixture uses volatile content; delayed persistent reads, event-loop timer
progress during storage latency, concurrent same-descriptor cursor operations,
positioned/vector IO and unlink-while-open remain unqualified. Async open with
create/truncate and complete Node/TypeScript execution are still pending. No
new runtime milestone is established here.
