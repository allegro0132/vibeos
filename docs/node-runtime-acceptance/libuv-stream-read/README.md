# Event-loop standard-input reads

The pipe backend implements uv__read_start/uv_read_stop behind upstream
uv_read_start validation. Readiness polling uses an owned 1024-byte buffer,
never a user allocator or read callback. Loop completion allocates a caller
buffer, rechecks descriptor authority, copies at most its capacity and invokes
the read callback. Smaller buffers preserve the unread suffix. A stopped read
retains its cache for restart; close frees it. EOF stops the handle and clears
readability. Null/empty caller allocation yields ENOBUFS without losing data.
IPC remains excluded; the otherwise-unused queued_fds field owns read state.

QEMU receives a second delayed stdin payload after the original fs-read fixture.
The stream fixture verifies duplicate-start and invalid-callback rejection,
one ENOBUFS callback, a successful retry, a three-byte read followed by stop,
no callbacks while stopped, restart preserving the remaining nine bytes across
three further callbacks, exact content, one EOF, inactive state and clean close.
The cumulative V8/libuv gate passes with 74 parks, zero waiters, normal shutdown
and a 305729152-byte global allocator peak. Existing write, shutdown, filesystem,
capability and actual V8 expression/exception/GC checks also pass.

This does not qualify revocation races, allocator-callback stop/close reentrancy,
duplicate descriptor attachment or sustained invocation lifecycle. Read-ahead
must not be mixed with independent fs reads on the same descriptor without an
ownership rule. Full Node and TypeScript execution remain unaccepted.
