# Real Node standard input and EOF

The private gate's granted input pipe receives two delayed writes (7 and 8
bytes). A UTF-8 character's byte sequence spans the writes. Node's actual
process.stdin uses setEncoding('utf8'), collects data events and must receive
exactly the expected decoded text and EOF before its completion flag is set.
Pipe transport may coalesce writes; this is not an assertion about data-event
packet boundaries. The producer joins before final waiter accounting.

The real Node image passes the new stdin marker and all prior project CJS/ESM,
dynamic import, synchronous/Promise file IO, metadata/error boundaries, Buffer,
Promise/timer and asynchronous zlib checks. Node normal teardown completes;
return code is zero, parks 13, waiters zero, and QEMU shuts down normally.
Shared allocator accounting: live before 776064, live after 36161664, peak
305743744 bytes. These figures are not process RSS or repeated-instance leak
qualification. Output and diagnostic channels drain independently.

This closes the stdin/EOF gap in the preliminary embedding gate. Nonzero exit,
cancellation, production VSH/SSH commands, repeated lifecycle and the complete
TypeScript/tsx toolchain remain pending; M2 is not yet complete.
