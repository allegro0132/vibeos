# First passing real Node embedding execution

The locked real Node/V8 image executes in QEMU RV64GC, JIT-less with a
single-threaded platform and explicit private project/std-stream/entropy grants.
The inline Node script verifies builtin module loading, Buffer, Promise/timer
completion, async gzip/gunzip, invocation identity/title, explicit home/hostname,
image identity and defined unsupported-operation errors (workers, IPC, networking,
child processes, signal/watch registration, Node WASI and unavailable statistics).
All scripted checks must complete for the native entry to return zero.

Normal Node environment/isolate/platform/process teardown completes and the
loop closes. A test-only kernel probe emits the teardown marker after destruction
because Node owns and closes its stdio endpoints. User output is then drained by
the enclosing firmware tasks; ordering across these separate diagnostic/output
channels is not a JavaScript execution order assertion. The gate returns zero
with two parks, zero waiters and normal QEMU shutdown. Allocator accounting:
live before 774144, live after 36160512, global peak 305731200 bytes. This is
shared-kernel allocator accounting, not process RSS. The trusted newlib arena
remains process-lifetime storage; zero leaks across repeated invocations is not
claimed. The verifier also checks Node initialization symbols and rejects W+X
or executable sections outside admitted text.

This is preliminary execution, NOT the full Node milestone. Project CJS/ESM and
dynamic import, Node file operations, stdin, exit/cancel behavior, repeated
lifecycle, production capability launcher/VSH integration and TypeScript/tsx
acceptance remain pending. Earlier failed execution reports remain unchanged.
