# Node JavaScript executes; final output marker is lost

With a private project FileGrant, Node executes the inline JavaScript checks,
Buffer/Promise/timer callback and asynchronous gzip/gunzip roundtrip. The entry
returns zero after normal destruction, with two parks and zero waiters. The
verifier remains failed because Node FreeEnvironment closes its standard stream
handles before the final C puts teardown marker. This failed assertion is kept;
it is not relabelled as a pass. A test-only kernel probe will report completion
after normal Node/V8 teardown without reopening or bypassing user stdio.
