# Native task identity ABI prerequisite

The recorded RV64GC kernel passed four-hart QEMU execution. Two native TLS
contexts have distinct positive IDs. The C++ fixture reads the C ABI and
retains its first result in real compiler-generated TLS, rejecting nonpositive
or changed values on subsequent entry/resume. The same fixture executes across
three executor parking intervals. Existing page, RAII, destructor and VSH
checks also passed. Exact kernel/source hashes and logs are attached.

This validates stable execution-context identity, not V8 thread creation,
Node workers, cross-hart native task migration, or ID-space exhaustion.
The bridge does not return a hart ID or pointer. V8/Node execution acceptance
remains open.
