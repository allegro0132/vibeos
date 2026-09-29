# First real Node firmware execution: initialization failure

The Node image executes in QEMU and fails at CHECK(!internal::g_page_allocator)
in cppgc::InitializeProcess, reached from the Node embedding smoke entry. The
pinned V8::Initialize implementation already initializes cppgc when absent;
the test entry's extra explicit initialization is incorrect. No JavaScript
acceptance marker or normal teardown is produced. The raw trap is retained.

An earlier launcher attempt used the V8 artifact name instead of node-gate.elf
and did not run QEMU; its path error is retained separately. This report records
the actual second launcher attempt and first target execution, not a pass.
