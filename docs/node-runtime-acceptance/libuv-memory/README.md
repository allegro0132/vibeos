# Memory query prerequisites

QEMU executes the real V8 and cumulative libuv gate successfully: expression,
exception, GC, teardown and normal return, 102 parks and zero waiters. Peak
allocator charge is 305733248 bytes. The memory test checks positive bounded
system/available/free readings, unchanged RAM extent and decreased free memory
when the native page pool obtains real backing. RSS rejection preserves output.

Total memory comes from the platform RAM extent. Free memory is the managed heap
extent minus live charged allocations, including reusable free-list space; it
is not a contiguous-allocation promise. Available memory uses the unconstrained
libuv fallback. No unified process limit is claimed: constrained memory returns
zero (unknown), while separate native page/newlib bounds remain enforced.
Process RSS is unsupported because shared kernel/TCB memory is not attributed
to a process; null RSS output returns EINVAL. This is not Node memoryUsage
acceptance. No complete Node or TypeScript execution is claimed.
