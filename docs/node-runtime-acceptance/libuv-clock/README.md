# Native libuv clocks and execution identity

uv_gettimeofday and uv_clock_gettime use granted realtime/monotonic services.
uv_uptime reports monotonic boot uptime. Millisecond uv_sleep waits through the
native deadline bridge; it never sleeps the Rust executor or busy-polls.
uv_thread_self identifies the admitted native execution task, not a hart.
uv_available_parallelism returns the port's one active native task limit,
independently of the QEMU hart count. This does not enable native threads.

QEMU checks timestamp normalization and realtime agreement, monotonic uptime,
invalid clock/null output rejection, unchanged output on invalid clock, stable
identity across a 3 ms parked sleep, identity equality and native parallelism.
All existing V8/libuv/newlib capability checks pass too: 31 parks and zero
waiters on normal return. The linked GYP libuv archive includes the new source;
patch 45 applies with zero fuzz after patch 43 on prepared tree 11's uv.gyp.
Clock-service failure injection, cancellation of sleep, concurrent identities
and full Node execution remain unqualified. Random/entropy integration is not
changed by this prerequisite.
