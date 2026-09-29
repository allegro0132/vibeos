# System image identity and unavailable statistics

uv_os_uname copies static VibeOS image identity: sysname VibeOS, release from the
kernel's CARGO_PKG_VERSION, version labelled with that release, machine riscv64.
No build-host uname is imported. Unknown native label indices return NULL and
invalid uname output returns EINVAL; output is published only after every field
fits. uv_os_gethostname uses the explicit invocation HOSTNAME environment value,
with ENOTSUP when absent and normal size-query/short-buffer rules.

CPU model/speed/time accounting is unavailable: uv_cpu_info returns ENOTSUP,
preserving outputs. The void uv_loadavg C ABI returns three NaNs to mark samples
unavailable. Node's CPU/load bindings throw ENOTSUP instead of hiding failure
behind an empty CPU list or reporting numeric load. Patch 54 applies without
fuzz to pinned pristine Node source and the Node archive compiles.

QEMU verifies image labels, invalid arguments, CPU output preservation, NaN load
samples, absent/explicit HOSTNAME, exact copies and short-buffer preservation.
Cumulative real-V8/libuv tests pass with 143 parks, zero waiters, normal shutdown
and 305733376-byte allocator peak. Node JavaScript identity/hostname/error tests
are prepared but have not executed. Full Node/TypeScript acceptance is pending.
