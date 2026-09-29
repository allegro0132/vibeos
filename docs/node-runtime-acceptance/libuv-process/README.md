# Invocation process metadata

Process titles are owned by NativeTls metadata, initially empty and explicitly
seedable by a launcher. Setting a title copies at most 4096 bytes; bounded
allocation precedes publication. Setup-args copies argv[0] into the title but
returns the original argv without overwriting or retaining its storage. Empty
titles are valid. Short reads preserve output; over-limit writes preserve the
previous title. Logical PID equals the native invocation identity, stays stable
across parks and is not an authority. PPID is zero: there is no POSIX process
tree. Stdio inheritance disabling does not alter explicit endpoint grants;
there is no ambient inherited descriptor table or supported child creation.

The embedded firmware is not an executable file inside a project directory.
uv_exepath therefore returns ENOTSUP without modifying output. Upstream Node's
Environment::GetExecPath falls back to argv[0]. Supplying a proper virtual
executable path from the production launcher/tool mount remains pending.

QEMU checks the launcher seed after a prior invocation changed its own title,
argument copying and preservation, title bounds/empty value, stable PID across
sleep, unchanged exepath outputs and retained stdio endpoints. All cumulative
real-V8/libuv checks pass: 116 parks, zero waiters, normal shutdown, allocator
peak 305733376 bytes. A prospective Node JavaScript pid/ppid/title assertion is
added but has not executed. No complete Node or TypeScript milestone is claimed.
