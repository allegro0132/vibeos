# Node WASI unsupported boundary

The VibeOS configuration disables V8 WebAssembly. Node's WASI binding therefore
rejects initialization with ERR_VIBEOS_UNSUPPORTED rather than linking uvwasi's
host-style filesystem/runtime implementation. The Node process metadata marks
uvwasi as disabled-vibeos. This does not alter VibeOS's separate WASI executor
or the real official esbuild WASI path already qualified on the target.

Build 18 exposed node_metadata.cc's remaining uvwasi header dependency; patch
44 now gates that metadata too. Build 19 produces libnode.a successfully. The
patch applies with zero fuzz against the affected files from prepared tree 11.
node-smoke.cc now requires new WASI({version:'preview1'}) to throw the explicit
port error. That JavaScript check has NOT executed yet: Node firmware linking
and runtime acceptance remain pending. Import behavior is based on upstream
lib/wasi.js's constructor-time binding load, not a host execution substitution.
