# Native C++ suspension/RAII prerequisite

The LP64D QEMU image used `wasi-ssh-upload,native-runtime-probe,native-cxx-probe`.
`kernel/build.rs` builds `native-cxx-probe.cc` with the pinned bare-metal GCC,
archives it, and links the actual RISC-V object into the kernel. Default images
never compile or link this probe. The fixture uses no C++ standard library and
disables C++ exceptions; it is not the complete static runtime TCB.

A real C++ stack object and floating-point local survive three native context
yields. The caller checks zero destructors while suspended. After four resumes,
the C++ function returns normally and C++/Rust destructors each ran exactly
once, before stack unmapping/freeing. Four harts and a VSH echo pass. No forced
jump or interrupted-frame reclamation is part of this path.

This does not prove V8/Node execution, executor parking, cancellation, TLS
allocation/destructors or 100 invocation cleanup. The results and compiler
metadata record the kernel, source and compiler identities.
