# Native suspend/resume prerequisite

The LP64D QEMU image used `wasi-ssh-upload,native-runtime-probe,native-call-probe`.
A pinned control block and guarded RW/NX stack survive three explicit yields.
Four resumes verify TLS, FCSR and a floating-point local, with a Rust Drop
counter remaining zero until normal exit, then exactly one. The entry returns
through its normal epilogue; only an assembly trampoline restores the caller.
The stack is unmapped and freed only after that return. Four harts and VSH pass.

This test does not prove executor parking, cancellation, C++ destructors,
standard-library TLS cleanup, V8 execution or the 100-invocation requirement.
It demonstrates register/stack continuation, not a complete native task service.
