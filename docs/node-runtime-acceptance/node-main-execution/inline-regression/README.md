# Shared project fixture: embedding regression

After extracting the target project checks into node-project-smoke.js, the
original embedding entry passes the same QEMU runtime checks, normal exit 0
and teardown with zero waiters. The linker report now hashes both the source
JS fixture and generated C++ raw-string include and checks their stability
through the link. No host-side JavaScript execution is involved.
