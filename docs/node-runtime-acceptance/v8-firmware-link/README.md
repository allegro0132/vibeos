# V8 plus Rust firmware link diagnostic — failed

The diagnostic forces the actual smoke entry into the Rust firmware link,
using the integrated target V8 archives and pinned RV64 LP64D C/C++ runtime.
It is not a runnable V8 acceptance image (the fixture flag page remains and
the boot path does not call V8). The link failed; no runtime pass is claimed.

The kernel now resolves the previously standalone-missing memory, TLS, stack,
clock, cache and TCB page bridges. There are 25 remaining undefined symbols,
listed in results.json. In addition, lld reports 3088 relocations referring to
symbols in discarded sections, with references from GCC exception tables.
Exception/unwind and garbage-collection configuration needs investigation;
this evidence does not establish its cause or justify suppressing errors.

Reproduce with scripts/check-v8-firmware-link.py, specifying the prepared V8
source tree and a fresh evidence directory under target. Complete local output
is target/node-runtime/firmware-link-audit-1/link.log. The full error log is
large; results.json preserves the exact commands and diagnostic counts.
