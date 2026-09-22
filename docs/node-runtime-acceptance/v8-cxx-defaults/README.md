# Corrected V8 target C++ defaults

Patch 0022 restores the upstream no-exception, no-RTTI and no-strict-aliasing
C++ defaults for the VibeOS target. Generated makefiles show the engine and
support libraries use these flags while Torque retains its explicit exception
override. The affected target engine/snapshot/support build completed with
exit code zero after about 877.6 seconds; configuration hash and validation
remain unchanged. The host/target build separation is preserved.

This is compilation evidence only. JavaScript exceptions still need the real
V8 QEMU gate, and full firmware link correctness is not established. The follow-up audit
in `../v8-firmware-link-2/` has no discarded-section relocation errors but
still fails with 18 missing interfaces.
The pinned libstdc++ remains unchanged; no fake exception/unwind symbols were
added to hide failures.
