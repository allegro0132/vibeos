# Final-source native ABI regression

Run 1 reaches the file-open probe, then fails its obsolete assertion that
write-only opens must be unsupported. Node's file layer now supports that mode.
The corrected probe retains rejection of invalid access mode 3, opens mode 1,
proves that reads are denied without touching the destination, and closes it.
Existing readonly-descriptor write denial and post-revocation tests remain.
The verifier now also rejects fatal/panic output immediately.

Run 2 passes every target check: four-hart identity under foreign tp, protected
LP64D call/return and FP/FCSR preservation, stack suspension and Rust/C++ drops,
GCC emutls and exit destructors, page/cache permissions and ownership, notify,
wait and semaphore behavior, granted entropy, libc allocation, stdio backpressure,
file descriptors, unlink and file read/seek/EOF/revocation. No fatal output occurs.
This is a native bridge regression, not a replacement for V8/Node execution.
