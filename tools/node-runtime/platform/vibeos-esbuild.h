#ifndef VIBEOS_ESBUILD_H
#define VIBEOS_ESBUILD_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// One transform per native invocation at a time. Input is copied before return.
// Positive IDs are invocation-local; negative values are admission errors.
int64_t vibeos_esbuild_begin(const uint8_t* packet, size_t length);
// 0: complete, -15: pending; other negative values are errors. Register the
// native event-loop notification before polling to avoid lost completions.
// Returned bytes stay owned by native TLS until release or invocation teardown.
int vibeos_esbuild_poll(uint64_t id, const uint8_t** output, size_t* length);
// Wait by suspending the protected native stack, preserving live C++ frames.
// Then poll for the result; wait success does not imply transform success.
int vibeos_esbuild_wait(uint64_t id);
// Request cancellation while retaining the handle; wait/poll observes cleanup.
int vibeos_esbuild_cancel(uint64_t id);
// Cancels pending work. The existing WASI reaper owns guest cleanup independently
// of this handle. Completed output must be copied before releasing its handle.
int vibeos_esbuild_release(uint64_t id);
#ifdef __cplusplus
}
#endif
#endif
