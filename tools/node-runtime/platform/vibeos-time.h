// Granted native-runtime clocks, implemented by the Rust platform bridge.
#ifndef VIBEOS_NATIVE_TIME_H_
#define VIBEOS_NATIVE_TIME_H_
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Microseconds since Unix epoch and since the monotonic boot epoch,
// respectively. Negative values mean the clock is unavailable or failed.
int64_t vibeos_native_realtime_us(void);
int64_t vibeos_native_monotonic_us(void);
#ifdef __cplusplus
}
#endif
#endif
