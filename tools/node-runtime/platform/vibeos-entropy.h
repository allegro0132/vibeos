#ifndef VIBEOS_NATIVE_ENTROPY_H_
#define VIBEOS_NATIVE_ENTROPY_H_
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Fill every requested byte from the granted entropy service. Zero means
// success, negative means unavailable/failure. Never return partial success.
int vibeos_native_entropy(uint8_t* bytes, size_t length);
#ifdef __cplusplus
}
#endif
#endif
