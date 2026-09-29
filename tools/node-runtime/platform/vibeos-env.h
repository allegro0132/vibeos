#ifndef VIBEOS_NATIVE_ENV_H_
#define VIBEOS_NATIVE_ENV_H_
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* -9 invalid, -16 allocation failure, -20 configured environment limit. */
const char* vibeos_native_env_get(const void* name, size_t length);
int vibeos_native_env_set(const void* name, size_t length, const void* value,
                          size_t value_length, int overwrite);
int vibeos_native_env_unset(const void* name, size_t length);
size_t vibeos_native_env_count(void);
int vibeos_native_env_entry(size_t index, const char** name, const char** value);
#ifdef __cplusplus
}
#endif
#endif
