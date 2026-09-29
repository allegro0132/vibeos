#include <reent.h>
#include <stddef.h>
static_assert(offsetof(_reent, _freelist) == 104);
static_assert(offsetof(_Bigint, _next) == 0);
static_assert(offsetof(_Bigint, _k) == 8);
