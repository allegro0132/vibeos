/*
 * VibeOS freestanding adapter for jitterentropy-library.
 *
 * The upstream library is dual BSD/GPL; VibeOS uses the BSD option preserved
 * in vendor/jitterentropy/LICENSE.bsd. This adapter is VibeOS code.
 */
#ifndef _JITTERENTROPY_BASE_USER_H
#define _JITTERENTROPY_BASE_USER_H

typedef __SIZE_TYPE__ size_t;
typedef __PTRDIFF_TYPE__ ssize_t;
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

#define NULL ((void *)0)
#define UINT32_MAX 0xffffffffU
#define UINT32_C(x) x##U
#define UINT64_C(x) x##ULL

#define EAGAIN 11
#define ENOENT 2
#define ENOMEM 12
#define EINVAL 22
#define ETIMEDOUT 110
#define EBUSY 16

void *vibeos_jent_zalloc(size_t len);
void vibeos_jent_zfree(void *ptr, size_t len);

static inline void *vibeos_jent_memcpy(void *dst, const void *src, size_t len)
{
	uint8_t *d = (uint8_t *)dst;
	const uint8_t *s = (const uint8_t *)src;
	while (len--)
		*d++ = *s++;
	return dst;
}

static inline void *vibeos_jent_memset(void *dst, int value, size_t len)
{
	uint8_t *d = (uint8_t *)dst;
	while (len--)
		*d++ = (uint8_t)value;
	return dst;
}

#define memcpy vibeos_jent_memcpy
#define memset vibeos_jent_memset

static inline void jent_get_nstime(uint64_t *out)
{
	uint64_t ticks;
	__asm__ __volatile__("rdtime %0" : "=r" (ticks));
	*out = ticks;
}

static inline void jent_memset_secure(void *ptr, size_t len)
{
	vibeos_jent_memset(ptr, 0, len);
	__asm__ __volatile__("" : : "r" (ptr) : "memory");
}

static inline void *jent_zalloc(size_t len)
{
	return vibeos_jent_zalloc(len);
}

static inline void jent_zfree(void *ptr, size_t len)
{
	if (ptr != NULL)
		jent_memset_secure(ptr, len);
	vibeos_jent_zfree(ptr, len);
}

static inline int jent_fips_enabled(void)
{
	return 0;
}

static inline long jent_ncpu(void)
{
	return 1;
}

static inline uint32_t jent_cache_size_roundup(int all_caches)
{
	(void)all_caches;
	return 0;
}

static inline void jent_yield(void)
{
	__asm__ __volatile__("nop" : : : "memory");
}

static inline uint64_t rol64(uint64_t x, int n)
{
	return (x << (n & 63)) | (x >> ((64 - n) & 63));
}

#endif
