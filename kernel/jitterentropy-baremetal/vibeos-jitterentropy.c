/*
 * One translation unit is intentional. Besides matching upstream's raw-data
 * recorder, it lets the probe shim reach the library's private measurement
 * functions without modifying the upstream submodule sources.
 */
#include "jitterentropy-base-user.h"
#include "jitterentropy-sha3.c"
#include "jitterentropy-gcd.c"
#include "jitterentropy-health.c"
#include "jitterentropy-noise.c"
#include "jitterentropy-timer.c"
#include "jitterentropy-base.c"

struct rand_data *vibeos_jent_raw_alloc(unsigned int osr, unsigned int flags)
{
	struct rand_data *ec;

	/* Raw evidence must remain collectible even on a platform that fails the
	 * production startup test. Run only the cryptographic self-tests, exactly
	 * like upstream jitterentropy-hashtime.c. */
	jent_common_timer_gcd = 0;
	if (jent_entropy_init_common_pre())
		return NULL;

	ec = jent_entropy_collector_alloc_internal(osr, flags);
	if (ec == NULL)
		return NULL;

	ec->fips_enabled = 1;
	jent_measure_jitter(ec, 0, NULL);
	return ec;
}

unsigned int vibeos_jent_raw_next(struct rand_data *ec, uint64_t *delta)
{
	return jent_measure_jitter(ec, 0, delta);
}

unsigned int vibeos_jent_raw_health(struct rand_data *ec)
{
	return jent_health_failure(ec);
}
