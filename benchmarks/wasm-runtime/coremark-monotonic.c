/* CoreMark POSIX timer adaptation for targets without a wall-clock epoch.
 * Link with --wrap=clock_gettime. The benchmark algorithm is unchanged.
 */
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

int __real_clock_gettime(clockid_t clock, struct timespec *value);
int __wrap_clock_gettime(clockid_t clock, struct timespec *value) {
    int result = __real_clock_gettime(clock == CLOCK_REALTIME ? CLOCK_MONOTONIC : clock, value);
    if (result != 0) {
        fputs("CoreMark clock_gettime failed\n", stderr);
        exit(1);
    }
    return result;
}
