#include <stdio.h>
#include <stdint.h>
#include <time.h>
static uint64_t ns(struct timespec t) { return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec; }
int main(void) {
    struct timespec r, m, resolution, end;
    if (clock_gettime(CLOCK_REALTIME, &r) || clock_gettime(CLOCK_MONOTONIC, &m)
        || clock_getres(CLOCK_MONOTONIC, &resolution)) return 1;
    if (r.tv_sec < 1577836800 || !ns(resolution)) return 2;
    do { if (clock_gettime(CLOCK_MONOTONIC, &end)) return 3; }
    while (ns(end) - ns(m) < 20000000);
    printf("realtime_ns=%llu monotonic_ns=%llu resolution_ns=%llu elapsed_ns=%llu\n",
        (unsigned long long)ns(r), (unsigned long long)ns(m),
        (unsigned long long)ns(resolution), (unsigned long long)(ns(end) - ns(m)));
    return 0;
}
