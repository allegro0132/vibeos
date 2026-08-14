#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct block_stats {
    uint64_t reads;
    uint64_t read_sectors;
    uint64_t writes;
    uint64_t write_sectors;
    uint64_t flushes;
};

static bool read_block_stats(const char *path, struct block_stats *stats) {
    FILE *stream = fopen(path, "re");
    if (stream == NULL) return false;
    uint64_t field[17] = {0};
    int count = fscanf(stream,
        "%" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64
        " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64
        " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64
        " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64,
        &field[0], &field[1], &field[2], &field[3], &field[4], &field[5],
        &field[6], &field[7], &field[8], &field[9], &field[10], &field[11],
        &field[12], &field[13], &field[14], &field[15], &field[16]);
    bool closed = fclose(stream) == 0;
    if (count < 16 || !closed) return false;
    *stats = (struct block_stats) {
        .reads = field[0], .read_sectors = field[2],
        .writes = field[4], .write_sectors = field[6], .flushes = field[15],
    };
    return true;
}

static uint64_t monotonic_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &value) != 0) {
        perror("clock_gettime");
        exit(2);
    }
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static bool transfer_all(int fd, uint8_t *buffer, size_t length, bool write_mode) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write_mode ? write(fd, buffer + offset, length - offset)
                                   : read(fd, buffer + offset, length - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        offset += (size_t)count;
    }
    return true;
}

static void fill_payload(uint8_t *buffer, size_t length, uint64_t seed) {
    for (size_t index = 0; index < length; ++index) {
        uint64_t value = (uint64_t)index * UINT64_C(131);
        value += (uint64_t)index >> 7;
        value += seed * UINT64_C(17);
        value += UINT64_C(0x5a);
        buffer[index] = (uint8_t)value;
    }
}

static bool durable_put(int dirfd, const char *temporary, const char *final,
                        uint8_t *payload, uint8_t *readback, size_t length) {
    int fd = openat(dirfd, temporary, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0 || !transfer_all(fd, payload, length, true) || fdatasync(fd) != 0 || close(fd) != 0) {
        if (fd >= 0) close(fd);
        unlinkat(dirfd, temporary, 0);
        return false;
    }
    if (renameat(dirfd, temporary, dirfd, final) != 0 || fsync(dirfd) != 0) {
        unlinkat(dirfd, temporary, 0);
        return false;
    }
    fd = openat(dirfd, final, O_RDONLY | O_CLOEXEC);
    bool ok = fd >= 0 && transfer_all(fd, readback, length, false) && close(fd) == 0;
    return ok && memcmp(payload, readback, length) == 0;
}

static bool verified_get(int dirfd, const char *final, uint8_t *payload,
                         uint8_t *readback, size_t length) {
    int fd = openat(dirfd, final, O_RDONLY | O_CLOEXEC);
    bool ok = fd >= 0 && transfer_all(fd, readback, length, false) && close(fd) == 0;
    return ok && memcmp(payload, readback, length) == 0;
}

static uint64_t parse_u64(const char *name, const char *value) {
    char *end = NULL;
    errno = 0;
    unsigned long long result = strtoull(value, &end, 0);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "invalid %s: %s\n", name, value);
        exit(2);
    }
    return (uint64_t)result;
}

int main(int argc, char **argv) {
    const char *directory = "/mnt/data";
    const char *block_stat = "/sys/block/vda/stat";
    uint64_t byte_count = 4096, seed_base = 1, warmups = 5, samples = 20;
    for (int index = 1; index < argc; ++index) {
        if (index + 1 >= argc) {
            fprintf(stderr, "missing argument value\n");
            return 2;
        }
        const char *name = argv[index++];
        const char *value = argv[index];
        if (strcmp(name, "--directory") == 0) directory = value;
        else if (strcmp(name, "--block-stat") == 0) block_stat = value;
        else if (strcmp(name, "--bytes") == 0) byte_count = parse_u64("bytes", value);
        else if (strcmp(name, "--seed") == 0) seed_base = parse_u64("seed", value);
        else if (strcmp(name, "--warmups") == 0) warmups = parse_u64("warmups", value);
        else if (strcmp(name, "--samples") == 0) samples = parse_u64("samples", value);
        else {
            fprintf(stderr, "unknown argument: %s\n", name);
            return 2;
        }
    }
    if (byte_count > SIZE_MAX || warmups + samples < warmups) return 2;
    size_t length = (size_t)byte_count;
    uint8_t *payload = malloc(length == 0 ? 1 : length);
    uint8_t *readback = malloc(length == 0 ? 1 : length);
    if (payload == NULL || readback == NULL) return 2;
    int dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) {
        perror("open data directory");
        return 2;
    }
    for (uint64_t index = 0; index < warmups + samples; ++index) {
        uint64_t seed = seed_base + index;
        char temporary[64], final[64];
        snprintf(temporary, sizeof(temporary), ".bench-%016" PRIx64 ".tmp", seed);
        snprintf(final, sizeof(final), "bench-%016" PRIx64, seed);
        fill_payload(payload, length, seed);
        struct block_stats before, after;
        bool stats_ok = read_block_stats(block_stat, &before);
        uint64_t put_start = monotonic_ns();
        bool put_ok = stats_ok && durable_put(dirfd, temporary, final, payload, readback, length);
        uint64_t put_ns = monotonic_ns() - put_start;
        uint64_t get_start = monotonic_ns();
        bool get_ok = put_ok && verified_get(dirfd, final, payload, readback, length);
        uint64_t get_ns = monotonic_ns() - get_start;
        stats_ok = stats_ok && read_block_stats(block_stat, &after);
        if (put_ok && get_ok && stats_ok
                && after.reads >= before.reads && after.read_sectors >= before.read_sectors
                && after.writes >= before.writes && after.write_sectors >= before.write_sectors
                && after.flushes >= before.flushes) {
            uint64_t reads = after.reads - before.reads;
            uint64_t writes = after.writes - before.writes;
            uint64_t flushes = after.flushes - before.flushes;
            printf("VIBE_STORAGE_BENCH {\"schema\":\"vibeos.storage-bench.sample\"," 
                   "\"version\":1,\"backend\":\"linux-ext4\",\"layer\":\"object\","
                   "\"workload\":\"object-durable-put-get\",\"durability\":"
                   "\"write-fdatasync-rename-dirfsync-readback\",\"object_bytes\":%" PRIu64
                   ",\"seed\":%" PRIu64 ",\"sample_index\":%" PRIu64
                   ",\"warmup\":%s,\"put_ns\":%" PRIu64 ",\"get_ns\":%" PRIu64
                   ",\"block_requests\":%" PRIu64
                   ",\"block_read_requests\":%" PRIu64
                   ",\"block_write_requests\":%" PRIu64
                   ",\"block_flush_requests\":%" PRIu64
                   ",\"block_read_bytes\":%" PRIu64
                   ",\"block_write_bytes\":%" PRIu64
                   ",\"status\":\"ok\"}\n",
                   byte_count, seed, index < warmups ? index : index - warmups,
                   index < warmups ? "true" : "false", put_ns == 0 ? 1 : put_ns,
                   get_ns == 0 ? 1 : get_ns, reads + writes + flushes,
                   reads, writes, flushes,
                   (after.read_sectors - before.read_sectors) * UINT64_C(512),
                   (after.write_sectors - before.write_sectors) * UINT64_C(512));
        } else {
            printf("VIBE_STORAGE_BENCH {\"schema\":\"vibeos.storage-bench.sample\","
                   "\"version\":1,\"backend\":\"linux-ext4\",\"layer\":\"object\","
                   "\"workload\":\"object-durable-put-get\",\"object_bytes\":%" PRIu64
                   ",\"seed\":%" PRIu64 ",\"sample_index\":%" PRIu64
                   ",\"warmup\":%s,\"status\":\"failed-closed\","
                   "\"reason\":\"durable publication, read-back, or block accounting failed\"}\n",
                   byte_count, seed, index < warmups ? index : index - warmups,
                   index < warmups ? "true" : "false");
        }
        fflush(stdout);
    }
    close(dirfd);
    free(readback);
    free(payload);
    return 0;
}
