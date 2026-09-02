#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
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

static bool pread_all(int fd, uint8_t *buffer, size_t length, uint64_t offset) {
    size_t done = 0;
    while (done < length) {
        ssize_t count = pread(fd, buffer + done, length - done,
                              (off_t)(offset + done));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        done += (size_t)count;
    }
    return true;
}

static bool pwrite_all(int fd, const uint8_t *buffer, size_t length, uint64_t offset) {
    size_t done = 0;
    while (done < length) {
        ssize_t count = pwrite(fd, buffer + done, length - done,
                               (off_t)(offset + done));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        done += (size_t)count;
    }
    return true;
}

static uint64_t next_random(uint64_t *state) {
    *state = *state * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
    return *state;
}

static int run_block_workload(const char *workload, const char *device,
                              const char *block_stat, uint64_t seed_base,
                              uint64_t warmups, uint64_t samples,
                              uint64_t queue_depth) {
    const uint64_t scratch_first = UINT64_C(128) * 1024 * 1024;
    const uint64_t scratch_bytes = UINT64_C(64) * 1024 * 1024;
    const bool random_read = strcmp(workload, "block-random-read") == 0;
    const bool random_write = strcmp(workload, "block-random-write") == 0;
    const bool flush_only = strcmp(workload, "block-flush") == 0;
    const bool sequential = strcmp(workload, "block-sequential-128k") == 0
                         || strcmp(workload, "block-sequential-64m") == 0;
    const uint64_t operations = random_read || random_write ? 256 : flush_only ? 128 : 512;
    if (!random_read && !random_write && !flush_only && !sequential) {
        fprintf(stderr, "unsupported block workload: %s\n", workload);
        return 2;
    }
    if (queue_depth != 1) {
        for (uint64_t index = 0; index < warmups + samples; ++index) {
            printf("VIBE_STORAGE_BENCH {\"schema\":\"vibeos.storage-bench.sample\","
                   "\"version\":1,\"backend\":\"linux-ext4\",\"layer\":\"block\","
                   "\"workload\":\"%s\",\"object_bytes\":%" PRIu64
                   ",\"seed\":%" PRIu64 ",\"queue_depth\":%" PRIu64
                   ",\"sample_index\":%" PRIu64 ",\"warmup\":%s"
                   ",\"status\":\"unsupported\",\"reason\":\"agent currently uses one synchronous direct-I/O request\"}\n",
                   workload, (uint64_t)(random_read || random_write ? 4096 :
                   strcmp(workload, "block-sequential-128k") == 0 ? 128 * 1024 :
                   strcmp(workload, "block-sequential-64m") == 0 ? 64 * 1024 * 1024 : 0),
                   seed_base + index, queue_depth,
                   index < warmups ? index : index - warmups,
                   index < warmups ? "true" : "false");
        }
        return 0;
    }
    int fd = open(device, O_RDWR | O_CLOEXEC | O_DIRECT);
    if (fd < 0) {
        perror("open benchmark block device");
        return 2;
    }
    uint8_t *buffer = NULL;
    if (posix_memalign((void **)&buffer, 4096, 128 * 1024) != 0 || buffer == NULL) {
        close(fd);
        return 2;
    }
    uint64_t transferred = sequential ? UINT64_C(128) * 1024 * 1024
                                      : random_read || random_write ? UINT64_C(1) * 1024 * 1024 : 0;
    uint64_t object_bytes = random_read || random_write ? 4096
                            : strcmp(workload, "block-sequential-128k") == 0 ? 128 * 1024
                            : strcmp(workload, "block-sequential-64m") == 0 ? 64 * 1024 * 1024 : 0;
    for (uint64_t index = 0; index < warmups + samples; ++index) {
        uint64_t seed = seed_base + index;
        struct block_stats before, after;
        bool stats_ok = read_block_stats(block_stat, &before);
        uint64_t started = monotonic_ns();
        bool ok = stats_ok;
        uint64_t state = seed;
        if (random_read || random_write) {
            fill_payload(buffer, 4096, seed);
            for (uint64_t operation = 0; operation < 256 && ok; ++operation) {
                uint64_t slot = next_random(&state) % ((scratch_bytes / 4096) - 1);
                uint64_t offset = scratch_first + slot * 4096;
                if (random_read) ok = pread_all(fd, buffer, 4096, offset);
                else ok = pwrite_all(fd, buffer, 4096, offset) && fdatasync(fd) == 0;
            }
        } else if (flush_only) {
            for (uint64_t operation = 0; operation < operations && ok; ++operation)
                ok = fsync(fd) == 0;
        } else {
            fill_payload(buffer, 128 * 1024, seed);
            for (uint64_t chunk = 0; chunk < 512 && ok; ++chunk) {
                uint64_t offset = scratch_first + chunk * 128 * 1024;
                ok = pwrite_all(fd, buffer, 128 * 1024, offset);
            }
            ok = ok && fdatasync(fd) == 0;
            for (uint64_t chunk = 0; chunk < 512 && ok; ++chunk) {
                uint64_t offset = scratch_first + chunk * 128 * 1024;
                ok = pread_all(fd, buffer, 128 * 1024, offset);
            }
        }
        uint64_t elapsed = monotonic_ns() - started;
        stats_ok = stats_ok && read_block_stats(block_stat, &after);
        if (ok && stats_ok && after.reads >= before.reads && after.read_sectors >= before.read_sectors
                && after.writes >= before.writes && after.write_sectors >= before.write_sectors
                && after.flushes >= before.flushes) {
            uint64_t reads = after.reads - before.reads;
            uint64_t writes = after.writes - before.writes;
            uint64_t flushes = after.flushes - before.flushes;
            printf("VIBE_STORAGE_BENCH {\"schema\":\"vibeos.storage-bench.sample\","
                   "\"version\":1,\"backend\":\"linux-ext4\",\"layer\":\"block\","
                   "\"workload\":\"%s\",\"object_bytes\":%" PRIu64
                   ",\"seed\":%" PRIu64 ",\"sample_index\":%" PRIu64
                   ",\"warmup\":%s,\"operations\":%" PRIu64
                   ",\"transferred_bytes\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64
                   ",\"latency_ns\":%" PRIu64 ",\"block_requests\":%" PRIu64
                   ",\"block_read_requests\":%" PRIu64
                   ",\"block_write_requests\":%" PRIu64
                   ",\"block_flush_requests\":%" PRIu64
                   ",\"block_read_bytes\":%" PRIu64
                   ",\"block_write_bytes\":%" PRIu64 ",\"status\":\"ok\"}\n",
                   workload, object_bytes, seed, index < warmups ? index : index - warmups,
                   index < warmups ? "true" : "false", operations, transferred,
                   elapsed == 0 ? 1 : elapsed,
                   (elapsed / operations) == 0 ? 1 : elapsed / operations,
                   reads + writes + flushes, reads, writes, flushes,
                   (after.read_sectors - before.read_sectors) * 512,
                   (after.write_sectors - before.write_sectors) * 512);
        } else {
            printf("VIBE_STORAGE_BENCH {\"schema\":\"vibeos.storage-bench.sample\","
                   "\"version\":1,\"backend\":\"linux-ext4\",\"layer\":\"block\","
                   "\"workload\":\"%s\",\"object_bytes\":%" PRIu64
                   ",\"seed\":%" PRIu64 ",\"sample_index\":%" PRIu64
                   ",\"warmup\":%s,\"status\":\"failed-closed\","
                   "\"reason\":\"block operation or block accounting failed\"}\n",
                   workload, object_bytes, seed, index < warmups ? index : index - warmups,
                   index < warmups ? "true" : "false");
        }
        fflush(stdout);
    }
    free(buffer);
    close(fd);
    return 0;
}

static void emit_unsupported_sample(const char *layer, const char *workload,
                                    uint64_t bytes, uint64_t count, uint64_t seed,
                                    uint64_t sample_index, bool warmup,
                                    const char *reason) {
    printf("VIBE_STORAGE_BENCH {\"schema\":\"vibeos.storage-bench.sample\","
           "\"version\":1,\"backend\":\"linux-ext4\",\"layer\":\"%s\","
           "\"workload\":\"%s\",\"object_bytes\":%" PRIu64
           ",\"object_count\":%" PRIu64 ",\"seed\":%" PRIu64
           ",\"sample_index\":%" PRIu64 ",\"warmup\":%s"
           ",\"status\":\"unsupported\",\"reason\":\"%s\"}\n",
           layer, workload, bytes, count, seed, sample_index,
           warmup ? "true" : "false", reason);
}

static int run_extended_workload(const char *workload, const char *directory,
                                 const char *block_stat, uint64_t bytes,
                                 uint64_t object_count, uint64_t seed_base,
                                 uint64_t warmups, uint64_t samples) {
    if (strcmp(workload, "v2-dedup-gc") == 0) {
        for (uint64_t index = 0; index < warmups + samples; ++index) {
            emit_unsupported_sample("object", workload, bytes, object_count,
                                    seed_base + index,
                                    index < warmups ? index : index - warmups,
                                    index < warmups,
                                    "ext4 has no equivalent content-addressed deduplication or cleaner");
        }
        return 0;
    }
    if (strcmp(workload, "object-cold-recovery") == 0) {
        for (uint64_t index = 0; index < warmups + samples; ++index) {
            emit_unsupported_sample("object", workload, bytes, object_count,
                                    seed_base + index,
                                    index < warmups ? index : index - warmups,
                                    index < warmups,
                                    "guest agent cannot reboot and remount inside a timed sample");
        }
        return 0;
    }
    int dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) return 2;
    uint8_t *payload = malloc(bytes == 0 ? 1 : (size_t)bytes);
    uint8_t *readback = malloc(bytes == 0 ? 1 : (size_t)bytes);
    if (payload == NULL || readback == NULL) return 2;
    for (uint64_t index = 0; index < warmups + samples; ++index) {
        uint64_t seed = seed_base + index;
        uint64_t started = monotonic_ns();
        uint64_t transferred = 0;
        uint64_t operations = 0;
        bool ok = true;
        struct block_stats before, after;
        bool stats_ok = read_block_stats(block_stat, &before);
        fill_payload(payload, (size_t)bytes, seed);
        if (strcmp(workload, "object-range-get") == 0 ||
            strcmp(workload, "object-revoke") == 0 ||
            strcmp(workload, "object-v2-large") == 0) {
            char temporary[64], final[64];
            snprintf(temporary, sizeof(temporary), ".bench-%016" PRIx64 ".tmp", seed);
            snprintf(final, sizeof(final), "bench-%016" PRIx64, seed);
            ok = durable_put(dirfd, temporary, final, payload, readback, (size_t)bytes);
            operations++;
            if (ok && strcmp(workload, "object-range-get") == 0) {
                int fd = openat(dirfd, final, O_RDONLY | O_CLOEXEC);
                uint64_t offset = bytes == 0 ? 0 : (seed % ((bytes + 4095) / 4096)) * 4096;
                size_t length = (size_t)((offset >= bytes) ? 0 :
                    ((bytes - offset) < 4096 ? bytes - offset : 4096));
                ok = fd >= 0 && pread_all(fd, readback, length, offset) && close(fd) == 0;
                transferred = length;
                operations++;
            } else if (ok && strcmp(workload, "object-v2-large") == 0) {
                ok = verified_get(dirfd, final, payload, readback, (size_t)bytes);
                transferred = bytes * 2;
                operations++;
            } else if (ok) {
                ok = unlinkat(dirfd, final, 0) == 0 && fsync(dirfd) == 0;
                operations++;
            }
        } else if (strcmp(workload, "file-durable-mutations") == 0 ||
                   strcmp(workload, "file-overwrite-4k") == 0 ||
                   strcmp(workload, "file-overwrite-1m") == 0) {
            char temporary[64], final[64];
            snprintf(temporary, sizeof(temporary), ".file-%016" PRIx64 ".tmp", seed);
            snprintf(final, sizeof(final), "file-%016" PRIx64, seed);
            ok = durable_put(dirfd, temporary, final, payload, readback, (size_t)bytes);
            operations++;
            if (ok && strcmp(workload, "file-durable-mutations") == 0) {
                ok = unlinkat(dirfd, final, 0) == 0 && fsync(dirfd) == 0;
                operations++;
            } else if (ok) {
                ok = durable_put(dirfd, temporary, final, payload, readback, (size_t)bytes);
                operations++;
            }
            transferred = bytes * operations;
        } else if (strcmp(workload, "file-batch-create") == 0) {
            for (uint64_t file = 0; file < object_count && ok; ++file) {
                char temporary[64], final[64];
                snprintf(temporary, sizeof(temporary), ".batch-%016" PRIx64 "-%04" PRIu64 ".tmp", seed, file);
                snprintf(final, sizeof(final), "batch-%016" PRIu64 "-%04" PRIu64, seed, file);
                ok = durable_put(dirfd, temporary, final, payload, readback, (size_t)bytes);
                operations++;
                transferred += bytes;
            }
        } else if (strcmp(workload, "file-sequential") == 0) {
            char path[64];
            snprintf(path, sizeof(path), "seq-%016" PRIx64, seed);
            int fd = openat(dirfd, path, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
            ok = fd >= 0;
            for (uint64_t offset = 0; ok && offset < bytes; offset += 128 * 1024) {
                size_t length = (size_t)((bytes - offset) < 128 * 1024 ? bytes - offset : 128 * 1024);
                ok = pwrite_all(fd, payload, length, offset);
                transferred += length;
            }
            ok = ok && fdatasync(fd) == 0;
            for (uint64_t offset = 0; ok && offset < bytes; offset += 128 * 1024) {
                size_t length = (size_t)((bytes - offset) < 128 * 1024 ? bytes - offset : 128 * 1024);
                ok = pread_all(fd, readback, length, offset);
                transferred += length;
            }
            if (fd >= 0) close(fd);
            unlinkat(dirfd, path, 0);
            fsync(dirfd);
            operations = 2;
        } else if (strcmp(workload, "file-directory") == 0) {
            for (uint64_t file = 0; file < object_count && ok; ++file) {
                char temporary[64], final[64];
                snprintf(temporary, sizeof(temporary), ".dir-%016" PRIx64 "-%04" PRIu64 ".tmp", seed, file);
                snprintf(final, sizeof(final), "dir-%016" PRIu64 "-%04" PRIu64, seed, file);
                ok = durable_put(dirfd, temporary, final, payload, readback, (size_t)bytes);
                operations++;
                transferred += bytes;
            }
            DIR *stream = fdopendir(dup(dirfd));
            if (stream == NULL) ok = false;
            if (stream != NULL) {
                while (readdir(stream) != NULL) {}
                closedir(stream);
                operations++;
            }
        } else {
            emit_unsupported_sample("file-tree", workload, bytes, object_count,
                                    seed, index < warmups ? index : index - warmups,
                                    index < warmups,
                                    "Linux guest workload is not implemented");
            continue;
        }
        uint64_t elapsed = monotonic_ns() - started;
        stats_ok = stats_ok && read_block_stats(block_stat, &after);
        uint64_t reads = 0, writes = 0, flushes = 0, read_bytes = 0, write_bytes = 0;
        if (stats_ok && after.reads >= before.reads && after.read_sectors >= before.read_sectors
                && after.writes >= before.writes && after.write_sectors >= before.write_sectors
                && after.flushes >= before.flushes) {
            reads = after.reads - before.reads;
            writes = after.writes - before.writes;
            flushes = after.flushes - before.flushes;
            read_bytes = (after.read_sectors - before.read_sectors) * 512;
            write_bytes = (after.write_sectors - before.write_sectors) * 512;
        } else {
            ok = false;
        }
        if (ok) {
            printf("VIBE_STORAGE_BENCH {\"schema\":\"vibeos.storage-bench.sample\","
                   "\"version\":1,\"backend\":\"linux-ext4\",\"layer\":\"%s\","
                   "\"workload\":\"%s\",\"object_bytes\":%" PRIu64
                   ",\"object_count\":%" PRIu64 ",\"seed\":%" PRIu64
                   ",\"sample_index\":%" PRIu64 ",\"warmup\":%s"
                   ",\"operations\":%" PRIu64 ",\"transferred_bytes\":%" PRIu64
                   ",\"elapsed_ns\":%" PRIu64 ",\"latency_ns\":%" PRIu64
                   ",\"block_requests\":%" PRIu64 ",\"block_read_requests\":%" PRIu64
                   ",\"block_write_requests\":%" PRIu64 ",\"block_flush_requests\":%" PRIu64
                   ",\"block_read_bytes\":%" PRIu64 ",\"block_write_bytes\":%" PRIu64
                   ",\"status\":\"ok\"}\n",
                   (strcmp(workload, "object-range-get") == 0 ||
                    strcmp(workload, "object-revoke") == 0 ||
                    strcmp(workload, "object-v2-large") == 0) ? "object" : "file-tree",
                   workload, bytes, object_count, seed,
                   index < warmups ? index : index - warmups,
                   index < warmups ? "true" : "false", operations, transferred,
                   elapsed == 0 ? 1 : elapsed, elapsed == 0 ? 1 : elapsed,
                   reads + writes + flushes, reads, writes, flushes,
                   read_bytes, write_bytes);
        } else {
            emit_unsupported_sample("file-tree", workload, bytes, object_count,
                                    seed, index < warmups ? index : index - warmups,
                                    index < warmups,
                                    "durable operation or block accounting failed");
        }
        fflush(stdout);
    }
    free(readback);
    free(payload);
    close(dirfd);
    return 0;
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
    const char *workload = NULL;
    const char *block_device = NULL;
    uint64_t byte_count = 4096, object_count = 1, seed_base = 1, warmups = 5, samples = 20, queue_depth = 1;
    for (int index = 1; index < argc; ++index) {
        if (index + 1 >= argc) {
            fprintf(stderr, "missing argument value\n");
            return 2;
        }
        const char *name = argv[index++];
        const char *value = argv[index];
        if (strcmp(name, "--directory") == 0) directory = value;
        else if (strcmp(name, "--block-stat") == 0) block_stat = value;
        else if (strcmp(name, "--workload") == 0) workload = value;
        else if (strcmp(name, "--block-device") == 0) block_device = value;
        else if (strcmp(name, "--bytes") == 0) byte_count = parse_u64("bytes", value);
        else if (strcmp(name, "--object-count") == 0) object_count = parse_u64("object-count", value);
        else if (strcmp(name, "--queue-depth") == 0) queue_depth = parse_u64("queue-depth", value);
        else if (strcmp(name, "--seed") == 0) seed_base = parse_u64("seed", value);
        else if (strcmp(name, "--warmups") == 0) warmups = parse_u64("warmups", value);
        else if (strcmp(name, "--samples") == 0) samples = parse_u64("samples", value);
        else {
            fprintf(stderr, "unknown argument: %s\n", name);
            return 2;
        }
    }
    if (byte_count > SIZE_MAX || warmups + samples < warmups) return 2;
    if (workload != NULL && strncmp(workload, "block-", 6) == 0) {
        if (block_device == NULL) {
            fprintf(stderr, "--block-device is required for block workloads\n");
            return 2;
        }
        return run_block_workload(workload, block_device, block_stat,
                                  seed_base, warmups, samples, queue_depth);
    }
    if (workload != NULL && strcmp(workload, "object-durable-put-get") != 0) {
        return run_extended_workload(workload, directory, block_stat, byte_count,
                                     object_count, seed_base, warmups, samples);
    }
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
