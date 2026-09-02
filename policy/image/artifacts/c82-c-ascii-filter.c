typedef unsigned char byte;
typedef unsigned int u32;

enum {
    MAX_INPUT = 4096,
    MAX_ARGUMENT_BYTES = 64,
    EXIT_USAGE = 64,
    EXIT_INPUT_TOO_LARGE = 65,
    EXIT_SOFTWARE = 70,
    EXIT_IO = 74,
};

struct iovec {
    byte *buffer;
    u32 length;
};

struct const_iovec {
    const byte *buffer;
    u32 length;
};

static u32 argument_count;
static u32 argument_byte_count;
static byte *argument_pointers[2];
static byte argument_bytes[MAX_ARGUMENT_BYTES];
static u32 io_amount;
static struct iovec read_iovec;
static struct const_iovec write_iovec;
static byte input[MAX_INPUT + 1];

#define WASIP1(name) \
    __attribute__((import_module("wasi_snapshot_preview1"), import_name(name)))

WASIP1("args_sizes_get") u32 args_sizes_get(u32 *count, u32 *bytes);
WASIP1("args_get") u32 args_get(byte **arguments, byte *bytes);
WASIP1("fd_read")
u32 fd_read(u32 fd, const struct iovec *iovecs, u32 iovec_count, u32 *read);
WASIP1("fd_write")
u32 fd_write(u32 fd, const struct const_iovec *iovecs, u32 iovec_count, u32 *written);
WASIP1("proc_exit") __attribute__((noreturn)) void proc_exit(u32 code);

static __attribute__((noreturn)) void exit_with(u32 code) {
    proc_exit(code);
}

static int begins_with(const byte *value, const char expected[6]) {
    for (u32 index = 0; index < 6; ++index) {
        if (value[index] != (byte)expected[index]) return 0;
    }
    return 1;
}

static int selected_mode(void) {
    if (args_sizes_get(&argument_count, &argument_byte_count) != 0 ||
        argument_count != 2 || argument_byte_count < 6 ||
        argument_byte_count > MAX_ARGUMENT_BYTES) {
        exit_with(EXIT_USAGE);
    }

    if (args_get(argument_pointers, argument_bytes) != 0 ||
        argument_pointers[1] < argument_bytes ||
        argument_pointers[1] + 6 > argument_bytes + argument_byte_count) {
        exit_with(EXIT_USAGE);
    }
    if (begins_with(argument_pointers[1], "upper")) return 1;
    if (begins_with(argument_pointers[1], "lower")) return 0;
    exit_with(EXIT_USAGE);
}

static u32 read_input(void) {
    u32 used = 0;
    for (;;) {
        read_iovec.buffer = input + used;
        read_iovec.length = MAX_INPUT + 1 - used;
        io_amount = 0;
        if (fd_read(0, &read_iovec, 1, &io_amount) != 0) exit_with(EXIT_IO);
        if (io_amount > read_iovec.length) exit_with(EXIT_SOFTWARE);
        used += io_amount;
        if (used > MAX_INPUT) exit_with(EXIT_INPUT_TOO_LARGE);
        if (io_amount == 0) return used;
    }
}

static void write_output(u32 length) {
    u32 used = 0;
    while (used < length) {
        write_iovec.buffer = input + used;
        write_iovec.length = length - used;
        io_amount = 0;
        if (fd_write(1, &write_iovec, 1, &io_amount) != 0) exit_with(EXIT_IO);
        if (io_amount == 0 || io_amount > write_iovec.length) exit_with(EXIT_SOFTWARE);
        used += io_amount;
    }
}

__attribute__((noreturn)) void _start(void) {
    const int upper = selected_mode();
    const u32 length = read_input();
    for (u32 index = 0; index < length; ++index) {
        byte value = input[index];
        if (upper && value >= 'a' && value <= 'z') value -= 'a' - 'A';
        if (!upper && value >= 'A' && value <= 'Z') value += 'a' - 'A';
        input[index] = value;
    }
    write_output(length);
    exit_with(0);
}
