#include <stdint.h>

/*
 * Compile for wasm32-wasip1 with wasi-sdk-33, -ffreestanding, -fno-builtin,
 * and -nostdlib, then
 * link with 128 KiB of initial memory (--initial-memory=131072). No libc or
 * allocator operation is used by this Canonical ABI fixture.
 */
#define WASM_EXPORT(name) __attribute__((export_name(name)))

enum {
    INITIAL_MEMORY_BYTES = 131072u,
    RESULT_POINTER = 1024u,
    RESULT_BYTES = 72u,
    RESPONSE_PAYLOAD_OFFSET = 8u,
    REQUEST_BYTES = 56u,
    TUPLE_ENUM_OFFSET = 56u,
    LABEL_OUTPUT_POINTER = 16384u,
    PAYLOAD_OUTPUT_POINTER = 32768u,
};

static uint32_t bump_pointer = 69632u;

static uint8_t read_u8(uint32_t address) {
    return *(volatile const uint8_t *)(uintptr_t)address;
}

static void write_u8(uint32_t address, uint8_t value) {
    *(volatile uint8_t *)(uintptr_t)address = value;
}

static void write_u16(uint32_t address, uint16_t value) {
    *(volatile uint16_t *)(uintptr_t)address = value;
}

static void write_u32(uint32_t address, uint32_t value) {
    *(volatile uint32_t *)(uintptr_t)address = value;
}

static void write_u64(uint32_t address, uint64_t value) {
    *(volatile uint64_t *)(uintptr_t)address = value;
}

static void copy_volatile(uint32_t source, uint32_t destination, uint32_t length) {
    uint32_t index = 0;
    while (index < length) {
        write_u8(destination + index, read_u8(source + index));
        index += 1;
    }
}

static void zero_volatile(uint32_t destination, uint32_t length) {
    uint32_t index = 0;
    while (index < length) {
        write_u8(destination + index, 0);
        index += 1;
    }
}

WASM_EXPORT("cabi_realloc")
uint32_t cabi_realloc(uint32_t old_pointer, uint32_t old_size,
                      uint32_t alignment, uint32_t new_size) {
    if (new_size == 0u) {
        return 0u;
    }
    if (alignment == 0u || (alignment & (alignment - 1u)) != 0u) {
        return 0u;
    }

    uint32_t mask = alignment - 1u;
    uint32_t aligned = (bump_pointer + mask) & ~mask;
    if (aligned < bump_pointer || aligned > INITIAL_MEMORY_BYTES ||
        new_size > INITIAL_MEMORY_BYTES - aligned) {
        return 0u;
    }
    bump_pointer = aligned + new_size;

    if (old_pointer != 0u) {
        uint32_t copied = old_size < new_size ? old_size : new_size;
        copy_volatile(old_pointer, aligned, copied);
    }
    return aligned;
}

WASM_EXPORT("transform")
uint32_t transform(uint32_t truth, int32_t signed_value, uint64_t wide,
                   uint32_t symbol, uint32_t label_pointer,
                   uint32_t label_length, uint32_t payload_pointer,
                   uint32_t payload_length, uint32_t attributes,
                   uint32_t maybe_discriminant, uint32_t maybe_value,
                   uint32_t outcome_discriminant, uint32_t outcome_value) {
    zero_volatile(RESULT_POINTER, RESULT_BYTES);
    uint32_t response_payload = RESULT_POINTER + RESPONSE_PAYLOAD_OFFSET;

    if (truth == 0u) {
        /* response::rejected(error-code::denied) */
        write_u8(RESULT_POINTER, 1u);
        write_u8(response_payload, 0u);
        return RESULT_POINTER;
    }

    copy_volatile(label_pointer, LABEL_OUTPUT_POINTER, label_length);
    copy_volatile(payload_pointer, PAYLOAD_OUTPUT_POINTER, payload_length);

    /*
     * response::accepted((request, error-code::invalid)). The request layout
     * uses offsets 0,4,8,16,20/24,28/32,36,38/40,44/48 and has size 56.
     */
    write_u8(RESULT_POINTER, 0u);
    uint32_t request = response_payload;
    write_u8(request, 1u);
    write_u32(request + 4u, (uint32_t)signed_value);
    write_u64(request + 8u, wide);
    write_u32(request + 16u, symbol);
    write_u32(request + 20u, LABEL_OUTPUT_POINTER);
    write_u32(request + 24u, label_length);
    write_u32(request + 28u, PAYLOAD_OUTPUT_POINTER);
    write_u32(request + 32u, payload_length);
    write_u8(request + 36u, (uint8_t)attributes);
    write_u8(request + 38u, (uint8_t)maybe_discriminant);
    write_u16(request + 40u, (uint16_t)maybe_value);
    write_u8(request + 44u, (uint8_t)outcome_discriminant);
    write_u32(request + 48u, outcome_value);
    write_u8(request + TUPLE_ENUM_OFFSET, 1u);

    (void)REQUEST_BYTES;
    return RESULT_POINTER;
}

WASM_EXPORT("cabi_post_transform")
void cabi_post_transform(uint32_t result_pointer) {
    (void)result_pointer;
}
