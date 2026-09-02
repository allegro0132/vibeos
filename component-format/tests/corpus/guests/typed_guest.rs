#![no_std]
#![no_main]

use core::{
    panic::PanicInfo,
    ptr::{read_volatile, write_volatile},
};

// This fixture is linked for wasm32-wasip1 with 128 KiB of initial
// memory (`--initial-memory=131072`) and no libc or allocator. The signatures
// below are the Memory32 Canonical ABI for canonical-values.wit.
const INITIAL_MEMORY_BYTES: u32 = 131_072;
const RESULT_POINTER: u32 = 1_024;
const RESULT_BYTES: u32 = 72;
const RESPONSE_PAYLOAD_OFFSET: u32 = 8;
const REQUEST_BYTES: u32 = 56;
const TUPLE_ENUM_OFFSET: u32 = 56;
const LABEL_OUTPUT_POINTER: u32 = 16_384;
const PAYLOAD_OUTPUT_POINTER: u32 = 32_768;

static mut BUMP_POINTER: u32 = 69_632;

unsafe fn read_u8(address: u32) -> u8 {
    unsafe { read_volatile(address as usize as *const u8) }
}

unsafe fn write_u8(address: u32, value: u8) {
    unsafe { write_volatile(address as usize as *mut u8, value) };
}

unsafe fn write_u16(address: u32, value: u16) {
    unsafe { write_volatile(address as usize as *mut u16, value) };
}

unsafe fn write_u32(address: u32, value: u32) {
    unsafe { write_volatile(address as usize as *mut u32, value) };
}

unsafe fn write_u64(address: u32, value: u64) {
    unsafe { write_volatile(address as usize as *mut u64, value) };
}

unsafe fn copy_volatile(source: u32, destination: u32, length: u32) {
    let mut index = 0;
    while index < length {
        unsafe { write_u8(destination + index, read_u8(source + index)) };
        index += 1;
    }
}

unsafe fn zero_volatile(destination: u32, length: u32) {
    let mut index = 0;
    while index < length {
        unsafe { write_u8(destination + index, 0) };
        index += 1;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cabi_realloc(
    old_pointer: u32,
    old_size: u32,
    alignment: u32,
    new_size: u32,
) -> u32 {
    if new_size == 0 {
        return 0;
    }
    if alignment == 0 || !alignment.is_power_of_two() {
        return 0;
    }

    let current = unsafe { BUMP_POINTER };
    let Some(aligned) = current
        .checked_add(alignment - 1)
        .map(|pointer| pointer & !(alignment - 1))
    else {
        return 0;
    };
    let Some(end) = aligned.checked_add(new_size) else {
        return 0;
    };
    if end > INITIAL_MEMORY_BYTES {
        return 0;
    }
    unsafe { BUMP_POINTER = end };

    if old_pointer != 0 {
        unsafe { copy_volatile(old_pointer, aligned, old_size.min(new_size)) };
    }
    aligned
}

#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn transform(
    truth: u32,
    signed: i32,
    wide: u64,
    symbol: u32,
    label_pointer: u32,
    label_length: u32,
    payload_pointer: u32,
    payload_length: u32,
    attributes: u32,
    maybe_discriminant: u32,
    maybe_value: u32,
    outcome_discriminant: u32,
    outcome_value: u32,
) -> u32 {
    unsafe {
        zero_volatile(RESULT_POINTER, RESULT_BYTES);
        let response_payload = RESULT_POINTER + RESPONSE_PAYLOAD_OFFSET;

        if truth == 0 {
            // response::rejected(error-code::denied)
            write_u8(RESULT_POINTER, 1);
            write_u8(response_payload, 0);
            return RESULT_POINTER;
        }

        copy_volatile(label_pointer, LABEL_OUTPUT_POINTER, label_length);
        copy_volatile(payload_pointer, PAYLOAD_OUTPUT_POINTER, payload_length);

        // response::accepted((request, error-code::invalid)). The request layout is
        // fixed at offsets 0,4,8,16,20/24,28/32,36,38/40,44/48 and has size 56.
        write_u8(RESULT_POINTER, 0);
        let request = response_payload;
        write_u8(request, 1);
        write_u32(request + 4, signed as u32);
        write_u64(request + 8, wide);
        write_u32(request + 16, symbol);
        write_u32(request + 20, LABEL_OUTPUT_POINTER);
        write_u32(request + 24, label_length);
        write_u32(request + 28, PAYLOAD_OUTPUT_POINTER);
        write_u32(request + 32, payload_length);
        write_u8(request + 36, attributes as u8);
        write_u8(request + 38, maybe_discriminant as u8);
        write_u16(request + 40, maybe_value as u16);
        write_u8(request + 44, outcome_discriminant as u8);
        write_u32(request + 48, outcome_value);
        write_u8(request + TUPLE_ENUM_OFFSET, 1);

        let _ = REQUEST_BYTES;
        RESULT_POINTER
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn cabi_post_transform(_result_pointer: u32) {}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
