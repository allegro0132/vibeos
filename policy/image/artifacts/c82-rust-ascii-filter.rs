#![no_std]
#![no_main]

use core::panic::PanicInfo;

const MAX_INPUT: usize = 4096;
const MAX_ARGUMENT_BYTES: usize = 64;
const EXIT_USAGE: u32 = 64;
const EXIT_INPUT_TOO_LARGE: u32 = 65;
const EXIT_SOFTWARE: u32 = 70;
const EXIT_IO: u32 = 74;

#[repr(C)]
struct Iovec {
    buffer: *mut u8,
    length: usize,
}

#[repr(C)]
struct ConstIovec {
    buffer: *const u8,
    length: usize,
}

static mut ARGUMENT_COUNT: u32 = 0;
static mut ARGUMENT_BYTE_COUNT: u32 = 0;
static mut ARGUMENT_POINTERS: [*mut u8; 2] = [core::ptr::null_mut(); 2];
static mut ARGUMENT_BYTES: [u8; MAX_ARGUMENT_BYTES] = [0; MAX_ARGUMENT_BYTES];
static mut IO_AMOUNT: u32 = 0;
static mut READ_IOVEC: Iovec = Iovec {
    buffer: core::ptr::null_mut(),
    length: 0,
};
static mut WRITE_IOVEC: ConstIovec = ConstIovec {
    buffer: core::ptr::null(),
    length: 0,
};
static mut INPUT: [u8; MAX_INPUT + 1] = [0; MAX_INPUT + 1];

#[link(wasm_import_module = "wasi_snapshot_preview1")]
unsafe extern "C" {
    fn args_sizes_get(argument_count: *mut u32, argument_bytes: *mut u32) -> u32;
    fn args_get(arguments: *mut *mut u8, argument_bytes: *mut u8) -> u32;
    fn fd_read(fd: u32, iovecs: *const Iovec, iovec_count: u32, read: *mut u32) -> u32;
    fn fd_write(
        fd: u32,
        iovecs: *const ConstIovec,
        iovec_count: u32,
        written: *mut u32,
    ) -> u32;
    fn proc_exit(code: u32) -> !;
}

fn exit(code: u32) -> ! {
    unsafe { proc_exit(code) }
}

unsafe fn matches_mode(pointer: *const u8, expected: &[u8; 6]) -> bool {
    for (index, expected) in expected.iter().copied().enumerate() {
        if unsafe { core::ptr::read_volatile(pointer.add(index)) } != expected {
            return false;
        }
    }
    true
}

fn selected_mode() -> bool {
    let size_errno = unsafe {
        args_sizes_get(
            &raw mut ARGUMENT_COUNT,
            &raw mut ARGUMENT_BYTE_COUNT,
        )
    };
    let count = unsafe { core::ptr::read_volatile(&raw const ARGUMENT_COUNT) };
    let byte_count = unsafe { core::ptr::read_volatile(&raw const ARGUMENT_BYTE_COUNT) };
    if size_errno != 0
        || count != 2
        || byte_count < 6
        || byte_count as usize > MAX_ARGUMENT_BYTES
    {
        exit(EXIT_USAGE);
    }

    if unsafe {
        args_get(
            (&raw mut ARGUMENT_POINTERS).cast::<*mut u8>(),
            (&raw mut ARGUMENT_BYTES).cast::<u8>(),
        )
    } != 0
    {
        exit(EXIT_USAGE);
    }
    let mode = unsafe {
        core::ptr::read_volatile((&raw const ARGUMENT_POINTERS).cast::<*mut u8>().add(1))
    };
    let start = (&raw const ARGUMENT_BYTES).cast::<u8>() as usize;
    let end = start + byte_count as usize;
    if (mode as usize) < start || (mode as usize) + 6 > end {
        exit(EXIT_USAGE);
    }
    if unsafe { matches_mode(mode, b"upper\0") } {
        true
    } else if unsafe { matches_mode(mode, b"lower\0") } {
        false
    } else {
        exit(EXIT_USAGE);
    }
}

fn read_input() -> usize {
    let mut used = 0_usize;
    loop {
        unsafe {
            core::ptr::write_volatile(
                (&raw mut READ_IOVEC).cast::<*mut u8>(),
                (&raw mut INPUT).cast::<u8>().add(used),
            );
            core::ptr::write_volatile(
                (&raw mut READ_IOVEC).cast::<u8>().add(4).cast::<usize>(),
                MAX_INPUT + 1 - used,
            );
            core::ptr::write_volatile(&raw mut IO_AMOUNT, 0);
        }
        if unsafe { fd_read(0, &raw const READ_IOVEC, 1, &raw mut IO_AMOUNT) } != 0 {
            exit(EXIT_IO);
        }
        let amount = unsafe { core::ptr::read_volatile(&raw const IO_AMOUNT) } as usize;
        if amount > MAX_INPUT + 1 - used {
            exit(EXIT_SOFTWARE);
        }
        used += amount;
        if used > MAX_INPUT {
            exit(EXIT_INPUT_TOO_LARGE);
        }
        if amount == 0 {
            return used;
        }
    }
}

fn write_output(length: usize) {
    let mut used = 0_usize;
    while used < length {
        unsafe {
            core::ptr::write_volatile(
                (&raw mut WRITE_IOVEC).cast::<*const u8>(),
                (&raw const INPUT).cast::<u8>().add(used),
            );
            core::ptr::write_volatile(
                (&raw mut WRITE_IOVEC).cast::<u8>().add(4).cast::<usize>(),
                length - used,
            );
            core::ptr::write_volatile(&raw mut IO_AMOUNT, 0);
        }
        if unsafe { fd_write(1, &raw const WRITE_IOVEC, 1, &raw mut IO_AMOUNT) } != 0 {
            exit(EXIT_IO);
        }
        let amount = unsafe { core::ptr::read_volatile(&raw const IO_AMOUNT) } as usize;
        if amount == 0 || amount > length - used {
            exit(EXIT_SOFTWARE);
        }
        used += amount;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let upper = selected_mode();
    let length = read_input();
    for index in 0..length {
        let pointer = unsafe { (&raw mut INPUT).cast::<u8>().add(index) };
        let value = unsafe { core::ptr::read_volatile(pointer) };
        let transformed = if upper && value.is_ascii_lowercase() {
            value - (b'a' - b'A')
        } else if !upper && value.is_ascii_uppercase() {
            value + (b'a' - b'A')
        } else {
            value
        };
        unsafe { core::ptr::write_volatile(pointer, transformed) };
    }
    write_output(length);
    exit(0);
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    exit(EXIT_SOFTWARE)
}
