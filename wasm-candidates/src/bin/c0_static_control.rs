#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

extern crate alloc;

mod support;

fn probe() -> usize {
    #[cfg(target_os = "none")]
    {
        return support::escaped_box(core::hint::black_box(support::EMPTY_CORE).len());
    }
    #[cfg(not(target_os = "none"))]
    let value = alloc::boxed::Box::new(core::hint::black_box(support::EMPTY_CORE).len());
    #[cfg(not(target_os = "none"))]
    {
        core::hint::black_box(*value)
    }
}

#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    support::finish(probe())
}

#[cfg(not(target_os = "none"))]
fn main() {
    assert_eq!(probe(), 8);
}
