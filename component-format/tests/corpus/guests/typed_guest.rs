#![no_std]

#[no_mangle]
pub extern "C" fn add(lhs: i32, rhs: i32) -> i32 {
    lhs.wrapping_add(rhs)
}
