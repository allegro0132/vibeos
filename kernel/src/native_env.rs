//! Bounded, explicitly seeded environment owned by one native invocation.
use alloc::{ffi::CString, vec::Vec};
use core::ffi::c_char;

pub(super) struct Environment { entries: Vec<(CString, CString)> }
impl Environment {
    pub(super) fn new() -> Self { Self { entries: Vec::new() } }
    fn valid_name(name: &[u8]) -> bool { !name.is_empty() && !name.contains(&0) && !name.contains(&b'=') }
    pub(super) fn set(&mut self, name: &[u8], value: &[u8], overwrite: bool) -> Result<(), i32> {
        if !Self::valid_name(name) || value.contains(&0) { return Err(-9); }
        if name.len() > 255 || value.len() > 4096 { return Err(-20); }
        let index = self.entries.iter().position(|(key, _)| key.as_bytes() == name);
        if index.is_some() && !overwrite { return Ok(()); }
        if index.is_none() && self.entries.len() == 64 { return Err(-20); }
        let used: usize = self.entries.iter().enumerate().filter(|(i, _)| Some(*i) != index)
            .map(|(_, (key, value))| key.as_bytes_with_nul().len() + value.as_bytes_with_nul().len()).sum();
        if used + name.len() + value.len() + 2 > 65536 { return Err(-20); }
        let value = CString::new(value).map_err(|_| -9)?;
        if let Some(index) = index { self.entries[index].1 = value; }
        else {
            self.entries.try_reserve(1).map_err(|_| -16)?;
            self.entries.push((CString::new(name).map_err(|_| -9)?, value));
        }
        Ok(())
    }
    fn get(&self, name: &[u8]) -> *const c_char {
        self.entries.iter().find(|(key, _)| key.as_bytes() == name)
            .map_or(core::ptr::null(), |(_, value)| value.as_ptr())
    }
}

unsafe fn bytes<'a>(pointer: *const u8, length: usize, limit: usize) -> Result<&'a [u8], i32> {
    if pointer.is_null() { return Err(-9); }
    if length > limit { return Err(-20); }
    Ok(unsafe { core::slice::from_raw_parts(pointer, length) })
}
// Borrowed pointer remains valid until that entry changes or invocation teardown.
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_env_get(name: *const u8, length: usize) -> *const c_char {
    let Ok(name) = (unsafe { bytes(name, length, 255) }) else { return core::ptr::null(); };
    crate::native_tls::with_environment(|env| env.get(name))
}
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_env_set(name: *const u8, length: usize,
    value: *const u8, value_length: usize, overwrite: i32) -> i32 {
    let name = match unsafe { bytes(name, length, 255) } { Ok(v) => v, Err(e) => return e };
    let value = match unsafe { bytes(value, value_length, 4096) } { Ok(v) => v, Err(e) => return e };
    crate::native_tls::with_environment(|env| env.set(name, value, overwrite != 0).map_or_else(|e| e, |_| 0))
}
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_env_unset(name: *const u8, length: usize) -> i32 {
    let name = match unsafe { bytes(name, length, 255) } { Ok(v) => v, Err(e) => return e };
    if !Environment::valid_name(name) { return -9; }
    crate::native_tls::with_environment(|env| {
        if let Some(index) = env.entries.iter().position(|(key, _)| key.as_bytes() == name) { env.entries.remove(index); }
    });
    0
}
#[no_mangle]
pub(super) extern "C" fn vibeos_native_env_count() -> usize {
    crate::native_tls::with_environment(|env| env.entries.len())
}
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_env_entry(index: usize,
    name: *mut *const c_char, value: *mut *const c_char) -> i32 {
    if name.is_null() || value.is_null() { return -9; }
    crate::native_tls::with_environment(|env| {
        let Some((key, data)) = env.entries.get(index) else { return -6; };
        unsafe { name.write(key.as_ptr()); value.write(data.as_ptr()); }
        0
    })
}
