#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

extern crate alloc;

mod support;

use dlr_wasm_interpreter::{decode_and_validate, RunState, Store, Value};
use vibeos_wasm_candidates::baseline_contract::{FUEL_BUDGET, FUEL_INPUT};

const FUEL_CORE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/c0_fuel.wasm"));

fn probe() -> usize {
    let module = decode_and_validate(FUEL_CORE, &mut ()).unwrap();
    let mut store = Store::new(());
    // SAFETY: the decoded module is import-free and belongs to this store.
    let outcome = unsafe { store.module_instantiate(&module, alloc::vec![], None) }.unwrap();
    // SAFETY: the address was returned by this store and the export is checked.
    let burn = unsafe { store.instance_export(outcome.module_addr, "burn") }
        .unwrap()
        .as_func()
        .unwrap();
    // SAFETY: the function belongs to this store and receives its exact i32 parameter.
    let state = unsafe {
        store.invoke(
            burn,
            alloc::vec![Value::I32(FUEL_INPUT as u32)],
            Some(FUEL_BUDGET),
        )
    }
    .unwrap();
    let RunState::Finished {
        values,
        maybe_remaining_fuel: Some(remaining),
    } = state
    else {
        panic!("fuel probe did not finish")
    };
    assert_eq!(values.as_slice(), &[Value::I32(0)]);
    core::hint::black_box(FUEL_BUDGET - remaining) as usize
}

#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    support::finish(probe())
}

#[cfg(not(target_os = "none"))]
fn main() {
    assert!(probe() > 0);
}
