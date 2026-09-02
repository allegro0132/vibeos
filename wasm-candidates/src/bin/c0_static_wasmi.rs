#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

mod support;

use vibeos_wasm_candidates::baseline_contract::{FUEL_BUDGET, FUEL_INPUT};
use vibeos_wasm_candidates::configured_wasmi_engine;
use wasmi::{Linker, Module, Store};

const FUEL_CORE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/c0_fuel.wasm"));

fn probe() -> usize {
    let engine = configured_wasmi_engine();
    let module = Module::new(&engine, FUEL_CORE).unwrap();
    let mut store = Store::new(&engine, ());
    store.set_fuel(FUEL_BUDGET).unwrap();
    let instance = Linker::new(&engine)
        .instantiate_and_start(&mut store, &module)
        .unwrap();
    let burn = instance.get_typed_func::<i32, i32>(&store, "burn").unwrap();
    let result = burn.call(&mut store, FUEL_INPUT).unwrap();
    assert_eq!(result, 0);
    core::hint::black_box(FUEL_BUDGET - store.get_fuel().unwrap()) as usize
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
