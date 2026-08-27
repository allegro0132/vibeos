#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

mod support;

use vibeos_component_runtime::{
    canonical::{AbiBudget, CallGate, CanonicalMachine, ReallocRequest, Reallocator},
    memory::{AbiError, Allocation, GuestMemory, VecMemory},
};
use vibeos_wasm_candidates::baseline_contract::{CANONICAL_LIST_ELEMENTS, CANONICAL_TEXT_BYTES};
use vibeos_wasm_candidates::{inspect_component, validate_wit_world};

const COMPONENT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/c0_typed_component.wasm"));
const WIT: &str = include_str!("../../../component-format/tests/corpus/wit/world.wit");
const CANONICAL_TEXT: &str = concat!(
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_",
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_",
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_",
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_",
);
const CANONICAL_LIST: [u32; CANONICAL_LIST_ELEMENTS] = [0x0102_0304; CANONICAL_LIST_ELEMENTS];
const _: () = assert!(CANONICAL_TEXT.len() == CANONICAL_TEXT_BYTES);

struct ResettingBump {
    next: u32,
    live: u32,
}

impl ResettingBump {
    const fn new() -> Self {
        Self { next: 64, live: 0 }
    }
}

impl Reallocator<VecMemory> for ResettingBump {
    fn realloc(
        &mut self,
        memory: &mut VecMemory,
        _gate: &CallGate,
        request: ReallocRequest,
        _budget: &mut AbiBudget,
    ) -> Result<u32, AbiError> {
        if request.old_pointer != 0 || request.old_size != 0 || request.new_size == 0 {
            return Err(AbiError::BadRealloc);
        }
        let aligned = self
            .next
            .checked_add(request.alignment - 1)
            .map(|value| value & !(request.alignment - 1))
            .ok_or(AbiError::Overflow)?;
        let end = aligned
            .checked_add(request.new_size)
            .ok_or(AbiError::Overflow)?;
        if memory.len() < u64::from(end) {
            memory.grow_to(end as usize)?;
        }
        self.next = end;
        self.live = self.live.checked_add(1).ok_or(AbiError::AllocationLimit)?;
        Ok(aligned)
    }

    fn free(
        &mut self,
        _memory: &mut VecMemory,
        _gate: &CallGate,
        _allocation: Allocation,
        _budget: &mut AbiBudget,
    ) -> Result<(), AbiError> {
        self.live = self.live.checked_sub(1).ok_or(AbiError::CleanupFailed)?;
        if self.live == 0 {
            self.next = 64;
        }
        Ok(())
    }

    fn discard_arena(&mut self, _memory: &mut VecMemory, _gate: &CallGate) {
        self.next = 64;
        self.live = 0;
    }
}

fn canonical_roundtrip() -> usize {
    let memory = VecMemory::new(65_536, 65_536).unwrap();
    let mut machine = CanonicalMachine::new(memory, ResettingBump::new(), 100_000).unwrap();
    machine.begin_call().unwrap();
    let (text_pointer, text_length) = machine.lower_utf8(CANONICAL_TEXT).unwrap();
    let lifted_text = machine.lift_utf8(text_pointer, text_length).unwrap();
    let (list_pointer, list_length) = machine.lower_u32_list(&CANONICAL_LIST).unwrap();
    let lifted_list = machine.lift_u32_list(list_pointer, list_length).unwrap();
    assert_eq!(lifted_text, CANONICAL_TEXT);
    assert_eq!(lifted_list.as_slice(), CANONICAL_LIST);
    machine.finish_success(|_, _, _| Ok(())).unwrap();
    lifted_text.len() + lifted_list.len()
}

fn probe() -> usize {
    let summary = inspect_component(COMPONENT).unwrap();
    validate_wit_world(WIT, "typed-filter").unwrap();
    assert_eq!(summary.embedded_modules, 1);
    assert_eq!(summary.exports, 1);
    core::hint::black_box(
        summary.canonical_functions as usize + COMPONENT.len() + canonical_roundtrip(),
    )
}

#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    support::finish(probe())
}

#[cfg(not(target_os = "none"))]
fn main() {
    assert!(probe() >= COMPONENT.len());
}
