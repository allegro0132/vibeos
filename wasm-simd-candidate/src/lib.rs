//! C8.10-S2 acceptance-only deterministic fixed-SIMD engine candidate.
//!
//! The default build contains no engine dependency. The candidate is reachable
//! only through `c810-s2-acceptance`; code 7 remains `ValidationOnly`.

#![no_std]

extern crate alloc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateIdentity {
    pub package: &'static str,
    pub version: &'static str,
    pub feature_set: &'static str,
    pub acceptance_feature: &'static str,
    pub fixed_simd: bool,
    pub relaxed_simd: bool,
    pub production_ready: bool,
}

pub const CANDIDATE_IDENTITY: CandidateIdentity = CandidateIdentity {
    package: "vibeos-wasmi-simd-softfloat",
    version: "1.1.0-vibeos-simd1.1",
    feature_set:
        "default-features=false;extra-checks,prefer-btree-collections,simd;relaxed-simd=false",
    acceptance_feature: "c810-s2-acceptance",
    fixed_simd: true,
    relaxed_simd: false,
    production_ready: false,
};

#[cfg(feature = "c810-s2-acceptance")]
mod acceptance {
    use alloc::vec::Vec;
    use vibeos_component_format::{
        profile_4_sync_simd_validation_contract, ProfileIdentity, TrapCode, WasmiCompilationMode,
        WasmiEnforcedLimits, WasmiFuelCosts,
    };
    use wasmi_simd_softfloat::{
        CompilationMode, Config, EnforcedLimits, Engine, Linker, Module, Store, Val, ValType, F32,
        F64, V128,
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CandidateValue {
        I32(i32),
        I64(i64),
        F32Bits(u32),
        F64Bits(u64),
        V128Bits(u128),
    }

    impl CandidateValue {
        fn ty(self) -> ValType {
            match self {
                Self::I32(_) => ValType::I32,
                Self::I64(_) => ValType::I64,
                Self::F32Bits(_) => ValType::F32,
                Self::F64Bits(_) => ValType::F64,
                Self::V128Bits(_) => ValType::V128,
            }
        }

        fn into_wasmi(self) -> Val {
            match self {
                Self::I32(value) => Val::I32(value),
                Self::I64(value) => Val::I64(value),
                Self::F32Bits(bits) => Val::F32(F32::from_bits(bits)),
                Self::F64Bits(bits) => Val::F64(F64::from_bits(bits)),
                Self::V128Bits(bits) => Val::V128(V128::from(bits)),
            }
        }

        fn from_wasmi(value: &Val) -> Option<Self> {
            match value {
                Val::I32(value) => Some(Self::I32(*value)),
                Val::I64(value) => Some(Self::I64(*value)),
                Val::F32(value) => Some(Self::F32Bits(value.to_bits())),
                Val::F64(value) => Some(Self::F64Bits(value.to_bits())),
                Val::V128(value) => Some(Self::V128Bits(value.as_u128())),
                _ => None,
            }
        }
    }

    fn default_value(ty: ValType) -> Option<Val> {
        match ty {
            ValType::I32 => Some(Val::I32(0)),
            ValType::I64 => Some(Val::I64(0)),
            ValType::F32 => Some(Val::F32(F32::from_bits(0))),
            ValType::F64 => Some(Val::F64(F64::from_bits(0))),
            ValType::V128 => Some(Val::V128(V128::from(0))),
            _ => None,
        }
    }

    fn engine() -> Result<Engine, TrapCode> {
        let contract = profile_4_sync_simd_validation_contract();
        if contract.profile() != ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION
            || contract.runtime_ready()
        {
            return Err(TrapCode::Validation);
        }
        let runtime = contract.target_wasmi_configuration();
        if !runtime.floats() || !runtime.simd_compiled() || runtime.relaxed_simd_compiled() {
            return Err(TrapCode::UnsupportedFeature);
        }
        let mut config = Config::default();
        config
            .floats(true)
            .wasm_simd(true)
            .wasm_relaxed_simd(false)
            .wasm_mutable_global(runtime.mutable_global())
            .wasm_sign_extension(runtime.sign_extension())
            .wasm_saturating_float_to_int(runtime.saturating_float_to_int())
            .wasm_multi_value(runtime.multi_value())
            .wasm_multi_memory(runtime.multi_memory())
            .wasm_bulk_memory(runtime.bulk_memory())
            .wasm_reference_types(runtime.reference_types())
            .wasm_tail_call(runtime.tail_call())
            .wasm_extended_const(runtime.extended_const())
            .wasm_custom_page_sizes(runtime.custom_page_sizes())
            .wasm_memory64(runtime.memory64())
            .wasm_wide_arithmetic(runtime.wide_arithmetic())
            .consume_fuel(runtime.consume_fuel())
            .ignore_custom_sections(runtime.ignore_custom_sections())
            .compilation_mode(match runtime.compilation_mode() {
                WasmiCompilationMode::Eager => CompilationMode::Eager,
            })
            .set_max_recursion_depth(runtime.max_recursion_depth())
            .set_min_stack_height(runtime.min_stack_height())
            .set_max_stack_height(runtime.max_stack_height())
            .set_max_cached_stacks(runtime.max_cached_stacks())
            .enforced_limits(match runtime.enforced_limits() {
                WasmiEnforcedLimits::Strict => EnforcedLimits::strict(),
            });
        match runtime.fuel_costs() {
            WasmiFuelCosts::Wasmi110Default => {}
        }
        Ok(Engine::new(&config))
    }

    pub fn execute(
        bytes: &[u8],
        export: &str,
        inputs: &[CandidateValue],
        fuel: u64,
    ) -> Result<(Vec<CandidateValue>, u64), TrapCode> {
        if fuel == 0 {
            return Err(TrapCode::FuelExhausted);
        }
        let engine = engine()?;
        let module = Module::new(&engine, bytes).map_err(|_| TrapCode::Validation)?;
        if module.imports().next().is_some() {
            return Err(TrapCode::Validation);
        }
        let mut store = Store::new(&engine, ());
        store.set_fuel(fuel).map_err(|_| TrapCode::FuelExhausted)?;
        let instance = Linker::new(&engine)
            .instantiate_and_start(&mut store, &module)
            .map_err(|_| TrapCode::Validation)?;
        let function = instance
            .get_func(&store, export)
            .ok_or(TrapCode::Validation)?;
        let ty = function.ty(&store);
        if ty.params().len() != inputs.len()
            || !inputs.iter().zip(ty.params()).all(|(a, b)| a.ty() == *b)
        {
            return Err(TrapCode::Validation);
        }
        let args = inputs
            .iter()
            .copied()
            .map(CandidateValue::into_wasmi)
            .collect::<Vec<_>>();
        let mut outputs = ty
            .results()
            .iter()
            .copied()
            .map(default_value)
            .collect::<Option<Vec<_>>>()
            .ok_or(TrapCode::Validation)?;
        function
            .call(&mut store, &args, &mut outputs)
            .map_err(|error| match error.kind().as_trap_code() {
                Some(wasmi_simd_softfloat::TrapCode::OutOfFuel) => TrapCode::FuelExhausted,
                _ => TrapCode::Validation,
            })?;
        let remaining = store.get_fuel().map_err(|_| TrapCode::FuelExhausted)?;
        let values = outputs
            .iter()
            .map(CandidateValue::from_wasmi)
            .collect::<Option<Vec<_>>>()
            .ok_or(TrapCode::Validation)?;
        Ok((values, fuel - remaining))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use alloc::vec;

        fn wasm(source: &str) -> Vec<u8> {
            wat::parse_str(source).unwrap()
        }

        #[test]
        fn fixed_integer_and_float_simd_are_bit_deterministic() {
            let add = wasm("(module (func (export \"run\") (param v128 v128) (result v128) local.get 0 local.get 1 i32x4.add))");
            let lhs = CandidateValue::V128Bits(0x00000004_00000003_00000002_00000001);
            let rhs = CandidateValue::V128Bits(0x00000028_0000001e_00000014_0000000a);
            let expected = CandidateValue::V128Bits(0x0000002c_00000021_00000016_0000000b);
            let first = execute(&add, "run", &[lhs, rhs], 10_000).unwrap();
            assert_eq!(first, execute(&add, "run", &[lhs, rhs], 10_000).unwrap());
            assert_eq!(first.0, vec![expected]);

            let float = wasm("(module (func (export \"run\") (param v128 v128) (result v128) local.get 0 local.get 1 f32x4.add))");
            let one = CandidateValue::V128Bits(0x3f800000_3f800000_3f800000_3f800000);
            let two = CandidateValue::V128Bits(0x40000000_40000000_40000000_40000000);
            assert_eq!(
                execute(&float, "run", &[one, one], 10_000).unwrap().0,
                vec![two]
            );

            let nan = CandidateValue::V128Bits(0x7fa00001_7fa00001_7fa00001_7fa00001);
            let canonical_nan = CandidateValue::V128Bits(0x7fc00000_7fc00000_7fc00000_7fc00000);
            assert_eq!(
                execute(&float, "run", &[nan, one], 10_000).unwrap().0,
                vec![canonical_nan]
            );

            let div = wasm("(module (func (export \"run\") (param v128 v128) (result v128) local.get 0 local.get 1 f64x2.div))");
            let six = CandidateValue::V128Bits(0x4018000000000000_4018000000000000);
            let two64 = CandidateValue::V128Bits(0x4000000000000000_4000000000000000);
            let three = CandidateValue::V128Bits(0x4008000000000000_4008000000000000);
            assert_eq!(
                execute(&div, "run", &[six, two64], 10_000).unwrap().0,
                vec![three]
            );

            let sqrt = wasm("(module (func (export \"run\") (param v128) (result v128) local.get 0 f64x2.sqrt))");
            let four = CandidateValue::V128Bits(0x4010000000000000_4010000000000000);
            assert_eq!(
                execute(&sqrt, "run", &[four], 10_000).unwrap().0,
                vec![two64]
            );
        }

        #[test]
        fn saturating_shuffle_and_memory_paths_execute() {
            let sat = wasm("(module (func (export \"run\") (param v128 v128) (result v128) local.get 0 local.get 1 i8x16.add_sat_u))");
            assert_eq!(
                execute(
                    &sat,
                    "run",
                    &[
                        CandidateValue::V128Bits(u128::MAX),
                        CandidateValue::V128Bits(1)
                    ],
                    10_000
                )
                .unwrap()
                .0,
                vec![CandidateValue::V128Bits(u128::MAX)]
            );
            let shuffle = wasm("(module (func (export \"run\") (param v128 v128) (result v128) local.get 0 local.get 1 i8x16.shuffle 31 30 29 28 27 26 25 24 7 6 5 4 3 2 1 0))");
            assert_eq!(
                execute(
                    &shuffle,
                    "run",
                    &[
                        CandidateValue::V128Bits(0x000102030405060708090a0b0c0d0e0f),
                        CandidateValue::V128Bits(0x101112131415161718191a1b1c1d1e1f)
                    ],
                    10_000
                )
                .unwrap()
                .0
                .len(),
                1
            );
            let memory = wasm("(module (memory 1 1) (func (export \"run\") (param v128) (result v128) i32.const 0 local.get 0 v128.store i32.const 0 v128.load))");
            let value = CandidateValue::V128Bits(0x0123456789abcdef_fedcba9876543210);
            assert_eq!(
                execute(&memory, "run", &[value], 10_000).unwrap().0,
                vec![value]
            );
        }

        #[test]
        fn relaxed_simd_and_adjacent_proposals_fail_closed() {
            let relaxed = wasm("(module (func (export \"run\") (param v128 v128 v128) (result v128) local.get 0 local.get 1 local.get 2 f32x4.relaxed_madd))");
            assert_eq!(
                execute(&relaxed, "run", &[], 10_000),
                Err(TrapCode::Validation)
            );
            let bulk = wasm("(module (memory 1 1) (func (export \"run\") i32.const 0 i32.const 0 i32.const 0 memory.copy))");
            assert_eq!(
                execute(&bulk, "run", &[], 10_000),
                Err(TrapCode::Validation)
            );
        }

        #[test]
        fn fuel_is_exact_and_exhaustion_is_closed() {
            let add = wasm("(module (func (export \"run\") (param v128 v128) (result v128) local.get 0 local.get 1 i64x2.add))");
            let args = [CandidateValue::V128Bits(1), CandidateValue::V128Bits(2)];
            let (_, used) = execute(&add, "run", &args, 10_000).unwrap();
            assert_eq!(used, 3, "two local reads plus one SIMD instruction");
            assert_eq!(
                execute(&add, "run", &args, used - 1),
                Err(TrapCode::FuelExhausted)
            );
            assert_eq!(execute(&add, "run", &args, used).unwrap().1, used);
        }
    }
}

#[cfg(feature = "c810-s2-acceptance")]
pub use acceptance::{execute, CandidateValue};
