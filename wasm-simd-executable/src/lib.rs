//! C8.11-S2 independently numbered deterministic fixed-SIMD executor.

#![no_std]

extern crate alloc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutableIdentity {
    pub package: &'static str,
    pub version: &'static str,
    pub feature_set: &'static str,
    pub profile_code: u16,
    pub production_ready: bool,
}

pub const EXECUTABLE_IDENTITY: ExecutableIdentity = ExecutableIdentity {
    package: "vibeos-wasmi-simd-executable-softfloat",
    version: "1.1.0-vibeos-simd2.1",
    feature_set:
        "default-features=false;extra-checks,prefer-btree-collections,simd;relaxed-simd=false",
    profile_code: 8,
    production_ready: false,
};

#[cfg(feature = "c811-s2-acceptance")]
mod implementation {
    use alloc::vec::Vec;
    use vibeos_component_format::{
        current_validation_engine_identity, ProfileIdentity, TrapCode, WasmiCompilationMode,
        WasmiEnforcedLimits, WasmiFuelCosts,
    };
    use wasmi_simd_executable::{
        CompilationMode, Config, EnforcedLimits, Engine, Linker, Module, Store, Val, ValType, F32,
        F64, V128,
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ExecutableValue {
        I32(i32),
        I64(i64),
        F32Bits(u32),
        F64Bits(u64),
        V128Bits(u128),
    }

    impl ExecutableValue {
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
        let identity =
            current_validation_engine_identity(ProfileIdentity::PROFILE_5_SYNC_SIMD_EXECUTABLE)
                .ok_or(TrapCode::Validation)?;
        if identity.profile() != ProfileIdentity::PROFILE_5_SYNC_SIMD_EXECUTABLE
            || identity.wasmi().name() != super::EXECUTABLE_IDENTITY.package
            || identity.wasmi().version() != super::EXECUTABLE_IDENTITY.version
        {
            return Err(TrapCode::Validation);
        }
        let runtime = identity.runtime();
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
        inputs: &[ExecutableValue],
        fuel: u64,
    ) -> Result<(Vec<ExecutableValue>, u64), TrapCode> {
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
            || !inputs
                .iter()
                .zip(ty.params())
                .all(|(left, right)| left.ty() == *right)
        {
            return Err(TrapCode::Validation);
        }
        let arguments = inputs
            .iter()
            .copied()
            .map(ExecutableValue::into_wasmi)
            .collect::<Vec<_>>();
        let mut outputs = ty
            .results()
            .iter()
            .copied()
            .map(default_value)
            .collect::<Option<Vec<_>>>()
            .ok_or(TrapCode::Validation)?;
        function
            .call(&mut store, &arguments, &mut outputs)
            .map_err(|error| match error.kind().as_trap_code() {
                Some(wasmi_simd_executable::TrapCode::OutOfFuel) => TrapCode::FuelExhausted,
                _ => TrapCode::Validation,
            })?;
        let remaining = store.get_fuel().map_err(|_| TrapCode::FuelExhausted)?;
        let values = outputs
            .iter()
            .map(ExecutableValue::from_wasmi)
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
        fn code8_executes_fixed_integer_and_float_simd_exactly() {
            let integer = wasm("(module (func (export \"run\") (param v128 v128) (result v128) local.get 0 local.get 1 i32x4.add))");
            let left = ExecutableValue::V128Bits(0x00000004_00000003_00000002_00000001);
            let right = ExecutableValue::V128Bits(0x00000028_0000001e_00000014_0000000a);
            let expected = ExecutableValue::V128Bits(0x0000002c_00000021_00000016_0000000b);
            assert_eq!(
                execute(&integer, "run", &[left, right], 10_000).unwrap().0,
                vec![expected]
            );

            let float = wasm("(module (func (export \"run\") (param v128 v128) (result v128) local.get 0 local.get 1 f32x4.add))");
            let nan = ExecutableValue::V128Bits(0x7fa00001_7fa00001_7fa00001_7fa00001);
            let one = ExecutableValue::V128Bits(0x3f800000_3f800000_3f800000_3f800000);
            let canonical = ExecutableValue::V128Bits(0x7fc00000_7fc00000_7fc00000_7fc00000);
            assert_eq!(
                execute(&float, "run", &[nan, one], 10_000).unwrap().0,
                vec![canonical]
            );
        }

        #[test]
        fn relaxed_simd_and_zero_fuel_fail_closed() {
            let fixed =
                wasm("(module (func (export \"run\") (param v128) (result v128) local.get 0))");
            assert_eq!(
                execute(&fixed, "run", &[ExecutableValue::V128Bits(0)], 0),
                Err(TrapCode::FuelExhausted)
            );
            let relaxed = wasm("(module (func (export \"run\") (param v128) (result v128) local.get 0 i8x16.relaxed_swizzle))");
            assert_eq!(
                execute(&relaxed, "run", &[ExecutableValue::V128Bits(0)], 10_000),
                Err(TrapCode::Validation)
            );
        }
    }
}

#[cfg(feature = "c811-s2-acceptance")]
pub use implementation::{execute, ExecutableValue};
