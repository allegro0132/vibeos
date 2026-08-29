//! C8.13-E2 independently numbered bounded Reference Types executor.
#![no_std]

extern crate alloc;

pub const PACKAGE: &str = "vibeos-wasmi-reference-executable";
pub const VERSION: &str = "1.1.0-vibeos-ref2.1";
pub const FEATURE_SET: &str =
    "default-features=false;extra-checks,prefer-btree-collections;simd=false";
pub const PROFILE_CODE: u16 = 10;

#[cfg(feature = "c813-e2-acceptance")]
mod implementation {
    use alloc::vec::Vec;
    use vibeos_component_format::{
        current_validation_engine_identity, ProfileIdentity, TrapCode, WasmiCompilationMode,
        WasmiEnforcedLimits,
    };
    use wasmi_reference_executable::{
        CompilationMode, Config, EnforcedLimits, Engine, Linker, Module, Store, Val, ValType,
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ExecutableValue {
        I32(i32),
        I64(i64),
    }

    impl ExecutableValue {
        fn ty(self) -> ValType {
            match self {
                Self::I32(_) => ValType::I32,
                Self::I64(_) => ValType::I64,
            }
        }
        fn into_wasmi(self) -> Val {
            match self {
                Self::I32(v) => Val::I32(v),
                Self::I64(v) => Val::I64(v),
            }
        }
        fn from_wasmi(value: &Val) -> Option<Self> {
            match value {
                Val::I32(v) => Some(Self::I32(*v)),
                Val::I64(v) => Some(Self::I64(*v)),
                _ => None,
            }
        }
    }

    fn engine() -> Result<Engine, TrapCode> {
        let identity = current_validation_engine_identity(
            ProfileIdentity::PROFILE_7_SYNC_REFERENCE_TYPES_EXECUTABLE,
        )
        .ok_or(TrapCode::Validation)?;
        if identity.wasmi().name() != super::PACKAGE || identity.wasmi().version() != super::VERSION
        {
            return Err(TrapCode::Validation);
        }
        let runtime = identity.runtime();
        if runtime.floats() || !runtime.reference_types() || runtime.simd_compiled() {
            return Err(TrapCode::UnsupportedFeature);
        }
        let mut config = Config::default();
        config
            .floats(false)
            .wasm_reference_types(true)
            .wasm_mutable_global(runtime.mutable_global())
            .wasm_sign_extension(runtime.sign_extension())
            .wasm_saturating_float_to_int(runtime.saturating_float_to_int())
            .wasm_multi_value(runtime.multi_value())
            .wasm_multi_memory(runtime.multi_memory())
            .wasm_bulk_memory(runtime.bulk_memory())
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
        vibeos_wasm_reference_candidate::validate(bytes).map_err(|_| TrapCode::Validation)?;
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
            .map(ExecutableValue::into_wasmi)
            .collect::<Vec<_>>();
        let mut outputs = ty
            .results()
            .iter()
            .map(|ty| match ty {
                ValType::I32 => Some(Val::I32(0)),
                ValType::I64 => Some(Val::I64(0)),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(TrapCode::Validation)?;
        function
            .call(&mut store, &args, &mut outputs)
            .map_err(|error| match error.kind().as_trap_code() {
                Some(wasmi_reference_executable::TrapCode::OutOfFuel) => TrapCode::FuelExhausted,
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

        #[test]
        fn executes_nullable_funcref_table_indirectly() {
            let wasm = wat::parse_str("(module (type (func (param i32) (result i32))) (func $inc (type 0) local.get 0 i32.const 1 i32.add) (table 1 funcref) (elem (i32.const 0) $inc) (func (export \"run\") (param i32) (result i32) local.get 0 i32.const 0 call_indirect (type 0)))").unwrap();
            assert_eq!(
                execute(&wasm, "run", &[ExecutableValue::I32(41)], 10_000)
                    .unwrap()
                    .0,
                vec![ExecutableValue::I32(42)]
            );
        }

        #[test]
        fn zero_fuel_and_externref_fail_closed() {
            let fixed = wat::parse_str("(module (func (export \"run\") (result i32) i32.const 1))")
                .unwrap();
            assert_eq!(execute(&fixed, "run", &[], 0), Err(TrapCode::FuelExhausted));
            let adjacent = wat::parse_str("(module (global externref (ref.null extern)))").unwrap();
            assert_eq!(
                execute(&adjacent, "run", &[], 10_000),
                Err(TrapCode::Validation)
            );
        }
    }
}

#[cfg(feature = "c813-e2-acceptance")]
pub use implementation::{execute, ExecutableValue};
