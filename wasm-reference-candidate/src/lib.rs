//! C8.12-R2 acceptance-only bounded Reference Types validation candidate.
//!
//! Default builds contain no parser or engine dependency. The acceptance
//! feature enables a two-pass validator: wasmparser freezes the exact syntax
//! subset and the separately named Wasmi facade proves the same bytes translate
//! under the matching runtime configuration. Code 9 remains `ValidationOnly`.

#![no_std]

extern crate alloc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateIdentity {
    pub package: &'static str,
    pub version: &'static str,
    pub feature_set: &'static str,
    pub acceptance_feature: &'static str,
    pub production_ready: bool,
}

pub const CANDIDATE_IDENTITY: CandidateIdentity = CandidateIdentity {
    package: "vibeos-wasmi-reference-validation",
    version: "1.1.0-vibeos-ref1.1",
    feature_set: "default-features=false;extra-checks,prefer-btree-collections;simd=false",
    acceptance_feature: "c812-r2-acceptance",
    production_ready: false,
};

#[cfg(feature = "c812-r2-acceptance")]
mod acceptance {
    use alloc::vec::Vec;
    use vibeos_component_format::{
        profile_6_sync_reference_types_validation_contract, CoreNumericProfile, ProfileIdentity,
        TrapCode, WasmiCompilationMode, WasmiEnforcedLimits, WasmiFuelCosts,
    };
    use wasmi_reference::{CompilationMode, Config, EnforcedLimits, Engine, Module};
    use wasmparser::{
        ElementItems, ElementKind, ExternalKind, HeapType, Operator, Parser, Payload, RefType,
        TypeRef, ValType, Validator, WasmFeatures,
    };

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ValidationReport {
        pub functions: u32,
        pub tables: u32,
        pub reference_operators: u32,
        pub active_elements: u32,
        pub exports: u32,
    }

    fn allowed_value_type(ty: ValType) -> bool {
        matches!(ty, ValType::I32 | ValType::I64) || ty == ValType::Ref(RefType::FUNCREF)
    }

    fn boundary_value_type(ty: ValType) -> bool {
        matches!(ty, ValType::I32 | ValType::I64)
    }

    fn inspect_operator(
        operator: &Operator<'_>,
        report: &mut ValidationReport,
    ) -> Result<(), TrapCode> {
        match operator {
            Operator::RefNull { hty } => {
                if *hty != HeapType::FUNC {
                    return Err(TrapCode::UnsupportedFeature);
                }
                report.reference_operators += 1;
            }
            Operator::RefIsNull | Operator::RefFunc { .. } => {
                report.reference_operators += 1;
            }
            Operator::TypedSelect { ty } => {
                if !allowed_value_type(*ty) {
                    return Err(TrapCode::UnsupportedFeature);
                }
                report.reference_operators += 1;
            }
            Operator::TypedSelectMulti { .. } => return Err(TrapCode::UnsupportedFeature),
            Operator::TableGet { table }
            | Operator::TableSet { table }
            | Operator::TableGrow { table }
            | Operator::TableSize { table }
            | Operator::TableFill { table } => {
                if *table != 0 {
                    return Err(TrapCode::UnsupportedFeature);
                }
                report.reference_operators += 1;
            }
            _ => {}
        }
        Ok(())
    }

    fn inspect_const_expr(
        expression: wasmparser::ConstExpr<'_>,
        report: &mut ValidationReport,
    ) -> Result<(), TrapCode> {
        let mut operators = expression.get_operators_reader();
        while !operators.eof() {
            let operator = operators.read().map_err(|_| TrapCode::Validation)?;
            inspect_operator(&operator, report)?;
        }
        Ok(())
    }

    fn parser_features() -> WasmFeatures {
        let mut features = WasmFeatures::empty();
        features.set(WasmFeatures::REFERENCE_TYPES, true);
        // Required by wasmparser for heap-type decoding. GC instructions and
        // composite types remain disabled/rejected by the validator and scan.
        features.set(WasmFeatures::GC_TYPES, true);
        features
    }

    fn inspect(bytes: &[u8]) -> Result<ValidationReport, TrapCode> {
        Validator::new_with_features(parser_features())
            .validate_all(bytes)
            .map_err(|_| TrapCode::Validation)?;

        let mut report = ValidationReport::default();
        let mut types = Vec::new();
        let mut function_types = Vec::new();
        let mut exported_functions = Vec::new();
        for payload in Parser::new(0).parse_all(bytes) {
            match payload.map_err(|_| TrapCode::Validation)? {
                Payload::TypeSection(section) => {
                    for ty in section.into_iter_err_on_gc_types() {
                        let ty = ty.map_err(|_| TrapCode::UnsupportedFeature)?;
                        if !ty.params().iter().copied().all(allowed_value_type)
                            || !ty.results().iter().copied().all(allowed_value_type)
                        {
                            return Err(TrapCode::UnsupportedFeature);
                        }
                        types.push(ty);
                    }
                }
                Payload::ImportSection(section) => {
                    for import in section {
                        let import = import.map_err(|_| TrapCode::Validation)?;
                        match import.ty {
                            TypeRef::Func(_)
                            | TypeRef::Table(_)
                            | TypeRef::Memory(_)
                            | TypeRef::Global(_)
                            | TypeRef::Tag(_) => return Err(TrapCode::UnsupportedFeature),
                        }
                    }
                }
                Payload::FunctionSection(section) => {
                    for index in section {
                        function_types.push(index.map_err(|_| TrapCode::Validation)?);
                        report.functions += 1;
                    }
                }
                Payload::TableSection(section) => {
                    for table in section {
                        let table = table.map_err(|_| TrapCode::Validation)?;
                        report.tables += 1;
                        if report.tables > 1 || table.ty.element_type != RefType::FUNCREF {
                            return Err(TrapCode::UnsupportedFeature);
                        }
                        if let wasmparser::TableInit::Expr(expression) = table.init {
                            inspect_const_expr(expression, &mut report)?;
                        }
                    }
                }
                Payload::GlobalSection(section) => {
                    for global in section {
                        let global = global.map_err(|_| TrapCode::Validation)?;
                        if !allowed_value_type(global.ty.content_type) {
                            return Err(TrapCode::UnsupportedFeature);
                        }
                        inspect_const_expr(global.init_expr, &mut report)?;
                    }
                }
                Payload::ElementSection(section) => {
                    for element in section {
                        let element = element.map_err(|_| TrapCode::Validation)?;
                        let offset = match element.kind {
                            ElementKind::Active {
                                table_index,
                                offset_expr,
                            } if table_index.unwrap_or(0) == 0 => offset_expr,
                            _ => return Err(TrapCode::UnsupportedFeature),
                        };
                        inspect_const_expr(offset, &mut report)?;
                        match element.items {
                            ElementItems::Functions(functions) => {
                                for function in functions {
                                    function.map_err(|_| TrapCode::Validation)?;
                                }
                            }
                            ElementItems::Expressions(ty, expressions) => {
                                if ty != RefType::FUNCREF {
                                    return Err(TrapCode::UnsupportedFeature);
                                }
                                for expression in expressions {
                                    inspect_const_expr(
                                        expression.map_err(|_| TrapCode::Validation)?,
                                        &mut report,
                                    )?;
                                }
                            }
                        }
                        report.active_elements += 1;
                    }
                }
                Payload::ExportSection(section) => {
                    for export in section {
                        let export = export.map_err(|_| TrapCode::Validation)?;
                        report.exports += 1;
                        match export.kind {
                            ExternalKind::Func => exported_functions.push(export.index),
                            ExternalKind::Memory => {}
                            _ => return Err(TrapCode::UnsupportedFeature),
                        }
                    }
                }
                Payload::CodeSectionEntry(body) => {
                    let locals = body.get_locals_reader().map_err(|_| TrapCode::Validation)?;
                    for local in locals {
                        let (_, ty) = local.map_err(|_| TrapCode::Validation)?;
                        if !allowed_value_type(ty) {
                            return Err(TrapCode::UnsupportedFeature);
                        }
                    }
                    let mut operators = body
                        .get_operators_reader()
                        .map_err(|_| TrapCode::Validation)?;
                    while !operators.eof() {
                        let operator = operators.read().map_err(|_| TrapCode::Validation)?;
                        inspect_operator(&operator, &mut report)?;
                    }
                }
                Payload::TagSection(_) => return Err(TrapCode::UnsupportedFeature),
                _ => {}
            }
        }

        for function in exported_functions {
            let type_index = *function_types
                .get(function as usize)
                .ok_or(TrapCode::Validation)? as usize;
            let ty = types.get(type_index).ok_or(TrapCode::Validation)?;
            if !ty.params().iter().copied().all(boundary_value_type)
                || !ty.results().iter().copied().all(boundary_value_type)
            {
                return Err(TrapCode::UnsupportedFeature);
            }
        }
        Ok(report)
    }

    fn engine() -> Result<Engine, TrapCode> {
        let contract = profile_6_sync_reference_types_validation_contract();
        if contract.profile() != ProfileIdentity::PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION
            || contract.runtime_ready()
            || contract.core_validator().numeric_profile()
                != CoreNumericProfile::Profile6IntegerReferences
        {
            return Err(TrapCode::Validation);
        }
        let runtime = contract.target_wasmi_configuration();
        if runtime.floats()
            || !runtime.reference_types()
            || runtime.bulk_memory()
            || runtime.multi_memory()
            || runtime.simd_compiled()
        {
            return Err(TrapCode::UnsupportedFeature);
        }
        let mut config = Config::default();
        config
            .floats(false)
            .wasm_mutable_global(runtime.mutable_global())
            .wasm_sign_extension(runtime.sign_extension())
            .wasm_saturating_float_to_int(runtime.saturating_float_to_int())
            .wasm_multi_value(runtime.multi_value())
            .wasm_multi_memory(runtime.multi_memory())
            .wasm_bulk_memory(runtime.bulk_memory())
            .wasm_reference_types(true)
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

    pub fn validate(bytes: &[u8]) -> Result<ValidationReport, TrapCode> {
        let report = inspect(bytes)?;
        Module::new(&engine()?, bytes).map_err(|_| TrapCode::Validation)?;
        Ok(report)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use alloc::vec::Vec;

        fn wasm(source: &str) -> Vec<u8> {
            wat::parse_str(source).unwrap()
        }

        #[test]
        fn bounded_funcref_surface_validates() {
            let bytes = wasm(
                "(module
                    (type (func (param funcref) (result i32)))
                    (table 4 funcref)
                    (func $f)
                    (elem (i32.const 0) $f)
                    (func (export \"run\") (result i32)
                      ref.null func ref.is_null
                      ref.func $f ref.is_null i32.add
                      i32.const 0 table.get ref.is_null i32.add
                      i32.const 1 ref.func $f table.set
                      table.size i32.add))",
            );
            let report = validate(&bytes).unwrap();
            assert_eq!(report.tables, 1);
            assert_eq!(report.active_elements, 1);
            assert!(report.reference_operators >= 6);
        }

        #[test]
        fn externref_and_reference_exports_are_rejected() {
            let external = wasm("(module (func (param externref) local.get 0 drop))");
            assert_eq!(validate(&external), Err(TrapCode::UnsupportedFeature));
            let boundary = wasm("(module (func (export \"leak\") (result funcref) ref.null func))");
            assert_eq!(validate(&boundary), Err(TrapCode::UnsupportedFeature));
        }

        #[test]
        fn bulk_memory_passive_elements_and_multiple_tables_are_rejected() {
            let passive = wasm("(module (table 1 funcref) (func $f) (elem func $f))");
            assert!(validate(&passive).is_err());
            let multiple = wasm("(module (table 1 funcref) (table 1 funcref))");
            assert_eq!(validate(&multiple), Err(TrapCode::UnsupportedFeature));
        }

        #[test]
        fn adjacent_numeric_and_proposal_features_are_rejected() {
            for source in [
                "(module (func f32.const 0 drop))",
                "(module (memory i64 1))",
                "(module (memory 1 1 shared))",
                "(module (func (result v128) v128.const i32x4 0 0 0 0))",
            ] {
                assert!(validate(&wasm(source)).is_err(), "accepted {source}");
            }
        }
    }
}

#[cfg(feature = "c812-r2-acceptance")]
pub use acceptance::{validate, ValidationReport};
