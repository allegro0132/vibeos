//! C8.12-R3 fixed-QEMU qualification for validation-only code 9.

#![no_std]

#[cfg(feature = "c812-r3-qemu-qualification")]
extern crate alloc;

#[cfg(feature = "c812-r3-qemu-qualification")]
mod qualification {
    use alloc::vec::Vec;
    use vibeos_component_format::{
        current_validation_engine_identity, ProfileIdentity, ProfileStage, TrapCode,
    };
    use vibeos_component_runtime::decode::{
        current_component_validation_engine, inspect_component_for_profile,
        inspect_component_for_profile_6_candidate,
    };
    use vibeos_wasm_reference_candidate::{validate, CANDIDATE_IDENTITY};
    use vibeos_wasm_runtime::current_core_validation_engine;

    #[allow(dead_code)]
    mod inputs {
        include!(concat!(env!("OUT_DIR"), "/inputs.rs"));
    }
    use inputs::*;

    pub const CASE_IDS: [&str; 8] = [
        "nullable-funcref",
        "table-operations",
        "active-elements",
        "externref-containment",
        "reference-boundary-containment",
        "adjacent-proposals",
        "component-containment",
        "mutation-containment",
    ];

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct QualificationReport {
        pub cases: [bool; 8],
        pub mutation_rejected: u16,
        pub mutation_accepted_inert: u16,
        pub code5_inert: bool,
        pub code7_inert: bool,
        pub code9_validation_only: bool,
        pub current_engine: bool,
        pub durable_authorized: bool,
        pub execution_authorized: bool,
        pub successor_review_before_qualification: bool,
    }

    impl QualificationReport {
        pub fn passed(&self) -> bool {
            self.cases.iter().all(|value| *value)
                && self.mutation_rejected == 208
                && self.mutation_accepted_inert == 48
                && self.code5_inert
                && self.code7_inert
                && self.code9_validation_only
                && !self.current_engine
                && !self.durable_authorized
                && !self.execution_authorized
                && !self.successor_review_before_qualification
        }
    }

    pub fn qualify() -> QualificationReport {
        let bounded = validate(BOUNDED_WASM).ok();
        let table = validate(TABLE_WASM).ok();
        let nullable = bounded.is_some_and(|report| report.reference_operators >= 6);
        let table_operations =
            table.is_some_and(|report| report.tables == 1 && report.reference_operators >= 6);
        let active_elements = bounded.is_some_and(|report| report.active_elements == 1);
        let externref = validate(EXTERNREF_WASM) == Err(TrapCode::UnsupportedFeature);
        let boundary = validate(REFERENCE_EXPORT_WASM) == Err(TrapCode::UnsupportedFeature);
        let adjacent = validate(PASSIVE_WASM).is_err()
            && validate(MULTIPLE_TABLES_WASM).is_err()
            && validate(ADJACENT_FLOAT_WASM).is_err();
        let profile = ProfileIdentity::PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION;
        let component = inspect_component_for_profile_6_candidate(COMPONENT_WASM).is_ok()
            && inspect_component_for_profile(COMPONENT_WASM, profile).is_err();

        let mut rejected = 0u16;
        let mut accepted_inert = 0u16;
        for index in 0..256usize {
            let mut changed = Vec::from(COMPONENT_WASM);
            let offset = 8 + (index * 131 % (changed.len() - 8));
            changed[offset] ^= 1 << (index % 8);
            if inspect_component_for_profile_6_candidate(&changed).is_err() {
                rejected += 1;
            } else if current_validation_engine_identity(profile).is_none() {
                accepted_inert += 1;
            }
        }
        let mutation = rejected == 208 && accepted_inert == 48;
        QualificationReport {
            cases: [
                nullable,
                table_operations,
                active_elements,
                externref,
                boundary,
                adjacent,
                component,
                mutation,
            ],
            mutation_rejected: rejected,
            mutation_accepted_inert: accepted_inert,
            code5_inert: current_validation_engine_identity(ProfileIdentity::PROFILE_2_SYNC_FLOAT)
                .is_none()
                && current_component_validation_engine(ProfileIdentity::PROFILE_2_SYNC_FLOAT)
                    .is_none(),
            code7_inert: current_validation_engine_identity(
                ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION,
            )
            .is_none(),
            code9_validation_only: profile.stage == ProfileStage::ValidationOnly
                && !profile.execution_enabled()
                && !CANDIDATE_IDENTITY.production_ready,
            current_engine: current_validation_engine_identity(profile).is_some()
                || current_component_validation_engine(profile).is_some()
                || current_core_validation_engine(profile).is_some(),
            durable_authorized: false,
            execution_authorized: false,
            successor_review_before_qualification: false,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn fixed_qemu_code9_report_is_exact() {
            let table = validate(TABLE_WASM);
            assert!(table.is_ok(), "table fixture: {table:?}");
            let report = qualify();
            assert!(report.passed(), "{report:?}");
            assert_eq!(COMPONENT_SHA256.len(), 64);
            assert_ne!(BOUNDED_SHA256, EXTERNREF_SHA256);
        }
    }
}

#[cfg(feature = "c812-r3-qemu-qualification")]
pub use qualification::{qualify, QualificationReport, CASE_IDS};
