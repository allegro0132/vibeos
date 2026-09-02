//! C8.10-S5 fixed-QEMU qualification for the validation-only SIMD successor.

#![no_std]
#![cfg_attr(
    not(any(
        feature = "c810-s5-qemu-qualification",
        feature = "c811-s3-qemu-qualification"
    )),
    doc = r#"
The target qualifier is structurally absent by default:

```compile_fail
use vibeos_wasm_simd_target::qualify;
```
"#
)]

#[cfg(any(
    feature = "c810-s5-qemu-qualification",
    feature = "c811-s3-qemu-qualification"
))]
extern crate alloc;

#[cfg(feature = "c810-s5-qemu-qualification")]
mod qualification {
    use alloc::vec::Vec;
    use vibeos_component_admission::{
        admit_simd_acceptance_candidate, ArtifactTrust, CallerAuthority, ComponentArtifact,
        InstanceLimits, SimdAcceptanceAdmissionPolicy, SimdCandidateError, SimdCandidatePoll,
        SimdCandidateState, SIMD_ACCEPTANCE_ACTIVATION_LABEL,
    };
    use vibeos_component_format::{
        current_validation_engine_identity, ProfileIdentity, ProfileStage, TrapCode,
    };
    use vibeos_component_runtime::{
        decode::{current_component_validation_engine, inspect_component_for_profile_4_candidate},
        world::WorldContract,
    };
    use vibeos_wasm_runtime::profile_4_candidate_required_compile_bytes;
    use vibeos_wasm_simd_candidate::{execute, CandidateValue, CANDIDATE_IDENTITY};

    include!(concat!(env!("OUT_DIR"), "/inputs.rs"));

    pub const WORLD: &str = "vibe:simd/validation@1.0.0";
    pub const WIT: &str = "package vibe:simd@1.0.0;\nworld validation {\n  export run: func(mode: u32, input: list<u8>) -> list<u8>;\n}\n";
    pub const TOTAL_FUEL: u64 = 50;
    pub const CASE_IDS: [&str; 6] = [
        "integer-lanes",
        "float-lanes",
        "nan-canonical",
        "saturation-memory",
        "fuel-adjacent",
        "component-binding",
    ];

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct LifecycleEvidence {
        pub cancellations: u64,
        pub faults: u64,
        pub recoveries: u64,
        pub reclaimed_instances: u64,
        pub revocations: u64,
        pub live_instances: u8,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct QualificationReport {
        pub cases: [bool; 6],
        pub lifecycle: LifecycleEvidence,
        pub code5_inert: bool,
        pub code7_validation_only: bool,
        pub current_engine: bool,
        pub durable_authorized: bool,
        pub release_authorized: bool,
    }

    impl QualificationReport {
        pub fn passed(&self) -> bool {
            self.cases.iter().all(|passed| *passed)
                && self.lifecycle
                    == LifecycleEvidence {
                        cancellations: 1,
                        faults: 2,
                        recoveries: 3,
                        reclaimed_instances: 4,
                        revocations: 1,
                        live_instances: 0,
                    }
                && self.code5_inert
                && self.code7_validation_only
                && !self.current_engine
                && !self.durable_authorized
                && !self.release_authorized
        }
    }

    fn values(
        bytes: &[u8],
        inputs: &[CandidateValue],
        fuel: u64,
    ) -> Option<(Vec<CandidateValue>, u64)> {
        execute(bytes, "run", inputs, fuel).ok()
    }

    pub fn qualify() -> QualificationReport {
        let lhs = CandidateValue::V128Bits(0x00000004_00000003_00000002_00000001);
        let rhs = CandidateValue::V128Bits(0x00000028_0000001e_00000014_0000000a);
        let integer = values(INTEGER_WASM, &[lhs, rhs], 10_000).is_some_and(|(result, _)| {
            result
                == [CandidateValue::V128Bits(
                    0x0000002c_00000021_00000016_0000000b,
                )]
        });

        let one = CandidateValue::V128Bits(0x3f800000_3f800000_3f800000_3f800000);
        let float = values(FLOAT_WASM, &[one, one], 10_000).is_some_and(|(result, _)| {
            result
                == [CandidateValue::V128Bits(
                    0x40000000_40000000_40000000_40000000,
                )]
        });
        let nan = CandidateValue::V128Bits(0x7fa00001_7fa00001_7fa00001_7fa00001);
        let nan_canonical = values(FLOAT_WASM, &[nan, one], 10_000).is_some_and(|(result, _)| {
            result
                == [CandidateValue::V128Bits(
                    0x7fc00000_7fc00000_7fc00000_7fc00000,
                )]
        });

        let saturation = values(
            SATURATING_WASM,
            &[
                CandidateValue::V128Bits(u128::MAX),
                CandidateValue::V128Bits(1),
            ],
            10_000,
        )
        .is_some_and(|(result, _)| result == [CandidateValue::V128Bits(u128::MAX)]);
        let memory_value = CandidateValue::V128Bits(0x0123456789abcdef_fedcba9876543210);
        let memory = values(MEMORY_WASM, &[memory_value], 10_000)
            .is_some_and(|(result, _)| result == [memory_value]);

        let fuel_inputs = [lhs, rhs];
        let fuel = values(INTEGER_WASM, &fuel_inputs, 10_000).is_some_and(|(_, used)| {
            used == 3
                && execute(INTEGER_WASM, "run", &fuel_inputs, used - 1)
                    == Err(TrapCode::FuelExhausted)
                && execute(INTEGER_WASM, "run", &fuel_inputs, used).is_ok()
        });
        let adjacent = execute(RELAXED_WASM, "run", &[], 10_000) == Err(TrapCode::Validation);
        let spin = execute(SPIN_WASM, "run", &[], 8) == Err(TrapCode::FuelExhausted);

        let world = WorldContract::parse_profile_4_sync_simd_candidate(WIT, WORLD);
        let lifecycle = world
            .ok()
            .and_then(|world| qualify_component_lifecycle(&world).ok());
        let component = lifecycle.is_some();
        let lifecycle = lifecycle.unwrap_or(LifecycleEvidence {
            cancellations: 0,
            faults: 0,
            recoveries: 0,
            reclaimed_instances: 0,
            revocations: 0,
            live_instances: 1,
        });

        let profile = ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION;
        QualificationReport {
            cases: [
                integer,
                float,
                nan_canonical,
                saturation && memory,
                fuel && adjacent && spin,
                component,
            ],
            lifecycle,
            code5_inert: current_validation_engine_identity(ProfileIdentity::PROFILE_2_SYNC_FLOAT)
                .is_none()
                && current_component_validation_engine(ProfileIdentity::PROFILE_2_SYNC_FLOAT)
                    .is_none(),
            code7_validation_only: profile.stage == ProfileStage::ValidationOnly
                && !profile.execution_enabled()
                && !CANDIDATE_IDENTITY.production_ready,
            current_engine: current_validation_engine_identity(profile).is_some()
                || current_component_validation_engine(profile).is_some(),
            durable_authorized: false,
            release_authorized: false,
        }
    }

    fn qualify_component_lifecycle(
        world: &WorldContract,
    ) -> Result<LifecycleEvidence, SimdCandidateError> {
        let artifact = ComponentArtifact::copy_from(
            COMPONENT_WASM,
            ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION,
        )
        .map_err(|_| SimdCandidateError::InvalidPlan)?;
        let plan = inspect_component_for_profile_4_candidate(COMPONENT_WASM)
            .map_err(|_| SimdCandidateError::InvalidPlan)?;
        let core = plan
            .embedded_modules()
            .first()
            .ok_or(SimdCandidateError::InvalidPlan)?;
        let compile_reservation_bytes = profile_4_candidate_required_compile_bytes(core)
            .map_err(|_| SimdCandidateError::InvalidPlan)?;
        let policy = SimdAcceptanceAdmissionPolicy {
            activation_label: SIMD_ACCEPTANCE_ACTIVATION_LABEL,
            exact_world: world,
            trust: ArtifactTrust::ImagePinned(artifact.identity()),
            limits: InstanceLimits {
                memory_bytes: 65_536,
                total_fuel: TOTAL_FUEL,
                poll_quantum: TOTAL_FUEL,
                resources: 0,
            },
            compile_reservation_bytes,
        };
        let admitted =
            admit_simd_acceptance_candidate(artifact, &policy, &CallerAuthority { offers: &[] })
                .map_err(SimdCandidateError::Admission)?;
        if !admitted
            .validated_plan()
            .map_err(SimdCandidateError::Admission)?
            .has_exact_simd_candidate_execution_binding()
        {
            return Err(SimdCandidateError::InvalidPlan);
        }
        let mut lifecycle = admitted.activate()?;
        lifecycle.start_call(0, b"qemu")?;
        if lifecycle.poll_call()? != SimdCandidatePoll::Ready(Vec::new()) {
            return Err(SimdCandidateError::InvalidPlan);
        }
        lifecycle.start_call(0, b"cancel")?;
        lifecycle.cancel()?;
        lifecycle.recover()?;
        lifecycle.start_call(1, b"fault")?;
        if lifecycle.poll_call()? != SimdCandidatePoll::Faulted(TrapCode::Validation) {
            return Err(SimdCandidateError::InvalidPlan);
        }
        lifecycle.recover()?;
        lifecycle.start_call(2, b"fuel")?;
        if lifecycle.poll_call()? != SimdCandidatePoll::Faulted(TrapCode::FuelExhausted) {
            return Err(SimdCandidateError::InvalidPlan);
        }
        lifecycle.recover()?;
        lifecycle.revoke();
        lifecycle.revoke();
        if lifecycle.state() != SimdCandidateState::Revoked
            || lifecycle.recover() != Err(SimdCandidateError::Revoked)
        {
            return Err(SimdCandidateError::InvalidPlan);
        }
        let metrics = lifecycle.metrics();
        Ok(LifecycleEvidence {
            cancellations: metrics.cancellations,
            faults: metrics.faults,
            recoveries: metrics.recoveries,
            reclaimed_instances: metrics.reclaimed_instances,
            revocations: metrics.revocations,
            live_instances: lifecycle.live_instances(),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn fixed_qemu_qualification_report_is_exact() {
            let report = qualify();
            assert!(report.passed(), "{report:?}");
            assert_eq!(INTEGER_SHA256.len(), 64);
            assert_eq!(FLOAT_SHA256.len(), 64);
            assert_eq!(COMPONENT_SHA256.len(), 64);
        }
    }
}

#[cfg(feature = "c810-s5-qemu-qualification")]
pub use qualification::*;

#[cfg(feature = "c811-s3-qemu-qualification")]
mod c811;
#[cfg(feature = "c811-s3-qemu-qualification")]
pub use c811::{qualify_c811, C811LifecycleEvidence, C811QualificationReport, C811_CASE_IDS};
