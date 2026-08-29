//! C8.11-S3 fixed-QEMU qualification for the independently numbered code-8 runtime.

use alloc::vec::Vec;
use vibeos_component_admission::{
    admit_simd_executable, ArtifactTrust, CallerAuthority, ComponentArtifact, InstanceLimits,
    SimdExecutableAdmissionPolicy, SimdExecutableError, SimdExecutablePoll, SimdExecutableState,
    SIMD_EXECUTABLE_ACTIVATION_LABEL,
};
use vibeos_component_format::{
    current_validation_engine_identity, ProfileIdentity, ProfileStage, TrapCode,
};
use vibeos_component_runtime::{
    decode::{current_component_validation_engine, inspect_component_for_profile},
    world::WorldContract,
};
use vibeos_wasm_runtime::{current_core_validation_engine, current_profile_required_compile_bytes};
use vibeos_wasm_simd_executable::{execute, ExecutableValue, EXECUTABLE_IDENTITY};

include!(concat!(env!("OUT_DIR"), "/inputs.rs"));

pub const C811_WORLD: &str = "vibe:simd/runtime@1.0.0";
pub const C811_WIT: &str = "package vibe:simd@1.0.0;\nworld runtime {\n  export run: func(mode: u32, input: list<u8>) -> list<u8>;\n}\n";
pub const C811_TOTAL_FUEL: u64 = 50;
pub const C811_CASE_IDS: [&str; 6] = [
    "integer-lanes",
    "float-lanes",
    "nan-canonical",
    "saturation-memory",
    "fuel-adjacent",
    "component-binding",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C811LifecycleEvidence {
    pub cancellations: u64,
    pub faults: u64,
    pub recoveries: u64,
    pub reclaimed_instances: u64,
    pub revocations: u64,
    pub live_instances: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C811QualificationReport {
    pub cases: [bool; 6],
    pub lifecycle: C811LifecycleEvidence,
    pub code5_inert: bool,
    pub code7_inert: bool,
    pub current_engine: bool,
    pub durable_authorized: bool,
    pub release_authorized: bool,
}

impl C811QualificationReport {
    pub fn passed(&self) -> bool {
        self.cases.iter().all(|value| *value)
            && self.lifecycle
                == C811LifecycleEvidence {
                    cancellations: 1,
                    faults: 2,
                    recoveries: 3,
                    reclaimed_instances: 4,
                    revocations: 1,
                    live_instances: 0,
                }
            && self.code5_inert
            && self.code7_inert
            && self.current_engine
            && !self.durable_authorized
            && !self.release_authorized
    }
}

fn values(
    bytes: &[u8],
    inputs: &[ExecutableValue],
    fuel: u64,
) -> Option<(Vec<ExecutableValue>, u64)> {
    execute(bytes, "run", inputs, fuel).ok()
}

pub fn qualify_c811() -> C811QualificationReport {
    let lhs = ExecutableValue::V128Bits(0x00000004_00000003_00000002_00000001);
    let rhs = ExecutableValue::V128Bits(0x00000028_0000001e_00000014_0000000a);
    let integer = values(INTEGER_WASM, &[lhs, rhs], 10_000).is_some_and(|(result, _)| {
        result
            == [ExecutableValue::V128Bits(
                0x0000002c_00000021_00000016_0000000b,
            )]
    });
    let one = ExecutableValue::V128Bits(0x3f800000_3f800000_3f800000_3f800000);
    let float = values(FLOAT_WASM, &[one, one], 10_000).is_some_and(|(result, _)| {
        result
            == [ExecutableValue::V128Bits(
                0x40000000_40000000_40000000_40000000,
            )]
    });
    let nan = ExecutableValue::V128Bits(0x7fa00001_7fa00001_7fa00001_7fa00001);
    let nan_canonical = values(FLOAT_WASM, &[nan, one], 10_000).is_some_and(|(result, _)| {
        result
            == [ExecutableValue::V128Bits(
                0x7fc00000_7fc00000_7fc00000_7fc00000,
            )]
    });
    let saturation = values(
        SATURATING_WASM,
        &[
            ExecutableValue::V128Bits(u128::MAX),
            ExecutableValue::V128Bits(1),
        ],
        10_000,
    )
    .is_some_and(|(result, _)| result == [ExecutableValue::V128Bits(u128::MAX)]);
    let memory_value = ExecutableValue::V128Bits(0x0123456789abcdef_fedcba9876543210);
    let memory = values(MEMORY_WASM, &[memory_value], 10_000)
        .is_some_and(|(result, _)| result == [memory_value]);
    let fuel_inputs = [lhs, rhs];
    let fuel = values(INTEGER_WASM, &fuel_inputs, 10_000).is_some_and(|(_, used)| {
        used == 3
            && execute(INTEGER_WASM, "run", &fuel_inputs, used - 1) == Err(TrapCode::FuelExhausted)
            && execute(INTEGER_WASM, "run", &fuel_inputs, used).is_ok()
    });
    let adjacent = execute(RELAXED_WASM, "run", &[], 10_000) == Err(TrapCode::Validation);
    let spin = execute(SPIN_WASM, "run", &[], 8) == Err(TrapCode::FuelExhausted);
    let lifecycle = WorldContract::parse_profile_5_sync_simd_executable(C811_WIT, C811_WORLD)
        .ok()
        .and_then(|world| qualify_lifecycle(&world).ok());
    let component = lifecycle.is_some();
    let lifecycle = lifecycle.unwrap_or(C811LifecycleEvidence {
        cancellations: 0,
        faults: 0,
        recoveries: 0,
        reclaimed_instances: 0,
        revocations: 0,
        live_instances: 1,
    });
    let profile = ProfileIdentity::PROFILE_5_SYNC_SIMD_EXECUTABLE;
    C811QualificationReport {
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
            && current_component_validation_engine(ProfileIdentity::PROFILE_2_SYNC_FLOAT).is_none(),
        code7_inert: current_validation_engine_identity(
            ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION,
        )
        .is_none()
            && current_component_validation_engine(ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION)
                .is_none(),
        current_engine: profile.stage == ProfileStage::Executable
            && profile.execution_enabled()
            && !EXECUTABLE_IDENTITY.production_ready
            && current_validation_engine_identity(profile).is_some()
            && current_component_validation_engine(profile).is_some()
            && current_core_validation_engine(profile).is_some(),
        durable_authorized: false,
        release_authorized: false,
    }
}

fn qualify_lifecycle(world: &WorldContract) -> Result<C811LifecycleEvidence, SimdExecutableError> {
    let profile = ProfileIdentity::PROFILE_5_SYNC_SIMD_EXECUTABLE;
    let artifact = ComponentArtifact::copy_from(COMPONENT_WASM, profile)
        .map_err(|_| SimdExecutableError::InvalidPlan)?;
    let plan = inspect_component_for_profile(COMPONENT_WASM, profile)
        .map_err(|_| SimdExecutableError::InvalidPlan)?;
    let core = plan
        .embedded_modules()
        .first()
        .ok_or(SimdExecutableError::InvalidPlan)?;
    let engine = current_core_validation_engine(profile).ok_or(SimdExecutableError::InvalidPlan)?;
    let compile_reservation_bytes = current_profile_required_compile_bytes(core, &engine)
        .map_err(|_| SimdExecutableError::InvalidPlan)?;
    let policy = SimdExecutableAdmissionPolicy {
        activation_label: SIMD_EXECUTABLE_ACTIVATION_LABEL,
        exact_world: world,
        trust: ArtifactTrust::ImagePinned(artifact.identity()),
        limits: InstanceLimits {
            memory_bytes: 65_536,
            total_fuel: C811_TOTAL_FUEL,
            poll_quantum: C811_TOTAL_FUEL,
            resources: 0,
        },
        compile_reservation_bytes,
    };
    let admitted = admit_simd_executable(artifact, &policy, &CallerAuthority { offers: &[] })
        .map_err(SimdExecutableError::Admission)?;
    let mut lifecycle = admitted.activate()?;
    lifecycle.start_call(0, b"qemu")?;
    if lifecycle.poll_call()? != SimdExecutablePoll::Ready(Vec::new()) {
        return Err(SimdExecutableError::InvalidPlan);
    }
    lifecycle.start_call(0, b"cancel")?;
    lifecycle.cancel()?;
    lifecycle.recover()?;
    lifecycle.start_call(1, b"fault")?;
    if lifecycle.poll_call()? != SimdExecutablePoll::Faulted(TrapCode::Validation) {
        return Err(SimdExecutableError::InvalidPlan);
    }
    lifecycle.recover()?;
    lifecycle.start_call(2, b"fuel")?;
    if lifecycle.poll_call()? != SimdExecutablePoll::Faulted(TrapCode::FuelExhausted) {
        return Err(SimdExecutableError::InvalidPlan);
    }
    lifecycle.recover()?;
    lifecycle.revoke();
    lifecycle.revoke();
    if lifecycle.state() != SimdExecutableState::Revoked
        || lifecycle.recover() != Err(SimdExecutableError::Revoked)
    {
        return Err(SimdExecutableError::InvalidPlan);
    }
    let metrics = lifecycle.metrics();
    Ok(C811LifecycleEvidence {
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
    fn fixed_qemu_code8_report_is_exact() {
        let report = qualify_c811();
        assert!(report.passed(), "{report:?}");
        assert_eq!(INTEGER_SHA256.len(), 64);
        assert_eq!(COMPONENT_SHA256.len(), 64);
    }
}
