#![cfg(feature = "native-async-command-projection")]

use vibeos_component_format::{ProfileIdentity, ProfileStage};
use vibeos_component_image_adapter::{
    project_native_async_command, NativeAsyncCommandProjection, ProjectionError,
};
use vibeos_image_policy::{NativeAsyncCommandPin, C53_NATIVE_ASYNC_COMMAND};
use vibeos_vsh::StreamMode;

#[test]
fn projection_copies_every_exact_image_field_into_vsh_metadata() {
    let projection = project_native_async_command(C53_NATIVE_ASYNC_COMMAND).unwrap();
    let manifest = projection.manifest();
    let pin = C53_NATIVE_ASYNC_COMMAND;

    assert_eq!(manifest.name(), "native-case-filter");
    assert_eq!(manifest.name(), pin.command_name());
    assert_eq!(manifest.abi(), pin.abi());
    assert_eq!(manifest.artifact().as_bytes(), &pin.expected_sha256());
    assert_eq!(manifest.world(), pin.world());
    assert_eq!(manifest.entrypoint(), pin.entrypoint());
    assert_eq!((manifest.min_args(), manifest.max_args()), (0, 0));
    assert_eq!(manifest.stdin(), StreamMode::Required);
    assert_eq!(manifest.stdout(), StreamMode::Required);
    assert_eq!(manifest.stderr(), StreamMode::Optional);
    assert_eq!(manifest.memory_bytes(), pin.limits().memory_bytes);
    assert_eq!(manifest.total_fuel(), pin.limits().total_fuel);
    assert_eq!(manifest.poll_quantum(), pin.limits().poll_quantum);
    assert_eq!(manifest.resource_limit(), pin.limits().resources);
    assert!(manifest.requirements().is_empty());
}

#[test]
fn projection_revalidates_the_inert_native_plan_without_runtime_activation() {
    let projection = project_native_async_command(C53_NATIVE_ASYNC_COMMAND).unwrap();
    for _ in 0..3 {
        let plan = projection.validated_plan().unwrap();
        assert_eq!(
            plan.profile(),
            ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE
        );
        assert_eq!(plan.profile().stage, ProfileStage::ValidationOnly);
        assert!(!plan.profile().execution_enabled());
        assert!(!plan.runtime_ready());
        assert!(!plan.native_async_runtime_ready());
        assert_eq!(plan.embedded_modules().len(), 2);
        assert_eq!(plan.runtime_instance_count(), 2);
        assert_eq!(plan.summary().resources, 0);
        assert!(plan.native_async_execution_plan().is_some());
    }
    assert_eq!(projection.manifest().resource_limit(), 8);
}

#[test]
fn the_only_factory_signature_requires_the_distinct_command_pin() {
    let factory: fn(
        NativeAsyncCommandPin,
    ) -> Result<NativeAsyncCommandProjection, ProjectionError> = project_native_async_command;
    let projection = factory(C53_NATIVE_ASYNC_COMMAND).unwrap();
    assert_eq!(projection.manifest().name(), "native-case-filter");
}

#[test]
fn projection_can_be_retained_by_the_managed_kernel_lifecycle() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<NativeAsyncCommandProjection>();
}
