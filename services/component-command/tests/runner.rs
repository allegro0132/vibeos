use std::sync::{Arc, Mutex};

use vibeos_component_admission::{
    admit, AdmissionPolicy, ArtifactTrust, CallerAuthority, CommandStreamMode, ComponentArtifact,
    InstanceLimits, ProfileIdentity,
};
use vibeos_component_command::{
    try_manifest_from_admitted, RunnerBuildError, SynchronousCommandRunner,
};
use vibeos_component_runtime::{decode::inspect_component, world::WorldContract};
use vibeos_core::cap::Rights;
use vibeos_vsh::{
    ComponentArtifactIdentity, ComponentAuthorityRequirement, ComponentCommandFuture,
    ComponentCommandManifest, ComponentCommandResult, ComponentCommandRunner, ComponentTerminal,
    PreparedComponentStage, Session, Status, StreamMode, TerminalDetail,
};

const FILTER: &str = include_str!("fixtures/byte-filter.component.wat");
static SERIAL: Mutex<()> = Mutex::new(());

fn admitted(
    command_name: &str,
    entrypoint: &str,
    min_args: usize,
    max_args: usize,
) -> Arc<vibeos_component_admission::AdmittedComponent> {
    let bytes = wat::parse_str(FILTER).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    let world = WorldContract {
        identity: String::from("vibe:stream/filter@1.0.0"),
        imports: plan.imports,
        exports: plan.exports,
    };
    let artifact = ComponentArtifact::copy_from(&bytes, ProfileIdentity::PROFILE_1).unwrap();
    let identity = artifact.identity();
    Arc::new(
        admit(
            artifact,
            &AdmissionPolicy {
                command_name,
                entrypoint,
                min_args,
                max_args,
                exact_world: &world,
                profile: ProfileIdentity::PROFILE_1,
                trust: ArtifactTrust::ImagePinned(identity),
                limits: InstanceLimits {
                    memory_bytes: 512 * 1024,
                    total_fuel: 100_000,
                    poll_quantum: 100,
                    resources: 4,
                },
                stdin: CommandStreamMode::Required,
                stdout: CommandStreamMode::Required,
                stderr: CommandStreamMode::Optional,
                interfaces: &[],
            },
            &CallerAuthority { offers: &[] },
        )
        .unwrap(),
    )
}

fn execute(
    session: Session,
    source: &'static str,
) -> (
    Session,
    Result<Vec<vibeos_vsh::JobReport>, vibeos_vsh::Diagnostic>,
) {
    use std::sync::Mutex;
    use vibeos_core::exec;

    let result = Arc::new(Mutex::new(None));
    let result_task = result.clone();
    let session = Arc::new(Mutex::new(Some(session)));
    let session_task = session.clone();
    let task = exec::spawn_tracked("real-component-command-test", async move {
        let mut owned = session_task.lock().unwrap().take().unwrap();
        let report = owned.execute(source).await;
        *session_task.lock().unwrap() = Some(owned);
        *result_task.lock().unwrap() = Some(report);
    });
    exec::run_until_idle(100_000);
    assert!(
        task.try_exit().is_some(),
        "component command did not terminate"
    );
    let session = session.lock().unwrap().take().unwrap();
    let report = result.lock().unwrap().take().unwrap();
    (session, report)
}

#[test]
fn admitted_artifact_runs_as_a_real_vsh_pipeline_stage() {
    let _serial = SERIAL.lock().unwrap();
    let admitted = admitted("case-filter", "run", 0, 0);
    let runner = Arc::new(SynchronousCommandRunner::new(admitted.clone()).unwrap());
    let manifest = runner.manifest();
    assert_eq!(
        manifest.artifact().as_bytes(),
        admitted.identity().as_bytes()
    );
    assert_eq!(manifest.world(), "vibe:stream/filter@1.0.0");
    assert_eq!(manifest.entrypoint(), "run");
    assert_eq!(manifest.resource_limit(), 4);
    assert_eq!(manifest.total_fuel(), 100_000);
    assert_eq!(manifest.poll_quantum(), 100);

    let mut session = Session::new();
    session.install_component_command(runner.clone()).unwrap();
    let (_, reports) = execute(session, "echo AbC | case-filter > @console");
    let reports = reports.unwrap();
    assert_eq!(reports[0].status, Status::Success);
    assert_eq!(reports[0].output, "aBc*");
    assert_eq!(
        reports[0].stages[1].detail,
        TerminalDetail::Component(ComponentTerminal::Success)
    );
    assert_eq!(runner.started_invocations(), 1);
}

#[test]
fn unauthorized_later_stage_prevents_real_runner_start_and_guest_effect() {
    let _serial = SERIAL.lock().unwrap();
    let runner =
        Arc::new(SynchronousCommandRunner::new(admitted("case-filter", "run", 0, 0)).unwrap());
    struct GuardedRunner {
        manifest: ComponentCommandManifest,
    }
    impl ComponentCommandRunner for GuardedRunner {
        fn manifest(&self) -> &ComponentCommandManifest {
            &self.manifest
        }

        fn preflight(&self, _: &ComponentCommandManifest) -> Result<(), ComponentTerminal> {
            panic!("unauthorized later stage must fail before runner preflight")
        }

        fn run<'a>(&'a self, _: PreparedComponentStage) -> ComponentCommandFuture<'a> {
            Box::pin(async {
                panic!("unauthorized later stage must never run");
                #[allow(unreachable_code)]
                ComponentCommandResult::budget_exceeded()
            })
        }
    }
    let guarded = Arc::new(GuardedRunner {
        manifest: ComponentCommandManifest::new(
            "guarded-filter",
            1,
            ComponentArtifactIdentity::new([0x77; 32]),
            "vibe:stream/guarded@1.0.0",
            "run",
            0,
            0,
            StreamMode::Required,
            StreamMode::Required,
            StreamMode::Optional,
            512 * 1024,
            100_000,
            100,
            4,
            [ComponentAuthorityRequirement::new(
                "missing-filter-authority",
                "vibe:blob/blob@1.0.0",
                "blob",
                "component-blob",
                Rights::READ,
            )],
        )
        .unwrap(),
    });
    let mut session = Session::new();
    session.install_component_command(runner.clone()).unwrap();
    session.install_component_command(guarded).unwrap();
    let (_, result) = execute(session, "echo side-effect | case-filter | guarded-filter");
    let error = result.unwrap_err();
    assert_eq!(error.message, "component authority is unavailable");
    assert_eq!(runner.started_invocations(), 0);
}

#[test]
fn admitted_policy_fields_are_not_defaulted_or_dropped() {
    let admitted_component = admitted("case-filter", "run", 0, 0);
    let manifest = try_manifest_from_admitted(&admitted_component).unwrap();
    assert_eq!(manifest.min_args(), 0);
    assert_eq!(manifest.max_args(), 0);
    assert_eq!(manifest.memory_bytes(), 512 * 1024);
    assert_eq!(manifest.resource_limit(), 4);
    assert!(manifest.requirements().is_empty());

    let unsupported = admitted("case-filter-arg", "run", 0, 1);
    assert!(matches!(
        SynchronousCommandRunner::new(unsupported),
        Err(RunnerBuildError::UnsupportedArguments)
    ));
}

#[test]
fn runner_manifest_identity_cannot_be_mismatched_at_install_or_preflight() {
    let runner = SynchronousCommandRunner::new(admitted("case-filter", "run", 0, 0)).unwrap();
    let other = try_manifest_from_admitted(&admitted("other-filter", "run", 0, 0)).unwrap();
    assert_eq!(
        runner.preflight(&other),
        Err(ComponentTerminal::BackendFault)
    );

    let mut session = Session::new();
    session.install_component_command(Arc::new(runner)).unwrap();
    assert!(session
        .completion_candidates()
        .iter()
        .any(|name| name == "case-filter"));
    assert!(!session
        .completion_candidates()
        .iter()
        .any(|name| name == "other-filter"));
}

#[test]
fn only_the_exact_import_free_byte_filter_signature_is_executable() {
    let wrong_entrypoint = admitted("bad-filter", "run", 0, 0);
    assert!(SynchronousCommandRunner::new(wrong_entrypoint).is_ok());

    // The admission layer itself rejects an unpinned/missing entrypoint. The
    // runner then performs its independent exact type check on every use.
    let bytes = wat::parse_str("(component (core module (func (export \"run\") (result i32) i32.const 1)) (core instance $i (instantiate 0)) (func $f (result s32) (canon lift (core func $i \"run\"))) (export \"run\" (func $f)))").unwrap();
    let plan = inspect_component(&bytes).unwrap();
    let world = WorldContract {
        identity: String::from("vibe:stream/not-a-filter@1.0.0"),
        imports: plan.imports,
        exports: plan.exports,
    };
    let artifact = ComponentArtifact::copy_from(&bytes, ProfileIdentity::PROFILE_1).unwrap();
    let identity = artifact.identity();
    let invalid = Arc::new(
        admit(
            artifact,
            &AdmissionPolicy {
                command_name: "not-filter",
                entrypoint: "run",
                min_args: 0,
                max_args: 0,
                exact_world: &world,
                profile: ProfileIdentity::PROFILE_1,
                trust: ArtifactTrust::ImagePinned(identity),
                limits: InstanceLimits {
                    memory_bytes: 512 * 1024,
                    total_fuel: 100_000,
                    poll_quantum: 100,
                    resources: 4,
                },
                stdin: CommandStreamMode::Required,
                stdout: CommandStreamMode::Required,
                stderr: CommandStreamMode::Optional,
                interfaces: &[],
            },
            &CallerAuthority { offers: &[] },
        )
        .unwrap(),
    );
    assert!(matches!(
        SynchronousCommandRunner::new(invalid),
        Err(RunnerBuildError::UnsupportedSignature)
    ));
}

#[test]
fn aggregate_memory_limit_requires_exactly_one_runtime_instance() {
    let source = FILTER.replacen(
        "  (core instance $instance (instantiate $guest))",
        "  (core instance $spare (instantiate $guest))\n  (core instance $instance (instantiate $guest))",
        1,
    );
    assert_ne!(source, FILTER, "fixture insertion point must remain stable");
    let bytes = wat::parse_str(source).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    assert_eq!(plan.runtime_instance_count(), 2);
    let world = WorldContract {
        identity: String::from("vibe:stream/filter@1.0.0"),
        imports: plan.imports,
        exports: plan.exports,
    };
    let artifact = ComponentArtifact::copy_from(&bytes, ProfileIdentity::PROFILE_1).unwrap();
    let identity = artifact.identity();
    let admitted = Arc::new(
        admit(
            artifact,
            &AdmissionPolicy {
                command_name: "multi-filter",
                entrypoint: "run",
                min_args: 0,
                max_args: 0,
                exact_world: &world,
                profile: ProfileIdentity::PROFILE_1,
                trust: ArtifactTrust::ImagePinned(identity),
                limits: InstanceLimits {
                    memory_bytes: 512 * 1024,
                    total_fuel: 100_000,
                    poll_quantum: 100,
                    resources: 4,
                },
                stdin: CommandStreamMode::Required,
                stdout: CommandStreamMode::Required,
                stderr: CommandStreamMode::Optional,
                interfaces: &[],
            },
            &CallerAuthority { offers: &[] },
        )
        .unwrap(),
    );
    assert!(matches!(
        SynchronousCommandRunner::new(admitted),
        Err(RunnerBuildError::UnsupportedRuntimeInstances)
    ));
}

#[test]
fn runner_and_host_dispatcher_seams_remain_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SynchronousCommandRunner>();
    assert_send::<vibeos_component_host::ComponentHostDispatcher>();
    assert_send::<vibeos_component_runtime::host::RejectHost>();
}
