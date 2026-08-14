use std::any::Any;
use std::fmt::Write as _;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use vibeos_core::cap::{CSpace, Resource, Rights};
use vibeos_core::exec;
use vibeos_core::heap::{AllocationDomain, ArenaId, OwnerId};
use vibeos_core::sync::SpinLock;
use vibeos_vsh::{
    ComponentArtifactIdentity, ComponentAuthorityRequirement, ComponentCommandFuture,
    ComponentCommandManifest, ComponentCommandResult, ComponentCommandRunner, ComponentTerminal,
    ComponentTrapCode, ManagedComponentCancel, ManagedComponentLifecycle, ManagedComponentState,
    ManagedComponentToken, PreparedComponentStage, Session, SessionProfile, SshExecComponentPolicy,
    Status, StreamMode, TerminalDetail,
};

static SERIAL: Mutex<()> = Mutex::new(());
static SUBSTITUTION_EFFECTS: AtomicUsize = AtomicUsize::new(0);
static TRACKED_BUILTIN_OK: AtomicUsize = AtomicUsize::new(0);
static TRACKED_COMPONENT_CLOSED: AtomicUsize = AtomicUsize::new(0);
static TRACKED_COMPONENT_RUNS: AtomicUsize = AtomicUsize::new(0);
static TRACKED_MANAGED_OK: AtomicUsize = AtomicUsize::new(0);

unsafe fn unexpected_tracked_test_reclaim(
    _witness: exec::ReclaimableFaultWitness,
) -> exec::FaultReclaimOutcome {
    panic!("tracked VSH compatibility test unexpectedly faulted")
}

fn execute(
    session: Session,
    source: &'static str,
) -> (
    Session,
    Result<Vec<vibeos_vsh::JobReport>, vibeos_vsh::Diagnostic>,
) {
    let result = Arc::new(Mutex::new(None));
    let result_task = result.clone();
    let session = Arc::new(Mutex::new(Some(session)));
    let session_task = session.clone();
    let task = exec::spawn_tracked("vsh-component-test", async move {
        let mut owned = session_task.lock().unwrap().take().unwrap();
        let report = owned.execute(source).await;
        *session_task.lock().unwrap() = Some(owned);
        *result_task.lock().unwrap() = Some(report);
    });
    exec::run_until_idle(100_000);
    assert!(task.try_exit().is_some(), "vsh task did not terminate");
    let session = session.lock().unwrap().take().unwrap();
    let report = result.lock().unwrap().take().unwrap();
    (session, report)
}

fn execute_with_delayed_cancel(
    mut session: Session,
    source: &'static str,
    lifecycle: &'static ManagedProbe,
) -> Vec<vibeos_vsh::JobReport> {
    let result = Arc::new(Mutex::new(None));
    let result_task = result.clone();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_task = cancel.clone();
    let task = exec::spawn_tracked("managed-cancel-vsh", async move {
        let reports = session.execute_cancellable(source, cancel_task).await;
        *result_task.lock().unwrap() = Some(reports);
    });
    let cancel_task = cancel.clone();
    let canceller = exec::spawn_tracked("managed-cancel-signal", async move {
        while lifecycle.starts.load(Ordering::Acquire) == 0 {
            exec::yield_now().await;
        }
        cancel_task.store(true, Ordering::Release);
    });

    exec::run_until_idle(100_000);
    assert_eq!(task.state(), exec::TaskState::Exited);
    assert_eq!(canceller.state(), exec::TaskState::Exited);
    let reports = result.lock().unwrap().take().unwrap().unwrap();
    reports
}

#[derive(Clone, Copy)]
enum Behavior {
    TransformUppercase,
    Terminal(ComponentTerminal),
    WaitForCancellation,
}

struct ProbeRunner {
    manifest: ComponentCommandManifest,
    preflights: AtomicUsize,
    runs: AtomicUsize,
    effects: AtomicUsize,
    behavior: Behavior,
    preflight_failure: Option<ComponentTerminal>,
    prepared_debug: Mutex<String>,
}

#[derive(Clone, Copy)]
enum ManagedBehavior {
    Complete(ComponentTerminal),
    WaitForCancellation,
    CancelLost,
    CancelAlreadyComplete(ComponentTerminal),
    Lost,
    StartError(ComponentTerminal),
}

struct ManagedProbe {
    manifest: ComponentCommandManifest,
    starts: AtomicUsize,
    state_reads: AtomicUsize,
    cancels: AtomicUsize,
    acknowledgements: AtomicUsize,
    cancelled: AtomicBool,
    behavior: ManagedBehavior,
    token_raw: NonZeroU64,
}

impl ManagedProbe {
    fn leaked(manifest: ComponentCommandManifest, behavior: ManagedBehavior) -> &'static Self {
        Box::leak(Box::new(Self {
            manifest,
            starts: AtomicUsize::new(0),
            state_reads: AtomicUsize::new(0),
            cancels: AtomicUsize::new(0),
            acknowledgements: AtomicUsize::new(0),
            cancelled: AtomicBool::new(false),
            behavior,
            token_raw: NonZeroU64::new(1).unwrap(),
        }))
    }

    fn recognizes(&self, token: ManagedComponentToken) -> bool {
        // SAFETY: only this trusted test lifecycle decodes tokens that it
        // issued, and it validates the exact lifecycle-private nonce.
        unsafe { token.trusted_raw() == self.token_raw }
    }
}

// SAFETY: this leaked test service is globally stable, owns all mutable state,
// retains no VSH references, and exposes only copy-only token/status scalars.
unsafe impl ManagedComponentLifecycle for ManagedProbe {
    fn manifest(&self) -> &ComponentCommandManifest {
        &self.manifest
    }

    fn start(&self) -> Result<ManagedComponentToken, ComponentTerminal> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        if let ManagedBehavior::StartError(terminal) = self.behavior {
            return Err(terminal);
        }
        // SAFETY: the leaked probe never reuses its single nonce for a second
        // concurrently live invocation in these serialized tests.
        Ok(unsafe { ManagedComponentToken::from_trusted_raw(self.token_raw) })
    }

    fn state(&self, token: ManagedComponentToken) -> ManagedComponentState {
        self.state_reads.fetch_add(1, Ordering::SeqCst);
        if !self.recognizes(token) {
            return ManagedComponentState::Lost;
        }
        match self.behavior {
            ManagedBehavior::Complete(terminal) => ManagedComponentState::Complete(terminal),
            ManagedBehavior::WaitForCancellation => {
                if self.cancelled.load(Ordering::Acquire) {
                    ManagedComponentState::Complete(ComponentTerminal::Cancelled)
                } else {
                    ManagedComponentState::Running
                }
            }
            ManagedBehavior::CancelLost => {
                if self.cancelled.load(Ordering::Acquire) {
                    ManagedComponentState::Lost
                } else {
                    ManagedComponentState::Running
                }
            }
            ManagedBehavior::CancelAlreadyComplete(terminal) => {
                if self.cancelled.load(Ordering::Acquire) {
                    ManagedComponentState::Complete(terminal)
                } else {
                    ManagedComponentState::Running
                }
            }
            ManagedBehavior::Lost => ManagedComponentState::Lost,
            ManagedBehavior::StartError(_) => ManagedComponentState::Lost,
        }
    }

    fn request_cancel(&self, token: ManagedComponentToken) -> ManagedComponentCancel {
        self.cancels.fetch_add(1, Ordering::SeqCst);
        if !self.recognizes(token) {
            return ManagedComponentCancel::Lost;
        }
        match self.behavior {
            ManagedBehavior::Complete(_) => ManagedComponentCancel::AlreadyComplete,
            ManagedBehavior::WaitForCancellation => {
                self.cancelled.store(true, Ordering::Release);
                ManagedComponentCancel::Requested
            }
            ManagedBehavior::CancelLost => {
                self.cancelled.store(true, Ordering::Release);
                ManagedComponentCancel::Lost
            }
            ManagedBehavior::CancelAlreadyComplete(_) => {
                self.cancelled.store(true, Ordering::Release);
                ManagedComponentCancel::AlreadyComplete
            }
            ManagedBehavior::Lost | ManagedBehavior::StartError(_) => ManagedComponentCancel::Lost,
        }
    }

    fn acknowledge_complete(&self, token: ManagedComponentToken) {
        if self.recognizes(token) {
            self.acknowledgements.fetch_add(1, Ordering::SeqCst);
        }
    }
}

struct FlippingManagedProbe {
    selected: AtomicUsize,
    starts: AtomicUsize,
    pinned: ComponentCommandManifest,
    replacement: ComponentCommandManifest,
}

// SAFETY: this deliberately adversarial test implementation is static and
// retains no caller state. It violates the semantic immutable-manifest rule so
// VSH's redundant pre-start equality gate can be exercised; `start` must and
// does remain unreachable.
unsafe impl ManagedComponentLifecycle for FlippingManagedProbe {
    fn manifest(&self) -> &ComponentCommandManifest {
        if self.selected.fetch_add(1, Ordering::SeqCst) == 0 {
            &self.pinned
        } else {
            &self.replacement
        }
    }

    fn start(&self) -> Result<ManagedComponentToken, ComponentTerminal> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        Err(ComponentTerminal::BackendFault)
    }

    fn state(&self, _token: ManagedComponentToken) -> ManagedComponentState {
        ManagedComponentState::Lost
    }

    fn request_cancel(&self, _token: ManagedComponentToken) -> ManagedComponentCancel {
        ManagedComponentCancel::Lost
    }
}

impl ProbeRunner {
    fn new(manifest: ComponentCommandManifest, behavior: Behavior) -> Arc<Self> {
        Arc::new(Self {
            manifest,
            preflights: AtomicUsize::new(0),
            runs: AtomicUsize::new(0),
            effects: AtomicUsize::new(0),
            behavior,
            preflight_failure: None,
            prepared_debug: Mutex::new(String::new()),
        })
    }
}

impl ComponentCommandRunner for ProbeRunner {
    fn manifest(&self) -> &ComponentCommandManifest {
        &self.manifest
    }

    fn preflight(&self, manifest: &ComponentCommandManifest) -> Result<(), ComponentTerminal> {
        self.preflights.fetch_add(1, Ordering::SeqCst);
        assert_eq!(manifest.entrypoint(), "run");
        self.preflight_failure.map_or(Ok(()), Err)
    }

    fn run<'a>(&'a self, stage: PreparedComponentStage) -> ComponentCommandFuture<'a> {
        Box::pin(async move {
            self.runs.fetch_add(1, Ordering::SeqCst);
            *self.prepared_debug.lock().unwrap() = format!("{stage:?}");
            match self.behavior {
                Behavior::WaitForCancellation => {
                    while !stage.cancellation().is_cancelled() {
                        exec::yield_now().await;
                    }
                    ComponentCommandResult::try_new(ComponentTerminal::Cancelled, Vec::new())
                        .unwrap()
                }
                Behavior::TransformUppercase => {
                    exec::yield_now().await;
                    if stage.cancellation().is_cancelled() {
                        return ComponentCommandResult::try_new(
                            ComponentTerminal::Cancelled,
                            Vec::new(),
                        )
                        .unwrap();
                    }
                    self.effects.fetch_add(1, Ordering::SeqCst);
                    let output = stage.input().iter().map(u8::to_ascii_uppercase).collect();
                    ComponentCommandResult::try_new(ComponentTerminal::Success, output).unwrap()
                }
                Behavior::Terminal(terminal) => {
                    exec::yield_now().await;
                    if stage.cancellation().is_cancelled() {
                        return ComponentCommandResult::try_new(
                            ComponentTerminal::Cancelled,
                            Vec::new(),
                        )
                        .unwrap();
                    }
                    self.effects.fetch_add(1, Ordering::SeqCst);
                    let output = if matches!(
                        terminal,
                        ComponentTerminal::Success | ComponentTerminal::Returned(_)
                    ) {
                        b"component\n".to_vec()
                    } else {
                        Vec::new()
                    };
                    ComponentCommandResult::try_new(terminal, output).unwrap()
                }
            }
        })
    }
}

fn manifest(
    name: &str,
    min_args: usize,
    max_args: usize,
    stdin: StreamMode,
    requirements: Vec<ComponentAuthorityRequirement>,
) -> ComponentCommandManifest {
    ComponentCommandManifest::new(
        name,
        1,
        ComponentArtifactIdentity::new([0xab; 32]),
        "test:component/demo@1.0.0",
        "run",
        min_args,
        max_args,
        stdin,
        StreamMode::Required,
        StreamMode::Optional,
        vibeos_vsh::DEFAULT_STAGE_MEMORY,
        10_000,
        100,
        256,
        requirements,
    )
    .unwrap()
}

fn runner(
    name: &str,
    min_args: usize,
    max_args: usize,
    stdin: StreamMode,
    requirements: Vec<ComponentAuthorityRequirement>,
    behavior: Behavior,
) -> Arc<ProbeRunner> {
    ProbeRunner::new(
        manifest(name, min_args, max_args, stdin, requirements),
        behavior,
    )
}

fn managed_manifest(name: &str) -> ComponentCommandManifest {
    manifest(name, 0, 0, StreamMode::Closed, Vec::new())
}

fn managed_policy(name: &str) -> SshExecComponentPolicy {
    component_policy(name, 0, 0, StreamMode::Closed, Vec::new())
}

fn component_policy(
    name: &str,
    min_args: usize,
    max_args: usize,
    stdin: StreamMode,
    requirements: Vec<ComponentAuthorityRequirement>,
) -> SshExecComponentPolicy {
    SshExecComponentPolicy::from_image_pin(
        name,
        1,
        ComponentArtifactIdentity::new([0xab; 32]),
        "test:component/demo@1.0.0",
        "run",
        min_args,
        max_args,
        stdin,
        StreamMode::Required,
        StreamMode::Optional,
        vibeos_vsh::DEFAULT_STAGE_MEMORY,
        10_000,
        100,
        256,
        requirements,
    )
    .unwrap()
}

fn blob_requirement() -> ComponentAuthorityRequirement {
    ComponentAuthorityRequirement::new(
        "blob",
        "vibe:blob/blob@1.0.0",
        "blob",
        "component-blob",
        Rights::READ,
    )
}

fn substitution_effect(_args: &[String]) -> Result<String, Status> {
    SUBSTITUTION_EFFECTS.fetch_add(1, Ordering::SeqCst);
    Ok(String::from("effect"))
}

#[test]
fn component_runner_transforms_a_bounded_pipeline_surrogate() {
    let _serial = SERIAL.lock().unwrap();
    let runner = runner(
        "upper",
        0,
        0,
        StreamMode::Required,
        Vec::new(),
        Behavior::TransformUppercase,
    );
    let mut session = Session::new();
    session.install_component_command(runner.clone()).unwrap();

    let (_session, reports) = execute(session, "echo hello | upper > @console");
    let reports = reports.unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].status, Status::Success);
    assert_eq!(reports[0].output, "HELLO\n");
    assert_eq!(reports[0].stages.len(), 2);
    assert_eq!(
        reports[0].stages[1].detail,
        TerminalDetail::Component(ComponentTerminal::Success)
    );
    assert_eq!(runner.preflights.load(Ordering::SeqCst), 1);
    assert_eq!(runner.runs.load(Ordering::SeqCst), 1);
    assert_eq!(runner.effects.load(Ordering::SeqCst), 1);
}

#[test]
fn tracked_kernel_domain_keeps_builtins_working_and_components_fail_closed() {
    let _serial = SERIAL.lock().unwrap();
    TRACKED_BUILTIN_OK.store(0, Ordering::SeqCst);
    TRACKED_COMPONENT_CLOSED.store(0, Ordering::SeqCst);
    TRACKED_COMPONENT_RUNS.store(0, Ordering::SeqCst);
    exec::set_fault_reclaimer(unexpected_tracked_test_reclaim);

    struct TrackedProbeRunner {
        manifest: ComponentCommandManifest,
    }
    impl ComponentCommandRunner for TrackedProbeRunner {
        fn manifest(&self) -> &ComponentCommandManifest {
            &self.manifest
        }

        fn preflight(&self, _manifest: &ComponentCommandManifest) -> Result<(), ComponentTerminal> {
            Ok(())
        }

        fn run<'a>(&'a self, _stage: PreparedComponentStage) -> ComponentCommandFuture<'a> {
            Box::pin(async {
                TRACKED_COMPONENT_RUNS.fetch_add(1, Ordering::SeqCst);
                ComponentCommandResult::try_new(ComponentTerminal::Success, Vec::new()).unwrap()
            })
        }
    }

    let domain = AllocationDomain::new(OwnerId::new(40_001), ArenaId::new(50_001));
    let handle = unsafe {
        exec::spawn_reclaimable_owned(domain, "tracked-vsh", async move {
            let mut session = Session::new();
            let builtin = session.execute("echo tracked > @console").await.unwrap();
            if builtin.len() == 1
                && builtin[0].status == Status::Success
                && builtin[0].output == "tracked\n"
            {
                TRACKED_BUILTIN_OK.store(1, Ordering::SeqCst);
            }

            let runner = Arc::new(TrackedProbeRunner {
                manifest: manifest("tracked-component", 0, 0, StreamMode::Closed, Vec::new()),
            });
            let policy = managed_policy("tracked-component");
            session.install_component_command(runner.clone()).unwrap();
            let rejected = session.execute("tracked-component").await.unwrap_err();
            let mut ssh = Session::with_profile(SessionProfile::SshExec);
            ssh.install_ssh_exec_component_command(&policy, runner)
                .unwrap();
            let ssh_rejected = ssh.execute("tracked-component").await.unwrap_err();
            if rejected.message == "component lifecycle registry is not installed"
                && ssh_rejected.message == "component lifecycle registry is not installed"
            {
                TRACKED_COMPONENT_CLOSED.store(1, Ordering::SeqCst);
            }
        })
    };

    exec::run_until_idle(100_000);
    assert_eq!(handle.state(), exec::TaskState::Exited);
    assert_eq!(TRACKED_BUILTIN_OK.load(Ordering::SeqCst), 1);
    assert_eq!(TRACKED_COMPONENT_CLOSED.load(Ordering::SeqCst), 1);
    assert_eq!(TRACKED_COMPONENT_RUNS.load(Ordering::SeqCst), 0);
}

#[test]
fn later_redirect_or_authority_denial_precedes_substitution_and_runner_hooks() {
    let _serial = SERIAL.lock().unwrap();
    SUBSTITUTION_EFFECTS.store(0, Ordering::SeqCst);

    let first = runner(
        "first",
        1,
        1,
        StreamMode::Closed,
        Vec::new(),
        Behavior::Terminal(ComponentTerminal::Success),
    );
    let mut redirect_session = Session::new();
    redirect_session.install_host_command("effect", 0, 0, substitution_effect);
    redirect_session
        .install_component_command(first.clone())
        .unwrap();
    let (_, redirect_error) = execute(redirect_session, "first \"$(effect)\" | wc > @missing");
    assert_eq!(redirect_error.unwrap_err().message, "unknown capability");
    assert_eq!(SUBSTITUTION_EFFECTS.load(Ordering::SeqCst), 0);
    assert_eq!(first.preflights.load(Ordering::SeqCst), 0);
    assert_eq!(first.runs.load(Ordering::SeqCst), 0);
    assert_eq!(first.effects.load(Ordering::SeqCst), 0);

    let guarded = runner(
        "guarded",
        0,
        0,
        StreamMode::Required,
        vec![ComponentAuthorityRequirement::new(
            "missing",
            "test:component/probe@1.0.0",
            "probe",
            "probe-resource",
            Rights::READ,
        )],
        Behavior::Terminal(ComponentTerminal::Success),
    );
    let mut authority_session = Session::new();
    authority_session.install_host_command("effect", 0, 0, substitution_effect);
    authority_session
        .install_component_command(first.clone())
        .unwrap();
    authority_session
        .install_component_command(guarded.clone())
        .unwrap();
    let (_, authority_error) = execute(authority_session, "first \"$(effect)\" | guarded");
    assert_eq!(
        authority_error.unwrap_err().message,
        "component authority is unavailable"
    );
    assert_eq!(SUBSTITUTION_EFFECTS.load(Ordering::SeqCst), 0);
    assert_eq!(first.preflights.load(Ordering::SeqCst), 0);
    assert_eq!(first.runs.load(Ordering::SeqCst), 0);
    assert_eq!(guarded.preflights.load(Ordering::SeqCst), 0);
    assert_eq!(guarded.runs.load(Ordering::SeqCst), 0);
    assert_eq!(guarded.effects.load(Ordering::SeqCst), 0);

    let substitution_runner = runner(
        "substitution-component",
        2,
        2,
        StreamMode::Closed,
        Vec::new(),
        Behavior::Terminal(ComponentTerminal::Success),
    );
    let mut substitution_session = Session::new();
    substitution_session.install_host_command("effect", 0, 0, substitution_effect);
    substitution_session
        .install_component_command(substitution_runner.clone())
        .unwrap();
    let (_, substitution_error) = execute(
        substitution_session,
        "substitution-component \"$(effect)\" \"$(false)\"",
    );
    assert_eq!(
        substitution_error.unwrap_err().message,
        "component pipeline substitution must be side-effect-free"
    );
    assert_eq!(SUBSTITUTION_EFFECTS.load(Ordering::SeqCst), 0);
    assert_eq!(substitution_runner.preflights.load(Ordering::SeqCst), 0);
    assert_eq!(substitution_runner.runs.load(Ordering::SeqCst), 0);
    assert_eq!(substitution_runner.effects.load(Ordering::SeqCst), 0);
}

#[test]
fn duplicate_component_install_is_rejected_without_growing_authority() {
    let _serial = SERIAL.lock().unwrap();
    let first = runner(
        "unique-component",
        0,
        0,
        StreamMode::Closed,
        Vec::new(),
        Behavior::Terminal(ComponentTerminal::Success),
    );
    let duplicate = runner(
        "unique-component",
        0,
        0,
        StreamMode::Closed,
        Vec::new(),
        Behavior::Terminal(ComponentTerminal::Success),
    );
    let mut session = Session::new();
    session.install_component_command(first).unwrap();
    let before = session.local_authority_count();
    let error = session.install_component_command(duplicate).unwrap_err();
    assert_eq!(
        error.message,
        "component command name is already registered"
    );
    assert_eq!(session.local_authority_count(), before);

    let echo_collision = session
        .install_component_command(runner(
            "echo",
            0,
            0,
            StreamMode::Closed,
            Vec::new(),
            Behavior::Terminal(ComponentTerminal::Success),
        ))
        .unwrap_err();
    assert_eq!(
        echo_collision.message,
        "component command name is already registered"
    );
    assert_eq!(session.local_authority_count(), before);
}

#[test]
fn effect_free_value_expansion_can_still_select_a_session_local_command() {
    let _serial = SERIAL.lock().unwrap();
    let mut session = Session::new();
    session.set_value("selected", "echo").unwrap();
    let (_, reports) = execute(session, "$selected preserved > @console");
    let reports = reports.unwrap();
    assert_eq!(reports[0].status, Status::Success);
    assert_eq!(reports[0].output, "preserved\n");
}

#[test]
fn component_terminal_details_do_not_fold_security_or_backend_failures() {
    let _serial = SERIAL.lock().unwrap();
    let cases = [
        ("deny-component", ComponentTerminal::Denied, Status::Denied),
        (
            "unavailable-component",
            ComponentTerminal::Unavailable,
            Status::Unavailable,
        ),
        (
            "backend-component",
            ComponentTerminal::BackendFault,
            Status::BackendFault,
        ),
        (
            "trap-component",
            ComponentTerminal::Trapped(ComponentTrapCode::new(0x0200)),
            Status::Faulted,
        ),
    ];
    for (name, terminal, status) in cases {
        let runner = runner(
            name,
            0,
            0,
            StreamMode::Closed,
            Vec::new(),
            Behavior::Terminal(terminal),
        );
        let mut session = Session::new();
        session.install_component_command(runner).unwrap();
        let source = match name {
            "deny-component" => "deny-component",
            "unavailable-component" => "unavailable-component",
            "backend-component" => "backend-component",
            _ => "trap-component",
        };
        let (_, reports) = execute(session, source);
        let report = &reports.unwrap()[0];
        assert_eq!(report.status, status);
        assert_eq!(report.stages[0].status, status);
        assert_eq!(report.stages[0].detail, TerminalDetail::Component(terminal));
        assert!(report.output.is_empty());
    }
}

#[test]
fn component_results_are_bounded_and_returned_output_is_preserved() {
    let _serial = SERIAL.lock().unwrap();
    assert_eq!(
        ComponentCommandResult::try_new(
            ComponentTerminal::Success,
            vec![0_u8; vibeos_vsh::MAX_CAPTURED_OUTPUT + 1],
        )
        .unwrap_err(),
        vibeos_vsh::ComponentCommandResultError::OutputLimit,
    );
    assert_eq!(
        ComponentCommandResult::try_new(ComponentTerminal::Denied, vec![1]).unwrap_err(),
        vibeos_vsh::ComponentCommandResultError::OutputForFailure,
    );

    let runner = runner(
        "returned-component",
        0,
        0,
        StreamMode::Closed,
        Vec::new(),
        Behavior::Terminal(ComponentTerminal::Returned(7)),
    );
    let mut session = Session::new();
    session.install_component_command(runner).unwrap();
    let (_, reports) = execute(session, "returned-component > @console");
    let report = &reports.unwrap()[0];
    assert_eq!(report.status, Status::Returned(7));
    assert_eq!(report.output, "component\n");
    assert_eq!(
        report.stages[0].detail,
        TerminalDetail::Component(ComponentTerminal::Returned(7)),
    );
}

#[test]
fn component_conditionals_background_wait_and_ctrl_c_keep_typed_semantics() {
    let _serial = SERIAL.lock().unwrap();

    let denied = runner(
        "gate",
        0,
        0,
        StreamMode::Closed,
        Vec::new(),
        Behavior::Terminal(ComponentTerminal::Denied),
    );
    let mut conditional = Session::new();
    conditional.install_component_command(denied).unwrap();
    let (_, reports) = execute(conditional, "gate || echo recovered > @console");
    let reports = reports.unwrap();
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].status, Status::Denied);
    assert_eq!(
        reports[0].stages[0].detail,
        TerminalDetail::Component(ComponentTerminal::Denied)
    );
    assert_eq!(reports[1].status, Status::Success);
    assert_eq!(reports[1].output, "recovered\n");

    let completed = runner(
        "background-component",
        0,
        0,
        StreamMode::Closed,
        Vec::new(),
        Behavior::Terminal(ComponentTerminal::Success),
    );
    let mut background = Session::new();
    background.install_component_command(completed).unwrap();
    let (background, admitted) = execute(background, "background-component &");
    assert_eq!(admitted.unwrap()[0].output, "[%1]\n");
    let (_background, waited) = execute(background, "wait %1");
    let waited = waited.unwrap();
    assert_eq!(waited[0].status, Status::Success);
    assert_eq!(waited[0].output, "component\n");
    assert_eq!(
        waited[0].stages[0].detail,
        TerminalDetail::Component(ComponentTerminal::Success)
    );

    let waiting = runner(
        "waiting-component",
        0,
        0,
        StreamMode::Closed,
        Vec::new(),
        Behavior::WaitForCancellation,
    );
    let mut cancelled = Session::new();
    cancelled.install_component_command(waiting).unwrap();
    cancelled.cancel_next_job_for_test();
    let (_, reports) = execute(cancelled, "waiting-component");
    let report = &reports.unwrap()[0];
    assert_eq!(report.status, Status::Cancelled);
    assert_eq!(
        report.stages[0].detail,
        TerminalDetail::Component(ComponentTerminal::Cancelled)
    );
    assert!(report.output.is_empty());
}

#[test]
fn component_manifest_and_debug_views_are_owned_and_redacted() {
    let _serial = SERIAL.lock().unwrap();
    let mut name = String::from("owned-component");
    let mut world = String::from("test:component/owned@1.0.0");
    let mut entrypoint = String::from("run");
    let mut requirements = vec![ComponentAuthorityRequirement::new(
        "secret",
        "test:component/probe@1.0.0",
        "probe",
        "probe-resource",
        Rights::READ,
    )];
    let manifest = ComponentCommandManifest::new(
        name.clone(),
        1,
        ComponentArtifactIdentity::new([0xab; 32]),
        world.clone(),
        entrypoint.clone(),
        0,
        0,
        StreamMode::Closed,
        StreamMode::Required,
        StreamMode::Optional,
        vibeos_vsh::DEFAULT_STAGE_MEMORY,
        10_000,
        100,
        256,
        requirements.clone(),
    )
    .unwrap();
    name.clear();
    world.clear();
    entrypoint.clear();
    requirements.clear();
    assert_eq!(manifest.name(), "owned-component");
    assert_eq!(manifest.world(), "test:component/owned@1.0.0");
    assert_eq!(manifest.entrypoint(), "run");
    assert_eq!(manifest.requirements()[0].label(), "secret");
    let debug = format!("{manifest:?}");
    assert!(debug.contains("ComponentArtifactIdentity(<redacted>)"));
    assert!(!debug.contains("abababab"));

    struct ProbeResource;
    impl Resource for ProbeResource {
        fn kind(&self) -> &'static str {
            "probe-resource"
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    let runner = ProbeRunner::new(manifest, Behavior::Terminal(ComponentTerminal::Success));
    let mut session = Session::new();
    session
        .install_capability(
            "secret",
            Arc::new(ProbeResource),
            Rights::READ.union(Rights::GRANT),
        )
        .unwrap();
    session.install_component_command(runner.clone()).unwrap();
    let (_, reports) = execute(session, "owned-component");
    let reports = reports.unwrap();
    let prepared = runner.prepared_debug.lock().unwrap().clone();
    assert!(prepared.contains("authority: \"<stage-local>\""));
    assert!(prepared.contains("execution_context: \"<stage-local>\""));
    assert!(!prepared.contains("0x"));
    assert!(!prepared.contains("cap:"));
    let report_debug = format!("{:?}", reports[0]);
    assert!(report_debug.contains("stage: 0"));
    assert!(!report_debug.contains("task:"));
    assert!(!report_debug.contains("0x"));
}

#[test]
fn component_manifest_rejects_a_zero_memory_ceiling() {
    let error = ComponentCommandManifest::new(
        "zero-memory",
        1,
        ComponentArtifactIdentity::new([0xab; 32]),
        "test:component/demo@1.0.0",
        "run",
        0,
        0,
        StreamMode::Closed,
        StreamMode::Required,
        StreamMode::Optional,
        0,
        10_000,
        100,
        1,
        Vec::new(),
    )
    .unwrap_err();
    assert_eq!(error.message, "invalid component command manifest");
}

fn leaking_ps(_args: &[String]) -> Result<String, Status> {
    Ok(String::from(
        "component:7 task:9 cap:2.4 address:0xdeadbeef\n",
    ))
}

fn safe_mem(_args: &[String]) -> Result<String, Status> {
    Ok(String::from(
        "worker state=running polls=17 budget=262144\n",
    ))
}

#[test]
fn ps_caps_mem_boundary_rejects_opaque_identifiers_before_output() {
    let _serial = SERIAL.lock().unwrap();
    for marker in [
        "cap:1.2",
        "component:7",
        "task:9",
        "cspace:3",
        "slot:1",
        "generation:2",
        "object-id:4",
        "pointer:7",
        "address:12",
        "0xcafe",
    ] {
        assert_eq!(
            vibeos_vsh::validate_observability_output(marker),
            Err(Status::BackendFault)
        );
    }
    assert_eq!(
        vibeos_vsh::validate_observability_output(
            "worker state=running polls=17 live=4096 budget=262144\n"
        ),
        Ok(())
    );

    let mut session = Session::new();
    session.install_host_command("ps", 0, 0, leaking_ps);
    let (mut session, reports) = execute(session, "ps");
    let report = &reports.unwrap()[0];
    assert_eq!(report.status, Status::BackendFault);
    assert_eq!(
        report.stages[0].detail,
        TerminalDetail::Command(Status::BackendFault)
    );
    assert!(report.output.is_empty());

    session.install_host_command("mem", 0, 0, safe_mem);
    let (_, reports) = execute(session, "mem");
    let report = &reports.unwrap()[0];
    assert_eq!(report.status, Status::Success);
    assert_eq!(
        report.output,
        "worker state=running polls=17 budget=262144\n"
    );
}

#[test]
fn tracked_ssh_exec_uses_only_the_explicit_managed_lifecycle() {
    let _serial = SERIAL.lock().unwrap();
    TRACKED_MANAGED_OK.store(0, Ordering::SeqCst);
    exec::set_fault_reclaimer(unexpected_tracked_test_reclaim);

    let lifecycle = ManagedProbe::leaked(
        managed_manifest("managed-remote"),
        ManagedBehavior::Complete(ComponentTerminal::Success),
    );
    let policy: &'static SshExecComponentPolicy =
        Box::leak(Box::new(managed_policy("managed-remote")));
    let domain = AllocationDomain::new(OwnerId::new(40_002), ArenaId::new(50_002));
    // SAFETY: the task owns its exact reclaimable domain, and the nested
    // installer call models the trusted SSH platform hook after an exact
    // accepted-profile plus independently constructed full-pin match. The
    // leaked lifecycle satisfies the managed test contract.
    let handle = unsafe {
        exec::spawn_reclaimable_owned(domain, "tracked-managed-vsh", async move {
            let mut session = Session::with_profile(SessionProfile::SshExec);
            session
                .install_ssh_exec_managed_component_command(policy, lifecycle)
                .unwrap();
            let reports = session.execute("managed-remote").await.unwrap();
            if reports.len() == 1
                && reports[0].status == Status::Success
                && reports[0].output.is_empty()
                && reports[0].stages.len() == 1
                && reports[0].stages[0].detail
                    == TerminalDetail::Component(ComponentTerminal::Success)
            {
                TRACKED_MANAGED_OK.store(1, Ordering::SeqCst);
            }
        })
    };

    exec::run_until_idle(100_000);
    assert_eq!(handle.state(), exec::TaskState::Exited);
    assert_eq!(TRACKED_MANAGED_OK.load(Ordering::SeqCst), 1);
    assert_eq!(lifecycle.starts.load(Ordering::SeqCst), 1);
    assert_eq!(lifecycle.state_reads.load(Ordering::SeqCst), 1);
    assert_eq!(lifecycle.cancels.load(Ordering::SeqCst), 0);
    assert_eq!(lifecycle.acknowledgements.load(Ordering::SeqCst), 1);
}

#[test]
fn managed_installer_requires_exact_image_and_session_policy() {
    let _serial = SERIAL.lock().unwrap();
    let lifecycle = ManagedProbe::leaked(
        managed_manifest("managed-policy"),
        ManagedBehavior::Complete(ComponentTerminal::Success),
    );
    let exact = managed_policy("managed-policy");

    let mut interactive = Session::new();
    // SAFETY: this is a negative boundary test using a static inert lifecycle;
    // it deliberately models a compromised hook and verifies the profile gate
    // rejects before consulting or starting the lifecycle.
    assert_eq!(
        unsafe { interactive.install_ssh_exec_managed_component_command(&exact, lifecycle) }
            .unwrap_err()
            .message,
        "managed SSH component policy requires an SSH exec session"
    );

    let wrong = SshExecComponentPolicy::from_image_pin(
        "managed-policy",
        1,
        ComponentArtifactIdentity::new([0xcd; 32]),
        "test:component/demo@1.0.0",
        "run",
        0,
        0,
        StreamMode::Closed,
        StreamMode::Required,
        StreamMode::Optional,
        vibeos_vsh::DEFAULT_STAGE_MEMORY,
        10_000,
        100,
        256,
        Vec::new(),
    )
    .unwrap();
    let mut ssh = Session::with_profile(SessionProfile::SshExec);
    // SAFETY: this negative test deliberately supplies a mismatched image pin
    // to the otherwise inert trusted-hook seam and verifies rejection occurs
    // before lifecycle start; no production caller may do this.
    assert_eq!(
        unsafe { ssh.install_ssh_exec_managed_component_command(&wrong, lifecycle) }
            .unwrap_err()
            .message,
        "managed component lifecycle does not match SSH image policy"
    );
    assert_eq!(lifecycle.starts.load(Ordering::SeqCst), 0);
    assert_eq!(
        execute(ssh, "managed-policy").1.unwrap_err().message,
        "command is outside the SSH exec profile"
    );
}

#[test]
fn managed_manifest_change_after_installation_is_rejected_before_start() {
    let _serial = SERIAL.lock().unwrap();
    let pinned = managed_manifest("managed-flip");
    let replacement = ComponentCommandManifest::new(
        "managed-flip",
        1,
        ComponentArtifactIdentity::new([0xcd; 32]),
        "test:component/replacement@1.0.0",
        "run",
        0,
        0,
        StreamMode::Closed,
        StreamMode::Required,
        StreamMode::Optional,
        vibeos_vsh::DEFAULT_STAGE_MEMORY,
        10_000,
        100,
        256,
        Vec::new(),
    )
    .unwrap();
    let lifecycle: &'static FlippingManagedProbe = Box::leak(Box::new(FlippingManagedProbe {
        selected: AtomicUsize::new(0),
        starts: AtomicUsize::new(0),
        pinned,
        replacement,
    }));
    let policy = managed_policy("managed-flip");
    let mut session = Session::with_profile(SessionProfile::SshExec);
    // SAFETY: this negative test deliberately installs a static adversarial
    // lifecycle whose first manifest exactly matches an independently built
    // pin. The second read changes identity; the test verifies VSH rejects it
    // before `start`, and no child or runtime payload exists.
    unsafe { session.install_ssh_exec_managed_component_command(&policy, lifecycle) }.unwrap();

    let (_, result) = execute(session, "managed-flip");
    assert_eq!(
        result.unwrap_err().message,
        "managed component manifest changed after installation"
    );
    assert_eq!(lifecycle.selected.load(Ordering::SeqCst), 2);
    assert_eq!(lifecycle.starts.load(Ordering::SeqCst), 0);
}

#[test]
fn managed_preparation_is_bound_to_the_exact_authorized_session() {
    let _serial = SERIAL.lock().unwrap();
    let lifecycle = ManagedProbe::leaked(
        managed_manifest("managed-session"),
        ManagedBehavior::Complete(ComponentTerminal::Success),
    );
    let policy: &'static SshExecComponentPolicy =
        Box::leak(Box::new(managed_policy("managed-session")));
    let rejected = Arc::new(AtomicBool::new(false));
    let rejected_task = rejected.clone();
    let task = exec::spawn_tracked("managed-session-binding", async move {
        let shared = Arc::new(SpinLock::new(CSpace::new("shared-ssh-test")));
        let mut authorized = Session::with_cspace_profile(shared.clone(), SessionProfile::SshExec);
        // SAFETY: the authorized test session models the exact accepted SSH
        // descriptor and independent full image pin; the second session is
        // intentionally not given this installation authority.
        unsafe { authorized.install_ssh_exec_managed_component_command(policy, lifecycle) }
            .unwrap();
        let mut foreign = Session::with_cspace_profile(shared, SessionProfile::SshExec);
        let script = vibeos_vsh::parse("managed-session").unwrap();
        let vibeos_vsh::Statement::Command(item) = &script.statements[0] else {
            unreachable!()
        };
        let preflight = authorized.preflight_pipeline(&item.command.first).unwrap();
        let prepare_error = match foreign.prepare_pipeline(preflight).await {
            Ok(_) => panic!("foreign session prepared an authorized managed pipeline"),
            Err(error) => error,
        };
        assert_eq!(
            prepare_error.message,
            "pipeline preflight belongs to another session"
        );

        let preflight = authorized.preflight_pipeline(&item.command.first).unwrap();
        let prepared = authorized.prepare_pipeline(preflight).await.unwrap();
        let error = prepared.commit(&mut foreign, false).await.unwrap_err();
        rejected_task.store(
            error.message == "prepared pipeline belongs to another session",
            Ordering::Release,
        );
    });

    exec::run_until_idle(100_000);
    assert_eq!(task.state(), exec::TaskState::Exited);
    assert!(rejected.load(Ordering::Acquire));
    assert_eq!(lifecycle.starts.load(Ordering::SeqCst), 0);
    assert_eq!(lifecycle.state_reads.load(Ordering::SeqCst), 0);
}

#[test]
fn managed_installer_rejects_non_scalar_component_contracts() {
    let _serial = SERIAL.lock().unwrap();
    let cases = [
        (
            manifest("managed-args", 0, 1, StreamMode::Closed, Vec::new()),
            component_policy("managed-args", 0, 1, StreamMode::Closed, Vec::new()),
        ),
        (
            manifest("managed-input", 0, 0, StreamMode::Optional, Vec::new()),
            component_policy("managed-input", 0, 0, StreamMode::Optional, Vec::new()),
        ),
        (
            manifest(
                "managed-authority",
                0,
                0,
                StreamMode::Closed,
                vec![blob_requirement()],
            ),
            component_policy(
                "managed-authority",
                0,
                0,
                StreamMode::Closed,
                vec![blob_requirement()],
            ),
        ),
    ];

    for (component_manifest, policy) in cases {
        let lifecycle = ManagedProbe::leaked(
            component_manifest,
            ManagedBehavior::Complete(ComponentTerminal::Success),
        );
        let mut session = Session::with_profile(SessionProfile::SshExec);
        // SAFETY: the fake hook supplies an exact independent pin but an
        // intentionally unsupported scalar contract, allowing the VSH gate to
        // be tested before lifecycle start without any live child.
        assert_eq!(
            unsafe { session.install_ssh_exec_managed_component_command(&policy, lifecycle) }
                .unwrap_err()
                .message,
            "managed SSH component contract is not scalar-only"
        );
        assert_eq!(lifecycle.starts.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn managed_grammar_denials_happen_before_lifecycle_start() {
    let _serial = SERIAL.lock().unwrap();
    let lifecycle = ManagedProbe::leaked(
        managed_manifest("managed-grammar"),
        ManagedBehavior::Complete(ComponentTerminal::Success),
    );
    let policy = managed_policy("managed-grammar");
    let mut session = Session::with_profile(SessionProfile::SshExec);
    // SAFETY: the test models an exact accepted SSH descriptor and independent
    // full image pin backed by a globally stable fake lifecycle.
    unsafe { session.install_ssh_exec_managed_component_command(&policy, lifecycle) }.unwrap();

    for source in [
        "managed-grammar | true",
        "managed-grammar > @console",
        "managed-grammar &",
        "managed-grammar $(true)",
        "$managed-grammar",
        "managed-grammar && true",
        "managed-grammar; true",
    ] {
        let (returned, result) = execute(session, source);
        session = returned;
        assert!(
            result.is_err(),
            "managed grammar unexpectedly admitted: {source}"
        );
        assert_eq!(
            lifecycle.starts.load(Ordering::SeqCst),
            0,
            "lifecycle started for denied grammar: {source}"
        );
        assert_eq!(lifecycle.state_reads.load(Ordering::SeqCst), 0);
        assert_eq!(lifecycle.cancels.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn managed_completion_scalars_preserve_terminal_status() {
    let _serial = SERIAL.lock().unwrap();
    let cases = [
        (
            "managed-returned",
            ManagedBehavior::Complete(ComponentTerminal::Returned(7)),
            Status::Returned(7),
            ComponentTerminal::Returned(7),
        ),
        (
            "managed-backend",
            ManagedBehavior::Complete(ComponentTerminal::BackendFault),
            Status::BackendFault,
            ComponentTerminal::BackendFault,
        ),
        (
            "managed-fault",
            ManagedBehavior::Complete(ComponentTerminal::RunnerFault),
            Status::Faulted,
            ComponentTerminal::RunnerFault,
        ),
        (
            "managed-lost",
            ManagedBehavior::Lost,
            Status::Faulted,
            ComponentTerminal::RunnerFault,
        ),
        (
            "managed-start-denied",
            ManagedBehavior::StartError(ComponentTerminal::Denied),
            Status::Denied,
            ComponentTerminal::Denied,
        ),
    ];

    for (name, behavior, status, terminal) in cases {
        let lifecycle = ManagedProbe::leaked(managed_manifest(name), behavior);
        let policy = managed_policy(name);
        let mut session = Session::with_profile(SessionProfile::SshExec);
        // SAFETY: each case models an exact accepted SSH descriptor and
        // independently pinned immutable manifest with a static fake service.
        unsafe { session.install_ssh_exec_managed_component_command(&policy, lifecycle) }.unwrap();
        let (_, reports) = execute(session, name);
        let report = &reports.unwrap()[0];
        assert_eq!(report.status, status);
        assert_eq!(report.stages[0].status, status);
        assert_eq!(report.stages[0].detail, TerminalDetail::Component(terminal));
        assert!(report.output.is_empty());
        assert_eq!(lifecycle.starts.load(Ordering::SeqCst), 1);
        let expected_acknowledgements = match behavior {
            ManagedBehavior::Complete(_) => 1,
            ManagedBehavior::Lost | ManagedBehavior::StartError(_) => 0,
            _ => unreachable!("completion table contains only terminal cases"),
        };
        assert_eq!(
            lifecycle.acknowledgements.load(Ordering::SeqCst),
            expected_acknowledgements
        );
    }
}

#[test]
fn managed_foreground_cancellation_is_cooperative_and_token_only() {
    let _serial = SERIAL.lock().unwrap();
    let lifecycle = ManagedProbe::leaked(
        managed_manifest("managed-cancel"),
        ManagedBehavior::WaitForCancellation,
    );
    let policy = managed_policy("managed-cancel");
    let mut initial = Session::with_profile(SessionProfile::SshExec);
    // SAFETY: this test models an exact accepted SSH descriptor and independent
    // full image pin backed by a globally stable fake lifecycle.
    unsafe { initial.install_ssh_exec_managed_component_command(&policy, lifecycle) }.unwrap();

    let reports = execute_with_delayed_cancel(initial, "managed-cancel", lifecycle);
    assert_eq!(reports[0].status, Status::Cancelled);
    assert_eq!(
        reports[0].stages[0].detail,
        TerminalDetail::Component(ComponentTerminal::Cancelled)
    );
    assert_eq!(lifecycle.starts.load(Ordering::SeqCst), 1);
    assert_eq!(lifecycle.cancels.load(Ordering::SeqCst), 1);
    assert!(lifecycle.state_reads.load(Ordering::SeqCst) >= 1);
    assert_eq!(lifecycle.acknowledgements.load(Ordering::SeqCst), 1);
}

#[test]
fn managed_prepublication_cancellation_never_starts_a_child() {
    let _serial = SERIAL.lock().unwrap();
    let lifecycle = ManagedProbe::leaked(
        managed_manifest("managed-pre-cancel"),
        ManagedBehavior::Complete(ComponentTerminal::Success),
    );
    let policy = managed_policy("managed-pre-cancel");
    let mut session = Session::with_profile(SessionProfile::SshExec);
    // SAFETY: this test models an exact accepted SSH descriptor and independent
    // full image pin backed by a globally stable fake lifecycle.
    unsafe { session.install_ssh_exec_managed_component_command(&policy, lifecycle) }.unwrap();
    session.cancel_next_job_for_test();

    let (_, reports) = execute(session, "managed-pre-cancel");
    let reports = reports.unwrap();
    assert_eq!(reports[0].status, Status::Cancelled);
    assert_eq!(
        reports[0].stages[0].detail,
        TerminalDetail::Component(ComponentTerminal::Cancelled)
    );
    assert_eq!(lifecycle.starts.load(Ordering::SeqCst), 0);
    assert_eq!(lifecycle.state_reads.load(Ordering::SeqCst), 0);
    assert_eq!(lifecycle.cancels.load(Ordering::SeqCst), 0);
    assert_eq!(lifecycle.acknowledgements.load(Ordering::SeqCst), 0);
}

#[test]
fn managed_cancel_lost_and_already_complete_fail_closed_without_retry() {
    let _serial = SERIAL.lock().unwrap();
    let cases = [
        (
            "managed-cancel-lost",
            ManagedBehavior::CancelLost,
            Status::Faulted,
            ComponentTerminal::RunnerFault,
        ),
        (
            "managed-cancel-complete",
            ManagedBehavior::CancelAlreadyComplete(ComponentTerminal::Success),
            Status::Success,
            ComponentTerminal::Success,
        ),
    ];

    for (name, behavior, status, terminal) in cases {
        let lifecycle = ManagedProbe::leaked(managed_manifest(name), behavior);
        let policy = managed_policy(name);
        let mut session = Session::with_profile(SessionProfile::SshExec);
        // SAFETY: each test case models an exact accepted SSH descriptor and
        // independently built full image pin with a static fake lifecycle.
        unsafe { session.install_ssh_exec_managed_component_command(&policy, lifecycle) }.unwrap();

        let reports = execute_with_delayed_cancel(session, name, lifecycle);
        assert_eq!(reports[0].status, status);
        assert_eq!(
            reports[0].stages[0].detail,
            TerminalDetail::Component(terminal)
        );
        assert_eq!(lifecycle.starts.load(Ordering::SeqCst), 1);
        assert_eq!(lifecycle.cancels.load(Ordering::SeqCst), 1);
        let expected_acknowledgements = match behavior {
            ManagedBehavior::CancelAlreadyComplete(_) => 1,
            ManagedBehavior::CancelLost => 0,
            _ => unreachable!("cancellation table contains only two cases"),
        };
        assert_eq!(
            lifecycle.acknowledgements.load(Ordering::SeqCst),
            expected_acknowledgements
        );
    }
}

#[test]
fn ssh_default_profile_does_not_gain_component_commands_implicitly() {
    let _serial = SERIAL.lock().unwrap();
    let runner = runner(
        "remote-component",
        0,
        0,
        StreamMode::Closed,
        Vec::new(),
        Behavior::Terminal(ComponentTerminal::Success),
    );
    let mut session = Session::with_profile(SessionProfile::SshExec);
    let error = session.install_component_command(runner).unwrap_err();
    assert_eq!(
        error.message,
        "component commands are outside the SSH exec profile"
    );
    assert_eq!(
        vibeos_vsh::validate_ssh_exec("remote-component")
            .unwrap_err()
            .message,
        "command is outside the SSH exec profile"
    );
    assert_eq!(
        vibeos_vsh::validate_ssh_exec_with_component_name("remote-component", "remote-component"),
        Ok(true)
    );
    assert_eq!(
        vibeos_vsh::validate_ssh_exec_with_component_name("echo builtin", "remote-component"),
        Ok(false)
    );
    for source in [
        "remote-component | true",
        "remote-component &",
        "remote-component > @console",
        "remote-component $(true)",
        "$remote-component",
    ] {
        assert!(
            vibeos_vsh::validate_ssh_exec_with_component_name(source, "remote-component").is_err()
        );
    }
}

#[test]
fn ssh_exec_installs_only_an_exact_explicit_image_session_policy() {
    let _serial = SERIAL.lock().unwrap();
    let runner = runner(
        "remote-component",
        0,
        0,
        StreamMode::Closed,
        Vec::new(),
        Behavior::Terminal(ComponentTerminal::BackendFault),
    );
    let policy = SshExecComponentPolicy::from_image_pin(
        "remote-component",
        1,
        ComponentArtifactIdentity::new([0xab; 32]),
        "test:component/demo@1.0.0",
        "run",
        0,
        0,
        StreamMode::Closed,
        StreamMode::Required,
        StreamMode::Optional,
        vibeos_vsh::DEFAULT_STAGE_MEMORY,
        10_000,
        100,
        256,
        Vec::new(),
    )
    .unwrap();
    let mut session = Session::with_profile(SessionProfile::SshExec);
    session
        .install_ssh_exec_component_command(&policy, runner.clone())
        .unwrap();

    // The public context-free validator remains the fail-closed default. Only
    // this explicitly configured session can see the policy command.
    assert_eq!(
        vibeos_vsh::validate_ssh_exec("remote-component")
            .unwrap_err()
            .message,
        "command is outside the SSH exec profile"
    );
    let (_session, reports) = execute(session, "remote-component");
    let reports = reports.unwrap();
    assert_eq!(reports[0].status, Status::BackendFault);
    assert_eq!(
        reports[0].stages[0].detail,
        TerminalDetail::Component(ComponentTerminal::BackendFault)
    );
    assert_eq!(runner.runs.load(Ordering::SeqCst), 1);
}

#[test]
fn ssh_exec_policy_installation_cannot_target_an_interactive_session() {
    let runner = runner(
        "remote-component",
        0,
        0,
        StreamMode::Closed,
        Vec::new(),
        Behavior::Terminal(ComponentTerminal::Success),
    );
    let policy = SshExecComponentPolicy::from_image_pin(
        "remote-component",
        1,
        ComponentArtifactIdentity::new([0xab; 32]),
        "test:component/demo@1.0.0",
        "run",
        0,
        0,
        StreamMode::Closed,
        StreamMode::Required,
        StreamMode::Optional,
        vibeos_vsh::DEFAULT_STAGE_MEMORY,
        10_000,
        100,
        256,
        Vec::new(),
    )
    .unwrap();
    let mut session = Session::new();
    let error = session
        .install_ssh_exec_component_command(&policy, runner)
        .unwrap_err();
    assert_eq!(
        error.message,
        "SSH component policy requires an SSH exec session"
    );
}

#[test]
fn ssh_policy_snapshots_the_exact_manifest_that_was_authorized() {
    let _serial = SERIAL.lock().unwrap();
    struct FlippingRunner {
        selected: AtomicUsize,
        pinned: ComponentCommandManifest,
        replacement: ComponentCommandManifest,
    }

    impl ComponentCommandRunner for FlippingRunner {
        fn manifest(&self) -> &ComponentCommandManifest {
            if self.selected.fetch_add(1, Ordering::SeqCst) == 0 {
                &self.pinned
            } else {
                &self.replacement
            }
        }

        fn preflight(&self, _manifest: &ComponentCommandManifest) -> Result<(), ComponentTerminal> {
            Ok(())
        }

        fn run<'a>(&'a self, _stage: PreparedComponentStage) -> ComponentCommandFuture<'a> {
            Box::pin(async {
                ComponentCommandResult::try_new(ComponentTerminal::Success, Vec::new()).unwrap()
            })
        }
    }

    let pinned = manifest("flip-component", 0, 0, StreamMode::Closed, Vec::new());
    let replacement = ComponentCommandManifest::new(
        "flip-component",
        1,
        ComponentArtifactIdentity::new([0xcd; 32]),
        "test:component/replacement@1.0.0",
        "run",
        0,
        0,
        StreamMode::Closed,
        StreamMode::Required,
        StreamMode::Optional,
        vibeos_vsh::DEFAULT_STAGE_MEMORY,
        10_000,
        100,
        256,
        Vec::new(),
    )
    .unwrap();
    let policy = SshExecComponentPolicy::from_image_pin(
        pinned.name(),
        pinned.abi(),
        pinned.artifact(),
        pinned.world(),
        pinned.entrypoint(),
        pinned.min_args(),
        pinned.max_args(),
        pinned.stdin(),
        pinned.stdout(),
        pinned.stderr(),
        pinned.memory_bytes(),
        pinned.total_fuel(),
        pinned.poll_quantum(),
        pinned.resource_limit(),
        Vec::new(),
    )
    .unwrap();
    let runner = Arc::new(FlippingRunner {
        selected: AtomicUsize::new(0),
        pinned,
        replacement,
    });
    let mut session = Session::with_profile(SessionProfile::SshExec);
    session
        .install_ssh_exec_component_command(&policy, runner.clone())
        .unwrap();

    // Installation queried exactly once and copied that authorized snapshot.
    // Execution's independent equality check observes the replacement and
    // fails closed before calling the runner.
    assert_eq!(runner.selected.load(Ordering::SeqCst), 1);
    let (_, reports) = execute(session, "flip-component");
    assert_eq!(
        reports.unwrap_err().message,
        "component runner manifest changed after installation"
    );
}

#[test]
fn ssh_exec_rejects_a_runner_that_differs_from_the_image_pin() {
    let _serial = SERIAL.lock().unwrap();
    let component_runner = runner(
        "remote-component",
        0,
        0,
        StreamMode::Closed,
        Vec::new(),
        Behavior::Terminal(ComponentTerminal::Success),
    );
    enum Mismatch {
        Name,
        Abi,
        Artifact,
        World,
        Entrypoint,
        MaxArgs,
        Stdin,
        Stdout,
        Stderr,
        Memory,
        Fuel,
        Quantum,
        Resources,
        Requirements,
    }

    for mismatch in [
        Mismatch::Name,
        Mismatch::Abi,
        Mismatch::Artifact,
        Mismatch::World,
        Mismatch::Entrypoint,
        Mismatch::MaxArgs,
        Mismatch::Stdin,
        Mismatch::Stdout,
        Mismatch::Stderr,
        Mismatch::Memory,
        Mismatch::Fuel,
        Mismatch::Quantum,
        Mismatch::Resources,
        Mismatch::Requirements,
    ] {
        let name = if matches!(mismatch, Mismatch::Name) {
            "other-component"
        } else {
            "remote-component"
        };
        let abi = if matches!(mismatch, Mismatch::Abi) {
            2
        } else {
            1
        };
        let artifact = if matches!(mismatch, Mismatch::Artifact) {
            [0xcd; 32]
        } else {
            [0xab; 32]
        };
        let world = if matches!(mismatch, Mismatch::World) {
            "test:component/other@1.0.0"
        } else {
            "test:component/demo@1.0.0"
        };
        let entrypoint = if matches!(mismatch, Mismatch::Entrypoint) {
            "other"
        } else {
            "run"
        };
        let max_args = usize::from(matches!(mismatch, Mismatch::MaxArgs));
        let stdin = if matches!(mismatch, Mismatch::Stdin) {
            StreamMode::Optional
        } else {
            StreamMode::Closed
        };
        let stdout = if matches!(mismatch, Mismatch::Stdout) {
            StreamMode::Optional
        } else {
            StreamMode::Required
        };
        let stderr = if matches!(mismatch, Mismatch::Stderr) {
            StreamMode::Closed
        } else {
            StreamMode::Optional
        };
        let memory = if matches!(mismatch, Mismatch::Memory) {
            vibeos_vsh::DEFAULT_STAGE_MEMORY + 1
        } else {
            vibeos_vsh::DEFAULT_STAGE_MEMORY
        };
        let fuel = if matches!(mismatch, Mismatch::Fuel) {
            10_001
        } else {
            10_000
        };
        let quantum = if matches!(mismatch, Mismatch::Quantum) {
            101
        } else {
            100
        };
        let resources = if matches!(mismatch, Mismatch::Resources) {
            255
        } else {
            256
        };
        let requirements = if matches!(mismatch, Mismatch::Requirements) {
            vec![ComponentAuthorityRequirement::new(
                "blob",
                "vibe:blob/blob@1.0.0",
                "blob",
                "component-blob",
                Rights::READ,
            )]
        } else {
            Vec::new()
        };
        let wrong_policy = SshExecComponentPolicy::from_image_pin(
            name,
            abi,
            ComponentArtifactIdentity::new(artifact),
            world,
            entrypoint,
            0,
            max_args,
            stdin,
            stdout,
            stderr,
            memory,
            fuel,
            quantum,
            resources,
            requirements,
        )
        .unwrap();
        let mut session = Session::with_profile(SessionProfile::SshExec);
        let error = session
            .install_ssh_exec_component_command(&wrong_policy, component_runner.clone())
            .unwrap_err();
        assert_eq!(
            error.message,
            "component runner does not match SSH image policy"
        );
        let (_session, result) = execute(session, "remote-component");
        assert_eq!(
            result.unwrap_err().message,
            "command is outside the SSH exec profile"
        );
    }

    // Exercise the remaining independent argument-range field with a valid
    // `0..=1` policy against a runner pinned to `1..=1`.
    let arg_runner = runner(
        "remote-arg-component",
        1,
        1,
        StreamMode::Closed,
        Vec::new(),
        Behavior::Terminal(ComponentTerminal::Success),
    );
    let wrong_min_args = SshExecComponentPolicy::from_image_pin(
        "remote-arg-component",
        1,
        ComponentArtifactIdentity::new([0xab; 32]),
        "test:component/demo@1.0.0",
        "run",
        0,
        1,
        StreamMode::Closed,
        StreamMode::Required,
        StreamMode::Optional,
        vibeos_vsh::DEFAULT_STAGE_MEMORY,
        10_000,
        100,
        256,
        Vec::new(),
    )
    .unwrap();
    let mut session = Session::with_profile(SessionProfile::SshExec);
    assert!(session
        .install_ssh_exec_component_command(&wrong_min_args, arg_runner.clone())
        .is_err());

    assert_eq!(component_runner.preflights.load(Ordering::SeqCst), 0);
    assert_eq!(component_runner.runs.load(Ordering::SeqCst), 0);
    assert_eq!(component_runner.effects.load(Ordering::SeqCst), 0);
    assert_eq!(arg_runner.preflights.load(Ordering::SeqCst), 0);
    assert_eq!(arg_runner.runs.load(Ordering::SeqCst), 0);
    assert_eq!(arg_runner.effects.load(Ordering::SeqCst), 0);
}

#[test]
fn component_terminal_formatting_never_contains_pointer_like_text() {
    let mut rendered = String::new();
    write!(
        &mut rendered,
        "{:?}",
        TerminalDetail::Component(ComponentTerminal::Trapped(ComponentTrapCode::new(0x0204)))
    )
    .unwrap();
    assert!(rendered.contains("ComponentTrapCode(516)"));
    assert!(!rendered.contains("0x"));
    assert!(!rendered.contains("cap:"));
    assert!(!rendered.contains("address"));
}
