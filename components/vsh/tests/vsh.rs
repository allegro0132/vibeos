use std::any::Any;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use vibeos_core::cap::{Resource, Rights};
use vibeos_core::exec;
use vibeos_vsh as vsh;
use vibeos_vsh::{ScriptManifest, ScriptRequirement, Session, SessionProfile, Statement, Status};

static SERIAL: Mutex<()> = Mutex::new(());

fn execute(
    session: Session,
    source: &'static str,
) -> (Session, Result<Vec<vsh::JobReport>, vsh::Diagnostic>) {
    let result = Arc::new(Mutex::new(None));
    let result_task = result.clone();
    let session = Arc::new(Mutex::new(Some(session)));
    let session_task = session.clone();
    let task = exec::spawn_tracked("vsh-test", async move {
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

fn execute_ssh(
    session: Session,
    source: &'static str,
) -> (Session, Result<Vec<vsh::JobReport>, vsh::Diagnostic>) {
    let result = Arc::new(Mutex::new(None));
    let result_task = result.clone();
    let session = Arc::new(Mutex::new(Some(session)));
    let session_task = session.clone();
    let task = exec::spawn_tracked("vsh-ssh-test", async move {
        let mut owned = session_task.lock().unwrap().take().unwrap();
        let report = owned
            .execute_ssh_cancellable(source, Arc::new(AtomicBool::new(false)))
            .await;
        *session_task.lock().unwrap() = Some(owned);
        *result_task.lock().unwrap() = Some(report);
    });
    exec::run_until_idle(100_000);
    assert!(
        task.try_exit().is_some(),
        "restricted vsh task did not terminate"
    );
    let session = session.lock().unwrap().take().unwrap();
    let report = result.lock().unwrap().take().unwrap();
    (session, report)
}

fn live_background_tasks() -> Vec<exec::TaskReport> {
    exec::task_report()
        .into_iter()
        .filter(|task| matches!(task.name.as_str(), "vsh-stage" | "vsh-job-supervisor"))
        .collect()
}

fn assert_background_tasks_running(expected: usize) {
    let tasks = live_background_tasks();
    assert_eq!(
        tasks.iter().filter(|task| task.name == "vsh-stage").count(),
        expected,
        "background Jobs published the wrong number of live stages"
    );
    assert_eq!(
        tasks
            .iter()
            .filter(|task| task.name == "vsh-job-supervisor")
            .count(),
        expected,
        "background Jobs published the wrong number of live supervisors"
    );
}

fn assert_no_background_tasks() {
    let tasks = live_background_tasks();
    assert!(tasks.is_empty(), "background tasks survived: {tasks:?}");
}

fn shutdown_session(mut session: Session) {
    let task = exec::spawn_tracked("vsh-shutdown-test", async move {
        session.shutdown().await;
        session.shutdown().await;
    });
    exec::run_until_idle(100_000);
    assert!(task.try_exit().is_some(), "vsh shutdown did not terminate");
}

fn drop_session(session: Session) {
    let task = exec::spawn_tracked("vsh-drop-test", async move {
        drop(session);
    });
    exec::run_until_idle(100_000);
    assert!(task.try_exit().is_some(), "vsh drop task did not terminate");
}

#[test]
fn parser_preserves_capability_value_separation_and_quotes() {
    let ast = vsh::parse("echo '$x' \"$x\" @console > @console && wc").unwrap();
    assert_eq!(ast.statements.len(), 1);
    let Statement::Command(item) = &ast.statements[0] else {
        panic!("expected command statement");
    };
    assert_eq!(item.command.first.commands[0].args.len(), 3);
    assert_eq!(item.command.rest.len(), 1);
    assert!(vsh::parse("echo hi > '$sink'").is_err());
    assert!(vsh::parse("(echo hi)").is_err());
}

#[test]
fn s4_vertical_echo_wc_pipeline() {
    let _serial = SERIAL.lock().unwrap();
    let (_session, reports) = execute(Session::new(), "echo hello | wc > @console");
    let reports = reports.unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].status, Status::Success);
    assert_eq!(reports[0].stages.len(), 2);
    assert_ne!(reports[0].stages[0].task, reports[0].stages[1].task);
    assert_eq!(reports[0].output, "1 1 6\n");
    assert!(reports[0].peak_pipe_depth <= vsh::STREAM_BUFFER_CHUNKS);
}

#[test]
fn unknown_later_stage_executes_nothing() {
    let _serial = SERIAL.lock().unwrap();
    let (_session, result) = execute(Session::new(), "echo escaped > @console | missing");
    assert_eq!(result.unwrap_err().message, "unknown command");
}

#[test]
fn expanded_text_cannot_forge_capability() {
    let _serial = SERIAL.lock().unwrap();
    let mut session = Session::new();
    session.set_value("x", "@console").unwrap();
    let (_session, reports) = execute(session, "echo $x > @console");
    assert_eq!(reports.unwrap()[0].output, "@console\n");
}

struct WrongKind;
impl Resource for WrongKind {
    fn kind(&self) -> &'static str {
        "not-a-byte-sink"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[test]
fn wrong_kind_and_missing_grant_fail_during_admission() {
    let _serial = SERIAL.lock().unwrap();
    let mut wrong = Session::new();
    wrong
        .install_capability(
            "wrong",
            Arc::new(WrongKind),
            Rights::WRITE.union(Rights::GRANT),
        )
        .unwrap();
    let (_, result) = execute(wrong, "echo no > @wrong");
    assert_eq!(
        result.unwrap_err().message,
        "output capability has wrong resource kind"
    );

    let mut no_grant = Session::new();
    assert!(no_grant.attenuate_command_for_test("wc"));
    let (_, result) = execute(no_grant, "echo no | wc > @console");
    assert_eq!(result.unwrap_err().message, "missing GRANT on command");
}

#[test]
fn typed_pipefail_prefers_fault_and_denial() {
    let _serial = SERIAL.lock().unwrap();
    let (_, reports) = execute(Session::new(), "fault > @console");
    assert_eq!(reports.unwrap()[0].status, Status::Faulted);
    let (_, reports) = execute(Session::new(), "deny > @console");
    assert_eq!(reports.unwrap()[0].status, Status::Denied);
}

#[test]
fn parent_revocation_and_ctrl_c_path_fail_closed() {
    let _serial = SERIAL.lock().unwrap();
    let mut revoked = Session::new();
    assert!(revoked.revoke_during_next_job_for_test("console"));
    let (_, reports) = execute(revoked, "echo hidden | wc > @console");
    let report = &reports.unwrap()[0];
    assert_eq!(report.status, Status::Denied);
    assert!(report.output.is_empty());

    let mut cancelled = Session::new();
    cancelled.cancel_next_job_for_test();
    let (_, reports) = execute(cancelled, "echo hidden | wc > @console");
    let report = &reports.unwrap()[0];
    assert_eq!(report.status, Status::Cancelled);
    assert!(report.output.is_empty());
}

#[test]
fn value_and_job_special_forms_are_session_local() {
    let _serial = SERIAL.lock().unwrap();
    let (session, reports) = execute(
        Session::new(),
        "let greeting hello; echo $greeting > @console",
    );
    assert_eq!(reports.unwrap()[0].output, "hello\n");

    let (session, admitted) = execute(session, "echo hello | wc > @console &");
    assert_eq!(admitted.unwrap()[0].output, "[%2]\n");
    let (session, jobs) = execute(session, "jobs");
    assert!(jobs.unwrap()[0].output.contains("%2 done"));
    let (_session, waited) = execute(session, "wait %2");
    assert_eq!(waited.unwrap()[0].output, "1 1 6\n");
}

#[test]
fn background_cancel_joins_and_releases_the_job() {
    let _serial = SERIAL.lock().unwrap();
    let (session, admitted) = execute(Session::new(), "spin &");
    assert_eq!(admitted.unwrap()[0].output, "[%1]\n");
    let (session, cancelled) = execute(session, "cancel %1");
    assert!(cancelled.unwrap().is_empty());
    let (_session, waited) = execute(session, "wait %1");
    assert_eq!(waited.unwrap()[0].status, Status::Cancelled);
}

#[test]
fn shutdown_cancels_and_joins_all_background_tasks() {
    let _serial = SERIAL.lock().unwrap();
    assert_no_background_tasks();
    let (session, admitted) = execute(Session::new(), "spin &");
    assert_eq!(admitted.unwrap()[0].output, "[%1]\n");
    let (session, admitted) = execute(session, "spin &");
    assert_eq!(admitted.unwrap()[0].output, "[%2]\n");
    assert_background_tasks_running(2);

    shutdown_session(session);

    assert_no_background_tasks();
}

#[test]
fn dropping_session_cancels_all_background_tasks() {
    let _serial = SERIAL.lock().unwrap();
    assert_no_background_tasks();
    let (session, admitted) = execute(Session::new(), "spin &");
    assert_eq!(admitted.unwrap()[0].output, "[%1]\n");
    assert_background_tasks_running(1);

    drop_session(session);

    assert_no_background_tasks();
}

#[test]
fn s5_parser_builds_control_function_and_substitution_nodes() {
    let script = vsh::parse(
        "function greet who { if false; then echo no; else echo \"$(echo $who)\"; fi; }; while false; do greet no; done",
    )
    .unwrap();
    assert_eq!(script.statements.len(), 2);
    let Statement::Function {
        name, params, body, ..
    } = &script.statements[0]
    else {
        panic!("expected function definition");
    };
    assert_eq!(name, "greet");
    assert_eq!(params, &["who"]);
    assert!(matches!(body.statements[0], Statement::If { .. }));
    assert!(matches!(script.statements[1], Statement::While { .. }));

    assert!(vsh::parse("if true; echo no; fi").is_err());
    assert!(vsh::parse("while true; do echo no").is_err());
    assert!(vsh::parse("function bad x x { true; }").is_err());
    assert!(vsh::parse("echo $(echo no").is_err());

    let multiline = vsh::parse_script("if false\nthen\n  echo no\nelse\n  echo yes\nfi\n").unwrap();
    assert!(matches!(multiline.statements[0], Statement::If { .. }));
}

#[test]
fn s5_if_while_and_function_scopes_are_bounded_and_local() {
    let _serial = SERIAL.lock().unwrap();
    let (session, reports) = execute(
        Session::new(),
        "if false; then echo hidden > @console; else echo branch > @console; fi; while false; do echo hidden > @console; done; function greet who { let prefix hello; echo \"$prefix $who\" > @console; }; greet VibeOS",
    );
    let reports = reports.unwrap();
    let output: String = reports
        .iter()
        .map(|report| report.output.as_str())
        .collect();
    assert_eq!(output, "branch\nhello VibeOS\n");
    assert_eq!(reports.last().unwrap().status, Status::Success);

    let (_session, reports) = execute(session, "echo $prefix > @console");
    assert_eq!(reports.unwrap()[0].output, "\n");
}

#[test]
fn s5_while_iteration_budget_returns_typed_failure() {
    let _serial = SERIAL.lock().unwrap();
    let (_session, reports) = execute(Session::new(), "while true; do true; done");
    let reports = reports.unwrap();
    assert_eq!(reports.last().unwrap().status, Status::BudgetExceeded);
    assert_eq!(
        reports
            .iter()
            .filter(|report| report.status == Status::BudgetExceeded)
            .count(),
        1
    );
}

#[test]
fn s5_function_recursion_and_capability_revalidation_fail_closed() {
    let _serial = SERIAL.lock().unwrap();
    let (_session, reports) = execute(Session::new(), "function recurse { recurse; }; recurse");
    assert_eq!(
        reports.unwrap().last().unwrap().status,
        Status::BudgetExceeded
    );

    let (mut session, defined) = execute(
        Session::new(),
        "function speak { echo visible > @console; }",
    );
    assert!(defined.unwrap().is_empty());
    assert!(session.revoke_capability("console"));
    let (_session, denied) = execute(session, "speak");
    assert_eq!(
        denied.unwrap_err().message,
        "default stdout cannot be delegated"
    );
}

#[test]
fn s5_command_substitution_is_bounded_isolated_and_not_reparsed() {
    let _serial = SERIAL.lock().unwrap();
    let (session, reports) = execute(
        Session::new(),
        "let outer kept; echo \"x$(let outer changed; echo inner)y\" > @console",
    );
    assert_eq!(reports.unwrap()[0].output, "xinnery\n");
    let (_session, reports) = execute(session, "echo $outer > @console");
    assert_eq!(reports.unwrap()[0].output, "kept\n");

    let (_, failed) = execute(Session::new(), "echo \"$(false)\" > @console");
    assert_eq!(failed.unwrap_err().message, "command substitution failed");
    let (_, background) = execute(Session::new(), "echo \"$(echo no &)\" > @console");
    assert_eq!(
        background.unwrap_err().message,
        "background job is not allowed in this scope"
    );
}

#[test]
fn s5_read_only_script_artifact_has_an_exact_authority_manifest() {
    let _serial = SERIAL.lock().unwrap();
    let source = "function emit what { echo $what > @console; }; let local changed; if false; then emit hidden; else emit artifact; fi";
    let manifest = ScriptManifest {
        name: "demo".into(),
        abi: 1,
        requirements: vec![ScriptRequirement {
            label: "console".into(),
            resource_kind: "byte-sink".into(),
            rights: Rights::WRITE,
        }],
    };
    let mut session = Session::new();
    session.set_value("local", "parent").unwrap();
    session.install_script("demo", source, manifest).unwrap();
    let (session, reports) = execute(session, "run-script @demo");
    let output: String = reports
        .unwrap()
        .iter()
        .map(|report| report.output.as_str())
        .collect();
    assert_eq!(output, "artifact\n");
    let (_session, reports) = execute(session, "echo $local > @console");
    assert_eq!(reports.unwrap()[0].output, "parent\n");

    let missing = ScriptManifest {
        name: "missing".into(),
        abi: 1,
        requirements: Vec::new(),
    };
    assert_eq!(
        vsh::ScriptArtifact::new("echo no > @console", missing)
            .err()
            .unwrap()
            .message,
        "script authority manifest is not exact"
    );

    let extra = ScriptManifest {
        name: "extra".into(),
        abi: 1,
        requirements: vec![ScriptRequirement {
            label: "console".into(),
            resource_kind: "byte-sink".into(),
            rights: Rights::WRITE,
        }],
    };
    assert_eq!(
        vsh::ScriptArtifact::new("true", extra)
            .err()
            .unwrap()
            .message,
        "script authority manifest is not exact"
    );

    let over_righted = ScriptManifest {
        name: "wide".into(),
        abi: 1,
        requirements: vec![ScriptRequirement {
            label: "console".into(),
            resource_kind: "byte-sink".into(),
            rights: Rights::READ.union(Rights::WRITE),
        }],
    };
    assert_eq!(
        vsh::ScriptArtifact::new("echo no > @console", over_righted)
            .err()
            .unwrap()
            .message,
        "script authority manifest is not exact"
    );
}

#[test]
fn s5_nested_script_cannot_launder_ambient_authority() {
    let _serial = SERIAL.lock().unwrap();
    let mut session = Session::new();
    session
        .install_script(
            "inner",
            "echo leaked > @console",
            ScriptManifest {
                name: "inner".into(),
                abi: 1,
                requirements: vec![ScriptRequirement {
                    label: "console".into(),
                    resource_kind: "byte-sink".into(),
                    rights: Rights::WRITE,
                }],
            },
        )
        .unwrap();
    session
        .install_script(
            "outer",
            "run-script @inner",
            ScriptManifest {
                name: "outer".into(),
                abi: 1,
                requirements: vec![ScriptRequirement {
                    label: "inner".into(),
                    resource_kind: "script-artifact".into(),
                    rights: Rights::READ,
                }],
            },
        )
        .unwrap();

    let (_session, result) = execute(session, "run-script @outer");
    assert_eq!(
        result.unwrap_err().message,
        "nested script authority exceeds caller manifest"
    );
}

#[test]
fn ssh_exec_profile_installs_only_the_explicit_command_allowlist() {
    let _serial = SERIAL.lock().unwrap();
    let session = Session::with_profile(SessionProfile::SshExec);
    let (session, reports) = execute_ssh(session, "echo restricted");
    assert_eq!(reports.unwrap()[0].output, "restricted\n");

    let (session, reports) = execute_ssh(session, "true");
    assert_eq!(reports.unwrap()[0].status, Status::Success);
    let (session, reports) = execute_ssh(session, "false");
    assert_eq!(reports.unwrap()[0].status, Status::Returned(1));

    for source in ["wc", "deny", "fault", "spin", "jobs", "let x y"] {
        assert_eq!(
            vsh::validate_ssh_exec(source).unwrap_err().message,
            "command is outside the SSH exec profile"
        );
    }

    // The profile is enforced by Session::execute too, so a trusted caller
    // cannot accidentally bypass it by selecting the general entry point.
    let (_session, result) = execute(session, "fault");
    assert_eq!(
        result.unwrap_err().message,
        "command is outside the SSH exec profile"
    );
}

#[test]
fn ssh_exec_validation_rejects_every_non_simple_form() {
    let rejected = [
        ("", "SSH exec requires exactly one command"),
        (
            "echo one; echo two",
            "SSH exec requires exactly one command",
        ),
        (
            "echo one\necho two",
            "SSH exec requires exactly one command",
        ),
        ("echo one | true", "SSH exec pipelines are not allowed"),
        ("echo one &", "SSH exec background jobs are not allowed"),
        (
            "true && echo hidden",
            "SSH exec conditional lists are not allowed",
        ),
        (
            "false || echo hidden",
            "SSH exec conditional lists are not allowed",
        ),
        (
            "if true; then echo hidden; fi",
            "SSH exec scripting syntax is not allowed",
        ),
        (
            "while false; do true; done",
            "SSH exec scripting syntax is not allowed",
        ),
        (
            "function hidden { true; }",
            "SSH exec scripting syntax is not allowed",
        ),
        ("echo $(true)", "SSH exec substitution is not allowed"),
        ("echo $value", "SSH exec substitution is not allowed"),
        ("$command", "SSH exec command name must be literal"),
        ("echo hi > @console", "SSH exec redirection is not allowed"),
        (
            "echo @console",
            "SSH exec capability arguments are not allowed",
        ),
        (
            "true unexpected",
            "command argument count rejected by SSH exec profile",
        ),
    ];
    for (source, message) in rejected {
        assert_eq!(vsh::validate_ssh_exec(source).unwrap_err().message, message);
    }
}

#[test]
fn ssh_exec_literal_input_is_bounded_and_remains_literal() {
    let _serial = SERIAL.lock().unwrap();
    let session = Session::with_profile(SessionProfile::SshExec);
    let (_session, reports) = execute_ssh(session, "echo '$x $(false) | ; >'");
    assert_eq!(reports.unwrap()[0].output, "$x $(false) | ; >\n");

    let at_limit = format!(
        "echo {}",
        "a".repeat(vsh::SSH_EXEC_MAX_INPUT_BYTES - "echo ".len())
    );
    assert_eq!(at_limit.len(), vsh::SSH_EXEC_MAX_INPUT_BYTES);
    assert!(vsh::validate_ssh_exec(&at_limit).is_ok());

    let over_limit = format!("{at_limit}a");
    assert_eq!(
        vsh::validate_ssh_exec(&over_limit).unwrap_err().message,
        "source exceeds its byte limit"
    );
}

#[test]
fn ssh_exec_api_rejects_an_interactive_session() {
    let _serial = SERIAL.lock().unwrap();
    let (_session, result) = execute_ssh(Session::new(), "true");
    assert_eq!(
        result.unwrap_err().message,
        "session does not use the SSH exec profile"
    );
}
