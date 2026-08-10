use std::any::Any;
use std::sync::{Arc, Mutex};

use vibeos_core::cap::{Resource, Rights};
use vibeos_core::exec;
use vibeos_core::vsh::{self, Session, Status};

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

#[test]
fn parser_preserves_capability_value_separation_and_quotes() {
    let ast = vsh::parse("echo '$x' \"$x\" @console > @console && wc").unwrap();
    assert_eq!(ast.items.len(), 1);
    assert_eq!(ast.items[0].command.first.commands[0].args.len(), 3);
    assert_eq!(ast.items[0].command.rest.len(), 1);
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
    let (session, reports) = execute(Session::new(), "let greeting hello; echo $greeting > @console");
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
