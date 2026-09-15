use std::sync::{Arc, Mutex};
use vibeos_core::exec::{self, TaskId, TaskState};
use vibeos_vsh::vtop::*;
use vibeos_vsh::{Session, SessionProfile, Status};

fn snapshot(now: u64, idle: u64) -> Snapshot {
    Snapshot {
        board: "QEMU virt".into(),
        now,
        timebase_hz: 1000,
        cpus: vec![Cpu {
            index: 0,
            since: 0,
            now,
            idle,
        }],
        online_cpus: 1,
        heap_live: 1024 * 1024,
        heap_peak: 2 * 1024 * 1024,
        heap_total: 16 * 1024 * 1024,
        heap_untouched: 8 * 1024 * 1024,
        tasks: 4,
        services: vec![Service {
            name: "worker".into(),
            generation: 1,
            task: TaskId(10),
            state: TaskState::Running,
            polls: now / 10,
            poll_ticks: now / 4,
            live: 1024,
            peak: 4096,
            budget: 65536,
            denials: 0,
            protected: None,
        }],
    }
}
struct Fake {
    snapshot: Mutex<Snapshot>,
    requests: Mutex<Vec<Request>>,
    pending: Mutex<bool>,
}
impl Fake {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            snapshot: Mutex::new(snapshot(1000, 500)),
            requests: Mutex::new(vec![]),
            pending: Mutex::new(false),
        })
    }
}
impl Backend for Fake {
    fn snapshot(&self) -> Snapshot {
        self.snapshot.lock().unwrap().clone()
    }
    fn control(&self, request: &Request) -> Result<Control, &'static str> {
        if let Some(reason) = self.snapshot.lock().unwrap().services[0].protected {
            return Err(reason);
        }
        self.requests.lock().unwrap().push(request.clone());
        let current = self.snapshot.lock().unwrap();
        if request.generation != current.services[0].generation
            || request.task != current.services[0].task
        {
            return Err("service generation changed; select it again");
        }
        Ok(if *self.pending.lock().unwrap() {
            Control::Pending
        } else {
            Control::Done
        })
    }
}
fn session(fake: Arc<Fake>) -> Session {
    let mut s = Session::new();
    s.install_vtop(fake);
    s
}
fn text(frame: &str) -> String {
    let mut result = String::new();
    let mut escape = 0;
    for c in frame.chars() {
        if escape == 1 {
            if c == '[' {
                escape = 2;
            } else {
                escape = 0;
            }
            continue;
        }
        if escape == 2 {
            if ('@'..='~').contains(&c) {
                escape = 0;
            }
            continue;
        }
        if c == '\x1b' {
            escape = 1;
        } else if c != '\r' {
            result.push(c);
        }
    }
    result
}

#[test]
fn cpu_uses_idle_deltas_and_service_rates_use_time_and_generation() {
    let mut sampler = Sampler::default();
    assert_eq!(sampler.sample(snapshot(1000, 500)).1.total, None);
    let (_, rates) = sampler.sample(snapshot(2000, 1250));
    assert_eq!(rates.total, Some(250));
    assert_eq!(rates.services[0].1, Some(250));
    assert_eq!(rates.services[0].2, Some(100));
    let mut restarted = snapshot(3000, 2250);
    restarted.services[0].generation += 1;
    restarted.services[0].poll_ticks = 2;
    restarted.services[0].polls = 1;
    let (_, rates) = sampler.sample(restarted);
    assert_eq!(rates.total, Some(0));
    assert_eq!(rates.services[0].1, None);
    assert_eq!(rates.services[0].2, None);
}

#[test]
fn unavailable_zero_interval_and_reset_cpu_samples_never_claim_zero_load() {
    let mut sampler = Sampler::default();
    sampler.sample(snapshot(1000, 500));
    assert_eq!(sampler.sample(snapshot(1000, 500)).1.total, None);
    assert_eq!(sampler.sample(snapshot(2000, 0)).1.total, None);
    let mut missing = snapshot(3000, 500);
    missing.online_cpus = 2;
    assert_eq!(sampler.sample(missing).1.total, None);
    let mut reactivated = snapshot(4000, 600);
    reactivated.cpus[0].since = 3500;
    assert_eq!(sampler.sample(reactivated).1.total, None);
}

#[test]
fn confirmation_binds_generation_and_removal_revokes_interactive_access() {
    let fake = Fake::new();
    let mut session = session(fake.clone());
    let mut dashboard = Dashboard::open(&session, "vtop").unwrap();
    assert!(!dashboard.key(&session, b'r'));
    assert!(fake.requests.lock().unwrap().is_empty());
    fake.snapshot.lock().unwrap().services[0].generation = 2;
    dashboard.refresh(&session).unwrap();
    dashboard.key(&session, b'y');
    assert_eq!(fake.requests.lock().unwrap()[0].generation, 1);
    assert!(text(&dashboard.render(80, 24)).contains("generation changed"));
    session.remove_command("vtop");
    assert_eq!(dashboard.refresh(&session), Err(Status::Unavailable));
    assert!(session
        .vtop_control(&Request {
            name: "worker".into(),
            generation: 2,
            task: TaskId(10),
            action: Action::Stop
        })
        .is_err());
    assert_eq!(fake.requests.lock().unwrap().len(), 1);
}

#[test]
fn pending_actions_are_bounded_and_no_duplicate_confirmations_are_dispatched() {
    let fake = Fake::new();
    let session = session(fake.clone());
    *fake.pending.lock().unwrap() = true;
    let mut dashboard = Dashboard::open(&session, "vtop").unwrap();
    dashboard.key(&session, b'r');
    dashboard.key(&session, b'y');
    dashboard.key(&session, b'x');
    dashboard.key(&session, b'y');
    assert_eq!(fake.requests.lock().unwrap().len(), 1);
    fake.snapshot.lock().unwrap().now += 6000;
    dashboard.refresh(&session).unwrap();
    assert!(text(&dashboard.render(80, 24)).contains("Still stopping"));
    assert_eq!(fake.requests.lock().unwrap().len(), 1);
}

#[test]
fn filtering_sorting_paging_and_protected_rows_are_transport_independent() {
    let fake = Fake::new();
    {
        let mut state = fake.snapshot.lock().unwrap();
        state.services[0].protected = Some("protected: console");
        for i in 0..40 {
            let mut service = state.services[0].clone();
            service.name = format!("service{i:02}");
            service.protected = None;
            state.services.push(service);
        }
    }
    let session = session(fake.clone());
    let mut dashboard = Dashboard::open(&session, "vtop").unwrap();
    dashboard.key(&session, b'x');
    dashboard.key(&session, b'y');
    assert!(fake.requests.lock().unwrap().is_empty());
    for b in b"/service39\r" {
        dashboard.key(&session, *b);
    }
    assert!(text(&dashboard.render(80, 24)).contains("> service39"));
    dashboard.key(&session, b'r');
    dashboard.key(&session, b'n');
    assert!(fake.requests.lock().unwrap().is_empty());
    dashboard.key(&session, 27);
    assert!(dashboard.key(&session, b'q'));
    let mut dashboard = Dashboard::open(&session, "vtop").unwrap();
    for b in b"nk\x1b[A" {
        dashboard.key(&session, *b);
    }
    assert!(text(&dashboard.render(80, 24)).contains("> service38"));
}

#[test]
fn frames_are_bounded_ascii_and_do_not_admit_terminal_injection() {
    let fake = Fake::new();
    fake.snapshot.lock().unwrap().board = "board\x1b[2J\nspoof".into();
    fake.snapshot.lock().unwrap().services[0].name = "test\x1b[?1049l".into();
    let session = session(fake);
    let dashboard = Dashboard::open(&session, "vtop").unwrap();
    for (cols, rows) in [
        (80, 24),
        (56, 16),
        (10, 3),
        (1, 2),
        (0, 0),
        (usize::MAX, usize::MAX),
    ] {
        let rendered = dashboard.render(cols, rows);
        assert!(!rendered.contains("\x1b[2J"));
        assert!(!rendered.contains("\x1b[?1049l"));
        assert!(rendered.len() < 13000);
        let plain = text(&rendered);
        let width = if cols == 0 {
            79
        } else {
            cols.clamp(1, 160) - 1
        };
        let height = if rows == 0 { 23 } else { rows.clamp(2, 60) - 1 };
        assert!(plain.lines().count() <= height);
        assert!(plain.lines().all(|line| line.len() <= width));
    }
    assert_eq!(bytes(1024 * 1024), "1.0 MiB");
    assert!(!bytes(usize::MAX).is_empty());
}

#[test]
fn restricted_profiles_and_shell_syntax_cannot_open_or_smuggle_vtop() {
    let fake = Fake::new();
    let mut restricted = Session::with_profile(SessionProfile::SshExec);
    restricted.install_vtop(fake.clone());
    assert!(Dashboard::open(&restricted, "vtop").is_none());
    assert!(!restricted
        .completion_candidates()
        .iter()
        .any(|s| s == "vtop"));
    let session = session(fake);
    for source in [
        "vtop --once",
        "vtop | wc",
        "vtop &",
        "echo vtop",
        "vtop; reboot",
    ] {
        assert!(Dashboard::open(&session, source).is_none());
    }
}

#[test]
fn command_failures_have_nonzero_status_and_cancelled_waits_do_not_restart() {
    let fake = Fake::new();
    let result = Arc::new(Mutex::new(None));
    let result_task = result.clone();
    let fake_task = fake.clone();
    let handle = exec::spawn_tracked("vtop-command-test", async move {
        let mut session = session(fake_task.clone());
        // A stale generation is rejected by the fake backend after a pending
        // request, exactly like a concurrent supervisor restart.
        *fake_task.pending.lock().unwrap() = true;
        let cancel = Arc::new(vibeos_vsh::CancellationSignal::new());
        cancel.cancel();
        let cancelled = session
            .execute_cancellable("vtop restart worker", cancel)
            .await
            .unwrap();
        assert_eq!(cancelled[0].status, Status::Cancelled);
        let reports = session.execute("vtop --help").await.unwrap();
        assert_eq!(reports[0].status, Status::Success);
        assert!(reports[0].output.contains("start|stop|restart"));
        fake_task.snapshot.lock().unwrap().services[0].protected = Some("protected: console");
        let denied = session.execute("vtop stop worker").await.unwrap();
        assert_eq!(denied[0].status, Status::Returned(1));
        assert!(denied[0].output.contains("protected: console"));
        let reports = session.execute("vtop unknown worker").await.unwrap();
        assert_eq!(reports[0].status, Status::Usage);
        let backend: Arc<dyn Backend> = fake_task.clone();
        let reply = command(&backend, &["restart".into(), "worker".into()], || false).await;
        assert_eq!(reply.unwrap_err(), Status::Cancelled);
        assert!(session.execute("echo $(vtop stop worker)").await.is_err());
        *result_task.lock().unwrap() = Some(());
    });
    for _ in 0..100 {
        exec::run_until_idle(100_000);
        if handle.try_exit().is_some() {
            break;
        }
        vibeos_core::arch::advance_time(exec::timebase_hz() / 10);
        exec::timer_tick();
    }
    assert!(handle.try_exit().is_some());
    assert!(result.lock().unwrap().is_some());
    assert!(fake.requests.lock().unwrap().is_empty());
}

#[test]
fn reused_name_and_generation_cannot_retarget_an_old_confirmation() {
    let fake = Fake::new();
    let session = session(fake.clone());
    let mut dashboard = Dashboard::open(&session, "vtop").unwrap();
    dashboard.key(&session, b'r');
    fake.snapshot.lock().unwrap().services[0].task = TaskId(11);
    dashboard.key(&session, b'y');
    assert_eq!(fake.requests.lock().unwrap()[0].task, TaskId(10));
    assert!(text(&dashboard.render(80, 24)).contains("generation changed"));
    let frame = text(&dashboard.render(80, 24));
    assert!(!frame.contains("TaskId"));
}
