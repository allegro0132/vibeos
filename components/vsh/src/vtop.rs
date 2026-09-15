//! Bounded, transport-independent system monitor. Only an installed VSH
//! command capability can obtain snapshots or request lifecycle operations.
use crate::{Session, Status};
use alloc::{collections::VecDeque, format, string::String, sync::Arc, vec::Vec};
use core::fmt::Write;
use vibeos_core::exec::{TaskId, TaskState};

pub const ENTER: &str = "\x1b[?1049h\x1b[?25l\x1b[2J";
pub const LEAVE: &str = "\x1b[0m\x1b[?25h\x1b[?1049l";
pub const INTERVAL_MS: u64 = 1000;
const HISTORY: usize = 48;

#[derive(Clone, Debug)]
pub struct Cpu {
    pub index: usize,
    pub since: u64,
    pub now: u64,
    pub idle: u64,
}

#[derive(Clone, Debug)]
pub struct Service {
    pub name: String,
    pub generation: u64,
    /// Exact task identity is used only for control, never rendered.
    pub task: TaskId,
    pub state: TaskState,
    pub polls: u64,
    pub poll_ticks: u64,
    pub live: usize,
    pub peak: usize,
    pub budget: usize,
    pub denials: u64,
    /// A short explanation for services the current transport cannot manage.
    pub protected: Option<&'static str>,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub board: String,
    pub now: u64,
    pub timebase_hz: u64,
    pub cpus: Vec<Cpu>,
    pub online_cpus: usize,
    pub heap_live: usize,
    pub heap_peak: usize,
    pub heap_total: usize,
    pub heap_untouched: usize,
    pub tasks: usize,
    pub services: Vec<Service>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Start,
    Stop,
    Restart,
}
impl Action {
    pub fn label(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub name: String,
    pub generation: u64,
    /// Exact task identity is used only for control, never rendered.
    pub task: TaskId,
    pub action: Action,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    Done,
    Pending,
}

pub trait Backend: Send + Sync {
    fn snapshot(&self) -> Snapshot;
    /// The backend must check the exact generation and its own management
    /// policy on every call. Pending means cancellation awaits a poll boundary.
    fn control(&self, request: &Request) -> Result<Control, &'static str>;
}

/// CPU residency and service rates use interval deltas, never poll counts as
/// an approximation for CPU time. Missing/reset samples remain unavailable.
#[derive(Default)]
pub struct Sampler {
    previous: Option<Snapshot>,
}
#[derive(Clone, Debug)]
pub struct Rates {
    pub cpu: Vec<(usize, Option<u16>)>,
    pub total: Option<u16>,
    pub services: Vec<(String, Option<u16>, Option<u64>)>,
}

fn ratio(numerator: u64, denominator: u64) -> Option<u16> {
    if denominator == 0 {
        return None;
    }
    Some(((u128::from(numerator) * 1000 / u128::from(denominator)).min(1000)) as u16)
}

impl Sampler {
    pub fn sample(&mut self, snapshot: Snapshot) -> (Snapshot, Rates) {
        let previous = self.previous.as_ref();
        let cpu: Vec<_> = snapshot
            .cpus
            .iter()
            .map(|cpu| {
                let load = previous
                    .and_then(|p| {
                        p.cpus
                            .iter()
                            .find(|p| p.index == cpu.index && p.since == cpu.since)
                    })
                    .and_then(|p| {
                        let elapsed = cpu.now.checked_sub(p.now)?;
                        let idle = cpu.idle.checked_sub(p.idle)?;
                        ratio(elapsed.checked_sub(idle)?, elapsed)
                    });
                (cpu.index, load)
            })
            .collect();
        let total = if cpu.len() == snapshot.online_cpus
            && !cpu.is_empty()
            && cpu.iter().all(|(_, v)| v.is_some())
        {
            Some(
                (cpu.iter().map(|(_, v)| u64::from(v.unwrap())).sum::<u64>() / cpu.len() as u64)
                    as u16,
            )
        } else {
            None
        };
        let services = snapshot
            .services
            .iter()
            .map(|service| {
                let old = previous.and_then(|p| {
                    p.services.iter().find(|p| {
                        p.name == service.name
                            && p.generation == service.generation
                            && p.task == service.task
                    })
                });
                let elapsed = previous
                    .and_then(|p| snapshot.now.checked_sub(p.now))
                    .filter(|d| *d > 0);
                let cpu = old
                    .zip(elapsed)
                    .and_then(|(p, d)| ratio(service.poll_ticks.checked_sub(p.poll_ticks)?, d));
                let polls = old.zip(elapsed).and_then(|(p, d)| {
                    let delta = service.polls.checked_sub(p.polls)?;
                    Some(
                        (u128::from(delta) * u128::from(snapshot.timebase_hz) / u128::from(d))
                            .min(u128::from(u64::MAX)) as u64,
                    )
                });
                (service.name.clone(), cpu, polls)
            })
            .collect();
        self.previous = Some(snapshot.clone());
        (
            snapshot,
            Rates {
                cpu,
                total,
                services,
            },
        )
    }
}

pub fn bytes(value: usize) -> String {
    let (divisor, unit) = if value >= 1024 * 1024 * 1024 {
        (1024 * 1024 * 1024, "GiB")
    } else if value >= 1024 * 1024 {
        (1024 * 1024, "MiB")
    } else if value >= 1024 {
        (1024, "KiB")
    } else {
        return format!("{value} B");
    };
    format!(
        "{}.{:01} {unit}",
        value / divisor,
        (value % divisor) * 10 / divisor
    )
}
fn percent(value: Option<u16>) -> String {
    value.map_or_else(
        || String::from("--"),
        |v| format!("{}.{:01}%", v / 10, v % 10),
    )
}
fn bar(value: Option<u16>, width: usize) -> String {
    let filled = usize::from(value.unwrap_or(0)) * width / 1000;
    format!("{}{}", "|".repeat(filled), ".".repeat(width - filled))
}
fn safe(text: &str, width: usize) -> String {
    // Device/service names can never inject terminal controls or expand a row.
    text.chars()
        .take(width)
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect()
}
fn uptime(snapshot: &Snapshot) -> String {
    let seconds = snapshot.now / snapshot.timebase_hz.max(1);
    format!(
        "{}d {:02}:{:02}:{:02}",
        seconds / 86400,
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60
    )
}

pub const HELP: &str = "vtop                         live resource and service dashboard (UART / SSH PTY)\nvtop --once                  plain snapshot for scripts and pipes\nvtop start|stop|restart NAME  manage an audited service\n\nKeys: arrows/j/k select, c CPU sort, m memory sort, n name sort, / filter\n      s start, x stop, r restart, y confirm, Esc cancel, Space pause, q quit\nCPU = non-WFI residency; service CPU = task poll time (one core = 100%).\nHeap = allocator capacity, not all physical RAM; -- = awaiting a sample.\n";

pub async fn command(
    backend: &Arc<dyn Backend>,
    args: &[String],
    mut live: impl FnMut() -> bool,
) -> Result<(String, Status), Status> {
    if !live() {
        return Err(Status::Cancelled);
    }
    match args {
        _ if args.is_empty() || (args.len() == 1 && args[0] == "--once") => {
            let mut sampler = Sampler::default();
            sampler.sample(backend.snapshot());
            vibeos_core::exec::sleep_ms(200).await;
            if !live() {
                return Err(Status::Cancelled);
            }
            let (snapshot, rates) = sampler.sample(backend.snapshot());
            Ok((plain(&snapshot, &rates), Status::Success))
        }
        [help] if help == "--help" || help == "-h" => Ok((String::from(HELP), Status::Success)),
        [action, name] => {
            let action = match action.as_str() {
                "start" => Action::Start,
                "stop" => Action::Stop,
                "restart" => Action::Restart,
                _ => return Err(Status::Usage),
            };
            let snapshot = backend.snapshot();
            let service = snapshot
                .services
                .iter()
                .find(|s| s.name == *name)
                .ok_or(Status::Unavailable)?;
            let request = Request {
                name: name.clone(),
                generation: service.generation,
                task: service.task,
                action,
            };
            // Bounded cooperative wait. A cancelled shell job never starts a
            // fresh incarnation after its authority has disappeared.
            for _ in 0..100 {
                if !live() {
                    return Err(Status::Cancelled);
                }
                match backend.control(&request) {
                    Ok(Control::Done) => {
                        return Ok((
                            format!("{}: {} complete\n", safe(name, 64), action.label()),
                            Status::Success,
                        ))
                    }
                    Err(error) => {
                        return Ok((format!("vtop: {}\n", safe(error, 160)), Status::Returned(1)))
                    }
                    Ok(Control::Pending) => vibeos_core::exec::sleep_ms(50).await,
                }
            }
            Ok((
                String::from("vtop: still stopping; inspect the service before retrying\n"),
                Status::Returned(1),
            ))
        }
        _ => Err(Status::Usage),
    }
}

pub fn plain(snapshot: &Snapshot, rates: &Rates) -> String {
    let mut out = format!(
        "VTOP | {} | up {} | {} CPUs | {} tasks\nCPU {} | heap {} / {} | peak {} | untouched {}\n",
        safe(&snapshot.board, 40),
        uptime(snapshot),
        snapshot.online_cpus,
        snapshot.tasks,
        percent(rates.total),
        bytes(snapshot.heap_live),
        bytes(snapshot.heap_total),
        bytes(snapshot.heap_peak),
        bytes(snapshot.heap_untouched)
    );
    out.push_str("SERVICE              STATE       CPU     POLL/s       LIVE       PEAK      LIMIT  ACCESS\n");
    for service in &snapshot.services {
        let rate = rates
            .services
            .iter()
            .find(|(name, _, _)| *name == service.name);
        let _ = writeln!(
            out,
            "{:<20} {:<10} {:>6} {:>10} {:>10} {:>10} {:>10}  {}",
            safe(&service.name, 20),
            format!("{}", service.state),
            percent(rate.and_then(|r| r.1)),
            rate.and_then(|r| r.2)
                .map_or_else(|| String::from("--"), |v| format!("{v}")),
            bytes(service.live),
            bytes(service.peak),
            if service.budget == usize::MAX {
                String::from("unlimited")
            } else {
                bytes(service.budget)
            },
            service.protected.unwrap_or("manage")
        );
    }
    out.push_str("CPU: non-WFI residency; service CPU: poll time. --: awaiting interval sample.\n");
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sort {
    Cpu,
    Memory,
    Name,
}
#[derive(Clone, Copy)]
enum Escape {
    Ground,
    Escape,
    Csi,
}

/// One session's UI state. History, filter, confirmation and pending lifecycle
/// action never leak between UART and SSH or between SSH connections.
pub struct Dashboard {
    sampler: Sampler,
    snapshot: Snapshot,
    rates: Rates,
    history: VecDeque<Option<u16>>,
    selected: Option<String>,
    sort: Sort,
    filter: String,
    filtering: bool,
    paused: bool,
    help: bool,
    confirm: Option<Request>,
    pending: Option<(Request, u64)>,
    notice: String,
    escape: Escape,
}

impl Dashboard {
    pub fn open(session: &Session, source: &str) -> Option<Self> {
        if source.trim() != "vtop" {
            return None;
        }
        let snapshot = session.vtop_snapshot().ok()?;
        let mut sampler = Sampler::default();
        let (snapshot, rates) = sampler.sample(snapshot);
        let selected = snapshot.services.first().map(|s| s.name.clone());
        Some(Self {
            sampler,
            snapshot,
            rates,
            history: VecDeque::new(),
            selected,
            sort: Sort::Cpu,
            filter: String::new(),
            filtering: false,
            paused: false,
            help: false,
            confirm: None,
            pending: None,
            notice: String::from(
                "Sampling...  Select a service to inspect its memory and controls.",
            ),
            escape: Escape::Ground,
        })
    }

    pub fn refresh(&mut self, session: &Session) -> Result<(), Status> {
        // Revalidate even while paused, and before every deferred operation.
        let snapshot = session.vtop_snapshot()?;
        if let Some((request, started)) = self.pending.clone() {
            if snapshot.now.saturating_sub(started) / snapshot.timebase_hz.max(1) >= 5 {
                self.pending = None;
                self.notice = String::from("Still stopping; inspect the service before retrying.");
            } else {
                self.apply(session, request, started);
            }
        }
        if !self.paused {
            (self.snapshot, self.rates) = self.sampler.sample(snapshot);
            if self.history.len() == HISTORY {
                self.history.pop_front();
            }
            self.history.push_back(self.rates.total);
            if self.notice.starts_with("Sampling...") {
                self.notice.clear();
            }
        }
        self.reconcile_selection();
        Ok(())
    }

    fn visible(&self) -> Vec<&Service> {
        let mut services: Vec<_> = self
            .snapshot
            .services
            .iter()
            .filter(|s| {
                s.name
                    .to_ascii_lowercase()
                    .contains(&self.filter.to_ascii_lowercase())
            })
            .collect();
        services.sort_unstable_by(|a, b| {
            let primary = match self.sort {
                Sort::Cpu => self.rate(b).0.cmp(&self.rate(a).0),
                Sort::Memory => b.live.cmp(&a.live),
                Sort::Name => a.name.cmp(&b.name),
            };
            primary.then_with(|| a.name.cmp(&b.name))
        });
        services
    }
    fn rate(&self, service: &Service) -> (Option<u16>, Option<u64>) {
        self.rates
            .services
            .iter()
            .find(|(name, _, _)| *name == service.name)
            .map_or((None, None), |r| (r.1, r.2))
    }
    fn reconcile_selection(&mut self) {
        let services = self.visible();
        if !services
            .iter()
            .any(|s| Some(&s.name) == self.selected.as_ref())
        {
            self.selected = services.first().map(|s| s.name.clone());
        }
    }
    fn move_selection(&mut self, delta: isize) {
        let services = self.visible();
        if services.is_empty() {
            self.selected = None;
            return;
        }
        let at = services
            .iter()
            .position(|s| Some(&s.name) == self.selected.as_ref())
            .unwrap_or(0);
        let next = at.saturating_add_signed(delta).min(services.len() - 1);
        self.selected = Some(services[next].name.clone());
    }
    fn apply(&mut self, session: &Session, request: Request, started: u64) {
        match session.vtop_control(&request) {
            Ok(Control::Done) => {
                self.notice = format!(
                    "{}: {} complete",
                    safe(&request.name, 40),
                    request.action.label()
                );
                self.pending = None;
            }
            Ok(Control::Pending) => {
                self.notice = format!(
                    "{}: waiting for a poll boundary...",
                    safe(&request.name, 40)
                );
                self.pending = Some((request, started));
            }
            Err(error) => {
                self.notice = String::from(error);
                self.pending = None;
            }
        }
    }

    /// True exits immediately. Raw bytes bypass the terminal line editor.
    pub fn key(&mut self, session: &Session, byte: u8) -> bool {
        if byte == 3 || byte == 4 {
            return true;
        }
        match self.escape {
            Escape::Escape => {
                self.escape = Escape::Ground;
                if byte == b'[' || byte == b'O' {
                    self.escape = Escape::Csi;
                    return false;
                }
            }
            Escape::Csi => {
                if (0x40..=0x7e).contains(&byte) {
                    self.escape = Escape::Ground;
                    if self.confirm.is_none() && !self.filtering {
                        match byte {
                            b'A' => self.move_selection(-1),
                            b'B' => self.move_selection(1),
                            _ => {}
                        }
                    }
                }
                return false;
            }
            Escape::Ground => {}
        }
        if byte == 0x1b {
            self.escape = Escape::Escape;
            self.confirm = None;
            self.filtering = false;
            self.help = false;
            return false;
        }
        if self.filtering {
            match byte {
                b'\r' | b'\n' => self.filtering = false,
                8 | 127 => {
                    self.filter.pop();
                }
                b if (32..127).contains(&b) && self.filter.len() < 32 => {
                    self.filter.push(b as char)
                }
                _ => {}
            }
            self.reconcile_selection();
            return false;
        }
        if let Some(request) = self.confirm.take() {
            if byte == b'y' || byte == b'Y' {
                self.apply(session, request, self.snapshot.now);
            } else if !matches!(byte, b'n' | b'N' | b'q') {
                self.confirm = Some(request);
            }
            return false;
        }
        match byte {
            b'q' | b'Q' if self.pending.is_none() => return true,
            b'q' | b'Q' => {
                self.notice =
                    String::from("Finishing service action; Ctrl-C exits without retrying.")
            }
            b'j' => self.move_selection(1),
            b'k' => self.move_selection(-1),
            b'c' => self.sort = Sort::Cpu,
            b'm' => self.sort = Sort::Memory,
            b'n' => self.sort = Sort::Name,
            b'/' => {
                self.filter.clear();
                self.filtering = true;
            }
            b' ' => {
                self.paused = !self.paused;
                self.sampler = Sampler::default();
            }
            b'?' => self.help = !self.help,
            b's' | b'x' | b'r' if self.pending.is_none() => {
                if let Some(service) = self
                    .snapshot
                    .services
                    .iter()
                    .find(|s| Some(&s.name) == self.selected.as_ref())
                {
                    if let Some(reason) = service.protected {
                        self.notice = String::from(reason);
                    } else {
                        self.confirm = Some(Request {
                            name: service.name.clone(),
                            generation: service.generation,
                            task: service.task,
                            action: match byte {
                                b's' => Action::Start,
                                b'x' => Action::Stop,
                                _ => Action::Restart,
                            },
                        });
                    }
                }
            }
            _ => {}
        }
        false
    }

    /// Cap dimensions before allocating; every ASCII row is clipped, and the
    /// final row is left unused to avoid autowrap/scroll on small terminals.
    pub fn render(&self, cols: usize, rows: usize) -> String {
        let width = if cols == 0 { 80 } else { cols.clamp(1, 160) }.saturating_sub(1);
        let height = if rows == 0 { 24 } else { rows.clamp(2, 60) }.saturating_sub(1);
        let mut lines: Vec<(String, &'static str)> = Vec::new();
        let state = if self.paused { "PAUSED" } else { "LIVE / 1s" };
        lines.push((
            format!(" VTOP   /   {}", safe(&self.snapshot.board, 40)),
            "\x1b[1;36m",
        ));
        lines.push((
            format!(
                " {}    up {}    {} CPUs / {} tasks",
                state,
                uptime(&self.snapshot),
                self.snapshot.online_cpus,
                self.snapshot.tasks
            ),
            "\x1b[90m",
        ));
        if width < 55 || height < 15 {
            lines.push((
                format!(
                    " CPU {}   Heap {} / {}",
                    percent(self.rates.total),
                    bytes(self.snapshot.heap_live),
                    bytes(self.snapshot.heap_total)
                ),
                "",
            ));
            lines.push((
                String::from(" Resize to at least 56 x 16.  q / Ctrl-C: quit"),
                "\x1b[33m",
            ));
        } else if self.help {
            for line in HELP.lines() {
                lines.push((format!(" {line}"), ""));
            }
            lines.push((String::from(" ? close help    q quit"), "\x1b[36m"));
        } else {
            let total = self.rates.total;
            lines.push((
                format!(
                    " CPU   [{}] {:>6}   non-WFI residency",
                    bar(total, 20),
                    percent(total)
                ),
                "\x1b[36m",
            ));
            let per_core = self
                .rates
                .cpu
                .iter()
                .map(|(id, load)| format!("cpu{id} {:>6}", percent(*load)))
                .collect::<Vec<_>>()
                .join("   ");
            lines.push((format!("       {per_core}"), "\x1b[90m"));
            let history: String = self
                .history
                .iter()
                .map(|v| {
                    v.map_or('?', |v| {
                        b"._:-=+*#%@"[(usize::from(v) * 9 / 1000).min(9)] as char
                    })
                })
                .collect();
            lines.push((format!(" 48s   {history}"), "\x1b[36m"));
            let memory = ratio(
                self.snapshot.heap_live as u64,
                self.snapshot.heap_total as u64,
            );
            lines.push((
                format!(
                    " HEAP  [{}] {:>6}   {} / {}",
                    bar(memory, 20),
                    percent(memory),
                    bytes(self.snapshot.heap_live),
                    bytes(self.snapshot.heap_total)
                ),
                "\x1b[35m",
            ));
            lines.push((
                format!(
                    "       peak {}   untouched {}",
                    bytes(self.snapshot.heap_peak),
                    bytes(self.snapshot.heap_untouched)
                ),
                "\x1b[90m",
            ));
            let services = self.visible();
            let running = self
                .snapshot
                .services
                .iter()
                .filter(|s| s.state == TaskState::Running)
                .count();
            let faults = self
                .snapshot
                .services
                .iter()
                .filter(|s| s.state == TaskState::Faulted)
                .count();
            lines.push((
                format!(
                    " SERVICES  {} running / {} faulted   sort: {}   /{}",
                    running,
                    faults,
                    match self.sort {
                        Sort::Cpu => "cpu",
                        Sort::Memory => "memory",
                        Sort::Name => "name",
                    },
                    safe(&self.filter, 32)
                ),
                "\x1b[1m",
            ));
            lines.push((
                String::from(
                    "   SERVICE              STATE       CPU    POLL/s       LIVE      LIMIT",
                ),
                "\x1b[90m",
            ));
            let count = height.saturating_sub(14).max(1);
            let selected_at = services
                .iter()
                .position(|s| Some(&s.name) == self.selected.as_ref())
                .unwrap_or(0);
            let start = (selected_at / count) * count;
            if services.is_empty() {
                lines.push((
                    String::from("   No matching services. Press / to change the filter."),
                    "\x1b[90m",
                ));
            }
            for service in services.iter().skip(start).take(count) {
                let selected = Some(&service.name) == self.selected.as_ref();
                let (cpu, polls) = self.rate(service);
                let text = format!(
                    " {} {:<20} {:<9} {:>6} {:>9} {:>10} {:>10}",
                    if selected { ">" } else { " " },
                    safe(&service.name, 20),
                    format!("{}", service.state),
                    percent(cpu),
                    polls.map_or_else(|| String::from("--"), |v| format!("{v}")),
                    bytes(service.live),
                    if service.budget == usize::MAX {
                        String::from("unlimited")
                    } else {
                        bytes(service.budget)
                    }
                );
                lines.push((
                    text,
                    if selected {
                        "\x1b[48;5;236m\x1b[1;37m"
                    } else if service.state == TaskState::Faulted {
                        "\x1b[31m"
                    } else {
                        ""
                    },
                ));
            }
            while lines.len() < height.saturating_sub(5) {
                lines.push((String::new(), ""));
            }
            if let Some(service) = services
                .iter()
                .find(|s| Some(&s.name) == self.selected.as_ref())
            {
                lines.push((
                    format!(
                        " {}  gen {} / peak {} / denied {}",
                        safe(&service.name, 24),
                        service.generation,
                        bytes(service.peak),
                        service.denials
                    ),
                    "\x1b[90m",
                ));
                lines.push((
                    format!(
                        " {}",
                        service
                            .protected
                            .unwrap_or("s start   x stop   r restart   (confirmation required)")
                    ),
                    "\x1b[90m",
                ));
            } else {
                lines.push((String::new(), ""));
                lines.push((String::new(), ""));
            }
            let notice = if let Some(request) = &self.confirm {
                format!(
                    " {} {}?  y confirm / n cancel",
                    request.action.label(),
                    safe(&request.name, 40)
                )
            } else if self.filtering {
                format!(" Filter: /{}_  Enter apply / Esc close", self.filter)
            } else if !self.notice.is_empty() {
                format!(" {}", safe(&self.notice, width))
            } else {
                format!(
                    " Showing {}-{} / {}   CPU per service: one core = 100%",
                    if services.is_empty() { 0 } else { start + 1 },
                    (start + count).min(services.len()),
                    services.len()
                )
            };
            lines.push((notice, "\x1b[33m"));
            lines.push((
                String::from(" j/k select  c/m/n sort  / filter  Space pause  ? help  q quit"),
                "\x1b[36m",
            ));
        }
        let mut out = String::with_capacity((width + 40) * height);
        out.push_str("\x1b[H");
        for (i, (line, style)) in lines.iter().take(height).enumerate() {
            if i != 0 {
                out.push_str("\r\n");
            }
            out.push_str(style);
            out.push_str(&safe(line, width));
            out.push_str("\x1b[0m\x1b[K");
        }
        out.push_str("\x1b[J");
        out
    }
}
