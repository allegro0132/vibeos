//! Interactive setup for a VibeOS build selection.
//!
//! The screen is a tab strip over a list and a detail pane. Every row shows the
//! *resolved* outcome, not just the stored choice: an `auto` driver that the
//! dependency resolver pulled in is drawn as included, and a selected component
//! that cannot run on a board says so. Unicode and colour are optional; the
//! same layout renders in pure ASCII for serial consoles and plain locales.
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols::border,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
    Frame, Terminal,
};
use std::{env, io, path::Path, time::Duration};
use vibeos_config::{
    resolve, Board, Catalog, Config, Image, Kind, Node, Resolved, Result, Selection,
};

const ASCII_BORDER: border::Set<'static> = border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "-",
    horizontal_bottom: "-",
};
const TABS: [&str; 5] = ["Boards", "Drivers", "Components", "Presets", "Review"];
const BOARDS: usize = 0;
const DRIVERS: usize = 1;
const COMPONENTS: usize = 2;
const PRESETS: usize = 3;
const REVIEW: usize = 4;
const LABEL: usize = 11;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tone {
    Plain,
    Accent,
    Ok,
    Warn,
    Err,
    Dim,
}

/// What a row's leading glyph says about the resolved configuration.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mark {
    /// Included in the build.
    On,
    /// Not included.
    Off,
    /// Included and not user-controllable.
    Locked,
    /// Selected, but only some boards can run it.
    Partial,
    /// Selected, but the resolver could not include it.
    Failed,
    /// Explicitly forbidden by the user.
    Forbidden,
    /// Does not apply to any selected board.
    Absent,
    /// An action rather than a state.
    Go,
}

#[derive(Clone, Copy, Debug)]
pub struct Theme {
    ascii: bool,
    color: bool,
}
impl Theme {
    /// Unicode needs a UTF-8 locale; colour honours <https://no-color.org>.
    pub fn detect(force_ascii: bool) -> Self {
        let set = |name: &str| env::var(name).ok().filter(|v| !v.is_empty());
        let locale = set("LC_ALL")
            .or_else(|| set("LC_CTYPE"))
            .or_else(|| set("LANG"))
            .unwrap_or_default()
            .to_lowercase();
        let utf8 = locale.contains("utf-8") || locale.contains("utf8");
        Self {
            ascii: force_ascii
                || set("VIBECONFIG_ASCII").is_some()
                || !utf8
                || env::var("TERM").is_ok_and(|t| t == "linux"),
            color: set("NO_COLOR").is_none(),
        }
    }
    fn pick(self, unicode: &'static str, ascii: &'static str) -> &'static str {
        if self.ascii {
            ascii
        } else {
            unicode
        }
    }
    fn style(self, tone: Tone) -> Style {
        // Named ANSI colours follow the user's terminal palette in light and
        // dark themes. Without colour, weight carries the same hierarchy.
        let (color, weight) = match tone {
            Tone::Plain => return Style::new(),
            Tone::Accent => (Color::Cyan, Modifier::BOLD),
            Tone::Ok => (Color::Green, Modifier::empty()),
            Tone::Warn => (Color::Yellow, Modifier::BOLD),
            Tone::Err => (Color::Red, Modifier::BOLD),
            Tone::Dim => (Color::DarkGray, Modifier::DIM),
        };
        if self.color {
            Style::new().fg(color)
        } else {
            Style::new().add_modifier(weight)
        }
    }
    fn span(self, tone: Tone, text: impl Into<String>) -> Span<'static> {
        Span::styled(text.into(), self.style(tone))
    }
    fn bold(self, tone: Tone, text: impl Into<String>) -> Span<'static> {
        Span::styled(text.into(), self.style(tone).add_modifier(Modifier::BOLD))
    }
    fn mark(self, mark: Mark) -> (&'static str, Tone) {
        match mark {
            Mark::On => (self.pick("●", "[x]"), Tone::Ok),
            Mark::Off => (self.pick("○", "[ ]"), Tone::Dim),
            Mark::Locked => (self.pick("◆", "[#]"), Tone::Accent),
            Mark::Partial => (self.pick("●", "[~]"), Tone::Warn),
            Mark::Failed => (self.pick("!", "[!]"), Tone::Err),
            Mark::Forbidden => (self.pick("×", "[-]"), Tone::Warn),
            Mark::Absent => (self.pick("·", " . "), Tone::Dim),
            Mark::Go => (self.pick("›", " > "), Tone::Accent),
        }
    }
    fn panel(self, title: Line<'static>) -> Block<'static> {
        Block::bordered()
            .border_set(if self.ascii {
                ASCII_BORDER
            } else {
                border::ROUNDED
            })
            .border_style(self.style(Tone::Dim))
            .title(title)
    }
    fn dot(self) -> &'static str {
        self.pick(" · ", " - ")
    }
}

struct Row {
    id: String,
    mark: Mark,
    name: String,
    note: String,
    note_tone: Tone,
    /// Drawn subdued: the row is irrelevant to the current board selection.
    faded: bool,
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum Modal {
    None,
    Help,
    Quit,
    Preset(String),
    /// Selecting this board means leaving the current architecture or image.
    Switch(String),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Action {
    None,
    Save,
    SaveAndQuit,
    Quit,
}

struct App {
    config: Config,
    saved: Config,
    /// False until the selection has been written to the configuration file.
    on_disk: bool,
    tab: usize,
    selected: usize,
    query: String,
    searching: bool,
    message: Option<(Tone, String)>,
    modal: Modal,
    scroll: u16,
}

impl App {
    fn new(config: Config, on_disk: bool) -> Self {
        Self {
            saved: config.clone(),
            config,
            on_disk,
            // A first run starts from a preset rather than a blank slate.
            tab: if on_disk { BOARDS } else { PRESETS },
            selected: 0,
            query: String::new(),
            searching: false,
            message: (!on_disk).then(|| {
                (
                    Tone::Accent,
                    "Welcome. Pick a starting point, adjust it, then save.".into(),
                )
            }),
            modal: Modal::None,
            scroll: 0,
        }
    }
    fn dirty(&self) -> bool {
        self.config != self.saved
    }
    fn say(&mut self, tone: Tone, text: impl Into<String>) {
        self.message = Some((tone, text.into()));
    }
    fn go(&mut self, tab: usize) {
        self.tab = tab % TABS.len();
        self.selected = 0;
        self.scroll = 0;
        self.query.clear();
        self.searching = false;
    }
    fn boards<'a>(&self, c: &'a Catalog) -> Vec<&'a Board> {
        self.config
            .boards
            .iter()
            .filter_map(|id| c.board(id))
            .collect()
    }
    fn boot_required(&self, c: &Catalog, id: &str) -> bool {
        self.config
            .boards
            .iter()
            .filter_map(|b| c.board(b))
            .any(|b| b.required.iter().any(|r| r == id))
    }

    fn rows(&self, c: &Catalog, r: Option<&Resolved>) -> Vec<Row> {
        let included = |id: &str| r.map_or(0, |r| included_on(r, id));
        let total = self.config.boards.len();
        let mut rows: Vec<(Row, String)> = match self.tab {
            BOARDS => c
                .boards
                .iter()
                .map(|b| {
                    let on = self.config.boards.contains(&b.id);
                    (
                        Row {
                            id: b.id.clone(),
                            mark: if on { Mark::On } else { Mark::Off },
                            name: b.name.clone(),
                            note: b.arch.label().into(),
                            note_tone: Tone::Dim,
                            faded: false,
                        },
                        b.description.clone(),
                    )
                })
                .collect(),
            DRIVERS => {
                let mut rows: Vec<_> = c
                    .nodes
                    .iter()
                    .filter(|n| n.kind == Kind::Driver)
                    .map(|n| {
                        (
                            self.driver_row(c, n, included(&n.id)),
                            n.description.clone(),
                        )
                    })
                    .collect();
                // Stable: drivers for unselected boards sink below the usable ones.
                rows.sort_by_key(|(row, _)| row.faded);
                rows
            }
            COMPONENTS => c
                .nodes
                .iter()
                .filter(|n| n.kind == Kind::Component)
                .map(|n| {
                    let chosen = self.config.components.contains(&n.id);
                    let on = included(&n.id);
                    // A conflict is a build-wide error even when both sides resolve.
                    let clash = n
                        .conflicts
                        .iter()
                        .find(|other| on > 0 && included(other.as_str()) > 0);
                    let (mark, note, note_tone) = if n.id == "vsh" {
                        (Mark::Locked, "required".to_owned(), Tone::Dim)
                    } else if let Some(other) = clash {
                        (Mark::Failed, format!("conflicts with {other}"), Tone::Err)
                    } else if chosen && on == 0 {
                        (Mark::Failed, "unavailable".into(), Tone::Err)
                    } else if chosen && on < total {
                        (Mark::Partial, format!("{on}/{total} boards"), Tone::Warn)
                    } else if chosen {
                        (Mark::On, String::new(), Tone::Dim)
                    } else if on > 0 {
                        let by = r
                            .and_then(|r| needed_by(r, &n.id))
                            .map_or("dependency".to_owned(), |by| format!("via {by}"));
                        (Mark::On, by, Tone::Dim)
                    } else {
                        (Mark::Off, String::new(), Tone::Dim)
                    };
                    (
                        Row {
                            id: n.id.clone(),
                            mark,
                            name: n.name.clone(),
                            note,
                            note_tone,
                            faded: false,
                        },
                        n.description.clone(),
                    )
                })
                .collect(),
            PRESETS => preset_names(c)
                .into_iter()
                .map(|name| {
                    let current = c.preset(&name).is_ok_and(|p| p == self.config);
                    (
                        Row {
                            id: name.clone(),
                            mark: if current { Mark::On } else { Mark::Go },
                            name: name.clone(),
                            note: if current {
                                "current".into()
                            } else {
                                String::new()
                            },
                            note_tone: Tone::Dim,
                            faded: false,
                        },
                        preset_summary(c, &name),
                    )
                })
                .collect(),
            _ => Vec::new(),
        };
        let q = self.query.to_lowercase();
        rows.retain(|(row, text)| {
            format!("{} {} {text}", row.id, row.name)
                .to_lowercase()
                .contains(&q)
        });
        rows.into_iter().map(|(row, _)| row).collect()
    }

    fn driver_row(&self, c: &Catalog, n: &Node, included: usize) -> Row {
        let choice = self.config.drivers.get(&n.id).copied().unwrap_or_default();
        let applies = self.config.boards.iter().any(|b| n.supports(b));
        let (mark, note, note_tone) = if self.boot_required(c, &n.id) {
            (Mark::Locked, "boot", Tone::Dim)
        } else if !applies {
            match choice {
                Selection::On => (Mark::Failed, "on, no board", Tone::Err),
                _ => (Mark::Absent, "no board", Tone::Dim),
            }
        } else {
            match (choice, included > 0) {
                (Selection::On, true) => (Mark::On, "on", Tone::Plain),
                (Selection::On, false) => (Mark::Failed, "on, failed", Tone::Err),
                (Selection::Off, _) => (Mark::Forbidden, "off", Tone::Warn),
                (Selection::Auto, true) => (Mark::On, "auto, in use", Tone::Dim),
                (Selection::Auto, false) => (Mark::Off, "auto", Tone::Dim),
            }
        };
        Row {
            id: n.id.clone(),
            mark,
            name: n.name.clone(),
            note: note.into(),
            note_tone,
            faded: !applies,
        }
    }

    fn toggle(&mut self, c: &Catalog) {
        let rows = self.rows(c, None);
        let Some(id) = rows.get(self.selected).map(|r| r.id.clone()) else {
            return;
        };
        match self.tab {
            BOARDS => {
                if !self.config.boards.contains(&id) {
                    // One image has one architecture, and an external image
                    // has one board: crossing either line replaces the set.
                    let fits = c.board(&id).is_some_and(|new| {
                        self.boards(c).iter().all(|b| {
                            b.arch == new.arch
                                && b.image == Image::Universal
                                && new.image == Image::Universal
                        })
                    });
                    if fits {
                        self.config.boards.insert(id);
                    } else {
                        self.modal = Modal::Switch(id);
                    }
                } else if self.config.boards.len() == 1 {
                    self.say(Tone::Warn, "Keep at least one board.");
                } else {
                    self.config.boards.remove(&id);
                }
            }
            DRIVERS => {
                if self.boot_required(c, &id) {
                    self.say(
                        Tone::Warn,
                        format!("{id} is required to boot a selected board."),
                    );
                    return;
                }
                let next = self
                    .config
                    .drivers
                    .get(&id)
                    .copied()
                    .unwrap_or_default()
                    .next();
                self.say(
                    Tone::Dim,
                    match next {
                        Selection::Auto => {
                            format!("{id}: auto, included only when something needs it")
                        }
                        Selection::On => format!("{id}: on, required on every compatible board"),
                        Selection::Off => format!("{id}: off, forbidden even as a dependency"),
                    },
                );
                self.config.drivers.insert(id, next);
            }
            COMPONENTS => {
                if id == "vsh" {
                    self.say(Tone::Warn, "VSH is required by the minimal system.");
                } else if !self.config.components.remove(&id) {
                    self.config.components.insert(id);
                }
            }
            PRESETS => {
                if self.dirty() {
                    self.modal = Modal::Preset(id);
                } else {
                    self.load_preset(c, &id);
                }
            }
            _ => {}
        }
        self.scroll = 0;
    }

    fn load_preset(&mut self, c: &Catalog, name: &str) {
        match c.preset(name) {
            Ok(config) => {
                self.config = config;
                self.go(BOARDS);
                self.say(
                    Tone::Ok,
                    format!("Loaded {name}. Adjust it, then press s to save."),
                );
            }
            Err(e) => self.say(Tone::Err, e),
        }
    }

    fn request_quit(&mut self) -> Action {
        if self.dirty() {
            self.modal = Modal::Quit;
            Action::None
        } else {
            Action::Quit
        }
    }

    fn key(&mut self, c: &Catalog, key: KeyEvent) -> Action {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match self.modal.clone() {
            Modal::Help => {
                self.modal = Modal::None;
                return Action::None;
            }
            Modal::Quit => {
                match key.code {
                    KeyCode::Char('s') | KeyCode::Enter => {
                        self.modal = Modal::None;
                        return Action::SaveAndQuit;
                    }
                    KeyCode::Char('d') | KeyCode::Char('y') => return Action::Quit,
                    KeyCode::Char('n') | KeyCode::Char('c') | KeyCode::Esc => {
                        self.modal = Modal::None
                    }
                    _ => {}
                }
                return Action::None;
            }
            Modal::Preset(name) => {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Enter => {
                        self.modal = Modal::None;
                        self.load_preset(c, &name);
                    }
                    KeyCode::Char('n') | KeyCode::Esc => self.modal = Modal::None,
                    _ => {}
                }
                return Action::None;
            }
            Modal::Switch(id) => {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Enter => {
                        self.modal = Modal::None;
                        if let (Ok(config), Some(b)) = (c.preset(&id), c.board(&id)) {
                            self.config = config;
                            self.say(
                                Tone::Ok,
                                format!("Now configuring {} ({}).", b.name, b.arch.label()),
                            );
                        }
                    }
                    KeyCode::Char('n') | KeyCode::Esc => self.modal = Modal::None,
                    _ => {}
                }
                return Action::None;
            }
            Modal::None => {}
        }
        if ctrl && key.code == KeyCode::Char('s') {
            self.searching = false;
            return Action::Save;
        }
        if ctrl && key.code == KeyCode::Char('c') {
            return self.request_quit();
        }
        if self.searching {
            match key.code {
                KeyCode::Esc => {
                    self.searching = false;
                    self.query.clear();
                }
                KeyCode::Enter | KeyCode::Down | KeyCode::Up => self.searching = false,
                KeyCode::Backspace => {
                    self.query.pop();
                }
                KeyCode::Char(ch) => self.query.push(ch),
                _ => {}
            }
            self.selected = 0;
            return Action::None;
        }
        self.message = None;
        let last = self.rows(c, None).len().saturating_sub(1);
        match key.code {
            // Escape backs out one level at a time: filter first, then the program.
            KeyCode::Esc if !self.query.is_empty() => {
                self.query.clear();
                self.selected = 0;
            }
            KeyCode::Char('q') | KeyCode::Esc => return self.request_quit(),
            KeyCode::Char('s') => return Action::Save,
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => self.go(self.tab + 1),
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                self.go(self.tab + TABS.len() - 1)
            }
            KeyCode::Char(ch @ '1'..='5') => self.go(ch as usize - '1' as usize),
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = (self.selected + 1).min(last);
                self.scroll = 0;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
                self.scroll = 0;
            }
            KeyCode::Home | KeyCode::Char('g') => self.selected = 0,
            KeyCode::End | KeyCode::Char('G') => self.selected = last,
            KeyCode::PageDown => self.scroll = self.scroll.saturating_add(8),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(8),
            KeyCode::Char('/') if self.tab != REVIEW => {
                self.searching = true;
                self.query.clear();
                self.selected = 0;
            }
            KeyCode::Enter if self.tab == REVIEW => return Action::Save,
            KeyCode::Char(' ') | KeyCode::Enter => self.toggle(c),
            KeyCode::Char('?') => self.modal = Modal::Help,
            _ => {}
        }
        Action::None
    }

    /// Validate and write the selection. A failed save lands on Review, where
    /// every problem is listed next to the board it affects.
    fn save(&mut self, root: &Path, c: &Catalog, path: &Path) -> bool {
        let result = resolve(c, &self.config).and_then(|r| {
            c.check_features(root)?;
            super::save(root, path, &self.config, &r)
        });
        match result {
            Ok(()) => {
                self.saved = self.config.clone();
                self.on_disk = true;
                let next = if self.boards(c).iter().any(|b| b.image == Image::External) {
                    "See Review for how the image is built."
                } else {
                    "Next: ./build.sh"
                };
                self.say(Tone::Ok, format!("Saved {}. {next}", path.display()));
                true
            }
            Err(e) => {
                self.go(REVIEW);
                let first = e
                    .lines()
                    .next()
                    .unwrap_or("invalid configuration")
                    .to_owned();
                self.say(Tone::Err, format!("Not saved: {first}"));
                false
            }
        }
    }
}

fn included_on(r: &Resolved, id: &str) -> usize {
    r.boards.values().filter(|p| p.enabled.contains(id)).count()
}
/// The component that pulled `id` in transitively, from the resolver's reasons.
fn needed_by(r: &Resolved, id: &str) -> Option<String> {
    r.boards
        .values()
        .filter_map(|p| p.reasons.get(id))
        .flatten()
        .find_map(|reason| reason.strip_prefix("required by ").map(str::to_owned))
}
fn preset_names(c: &Catalog) -> Vec<String> {
    ["default", "minimal"]
        .into_iter()
        .map(str::to_owned)
        .chain(c.boards.iter().map(|b| b.id.clone()))
        .collect()
}
fn preset_summary(c: &Catalog, name: &str) -> String {
    match name {
        "default" => "Every board with its native storage and Ethernet drivers, the VSH \
                      console, file services and DHCP networking."
            .into(),
        "minimal" => "Every board with only its boot requirements and the VSH console. \
                      The smallest image that still boots everywhere."
            .into(),
        _ => match c.board(name) {
            Some(b) => format!(
                "{} only, with native storage and Ethernet, the VSH console, file services \
                 and DHCP networking.",
                b.name
            ),
            None => String::new(),
        },
    }
}
fn memory(bytes: u64) -> String {
    const MIB: u64 = 1 << 20;
    if bytes >= 1000 * MIB {
        format!("{:.1} GiB", bytes as f64 / (1024 * MIB) as f64)
    } else {
        format!("{} MiB", bytes / MIB)
    }
}
fn list_or(items: &[String], empty: &str) -> String {
    if items.is_empty() {
        empty.into()
    } else {
        items.join(", ")
    }
}
fn clip(text: &str, width: usize, th: Theme) -> String {
    if text.chars().count() <= width {
        return text.into();
    }
    let tail = th.pick("…", "..");
    let keep = width.saturating_sub(tail.chars().count());
    text.chars().take(keep).chain(tail.chars()).collect()
}
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

pub fn run(
    root: &Path,
    c: &Catalog,
    config: Config,
    path: &Path,
    on_disk: bool,
    theme: Theme,
) -> Result<()> {
    let old_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        old_hook(info);
    }));
    let mut app = App::new(config, on_disk);
    {
        let _restore = Restore;
        enable_raw_mode().map_err(|e| e.to_string())?;
        execute!(io::stdout(), EnterAlternateScreen).map_err(|e| e.to_string())?;
        let mut terminal =
            Terminal::new(CrosstermBackend::new(io::stdout())).map_err(|e| e.to_string())?;
        loop {
            terminal
                .draw(|f| draw(f, c, &app, path, theme))
                .map_err(|e| e.to_string())?;
            if !event::poll(Duration::from_millis(200)).map_err(|e| e.to_string())? {
                continue;
            }
            let Event::Key(key) = event::read().map_err(|e| e.to_string())? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match app.key(c, key) {
                Action::None => {}
                Action::Save => {
                    app.save(root, c, path);
                }
                Action::SaveAndQuit => {
                    if app.save(root, c, path) {
                        break;
                    }
                }
                Action::Quit => break,
            }
        }
    }
    // Back on the normal screen: leave the next step in the scrollback.
    if app.on_disk && !app.dirty() {
        println!("Configuration: {}", path.display());
        match app.boards(c).iter().find(|b| b.image == Image::External) {
            Some(b) => println!("{}: {}", b.name, b.build_hint),
            None => println!("Next: ./build.sh --config {}", path.display()),
        }
    } else {
        println!("No changes saved.");
    }
    Ok(())
}

fn draw(f: &mut Frame, c: &Catalog, app: &App, path: &Path, th: Theme) {
    let area = f.area();
    if area.width < 50 || area.height < 12 {
        let message = match app.modal {
            Modal::Quit => "VibeOS setup\nUnsaved changes: s save and quit / d discard / Esc return",
            Modal::Preset(_) => "VibeOS setup\nReplace selection with preset? y load / n return",
            Modal::Switch(_) => "VibeOS setup\nSwitch architecture and replace boards? y switch / n return",
            _ => "VibeOS setup\nResize the terminal to at least 50 x 12.\nSelection preserved; Ctrl-S saves, q quits.",
        };
        f.render_widget(Paragraph::new(message).wrap(Wrap { trim: false }), area);
        return;
    }
    let resolved = resolve(c, &app.config);
    let r = resolved.as_ref().ok();
    let problems: Vec<String> = match &resolved {
        Ok(r) => r.errors.clone(),
        Err(e) => vec![e.clone()],
    };
    let [header, tabs, body, status, hints] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Min(5),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area.inner(ratatui::layout::Margin::new(1, 0)));

    draw_header(f, header, app, path, th);
    draw_tabs(f, tabs, app, &problems, th);
    if app.tab == REVIEW {
        let lines = review(
            c,
            app,
            &resolved,
            path,
            body.width.saturating_sub(4) as usize,
            th,
        );
        draw_document(f, body, Line::from(" Review "), lines, app.scroll, th);
    } else {
        let rows = app.rows(c, r);
        let selected = app.selected.min(rows.len().saturating_sub(1));
        let [list, detail] = if body.width >= 84 {
            Layout::horizontal([Constraint::Length(40), Constraint::Min(40)])
                .spacing(1)
                .areas(body)
        } else {
            let top = (rows.len() as u16 + 2).min(body.height / 2).max(3);
            Layout::vertical([Constraint::Length(top), Constraint::Min(3)]).areas(body)
        };
        draw_list(f, list, app, &rows, selected, th);
        let (title, lines) = match rows.get(selected) {
            Some(row) => (row.name.clone(), details(c, app, r, row, th)),
            None => (
                "Nothing selected".into(),
                vec![Line::from("No matches. Press Esc to clear the filter.")],
            ),
        };
        draw_document(
            f,
            detail,
            Line::from(format!(" {title} ")),
            lines,
            app.scroll,
            th,
        );
    }
    draw_status(f, status, app, r, &problems, th);
    draw_hints(f, hints, app, th);
    match &app.modal {
        Modal::None => {}
        Modal::Help => draw_help(f, area, th),
        Modal::Quit => dialog(
            f,
            area,
            " Unsaved changes ",
            vec![
                Line::from("Your selection differs from the saved configuration."),
                Line::default(),
                keys(
                    th,
                    &[
                        ("s", "save and quit"),
                        ("d", "discard"),
                        ("Esc", "keep editing"),
                    ],
                ),
            ],
            th,
        ),
        Modal::Preset(name) => dialog(
            f,
            area,
            " Load preset ",
            vec![
                Line::from(format!("Replace the current selection with {name}?")),
                Line::from(th.span(Tone::Dim, "Unsaved changes will be lost.")),
                Line::default(),
                keys(th, &[("Enter", "load"), ("Esc", "cancel")]),
            ],
            th,
        ),
        Modal::Switch(id) => {
            let Some(new) = c.board(id) else { return };
            let current = app.boards(c);
            let why = match current.first() {
                Some(old) if old.arch != new.arch => format!(
                    "{} is {}; the current selection is {}.",
                    new.name,
                    new.arch.label(),
                    old.arch.label()
                ),
                _ if new.image == Image::External => {
                    format!(
                        "{} has its own image, built outside this workspace.",
                        new.name
                    )
                }
                _ => "The current board has its own image and is configured alone.".into(),
            };
            dialog(
                f,
                area,
                " Switch target ",
                vec![
                    Line::from(why),
                    Line::from(th.span(Tone::Dim, "One kernel image has one architecture.")),
                    Line::default(),
                    Line::from(format!(
                        "Replace the selection with {} and its defaults?",
                        new.name
                    )),
                    Line::default(),
                    keys(th, &[("Enter", "switch"), ("Esc", "cancel")]),
                ],
                th,
            )
        }
    }
}

fn draw_header(f: &mut Frame, area: Rect, app: &App, path: &Path, th: Theme) {
    let (tone, state) = if app.dirty() {
        (Tone::Warn, "modified")
    } else if app.on_disk {
        (Tone::Ok, "saved")
    } else {
        (Tone::Warn, "not saved yet")
    };
    let state = format!("{} {state}", th.pick("●", "*"));
    let room = (area.width as usize).saturating_sub(16 + state.chars().count() + 3);
    let shown = path.display().to_string();
    // Keep the file name: clip long paths from the left.
    let shown = if shown.chars().count() > room {
        let tail: String = shown
            .chars()
            .skip(shown.chars().count() + 2 - room.max(2))
            .collect();
        format!("{}{tail}", th.pick("…", ".."))
    } else {
        shown
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            th.bold(Tone::Accent, "VibeOS"),
            Span::raw(" setup"),
        ])),
        area,
    );
    f.render_widget(
        Paragraph::new(
            Line::from(vec![
                th.span(Tone::Dim, shown),
                Span::raw("  "),
                th.span(tone, state),
            ])
            .right_aligned(),
        ),
        area,
    );
}

fn draw_tabs(f: &mut Frame, area: Rect, app: &App, problems: &[String], th: Theme) {
    let mut spans = Vec::new();
    for (i, name) in TABS.iter().enumerate() {
        let badge = match i {
            BOARDS => app.config.boards.len().to_string(),
            COMPONENTS => app.config.components.len().to_string(),
            REVIEW if !problems.is_empty() => "!".into(),
            _ => String::new(),
        };
        let label = if app.tab == i {
            Span::styled(
                format!(" {name} "),
                th.style(Tone::Accent)
                    .add_modifier(Modifier::BOLD | Modifier::REVERSED),
            )
        } else {
            Span::raw(format!(" {name} "))
        };
        spans.push(label);
        if !badge.is_empty() {
            let tone = if i == REVIEW { Tone::Err } else { Tone::Dim };
            spans.push(th.span(tone, badge));
            spans.push(Span::raw(" "));
        }
        spans.push(Span::raw(" "));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_list(f: &mut Frame, area: Rect, app: &App, rows: &[Row], selected: usize, th: Theme) {
    let mut title = vec![Span::raw(format!(" {} ", TABS[app.tab]))];
    if app.searching || !app.query.is_empty() {
        title.push(th.span(Tone::Accent, format!("/{}", app.query)));
        if app.searching {
            title.push(th.span(Tone::Accent, th.pick("▏", "_")));
        }
        title.push(Span::raw(" "));
    }
    let mut block = th.panel(Line::from(title));
    if !rows.is_empty() {
        block = block.title_bottom(
            Line::from(th.span(Tone::Dim, format!(" {}/{} ", selected + 1, rows.len())))
                .right_aligned(),
        );
    }
    let inner = block.inner(area);
    f.render_widget(block, area);
    if rows.is_empty() {
        f.render_widget(
            Paragraph::new(th.span(Tone::Dim, format!(" No matches for \"{}\"", app.query))),
            inner,
        );
        return;
    }
    let height = inner.height as usize;
    let width = inner.width as usize;
    let first = (selected + 1).saturating_sub(height);
    let lines: Vec<Line> = rows
        .iter()
        .enumerate()
        .skip(first)
        .take(height)
        .map(|(i, row)| {
            let current = i == selected;
            let (glyph, tone) = th.mark(row.mark);
            let used = 1 + glyph.chars().count() + 1 + row.note.chars().count() + 2;
            let name = clip(&row.name, width.saturating_sub(used), th);
            let gap = width.saturating_sub(used + name.chars().count());
            let name_style = if current {
                Style::new().add_modifier(Modifier::BOLD)
            } else if row.faded {
                th.style(Tone::Dim)
            } else {
                Style::new()
            };
            Line::from(vec![
                th.span(Tone::Accent, if current { th.pick("▌", ">") } else { " " }),
                th.span(if row.faded { Tone::Dim } else { tone }, glyph),
                Span::raw(" "),
                Span::styled(name, name_style),
                Span::raw(" ".repeat(gap + 1)),
                th.span(row.note_tone, row.note.clone()),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_document(
    f: &mut Frame,
    area: Rect,
    title: Line<'static>,
    lines: Vec<Line<'static>>,
    scroll: u16,
    th: Theme,
) {
    let block = th.panel(title);
    let inner = block.inner(area).inner(ratatui::layout::Margin::new(1, 0));
    f.render_widget(block, area);
    let scroll = scroll.min((lines.len() as u16).saturating_sub(1));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        inner,
    );
}

fn field(th: Theme, label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        th.span(Tone::Dim, format!("{label:<LABEL$}")),
        Span::raw(value.into()),
    ])
}
/// A field whose value is a word list, wrapped with a hanging indent.
fn wrapped_field<'a>(
    th: Theme,
    label: &str,
    words: impl Iterator<Item = &'a String>,
    width: usize,
) -> Vec<Line<'static>> {
    let room = width.saturating_sub(LABEL).max(16);
    let mut rows = vec![String::new()];
    for word in words {
        let row = rows.last_mut().unwrap();
        if !row.is_empty() && row.len() + 1 + word.len() > room {
            rows.push(word.clone());
        } else {
            if !row.is_empty() {
                row.push(' ');
            }
            row.push_str(word);
        }
    }
    rows.into_iter()
        .enumerate()
        .map(|(i, row)| field(th, if i == 0 { label } else { "" }, row))
        .collect()
}
fn heading(th: Theme, text: impl Into<String>) -> Line<'static> {
    Line::from(th.bold(Tone::Plain, text))
}

fn details(
    c: &Catalog,
    app: &App,
    r: Option<&Resolved>,
    row: &Row,
    th: Theme,
) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    if let Some(n) = c.node(&row.id).filter(|_| app.tab != PRESETS) {
        out.push(Line::from(th.span(
            Tone::Dim,
            format!(
                "{}{}{}",
                n.id,
                th.dot(),
                if n.kind == Kind::Driver {
                    "driver"
                } else {
                    "component"
                }
            ),
        )));
        out.push(Line::default());
        out.push(Line::from(n.description.clone()));
        out.push(Line::default());
        if n.kind == Kind::Driver {
            let choice = app.config.drivers.get(&n.id).copied().unwrap_or_default();
            out.push(field(
                th,
                "Choice",
                if app.boot_required(c, &n.id) {
                    "locked: a selected board needs it to boot"
                } else {
                    match choice {
                        Selection::Auto => "auto: included only when something needs it",
                        Selection::On => "on: required on every compatible board",
                        Selection::Off => "off: forbidden, even as a dependency",
                    }
                },
            ));
        }
        let requires: Vec<String> = n
            .requires
            .iter()
            .map(|d| match d.strip_prefix("cap:") {
                Some(cap) => format!("any {cap} provider"),
                None => d.clone(),
            })
            .collect();
        out.push(field(th, "Requires", list_or(&requires, "nothing")));
        if !n.provides.is_empty() {
            out.push(field(th, "Provides", n.provides.join(", ")));
        }
        if !n.conflicts.is_empty() {
            out.push(field(th, "Conflicts", n.conflicts.join(", ")));
        }
        if n.kind == Kind::Driver {
            out.push(field(th, "Boards", list_or(&n.boards, "all")));
        }
        if let Some(r) = r {
            out.push(Line::default());
            out.push(heading(th, "On selected boards"));
            for (bid, plan) in &r.boards {
                let name = c.board(bid).map_or(bid.as_str(), |b| b.name.as_str());
                let (glyph, tone, notes): (_, _, Vec<String>) = if plan.enabled.contains(&n.id) {
                    (
                        th.pick("✓", "+"),
                        Tone::Ok,
                        plan.reasons
                            .get(&n.id)
                            .map(|s| s.iter().cloned().collect())
                            .unwrap_or_default(),
                    )
                } else if let Some(why) = plan.unavailable.get(&n.id) {
                    (th.pick("✗", "!"), Tone::Err, vec![why.clone()])
                } else if !n.supports(bid) {
                    (
                        th.pick("·", "."),
                        Tone::Dim,
                        vec!["not available on this board".into()],
                    )
                } else {
                    (th.pick("·", "."), Tone::Dim, vec!["not included".into()])
                };
                for (i, note) in notes.iter().enumerate() {
                    out.push(Line::from(vec![
                        th.span(tone, if i == 0 { glyph } else { " " }),
                        Span::raw(format!(" {:<12} ", if i == 0 { name } else { "" })),
                        th.span(
                            if tone == Tone::Err {
                                Tone::Err
                            } else {
                                Tone::Dim
                            },
                            note.clone(),
                        ),
                    ]));
                }
            }
        }
    } else if let Some(b) = c.board(&row.id).filter(|_| app.tab == BOARDS) {
        out.push(Line::from(th.span(Tone::Dim, b.id.clone())));
        out.push(Line::default());
        out.push(Line::from(b.description.clone()));
        out.push(Line::default());
        out.push(field(th, "Arch", b.arch.label()));
        if b.image == Image::External {
            out.push(field(th, "Image", "built outside this workspace"));
        }
        out.push(field(th, "RAM window", memory(b.memory_bytes)));
        out.push(field(th, "Load at", format!("{:#x}", b.load_address)));
        out.push(field(th, "Boot needs", b.required.join(", ")));
        out.push(field(th, "Defaults", b.defaults.join(", ")));
        match r.and_then(|r| r.boards.get(&b.id)) {
            Some(plan) => {
                out.push(Line::default());
                out.push(heading(
                    th,
                    format!("In this build{}{} parts", th.dot(), plan.enabled.len()),
                ));
                out.extend(plan_lines(c, plan, th));
            }
            None => {
                out.push(Line::default());
                out.push(Line::from(
                    th.span(Tone::Dim, "Not selected. Space adds this board."),
                ));
            }
        }
    } else {
        out.push(Line::from(preset_summary(c, &row.id)));
        out.push(Line::default());
        if let Ok(p) = c.preset(&row.id) {
            let on: Vec<String> = p.drivers.keys().cloned().collect();
            out.push(field(
                th,
                "Boards",
                p.boards.iter().cloned().collect::<Vec<_>>().join(", "),
            ));
            out.push(field(
                th,
                "Components",
                p.components.iter().cloned().collect::<Vec<_>>().join(", "),
            ));
            out.push(field(
                th,
                "Drivers on",
                list_or(&on, "boot requirements only"),
            ));
            out.push(Line::default());
            out.push(Line::from(th.span(
                Tone::Dim,
                "Enter replaces the current selection. Nothing is written until you save.",
            )));
        }
    }
    out
}

/// One board's resolved closure: what is in, why, and what could not be.
fn plan_lines(c: &Catalog, plan: &vibeos_config::BoardPlan, th: Theme) -> Vec<Line<'static>> {
    let name = |id: &str| c.node(id).map_or(id.to_owned(), |n| n.name.clone());
    let mut out = Vec::new();
    let mut ids: Vec<&String> = plan.enabled.iter().collect();
    // Components first: they are what the user asked for; drivers follow from them.
    ids.sort_by_key(|id| c.node(id).is_some_and(|n| n.kind == Kind::Driver));
    for id in ids {
        let why = plan
            .reasons
            .get(id)
            .and_then(|s| s.iter().next().cloned())
            .unwrap_or_default();
        out.push(Line::from(vec![
            th.span(Tone::Ok, format!("  {} ", th.pick("✓", "+"))),
            Span::raw(format!("{:<26} ", clip(&name(id), 26, th))),
            th.span(Tone::Dim, why),
        ]));
    }
    for (id, why) in &plan.unavailable {
        out.push(Line::from(vec![
            th.span(Tone::Err, format!("  {} ", th.pick("✗", "!"))),
            Span::raw(format!("{:<26} ", clip(&name(id), 26, th))),
            th.span(Tone::Err, why.clone()),
        ]));
    }
    out
}

fn review(
    c: &Catalog,
    app: &App,
    resolved: &Result<Resolved>,
    path: &Path,
    width: usize,
    th: Theme,
) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let r = match resolved {
        Ok(r) => r,
        Err(e) => {
            out.push(Line::from(
                th.bold(Tone::Err, "This selection cannot be resolved"),
            ));
            out.push(Line::from(format!("  {e}")));
            return out;
        }
    };
    if r.valid() {
        out.push(Line::from(vec![
            th.bold(
                Tone::Ok,
                format!(
                    "{} {}",
                    th.pick("✓", "+"),
                    match r.image {
                        Image::Universal => "Ready to build",
                        Image::External => "Selection is consistent",
                    }
                ),
            ),
            th.span(
                Tone::Dim,
                if app.dirty() || !app.on_disk {
                    "   press s to save"
                } else {
                    "   saved"
                },
            ),
        ]));
    } else {
        out.push(Line::from(th.bold(
            Tone::Err,
            format!(
                "{} {} to fix before saving",
                th.pick("✗", "!"),
                if r.errors.len() == 1 {
                    "1 problem".into()
                } else {
                    format!("{} problems", r.errors.len())
                }
            ),
        )));
        for e in &r.errors {
            out.push(Line::from(th.span(Tone::Err, format!("  {e}"))));
        }
    }
    out.push(Line::default());
    out.push(field(th, "File", path.display().to_string()));
    out.push(field(th, "Arch", r.arch.label()));
    out.push(field(th, "Target", r.target.clone()));
    out.push(field(th, "Digest", r.digest.clone()));
    if r.image == Image::Universal {
        out.push(field(
            th,
            "Output",
            format!("target/universal/{}/", clip(&r.digest, 13, th)),
        ));
        out.extend(wrapped_field(th, "Features", r.features.iter(), width));
    }
    for (bid, plan) in &r.boards {
        out.push(Line::default());
        out.push(heading(
            th,
            format!(
                "{}{}{} parts",
                c.board(bid).map_or(bid.as_str(), |b| b.name.as_str()),
                th.dot(),
                plan.enabled.len()
            ),
        ));
        out.extend(plan_lines(c, plan, th));
    }
    out.push(Line::default());
    out.push(heading(th, "Next"));
    let config = path.display();
    let mut steps = Vec::new();
    match r.image {
        Image::Universal => {
            steps.push((format!("./build.sh --config {config}"), "build the image"));
            if r.boards.contains_key("qemu-virt") {
                steps.push((format!("./run.sh --config {config}"), "boot it in QEMU"));
            }
        }
        Image::External => {
            // The image is linked by the product that pins this workspace.
            for b in app.boards(c) {
                out.push(Line::from(format!("  {}", b.build_hint)));
            }
        }
    }
    for (command, what) in steps {
        out.push(Line::from(vec![
            Span::raw(format!("  {command}")),
            th.span(Tone::Dim, format!("   {what}")),
        ]));
    }
    out
}

fn draw_status(
    f: &mut Frame,
    area: Rect,
    app: &App,
    r: Option<&Resolved>,
    problems: &[String],
    th: Theme,
) {
    let left = if let Some((tone, text)) = &app.message {
        Line::from(th.span(*tone, text.clone()))
    } else if let Some(first) = problems.first() {
        let more = match problems.len() {
            1 => String::new(),
            n => format!("  (+{} more, see Review)", n - 1),
        };
        Line::from(vec![
            th.bold(Tone::Err, format!("{} ", th.pick("✗", "!"))),
            th.span(Tone::Err, first.clone()),
            th.span(Tone::Dim, more),
        ])
    } else {
        Line::from(vec![
            th.span(Tone::Ok, format!("{} ", th.pick("✓", "+"))),
            Span::raw("Dependencies resolve"),
        ])
    };
    f.render_widget(Paragraph::new(left), area);
    if let Some(r) = r {
        let parts: std::collections::BTreeSet<&String> =
            r.boards.values().flat_map(|p| &p.enabled).collect();
        let summary = format!(
            "{}{}{} {}{}{} parts{}{}",
            r.arch.label(),
            th.dot(),
            r.boards.len(),
            if r.boards.len() == 1 {
                "board"
            } else {
                "boards"
            },
            th.dot(),
            parts.len(),
            th.dot(),
            clip(&r.digest, 9, th)
        );
        let width = summary.chars().count() as u16 + 2;
        if area.width > width + 40 {
            let right = Rect {
                x: area.x + area.width - width,
                width,
                ..area
            };
            f.render_widget(Clear, right);
            f.render_widget(
                Paragraph::new(Line::from(th.span(Tone::Dim, summary)).right_aligned()),
                right,
            );
        }
    }
}

fn keys(th: Theme, pairs: &[(&str, &str)]) -> Line<'static> {
    let mut spans = Vec::new();
    for (key, what) in pairs {
        spans.push(th.bold(Tone::Plain, key.to_string()));
        spans.push(th.span(Tone::Dim, format!(" {what}  ")));
    }
    Line::from(spans)
}

fn draw_hints(f: &mut Frame, area: Rect, app: &App, th: Theme) {
    let arrows = th.pick("↑↓", "Up/Dn");
    let line = if app.searching {
        keys(
            th,
            &[("type", "to filter"), ("Enter", "keep"), ("Esc", "clear")],
        )
    } else if app.tab == REVIEW {
        keys(
            th,
            &[
                ("s", "save"),
                ("q", "quit"),
                ("?", "help"),
                ("PgUp/PgDn", "scroll"),
                ("Tab", "section"),
            ],
        )
    } else {
        let act = match app.tab {
            DRIVERS => "auto/on/off",
            PRESETS => "load",
            _ => "toggle",
        };
        keys(
            th,
            &[
                (arrows, "move"),
                ("Space", act),
                ("s", "save"),
                ("q", "quit"),
                ("?", "help"),
                ("/", "filter"),
                ("Tab", "section"),
            ],
        )
    };
    f.render_widget(Paragraph::new(line), area);
}

fn dialog(f: &mut Frame, area: Rect, title: &'static str, lines: Vec<Line<'static>>, th: Theme) {
    let width = (lines.iter().map(|l| l.width()).max().unwrap_or(0) as u16 + 6)
        .max(40)
        .min(area.width);
    // Count rows after wrapping, so the last line (the keys) is never cut off.
    let text_width = width.saturating_sub(6).max(1) as usize;
    let rows: u16 = lines
        .iter()
        .map(|l| l.width().div_ceil(text_width).max(1) as u16)
        .sum();
    // Give up the vertical padding before giving up content.
    let pad = u16::from(rows + 4 <= area.height);
    let rect = centered(area, width, rows + 2 + 2 * pad);
    f.render_widget(Clear, rect);
    let block = th
        .panel(Line::from(th.bold(Tone::Accent, title)))
        .border_style(th.style(Tone::Accent));
    let inner = block
        .inner(rect)
        .inner(ratatui::layout::Margin::new(2, pad));
    f.render_widget(block, rect);
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn draw_help(f: &mut Frame, area: Rect, th: Theme) {
    let key = |k: &str, what: &str| {
        Line::from(vec![
            th.bold(Tone::Plain, format!("{k:<15}")),
            th.span(Tone::Dim, what.to_owned()),
        ])
    };
    let legend = |mark: Mark, what: &str| {
        let (glyph, tone) = th.mark(mark);
        Line::from(vec![
            th.span(tone, format!("{glyph:<4}")),
            th.span(Tone::Dim, what.to_owned()),
        ])
    };
    let mut lines = vec![
        key("Tab, 1-5", "switch section"),
        key("Up/Down, j/k", "move through the list"),
        key("Space, Enter", "toggle, cycle or load"),
        key("/", "filter the list"),
        key("PgUp, PgDn", "scroll the details"),
        key("s, Ctrl-S", "validate and save"),
        key("q, Esc", "quit (asks if unsaved)"),
    ];
    // The symbol legend is the first thing to go on a short terminal.
    if area.height >= 24 {
        lines.extend([
            Line::default(),
            legend(Mark::On, "included in the build"),
            legend(Mark::Off, "not included"),
            legend(Mark::Locked, "required; cannot be turned off"),
            legend(Mark::Partial, "selected; missing on some boards"),
            legend(Mark::Forbidden, "forced off, even as a dependency"),
            legend(Mark::Failed, "selected, but cannot be satisfied"),
            legend(Mark::Absent, "applies to no selected board"),
        ]);
    }
    lines.push(Line::default());
    lines.push(Line::from(th.span(Tone::Dim, "Press any key to close.")));
    dialog(f, area, " Keys and symbols ", lines, th);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    const UNICODE: Theme = Theme {
        ascii: false,
        color: true,
    };
    const ASCII: Theme = Theme {
        ascii: true,
        color: false,
    };

    fn catalog() -> Catalog {
        toml::from_str(include_str!("../../../configs/catalog.toml")).unwrap()
    }
    fn press(a: &mut App, c: &Catalog, code: KeyCode) -> Action {
        a.key(c, KeyEvent::new(code, KeyModifiers::NONE))
    }
    fn screen(c: &Catalog, a: &App, th: Theme, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| draw(f, c, a, Path::new("vibeos.toml"), th))
            .unwrap();
        let buffer = t.backend().buffer();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn minimal_keeps_last_board_and_boot_driver() {
        let c = catalog();
        let mut a = App::new(c.preset("qemu-virt").unwrap(), true);
        a.toggle(&c);
        assert_eq!(a.config.boards.len(), 1);
        a.go(DRIVERS);
        a.toggle(&c);
        assert!(!a.config.drivers.contains_key("uart16550"));
    }

    #[test]
    fn search_and_dirty_exit_are_reversible() {
        let c = catalog();
        let mut a = App::new(c.preset("default").unwrap(), true);
        a.go(COMPONENTS);
        a.query = "SSH".into();
        assert_eq!(a.rows(&c, None)[0].id, "ssh");
        a.toggle(&c);
        assert!(a.dirty());
        // Escape clears the filter before it offers to quit.
        assert_eq!(press(&mut a, &c, KeyCode::Esc), Action::None);
        assert!(a.query.is_empty() && a.modal == Modal::None);
        assert_eq!(press(&mut a, &c, KeyCode::Char('q')), Action::None);
        assert_eq!(a.modal, Modal::Quit);
        press(&mut a, &c, KeyCode::Esc);
        assert_eq!(a.modal, Modal::None);
        press(&mut a, &c, KeyCode::Char('q'));
        assert_eq!(press(&mut a, &c, KeyCode::Char('s')), Action::SaveAndQuit);
        press(&mut a, &c, KeyCode::Char('q'));
        assert_eq!(press(&mut a, &c, KeyCode::Char('d')), Action::Quit);
    }

    #[test]
    fn typing_in_the_filter_never_triggers_commands() {
        let c = catalog();
        let mut a = App::new(c.preset("default").unwrap(), true);
        a.go(DRIVERS);
        press(&mut a, &c, KeyCode::Char('/'));
        for ch in "qs1".chars() {
            assert_eq!(press(&mut a, &c, KeyCode::Char(ch)), Action::None);
        }
        assert_eq!((a.query.as_str(), a.tab), ("qs1", DRIVERS));
    }

    #[test]
    fn first_run_starts_from_a_preset_without_confirmation() {
        let c = catalog();
        let mut a = App::new(c.preset("default").unwrap(), false);
        assert_eq!(a.tab, PRESETS);
        a.selected = preset_names(&c)
            .iter()
            .position(|p| p == "milkv-mars")
            .unwrap();
        press(&mut a, &c, KeyCode::Enter);
        assert_eq!(a.modal, Modal::None);
        assert_eq!(a.tab, BOARDS);
        assert_eq!(a.config, c.preset("milkv-mars").unwrap());
        // With unsaved edits, a preset must ask before replacing them.
        a.go(PRESETS);
        press(&mut a, &c, KeyCode::Enter);
        assert_eq!(a.modal, Modal::Preset("default".into()));
    }

    #[test]
    fn another_architecture_replaces_the_selection_only_after_confirmation() {
        let c = catalog();
        let mut a = App::new(c.preset("default").unwrap(), true);
        a.selected = c
            .boards
            .iter()
            .position(|b| b.id == "bpi-r4pro-4e")
            .unwrap();
        press(&mut a, &c, KeyCode::Char(' '));
        assert_eq!(a.modal, Modal::Switch("bpi-r4pro-4e".into()));
        press(&mut a, &c, KeyCode::Esc);
        assert_eq!(a.config, c.preset("default").unwrap());
        press(&mut a, &c, KeyCode::Char(' '));
        press(&mut a, &c, KeyCode::Enter);
        assert_eq!(a.config, c.preset("bpi-r4pro-4e").unwrap());
        let r = resolve(&c, &a.config).unwrap();
        r.require_valid().unwrap();
        assert_eq!(
            (r.arch.label(), r.target.as_str()),
            ("arm64", "aarch64-unknown-none-softfloat")
        );
        let text = screen(&c, &a, ASCII, 100, 30);
        assert!(text.contains("arm64 - 1 board"), "{text}");
        a.go(REVIEW);
        assert!(screen(&c, &a, ASCII, 100, 40).contains("VibeWrt"));
        // Going back to RISC-V asks again; RISC-V boards then combine freely.
        a.go(BOARDS);
        a.selected = 0;
        press(&mut a, &c, KeyCode::Char(' '));
        assert_eq!(a.modal, Modal::Switch("qemu-virt".into()));
        press(&mut a, &c, KeyCode::Enter);
        a.selected = 1;
        press(&mut a, &c, KeyCode::Char(' '));
        assert_eq!((a.modal.clone(), a.config.boards.len()), (Modal::None, 2));
    }

    #[test]
    fn rows_show_the_resolved_outcome() {
        let c = catalog();
        let mut a = App::new(c.preset("default").unwrap(), true);
        a.config.components.insert("ssh".into());
        a.config.drivers.insert("xhci".into(), Selection::Off);
        let r = resolve(&c, &a.config).unwrap();
        a.go(DRIVERS);
        let rows = a.rows(&c, Some(&r));
        let find = |id: &str| rows.iter().find(|r| r.id == id).unwrap();
        assert_eq!(find("uart16550").mark, Mark::Locked);
        assert_eq!(find("virtio-blk").mark, Mark::On);
        // SSH needs entropy; the resolver picked a provider the user left on auto.
        assert_eq!(
            (find("virtio-rng").mark, find("virtio-rng").note.as_str()),
            (Mark::On, "auto, in use")
        );
        assert_eq!(find("xhci").mark, Mark::Forbidden);
        // Drivers for boards that are not selected sink to the bottom, faded.
        a.config = c.preset("qemu-virt").unwrap();
        let r = resolve(&c, &a.config).unwrap();
        let rows = a.rows(&c, Some(&r));
        assert!(rows.last().unwrap().faded && !rows[0].faded);
        assert_eq!(
            rows.iter().find(|r| r.id == "eqos-net").unwrap().mark,
            Mark::Absent
        );
    }

    #[test]
    fn conflicts_surface_in_status_and_review() {
        let c = catalog();
        let mut a = App::new(c.preset("default").unwrap(), true);
        a.config
            .components
            .extend(["ssh".to_owned(), "iperf3".to_owned()]);
        let text = screen(&c, &a, ASCII, 100, 30);
        assert!(text.contains("iperf3 conflicts with ssh"), "{text}");
        a.go(COMPONENTS);
        let r = resolve(&c, &a.config).unwrap();
        let rows = a.rows(&c, Some(&r));
        let ssh = rows.iter().find(|r| r.id == "ssh").unwrap();
        assert_eq!(
            (ssh.mark, ssh.note.as_str()),
            (Mark::Failed, "conflicts with iperf3")
        );
        a.go(REVIEW);
        let text = screen(&c, &a, ASCII, 100, 30);
        assert!(text.contains("2 problems to fix before saving"), "{text}");
    }

    #[test]
    fn renders_every_section_at_every_size_in_both_themes() {
        let c = catalog();
        let mut a = App::new(c.preset("default").unwrap(), true);
        for tab in 0..TABS.len() {
            a.go(tab);
            for modal in [
                Modal::None,
                Modal::Help,
                Modal::Quit,
                Modal::Preset("minimal".into()),
                Modal::Switch("bpi-r4pro-4e".into()),
            ] {
                a.modal = modal;
                for (w, h) in [(40, 10), (50, 12), (60, 15), (80, 24), (140, 40)] {
                    let anchor = match (&a.modal, w >= 50 && h >= 12) {
                        (Modal::Help, true) => "Press any key to close.",
                        (Modal::Quit, true) => "keep editing",
                        (Modal::Switch(_), true) => "cancel",
                        _ => "VibeOS",
                    };
                    assert!(screen(&c, &a, UNICODE, w, h).contains(anchor), "{w}x{h}");
                    let text = screen(&c, &a, ASCII, w, h);
                    assert!(text.contains(anchor), "{w}x{h}\n{text}");
                    assert!(text.is_ascii(), "non-ASCII cell in ASCII theme:\n{text}");
                }
            }
        }
    }

    /// Prints representative screens:
    /// `cargo test -p vibeos-config --features tui preview -- --ignored --nocapture`
    #[test]
    #[ignore = "prints screens for visual review"]
    fn preview() {
        let c = catalog();
        let mut a = App::new(c.preset("default").unwrap(), true);
        a.config.components.insert("ssh".into());
        for tab in [PRESETS, REVIEW] {
            a.go(tab);
            println!("{}\n", screen(&c, &a, UNICODE, 100, 28));
        }
        a.modal = Modal::Help;
        println!("{}\n", screen(&c, &a, UNICODE, 100, 28));
        a.modal = Modal::Quit;
        println!("{}\n", screen(&c, &a, ASCII, 60, 15));
        a.modal = Modal::None;
        a.config.components.insert("iperf3".into());
        a.go(COMPONENTS);
        println!("{}\n", screen(&c, &a, UNICODE, 100, 16));
        a.go(BOARDS);
        println!("{}\n", screen(&c, &a, ASCII, 78, 24));
        a.config = c.preset("default").unwrap();
        a.selected = 3;
        println!("{}\n", screen(&c, &a, UNICODE, 100, 24));
        press(&mut a, &c, KeyCode::Char(' '));
        println!("{}\n", screen(&c, &a, UNICODE, 100, 24));
        press(&mut a, &c, KeyCode::Enter);
        a.go(REVIEW);
        println!("{}\n", screen(&c, &a, UNICODE, 100, 30));
    }
}
