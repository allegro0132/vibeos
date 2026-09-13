use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use std::{io, path::Path, time::Duration};
use vibeos_config::{resolve, Catalog, Config, Kind, Result, Selection};

const ASCII_BORDER: ratatui::symbols::border::Set<'static> = ratatui::symbols::border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "-",
    horizontal_bottom: "-",
};
const CATEGORIES: [&str; 5] = ["Boards", "Drivers", "Components", "Presets", "Preview"];
const PRESETS: [&str; 5] = ["default", "minimal", "qemu-virt", "milkv-duo", "milkv-mars"];
struct App {
    config: Config,
    saved: Config,
    category: usize,
    selected: usize,
    query: String,
    searching: bool,
    status: String,
    confirm_exit: bool,
    confirm_preset: Option<String>,
    scroll: u16,
}
impl App {
    fn new(config: Config) -> Self {
        Self {
            saved: config.clone(),
            config,
            category: 0,
            selected: 0,
            query: String::new(),
            searching: false,
            status: "Tab category | Space toggle | / search | Ctrl-S save | ? help".into(),
            confirm_exit: false,
            confirm_preset: None,
            scroll: 0,
        }
    }
    fn dirty(&self) -> bool {
        self.config != self.saved
    }
    fn ids(&self, c: &Catalog) -> Vec<String> {
        let candidates: Vec<(String, String)> = match self.category {
            0 => c
                .boards
                .iter()
                .map(|b| (b.id.clone(), format!("{} {}", b.name, b.description)))
                .collect(),
            1 | 2 => c
                .nodes
                .iter()
                .filter(|n| {
                    n.kind
                        == if self.category == 1 {
                            Kind::Driver
                        } else {
                            Kind::Component
                        }
                })
                .map(|n| (n.id.clone(), format!("{} {}", n.name, n.description)))
                .collect(),
            3 => PRESETS
                .iter()
                .map(|p| (p.to_string(), p.to_string()))
                .collect(),
            _ => vec![],
        };
        let q = self.query.to_lowercase();
        candidates
            .into_iter()
            .filter(|(id, text)| format!("{id} {text}").to_lowercase().contains(&q))
            .map(|(id, _)| id)
            .collect()
    }
    fn toggle(&mut self, c: &Catalog) {
        let ids = self.ids(c);
        let Some(id) = ids.get(self.selected) else {
            return;
        };
        match self.category {
            0 => {
                if self.config.boards.contains(id) {
                    if self.config.boards.len() == 1 {
                        self.status = "Keep at least one board.".into();
                        return;
                    }
                    self.config.boards.remove(id);
                } else {
                    self.config.boards.insert(id.clone());
                }
            }
            1 => {
                if self
                    .config
                    .boards
                    .iter()
                    .filter_map(|b| c.board(b))
                    .any(|b| b.required.contains(id))
                {
                    self.status = format!("{id} is required to boot a selected board.");
                    return;
                }
                let current = self.config.drivers.get(id).copied().unwrap_or_default();
                self.config.drivers.insert(id.clone(), current.next());
            }
            2 => {
                if id == "vsh" {
                    self.status = "VSH is required by the minimal system.".into();
                    return;
                }
                if !self.config.components.remove(id) {
                    self.config.components.insert(id.clone());
                }
            }
            3 => {
                self.confirm_preset = Some(id.clone());
            }
            _ => {}
        }
        self.scroll = 0;
    }
    fn key(&mut self, c: &Catalog, key: KeyEvent) -> bool {
        if self.confirm_exit {
            match key.code {
                KeyCode::Char('y') => return true,
                KeyCode::Char('n') | KeyCode::Esc => self.confirm_exit = false,
                _ => {}
            }
            return false;
        }
        if let Some(preset) = self.confirm_preset.clone() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    self.config = c.preset(&preset).unwrap();
                    self.confirm_preset = None;
                    self.status = format!("Loaded {preset}; Ctrl-S to save.");
                }
                KeyCode::Char('n') | KeyCode::Esc => self.confirm_preset = None,
                _ => {}
            }
            return false;
        }
        if self.searching {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => self.searching = false,
                KeyCode::Backspace => {
                    self.query.pop();
                }
                KeyCode::Char(ch) => self.query.push(ch),
                _ => {}
            }
            self.selected = 0;
            return false;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => { if self.dirty() { self.confirm_exit = true; } else { return true; } },
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => { if self.dirty() { self.confirm_exit = true; } else { return true; } },
            KeyCode::Tab | KeyCode::Right => { self.category = (self.category + 1) % CATEGORIES.len(); self.selected = 0; self.query.clear(); self.scroll = 0; },
            KeyCode::BackTab | KeyCode::Left => { self.category = (self.category + CATEGORIES.len() - 1) % CATEGORIES.len(); self.selected = 0; self.query.clear(); self.scroll = 0; },
            KeyCode::Down | KeyCode::Char('j') => self.selected = (self.selected + 1).min(self.ids(c).len().saturating_sub(1)),
            KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.saturating_sub(1),
            KeyCode::Home => self.selected = 0,
            KeyCode::End => self.selected = self.ids(c).len().saturating_sub(1),
            KeyCode::PageDown => self.scroll = self.scroll.saturating_add(8),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(8),
            KeyCode::Char('/') => { self.searching = true; self.query.clear(); },
            KeyCode::Char(' ') | KeyCode::Enter => self.toggle(c),
            KeyCode::Char('?') => self.status = "Left/Right/Tab category | Up/Down/j/k select | Space toggle | / search | PgUp/PgDn scroll | Ctrl-S save | q quit; AUTO resolve / ON require / OFF forbid".into(),
            _ => {},
        }
        false
    }
}

struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}
pub fn run(root: &Path, c: &Catalog, config: Config, path: &Path) -> Result<()> {
    let old_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        old_hook(info);
    }));
    let _restore = Restore;
    enable_raw_mode().map_err(|e| e.to_string())?;
    execute!(io::stdout(), EnterAlternateScreen).map_err(|e| e.to_string())?;
    let mut terminal =
        Terminal::new(CrosstermBackend::new(io::stdout())).map_err(|e| e.to_string())?;
    let mut app = App::new(config);
    loop {
        terminal
            .draw(|f| draw(f, c, &app, path))
            .map_err(|e| e.to_string())?;
        if !event::poll(Duration::from_millis(200)).map_err(|e| e.to_string())? {
            continue;
        }
        if let Event::Key(key) = event::read().map_err(|e| e.to_string())? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if key.code == KeyCode::Char('s')
                && key.modifiers.contains(KeyModifiers::CONTROL)
                && !app.searching
                && !app.confirm_exit
                && app.confirm_preset.is_none()
            {
                let result = resolve(c, &app.config).and_then(|r| {
                    c.check_features(root)?;
                    super::save(root, path, &app.config, &r)
                });
                match result {
                    Ok(()) => {
                        app.saved = app.config.clone();
                        app.status = format!(
                            "Saved {}; build with ./build.sh --config {}.",
                            path.display(),
                            path.display()
                        );
                    }
                    Err(e) => app.status = format!("Save failed: {e}"),
                }
            } else if app.key(c, key) {
                break;
            }
        }
    }
    Ok(())
}

fn draw(f: &mut Frame, c: &Catalog, app: &App, path: &Path) {
    let area = f.area();
    if area.width < 60 || area.height < 15 {
        f.render_widget(Paragraph::new("VibeOS Configurator\nResize the terminal to at least 60 x 15.\nSelection preserved; Ctrl-S saves, q quits.").wrap(Wrap { trim: false }), area);
        return;
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(7),
            Constraint::Length(4),
        ])
        .split(area);
    let title = format!(
        "VibeOS Configurator {}  {}",
        if app.dirty() { "* unsaved" } else { "x" },
        path.display()
    );
    f.render_widget(
        Paragraph::new(title)
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(
                Block::default()
                    .border_set(ASCII_BORDER)
                    .borders(Borders::BOTTOM),
            ),
        rows[0],
    );
    let widths = if area.width >= 100 {
        [
            Constraint::Length(15),
            Constraint::Length(35),
            Constraint::Min(35),
        ]
    } else {
        [
            Constraint::Length(12),
            Constraint::Percentage(40),
            Constraint::Min(20),
        ]
    };
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(widths)
        .split(rows[1]);
    let mut category_state = ListState::default().with_selected(Some(app.category));
    f.render_stateful_widget(
        List::new(CATEGORIES)
            .highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
            .block(
                Block::default()
                    .border_set(ASCII_BORDER)
                    .title("Categories")
                    .borders(Borders::ALL),
            ),
        columns[0],
        &mut category_state,
    );
    let resolved = resolve(c, &app.config);
    let ids = app.ids(c);
    let items: Vec<ListItem> = ids
        .iter()
        .map(|id| {
            let (mark, name) = match app.category {
                0 => (
                    if app.config.boards.contains(id) {
                        "[x]"
                    } else {
                        "[ ]"
                    },
                    c.board(id).unwrap().name.as_str(),
                ),
                1 => {
                    let n = c.node(id).unwrap();
                    let mark = if app
                        .config
                        .boards
                        .iter()
                        .filter_map(|b| c.board(b))
                        .any(|b| b.required.contains(id))
                    {
                        "[REQ]"
                    } else {
                        match app.config.drivers.get(id).copied().unwrap_or_default() {
                            Selection::On => "[ON]",
                            Selection::Off => "[OFF]",
                            Selection::Auto => "[AUTO]",
                        }
                    };
                    (mark, n.name.as_str())
                }
                2 => (
                    if id == "vsh" {
                        "[REQ]"
                    } else if app.config.components.contains(id) {
                        "[x]"
                    } else {
                        "[ ]"
                    },
                    c.node(id).unwrap().name.as_str(),
                ),
                _ => (">", id.as_str()),
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{mark} "), Style::default().fg(Color::Cyan)),
                Span::raw(name),
            ]))
        })
        .collect();
    let mut state = ListState::default().with_selected(if items.is_empty() {
        None
    } else {
        Some(app.selected.min(items.len() - 1))
    });
    f.render_stateful_widget(
        List::new(items)
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .block(
                Block::default()
                    .border_set(ASCII_BORDER)
                    .title(if app.query.is_empty() {
                        "Select".into()
                    } else {
                        format!("Search: {}", app.query)
                    })
                    .borders(Borders::ALL),
            ),
        columns[1],
        &mut state,
    );
    let details = if app.category == 4 {
        match &resolved {
            Ok(r) => format!(
                "{}\n\n{}",
                r.report(),
                toml::to_string_pretty(&app.config).unwrap_or_default()
            ),
            Err(e) => e.clone(),
        }
    } else if let Some(id) = ids.get(app.selected) {
        let mut text = if let Some(n) = c.node(id) {
            format!(
                "{}\n{}\n\n{}\n\nRequires: {}\nConflicts: {}\n",
                n.name,
                n.id,
                n.description,
                n.requires.join(", "),
                n.conflicts.join(", ")
            )
        } else if let Some(b) = c.board(id) {
            format!(
                "{}\n\n{}\n\nBoot requirements: {}\nLoad address: {:#x}\n",
                b.name,
                b.description,
                b.required.join(", "),
                b.load_address
            )
        } else {
            format!(
                "Load {id} preset\n\nEnter to confirm replacing the selection. Save after loading."
            )
        };
        if let Ok(r) = &resolved {
            for (board, plan) in &r.boards {
                text.push_str(&format!("\n{board}: "));
                if plan.enabled.contains(id) {
                    text.push_str("Included / available\n");
                    if let Some(reasons) = plan.reasons.get(id) {
                        for reason in reasons {
                            text.push_str(&format!("  {reason}\n"));
                        }
                    }
                } else if let Some(why) = plan.unavailable.get(id) {
                    text.push_str(&format!("Unavailable\n  {why}\n"));
                } else {
                    text.push_str("Not selected or not applicable\n");
                }
            }
        }
        text
    } else {
        "No matches. Press / to search again.".into()
    };
    let detail_area = if app.category == 4 {
        Rect {
            x: columns[1].x,
            y: columns[1].y,
            width: columns[1].width + columns[2].width,
            height: columns[1].height,
        }
    } else {
        columns[2]
    };
    f.render_widget(
        Paragraph::new(details)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll, 0))
            .block(
                Block::default()
                    .border_set(ASCII_BORDER)
                    .title("Details / dependencies / boards")
                    .borders(Borders::ALL),
            ),
        detail_area,
    );
    let validation = match resolved {
        Ok(r) if r.valid() => "Dependencies valid".into(),
        Ok(r) => r.errors.join("; "),
        Err(e) => e,
    };
    let footer = if app.searching {
        format!(
            "Search: {}|  Enter finish / Esc close\n{validation}",
            app.query
        )
    } else {
        format!("{}\n{validation}", app.status)
    };
    f.render_widget(
        Paragraph::new(footer).wrap(Wrap { trim: false }).block(
            Block::default()
                .border_set(ASCII_BORDER)
                .borders(Borders::TOP),
        ),
        rows[2],
    );
    if app.confirm_exit || app.confirm_preset.is_some() {
        let dialog = Rect {
            x: area.x + area.width / 8,
            y: area.y + area.height / 3,
            width: area.width * 3 / 4,
            height: 5,
        };
        f.render_widget(Clear, dialog);
        let text = if app.confirm_exit {
            "Discard unsaved changes and quit?\n\n y discard   n / Esc return".to_owned()
        } else {
            format!(
                "Replace the current selection with {}?\n\n y / Enter load   n / Esc return",
                app.confirm_preset.as_ref().unwrap()
            )
        };
        f.render_widget(
            Paragraph::new(text)
                .block(
                    Block::default()
                        .border_set(ASCII_BORDER)
                        .title("Confirm")
                        .borders(Borders::ALL),
                )
                .wrap(Wrap { trim: false }),
            dialog,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn catalog() -> Catalog {
        toml::from_str(include_str!("../../../configs/catalog.toml")).unwrap()
    }
    #[test]
    fn minimal_keeps_last_board_and_boot_driver() {
        let c = catalog();
        let mut a = App::new(c.preset("qemu-virt").unwrap());
        a.toggle(&c);
        assert_eq!(a.config.boards.len(), 1);
        a.category = 1;
        a.toggle(&c);
        assert!(!a.config.drivers.contains_key("uart16550"));
    }
    #[test]
    fn search_and_dirty_exit_are_reversible() {
        let c = catalog();
        let mut a = App::new(c.preset("default").unwrap());
        a.category = 2;
        a.query = "SSH".into();
        assert!(a.ids(&c).contains(&"ssh".to_owned()));
        a.toggle(&c);
        assert!(a.dirty());
        assert!(!a.key(&c, KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
        assert!(a.confirm_exit);
        a.key(&c, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!a.confirm_exit);
    }
    #[test]
    fn render_handles_small_and_normal_terminals() {
        let c = catalog();
        let a = App::new(c.preset("default").unwrap());
        for (w, h) in [(40, 10), (60, 15), (80, 24), (140, 40)] {
            let mut t = Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
            t.draw(|f| draw(f, &c, &a, Path::new("vibeos.toml")))
                .unwrap();
            assert!(t
                .backend()
                .buffer()
                .content()
                .iter()
                .all(|cell| cell.symbol().is_ascii()));
            let text = t
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            assert!(text.contains("VibeOS"));
        }
    }
}
