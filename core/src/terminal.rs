//! Transport-independent, per-session terminal line discipline.
//!
//! A [`LineDiscipline`] owns exactly one editable input line, escape decoder,
//! and history. It returns bounded rendering actions instead of writing a
//! transport directly, so a synchronous UART adapter and a backpressured SSH
//! adapter can share the state machine without sharing session state.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;

pub const MAX_INPUT_BYTES: usize = 4 * 1024;
pub const MAX_HISTORY_ENTRIES: usize = 64;
pub const MAX_HISTORY_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EscapeState {
    Ground,
    Escape,
    Csi { plain: bool },
}

/// A completed terminal input event. Transport EOF remains distinct from the
/// Ctrl-D byte so each frontend can define its own wire semantics explicitly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalEvent {
    Line(String),
    Interrupt,
    Eof,
}

/// One bounded rendering or control action produced by an input byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputAction {
    None,
    Echo(char),
    Bell,
    BackspaceTail,
    MoveLeft,
    MoveRight,
    Redraw,
    Event(TerminalEvent),
}

/// Editable input and history for one terminal session.
///
/// The type contains no global state, transport, lock, allocator owner, prompt,
/// or capability. Its owner decides how actions are rendered and how completed
/// events are routed to a shell session.
pub struct LineDiscipline {
    input: String,
    cursor: usize,
    history: VecDeque<String>,
    history_bytes: usize,
    history_index: Option<usize>,
    draft: String,
    escape: EscapeState,
}

impl LineDiscipline {
    pub const fn new() -> Self {
        Self {
            input: String::new(),
            cursor: 0,
            history: VecDeque::new(),
            history_bytes: 0,
            history_index: None,
            draft: String::new(),
            escape: EscapeState::Ground,
        }
    }

    /// Clear the current editable line while preserving this session's history.
    pub fn reset_line(&mut self) {
        self.input.clear();
        self.cursor = 0;
        self.history_index = None;
        self.draft.clear();
        self.escape = EscapeState::Ground;
    }

    /// Feed one raw terminal byte through the incremental escape decoder.
    ///
    /// The current UART contract admits printable ASCII. A future UTF-8 SSH
    /// frontend must decode and validate multibyte input explicitly rather than
    /// smuggling partial code points through this byte API.
    pub fn feed_byte(&mut self, byte: u8) -> InputAction {
        match self.escape {
            EscapeState::Escape => {
                self.escape = if byte == b'[' {
                    EscapeState::Csi { plain: true }
                } else {
                    EscapeState::Ground
                };
                return InputAction::None;
            }
            EscapeState::Csi { plain } => {
                if (0x40..=0x7e).contains(&byte) {
                    self.escape = EscapeState::Ground;
                    return if plain {
                        match byte {
                            b'A' => self.history_previous(),
                            b'B' => self.history_next(),
                            b'C' => self.move_right(),
                            b'D' => self.move_left(),
                            _ => InputAction::None,
                        }
                    } else {
                        InputAction::None
                    };
                }
                if (0x20..=0x3f).contains(&byte) {
                    // Consume parameters and intermediates through the final
                    // byte. Unsupported sequences must not leak their suffix
                    // into the command line when an SSH client sends richer
                    // key encodings such as ESC[1;5D or ESC[3~.
                    self.escape = EscapeState::Csi { plain: false };
                    return InputAction::None;
                }
                self.escape = EscapeState::Ground;
                return InputAction::None;
            }
            EscapeState::Ground => {}
        }

        match byte {
            b'\r' | b'\n' => self.submit(),
            0x7f | 0x08 => self.backspace(),
            0x03 => self.interrupt(),
            0x1b => {
                self.escape = EscapeState::Escape;
                InputAction::None
            }
            byte if (0x20..0x7f).contains(&byte) => self.type_char(byte as char),
            _ => InputAction::None,
        }
    }

    /// Produce a session interrupt without interpreting a transport byte.
    pub fn interrupt(&mut self) -> InputAction {
        self.reset_line();
        InputAction::Event(TerminalEvent::Interrupt)
    }

    /// End this input transport without treating EOF as Ctrl-C or a submitted
    /// empty line.
    pub fn transport_eof(&mut self) -> InputAction {
        self.reset_line();
        InputAction::Event(TerminalEvent::Eof)
    }

    pub fn input(&self) -> &str {
        &self.input
    }

    /// Number of displayed characters between the cursor and the end of input.
    pub fn cursor_tail_chars(&self) -> usize {
        self.input[self.cursor..].chars().count()
    }

    fn type_char(&mut self, character: char) -> InputAction {
        if self.input.len().saturating_add(character.len_utf8()) > MAX_INPUT_BYTES {
            return InputAction::Bell;
        }
        let appended = self.cursor == self.input.len();
        self.input.insert(self.cursor, character);
        self.cursor += character.len_utf8();
        self.history_index = None;
        self.draft.clear();
        if appended {
            InputAction::Echo(character)
        } else {
            InputAction::Redraw
        }
    }

    fn backspace(&mut self) -> InputAction {
        if self.cursor == 0 {
            return InputAction::None;
        }
        let removed_from_end = self.cursor == self.input.len();
        let previous = self.input[..self.cursor]
            .char_indices()
            .last()
            .map(|(index, _)| index)
            .unwrap_or(0);
        self.input.remove(previous);
        self.cursor = previous;
        self.history_index = None;
        self.draft.clear();
        if removed_from_end {
            InputAction::BackspaceTail
        } else {
            InputAction::Redraw
        }
    }

    fn move_left(&mut self) -> InputAction {
        if self.cursor == 0 {
            return InputAction::None;
        }
        self.cursor = self.input[..self.cursor]
            .char_indices()
            .last()
            .map(|(index, _)| index)
            .unwrap_or(0);
        InputAction::MoveLeft
    }

    fn move_right(&mut self) -> InputAction {
        if self.cursor == self.input.len() {
            return InputAction::None;
        }
        self.cursor += self.input[self.cursor..]
            .chars()
            .next()
            .map(char::len_utf8)
            .unwrap_or(0);
        InputAction::MoveRight
    }

    fn history_previous(&mut self) -> InputAction {
        if self.history.is_empty() {
            return InputAction::None;
        }
        let index = match self.history_index {
            Some(0) => 0,
            Some(index) => index - 1,
            None => {
                self.draft = self.input.clone();
                self.history.len() - 1
            }
        };
        self.history_index = Some(index);
        self.input = self.history[index].clone();
        self.cursor = self.input.len();
        InputAction::Redraw
    }

    fn history_next(&mut self) -> InputAction {
        let Some(index) = self.history_index else {
            return InputAction::None;
        };
        if index + 1 < self.history.len() {
            let next = index + 1;
            self.history_index = Some(next);
            self.input = self.history[next].clone();
        } else {
            self.history_index = None;
            self.input = core::mem::take(&mut self.draft);
        }
        self.cursor = self.input.len();
        InputAction::Redraw
    }

    fn submit(&mut self) -> InputAction {
        self.escape = EscapeState::Ground;
        let line = core::mem::take(&mut self.input);
        self.cursor = 0;
        self.history_index = None;
        self.draft.clear();
        if !line.is_empty() && self.history.back().is_none_or(|last| last != &line) {
            while self.history.len() >= MAX_HISTORY_ENTRIES
                || self.history_bytes.saturating_add(line.len()) > MAX_HISTORY_BYTES
            {
                let Some(oldest) = self.history.pop_front() else {
                    break;
                };
                self.history_bytes -= oldest.len();
            }
            self.history_bytes += line.len();
            self.history.push_back(line.clone());
        }
        InputAction::Event(TerminalEvent::Line(line))
    }
}

impl Default for LineDiscipline {
    fn default() -> Self {
        Self::new()
    }
}
