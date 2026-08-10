//! Transport-independent, per-session terminal line discipline.
//!
//! A [`LineDiscipline`] owns exactly one editable input line, escape decoder,
//! and history. It returns bounded rendering actions instead of writing a
//! transport directly, so a synchronous UART adapter and a backpressured SSH
//! adapter can share the state machine without sharing session state.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

pub const MAX_INPUT_BYTES: usize = 4 * 1024;
pub const MAX_HISTORY_ENTRIES: usize = 64;
pub const MAX_HISTORY_BYTES: usize = 64 * 1024;
pub const MAX_PROMPT_BYTES: usize = 64;
pub const MAX_EMIT_TEXT_BYTES: usize = 1024;
pub const MAX_PENDING_OUTPUT_BYTES: usize = 8 * 1024;
pub const CONTROL_OUTPUT_RESERVE_BYTES: usize = 6;
pub const MAX_REGULAR_PENDING_OUTPUT_BYTES: usize =
    MAX_PENDING_OUTPUT_BYTES - CONTROL_OUTPUT_RESERVE_BYTES;

const ERASE_LINE: &[u8] = b"\r\x1b[2K";
const MAX_CURSOR_MOVE_BYTES: usize = 23;
const MAX_INPUT_ACTION_BYTES: usize =
    ERASE_LINE.len() + MAX_PROMPT_BYTES + MAX_INPUT_BYTES + MAX_CURSOR_MOVE_BYTES;
const _: () = assert!(MAX_INPUT_ACTION_BYTES <= MAX_REGULAR_PENDING_OUTPUT_BYTES);

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

/// A bounded terminal frontend error. Backpressure and oversized writes are
/// distinct so callers know whether draining and retrying can make progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontendError {
    Backpressure,
    OutputTooLarge,
    PromptTooLong,
    AllocationFailed,
    InvalidConsume,
    PromptActive,
    OutputInProgress,
    NoOutputInProgress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrontendState {
    Inactive,
    PromptVisible,
    PromptSuspended,
}

/// Per-session terminal renderer with a contiguous, bounded output queue.
///
/// The owner feeds channel bytes, handles returned [`TerminalEvent`]s, and
/// writes [`Self::pending_output`] in whatever partial chunks its transport
/// permits. No terminal state or output is shared between instances.
pub struct TerminalFrontend {
    line: LineDiscipline,
    prompt: String,
    output: Vec<u8>,
    output_start: usize,
    state: FrontendState,
    last_text_was_cr: bool,
    last_text_ended_line: bool,
    async_output_had_text: bool,
}

impl TerminalFrontend {
    pub const fn new() -> Self {
        Self {
            line: LineDiscipline::new(),
            prompt: String::new(),
            output: Vec::new(),
            output_start: 0,
            state: FrontendState::Inactive,
            last_text_was_cr: false,
            last_text_ended_line: false,
            async_output_had_text: false,
        }
    }

    /// Queue a fresh prompt after all output already pending for this session.
    pub fn show_prompt(&mut self, prompt: &str) -> Result<(), FrontendError> {
        if prompt.len() > MAX_PROMPT_BYTES
            || !prompt.bytes().all(|byte| (0x20..0x7f).contains(&byte))
        {
            return Err(FrontendError::PromptTooLong);
        }
        self.prompt
            .try_reserve(prompt.len())
            .map_err(|_| FrontendError::AllocationFailed)?;
        self.prepare_append(ERASE_LINE.len() + prompt.len())?;

        self.prompt.clear();
        self.prompt.push_str(prompt);
        self.line.reset_line();
        self.at_prompt = true;
        self.last_text_was_cr = false;
        self.append_raw(ERASE_LINE);
        self.append_raw(prompt.as_bytes());
        Ok(())
    }

    /// Feed one SSH terminal byte. A backpressure error leaves both the input
    /// state and pending output logically unchanged, so the exact byte may be
    /// retried after draining.
    pub fn input_byte(&mut self, byte: u8) -> Result<Option<TerminalEvent>, FrontendError> {
        if byte == 0x04 {
            if !self.at_prompt || self.line.input().is_empty() {
                return Ok(Some(self.finish_eof()));
            }
            return Ok(None);
        }

        if byte == 0x03 {
            return self.interrupt().map(Some);
        }

        if !self.at_prompt {
            return Ok(None);
        }

        // Reserve enough for the largest possible redraw before mutating the
        // editable line. Rendering below is then allocation-free and atomic.
        self.prepare_append(MAX_INPUT_ACTION_BYTES)?;
        let action = self.line.feed_byte(byte);
        Ok(self.render_input(action))
    }

    /// Interrupt this session without routing through a shared terminal. This
    /// is also used for an SSH `signal` request, so it has the same atomic
    /// backpressure contract as [`Self::input_byte`].
    pub fn interrupt(&mut self) -> Result<TerminalEvent, FrontendError> {
        self.prepare_append(b"^C\r\n".len())?;
        let InputAction::Event(event) = self.line.interrupt() else {
            unreachable!()
        };
        self.at_prompt = false;
        self.last_text_was_cr = false;
        self.append_raw(b"^C\r\n");
        Ok(event)
    }

    /// Report transport EOF independently of any terminal control byte.
    pub fn transport_eof(&mut self) -> TerminalEvent {
        self.finish_eof()
    }

    /// Queue asynchronous UTF-8 output. Bare LF is rendered as CRLF, matching
    /// the physical UART and a terminal with output newline processing. If a
    /// prompt is active it is erased and redrawn as one atomic queue append.
    pub fn emit_text(&mut self, text: &str) -> Result<(), FrontendError> {
        if text.is_empty() {
            return Ok(());
        }
        if text.len() > MAX_EMIT_TEXT_BYTES {
            return Err(FrontendError::OutputTooLarge);
        }
        let continues_text = !self.at_prompt && self.last_text_was_cr;
        let text_len = terminal_text_len(text.as_bytes(), continues_text)?;
        let redraw_len = if self.at_prompt {
            ERASE_LINE.len() + self.redraw_contents_len()
        } else {
            0
        };
        let additional = text_len
            .checked_add(redraw_len)
            .ok_or(FrontendError::OutputTooLarge)?;
        self.prepare_append(additional)?;

        if self.at_prompt {
            self.append_raw(ERASE_LINE);
        }
        self.append_terminal_text(text.as_bytes(), continues_text);
        if self.at_prompt {
            self.append_redraw_contents();
            self.last_text_was_cr = false;
        } else {
            self.last_text_was_cr = text.as_bytes().last() == Some(&b'\r');
        }
        Ok(())
    }

    pub fn pending_output(&self) -> &[u8] {
        &self.output[self.output_start..]
    }

    pub fn pending_len(&self) -> usize {
        self.output.len() - self.output_start
    }

    /// Acknowledge bytes successfully consumed by the transport.
    pub fn consume_output(&mut self, count: usize) -> Result<(), FrontendError> {
        if count > self.pending_len() {
            return Err(FrontendError::InvalidConsume);
        }
        self.output_start += count;
        if self.output_start == self.output.len() {
            self.output.clear();
            self.output_start = 0;
        }
        Ok(())
    }

    pub fn input(&self) -> &str {
        self.line.input()
    }

    pub fn cursor_tail_chars(&self) -> usize {
        self.line.cursor_tail_chars()
    }

    pub fn is_at_prompt(&self) -> bool {
        self.at_prompt
    }

    fn finish_eof(&mut self) -> TerminalEvent {
        let InputAction::Event(event) = self.line.transport_eof() else {
            unreachable!()
        };
        self.at_prompt = false;
        self.last_text_was_cr = false;
        event
    }

    fn render_input(&mut self, action: InputAction) -> Option<TerminalEvent> {
        match action {
            InputAction::None => None,
            InputAction::Echo(character) => {
                let mut encoded = [0; 4];
                self.append_raw(character.encode_utf8(&mut encoded).as_bytes());
                None
            }
            InputAction::Bell => {
                self.append_raw(b"\x07");
                None
            }
            InputAction::BackspaceTail => {
                self.append_raw(b"\x08 \x08");
                None
            }
            InputAction::MoveLeft => {
                self.append_raw(b"\x1b[D");
                None
            }
            InputAction::MoveRight => {
                self.append_raw(b"\x1b[C");
                None
            }
            InputAction::Redraw => {
                self.append_raw(ERASE_LINE);
                self.append_redraw_contents();
                None
            }
            InputAction::Event(event) => {
                self.at_prompt = false;
                self.last_text_was_cr = false;
                match event {
                    TerminalEvent::Line(_) => self.append_raw(b"\r\n"),
                    TerminalEvent::Interrupt => self.append_raw(b"^C\r\n"),
                    TerminalEvent::Eof => {}
                }
                Some(event)
            }
        }
    }

    fn redraw_contents_len(&self) -> usize {
        self.prompt.len() + self.line.input().len() + cursor_left_len(self.line.cursor_tail_chars())
    }

    fn append_redraw_contents(&mut self) {
        let prompt_len = self.prompt.len();
        let input_len = self.line.input().len();
        self.output.extend_from_slice(self.prompt.as_bytes());
        self.output.extend_from_slice(self.line.input().as_bytes());
        debug_assert_eq!(self.prompt.len(), prompt_len);
        debug_assert_eq!(self.line.input().len(), input_len);
        self.append_cursor_left(self.line.cursor_tail_chars());
    }

    fn append_cursor_left(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        let mut digits = [0u8; 20];
        let mut value = count;
        let mut start = digits.len();
        while value != 0 {
            start -= 1;
            digits[start] = b'0' + (value % 10) as u8;
            value /= 10;
        }
        self.append_raw(b"\x1b[");
        self.append_raw(&digits[start..]);
        self.append_raw(b"D");
    }

    fn append_terminal_text(&mut self, text: &[u8], previous_was_cr: bool) {
        let mut previous = previous_was_cr.then_some(b'\r');
        for byte in text.iter().copied() {
            if byte == b'\n' && previous != Some(b'\r') {
                self.output.push(b'\r');
            }
            self.output.push(byte);
            previous = Some(byte);
        }
    }

    fn append_raw(&mut self, bytes: &[u8]) {
        self.output.extend_from_slice(bytes);
        debug_assert!(self.pending_len() <= MAX_PENDING_OUTPUT_BYTES);
    }

    fn prepare_append(&mut self, additional: usize) -> Result<(), FrontendError> {
        if additional > MAX_PENDING_OUTPUT_BYTES {
            return Err(FrontendError::OutputTooLarge);
        }
        if self
            .pending_len()
            .checked_add(additional)
            .is_none_or(|total| total > MAX_PENDING_OUTPUT_BYTES)
        {
            return Err(FrontendError::Backpressure);
        }

        if self.output_start != 0 {
            self.output.copy_within(self.output_start.., 0);
            self.output.truncate(self.pending_len());
            self.output_start = 0;
        }
        self.output
            .try_reserve(additional)
            .map_err(|_| FrontendError::AllocationFailed)
    }
}

impl Default for TerminalFrontend {
    fn default() -> Self {
        Self::new()
    }
}

fn terminal_text_len(text: &[u8], previous_was_cr: bool) -> Result<usize, FrontendError> {
    let bare_newlines = text
        .iter()
        .enumerate()
        .filter(|(index, byte)| {
            **byte == b'\n'
                && if *index == 0 {
                    !previous_was_cr
                } else {
                    text[*index - 1] != b'\r'
                }
        })
        .count();
    text.len()
        .checked_add(bare_newlines)
        .ok_or(FrontendError::OutputTooLarge)
}

fn cursor_left_len(count: usize) -> usize {
    if count == 0 {
        0
    } else {
        3 + decimal_len(count)
    }
}

fn decimal_len(mut value: usize) -> usize {
    let mut digits = 1;
    while value >= 10 {
        digits += 1;
        value /= 10;
    }
    digits
}
