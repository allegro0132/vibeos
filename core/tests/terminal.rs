use vibeos_core::terminal::{
    FrontendError, InputAction, LineDiscipline, TerminalEvent, TerminalFrontend,
    MAX_EMIT_TEXT_BYTES, MAX_INPUT_BYTES, MAX_PENDING_OUTPUT_BYTES, MAX_PROMPT_BYTES,
};

fn feed(line: &mut LineDiscipline, bytes: &[u8]) -> Vec<InputAction> {
    bytes.iter().map(|byte| line.feed_byte(*byte)).collect()
}

fn take_output(frontend: &mut TerminalFrontend) -> Vec<u8> {
    let output = frontend.pending_output().to_vec();
    frontend.consume_output(output.len()).unwrap();
    output
}

fn feed_frontend(frontend: &mut TerminalFrontend, bytes: &[u8]) {
    for byte in bytes {
        assert_eq!(frontend.input_byte(*byte), Ok(None));
    }
}

#[test]
fn fragmented_escape_editing_submits_the_exact_line() {
    let mut line = LineDiscipline::new();

    assert_eq!(line.feed_byte(b'a'), InputAction::Echo('a'));
    assert_eq!(line.feed_byte(b'b'), InputAction::Echo('b'));
    assert_eq!(line.feed_byte(b'c'), InputAction::Echo('c'));
    assert_eq!(line.feed_byte(0x1b), InputAction::None);
    assert_eq!(line.feed_byte(b'['), InputAction::None);
    assert_eq!(line.feed_byte(b'D'), InputAction::MoveLeft);
    assert_eq!(line.feed_byte(b'X'), InputAction::Redraw);
    assert_eq!(line.input(), "abXc");
    assert_eq!(line.cursor_tail_chars(), 1);
    assert_eq!(
        line.feed_byte(b'\r'),
        InputAction::Event(TerminalEvent::Line(String::from("abXc")))
    );
}

#[test]
fn unsupported_parameterized_csi_does_not_leak_into_input() {
    let mut line = LineDiscipline::new();

    feed(&mut line, b"safe\x1b[1;5Dtext\x1b[3~");

    assert_eq!(line.input(), "safetext");
    assert_eq!(
        line.feed_byte(b'\r'),
        InputAction::Event(TerminalEvent::Line(String::from("safetext")))
    );
}

#[test]
fn input_cursor_draft_and_history_are_isolated_per_session() {
    let mut first = LineDiscipline::new();
    let mut second = LineDiscipline::new();

    feed(&mut first, b"first\r");
    feed(&mut second, b"second\r");
    feed(&mut first, b"draft-one");
    feed(&mut second, b"draft-two");

    assert_eq!(
        feed(&mut first, b"\x1b[A").last(),
        Some(&InputAction::Redraw)
    );
    assert_eq!(first.input(), "first");
    assert_eq!(second.input(), "draft-two");

    assert_eq!(
        feed(&mut first, b"\x1b[B").last(),
        Some(&InputAction::Redraw)
    );
    assert_eq!(first.input(), "draft-one");
    assert_eq!(second.input(), "draft-two");

    assert_eq!(
        feed(&mut second, b"\x1b[A").last(),
        Some(&InputAction::Redraw)
    );
    assert_eq!(second.input(), "second");
    assert_eq!(first.input(), "draft-one");
}

#[test]
fn interrupt_and_transport_eof_are_distinct_and_session_local() {
    let mut first = LineDiscipline::new();
    let mut second = LineDiscipline::new();
    feed(&mut first, b"discard");
    feed(&mut second, b"preserve");

    assert_eq!(
        first.feed_byte(0x03),
        InputAction::Event(TerminalEvent::Interrupt)
    );
    assert_eq!(first.input(), "");
    assert_eq!(second.input(), "preserve");

    feed(&mut first, b"again");
    assert_eq!(
        first.transport_eof(),
        InputAction::Event(TerminalEvent::Eof)
    );
    assert_eq!(first.input(), "");
    assert_eq!(second.input(), "preserve");
}

#[test]
fn input_limit_accepts_exactly_the_bound_then_bells_without_mutation() {
    let mut line = LineDiscipline::new();
    for _ in 0..MAX_INPUT_BYTES {
        assert_eq!(line.feed_byte(b'x'), InputAction::Echo('x'));
    }
    assert_eq!(line.input().len(), MAX_INPUT_BYTES);
    assert_eq!(line.feed_byte(b'x'), InputAction::Bell);
    assert_eq!(line.input().len(), MAX_INPUT_BYTES);
    assert_eq!(
        line.feed_byte(b'\n'),
        InputAction::Event(TerminalEvent::Line("x".repeat(MAX_INPUT_BYTES)))
    );
}

#[test]
fn adjacent_duplicate_and_empty_lines_do_not_replace_history() {
    let mut line = LineDiscipline::new();
    feed(&mut line, b"one\r");
    feed(&mut line, b"one\r");
    feed(&mut line, b"\r");

    assert_eq!(
        feed(&mut line, b"\x1b[A").last(),
        Some(&InputAction::Redraw)
    );
    assert_eq!(line.input(), "one");
    assert_eq!(
        feed(&mut line, b"\x1b[A").last(),
        Some(&InputAction::Redraw)
    );
    assert_eq!(line.input(), "one");
}

#[test]
fn frontend_renders_exact_editing_and_control_bytes() {
    let mut terminal = TerminalFrontend::new();

    terminal.show_prompt("vsh> ").unwrap();
    assert_eq!(take_output(&mut terminal), b"\r\x1b[2Kvsh> ");

    feed_frontend(&mut terminal, b"abc");
    assert_eq!(take_output(&mut terminal), b"abc");

    feed_frontend(&mut terminal, b"\x1b[D");
    assert_eq!(take_output(&mut terminal), b"\x1b[D");
    assert_eq!(terminal.cursor_tail_chars(), 1);

    feed_frontend(&mut terminal, b"X");
    assert_eq!(terminal.input(), "abXc");
    assert_eq!(take_output(&mut terminal), b"\r\x1b[2Kvsh> abXc\x1b[1D");

    feed_frontend(&mut terminal, b"\x1b[C");
    assert_eq!(take_output(&mut terminal), b"\x1b[C");
    feed_frontend(&mut terminal, b"\x7f");
    assert_eq!(terminal.input(), "abX");
    assert_eq!(take_output(&mut terminal), b"\x08 \x08");

    assert_eq!(
        terminal.input_byte(b'\r'),
        Ok(Some(TerminalEvent::Line(String::from("abX"))))
    );
    assert_eq!(take_output(&mut terminal), b"\r\n");
    assert!(!terminal.is_at_prompt());
    assert_eq!(terminal.input_byte(b'z'), Ok(None));
    assert!(terminal.pending_output().is_empty());

    terminal.show_prompt("vsh> ").unwrap();
    take_output(&mut terminal);
    feed_frontend(&mut terminal, b"discard");
    take_output(&mut terminal);
    assert_eq!(terminal.interrupt(), Ok(TerminalEvent::Interrupt));
    assert_eq!(terminal.input(), "");
    assert_eq!(take_output(&mut terminal), b"^C\r\n");

    terminal.show_prompt("vsh> ").unwrap();
    take_output(&mut terminal);
    assert_eq!(terminal.input_byte(0x04), Ok(Some(TerminalEvent::Eof)));
    assert!(terminal.pending_output().is_empty());
}

#[test]
fn frontend_preserves_editing_state_around_async_output() {
    let mut terminal = TerminalFrontend::new();
    terminal.show_prompt("vsh> ").unwrap();
    take_output(&mut terminal);
    feed_frontend(&mut terminal, b"abcd");
    take_output(&mut terminal);
    feed_frontend(&mut terminal, b"\x1b[D\x1b[D");
    assert_eq!(take_output(&mut terminal), b"\x1b[D\x1b[D");

    terminal.emit_text("job\nready\r\n").unwrap();
    assert_eq!(terminal.input(), "abcd");
    assert_eq!(terminal.cursor_tail_chars(), 2);
    assert_eq!(
        take_output(&mut terminal),
        b"\r\x1b[2Kjob\r\nready\r\nvsh> abcd\x1b[2D"
    );

    feed_frontend(&mut terminal, b"X");
    assert_eq!(terminal.input(), "abXcd");
    assert_eq!(take_output(&mut terminal), b"\r\x1b[2Kvsh> abXcd\x1b[2D");

    assert!(matches!(
        terminal.input_byte(b'\r'),
        Ok(Some(TerminalEvent::Line(_)))
    ));
    take_output(&mut terminal);
    terminal.emit_text("split\r").unwrap();
    terminal.emit_text("\nnext\n").unwrap();
    assert_eq!(take_output(&mut terminal), b"split\r\nnext\r\n");
}

#[test]
fn frontend_backpressure_is_atomic_and_retryable() {
    let mut output = TerminalFrontend::new();
    let chunk = "x".repeat(MAX_EMIT_TEXT_BYTES);
    for _ in 0..(MAX_PENDING_OUTPUT_BYTES / MAX_EMIT_TEXT_BYTES) {
        output.emit_text(&chunk).unwrap();
    }
    assert_eq!(output.pending_len(), MAX_PENDING_OUTPUT_BYTES);
    let snapshot = output.pending_output().to_vec();
    assert_eq!(output.emit_text("y"), Err(FrontendError::Backpressure));
    assert_eq!(output.pending_output(), snapshot);
    assert_eq!(
        output.consume_output(MAX_PENDING_OUTPUT_BYTES + 1),
        Err(FrontendError::InvalidConsume)
    );
    assert_eq!(output.pending_output(), snapshot);

    output.consume_output(1).unwrap();
    output.emit_text("y").unwrap();
    assert_eq!(output.pending_len(), MAX_PENDING_OUTPUT_BYTES);
    assert_eq!(output.pending_output().last(), Some(&b'y'));

    let mut input = TerminalFrontend::new();
    input.show_prompt("vsh> ").unwrap();
    take_output(&mut input);
    feed_frontend(&mut input, b"ab");
    take_output(&mut input);
    for _ in 0..4 {
        input.emit_text(&chunk).unwrap();
    }
    let pending = input.pending_output().to_vec();
    assert_eq!(input.input_byte(0x1b), Err(FrontendError::Backpressure));
    assert_eq!(input.input(), "ab");
    assert_eq!(input.cursor_tail_chars(), 0);
    assert_eq!(input.pending_output(), pending);

    take_output(&mut input);
    feed_frontend(&mut input, b"\x1b[D");
    assert_eq!(input.cursor_tail_chars(), 1);
    assert_eq!(take_output(&mut input), b"\x1b[D");
}

#[test]
fn frontend_bounds_prompts_chunks_and_maximum_redraw() {
    let mut terminal = TerminalFrontend::new();
    assert_eq!(
        terminal.show_prompt(&"p".repeat(MAX_PROMPT_BYTES + 1)),
        Err(FrontendError::PromptTooLong)
    );
    assert_eq!(
        terminal.show_prompt("bad\n"),
        Err(FrontendError::PromptTooLong)
    );
    assert_eq!(
        terminal.emit_text(&"x".repeat(MAX_EMIT_TEXT_BYTES + 1)),
        Err(FrontendError::OutputTooLarge)
    );
    assert!(terminal.pending_output().is_empty());

    terminal.show_prompt(&"p".repeat(MAX_PROMPT_BYTES)).unwrap();
    take_output(&mut terminal);
    for _ in 0..(MAX_INPUT_BYTES - 1) {
        assert_eq!(terminal.input_byte(b'x'), Ok(None));
        take_output(&mut terminal);
    }
    for _ in 0..(MAX_INPUT_BYTES / 2) {
        feed_frontend(&mut terminal, b"\x1b[D");
        take_output(&mut terminal);
    }
    assert_eq!(terminal.input_byte(b'y'), Ok(None));
    assert_eq!(terminal.input().len(), MAX_INPUT_BYTES);
    assert_eq!(terminal.cursor_tail_chars(), MAX_INPUT_BYTES / 2);
    assert!(terminal.pending_len() < MAX_PENDING_OUTPUT_BYTES);
    assert!(terminal.pending_output().starts_with(b"\r\x1b[2K"));
    assert!(terminal.pending_output().ends_with(b"\x1b[2048D"));

    take_output(&mut terminal);
    assert_eq!(terminal.input_byte(b'z'), Ok(None));
    assert_eq!(take_output(&mut terminal), b"\x07");

    terminal
        .emit_text(&"\n".repeat(MAX_EMIT_TEXT_BYTES))
        .unwrap();
    assert!(terminal.pending_len() < MAX_PENDING_OUTPUT_BYTES);
    assert!(terminal.pending_output().starts_with(b"\r\x1b[2K\r\n"));
    assert!(terminal.pending_output().ends_with(b"\x1b[2048D"));
}

#[test]
fn frontend_partial_consumption_preserves_fifo_order() {
    let expected = b"first\r\nsecond";
    for split in 0..=expected.len() {
        let mut terminal = TerminalFrontend::new();
        terminal.emit_text("first\nsecond").unwrap();
        assert_eq!(terminal.pending_output(), expected);
        terminal.consume_output(split).unwrap();
        assert_eq!(terminal.pending_output(), &expected[split..]);
        terminal
            .consume_output(expected.len().saturating_sub(split))
            .unwrap();
        assert!(terminal.pending_output().is_empty());
    }

    let mut terminal = TerminalFrontend::new();
    terminal.emit_text("abcdef").unwrap();
    terminal.consume_output(0).unwrap();
    terminal.consume_output(2).unwrap();
    terminal.emit_text("gh").unwrap();
    assert_eq!(terminal.pending_output(), b"cdefgh");
}

#[test]
fn frontend_instances_do_not_share_state_or_backpressure() {
    let mut first = TerminalFrontend::new();
    let mut second = TerminalFrontend::new();
    first.show_prompt("one> ").unwrap();
    second.show_prompt("two> ").unwrap();
    take_output(&mut first);
    take_output(&mut second);
    feed_frontend(&mut first, b"private");
    feed_frontend(&mut second, b"other");
    take_output(&mut first);
    take_output(&mut second);

    let chunk = "x".repeat(MAX_EMIT_TEXT_BYTES);
    for _ in 0..4 {
        first.emit_text(&chunk).unwrap();
    }
    assert_eq!(first.input_byte(b'!'), Err(FrontendError::Backpressure));
    assert_eq!(first.input(), "private");

    assert_eq!(second.input_byte(b'!'), Ok(None));
    assert_eq!(second.input(), "other!");
    assert_eq!(take_output(&mut second), b"!");
    assert_eq!(first.input(), "private");
}
