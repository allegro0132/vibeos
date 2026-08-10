use vibeos_core::terminal::{InputAction, LineDiscipline, TerminalEvent, MAX_INPUT_BYTES};

fn feed(line: &mut LineDiscipline, bytes: &[u8]) -> Vec<InputAction> {
    bytes.iter().map(|byte| line.feed_byte(*byte)).collect()
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
