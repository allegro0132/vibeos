//! Tokenizer. Diagnostics are asserted verbatim because error messages are a
//! UI, and a silently reworded error is a regression a user notices first.

use vibeos_rustc::lex::{lex, Tok};

fn toks(src: &str) -> Vec<Tok> {
    lex(src).unwrap().into_iter().map(|t| t.tok).collect()
}

fn err(src: &str) -> String {
    lex(src).unwrap_err()
}

#[test]
fn keywords_are_not_identifiers() {
    assert_eq!(
        toks("fn let mut if else while return i64"),
        vec![
            Tok::Fn,
            Tok::Let,
            Tok::Mut,
            Tok::If,
            Tok::Else,
            Tok::While,
            Tok::Return,
            Tok::I64,
            Tok::Eof
        ]
    );
}

#[test]
fn identifiers_may_contain_keywords_as_substrings() {
    assert_eq!(
        toks("iffy return_value _x1"),
        vec![
            Tok::Ident("iffy".into()),
            Tok::Ident("return_value".into()),
            Tok::Ident("_x1".into()),
            Tok::Eof
        ]
    );
}

#[test]
fn two_character_punctuation_wins_over_one() {
    assert_eq!(
        toks("-> == != <= >= && || < > = ! -"),
        vec![
            Tok::Punct("->"),
            Tok::Punct("=="),
            Tok::Punct("!="),
            Tok::Punct("<="),
            Tok::Punct(">="),
            Tok::Punct("&&"),
            Tok::Punct("||"),
            Tok::Punct("<"),
            Tok::Punct(">"),
            Tok::Punct("="),
            Tok::Punct("!"),
            Tok::Punct("-"),
            Tok::Eof
        ]
    );
}

#[test]
fn integers_accept_underscore_separators() {
    assert_eq!(toks("1_000_000"), vec![Tok::Int(1_000_000), Tok::Eof]);
    assert_eq!(toks("0"), vec![Tok::Int(0), Tok::Eof]);
}

#[test]
fn an_integer_too_large_for_i64_is_rejected_not_wrapped() {
    assert_eq!(
        err("99999999999999999999"),
        "line 1: integer literal overflows i64"
    );
}

#[test]
fn a_macro_call_folds_the_bang_into_one_token() {
    assert_eq!(
        toks("println!"),
        vec![Tok::Macro("println".into()), Tok::Eof]
    );
}

#[test]
fn string_escapes_are_decoded() {
    assert_eq!(
        toks(r#""a\nb\tc\\d\"e\0f\r""#),
        vec![Tok::Str("a\nb\tc\\d\"e\0f\r".into()), Tok::Eof]
    );
}

#[test]
fn malformed_strings_are_diagnosed_precisely() {
    assert_eq!(err("\"abc"), "line 1: unterminated string literal");
    assert_eq!(err("\"a\nb\""), "line 1: newline in string literal");
    assert_eq!(err(r#""a\q""#), "line 1: unknown escape `\\q`");
    assert_eq!(err("\"a\\"), "line 1: unterminated escape sequence");
}

#[test]
fn line_comments_run_to_end_of_line_only() {
    assert_eq!(toks("// gone\n1"), vec![Tok::Int(1), Tok::Eof]);
    assert_eq!(toks("1 // gone"), vec![Tok::Int(1), Tok::Eof]);
}

#[test]
fn line_numbers_survive_comments_and_strings() {
    let ts = lex("1\n// c\n\n2\n\"s\"\n3").unwrap();
    let lines: Vec<u32> = ts.iter().map(|t| t.line).collect();
    assert_eq!(lines, vec![1, 4, 5, 6, 6]);
}

#[test]
fn an_unexpected_character_names_itself() {
    assert_eq!(err("@"), "line 1: unexpected character `@`");
    assert_eq!(err("\n\n#"), "line 3: unexpected character `#`");
}

#[test]
fn empty_input_is_just_eof() {
    assert_eq!(toks(""), vec![Tok::Eof]);
    assert_eq!(toks("   \n\t "), vec![Tok::Eof]);
}
