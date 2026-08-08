//! Tokenizer for the Rust subset.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq)]
pub enum Tok {
    Fn,
    Let,
    Mut,
    If,
    Else,
    While,
    Return,
    I64,
    Bool,
    True,
    False,
    Ident(String),
    Int(i64),
    Str(String),
    /// `println!` / `print!` — the `!` is folded into the token.
    Macro(String),
    Punct(&'static str),
    Eof,
}

#[derive(Clone, Debug)]
pub struct Token {
    pub tok: Tok,
    pub line: u32,
}

const PUNCTS: &[&str] = &[
    "->", "==", "!=", "<=", ">=", "&&", "||", "(", ")", "{", "}", ",", ";", ":", "=", "+", "-",
    "*", "/", "%", "<", ">", "!",
];

pub fn lex(src: &str) -> Result<Vec<Token>, String> {
    let b = src.as_bytes();
    let mut i = 0usize;
    let mut line = 1u32;
    let mut out = Vec::new();

    while i < b.len() {
        let c = b[i];

        if c == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // Line comments.
        if c == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        // Identifiers, keywords, macro calls.
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            let word = &src[start..i];
            if i < b.len() && b[i] == b'!' {
                i += 1;
                out.push(Token { tok: Tok::Macro(word.to_string()), line });
                continue;
            }
            let tok = match word {
                "fn" => Tok::Fn,
                "let" => Tok::Let,
                "mut" => Tok::Mut,
                "if" => Tok::If,
                "else" => Tok::Else,
                "while" => Tok::While,
                "return" => Tok::Return,
                "i64" => Tok::I64,
                "bool" => Tok::Bool,
                "true" => Tok::True,
                "false" => Tok::False,
                _ => Tok::Ident(word.to_string()),
            };
            out.push(Token { tok, line });
            continue;
        }

        // Integer literals, with `_` separators.
        if c.is_ascii_digit() {
            let mut v: i64 = 0;
            while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'_') {
                if b[i] != b'_' {
                    v = v
                        .checked_mul(10)
                        .and_then(|v| v.checked_add((b[i] - b'0') as i64))
                        .ok_or_else(|| format!("line {}: integer literal overflows i64", line))?;
                }
                i += 1;
            }
            out.push(Token { tok: Tok::Int(v), line });
            continue;
        }

        // String literals.
        if c == b'"' {
            i += 1;
            let mut s = String::new();
            loop {
                if i >= b.len() {
                    return Err(format!("line {}: unterminated string literal", line));
                }
                match b[i] {
                    b'"' => {
                        i += 1;
                        break;
                    }
                    b'\\' => {
                        i += 1;
                        let e = *b.get(i).ok_or_else(|| {
                            format!("line {}: unterminated escape sequence", line)
                        })?;
                        s.push(match e {
                            b'n' => '\n',
                            b't' => '\t',
                            b'r' => '\r',
                            b'0' => '\0',
                            b'\\' => '\\',
                            b'"' => '"',
                            other => {
                                return Err(format!(
                                    "line {}: unknown escape `\\{}`",
                                    line, other as char
                                ))
                            }
                        });
                        i += 1;
                    }
                    b'\n' => return Err(format!("line {}: newline in string literal", line)),
                    ch => {
                        s.push(ch as char);
                        i += 1;
                    }
                }
            }
            out.push(Token { tok: Tok::Str(s), line });
            continue;
        }

        // Punctuation, longest match first.
        let mut matched = None;
        for p in PUNCTS {
            if src[i..].starts_with(p) {
                matched = Some(*p);
                break;
            }
        }
        match matched {
            Some(p) => {
                i += p.len();
                out.push(Token { tok: Tok::Punct(p), line });
            }
            None => return Err(format!("line {}: unexpected character `{}`", line, c as char)),
        }
    }

    out.push(Token { tok: Tok::Eof, line });
    Ok(out)
}
