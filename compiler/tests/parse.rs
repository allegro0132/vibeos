//! Parser shape and diagnostics.
//!
//! ASTs are compared as s-expressions: a golden string is readable in a diff,
//! whereas a `Debug` dump of nested boxes is not.

use vibeos_rustc::ast::*;
use vibeos_rustc::lex::lex;
use vibeos_rustc::parse::Parser;

fn parse(src: &str) -> Result<Program, String> {
    Parser::new(lex(src)?).program()
}

fn err(src: &str) -> String {
    parse(src).unwrap_err()
}

/// Parse `fn main() { <body> }` and render main's body.
fn body(src: &str) -> String {
    let p = parse(&format!("fn main() {{ {src} }}")).unwrap();
    let f = p.funcs.iter().find(|f| f.name == "main").unwrap();
    block(&f.body)
}

fn block(b: &Block) -> String {
    let mut parts: Vec<String> = b.stmts.iter().map(stmt).collect();
    if let Some(t) = &b.tail {
        parts.push(format!("(tail {})", expr(t)));
    }
    format!("({})", parts.join(" "))
}

fn stmt(s: &Stmt) -> String {
    match s {
        Stmt::Let { name, mutable, init, declared, .. } => format!(
            "(let{}{} {} {})",
            if *mutable { "-mut" } else { "" },
            declared.map(|t| format!(":{t}")).unwrap_or_default(),
            name,
            expr(init)
        ),
        Stmt::Assign { name, value, .. } => format!("(= {} {})", name, expr(value)),
        Stmt::Expr(e) => format!("(expr {})", expr(e)),
        Stmt::While(c, b, _) => format!("(while {} {})", expr(c), block(b)),
        Stmt::Return(Some(e)) => format!("(return {})", expr(e)),
        Stmt::Return(None) => "(return)".into(),
        Stmt::Print { parts, newline } => {
            let ps: Vec<String> = parts
                .iter()
                .map(|p| match p {
                    PrintPart::Str(s) => format!("{s:?}"),
                    PrintPart::Val(e, _) => expr(e),
                })
                .collect();
            format!("({} {})", if *newline { "println" } else { "print" }, ps.join(" "))
        }
    }
}

fn expr(e: &Expr) -> String {
    match e {
        Expr::Int(v) => v.to_string(),
        Expr::Bool(v) => v.to_string(),
        Expr::BitNot(a) => format!("(bitnot {})", expr(a)),
        Expr::Var(n, _) => n.clone(),
        Expr::Neg(a) => format!("(neg {})", expr(a)),
        Expr::Not(a) => format!("(not {})", expr(a)),
        Expr::Bin(op, a, b, _) => format!("({:?} {} {})", op, expr(a), expr(b)),
        Expr::Call(n, args, _) => {
            let a: Vec<String> = args.iter().map(expr).collect();
            format!("(call {} {})", n, a.join(" ")).replace(" )", ")")
        }
        Expr::If(c, t, None, _) => format!("(if {} {})", expr(c), block(t)),
        Expr::If(c, t, Some(e), _) => format!("(if {} {} {})", expr(c), block(t), block(e)),
    }
}

// --- precedence and associativity ---

#[test]
fn multiplication_binds_tighter_than_addition() {
    assert_eq!(body("2 + 3 * 4;"), "((expr (Add 2 (Mul 3 4))))");
    assert_eq!(body("2 * 3 + 4;"), "((expr (Add (Mul 2 3) 4)))");
    assert_eq!(body("(2 + 3) * 4;"), "((expr (Mul (Add 2 3) 4)))");
}

#[test]
fn arithmetic_is_left_associative() {
    assert_eq!(body("1 - 2 - 3;"), "((expr (Sub (Sub 1 2) 3)))");
    assert_eq!(body("8 / 4 / 2;"), "((expr (Div (Div 8 4) 2)))");
}

#[test]
fn the_full_precedence_ladder_holds() {
    // || < && < equality < comparison < additive < multiplicative
    assert_eq!(
        body("1 || 2 && 3 == 4 < 5 + 6 * 7;"),
        "((expr (Or 1 (And 2 (Eq 3 (Lt 4 (Add 5 (Mul 6 7))))))))"
    );
}

#[test]
fn unary_binds_tighter_than_binary() {
    assert_eq!(body("-2 + 3;"), "((expr (Add (neg 2) 3)))");
    assert_eq!(body("-(2 + 3);"), "((expr (neg (Add 2 3))))");
    assert_eq!(body("!0 == 1;"), "((expr (Eq (not 0) 1)))");
    assert_eq!(body("--1;"), "((expr (neg (neg 1))))");
}

// --- control flow ---

#[test]
fn if_is_an_expression_with_a_block_value() {
    assert_eq!(body("let x = if 1 { 2 } else { 3 };"), "((let x (if 1 ((tail 2)) ((tail 3)))))");
}

#[test]
fn else_if_chains_desugar_into_nested_ifs() {
    assert_eq!(
        body("let x = if 1 { 2 } else if 3 { 4 } else { 5 };"),
        "((let x (if 1 ((tail 2)) ((tail (if 3 ((tail 4)) ((tail 5))))))))"
    );
}

#[test]
fn a_trailing_expression_is_the_block_value() {
    assert_eq!(body("let a = 1; a"), "((let a 1) (tail a))");
    assert_eq!(body("let a = 1; a;"), "((let a 1) (expr a))");
}

#[test]
fn assignment_is_distinguished_from_an_expression_statement() {
    assert_eq!(body("x = 1;"), "((= x 1))");
    assert_eq!(body("x == 1;"), "((expr (Eq x 1)))");
}

#[test]
fn calls_parse_with_trailing_commas_and_no_args() {
    assert_eq!(body("f();"), "((expr (call f)))");
    assert_eq!(body("f(1);"), "((expr (call f 1)))");
    assert_eq!(body("f(1, 2,);"), "((expr (call f 1 2)))");
}

#[test]
fn function_signatures_record_parameter_and_return_types() {
    let p = parse("fn f(a: i64, b: i64) -> i64 { a } fn main() {}").unwrap();
    let f = &p.funcs[0];
    assert_eq!(f.params, vec![("a".to_string(), Ty::I64), ("b".to_string(), Ty::I64)]);
    assert_eq!(f.ret, Ty::I64);
}

// --- format strings ---

#[test]
fn a_format_string_splits_into_literal_and_value_parts() {
    assert_eq!(body(r#"println!("a {} b {} c", 1, 2);"#), r#"((println "a " 1 " b " 2 " c"))"#);
    assert_eq!(body(r#"println!("{}", 1);"#), "((println 1))");
    assert_eq!(body(r#"println!("plain");"#), r#"((println "plain"))"#);
    assert_eq!(body(r#"print!("no newline");"#), r#"((print "no newline"))"#);
}

#[test]
fn doubled_braces_are_escapes_not_holes() {
    assert_eq!(body(r#"println!("{{}} {}", 1);"#), r#"((println "{} " 1))"#);
}

// --- diagnostics ---

#[test]
fn a_missing_main_is_reported() {
    assert_eq!(err("fn helper() {}"), "no `main` function found");
}

#[test]
fn duplicate_and_arity_problems_name_the_line() {
    assert_eq!(
        err("fn main() {\n  println!(\"{} {}\", 1);\n}"),
        "line 2: format string wants at least 2 argument(s), 1 given"
    );
    assert_eq!(
        err("fn main() {\n  println!(\"{}\", 1, 2);\n}"),
        "line 2: 2 argument(s) given but the format string uses 1"
    );
}

#[test]
fn unsupported_syntax_says_what_is_supported() {
    assert_eq!(
        err("fn main() { let x: u8 = 1; }"),
        "line 1: expected a type (`i64` or `bool`), found `u8`"
    );
    assert_eq!(err(r#"fn main() { format!("x"); }"#), "line 1: unsupported macro `format!`");
    assert_eq!(
        err(r#"fn main() { println!("{:?}", 1); }"#),
        "line 1: only the empty format specifier `{}` is supported"
    );
    assert_eq!(
        err(r#"fn main() { println!(1); }"#),
        "line 1: the first argument to print must be a string literal"
    );
}

#[test]
fn structural_errors_point_at_the_offending_token() {
    assert_eq!(err("fn main() { let x = ; }"), "line 1: expected an expression, found `;`");
    assert_eq!(err("fn main() { let = 1; }"), "line 1: expected an identifier, found `=`");
    assert_eq!(err("fn main() {"), "line 1: unclosed block");
    assert_eq!(err("fn main() { 1 }\nfn"), "line 2: expected an identifier, found end of input");
    // Keywords render as written, not as their internal Debug name.
    assert_eq!(err("fn main() { 1 }\nfn fn"), "line 2: expected an identifier, found `fn`");
}

#[test]
fn the_parser_never_panics_on_truncated_input() {
    // Every prefix of a valid program must produce Ok or Err, never a panic.
    let full = "fn f(a: i64) -> i64 { if a < 2 { a } else { f(a-1) } }\nfn main() { f(3); }";
    for n in 0..=full.len() {
        let _ = parse(&full[..n]);
    }
}
