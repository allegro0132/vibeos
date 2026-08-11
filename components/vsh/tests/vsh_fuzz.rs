//! Deterministic host fuzz corpus for the pure vsh parser. This deliberately
//! uses no scheduler or capabilities, so failures reduce to one input string.

use vibeos_vsh as vsh;

#[test]
fn bounded_parser_survives_generated_operator_quote_and_reference_corpus() {
    const ALPHABET: &[u8] = b"ab09_$@{}'\"\\ |&;<>2()-";
    let mut state = 0x9e37_79b9_u32;
    for len in 0..=256usize {
        let mut input = String::with_capacity(len);
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            input.push(ALPHABET[state as usize % ALPHABET.len()] as char);
        }
        let _ = vsh::parse(&input);
    }
}

#[test]
fn every_single_byte_ascii_input_is_diagnostic_or_ast() {
    for byte in 0u8..=127 {
        let input = String::from_utf8(vec![byte]).unwrap();
        let _ = vsh::parse(&input);
    }
}
