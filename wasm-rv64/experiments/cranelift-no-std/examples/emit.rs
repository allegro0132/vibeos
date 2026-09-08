use std::{fmt::Write, path::PathBuf};
fn main() {
    let out = PathBuf::from(std::env::args().nth(1).unwrap());
    std::fs::create_dir_all(&out).unwrap();
    for external in [false, true] {
        let code = vibeos_cranelift_no_std_check::compile_probe(external);
        let mut assembly = String::from(
        ".section .clif,\"ax\",@progbits\n.option norelax\n.balign 16\n.global clif_probe\nclif_probe:\n",
    );
        for chunk in code.chunks(16) {
            assembly.push_str(".byte ");
            for (i, byte) in chunk.iter().enumerate() {
                if i > 0 {
                    assembly.push(',');
                }
                write!(assembly, "0x{byte:02x}").unwrap();
            }
            assembly.push('\n');
        }
        if external {
            assembly = assembly
                .replace(".clif", ".clif_external")
                .replace("clif_probe", "clif_external");
        }
        std::fs::write(
            out.join(if external {
                "external.S"
            } else {
                "generated.S"
            }),
            assembly,
        )
        .unwrap();
        std::fs::write(
            out.join(if external { "external.bin" } else { "code.bin" }),
            &code,
        )
        .unwrap();
        println!("external={external}: generated {} bytes", code.len());
    }
    use vibeos_wasm_rv64::{Op, Slot};
    let slot = |n: i16| Slot::from(n);
    let ops = [
        Op::consume_fuel(1u32),
        Op::i32_add(slot(2), slot(0), slot(1)),
        Op::i32_mul(slot(3), slot(2), slot(1)),
        Op::i32_sub(slot(4), slot(3), slot(0)),
        Op::copy(slot(5), slot(4)),
        Op::copy_imm32(slot(6), 1u32),
        Op::consume_fuel(5u32),
        Op::i32_sub(slot(7), slot(7), slot(6)),
        Op::branch_i32_ne_imm16(slot(7), 0i16, -2i16),
        Op::f32_add(slot(0), slot(0), slot(0)),
        Op::i32_bitxor(slot(0), slot(2), slot(4)),
        Op::Return,
    ];
    let code = vibeos_cranelift_no_std_check::wasmi::compile(&ops, 8).unwrap();
    let mut assembly=String::from(".section .clif_wasmi,\"ax\",@progbits\n.option norelax\n.balign 16\n.global clif_wasmi\nclif_wasmi:\n");
    for byte in &code {
        writeln!(assembly, ".byte 0x{byte:02x}").unwrap();
    }
    std::fs::write(out.join("wasmi.S"), assembly).unwrap();
    std::fs::write(out.join("wasmi.bin"), &code).unwrap();
    println!("Wasmi IR: generated {} bytes", code.len());
}
