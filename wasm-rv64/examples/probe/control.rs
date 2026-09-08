use std::fmt::Write;
use vibeos_wasm_rv64::{compile, Op, Slot};
use wasmi_ir::IntoShiftAmount;

pub fn emit(assembly: &mut String) -> String {
    let s = |n: i16| Slot::from(n);
    let mut declarations = String::new();
    let mut descriptors = String::new();
    for kind in 0..15 {
        let ops = if kind == 0 {
            vec![
                Op::consume_fuel(1u32),
                Op::copy_imm32(s(2), 0xfedcba98u32),
                Op::i32_shl_by(s(3), s(0), i32::into_shift_amount(31).unwrap()),
                Op::i32_shr_u_by(s(4), s(0), i32::into_shift_amount(1).unwrap()),
                Op::i32_shr_s_by(s(5), s(0), i32::into_shift_amount(31).unwrap()),
                Op::i32_lt_s(s(6), s(0), s(1)),
                Op::i32_lt_u(s(7), s(0), s(1)),
                Op::i32_extend16_s(s(8), s(0)),
                Op::Return,
            ]
        } else {
            let lhs = s(0);
            let rhs = s(1);
            let offset = wasmi_ir::BranchOffset16::from(2i16);
            let branch = match kind {
                1 => Op::BranchI32Eq { lhs, rhs, offset },
                2 => Op::BranchI32Ne { lhs, rhs, offset },
                3 => Op::BranchI32LtS { lhs, rhs, offset },
                4 => Op::BranchI32LeS { lhs, rhs, offset },
                5 => Op::BranchI32LtU { lhs, rhs, offset },
                6 => Op::BranchI32LeU { lhs, rhs, offset },
                7 => Op::BranchI32LtUImm16Rhs {
                    lhs,
                    rhs: 65535u16.into(),
                    offset,
                },
                8 => Op::BranchI32LeUImm16Rhs {
                    lhs,
                    rhs: 65535u16.into(),
                    offset,
                },
                9 => Op::BranchI32LtSImm16Rhs {
                    lhs,
                    rhs: (-32768i16).into(),
                    offset,
                },
                10 => Op::BranchI32LeSImm16Rhs {
                    lhs,
                    rhs: (-32768i16).into(),
                    offset,
                },
                11 => Op::BranchI32LtSImm16Lhs {
                    lhs: (-32768i16).into(),
                    rhs: lhs,
                    offset,
                },
                12 => Op::BranchI32LeSImm16Lhs {
                    lhs: (-32768i16).into(),
                    rhs: lhs,
                    offset,
                },
                13 => Op::BranchI32LtUImm16Lhs {
                    lhs: 65535u16.into(),
                    rhs: lhs,
                    offset,
                },
                _ => Op::BranchI32LeUImm16Lhs {
                    lhs: 65535u16.into(),
                    rhs: lhs,
                    offset,
                },
            };
            vec![
                Op::consume_fuel(1u32),
                Op::copy_imm32(s(2), 0u32),
                branch,
                Op::branch(2i32),
                Op::copy_imm32(s(2), 1u32),
                Op::Return,
            ]
        };
        let code = compile(&ops, 9, 0, 4096).unwrap();
        writeln!(
            assembly,
            ".balign 4\n.global control_{kind}\ncontrol_{kind}:"
        )
        .unwrap();
        for word in code.words {
            writeln!(assembly, ".word 0x{word:08x}").unwrap();
        }
        writeln!(
            declarations,
            "extern void control_{kind}(struct Context*,void*);"
        )
        .unwrap();
        writeln!(
            descriptors,
            "{{control_{kind},{},{}}},",
            code.entries[0] * 4,
            ops.len() - 1
        )
        .unwrap();
    }
    let values = [
        0u32, 1, 2, 65535, 65536, 0x7fffffff, 0x80000000, 0xffffffff, 0xffff8000, 0x87654321,
    ];
    let mut rows = String::new();
    for a in values {
        for b in values {
            let expected = [
                a,
                b,
                0xfedcba98,
                a.wrapping_shl(31),
                a >> 1,
                ((a as i32) >> 31) as u32,
                ((a as i32) < (b as i32)) as u32,
                (a < b) as u32,
                (a as i16 as i32) as u32,
                (a == b) as u32,
                (a != b) as u32,
                ((a as i32) < (b as i32)) as u32,
                ((a as i32) <= (b as i32)) as u32,
                (a < b) as u32,
                (a <= b) as u32,
                (a < 65535) as u32,
                (a <= 65535) as u32,
                ((a as i32) < -32768) as u32,
                ((a as i32) <= -32768) as u32,
                (-32768 < (a as i32)) as u32,
                (-32768 <= (a as i32)) as u32,
                (65535 < a) as u32,
                (65535 <= a) as u32,
            ];
            rows.push('{');
            for value in expected {
                write!(rows, "0x{value:08x}ULL,").unwrap();
            }
            rows.push_str("},\n");
        }
    }
    format!(
        r#"
{declarations}
struct ControlCase {{ void (*run)(struct Context*,void*); unsigned entry,resume; }};
static const struct ControlCase control_cases[]={{ {descriptors} }};
static const u64 control_results[][23]={{ {rows} }};
static void control_probe(void) {{
 for(unsigned row=0;row<100;row++) for(unsigned kind=0;kind<15;kind++) {{
  u64 slots[9];for(unsigned i=0;i<9;i++) slots[i]=0xdeadbeef00000000ULL;
  slots[0]|=control_results[row][0]; slots[1]|=control_results[row][1];
  const struct ControlCase *c=&control_cases[kind];
  struct Context ctx={{(u64)slots,0,0,10,0,99}};
  c->run(&ctx,(char*)c->run+c->entry);
  if(ctx.fuel!=9 || ctx.reason!=0 || ctx.resume!=c->resume) fail();
  if(kind==0) {{for(unsigned i=2;i<9;i++) if(slots[i]!=control_results[row][i]) fail();}}
  else if(slots[2]!=control_results[row][kind+8]) fail();
 }}
}}
"#
    )
}
