use std::fmt::Write;
use vibeos_wasm_rv64::{compile, Op, Slot};

pub fn emit(assembly: &mut String) -> String {
    let s = |n: i16| Slot::from(n);
    let mut declarations = String::new();
    let mut descriptors = String::new();
    for kind in 0..8 {
        let (ops, bound) = if kind < 4 {
            let count = 1usize << kind;
            let mut ops = vec![
                Op::consume_fuel(1u32),
                Op::branch_table_0(s(0), count as u32),
            ];
            for n in 0..count {
                ops.push(Op::branch((count + n) as i32));
            }
            for n in 0..count {
                ops.push(Op::copy_imm32(s(3), n as u32));
                ops.push(Op::Return);
            }
            (ops, count as i32)
        } else {
            let value = [-32768i16, -1, 0, 32767][kind - 4];
            (
                vec![
                    Op::consume_fuel(1u32),
                    Op::select_i32_eq_imm16(s(3), s(0), value),
                    Op::Slot2 {
                        slots: [s(1), s(2)],
                    },
                    Op::Return,
                ],
                i32::from(value),
            )
        };
        let code = compile(&ops, 4, 0, 4096).unwrap();
        writeln!(assembly, ".balign 4\n.global flow_{kind}\nflow_{kind}:").unwrap();
        for word in code.words {
            writeln!(assembly, ".word 0x{word:08x}").unwrap();
        }
        writeln!(
            declarations,
            "extern void flow_{kind}(struct Context*,void*);"
        )
        .unwrap();
        writeln!(
            descriptors,
            "{{flow_{kind},{},{bound}}},",
            code.entries[0] * 4
        )
        .unwrap();
    }
    format!(
        r#"
{declarations}
struct FlowCase {{ void (*run)(struct Context*,void*); unsigned entry; int bound; }};
static const struct FlowCase flow_cases[]={{ {descriptors} }};
static void flow_probe(void) {{
 const unsigned values[]={{0,1,2,3,4,7,8,15,16,32767,32768,0x7fffffff,0x80000000,0xffff8000,0xffffffff}};
 for(unsigned kind=0;kind<8;kind++) for(unsigned i=0;i<15;i++) for(unsigned swap=0;swap<2;swap++) {{
  const struct FlowCase *f=&flow_cases[kind];
  u64 slots[]={{0xdeadbeef00000000ULL|values[i],0xfedcba9876543210ULL,0x0123456789abcdefULL,99}};
  if(swap) {{u64 t=slots[1];slots[1]=slots[2];slots[2]=t;}}
  u64 expected,pc;
  if(kind<4) {{unsigned target=values[i]<(unsigned)f->bound?values[i]:(unsigned)f->bound-1;expected=target;pc=3+f->bound+2*target;}}
  else {{expected=(int)values[i]==f->bound?slots[1]:slots[2];pc=3;}}
  struct Context ctx={{(u64)slots,0,0,10,0,99}};
  f->run(&ctx,(char*)f->run+f->entry);
  if(ctx.fuel!=9 || ctx.resume!=pc || ctx.reason!=0 || slots[3]!=expected) fail();
 }}
}}
"#
    )
}
