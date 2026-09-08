use std::fmt::Write;
use vibeos_wasm_rv64::{compile, Op, Slot};
use wasmi_ir::{FixedSlotSpan, SlotSpan};

pub fn emit(assembly: &mut String) -> String {
    let mut declarations = String::new();
    let mut rows = String::new();
    let mut count = 0;
    // Include constants, aliasing sources, swaps and overlapping destinations,
    // plus frame offsets beyond the immediate load/store encoding range.
    for base in [0i16, 256] {
        for destination in 0..3i16 {
            for a in -1..4i16 {
                for b in -1..4i16 {
                    let source = |n| Slot::from(if n < 0 { n } else { n + base });
                    let ops = [
                        Op::consume_fuel(1u32),
                        Op::Copy2 {
                            results: FixedSlotSpan::new(SlotSpan::new(Slot::from(
                                base + destination,
                            )))
                            .unwrap(),
                            values: [source(a), source(b)],
                        },
                        Op::Return,
                    ];
                    let code = compile(&ops, 260, 1, 4096).unwrap();
                    assert!(code.supported[1]);
                    writeln!(
                        assembly,
                        ".balign 4\n.global copies_{count}\ncopies_{count}:"
                    )
                    .unwrap();
                    for word in code.words {
                        writeln!(assembly, ".word 0x{word:08x}").unwrap();
                    }
                    writeln!(
                        declarations,
                        "extern void copies_{count}(struct Context*,void*);"
                    )
                    .unwrap();
                    writeln!(
                        rows,
                        "{{copies_{count},{},{},{},{}}},",
                        code.entries[0] * 4,
                        base + destination,
                        i16::from(source(a)),
                        i16::from(source(b))
                    )
                    .unwrap();
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 150);
    format!(
        r#"
{declarations}
struct CopyCase {{ void (*run)(struct Context*,void*); unsigned entry,destination; int a,b; }};
static const struct CopyCase copy_cases[]={{ {rows} }};
static void copies_probe(void) {{
 for(unsigned n=0;n<150;n++) {{
  const struct CopyCase *c=&copy_cases[n];
  u64 storage[261],expected[261];
  for(unsigned i=0;i<261;i++) storage[i]=expected[i]=0xfedcba9876543210ULL ^ ((u64)i*0x123456789abcdefULL);
  u64 *slots=storage+1;
  expected[c->destination+1]=slots[c->a];
  expected[c->destination+2]=slots[c->b];
  struct Context ctx={{(u64)slots,0,0,10,0,99}};
  c->run(&ctx,(char*)c->run+c->entry);
  if(ctx.fuel!=9 || ctx.reason!=0 || ctx.resume!=2) fail();
  for(unsigned i=0;i<261;i++) if(storage[i]!=expected[i]) fail();
 }}
}}
"#
    )
}
