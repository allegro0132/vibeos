//! Emit a freestanding QEMU probe with Rust-computed reference results.
use std::{fmt::Write, path::PathBuf};
use vibeos_wasm_rv64::{compile, Op, Slot};
#[path = "probe/cache.rs"]
mod cache;
#[path = "probe/control.rs"]
mod control;
#[path = "probe/copies.rs"]
mod copies;
#[path = "probe/flow.rs"]
mod flow;
#[path = "probe/memory.rs"]
mod memory;
fn main() {
    let out = PathBuf::from(std::env::args().nth(1).expect("output directory"));
    std::fs::create_dir_all(&out).unwrap();
    let slot = |n: i16| Slot::from(n);
    let mut ops = vec![Op::consume_fuel(1u32)];
    ops.extend([
        Op::i32_add(slot(2), slot(0), slot(1)),
        Op::i32_sub(slot(3), slot(0), slot(1)),
        Op::i32_mul(slot(4), slot(0), slot(1)),
        Op::i32_bitand(slot(5), slot(0), slot(1)),
        Op::i32_bitor(slot(6), slot(0), slot(1)),
        Op::i32_bitxor(slot(7), slot(0), slot(1)),
        Op::i32_add_imm16(slot(8), slot(0), -32768i16),
        Op::i32_mul_imm16(slot(9), slot(0), 32767i16),
        Op::copy(slot(10), slot(-1)),
        Op::consume_fuel(2u32),
        Op::i32_add_imm16(slot(11), slot(11), -1i16),
        Op::branch_i32_ne_imm16(slot(11), 0i16, wasmi_ir::BranchOffset16::from(-2i16)),
        Op::Return,
    ]);
    let code = compile(&ops, 12, 1, 4096).unwrap();
    let mut assembly =
        String::from(".section .text.generated,\"ax\"\n.balign 4\n.global generated\ngenerated:\n");
    for word in &code.words {
        writeln!(assembly, ".word 0x{word:08x}").unwrap();
    }
    let (memory_source, memory_cases) = memory::emit(&mut assembly);
    let control_source = control::emit(&mut assembly);
    let cache_source = cache::emit(&mut assembly);
    let copies_source = copies::emit(&mut assembly);
    let flow_source = flow::emit(&mut assembly);
    std::fs::write(out.join("generated.S"), assembly).unwrap();
    let values = [
        0u32, 1, 2, 3, 0x7fffffff, 0x80000000, 0xffffffff, 0xffff8000, 0x12345678, 0x87654321,
    ];
    let mut rows = String::new();
    for a in values {
        for b in values {
            let row = [
                a,
                b,
                a.wrapping_add(b),
                a.wrapping_sub(b),
                a.wrapping_mul(b),
                a & b,
                a | b,
                a ^ b,
                a.wrapping_add((-32768i32) as u32),
                a.wrapping_mul(32767),
            ];
            rows.push('{');
            for value in row {
                write!(rows, "0x{value:08x}ULL,").unwrap();
            }
            rows.push_str("},\n");
        }
    }
    let c = format!(
        r#"
typedef unsigned long u64;
struct Context {{ u64 slots,memory,memory_len,fuel,resume,reason; }};
extern void generated(struct Context*,void*);
static const u64 cases[][10]={{ {rows} }};
static void put(char c) {{ register long a0 __asm__("a0")=c; register long a7 __asm__("a7")=1; __asm__ volatile("ecall" : "+r"(a0) : "r"(a7) : "memory"); }}
static void text(const char *s) {{ while(*s) put(*s++); }}
static void stop(void) {{ register long a0 __asm__("a0")=0; register long a1 __asm__("a1")=0; register long a6 __asm__("a6")=0; register long a7 __asm__("a7")=0x53525354; __asm__ volatile("ecall" : "+r"(a0) : "r"(a1),"r"(a6),"r"(a7) : "memory"); for(;;) __asm__ volatile("wfi"); }}
static void fail(void) {{ text("FAIL RV64_CODEGEN\n"); stop(); }}
{memory_source}
{control_source}
{cache_source}
{copies_source}
{flow_source}
void probe(void) {{
 for(unsigned row=0;row<sizeof(cases)/sizeof(cases[0]);row++) {{
  for(unsigned split=0;split<2;split++) {{
   u64 slots[13]; for(unsigned i=0;i<13;i++) slots[i]=0xa5a5a5a500000000ULL;
   slots[0]=0xfedcba9876543210ULL;
   slots[1]|=cases[row][0]; slots[2]|=cases[row][1]; slots[12]=3;
   struct Context ctx={{(u64)&slots[1],0,0,split?1:100,0,99}};
   generated(&ctx,(char*)generated+{entry});
   if(split) {{
    if(ctx.reason!=1 || ctx.resume!=10 || ctx.fuel!=0 || slots[12]!=3) fail();
    ctx.fuel=6;
    generated(&ctx,(char*)generated+{resume});
   }}
   if(ctx.reason!=0 || ctx.resume!=13 || ctx.fuel!=(split?0:93)) fail();
   for(unsigned i=2;i<10;i++) if(slots[i+1]!=cases[row][i]) fail();
   if(slots[11]!=slots[0] || slots[12]!=0) fail();
  }}
 }}
 cache_probe();
 text("PASS RV64_CACHE interpreter and trap transitions\n");
 copies_probe();
 text("PASS RV64_COPIES 150 parallel-copy cases\n");
 flow_probe();
 text("PASS RV64_FLOW 240 table and select cases\n");
 control_probe();
 text("PASS RV64_CONTROL 1500 comparison and shift cases\n");
 memory_probe();
 text("PASS RV64_MEMORY {memory_cases} checked memory cases\n");
 text("PASS RV64_CODEGEN 200 arithmetic and fuel-resumption cases\n");stop();
}}
"#,
        entry = code.entries[0] * 4,
        resume = code.entries[10] * 4
    );
    std::fs::write(out.join("probe.c"), c).unwrap();
    std::fs::write(out.join("start.S"),".section .text.start,\"ax\"\n.global _start\n_start:\n.option push\n.option norelax\nla sp,stack_top\n.option pop\ncall probe\n1: wfi\nj 1b\n.section .bss\n.balign 16\n.skip 16384\nstack_top:\n").unwrap();
    std::fs::write(out.join("link.ld"),"ENTRY(_start)\nSECTIONS { . = 0x80200000; .text : { *(.text.start) *(.text*) } .rodata : { *(.rodata*) } .data : { *(.data*) *(.sdata*) } .bss : { *(.bss*) *(.sbss*) *(COMMON) } }\n").unwrap();
    println!(
        "{} lowered ops, {} code words; wrote {}",
        code.lowered,
        code.words.len(),
        out.display()
    );
}
