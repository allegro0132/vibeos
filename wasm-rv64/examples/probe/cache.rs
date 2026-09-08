use std::fmt::Write;
use vibeos_wasm_rv64::{compile, Op, Slot};

pub fn emit(assembly: &mut String) -> String {
    let slot = |n: i16| Slot::from(n);
    let ops = [
        Op::consume_fuel(1u32),
        Op::copy_imm32(slot(0), 0xf2345678u32),
        Op::f32_add(slot(0), slot(0), slot(0)), // interpreter transition
        Op::copy(slot(1), slot(0)),
        Op::Load32Offset16 {
            result: slot(3),
            ptr: slot(2),
            offset: wasmi_ir::Offset16::try_from(0u64).unwrap(),
        },
        Op::Return,
    ];
    let code = compile(&ops, 4, 0, 4096).unwrap();
    assert!(!code.supported[2]);
    writeln!(
        assembly,
        ".balign 4\n.global cache_transition\ncache_transition:"
    )
    .unwrap();
    for word in code.words {
        writeln!(assembly, ".word 0x{word:08x}").unwrap();
    }
    format!(
        r#"
extern void cache_transition(struct Context*,void*);
static void cache_probe(void) {{
 u64 slots[]={{0,1,0,0xdeadbeefULL}};
 unsigned char memory[]={{0xef,0xcd,0xab,0x89}};
 struct Context ctx={{(u64)slots,(u64)memory,0,10,0,99}};
 cache_transition(&ctx,(char*)cache_transition+{entry});
 if(ctx.fuel!=9 || ctx.reason!=0 || ctx.resume!=2 || slots[0]!=0xf2345678ULL) fail();
 // Simulate an interpreter update before re-entering at a supported IR entry.
 slots[0]=0xfedcba9876543210ULL;
 cache_transition(&ctx,(char*)cache_transition+{resume});
 if(ctx.fuel!=9 || ctx.reason!=2 || ctx.resume!=4 || slots[1]!=slots[0] || slots[3]!=0xdeadbeefULL) fail();
 // Every entry reloads the frame; the failed load did not overwrite its result.
 slots[1]=0x1122334455667788ULL;
 ctx.memory_len=4;
 cache_transition(&ctx,(char*)cache_transition+{load});
 if(ctx.fuel!=9 || ctx.reason!=0 || ctx.resume!=5 || slots[1]!=0x1122334455667788ULL || slots[3]!=0x89abcdefULL) fail();
}}
"#,
        entry = code.entries[0] * 4,
        resume = code.entries[3] * 4,
        load = code.entries[4] * 4
    )
}
