use std::fmt::Write;
use vibeos_wasm_rv64::{compile, Op, Slot};

pub fn emit(assembly: &mut String) -> (String, usize) {
    let mut declarations = String::new();
    let mut rows = String::new();
    let mut count = 0;
    for offset in [0u64, 1, 65535] {
        for kind in 0..19 {
            let ptr = Slot::from(0i16);
            let value = Slot::from(1i16);
            let result = Slot::from(2i16);
            let off = wasmi_ir::Offset16::try_from(offset).unwrap();
            let (op, width, signed, word, is_store) = match kind {
                0 => (
                    Op::Load32Offset16 {
                        result,
                        ptr,
                        offset: off,
                    },
                    4,
                    false,
                    true,
                    false,
                ),
                1 => (
                    Op::Load64Offset16 {
                        result,
                        ptr,
                        offset: off,
                    },
                    8,
                    false,
                    false,
                    false,
                ),
                2 => (
                    Op::I32Load8sOffset16 {
                        result,
                        ptr,
                        offset: off,
                    },
                    1,
                    true,
                    true,
                    false,
                ),
                3 => (
                    Op::I32Load8uOffset16 {
                        result,
                        ptr,
                        offset: off,
                    },
                    1,
                    false,
                    true,
                    false,
                ),
                4 => (
                    Op::I32Load16sOffset16 {
                        result,
                        ptr,
                        offset: off,
                    },
                    2,
                    true,
                    true,
                    false,
                ),
                5 => (
                    Op::I32Load16uOffset16 {
                        result,
                        ptr,
                        offset: off,
                    },
                    2,
                    false,
                    true,
                    false,
                ),
                6 => (
                    Op::I64Load8sOffset16 {
                        result,
                        ptr,
                        offset: off,
                    },
                    1,
                    true,
                    false,
                    false,
                ),
                7 => (
                    Op::I64Load8uOffset16 {
                        result,
                        ptr,
                        offset: off,
                    },
                    1,
                    false,
                    false,
                    false,
                ),
                8 => (
                    Op::I64Load16sOffset16 {
                        result,
                        ptr,
                        offset: off,
                    },
                    2,
                    true,
                    false,
                    false,
                ),
                9 => (
                    Op::I64Load16uOffset16 {
                        result,
                        ptr,
                        offset: off,
                    },
                    2,
                    false,
                    false,
                    false,
                ),
                10 => (
                    Op::I64Load32sOffset16 {
                        result,
                        ptr,
                        offset: off,
                    },
                    4,
                    true,
                    false,
                    false,
                ),
                11 => (
                    Op::I64Load32uOffset16 {
                        result,
                        ptr,
                        offset: off,
                    },
                    4,
                    false,
                    false,
                    false,
                ),
                12 => (
                    Op::Store32Offset16 {
                        ptr,
                        offset: off,
                        value,
                    },
                    4,
                    false,
                    false,
                    true,
                ),
                13 => (
                    Op::Store64Offset16 {
                        ptr,
                        offset: off,
                        value,
                    },
                    8,
                    false,
                    false,
                    true,
                ),
                14 => (
                    Op::I32Store8Offset16 {
                        ptr,
                        offset: off,
                        value,
                    },
                    1,
                    false,
                    false,
                    true,
                ),
                15 => (
                    Op::I32Store16Offset16 {
                        ptr,
                        offset: off,
                        value,
                    },
                    2,
                    false,
                    false,
                    true,
                ),
                16 => (
                    Op::I64Store8Offset16 {
                        ptr,
                        offset: off,
                        value,
                    },
                    1,
                    false,
                    false,
                    true,
                ),
                17 => (
                    Op::I64Store16Offset16 {
                        ptr,
                        offset: off,
                        value,
                    },
                    2,
                    false,
                    false,
                    true,
                ),
                _ => (
                    Op::I64Store32Offset16 {
                        ptr,
                        offset: off,
                        value,
                    },
                    4,
                    false,
                    false,
                    true,
                ),
            };
            let code = compile(&[Op::consume_fuel(3u32), op, Op::Return], 3, 0, 4096).unwrap();
            writeln!(
                assembly,
                ".balign 4\n.global memory_{count}\nmemory_{count}:"
            )
            .unwrap();
            for word in code.words {
                writeln!(assembly, ".word 0x{word:08x}").unwrap();
            }
            writeln!(
                declarations,
                "extern void memory_{count}(struct Context*,void*);"
            )
            .unwrap();
            writeln!(
                rows,
                "{{memory_{count},{},{width},{},{},{},{offset}}},",
                code.entries[0] * 4,
                signed as u8,
                word as u8,
                is_store as u8
            )
            .unwrap();
            count += 1;
        }
    }
    let source = format!(
        r#"
{declarations}
struct MemoryCase {{ void (*run)(struct Context*,void*); unsigned entry,width,sign,word,store; u64 offset; }};
static const struct MemoryCase memory_cases[]={{ {rows} }};
static void memory_probe(void) {{
 for(unsigned c=0;c<sizeof(memory_cases)/sizeof(memory_cases[0]);c++) {{
  const struct MemoryCase *m=&memory_cases[c];
  u64 lengths[]={{0,m->width-1,m->width,64}};
  u64 pointers[24]; for(unsigned i=0;i<17;i++) pointers[i]=i;
  pointers[17]=64-m->width-1; pointers[18]=64-m->width; pointers[19]=64-m->width+1;
  pointers[20]=~0ULL; pointers[21]=~1ULL; pointers[22]=0x100000000ULL; pointers[23]=~0ULL-65534;
  for(unsigned l=0;l<4;l++) for(unsigned p=0;p<24;p++) for(unsigned v=0;v<3;v++) {{
   unsigned char memory[80],expected[80];
   for(unsigned i=0;i<80;i++) memory[i]=expected[i]=(unsigned char)(i*37+0x91);
   u64 value=v==0?0:v==1?0xfedcba98f654b2f1ULL:~0ULL;
   u64 slots[]={{pointers[p],value,0xa5a5a5a5a5a5a5a5ULL}};
   struct Context ctx={{(u64)slots,(u64)(memory+7),lengths[l],10,0,99}};
   unsigned valid=pointers[p]<=~0ULL-m->offset && lengths[l]>=m->width;
   u64 address=pointers[p]+m->offset;
   valid=valid && address<=lengths[l]-m->width;
   u64 expected_result=slots[2];
   if(valid) {{
    if(m->store) {{ for(unsigned i=0;i<m->width;i++) expected[7+address+i]=(unsigned char)(value>>(8*i)); }}
    else {{
     expected_result=0;
     for(unsigned i=0;i<m->width;i++) expected_result|=(u64)expected[7+address+i]<<(8*i);
     if(m->sign && m->width<8 && (expected_result&(1ULL<<(m->width*8-1)))) expected_result|=~0ULL<<(m->width*8);
     if(m->word) expected_result&=0xffffffffULL;
    }}
   }}
   m->run(&ctx,(char*)m->run+m->entry);
   if(ctx.fuel!=7 || ctx.reason!=(valid?0:2) || ctx.resume!=(valid?2:1)) fail();
   if(slots[0]!=pointers[p] || slots[1]!=value || slots[2]!=expected_result) fail();
   for(unsigned i=0;i<80;i++) if(memory[i]!=expected[i]) fail();
  }}
 }}
}}
"#
    );
    (source, count * 4 * 24 * 3)
}
