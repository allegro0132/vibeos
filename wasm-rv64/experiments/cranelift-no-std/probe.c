typedef unsigned long u64;
extern u64 clif_probe(u64,u64,u64);
extern u64 clif_external(u64,u64,u64,const u64*);
static const u64 literal=0xfedcba9876543210UL;
extern char text_start[],text_end[],ro_start[],ro_end[];
extern void trap_entry(void);
static u64 root[512] __attribute__((aligned(4096)));
static u64 middle[512] __attribute__((aligned(4096)));
static u64 leaves[512] __attribute__((aligned(4096)));
static volatile unsigned expecting_fault;
struct Context {u64 slots,memory,memory_len,fuel,resume,reason;};
extern void clif_wasmi(struct Context*,u64);
static void wasmi_cases(void);
static void put(char c) {register long a0 __asm__("a0")=c;register long a7 __asm__("a7")=1;__asm__ volatile("ecall":"+r"(a0):"r"(a7):"memory");}
static void text(const char *s){while(*s)put(*s++);}
static void stop(void){register long a0 __asm__("a0")=0;register long a1 __asm__("a1")=0;register long a6 __asm__("a6")=0;register long a7 __asm__("a7")=0x53525354;__asm__ volatile("ecall":"+r"(a0):"r"(a1),"r"(a6),"r"(a7):"memory");for(;;)__asm__ volatile("wfi");}
static void fail(void){text("FAIL CRANELIFT_RV64\n");stop();}
void trap_report(void){u64 cause,address;__asm__ volatile("csrr %0,scause":"=r"(cause));__asm__ volatile("csrr %0,stval":"=r"(address));if(expecting_fault && cause==13 && address>=(u64)clif_probe && address<(u64)clif_probe+64)text("PASS EXPECTED_XO_CONSTANT_POOL_FAULT\n");else text("FAIL CRANELIFT_TRAP\n");stop();}
void probe(void){
 const u64 base=0x80200000UL;u64 code_page=(u64)clif_probe&~4095UL;
 if((u64)clif_probe!=code_page)fail();
 for(unsigned i=0;i<512;i++){
  u64 address=base+4096UL*i,flags=1|2|4|64|128;
  if(address>=(u64)text_start && address<(u64)text_end)flags=1|2|8|64;
  if(address>=(u64)ro_start && address<(u64)ro_end)flags=1|2|64;
  if(address==code_page)flags=1|2|8|64;
  if(address==((u64)clif_external&~4095UL) || address==((u64)clif_wasmi&~4095UL))flags=1|8|64;
  leaves[i]=(address>>12<<10)|flags;
 }
 root[2]=((u64)middle>>12<<10)|1;middle[1]=((u64)leaves>>12<<10)|1;
 __asm__ volatile("csrw stvec,%0"::"r"(trap_entry));
 u64 satp=(8UL<<60)|((u64)root>>12);
 __asm__ volatile("csrc sstatus,%0\ncsrw satp,%1\nsfence.vma\nfence.i"::"r"((1UL<<19)|(3UL<<13)|(3UL<<9)),"r"(satp):"memory");
 const u64 values[]={0,1,2,65535,0x7fffffff,0x80000000,0xffffffff,0x8000000000000000UL,0xffffffffffffffffUL,0xfedcba9876543210UL};
 const unsigned counts[]={0,1,2,7,31};
 for(unsigned a=0;a<10;a++)for(unsigned b=0;b<10;b++)for(unsigned c=0;c<5;c++){
  u64 expected=values[a];for(unsigned n=0;n<counts[c];n++)expected=(expected*1664525UL+1013904223UL)^values[b];
  expected^=0xfedcba9876543210UL;
  if(clif_probe(values[a],values[b],counts[c])!=expected)fail();
  if(clif_external(values[a],values[b],counts[c],&literal)!=expected)fail();
 }
 text("PASS CRANELIFT_RX 500 INTEGER CASES\n");
 text("PASS CRANELIFT_EXTERNAL_XO 500 INTEGER CASES\n");
 wasmi_cases();
 leaves[(code_page-base)/4096]=(code_page>>12<<10)|1|8|64;
 expecting_fault=1;__asm__ volatile("sfence.vma":::"memory");
 (void)clif_probe(1,2,3);
 text("PASS CRANELIFT_XO\n");stop();
}

static void wasmi_cases(void){
 const u64 values[]={0,1,2,65535,0x7fffffff,0x80000000,0xffffffff,0x8000000000000000UL,0xffffffffffffffffUL,0xfedcba9876543210UL};
 for(unsigned a=0;a<10;a++)for(unsigned b=0;b<10;b++)for(unsigned split=0;split<2;split++){
  u64 slots[]={values[a],values[b],0,0,0,0,0,3};
  struct Context c={(u64)slots,0,0,split?6:100,0,99};
  clif_wasmi(&c,0);
  if(split){if(c.fuel!=0 || c.reason!=1 || c.resume!=6 || slots[7]!=2)fail();c.fuel=10;clif_wasmi(&c,6);}
  unsigned x=(unsigned)(values[a]+values[b]),y=(unsigned)(x*values[b]),z=(unsigned)(y-values[a]);
  if(c.fuel!=(split?0:84) || c.reason!=0 || c.resume!=9 || slots[0]!=values[a] || slots[1]!=values[b] || slots[2]!=x || slots[3]!=y || slots[4]!=z || slots[5]!=z || slots[6]!=1 || slots[7]!=0)fail();
  slots[2]=0xfedcba9876543210UL;clif_wasmi(&c,10);
  if(c.reason!=0 || c.resume!=11 || slots[0]!=(unsigned)(slots[2]^slots[4]))fail();
 }
 text("PASS CRANELIFT_WASMI_XO 200 FUEL AND FRAME CASES\n");
}
