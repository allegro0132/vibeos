#!/usr/bin/env python3
"""Test the no-allocation parser and a real QEMU-generated DTB."""
import argparse,json,pathlib,subprocess
root=pathlib.Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--dtb',required=True,type=pathlib.Path)
p.add_argument('--harts',type=int,default=4)
p.add_argument('--mask',type=lambda s:int(s,0),default=15)
a=p.parse_args()
work=root/'target/coremark-performance/wasmtime-isa-parser';work.mkdir(parents=True,exist_ok=True)
source=root/'wasmtime-runtime/src/riscv_isa.rs'
subprocess.run(['rustc','--edition=2021','--test',str(source),'-o',str(work/'unit')],check=True)
subprocess.run([str(work/'unit')],check=True)
probe=work/'probe.rs'
probe.write_text(f'#[path={json.dumps(str(source))}] mod isa;\n'+'''
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let bytes = std::fs::read(&args[1]).unwrap();
    let harts = (0..args[2].parse::<u64>().unwrap()).collect::<Vec<_>>();
    let mask = isa::common(&bytes, &harts).expect("firmware ISA discovery").bits();
    assert_eq!(mask, args[3].parse::<u8>().unwrap());
    println!("PASS real DTB: {} harts, mask={:#x}", harts.len(), mask);
}
''')
subprocess.run(['rustc','--edition=2021',str(probe),'-o',str(work/'probe')],check=True)
subprocess.run([str(work/'probe'),str(a.dtb.resolve()),str(a.harts),str(a.mask)],check=True)
