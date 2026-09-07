#!/usr/bin/env python3
"""Upload and run raw modules through the explicit QEMU WASI SSH profile."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import shlex
import subprocess
import sys

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=22222)
    parser.add_argument('--identity',type=Path,default=Path('target/wasi-qemu/id_ed25519'))
    parser.add_argument('--known-hosts',type=Path,default=Path('target/wasi-qemu/known_hosts'))
    sub=parser.add_subparsers(dest='action',required=True)
    upload=sub.add_parser('upload');upload.add_argument('file',type=Path);upload.add_argument('--name')
    run=sub.add_parser('run');run.add_argument('name');run.add_argument('args',nargs=argparse.REMAINDER)
    args=parser.parse_args()
    spec=importlib.util.spec_from_file_location('wasi_peer',Path(__file__).with_name('openssh-peer.py'))
    peer=importlib.util.module_from_spec(spec);sys.modules[spec.name]=peer;spec.loader.exec_module(peer)
    command=peer._base_ssh_command('ssh',args.host,args.port,'vibe',args.identity,args.known_hosts,30,None)
    if args.action=='upload':
        data=args.file.read_bytes();name=args.name or args.file.name
        if not 0<len(data)<=512*1024:parser.error('module must be 1..524288 bytes')
        words=['wasm-upload',name,str(len(data)),hashlib.sha256(data).hexdigest()]
    else:
        name=args.name;words=['wasm-run',name,*args.args]
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*\.wasm',name) or len(name)>128:parser.error('invalid module name')
    command.append(shlex.join(words))
    if args.action=='upload':
        result=subprocess.run(command,input=data,timeout=180)
        if result.returncode==0:print(f'Uploaded {name} ({len(data)} bytes, SHA-256 {hashlib.sha256(data).hexdigest()})')
        return result.returncode
    return subprocess.run(command).returncode
if __name__=='__main__':sys.exit(main())
