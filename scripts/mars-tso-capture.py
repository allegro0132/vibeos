#!/usr/bin/env python3
"""Validate full Ethernet capture of the explicit one-shot Mars TSO probe."""
import argparse, ipaddress, json, re, struct
from pathlib import Path

def checksum_ok(data):
    if len(data)%2:data+=b'\0'
    total=sum(int.from_bytes(data[i:i+2],'big') for i in range(0,len(data),2))
    while total>>16:total=(total&65535)+(total>>16)
    return total==65535

def analyze(raw,payload,mss,src_mac,dst_mac,src_ip,dst_ip):
    if raw[:4] not in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4'):raise ValueError('unsupported pcap')
    endian='<' if raw[:4]==b'\xd4\xc3\xb2\xa1' else '>'
    if len(raw)<24 or struct.unpack_from(endian+'I',raw,20)[0]!=1:raise ValueError('not Ethernet pcap')
    pos=24; received=bytearray(); packets=[]
    while pos<len(raw):
        if len(raw)-pos<16:raise ValueError('truncated pcap header')
        _,_,cap,orig=struct.unpack_from(endian+'4I',raw,pos);pos+=16
        if cap!=orig or pos+cap>len(raw):raise ValueError('truncated packet')
        f=raw[pos:pos+cap];pos+=cap
        if len(f)<54 or f[12:14]!=b'\x08\x00' or f[23]!=6:continue
        ihl=(f[14]&15)*4
        if ihl<20 or len(f)<14+ihl+20:raise ValueError('bad IP header')
        tcp=14+ihl
        if f[tcp:tcp+4]!=struct.pack('!HH',5304,5305):continue
        if f[:6]!=dst_mac or f[6:12]!=src_mac or f[26:30]!=src_ip or f[30:34]!=dst_ip:raise ValueError('wrong peer')
        total=int.from_bytes(f[16:18],'big');end=14+total;th=(f[tcp+12]>>4)*4
        if ihl!=20 or th!=20 or total>1500 or end>len(f) or end<=tcp+th:raise ValueError('bad segment lengths')
        if f[14]!=0x45 or f[20:22]!=b'\x40\x00' or f[22]!=64 or f[42:46]!=bytes(4) or f[46]!=0x50 or f[48:50]!=b'\x7f\x00':raise ValueError('header changed')
        if not checksum_ok(f[14:34]):raise ValueError('IP checksum')
        pseudo=f[26:34]+bytes([0,6])+(total-ihl).to_bytes(2,'big')
        if not checksum_ok(pseudo+f[tcp:end]):raise ValueError('TCP checksum')
        segment=f[tcp+th:end];offset=len(received)
        if len(segment)!=min(mss,payload-offset):raise ValueError('MSS/duplicate/extra segment')
        seq=int.from_bytes(f[tcp+4:tcp+8],'big')
        if seq!=0x10000000+offset:raise ValueError('sequence/order')
        if f[tcp+13]!=(0x18 if offset+len(segment)==payload else 0x10):raise ValueError('PSH/control flags')
        expected=bytes(((i*17+i//251)%253) for i in range(offset,offset+len(segment)))
        if segment!=expected:raise ValueError('payload corruption')
        ident=int.from_bytes(f[18:20],'big')
        if ident!=0x6000+len(packets):raise ValueError('IP ID progression')
        received.extend(segment);packets.append({'seq':seq,'payload':len(segment),'ip_id':ident,'ip_length':total})
    if len(received)!=payload:raise ValueError(f'missing payload: {len(received)}/{payload}')
    return {'passed':True,'payload_bytes':len(received),'segments':packets,'wire_mtu':1500}

def main():
    p=argparse.ArgumentParser();p.add_argument('pcap',type=Path);p.add_argument('--capture-log',type=Path,required=True)
    for name in ['src-mac','dst-mac','src-ip','dst-ip']:p.add_argument('--'+name,required=True)
    p.add_argument('--payload',type=int,required=True);p.add_argument('--mss',type=int,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();drops=re.findall(r'(\d+) packets dropped by kernel',a.capture_log.read_text())
    if drops!=['0']:raise ValueError('capture drop status missing/nonzero')
    r=analyze(a.pcap.read_bytes(),a.payload,a.mss,bytes.fromhex(a.src_mac.replace(':','')),bytes.fromhex(a.dst_mac.replace(':','')),ipaddress.ip_address(a.src_ip).packed,ipaddress.ip_address(a.dst_ip).packed)
    a.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
if __name__=='__main__':main()
