import importlib.util,struct,unittest
from pathlib import Path
s=importlib.util.spec_from_file_location('tso_capture',Path(__file__).parents[1]/'mars-tso-capture.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
SRC=bytes.fromhex('020000000001');DST=bytes.fromhex('00e04f8387aa');SIP=bytes([192,168,77,10]);DIP=bytes([192,168,77,1])
def checksum(b):
    n=0
    for i,v in enumerate(b):n+=v<<(8 if i%2==0 else 0)
    n=(n&65535)+(n>>16);n=(n&65535)+(n>>16);return (~n&65535).to_bytes(2,'big')
def frames():
    out=[]
    for index,offset in enumerate(range(0,4097,1460)):
        count=min(1460,4097-offset);b=bytearray(54+count);b[:14]=DST+SRC+b'\x08\x00';b[14]=0x45;b[16:18]=(40+count).to_bytes(2,'big');b[18:20]=(0x6000+index).to_bytes(2,'big');b[20]=0x40;b[22]=64;b[23]=6;b[26:34]=SIP+DIP;b[34:38]=struct.pack('!HH',5304,5305);b[38:42]=(0x10000000+offset).to_bytes(4,'big');b[46]=0x50;b[47]=0x18 if offset+count==4097 else 0x10;b[48]=0x7f;b[54:]=bytes((i*17+i//251)%253 for i in range(offset,offset+count));b[24:26]=checksum(b[14:34]);b[50:52]=checksum(SIP+DIP+b'\x00\x06'+(20+count).to_bytes(2,'big')+b[34:]);out.append(bytes(b))
    return out
def pcap(fs):
    b=struct.pack('<IHH4I',0xa1b2c3d4,2,4,0,0,65535,1)
    for f in fs:b+=struct.pack('<4I',0,0,len(f),len(f))+f
    return b
class Tests(unittest.TestCase):
    def analyze(self,fs):return m.analyze(pcap(fs),4097,1460,SRC,DST,SIP,DIP)
    def test_complete_valid_capture(self):
        r=self.analyze(frames());self.assertTrue(r['passed']);self.assertEqual([p['payload'] for p in r['segments']],[1460,1460,1177])
    def test_missing_reordered_duplicate_and_corrupt_fail(self):
        fs=frames()
        for f in [fs[:2],fs[::-1],fs+[fs[-1]]]:
            with self.assertRaises(ValueError):self.analyze(f)
        for offset in [24,38,47,50,54]:
            bad=bytearray(fs[0]);bad[offset]^=1
            with self.assertRaises(ValueError):self.analyze([bytes(bad)]+fs[1:])
    def test_truncated_capture_fails(self):
        with self.assertRaises(ValueError):m.analyze(pcap(frames())[:-1],4097,1460,SRC,DST,SIP,DIP)
if __name__=='__main__':unittest.main()
