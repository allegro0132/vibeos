#!/usr/bin/env python3
"""Summarize matched single-hart measured sets; exclude calibration/validation scores."""
import argparse
import json
from pathlib import Path
import statistics

root=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--vibeos',type=Path,default=root/'target/coremark-benchmark/vibeos-single/results.json')
p.add_argument('--debian',type=Path,default=root/'target/coremark-benchmark/debian/results/results.json')
p.add_argument('--output',type=Path,default=root/'target/coremark-benchmark/comparison.json')
a=p.parse_args()
configuration=json.loads((a.vibeos.parent/'environment.json').read_text())['configuration']
debian_command=json.loads((a.debian.parent.parent/'qemu-command.json').read_text())
for key, flag, value in [('machine','-machine','virt'),('cpu','-cpu','rv64'),('harts','-smp','1'),('memory','-m','1G'),('accel','-accel','tcg,thread=single'),('rtc','-rtc','base=utc,clock=vm')]:
    assert str(configuration[key])==value and debian_command[debian_command.index(flag)+1]==value, key
assert configuration['icount'] is None and '-icount' not in debian_command
def summary(path):
    data=json.loads(path.read_text())
    assert len(data)==4 and all(row['seconds']>=10 for row in data)
    samples=[row['score'] for row in data if row['name'].startswith('performance-')]
    assert len(samples)==3 and min(samples)>0
    return dict(median=statistics.median(samples),minimum=min(samples),maximum=max(samples),samples=data,evidence=str(path))
v=summary(a.vibeos);d=summary(a.debian)
result=dict(unit='CoreMark iterations/second',configuration=configuration,vibeos_wasmi=v,debian_native=d,
    native_over_wasmi=d['median']/v['median'],wasmi_percent_native=100*v['median']/d['median'],
    scope='QEMU whole execution stack comparison, not isolated OS overhead or native hardware speed')
a.output.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
