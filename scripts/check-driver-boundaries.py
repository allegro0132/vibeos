#!/usr/bin/env python3
"""Check all declared production workspace edges, including optional features.

This checks static crate dependencies, not register access or runtime policy.
Dev dependencies are excluded: host fixtures may intentionally use real drivers.
"""
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def violations(packages):
    by_name = {p['name']: p for p in packages}
    graph = {
        p['name']: [d['name'] for d in p['dependencies']
                    if d.get('kind') != 'dev' and d['name'] in by_name]
        for p in packages
    }

    def category(p):
        path = Path(p['manifest_path']).resolve().relative_to(ROOT)
        return path.parts[0]

    errors = []
    for package in packages:
        source = package['name']
        role = category(package)
        forbidden = {'drivers', 'boards'} if role in {'kernel', 'hal', 'contracts'} else {'kernel', 'boards'} if role == 'drivers' else set()
        if not forbidden:
            continue
        pending = [(source, [source])]
        seen = set()
        while pending:
            node, chain = pending.pop()
            if node in seen:
                continue
            seen.add(node)
            if node != source and category(by_name[node]) in forbidden:
                errors.append(' -> '.join(chain))
            pending.extend((child, chain + [child]) for child in graph[node])
    return sorted(set(errors))


def main():
    metadata = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--offline', '--no-deps', '--format-version=1'],
        cwd=ROOT, text=True))
    errors = violations(metadata['packages'])
    if errors:
        print('Forbidden production crate dependencies:', file=sys.stderr)
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print('PASS: kernel/HAL/contracts exclude concrete drivers and BSPs; drivers exclude kernel and BSPs (including optional and build dependencies).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
