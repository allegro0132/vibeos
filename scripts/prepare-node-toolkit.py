#!/usr/bin/env python3
"""Prepare pinned upstream tool files without executing npm or JavaScript.

This produces input for a separately authorized read-only guest tool mount.
It applies checked esbuild and tsx platform adapters.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('node_inputs', ROOT / 'scripts/node-runtime.py')
inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inputs)
adapter_spec = importlib.util.spec_from_file_location('toolkit_adapter',
    ROOT / 'tools/node-runtime/toolkit/adapt.py')
adapter = importlib.util.module_from_spec(adapter_spec)
adapter_spec.loader.exec_module(adapter)


def prepare(work, output, offline):
    source_lock = ROOT / 'tools/node-runtime/sources.lock.json'
    dependency_lock = ROOT / 'tools/node-runtime/toolkit.lock.json'
    source = json.loads(source_lock.read_text())
    dependencies = json.loads(dependency_lock.read_text())
    if source['schema'] != 1 or dependencies['schema'] != 1:
        raise ValueError('unsupported lock schema')
    artifacts = {name: source['artifacts'][name] for name in ('typescript', 'tsx')}
    artifacts.update(dependencies['artifacts'])
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() or output.is_symlink():
        raise ValueError('output already exists; choose a fresh output directory')
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        staging = Path(temporary)
        tree = staging / 'toolkit'
        modules = tree / 'node_modules'
        modules.mkdir(parents=True)
        packages = {}
        for name, artifact in artifacts.items():
            archive = inputs.fetch(artifact, work / 'downloads', offline)
            unpacked = staging / ('unpacked-' + name)
            inputs.extract(archive, unpacked, artifact['member'])
            package = unpacked / 'package'
            metadata = json.loads((package / 'package.json').read_text())
            if metadata['name'] != name or metadata['version'] != artifact['version']:
                raise ValueError(f'{name}: package identity mismatch')
            missing = set(metadata.get('dependencies', {})) - artifacts.keys()
            if missing:
                raise ValueError(f'{name}: unlocked runtime dependencies: {sorted(missing)}')
            shutil.copytree(package, modules / name)
            packages[name] = dict(version=metadata['version'],
                                  archive_sha256=inputs.digest(archive),
                                  dependencies=metadata.get('dependencies', {}),
                                  omitted_optional_dependencies=metadata.get('optionalDependencies', {}))
        wasm_artifact = source['artifacts']['esbuild']
        archive = inputs.fetch(wasm_artifact, work / 'downloads', offline)
        unpacked = staging / 'unpacked-wasi'
        inputs.extract(archive, unpacked, wasm_artifact['member'])
        wasm = unpacked / wasm_artifact['member']
        if inputs.digest(wasm) != wasm_artifact['module_sha256']:
            raise ValueError('esbuild WASI module hash mismatch')
        (tree / 'wasi').mkdir()
        shutil.copyfile(wasm, tree / 'wasi/esbuild.wasm')
        adaptations = adapter.apply(tree)
        files = {p.relative_to(tree).as_posix(): dict(bytes=p.stat().st_size,
                 sha256=inputs.digest(p)) for p in sorted(tree.rglob('*')) if p.is_file()}
        manifest = dict(schema=1, stage='vibeos-platform-adapted', adaptations=adaptations,
                        packages=packages, files=files,
                        locks={p.name: inputs.digest(p) for p in (source_lock, dependency_lock)},
                        target_execution='NOT_RUN', guest_mount_policy='read-only-required')
        (tree / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
        # A bounded, non-executable container for the guest's separate tool root.
        # Only payload files are included; no paths come from user projects.
        with (staging / 'toolkit.pack').open('wb') as packed:
            packed.write(b'VIBETOOL1' + struct.pack('<I', len(files)))
            for name in sorted(files):
                path = name.encode('utf-8')
                data = (tree / name).read_bytes()
                packed.write(struct.pack('<HI', len(path), len(data)))
                packed.write(path)
                packed.write(data)
        # Stable mode, ownership and timestamps make the upload artifact reproducible.
        with tarfile.open(staging / 'toolkit.tar', 'w', format=tarfile.USTAR_FORMAT) as tar:
            for p in sorted(tree.rglob('*')):
                entry = tar.gettarinfo(str(p), arcname=p.relative_to(tree).as_posix())
                entry.uid = entry.gid = entry.mtime = 0
                entry.uname = entry.gname = ''
                entry.mode = 0o555 if p.is_dir() else 0o444
                if p.is_file():
                    with p.open('rb') as stream:
                        tar.addfile(entry, stream)
                else:
                    tar.addfile(entry)
        tree.rename(output)
        shutil.move(staging / 'toolkit.tar', output / 'toolkit.tar')
        shutil.move(staging / 'toolkit.pack', output / 'toolkit.pack')
    return dict(files=len(files), bytes=sum(p['bytes'] for p in files.values()),
                archive_sha256=inputs.digest(output / 'toolkit.tar'),
                pack_sha256=inputs.digest(output / 'toolkit.pack'),
                target_execution='NOT_RUN')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, default=ROOT / 'target/node-runtime')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    work, output = args.work.resolve(), args.output.resolve()
    target = (ROOT / 'target').resolve()
    if any(p == target or not p.is_relative_to(target) for p in (work, output)):
        parser.error('work and output must be subdirectories of target')
    try:
        print(json.dumps(prepare(work, output, args.offline), indent=2))
    except (OSError, ValueError, tarfile.TarError) as error:
        parser.exit(1, f'prepare-node-toolkit: {error}\n')


if __name__ == '__main__':
    main()
