"""Shared integrity checks for consumers of universal build artifacts."""
import hashlib
import json
from pathlib import Path


def load_manifest(path, board):
    path = Path(path).resolve()
    manifest = json.loads(path.read_text(encoding='utf-8'))
    if manifest.get('schema') != 1 or board not in manifest.get('boards', []):
        raise ValueError(f'manifest does not support {board}')
    if manifest.get('image') != 'vibeos.bin':
        raise ValueError('unexpected image path in manifest')
    image = path.parent / 'vibeos.bin'
    raw = image.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != manifest.get('sha256') or len(raw) != manifest.get('bytes'):
        raise ValueError('kernel checksum or length differs from manifest')
    resolved = path.parent / 'resolved.toml'
    if hashlib.sha256(resolved.read_bytes()).hexdigest() != manifest.get('resolved_sha256'):
        raise ValueError('resolved configuration differs from manifest')
    if manifest.get('layout', {}).get('sha256') != digest:
        raise ValueError('missing matching ELF verification record')
    return manifest, image
