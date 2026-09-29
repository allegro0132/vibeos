"""Checked platform replacements for pinned upstream tool packages."""
import hashlib
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent


def apply(tree):
    target = tree / 'node_modules/esbuild/lib/main.js'
    original = target.read_bytes()
    upstream = '9425d36afcd1c8542950739bb5611c569f67ba45b4701b274c7ea2ae91f2902b'
    if hashlib.sha256(original).hexdigest() != upstream:
        raise ValueError('esbuild platform patch: unexpected upstream main.js')
    source = original.decode()
    start = source.index('// lib/npm/node-platform.ts\n')
    end = source.index('var node_default = node_exports;\n', start)
    platform = HERE / 'esbuild-platform.js'
    source = source[:start] + platform.read_text() + '\n' + source[end:]
    # Upstream uses a service request only to log locally detected option
    # errors. This port has no long-lived logging service; preserve the same
    # structured diagnostics and original Error detail without an extra job.
    needle = '        sendRequest(refs, { command: "error", flags, error }, () => {\n'
    if source.count(needle) != 1:
        raise ValueError('esbuild platform patch: diagnostic anchor changed')
    source = source.replace(needle, '''        if (streamIn.vibeos) {
          error.detail = details.load(error.detail);
          callback(failureErrorWithLog("Transform failed", [error], []), null);
          return;
        }
''' + needle)
    target.write_text(source)
    spec = importlib.util.spec_from_file_location('tsx_adapter', HERE / 'tsx-adapt.py')
    tsx = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tsx)
    tsx_outputs, tsx_inputs = tsx.apply(tree)
    return dict(tsx=tsx_outputs, esbuild=dict(upstream_sha256=upstream,
                            output_sha256=hashlib.sha256(target.read_bytes()).hexdigest()),
                inputs=tsx_inputs | {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in (Path(__file__), platform)})
