#!/usr/bin/env python3
"""Freeze the explicitly supported pure-Python library into one CPython command."""
import marshal
from pathlib import Path
import sys

# No host paths or source files are exposed to the guest. Missing modules fail
# normally; native extension availability is determined by CPython's WASI build.
MODULES = '''encodings collections json re importlib
_py_abc _weakrefset _compat_pickle _colorize _opcode_metadata _py_warnings _strptime
__future__ abc annotationlib argparse ast bisect calendar codecs codeop contextlib copy copyreg csv
dataclasses datetime decimal difflib dis enum fnmatch fractions functools
genericpath gettext glob heapq inspect io keyword linecache locale ntpath numbers
opcode operator os pathlib pickle posixpath pprint reprlib runpy shlex
site stat string stringprep struct textwrap token tokenize traceback
types typing warnings weakref _collections_abc _sitebuiltins'''.split()


def freeze(library, output):
    files = {}
    for module in MODULES:
        path = library / module
        if path.is_dir():
            for child in sorted(path.rglob('*.py')):
                if '__pycache__' not in child.parts:
                    name = '.'.join(child.relative_to(library).with_suffix('').parts)
                    package = name.endswith('.__init__')
                    if package:
                        name = name[:-9]
                    files[name] = (child, package)
        else:
            files[module] = (path.with_suffix('.py'), False)
    with output.open('w') as out:
        rows = []
        for index, (name, (path, package)) in enumerate(sorted(files.items())):
            code = compile(path.read_bytes(), '<frozen ' + name + '>', 'exec', dont_inherit=True)
            data = marshal.dumps(code)
            symbol = f'vibe_frozen_{index}'
            out.write(f'static const unsigned char {symbol}[] = {{\n')
            for offset in range(0, len(data), 24):
                out.write(','.join(str(b) for b in data[offset:offset+24]) + ',\n')
            out.write('};\n')
            rows.append(f'{{"{name}", {symbol}, sizeof({symbol}), {int(package)}}},\n')
        out.write('static const struct _frozen vibe_stdlib[] = {\n')
        out.writelines(rows)
        out.write('{0, 0, 0, 0}\n};\n')


if __name__ == '__main__':
    freeze(Path(sys.argv[1]), Path(sys.argv[2]))
