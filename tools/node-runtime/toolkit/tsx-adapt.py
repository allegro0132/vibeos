"""Convert pinned upstream tsx loading to Node 24 in-instance sync hooks."""
import hashlib
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXPECTED = {
    'cjs/api/index.cjs': 'cfaf8a6e41b1c29e908a65e2e8cc470ef8ee5dd8393a48d12e0e0a38ec619b1a',
    'cjs/api/index.mjs': '39e31bcc1eb1fd36f96063caa58e1bbea4f0bd97e63d1e37f0aa74b5ec94b268',
    'cjs/index.cjs': 'b895c71328959906049a50c3a04a7b1a42973001805cab7a49a26c59a2e02053',
    'cjs/index.mjs': '19a417f3a37c66d93619ac2d9a8b70d12ee154439e92741d0b8784fb7567979e',
    'esm/api/index.cjs': '3add4ac5b04a70d06b439c979332e09dc6cb9edd4916f407bf637925dd682115',
    'esm/api/index.mjs': '2198d7f54368ed15a3b867c728c963d794cc5abcfde4e8fc1cf488a00ed5ba58',
    'esm/index.cjs': '9e2ff6af9c7dfd540bf1c595f5b3fbd372ba43c28cd4f3aa381bd425b14f9226',
    'loader.cjs': '228714bcafea42d1b332d5e80e9b4c0fdfaf88c413387ddc0142d8c4a3477178',
    'loader.mjs': 'bfd4639a782108cd25cdb316c299273dd7c5cf672a1b573ba15d3a3f53e295d8',
    'repl.cjs': '8207e7c1008a19de5f7e45567da8b10be4240a3b8f13ae489f7ca57a28dd66c9',
    'repl.mjs': 'bc9f753f49999f196ff460ef249616a63fe0285cf1a471f6cd5862f024355ffb',
    'client-D6NvIMSC.cjs': 'af10790d58385f62c205140c3f7c25dae26638c2961fa24eb958f888d8995a40',
    'client-BQVF1NaW.mjs': '334ad3dbfaf820eeb08dd2fa40750c8316e6f8a61311bdf99defd3c361fbece4',
    'temporary-directory-B83uKxJF.cjs': 'da189099aba4a7aff1e0ca337cd71410a0f96abc66298403db041cb812cbd24c',
    'temporary-directory-CwHp0_NW.mjs': 'e0771b7d9b216d438ff2ade7494a7a3ac6202c66cb752f2cd99bffb3d78226fe',
    'index-B4SIRlEU.cjs': '4bdc997673ea95e1efb524ba901949e9ea22396aad90329a79bdd8988df6595f',
    'index-DlKgSVBb.mjs': '04a0d6165671f2f9b5883e2f2aeae2b8e36916c937278bf25a84332a610ec4ab',
    'esm/index.mjs': '61fed59b0b2e2d10c5b1eb56cbac6428cd324c3ed55312439754d183c924a163',
}


def replace(source, old, new):
    if source.count(old) != 1:
        raise ValueError(f'tsx patch anchor changed: {old[:100]}')
    return source.replace(old, new)


def apply(tree):
    dist = tree / 'node_modules/tsx/dist'
    sources = {}
    for name, expected in EXPECTED.items():
        data = (dist / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f'tsx patch input changed: {name}')
        sources[name] = data.decode()
    # No IPC attempt and no ambient tmpdir/user identity query during imports.
    sources['client-D6NvIMSC.cjs'] = 'exports.parent={send:undefined};exports.connectingToServer=Promise.resolve();\n'
    sources['client-BQVF1NaW.mjs'] = 'const p={send:undefined},c=Promise.resolve();export{p,c};\n'
    sources['temporary-directory-B83uKxJF.cjs'] = 'exports.tmpdir="/.vibeos-cache-disabled";\n'
    sources['temporary-directory-CwHp0_NW.mjs'] = 'const t="/.vibeos-cache-disabled";export{t};\n'
    for name, cache in [('index-B4SIRlEU.cjs', 'kA'), ('index-DlKgSVBb.mjs', 'pA')]:
        sources[name] = replace(sources[name], f'process.env.TSX_DISABLE_CACHE?new Map:new {cache}', 'new Map')
    # tsx already bundles the upstream lexer JavaScript fallback used before
    # its asynchronous WASM initialization completes. Keep that parser and
    # omit WASM compilation entirely on the JIT-less, no-WebAssembly profile.
    for name, init, blob, fallback in [('index-B4SIRlEU.cjs', 'qe', 'ke', 'CA'),
                                       ('index-DlKgSVBb.mjs', '_e', 'we', 'BA')]:
        source = sources[name]
        start = source.index(f'const {init}=WebAssembly.compile(')
        end = source.index(f';var {blob};', start)
        source = source[:start] + f'const {init}=undefined' + source[end:]
        source = replace(source, f'let Xe=!1;{init}.then(()=>{{Xe=!0}});', '')
        sources[name] = replace(source, f'Xe?He(n,e):{fallback}(n,e)', f'{fallback}(n,e)')
    # Cache keys are private to this invocation. Full inputs avoid both a
    # crypto dependency and hash collisions; this is not a cryptographic API.
    sources['index-B4SIRlEU.cjs'] = replace(sources['index-B4SIRlEU.cjs'],
        ',Zt=require("node:crypto")', '')
    sources['index-B4SIRlEU.cjs'] = replace(sources['index-B4SIRlEU.cjs'],
        'Zt.createHash("sha1").update(n).digest("hex")', 'n')
    sources['index-DlKgSVBb.mjs'] = replace(sources['index-DlKgSVBb.mjs'],
        'import Vt from"node:crypto";', '')
    sources['index-DlKgSVBb.mjs'] = replace(sources['index-DlKgSVBb.mjs'],
        'Vt.createHash("sha1").update(n).digest("hex")', 'n')
    for name in sources:
        sources[name] = sources[name].replace('import"node:crypto";', '').replace('require("node:crypto"),', '').replace(',require("node:crypto");', ';')
        if 'node:crypto' in sources[name]:
            raise ValueError(f'unhandled tsx crypto import: {name}')
    name = 'index-DlKgSVBb.mjs'
    source = sources[name]
    start = source.index('wr=u(async(n,e,A)=>')
    end = source.index(';export{', start)
    sync = source[start:end].replace('wr=u(', 'vibeosTransformESM=u(', 1)
    sync = sync.replace('async(', '(').replace('await ', '').replace('gr(e,n,', 'Qr(e,n,').replace('$t(C,i)', 'Zt(C,i)')
    sources[name] = source[:end] + ';const ' + sync + source[end:]
    sources[name] = replace(sources[name], 'wr as t};', 'wr as t,vibeosTransformESM as v};')
    name = 'esm/index.mjs'
    source = sources[name]
    source = replace(source, 'import{isMainThread as j}from"node:worker_threads";', '')
    source = replace(source, 'import{r as A}from"../register-RyGUjI6j.mjs";', '')
    source = replace(source, 'g(W)&&j&&A();', '')
    source = replace(source, 'a as X,t as B,', 'a as X,v as B,')
    source = replace(source, 'import{readFile as K}from"node:fs/promises";', 'import{readFileSync as K}from"node:fs";')
    source = replace(source, 'await S.promises.access(t).then(()=>!0,()=>!1)', 'S.existsSync(t)')
    source = replace(source, 'await S.promises.readFile(t,"utf8")', 'S.readFileSync(t,"utf8")')
    # registerHooks covers both require and import. The CJS nextResolve uses
    # MODULE_NOT_FOUND, while the worker-only upstream path sees ESM codes.
    source = replace(source, 'p!=="ERR_MODULE_NOT_FOUND"&&p!=="ERR_PACKAGE_PATH_NOT_EXPORTED"',
                     'p!=="ERR_MODULE_NOT_FOUND"&&p!=="MODULE_NOT_FOUND"&&p!=="ERR_PACKAGE_PATH_NOT_EXPORTED"')
    source = replace(source, 's.code==="ERR_MODULE_NOT_FOUND"',
                     '(s.code==="ERR_MODULE_NOT_FOUND"||s.code==="MODULE_NOT_FOUND")')
    source = replace(source, 's.responseURL?.startsWith("file:")', 't.startsWith("file:")')
    # Sync hooks return transformed CJS source directly. The upstream worker
    # loader's data-URL workaround would change file identity under these hooks.
    source = replace(source,
        'const p=X(n,o,{tsconfigRaw:E?.(o)}),O=e?`${o}?namespace=${encodeURIComponent(e)}`:o;return s.responseURL=`data:text/javascript,${encodeURIComponent(p.code)}?filePath=${encodeURIComponent(O)}`,s',
        'const p=X(n,o,{tsconfigRaw:E?.(o)});return{...s,source:T(p)}')
    # Exact input hashes above bound this mechanical conversion to the reviewed
    # module. Every awaited dependency in its resolve/load chain is sync now.
    source = source.replace('async ', '').replace('async(', '(').replace('await ', '')
    if re.search(r'\b(?:async|await)\b', source):
        raise ValueError('tsx loader still contains asynchronous hooks')
    sources[name] = source
    outputs = {}
    for name, source in sources.items():
        (dist / name).write_text(source)
        outputs[name] = dict(upstream_sha256=EXPECTED[name],
                             output_sha256=hashlib.sha256(source.encode()).hexdigest())
    (tree / 'vibeos').mkdir(exist_ok=True)
    launcher = HERE / 'tsx-launcher.mjs'
    (tree / 'vibeos/tsx-launcher.mjs').write_bytes(launcher.read_bytes())
    return outputs, {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in (Path(__file__), launcher)}
