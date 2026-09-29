// VibeOS tsx port: upstream resolution/transforms on the current Node instance.
import { registerHooks } from 'node:module';
import { resolve as resolvePath } from 'node:path';
import { pathToFileURL } from 'node:url';
import { initialize, resolve, load } from '../node_modules/tsx/dist/esm/index.mjs';

const args = process.argv.slice(2);
if (!args.length || args[0].startsWith('-') || args[0] === 'watch') {
  throw Object.assign(new Error('VibeOS tsx: expected script path; watch and CLI subprocess modes are unavailable'),
                      { code: 'ENOTSUP' });
}
const entry = resolvePath(args[0]);
process.argv = [process.argv[0], entry, ...args.slice(1)];
process.setSourceMapsEnabled(true);
initialize({});
registerHooks({ resolve, load });
await import(pathToFileURL(entry).href);
