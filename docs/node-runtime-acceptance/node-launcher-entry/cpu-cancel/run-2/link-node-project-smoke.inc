R"VIBEOSJS(// Shared target-only project fixture, also embedded by the baseline gate.
if (process.argv[1] === '/main.cjs') {
  if (require.main !== module || __filename !== '/main.cjs' || process.cwd() !== '/')
    throw new Error('incorrect main module identity or cwd');
  process.exitCode = Number(process.argv[2]);
  globalThis.__vibeosRequestExit = Number(process.argv[3]);
  console.log('NODE MAIN file=1 argv=1 cwd=1 PASS');
}

        process.on('exit', code => { globalThis.__vibeosExitEvent = code; });
        const { Buffer } = require('buffer');
        globalThis.__vibeosNodeStdinResult = 0;
        let inputText = '';
        process.stdin.setEncoding('utf8');
        process.stdin.on('data', chunk => { inputText += chunk; });
        process.stdin.on('end', () => {
          if (inputText !== 'node-中-stdin\n') {
            globalThis.__vibeosNodeStdinResult = -1;
            console.error('NODE STDIN incorrect data', JSON.stringify(inputText));
            return;
          }
          globalThis.__vibeosNodeStdinResult = 1;
          console.log('NODE STDIN utf8=1 eof=1 bytes=15 PASS');
        });
        process.stdin.on('error', error => {
          globalThis.__vibeosNodeStdinResult = -1;
          console.error('NODE STDIN error:', error.stack);
        });
        const fs = require('fs');
        const projectRequire = require('module').createRequire('/gate.cjs');
        const project = projectRequire('./dep.cjs');
        if (project.answer !== 42) throw Error('project CJS dependency');
        fs.writeFileSync('/sync.txt', 'target-file-42');
        if (fs.readFileSync('/sync.txt', 'utf8') !== 'target-file-42') throw Error('sync file roundtrip');
        console.log('NODE PROJECT cjs=42 sync_file=1 PASS');
        globalThis.__vibeosNodeProjectResult = 0;
        Promise.all([project.load(), fs.promises.readFile('/sync.txt', 'utf8')])
          .then(async ([module, text]) => {
            if (module.answer !== 99 || text !== 'target-file-42') throw Error('ESM/async read');
            await fs.promises.writeFile('/async.txt', text + '-async');
            if (await fs.promises.readFile('/async.txt', 'utf8') !== 'target-file-42-async') throw Error('async file roundtrip');
            await fs.promises.writeFile('/async.txt', 'short');
            if (await fs.promises.readFile('/async.txt', 'utf8') !== 'short') throw Error('async truncation');
            globalThis.__vibeosNodeProjectResult = 1;
            console.log('NODE PROJECT esm=99 dynamic_import=1 async_file=1 PASS');
          }).catch(error => {
            globalThis.__vibeosNodeProjectResult = -1;
            console.error('NODE PROJECT error:', error.stack);
          });
        let wasiRejected = false;
        try { new (require('wasi').WASI)({ version: 'preview1', args: [], env: {} }); }
        catch (error) { wasiRejected = error.code === 'ERR_VIBEOS_UNSUPPORTED'; }
        if (!wasiRejected) throw Error('Node WASI unsupported boundary');
        for (const action of [
          () => require('child_process').spawn('unsupported-child'),
          () => new (require('worker_threads').Worker)('1 + 1', { eval: true }),
          () => require('net').connect({ host: '127.0.0.1', port: 1 }),
          () => require('dgram').createSocket('udp4'),
          () => process.on('SIGINT', () => {}),
          () => require('fs').watchFile('unsupported-watch', () => {}),
          () => {
            const binding = process.binding('pipe_wrap');
            return new binding.Pipe(binding.constants.IPC);
          },
        ]) {
          let rejected = false;
          try { action(); } catch (error) { rejected = error.code === 'ERR_VIBEOS_UNSUPPORTED'; }
          if (!rejected) throw Error('Node excluded-operation boundary');
        }
        for (const query of [() => process.cpuUsage(), () => process.threadCpuUsage(),
                             () => process.resourceUsage()]) {
          let rejected = false;
          try { query(); } catch (error) { rejected = error.code === 'ENOTSUP'; }
          if (!rejected) throw Error('unavailable usage accounting');
        }
        const os = require('os');
        if (os.type() !== 'VibeOS' || os.machine() !== 'riscv64' || !os.release()) throw Error('image identity');
        for (const query of [() => os.cpus(), () => os.loadavg()]) {
          let rejected = false;
          try { query(); } catch (error) { rejected = error.code === 'ENOTSUP'; }
          if (!rejected) throw Error('unavailable OS statistics');
        }
        const savedHostname = process.env.HOSTNAME;
        process.env.HOSTNAME = 'vibeos-node';
        if (os.hostname() !== 'vibeos-node') throw Error('explicit hostname');
        if (savedHostname === undefined) delete process.env.HOSTNAME;
        else process.env.HOSTNAME = savedHostname;
        const savedHome = process.env.HOME;
        process.env.HOME = '/explicit-home';
        if (require('os').homedir() !== '/explicit-home') throw Error('explicit home');
        if (savedHome === undefined) delete process.env.HOME;
        else process.env.HOME = savedHome;
        if (!(process.pid > 0) || process.ppid !== 0) throw Error('invocation identity');
        process.title = 'vibeos-node-gate';
        if (process.title !== 'vibeos-node-gate') throw Error('process title');
        if (Buffer.from('vibeos').toString('hex') !== '766962656f73') throw Error('Buffer');
        globalThis.__vibeosNodeWorkResult = 0;
        const zlib = require('zlib');
        zlib.gzip(Buffer.from('vibeos-native-work'), (error, zipped) => {
          if (error) throw error;
          zlib.gunzip(zipped, (error, plain) => {
            if (error) throw error;
            if (plain.toString() !== 'vibeos-native-work') throw Error('queued zlib work');
            globalThis.__vibeosNodeWorkResult = 1;
            console.log('NODE SMOKE queued zlib roundtrip PASS');
          });
        });
        globalThis.__vibeosNodeResult = 0;
        Promise.resolve(40).then(value => setTimeout(() => {
          globalThis.__vibeosNodeResult = value + 2;
          console.log('NODE SMOKE buffer promise timer=42 PASS');
        }, 5));
        if (globalThis.__vibeosRequestExit) {
          const finish = () => {
            if (globalThis.__vibeosNodeResult !== 42 || globalThis.__vibeosNodeWorkResult !== 1 ||
                globalThis.__vibeosNodeProjectResult !== 1 || globalThis.__vibeosNodeStdinResult !== 1) {
              setTimeout(finish, 2);
              return;
            }
            process.exit(process.exitCode);
            globalThis.__vibeosReturnedAfterExit = true;
          };
          setTimeout(finish, 2);
        }
      
// The launcher fixture grants /project as /; a sibling is never admitted.
{
  const fs = require('fs');
  if (fs.existsSync('/outside-secret')) throw new Error('sibling visible');
  for (const operation of [() => fs.readFileSync('/escape'),
                           () => fs.writeFileSync('/escape', 'bad'),
                           () => fs.realpathSync('/escape')]) {
    let denied = false;
    try { operation(); } catch (error) { denied = error.code === 'EACCES'; }
    if (!denied) throw new Error('project symlink boundary was not enforced');
  }
  console.log('NODE ROOT sibling_hidden=1 symlink_denied=3 PASS');
}

// The gate invokes these only for the explicit live-revocation scenario.
{
  const fs = require('fs');
  let admittedFd;
  globalThis.__vibeosPrepareRevoke = () => { admittedFd = fs.openSync('/main.cjs', 'r'); };
  globalThis.__vibeosCheckRevoke = () => {
    let denied = 0;
    for (const operation of [() => fs.readFileSync('/main.cjs'),
                             () => fs.readSync(admittedFd, Buffer.alloc(8), 0, 8, 0)]) {
      try { operation(); } catch (error) { if (error.code === 'EACCES') denied++; }
    }
    fs.closeSync(admittedFd);
    if (denied !== 2) throw new Error('revoked parent capability still readable');
    console.log('NODE REVOKE new_path=1 open_fd=1 PASS');
    return denied;
  };
}
)VIBEOSJS"
