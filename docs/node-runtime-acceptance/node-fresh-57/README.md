# Fresh 57-patch cross-build qualification

A separate source tree was unpacked from the pinned Node 24.14.0 source archive.
All 57 patches applied without fuzz. Configuration, V8 engine, libuv and Node
dependency and Node builds passed with the pinned cross compiler. The production VSH
image linked from this tree passes local console and authenticated OpenSSH
PTY acceptance. The final 100-cycle launcher gate also passes; see `repeat-100/`.

The phase result manifests record inputs, compiler identity, configuration and
exit status. Large raw logs are gzip-compressed without content changes;
`compressed-logs.json` records their uncompressed hashes and lengths. Successful
compilation is not a target execution acceptance result.

`vsh/` records eval, CJS and ESM imports, files, timer, pipeline stdin, stream
redirection, exact exit 7, exception source location, CPU/idle cancellation and
subsequent invocation. `ssh/` records authenticated remote project creation,
eval, pipeline stdin, exit 7 and Ctrl-C/relaunch. Both use the same frozen
production ELF. `shell-link/` and `repeat-link/` retain archive input hashes
and link diagnostics. No private SSH keys or disposable disks are included.
