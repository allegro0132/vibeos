# Official TypeScript on native Node (M3 partial)

`run-4/` passes official TypeScript 5.9.3 on VibeOS RV64GC/QEMU, using the
unmodified upstream compiler and declarations from the locked offline toolkit.
The host prepares source files and packages only; all checking and compilation
occurs inside the guest. The optional `node-toolkit` image registers:

```
tsc --root @home/ts-project -p tsconfig.json --noEmit
tsc --root @home/ts-project -p tsconfig.json
```

The launcher strips `--root`, sets the project cwd, and grants the compiler a
separate READ-only `/.vibeos-tools` root. `node` commands do not automatically
receive this mount. Direct watch flags return an explicit unavailable status.

The target test demonstrates compiler version, cross-file project checking with
no emit, JS plus `.d.ts` generation, and execution of emitted JS returning 43.
Adding a string-to-number error produces `bad.ts(1,14): error TS2322` and a
nonzero exit. Test output markers are split in input expressions so command
echoes cannot count as execution evidence.

## Investigation retained

- Run 1 terminates while loading the compiler through the bounded C/C++ arena.
- Run 2 adds an allocator-limit diagnostic: 10,289,152 bytes used and an
  8,392,704-byte growth request exceed the original 16 MiB capacity.
- The opt-in toolkit configuration now uses a bounded 64 MiB process-lifetime
  libc arena. Ordinary `node-runtime` retains its 16 MiB capacity. This is TCB
  storage, not per-job reclaimed memory; final toolkit peak/lifecycle
  qualification remains outstanding.
- Run 3 prints the official compiler version, then the UART receives only 255
  bytes of an overlong harness command, losing its newline. The stalled QEMU
  test is explicitly terminated and its failure retained.
- Run 4 uses short command lines and guest helper scripts with the same ELF as
  run 3; all compiler checks pass.
- `with-tsx/` repeats all checks successfully on the exact production ELF used
  by `../tsx-qemu/run-4/`, including the completed esbuild/tsx adapters. Its
  source hashes remain unchanged throughout the test. The corresponding link
  inputs and toolkit manifest are retained with that tsx run.

## Reproduce

Prepare the pinned native runtime as documented in `docs/NODE_RUNTIME.md`, then:

```
python3 scripts/prepare-node-toolkit.py --offline --output target/node-runtime/toolkit-packed
python3 scripts/check-v8-firmware-link.py --gate --node --node-shell \
  --toolkit target/node-runtime/toolkit-packed \
  --source /PATH/TO/QUALIFIED_NODE_SOURCE \
  --uv-archive /PATH/TO/QUALIFIED_NODE_SOURCE/out/Release/obj.target/deps/uv/libuv.a \
  --work target/node-runtime/tsc-shell-link
python3 scripts/test-tsc-qemu.py --kernel target/node-runtime/tsc-shell-link/node-shell.elf \
  --work target/tsc-qemu
```

Use fresh output directories. The link report binds the executable to the
toolkit manifest and packed payload hashes. The qualified source must include
the current libuv external-readiness hook. Platform-adapted tsx/esbuild target
execution now passes in the sibling evidence directories; complete clean-build,
security/lifecycle and final regression qualification remain pending. This
does not close M3 or the overall goal.
