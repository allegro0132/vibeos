# vtop

`vtop` is the built-in VSH resource monitor and service manager. Type `vtop`
at the UART `vsh>` prompt or in an authenticated SSH PTY shell. The legacy
`vibe>` shell also accepts it. No additional component or package is needed.

The dashboard uses a dark-terminal-friendly cyan/magenta palette, ASCII meters,
per-core readings, a 48-sample CPU history, and a service table. It refreshes
once per second. UART uses an 80 × 24 viewport; SSH follows PTY dimensions and
window changes. Small windows show a compact summary and a resize hint.

## Controls

| Key | Action |
| --- | --- |
| Up / Down, `k` / `j` | Select a service; scroll through pages |
| `c`, `m`, `n` | Sort by CPU, live memory, or name |
| `/` | Edit a case-insensitive service-name filter; Enter applies |
| `s`, `x`, `r` | Start, stop, or restart the selected service |
| `y`, `n` / Esc | Confirm or cancel a proposed operation |
| Space | Pause/resume the displayed readings |
| `?` | Show help |
| `q`, Ctrl-C / Ctrl-D | Leave and restore the cursor and shell |

Selection follows a service's name across sorting and refreshes. A confirmation
retains its exact generation: if another supervisor restarts the service before
you confirm, the operation fails rather than targeting the new instance.

Stopping is cooperative. A pending operation waits for the task's poll boundary,
with a five-second bound. `q` is temporarily disabled while an action is pending; press it again after
completion. Ctrl-C or Ctrl-D exits immediately and abandons further retries. If a restart has
already requested cancellation, that service may remain stopped; inspect its
state and use `s` to start it. No operation revokes capabilities merely to stop
a service. Starting a terminal instance uses its audited fresh-grant template.

## Commands and scripting

```text
vtop --once
vtop --help
vtop stop guest
vtop start guest
vtop restart guest
vtop --once | wc
```

`--once` takes two readings 200 ms apart and emits plain text without terminal
control sequences. A `vtop` invocation in a pipeline or script also produces a
plain snapshot. Only the standalone interactive `vtop` command enters the
alternate screen. Failed lifecycle operations return a nonzero job status and
a diagnostic. Command substitution cannot invoke vtop's privileged backend.

The installed VSH Command capability authorizes access. Snapshots and deferred
actions recheck it. Restricted SSH **exec** and password-onboarding sessions do
not receive vtop. Authenticated SSH **PTY shells** do. The system console and
components without audited restart templates are protected. SSH additionally
protects its network, SSH, and entropy dependencies; those operations require
the local console. The backend enforces this policy independently of the UI.

## Reading the numbers

- **CPU** is the fraction of each sampling interval spent outside `wfi` (the
  processor's wait-for-interrupt state), from the existing per-hart residency
  counters. The total is the mean of all online cores. Missing, newly active,
  or inconsistent samples display `--` and never imply zero usage.
- **Service CPU** is elapsed time in that service's completed task polls,
  including interrupts during the poll. One core equals 100%. This differs
  from total CPU residency, which also includes scheduler work, interrupt
  handling outside polls, and tasks not registered as supervised services.
- **POLL/s** is the interval rate of task polls, not a CPU estimate. Restarting
  changes generation and resets the rate baseline.
- **HEAP** shows live allocator bytes against the allocator's total managed
  capacity, not against all physical RAM. Peak is the allocator's high-water
  mark. Untouched means bump bytes never allocated; reusable freed blocks are
  not included in that number. The kernel image, reserved memory, and DMA
  regions outside the heap are not represented as free application memory.
- **LIVE / LIMIT** and the selected row's **peak / denied** values come from
  the component's enforced allocation account. An unlimited quota is shown
  explicitly. Faulted and exited records remain visible for diagnosis.

Sampling uses the existing `idle-profile` and `executor-profile` counters,
now enabled for kernel images. Timing adds clock reads and atomic updates to
the executor. vtop itself contributes to the observed load. It does not claim
to provide disk occupancy, network throughput, or per-service hardware-cycle
attribution.

## Verification

```sh
cargo test --locked --offline -p vibeos-vsh -p vibeos-sshd
cargo test --locked --offline -p vibeos-core --features idle-profile,executor-profile
python3 -B scripts/qemu-vtop-test.py
python3 -B scripts/qemu-vtop-ssh-test.py
```

The QEMU gate builds a normal VSH image, then boots one and four harts. It checks
real CPU intervals, stop/start/restart, console protection, raw-key filtering,
confirmation/cancellation, and prompt restoration after `q` and Ctrl-C. Logs
are saved under `target/vtop/`. Pass `--kernel PATH` to test an existing normal
QEMU image without rebuilding. Host tests cover missing/reset samples, generation
races, revoked command access, cancellation, bounded pending actions, terminal
injection, dimensions, and restricted profiles.

The SSH gate uses the explicit QEMU test identity, an ephemeral loopback-only
port forward, and a real OpenSSH PTY. It verifies refreshes, transport protection,
window changes, q/Ctrl-C restoration, and a fresh connection after exit. It
writes logs under `target/vtop/`; test private keys exist only in a temporary
directory. Pass `--kernel PATH` for an existing `ssh-test` image.
