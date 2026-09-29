# Native Node over authenticated SSH VSH

The remote command set already registered Node, but lacked a project-root
capability. A new default-empty platform hook installs project roots only for
non-onboarding interactive shells. The kernel revalidates the existing command
profile policy (live production command profile or explicit test profile 1,
generation 1). It shares the storage service's already recovered home tree;
it neither opens an ambient host path nor recovers an independent writer.
The default hook grants nothing and unrelated images do not expose this root.

Run 1 (link 66) authenticates successfully but VSH rejects the root because the
session lacks GRANT. The correction grants READ|WRITE|GRANT at the session,
which is necessary for VSH to derive per-command capabilities. Stages receive
only requested READ/WRITE rights, and the session gets no REVOKE right.
No authorization bypass was added to the command planner.

Twenty existing SSHD host tests pass. A sandbox-only preflight could not bind a
loopback port; the real QEMU/OpenSSH run uses an authorized localhost-only
forward. Fixture private keys remain in ignored target directories and are not
part of committed evidence. SSH exec has a separate restricted policy; these
cases explicitly exercise the authenticated interactive SSH/VSH interface.

Run 2 (link 67) passes setup, eval, stdin pipe and exact exit 7, but the harness
waits for live output from an infinite command. Existing SSH/VSH intentionally
captures bounded output until execute_cancellable finishes; the wait therefore
times out. This is a harness assumption failure, not evidence of failed Node
cancellation (no Ctrl-C was sent in that run).

Run 3 uses the same image and preserves SSH/VSH's existing capture semantics.
It starts an infinite eval after writing cpu-entered into the project, sends
real PTY Ctrl-C, observes the Cancelled report, then runs a fresh Node instance
that verifies cpu-entered and prints AFTER_CANCEL=ok. All setup/eval/pipe/exit7/
cancellation/restart checks pass, no fatal error, host wall time 10.615 seconds.
This qualifies the authorized interactive SSH/VSH path; restricted SSH exec
and changes to the existing buffered-output policy are not claimed.
