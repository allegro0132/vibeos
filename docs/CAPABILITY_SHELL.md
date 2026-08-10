# Capability-native shell contract

This document freezes the S0 contract for `vsh`, VibeOS's capability-native
shell. It is a design and acceptance specification, not an implementation
status claim. S1 and later work may refine internal representation, but changing
the observable semantics or security invariants below requires an explicit
revision of this document.

`vsh` borrows Bash's interactive composition syntax. It does not emulate Bash's
POSIX process, file-descriptor, pathname, signal, or ambient-environment model.

Normative terms such as **MUST**, **MUST NOT**, and **SHOULD** describe required
behaviour.

## 1. Goals and non-goals

### Goals

- Familiar quoting, pipelines, redirection, conditional lists, and background
  jobs.
- Every resource access remains capability-mediated and names the required
  rights.
- Every pipeline stage has an independent CSpace, allocation budget, task
  identity, and terminal report.
- Bounded buffering and real backpressure rather than unbounded byte capture.
- Deterministic cancellation, stream closure, and failure propagation.
- A pure, host-testable parser and planner whose output contains no live object
  pointers.

### Non-goals for v0.1

- Bash source or bug compatibility.
- POSIX processes, `fork`, `exec`, signals, process groups, sessions, or job
  stop/resume.
- File descriptors, `PATH`, a current working directory, pathname lookup, or a
  global command namespace.
- Globbing, `eval`, `source`, aliases, heredocs, or traps.
- Loading arbitrary ELF or treating in-tree applets as untrusted code.
- Persisting a live Job, its CSpaces, streams, or task state.

An eventual WASM or verified-bytecode command format is a separate confinement
milestone. v0.1 command implementations are audited, safe-Rust, in-tree
components and therefore remain in the trusted build.

## 2. Terms and trust boundary

- **Session**: one interactive `vsh` component and its local bindings.
- **Command**: an invokable `Command` resource with a manifest and a trusted
  factory.
- **Job**: one submitted command list tracked by a session-local `JobId`.
- **Stage**: one command invocation inside a Job. Each stage owns one supervised
  task, CSpace, and memory account.
- **Pipe**: one bounded, single-writer/single-reader byte-stream edge between
  adjacent stages.
- **Value binding**: a session-local UTF-8 string addressed as `$name`.
- **Capability binding**: a session-local reference to an existing CSpace slot,
  addressed as `@name`.
- **Special form**: syntax evaluated by the shell because it changes shell
  state, such as `let`, `jobs`, `wait`, `cancel`, and `run-script`. It is not a
  pipeline command.

The parser and planner are trusted input-processing code but receive no implicit
device or store references. Command implementations remain in the TCB for v0.1.
Generated or third-party code does not become a `Command` merely because it has
the right function signature.

The interactive shell MUST move out of the current `init` CSpace before it can
claim least-authority Job execution. Boot policy MUST create a dedicated shell
CSpace and grant only:

1. the commands visible in that session;
2. the resources intentionally exposed to the operator;
3. `GRANT` only on capabilities the shell may delegate to a stage; and
4. the CSpace/task control authority needed to supervise its own Jobs.

`init` retains the system roots. A parser or applet bug must not inherit them
merely because the shell is interactive.

## 3. Surface language

### 3.1 Grammar

The v0.1 grammar is intentionally small. Newlines and `;` terminate lists.

```text
input        := list? EOF
list         := and_or ((";" | "&") and_or)* (";" | "&")?
and_or       := pipeline (("&&" | "||") pipeline)*
pipeline     := command ("|" command)*
command      := WORD command_part*
command_part := WORD | VALUE_REF | CAP_REF | redirect
redirect     := ("<" | ">" | "2>") CAP_REF
VALUE_REF    := "$" NAME | "${" NAME "}"
CAP_REF      := "@" NAME
NAME         := [A-Za-z_][A-Za-z0-9_-]*
```

S1--S4 implement this base grammar. S5 adds the bounded scripting forms in
Section 3.6 without changing capability-reference tokenization.

### 3.2 Quoting and expansion

- Unquoted and double-quoted `$name`/`${name}` expand value bindings.
- Single quotes suppress all expansion.
- Backslash quotes the next byte outside single quotes and the documented
  escapable bytes inside double quotes.
- Expansion produces exactly one argument. v0.1 has no field splitting.
- Expansion output is never re-lexed and never interpreted as an operator or a
  capability reference.
- A capability reference is created only from a syntactic, unquoted `@name`
  token in command-argument or redirection position.
- Capability references are opaque AST nodes. They MUST NOT be converted to a
  slot/generation string, placed in a value variable, printed as an authority
  token, or reconstructed from text.

For example, if `$x` contains `@console`, `echo $x` prints the literal text
`@console`; it does not acquire console authority.

### 3.3 Command and capability name resolution

Bare command names resolve only in the session's bounded local command table.
That table maps a display name to a `Command` capability already present in the
shell CSpace. There is no global registry and no `PATH` search.

`@name` resolves only in the session's bounded local capability table. A label
is a UI convenience, not an object identity or authority source. Removing or
shadowing a label does not revoke an already-derived capability. Revocation is
an explicit capability operation.

Special forms are recognized before command-table lookup and may appear only as
a single foreground command. A special form in a pipeline or background list is
rejected during planning; it cannot accidentally mutate a temporary child scope
or race the interactive session state.

An external compiled artifact is invoked through an explicit command such as
`run @program`; it is not made executable by typing its label as a bare word.

### 3.4 Redirection

Redirection targets are capabilities, never pathnames:

```sh
echo "hello" > @console
producer 2> @diagnostics | consumer
```

`<` requires a recognized byte-source resource with `READ` or `RECV`, according
to its resource kind. `>` and `2>` require a recognized byte-sink resource with
`WRITE` or `SEND`. The planner MUST reject an unsupported resource kind before
starting any stage.

The console may have a trusted byte-sink adapter. Durable object creation is
transactional and is not generic redirection in v0.1; it remains an explicit
applet such as `store-write @store`, with a manifest that names the required
Store authority. Reading an object likewise explicitly names both Store and
StoredObject capabilities.

### 3.5 Lists, pipelines, and background jobs

- `a ; b` runs `b` after `a` reaches a terminal state.
- `a && b` runs `b` only when `a` succeeds.
- `a || b` runs `b` only when `a` does not succeed.
- `a | b` starts both stages before waiting for either and connects only `a`'s
  stdout to `b`'s stdin.
- `a & b` admits `a` as a background Job and then evaluates `b`; a trailing `&`
  returns the prompt after the Job has been admitted and all initial stages
  have been spawned. Neither form forks the shell.
- Foreground Ctrl-C cancels the foreground Job. Ctrl-C at an empty prompt only
  clears the input line.

Pipeline status uses mandatory `pipefail`: success requires every stage to
succeed. On multiple ordinary failures, the rightmost non-success status is the
reported status. A fault, denial, budget exhaustion, or explicit cancellation
initiates fail-fast teardown of the remaining stages and takes precedence over
ordinary returned statuses.

The final report is aggregated after all stage joins, so scheduling order cannot
change it. Severity is `Faulted`, `BudgetExceeded`, `Denied`, `Cancelled`, then
ordinary non-success; the rightmost stage wins within one severity. A stage fault
therefore wins over a racing cancellation, matching the executor's lifecycle
rule.

`jobs`, `wait %N`, and `cancel %N` use session-local, monotonically allocated
Job IDs. IDs MUST NOT be silently reused during a session.

### 3.6 Bounded scripting extension (S5)

S5 adds these forms:

```text
if AND_OR ; then SCRIPT (else SCRIPT)? fi
while AND_OR ; do SCRIPT done
function NAME NAME* { SCRIPT }
$(SCRIPT)
run-script @SCRIPT
```

- `if` and `while` conditions use typed command status. A fault, denial,
  cancellation, or budget failure is propagated rather than treated as false.
- `while` is capped at 256 completed iterations and yields after each body.
- Functions are foreground-only and cannot be pipeline stages in S5. Parameters
  are value-only, calls are capped at 32 nested frames, and definitions cannot
  shadow commands or special forms.
- A function stores syntax and parameter names, never a resolved capability.
  Any syntactic `@name` is resolved from the current permitted capability set
  at invocation, so function definition is not capability capture.
- Command substitution executes in an isolated value/function scope, rejects
  background Jobs, is capped at eight nested substitutions and 64 KiB of
  captured output, and removes trailing newlines. Its result remains one value
  argument and is never re-lexed.
- `run-script` accepts one explicit READ capability to an immutable
  `ScriptArtifact`. Artifacts are capped at 64 KiB and bind parsed source to an
  exact ABI-1 authority manifest. Missing, extra, wrong-kind, or over-righted
  manifest entries fail before execution.
- Artifact value and function bindings are local to the invocation. An artifact
  can use only syntactic capability labels present in its manifest; nested
  script calls are capped at eight, and an inner artifact's requirements must
  be a subset of its caller's allowed capability labels.

## 4. Command and authority model

### 4.1 Invocation right

S2 MUST add a volatile `INVOKE` right for `Command` resources. The shell holds
`INVOKE|GRANT` on commands it may delegate; a stage receives `INVOKE` without
`GRANT` or `REVOKE`.

The durable v1 rights mask remains unchanged. `INVOKE` MUST NOT be encoded in a
v1 durable grant. Persisting invokable Command capabilities requires a future
durable-format version; persisted program artifacts continue to use `READ` plus
the trusted loader admission path.

### 4.2 Command manifest

Every Command has an immutable manifest containing at least:

```text
name and ABI version
minimum and maximum argument count
accepted value/capability argument positions
resource kind and exact required rights for every capability argument
stdin/stdout/stderr mode: required, optional, or closed
memory-budget request and supervisor ceiling
cooperative-work budget or yield interval
whether early downstream close is a successful outcome
```

The manifest is descriptive policy, not a source of authority. The planner
intersects its requested rights with the rights held by the shell and rejects
missing `GRANT`, wrong resource kinds, or amplification before spawning tasks.

### 4.3 Stage CSpace

A stage CSpace contains only:

- its Command cap with `INVOKE`;
- stdin with `RECV`, when present;
- stdout and stderr with `SEND`, when present;
- explicitly referenced resource caps attenuated to manifest rights; and
- supervisor-private lifecycle metadata that is not exposed as a stage cap.

Stage resource caps do not carry `GRANT` or `REVOKE` unless a future manifest
kind explicitly describes delegation and receives separate security review.
No v0.1 applet may delegate authority.

Every stdout/stderr path is additionally guarded by the live Job state and uses
a revocable operation token. Output resources MUST NOT be handed to a stage as
raw invocation leases. This is how step 1 of teardown prevents output from being
published while an unrelated input or memory lease is still completing.

Arguments contain either owned strings or stage-local capability handles. Raw
handles from the shell CSpace MUST NOT be copied into the stage invocation.

### 4.4 Persistent capability delegation

The existing generic `grant` correctly refuses persistent capability nodes.
The shell MUST NOT bypass that rule.

When a Job needs a durable resource, a trusted broker may create an ephemeral,
non-grantable proxy whose private state contains a revocable token resolved from
the persistent parent. Each proxy operation revalidates that token and enforces
the attenuated operation rights. Parent revocation therefore denies the next
operation, while stage teardown revokes the proxy itself.

The broker MUST NOT expose the underlying object pointer or synthesize a new
durable derivation. Operations that require an invocation lease must declare
that fact in their manifest; as elsewhere in VibeOS, revocation cannot
retroactively invalidate an already-acquired raw lease.

## 5. Planning and admission transaction

The parser produces syntax only. Planning resolves names and prepares an
immutable `JobPlan` with no side effects. Admission follows this order:

1. Parse and expand bounded value arguments.
2. Resolve every command and capability label in the shell CSpace.
3. Validate every command manifest, resource kind, right, and policy ceiling.
4. Allocate all stage CSpaces, stream endpoints, memory accounts, and task
   envelopes as unpublished candidates.
5. Grant attenuated ephemeral capabilities and install persistent proxies into
   the candidate spaces.
6. If any step fails, revoke and reclaim all candidates; no applet has run.
7. Publish the complete Job record.
8. Spawn all stages, then make the foreground/background transition visible.

No stage may begin before the complete pipeline passes steps 1--6. This prevents
an early stage from producing external side effects before a later unknown
command or unauthorized redirection is discovered.

Planning is not transactional with respect to external state changes: authority
may be revoked after validation. Every operation must therefore still validate
its live token when performed.

## 6. Byte-stream contract

Pipes use a dedicated closeable resource rather than treating the current
`Endpoint<T>::send`, which waits forever unless a receiver consumes an item, as
a complete stream protocol.

The logical interface is:

```text
send(bytes) -> sent | closed(reason)
recv()      -> data(bytes) | end | closed(reason)
close_write(normal | failed(status) | cancelled)
close_read(normal | failed(status) | cancelled)
```

Required semantics:

- Each pipeline edge has exactly one writer and one reader in v0.1.
- Data chunks are non-empty and no larger than `MAX_STREAM_CHUNK_BYTES`.
- A full queue applies async backpressure without spinning.
- Normal writer close lets the reader drain already-buffered data and then
  observe `end`.
- Failed or cancelled writer close discards buffered data and wakes the reader
  with the close reason.
- Reader close discards buffered data and wakes a blocked or future writer with
  the close reason.
- Close is idempotent. The first non-normal terminal reason is retained.
- Drop is not the protocol. The supervisor owns an out-of-band close handle so
  a faulted stage that does not run destructors cannot strand its peer.
- Wait registrations must be released on normal completion, close,
  cancellation, and fault-arena reclamation.

A downstream applet such as `head` may close its input normally after producing
its requested result. An upstream applet whose manifest permits early
downstream close treats that close as success rather than as a fault.

stdin, stdout, and stderr are distinct capabilities. `|` connects stdout only;
stderr continues to its inherited sink unless `2>` explicitly redirects it.

## 7. Lifecycle, cancellation, and faults

Job state is monotonic:

```text
Preparing -> Running -> Completing -> Exited
                    \-> Cancelling -> Cancelled
                    \-> Failing    -> Failed
```

Once cancellation or failure wins the terminal claim, no new stage, grant,
proxy, or stream write may be published for that Job.

Teardown order is normative:

1. Atomically claim `Cancelling` or `Failing` and reject new Job activity.
2. Close every pipe through the supervisor handles, waking both directions.
3. Administratively `revoke_all` every ephemeral stage CSpace, blocking later
   lookups and invalidating revocable tokens.
4. Request cooperative cancellation for every non-terminal stage task.
5. Join all stages and retain their exact exit/fault/cancel reports.
6. Reclaim audited arenas, CSpaces, streams, proxies, and Job-owned metadata.
7. Publish the immutable terminal Job report and wake `wait` callers.

An active invocation lease may complete after step 3. It cannot publish new Job
output after the Job terminal claim, and teardown does not report completion
until all such stage tasks have returned or faulted.

Cancellation is still not preemption. Every in-tree applet loop MUST yield at a
reviewed bound and SHOULD also consume an operation budget. A trusted applet
that never yields can wedge its executor hart; S0 does not claim otherwise.

The shell task is never a member of the foreground Job and cannot cancel itself.
A shell panic remains a shell component fault, while an applet panic is confined
to that stage and triggers Job failure.

## 8. Status and diagnostics

Internally, status is typed rather than inferred from an integer:

```text
Success
Returned(nonzero code)
Usage
Unavailable
Denied
BudgetExceeded
Faulted
Cancelled
```

`&&` proceeds only on `Success`; `||` proceeds on every other terminal status.
The textual shell may render a stable numeric compatibility code, but security
and lifecycle decisions MUST use the typed status.

Parse and plan errors include a byte span and occur before Job publication.
Runtime diagnostics identify the Job and stage, but MUST NOT print raw capability
slot/generation pairs, object pointers, or authority-bearing serialized values.
Resource display names are non-authoritative hints.

## 9. Mandatory bounds

The following initial limits are part of the v0.1 policy. Implementations may
reject smaller inputs under memory pressure but MUST NOT silently exceed them.

| Limit | v0.1 value |
|---|---:|
| Interactive input line | 4 KiB |
| Script source | 64 KiB |
| Lexer tokens | 256 |
| AST nodes | 512 |
| Parser nesting | 32 |
| Pipeline stages | 16 |
| Arguments per stage | 128 |
| Expanded argument bytes per stage | 16 KiB |
| Session value bindings | 128 |
| One value binding | 4 KiB |
| Session capability bindings | 256 |
| Visible commands | 128 |
| Live Jobs per session | 32 |
| Total live stages per session | 64 |
| Stream chunk | 1 KiB |
| Buffered chunks per pipe | 8 |
| Future captured command output | 64 KiB |
| Stored script source | 64 KiB |
| Functions per session | 64 |
| Function call depth | 32 |
| Completed iterations per `while` | 256 |
| Command-substitution depth | 8 |
| Nested script-artifact calls | 8 |

Command manifests declare stage memory needs; boot policy supplies the ceiling.
The initial default applet budget is 256 KiB and no stage may receive more than
2 MiB without an explicit command-specific policy entry. Transactional store
applets may request a separately reviewed larger ceiling rather than inheriting
the shell's current 8 MiB budget.

The TTY MUST enforce the line limit while typing, before growing shared SYSTEM
storage. Expansion, planning, and diagnostics must use checked arithmetic and
must fail before partial Job publication.

## 10. Security invariants

S1 and later tests must preserve all of these:

1. Parsing and expansion never mint, widen, or discover authority.
2. Text produced by expansion is never reparsed as syntax or a capability.
3. A stage receives no capability absent from its manifest and command line.
4. Every granted right is a subset of both the manifest request and the
   shell-held source right.
5. Stage caps are non-delegable by default.
6. A failed admission executes no applet and publishes no partial Job.
7. Parent revocation denies the next proxy or revocable operation.
8. Job cancellation prevents new output publication and eventually releases
   all wait registrations and reclaimable memory, assuming stages yield.
9. Stream capacity, argv, expansion, scripts, jobs, and nesting are bounded.
10. Capability identities, object pointers, and executable entry addresses are
    never accepted from or serialized into shell text.
11. Bare command names resolve only through the session-local command table.
12. Persistent capability delegation never bypasses the durable lifecycle.

## 11. S0 acceptance and downstream gates

S0 is complete when this document is reviewed as the normative contract and the
Roadmap links to it. No runtime claim is implied until later gates pass.

S1 must deliver the bounded pure parser, AST, diagnostics, unit tests, and fuzz
target for Sections 3 and 9.

S2 must deliver `INVOKE`, Command manifests, closeable byte streams, persistent
proxies, and host tests for Sections 4 and 6.

S3 must deliver candidate admission, dynamic stage CSpaces, Job supervision,
cancel/join/fault teardown, and model/QEMU tests for Sections 5 and 7.

S4 must deliver the first safe-Rust applets and the vertical acceptance command:

```sh
echo hello | wc > @console
```

That command must prove parsing, complete-pipeline admission, two concurrent
stages, attenuated stdio caps, bounded backpressure, join, typed status, and
terminal cleanup. Negative acceptance must additionally show that an unknown
later command, a forged textual `@name`, a wrong resource kind, missing `GRANT`,
mid-pipeline revocation, stage fault, and Ctrl-C all fail closed while the shell
survives.

S5 delivers the Section 3.6 scripting extension. Host acceptance must cover AST
shape and malformed terminators, local function/value scope, recursion and loop
budgets, command-substitution isolation and failure, exact script manifests,
authority revocation after function definition, and script bindings that do not
escape an artifact invocation. QEMU acceptance exercises `if`, `while`, a
function call, and command substitution through the real console path.
