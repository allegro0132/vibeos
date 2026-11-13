# Independent TCP throughput probe

Opt-in diagnostic component (`tcp-throughput-probe` kernel/Mars feature).
The image keeps iperf3 on 5201 for same-image comparison and adds four separate
capability-confined listeners on 5300–5303. One supervised task serves them
round-robin, with independent connection state. The default image is unchanged.

Each connection sends a 24-byte request: ASCII `VBENCH02` (or legacy `VBENCH01`), one mode byte
(0 = board receives, 1 = board sends), seven zero bytes, and an unsigned 64-bit
big-endian payload byte count (1..16 GiB). Mode 0 sends the requested payload
after the request; mode 1 receives that many bytes. The board then sends a
16-byte result: completed payload bytes followed by elapsed milliseconds,
both unsigned 64-bit big-endian, and closes after draining queued output.
V2 sends a one-byte `R` readiness response after parsing the header and waits
for a one-byte `G` before transferring payload. The host waits for all flows
to become ready, then releases their GO barrier and starts timing. V1 skips
this handshake and remains available with client `--protocol 1`.
Invalid requests, premature close and the 300-second connection deadline abort
the connection. Capability checks and stale-generation rejection remain in the
kernel adapter on every operation. A revoked listener terminates the component.

The probe does not share iperf3 parsing, control messages, or application state.
It does share the production TCP capability API and stack. Like iperf3, each
listener has 64 KiB frontend RX/TX buffers, calls transfer at most 32 KiB, and
uses a 1 ms / 64-attempt cooperative idle budget. Receive buffers persist for
the task lifetime instead of being reinitialized per poll. Source data is a
static 0xa5 pattern. Four idle listener polls and six stack sockets also cost
CPU, so compare with iperf3 in the same image and report the old-image baseline
separately. A four-flow result changes aggregate buffering and scheduling work;
it alone cannot distinguish TCP window limits from single-flow processing.

`python3 scripts/mars-tcp-probe.py --address ADDRESS --flows 1 4 --bytes N
--output NEW.json` tests both directions. `N` is **per flow**. Use N/4 in a
separate four-flow invocation to keep aggregate transferred bytes constant.
Use `--loopback` first to calibrate the host client. Output files are never
replaced and failure details are retained. This is a byte-count benchmark,
not a payload-integrity qualification.

Host time includes request startup. Sink time ends on board byte-count
confirmation, source time on the final payload byte received. Aggregate rates
use the earliest worker start and latest completion, not a sum of individual
rates. Board source elapsed time only reaches enqueue completion; it must not
be reported as receiver throughput. Sink board elapsed time begins on its
first successful application read and excludes pre-read buffering.

For source tests, output now also includes `payload_interval_receiver_mbps`:
it excludes each stream's first received chunk and uses the common wall-time
span from the earliest first-chunk timestamp to the latest final payload.
Startup delays and first-chunk bytes are still reported separately; end-to-end
rates remain unchanged. Sink host send timing is never labeled as receiver
payload timing. The protocol model shows why this matters: an exclusive
listener's pending socket may complete the next handshake while the previous
connection remains in TIME-WAIT, before the service can accept that successor.
This measurement split does not remove TCP waiting or raise network throughput.

V2 mode 2 is a verified sink: byte at absolute payload offset `i` must equal
`i % 251`. Verification spans receive calls and reports the usual completed
count only if every application-visible byte matches. A mismatch resets the
connection without a success result. V1 mode 2 is rejected. This checks the
receive path after GRO/TCP/frontend delivery; its extra work is not a throughput
benchmark. Modes 0 and 1 keep their existing behavior.

Run `python3 scripts/mars-tcp-verify.py --address ADDRESS --output NEW.json`
for a 64 MiB verified receive. `--corrupt-at OFFSET` deliberately injects one
invalid byte and expects a connection reset after admission; bracket that test
with successful valid transfers to exclude an unrelated connectivity failure.
