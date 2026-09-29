QEMU passes capability-rooted stat, lstat and realpath: root directory stat,
symlink identity vs target identity, canonical /main.js within the admitted
root, symlink-based open/read, traversal denial and ELOOP on a circular link.
The same image passes prior descriptor/stdio/timer checks and the real V8 gate.
No host filesystem or host JavaScript execution participates.

The new FileTreeRoot::resolved_regular_reader pins metadata and bytes from one
namespace generation while admitting root-contained links. Existing callers of
regular_reader retain their link-rejecting behavior. A new host test changes
the target after opening through a link and verifies the old metadata AND old
bytes remain pinned. The complete file-store lib test run passes 29 tests with
5 existing ignored tests. The ignored tests are not claimed as passed.

Path stat/realpath use resident capability-backed snapshots. Libuv callback
forms use its native completion queue; current path assertions are synchronous.
Metadata type/size/identity/link count/generation are real FileTreeRoot values;
POSIX timestamps/ownership are unavailable (zero) and mode bits describe this
read-only adapter. Canonical absolute paths belong solely to the admitted root,
not the kernel namespace. The fixture is volatile; durable symlink IO, async
regular-file data, path mutation races, full POSIX path semantics, cwd/tool
mount separation and actual Node module resolution remain unqualified.
