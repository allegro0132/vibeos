# Independent read-only native tool mount

The native invocation can now receive a separate tool `FileGrant`. The TLS
installation attenuates it to READ while preserving its original lease provider
and revocation lineage. The mounted namespace is `/.vibeos-tools`; descriptors
retain the selected grant instead of falling back to the project grant.
Metadata, open, access, directory enumeration, readlink, realpath and cwd resolve
against the selected root. Project mutation paths reject the mounted namespace.
Node's supervisor accepts an optional tool grant and monitors its revocation
alongside the project grant.

`run-3/` passes the full native C++ ABI QEMU suite and the additional mount probe:
tool reads, denied write/create/truncate/append opens and unlink, mounted cwd and
relative reads, canonical alias paths, outward-symlink denial, independent project
creation and denial of reads through an already-open descriptor after revocation.
This run does not enable the optional entropy probe.

`run-1/` failed during fixture construction because creating an outward symlink
at the storage root is already forbidden. The corrected fixture creates the
link inside a tool subdirectory before projecting that directory. `run-2/`
then exposed a fixture-only byte-count typo (the 13-byte payload was expected to
be 12 bytes); the assertion now derives the length from the payload.

The production `node` command still supplies no tool mount. Official toolkit
loading and `tsc`/`tsx` command registration remain pending. Root listing does
not yet synthesize the tool mount entry, and cross-mount copy/rename/link are
not admitted. This evidence establishes native file-bridge behavior, not
official TypeScript or tsx target execution or the complete M4 audit.

`node-vsh/` passes the existing production Node console suite after the routing
change: eval, CJS/ESM, files, pipeline stdin, timer, redirection, exit 7,
exception location, CPU/idle cancellation and successful relaunch.
