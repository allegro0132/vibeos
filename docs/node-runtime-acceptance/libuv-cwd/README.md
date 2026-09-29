# Invocation-local working directory

uv_cwd/uv_chdir use the native invocation's file table. Initial cwd is the
capability root, rendered as `/`. chdir resolves and checks a directory under
a fresh READ lease and stores its canonical root-relative path and inode ID.
Relative native paths join that cwd, including both unlink entrypoints; absolute
paths remain rooted in the granted tree. cwd retrieval and relative resolution
revalidate the directory identity. Renaming/deleting/replacing it cannot silently
redirect the cwd into a different same-named directory. Absolute chdir can recover.

QEMU passes initial root, short-buffer preservation and required-size reporting,
chdir into src, relative symlink stat, parent-relative open, relative create and
unlink with absolute-path verification, failed chdir preserving state, escape
rejection, renamed/replaced directory rejection and absolute-root recovery.
The existing revocation callback verifies cwd/chdir return EACCES while leaving
the output buffer and size untouched. Cumulative V8/libuv checks pass with
82 parks, zero waiters, normal shutdown and a 305729152-byte allocator peak.

This is not complete POSIX cwd emulation: a renamed cwd currently returns ENOENT
until absolute chdir, rather than finding its new path. Resolution still uses
RelPath lexical dot-dot normalization; symlink-plus-dot-dot POSIX semantics and
concurrent rename races are not qualified. Queued async path operations resolve
against cwd when their backend operation begins; chdir between submission and
execution is not qualified. Separate invocation isolation, tool-directory mounts,
Node process.cwd()/module loading and TypeScript execution remain pending.
