# Project execution: asynchronous creation unavailable

Real Node loads the cross-file CJS project and performs sync file write/read.
The dynamic ESM import (including its dependency) and async file read resolve;
the callback checks their values before attempting fs.promises.writeFile.
That write fails ENOTSUP because libuv asynchronous O_CREAT/O_TRUNC opens were
still excluded. Node returns 1 with normal cleanup and zero waiters. The failed
verifier is retained; this is not project acceptance.
