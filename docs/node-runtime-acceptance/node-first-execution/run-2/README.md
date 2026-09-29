# Node execution after cppgc initialization fix

Removing the duplicate cppgc initialization allows Node bootstrap/JavaScript
loading to run. Execution then reports EACCES from process.cwd because the
embedding gate had no project FileGrant. Cleanup returns normally with code 1,
6 parks and zero waiters. This is a runtime failure, not Node acceptance.
The next fixture explicitly grants a private project tree to the invocation.
