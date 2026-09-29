# Explicit process.exit(7): first target check

The project, stdin and async runtime checks complete, and teardown returns to Rust
with zero waiters. The verifier fails because the test requires termination to
reach the embedding TryCatch. Native return is 1 (test failure), not accepted as
Node exit-code propagation. Run 2 adds diagnostics to identify that condition.
