# Seventh Node firmware link

The real firmware link still fails with 107 missing symbols.
The explicit excluded-operation backend resolves 11 names since run 6;
these are unsupported-operation errors, not successful process/watch/signal
implementations. Node-side constructors reject before CHECKs or uninitialized
handle cleanup. The target Node archive and updated embedding probe compile;
none of the JS probe assertions has run. Input identities and diagnostics are
retained; full Node/TypeScript acceptance remains pending.
