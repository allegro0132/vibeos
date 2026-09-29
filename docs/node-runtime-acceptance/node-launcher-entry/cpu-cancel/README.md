# CPU cancellation through the launcher ABI

The eval fixture runs the full project checks, then enters an infinite loop in
a timer callback. The loop emits a single marker from inside its body. Only
after the same-hart stdout consumer recognizes the entire marker does it arm
the cancellation peer (10 ms delay). The verifier requires the marker, peer,
exit 130, normal cleanup, zero waiters, and absence of finally/return markers.
This rules out cancellation during bootstrap or before reaching the loop.

Run 1 (link 59) reaches all project checks and the loop, receives cancellation,
then exits fatally with status 1 instead of returning through the launcher.
The native backtrace reaches newlib exit, with frame-pointer loss in newlib;
it does not alone identify its Node caller. Node source inspection shows that
RunTimers retries empty callbacks while can_call_into_js remains true and that
InternalCallbackScope must mark stopping before async-id-stack cleanup after
V8 termination. AsyncHooks corruption has a direct process Exit(1) path.

Patch 0057 makes VibeOS can_call_into_js reject a cancelled grant and makes
InternalCallbackScope's stopping check stop the environment before async-hooks
cleanup. It does not recover by jumping over C++ frames or suppress fatal exit.
The embedder still performs normal Stop/FreeEnvironment after uv_run returns.
The patch applies to pristine pinned Node source with zero fuzz.

Run 2 (link 60) with patch 0057 passes all checks: entered loop, same-hart
cancellation, normal teardown, native return 130, 231 parks, zero waiters,
no fatal exit and no finally/return marker. The protected outside file remains
unchanged. This qualifies timer-callback CPU cancellation through the actual
launcher ABI; it does not yet qualify production VSH cancellation.
