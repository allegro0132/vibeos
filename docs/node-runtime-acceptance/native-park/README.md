# Native executor parking prerequisite

The LP64D `native-cxx-probe` firmware runs the real C++ RAII fixture on a
protected stack inside a BOOT-hart-pinned executor task. Each of three yields
awaits the executor's 10 ms timer. A second task, pinned to that same hart,
must advance during every wait. This establishes that suspended native frames
do not keep the scheduler busy-waiting. C++ destructors remain pending until
normal return, then run exactly once. The stack is unmapped and freed; the peer
task is joined. Four-hart identity and VSH echo checks also pass.

ParkProbe's destructor can drain only this known, finite, three-yield fixture.
That cleanup is not offered as cancellation for arbitrary V8/Node code.
General predicate waits, cancellation/termination, the static C++ runtime and
real V8 execution remain separate requirements. This is not a milestone pass.
