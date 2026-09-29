# Real Node observes parent capability revocation

After completing the normal project checks, JavaScript opens /main.cjs and
retains its descriptor. The native gate revokes the original parent-tree
capability, not a separately minted project-view capability. JavaScript then
tries both fs.readFileSync('/main.cjs') and fs.readSync on the previously opened
descriptor. Both must report EACCES. Closing the descriptor still succeeds.

QEMU passes both rejection checks, prior subtree isolation checks, exit event
0 and complete Node/native teardown. Native return=0, parks=208, waiters=0.
The parent's protected sibling bytes remain unchanged. This scenario is
explicitly selected by --node-revoke; it is independent of explicit-exit and
infinite-loop cancellation scenarios.

This qualifies new path reads and an existing descriptor's synchronous read
after revocation through project projection. It does not yet qualify every
in-flight asynchronous operation or the production VSH command path.
