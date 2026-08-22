# CR-042 architecture and contracts review

Verdict: PASS

The exact proposal identity and all declared hashes verify, including every
decoded manifest target. The policy catalog now remains the single authority
for P2.1 through P2.14 completion requirements; every task has the same ordered
five-class evidence tuple.

`completion_run_evidence_tasks()` removes the stale duplicate task authority,
derives protected-run membership only from the closed catalog and rejects an
unpaired external evidence type. Unknown tasks, duplicate or reordered evidence
and malformed policy continue to fail closed. The existing generic lifecycle
path applies unchanged repository authority, immutable run attempt, required
gate, exact PR merge bundle, implementation/head/post-merge ancestry and
protected-master push checks to the derived set. No schema, permission, secret
scanner, specification, runtime, product implementation or gate-evidence bytes
change. The focused membership/pairing test plus existing P2 lifecycle tests are
sufficient for this bounded widening. No architecture or contract blocker.
