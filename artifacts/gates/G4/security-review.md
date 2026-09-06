# G4 security boundary evidence

result: PASS

- Source, propagation and SQL sink evidence are identity- and revision-bound.
- The safe control produces no signal, confirmed finding or patch candidate.
- Patch application and validation occur only in an ephemeral workspace; the
  original fixture hashes remain unchanged before and after the run.
- Sandbox execution is profile-attested, budgeted, network-free and always
  records teardown; driver, resource and teardown failures fail closed.
- Refusal, incomplete validation, stale heads and invalid output cannot become
  a validated candidate or product PASS.
- CLI and report receipts remain deterministic, escaped and source-free.

This is integrated gate evidence, not an independent review. Per the effective
methodology, independent product, architecture and security/evaluation review
is deferred to the single post-G9 cycle.
