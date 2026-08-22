# CR-044 product scope review

Verdict: PASS

Exact proposal commit, review subject, evidence bundle, promotion subject and
the decoded target hash independently verify. The sole promoted target is the
focused CR-043 CI-policy self-test; evaluator and product implementation bytes
are unchanged.

The repaired test explicitly constructs and accepts both closed P2.3
transition states: the legacy exact Core-only adapter dependency list and the
reviewed Core-plus-Tree-sitter-runtime-plus-Python-grammar list. It then adds an
unreviewed JavaScript grammar and requires rejection. This removes dependence
on whichever admitted state the workspace currently uses without changing the
dependency policy or authorizing another language.

The proposal changes no specification, package metadata, lockfile, workflow,
permission, gate criterion or P2.3 product boundary. No product scope,
traceability, transition-coverage or unintended-expansion finding.
