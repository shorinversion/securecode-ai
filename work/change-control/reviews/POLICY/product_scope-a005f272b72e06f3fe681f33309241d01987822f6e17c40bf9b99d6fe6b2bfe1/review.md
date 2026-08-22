# CR-043 product scope review

Verdict: PASS

Exact proposal commit, review subject, evidence bundle, promotion subject and
both decoded target hashes independently verify. The amendment admits only
`tree-sitter>=0.25,<0.26` and `tree-sitter-python>=0.25,<0.26` beside the exact
Core dependency in the adapters package.

This matches the accepted P2.3 Python CST and location-stable symbol-index
scope. JavaScript, TypeScript and Go parsers remain outside P2.3, and no
accepted specification, package, lockfile, workflow, gate criterion or product
implementation changes in this proposal.

The policy transition remains closed to exactly two adapter dependency sets:
the current Core-only state and the reviewed Core-plus-two-Tree-sitter state.
Every other dependency, alternate source and metadata drift remains rejected,
so policy-first delivery enables the later atomic P2.3 package/lock update
without bypass or broader dependency authority. No product scope,
traceability, transition-completeness or unintended-expansion finding.
