# CR-059 security/evaluation review

Verdict: PASS

Proposal `851dab01c8b44b9d5ece4665c6cad15f8524f4ce` is the direct child of
protected base `7b1d2f46cdd46ed57c38f08847389cb6ad262dd0`. Product review successor
`920da75658e75a7213072d23a06bd3c75b7603c2` and architecture review successor
`ba17cf23f31f5a97b70a2f1d5426965acfea477f` are consecutive single-parent
commits; both existing receipts validate with the same proposal identities.

The manifest decodes to exactly `scripts/ci_policy.py` and
`tests/unit/test_ci_policy.py`. Every current-base and final SHA-256 verifies,
and the length-framed promotion subject is
`7edfb9b5d1911f1d08659606eb0d5a6b68815869ce2d8aa4e5037f3235a1b2f1`.

The future evaluator permits exactly three ordered adapter dependency states:
Core-only, Python Tree-sitter, and the reviewed Go, JavaScript and TypeScript
grammar set. Partial, extra, reordered and version-drifted lists are rejected;
direct URL and non-PyPI source, artifact-hash, secret-scan and workflow controls
remain fail-closed. The amendment changes no lockfile, package metadata,
accepted specification, workflow, hook, source selection or secret baseline.

Promotion remains safe: it requires one direct-child promotion commit, exact
current-base/final target hashes, decoded-byte equality, a unique matching
manifest and all three separated PASS receipts. No security/evaluation blocker
remains.

Reviewed proposal: `851dab01c8b44b9d5ece4665c6cad15f8524f4ce`.
Protected base: `7b1d2f46cdd46ed57c38f08847389cb6ad262dd0`.
Review subject: `d06840b6ed16dcb8aed6c2f5e412fc585915f7cd9ea73ce626da0ef689f2db98`.
Evidence bundle: `51e6e8d29452669f64683e1cb4be91479f13ff8b174dd81dafc3ede86fe2ce9b`.
Promotion subject: `7edfb9b5d1911f1d08659606eb0d5a6b68815869ce2d8aa4e5037f3235a1b2f1`.
