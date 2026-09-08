# CR-059 product scope review

Verdict: PASS

The proposal is a direct child of the protected base and changes exactly its
four declared change-control paths. Its manifest decodes to only
`scripts/ci_policy.py` and `tests/unit/test_ci_policy.py`; both decoded final
byte hashes match the manifest.

The amendment admits only `tree-sitter-go==0.25.0`,
`tree-sitter-javascript==0.25.0` and `tree-sitter-typescript==0.23.2`, while
retaining the historical minimal and current Python-only transition states.
The proposal does not alter active product code, package metadata, lockfile,
accepted specifications, gate evidence, workflows, hooks, branch protection or
secret behavior. Later P7.1/P7.2 metadata work remains separately constrained.

The committed-candidate validator passes. Exact scope, review subject, evidence
bundle and promotion subject verify. No product-scope blocker remains.

Reviewed proposal: `851dab01c8b44b9d5ece4665c6cad15f8524f4ce`.
Protected base: `7b1d2f46cdd46ed57c38f08847389cb6ad262dd0`.
Review subject: `d06840b6ed16dcb8aed6c2f5e412fc585915f7cd9ea73ce626da0ef689f2db98`.
Evidence bundle: `51e6e8d29452669f64683e1cb4be91479f13ff8b174dd81dafc3ede86fe2ce9b`.
Promotion subject: `7edfb9b5d1911f1d08659606eb0d5a6b68815869ce2d8aa4e5037f3235a1b2f1`.
