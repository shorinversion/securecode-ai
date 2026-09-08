# CR-059 architecture contracts review

Verdict: PASS

Proposal `851dab01c8b44b9d5ece4665c6cad15f8524f4ce` is a direct child of
protected base `7b1d2f46cdd46ed57c38f08847389cb6ad262dd0`. Product review successor
`920da75658e75a7213072d23a06bd3c75b7603c2` is its direct child, and its
receipt validates successfully.

The manifest independently decodes to exactly `scripts/ci_policy.py` and
`tests/unit/test_ci_policy.py`. Base and final hashes match, with promotion
subject `7edfb9b5d1911f1d08659606eb0d5a6b68815869ce2d8aa4e5037f3235a1b2f1`.

The policy preserves three closed adapter states: historical Core-only,
current Python Tree-sitter, and the future exact Go/JavaScript/TypeScript
grammar set. Partial additions, extra packages, reordered or version-drifted
dependencies remain rejected. This supports policy-first promotion without
invalidating the protected base or allowing the implementation candidate to
authorize itself.

The target adds no package metadata, lockfile, runtime dependency,
source-selection behavior or application capability. Existing
registry/source/hash enforcement remains unchanged and applies when the
separately constrained implementation adds the exact packages. Negative tests
cover all three grammar version drifts and an additional unreviewed grammar.

Evidence bundle and review subject independently recompute. No
architecture-contract blocker remains.
