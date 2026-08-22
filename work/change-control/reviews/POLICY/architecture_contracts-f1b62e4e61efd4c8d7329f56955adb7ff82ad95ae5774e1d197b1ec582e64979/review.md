# CR-044 architecture and contracts review

Verdict: PASS

The exact manifest contains one decoded target, `tests/unit/test_ci_policy.py`,
and its declared base and final hashes independently verify. No evaluator,
package metadata, lockfile, implementation, specification, workflow,
permission or gate-contract byte changes in this proposal.

The repaired regression is state-independent. It first replaces the adapter
dependency list with the exact legacy Core-only state and requires acceptance.
It then replaces the same list with the exact reviewed Core plus Tree-sitter
runtime plus Python grammar state and requires acceptance. Finally, it adds an
unreviewed JavaScript grammar and requires rejection.

Using slice replacement is important: the test no longer assumes which of the
two admitted dependency states exists in the checkout. It exercises the same
closed policy transition before and after P2.3 dependency installation without
changing production policy authority. The adapters-to-Core ownership edge,
third-party parser ownership in adapters, single-lock/source integrity checks,
and P2.3 Python-only boundary remain unchanged.

Reviewed proposal: `0faec83c6ec5b8e2eb0090916af858240edf1664`.
Review subject: `f1b62e4e61efd4c8d7329f56955adb7ff82ad95ae5774e1d197b1ec582e64979`.
Evidence bundle: `8443526cbc9f69824d07e1b684f76e7d6b7278c8b36605fccf004c5db8e211d3`.
Promotion subject: `6fbd78cbaf44f324013b6b61c126c8f2164ef72694db5e382e2d0de51ae2a9ba`.
