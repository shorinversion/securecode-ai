# CR-053 security and evaluation review

Reviewer identity: codex-luna-security-cr053

Verdict: PASS.

The exact proposal commit `364604a67466af78920ce16e8c4ed2e4a21e61fb` was
reviewed against starting commit `3aec841ed5331dfbb67ce3aab99acc2a3d7f999a`.
The decoded amendment manifest contains only the declared targets
`scripts/spec_gate.py` and `tests/unit/test_spec_gate.py`; both manifest base
SHA-256 values match the starting commit and both final SHA-256 values match
the decoded bytes.

The implementation changes only the integrated-gate promotion-base lookup:
candidate documents are selected when the path is present, and the protected
base is read only for an absent candidate path. This removes the eager
evaluation of the fallback read for first-time gate evidence. The surrounding
controls still require the immutable base decision check, exact packet and
allowed-path binding, budgets, required evidence, review-subject hash,
GO-PROPOSED decision, promotion-manifest validation, completed-plan
derivation, promotion hash, and the existing sequential review/promotion
chain. The candidate document set is still restricted to changed paths, and
`docs/PLAN.md` remains rejected as an early candidate change, so the fix does
not create a missing-path fail-open, protection weakening, or scope-laundering
route.

The added unit regression specifically proves candidate-first selection for
the gate decision while asserting that base fallback is used only for the
unchanged plan path. No tests were run, per the review assignment.

Reviewed proposal commit: `364604a67466af78920ce16e8c4ed2e4a21e61fb`.
Review subject SHA-256: `4094b2767ca18713764aa3a9407814fc03022cafeb4bffb9b20b8c949ad55b34`.
Promotion subject SHA-256: `f4d06668f6323987d9eb23b53eaa8172bb30de9a991a833c20c097d2c737b826`.
