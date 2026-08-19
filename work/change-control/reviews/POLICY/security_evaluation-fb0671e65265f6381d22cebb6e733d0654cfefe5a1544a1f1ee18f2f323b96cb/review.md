# CR-019 security and evaluation review

Reviewer: Goodall, an internal Codex AI reviewer.

Verdict: PASS.

The amendment fails closed across the GitHub synthetic-merge boundary. It
rejects missing or malformed identities, checkout substitution, unexpected
parent count or ordering, divergent merge-only bytes, nonlinear head history,
and event-mode confusion. The logical head is used only after exact binding to
the checked synthetic commit.

The tests cover the confused-deputy boundary directly: an unauthorized
multi-commit candidate is rejected, an inserted commit invalidates an otherwise
valid promotion chain, the complete POLICY lifecycle is accepted only through
the protected path, and push or merge-group events reject pull-request head
authority. No fail-open or persistent bypass path was identified.

Reviewed proposal: 5bcece191afca13302460de470a0660a86d84efb.
Review subject: fb0671e65265f6381d22cebb6e733d0654cfefe5a1544a1f1ee18f2f323b96cb.
Evidence bundle: 667b464e2ea2bf51299662d2d6dd81364062c67e3c7314582f8d3cab6468c861.
Promotion subject: 7f2d3b2db99965dc237e5c6a3562bfc9fe50207eea37c5ec4018ec80d5d06930.
