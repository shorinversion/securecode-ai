# CR-019 architecture and contracts review

Reviewer: Fermat, an internal Codex AI reviewer.

Verdict: PASS.

The dual-authority contract is coherent. The synthetic GitHub SHA remains the
checked commit and must have the exact ordered base and head parents. Its tree
must equal the event-owned head tree before lifecycle validation is dispatched
on the logical head. The full base-to-head history must be an uninterrupted
single-parent chain.

Ordinary one-commit candidates retain existing behavior. Multi-commit heads are
limited to the existing G1 or POLICY promotion contracts, whose retrospective
validation proves the proposal, three separated reviews, final bytes, and
ancestry. Push, merge-group, and workflow-dispatch events cannot select the
pull-request authority path.

Reviewed proposal: 5bcece191afca13302460de470a0660a86d84efb.
Review subject: fb0671e65265f6381d22cebb6e733d0654cfefe5a1544a1f1ee18f2f323b96cb.
Evidence bundle: 667b464e2ea2bf51299662d2d6dd81364062c67e3c7314582f8d3cab6468c861.
Promotion subject: 7f2d3b2db99965dc237e5c6a3562bfc9fe50207eea37c5ec4018ec80d5d06930.
