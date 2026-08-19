# CR-019 product and scope review

Reviewer: Faraday, an internal Codex AI reviewer.

Verdict: PASS.

The proposal is limited to the GitHub pull-request candidate authority defect in
the closed CI evaluator. The workflow keeps the synthetic merge SHA as checkout
and check-run authority while passing the event-owned pull-request head as a
separate logical lifecycle identity. The amendment changes no accepted
specification, G1 criterion, product capability, task status, or gate evidence.

The target set contains only the workflow, CI policy validator, specification
gate evaluator, and focused tests. The added regression tests reject ordinary
multi-commit aggregation, an unreviewed gap before promotion, and PR-head
authority on push or merge-group events; they also accept the protected POLICY
promotion lifecycle through an exactly bound synthetic merge.

Reviewed proposal: 5bcece191afca13302460de470a0660a86d84efb.
Review subject: fb0671e65265f6381d22cebb6e733d0654cfefe5a1544a1f1ee18f2f323b96cb.
Evidence bundle: 667b464e2ea2bf51299662d2d6dd81364062c67e3c7314582f8d3cab6468c861.
Promotion subject: 7f2d3b2db99965dc237e5c6a3562bfc9fe50207eea37c5ec4018ec80d5d06930.
