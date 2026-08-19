# CR-020 architecture and contracts review

Reviewer: Fermat, an internal Codex AI reviewer.

Verdict: PASS.

The change is confined to the shared secret-scanning view and its focused
tests. Change-packet recognition is path-scoped and type-specific, rejects
duplicate keys, and requires the exact schema, identity, policy-owned paths,
budgets, and digest formats before sanitizing three typed hash fields.

Any mismatch returns the original bytes to ordinary detection. The scan-view
ordering preserves existing manifest, attestation, and receipt handling, while
policy-derived forms avoid a second schema authority. No architecture or
contract blocker was identified.

Proposal: 39c4a3e285d340568376ce146b49edeaf52f5126.
Review: 98bf9ea116d628ac9158eaa235edb4dd6b36399b72a1219f9409a7162cabf9d2.
Evidence: ec2a095b4a62b85c7e727f6f5ea525bc35b80f9c03ba9e743c2b496cca4366c3.
Promotion: 35638d66a311cf27e90b594bf0ced54ac4cc8078b056047f72b533226d711bba.
