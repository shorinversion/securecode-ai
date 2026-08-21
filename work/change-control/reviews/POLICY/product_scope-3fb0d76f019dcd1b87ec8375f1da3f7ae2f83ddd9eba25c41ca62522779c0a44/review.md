# CR-022 product and scope review

Reviewer: Faraday, an internal Codex AI reviewer.

Verdict: PASS.

The proposal, base, evidence, promotion, manifest hashes, and decoded target
bytes were independently verified. The exact target set is limited to the spec
gate implementation and its unit tests.

Ordinary single-parent pushes retain the existing validator. A protected
two-parent push merge is accepted only when its ordered parents, event base,
derived head, identical trees, linear lifecycle, receipts, and final bytes all
match. Pull-request behavior is unchanged and merge-group handling remains on
its existing path. CR-022 and D-035 accurately describe this bounded repair.

Proposal: 738c3b44db43ae60341028ecd06a87f5aa72909d.
Review: 3fb0d76f019dcd1b87ec8375f1da3f7ae2f83ddd9eba25c41ca62522779c0a44.
Evidence: 60f2004b864d88c11a73fb95a625ad9542c859e994daeb7b748b719008f3b6c9.
Promotion: 887d17b5a48fd8ce50d7df6f053ee2c2be5a278846ba850dee1458ad09f8fb1d.
