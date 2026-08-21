# CR-022 security and evaluation review

Reviewer: Goodall, an internal Codex AI reviewer.

Verdict: PASS.

The proposal, base, evidence, promotion, decoded final hashes, and canonical
proposal validation were independently verified.

Logical head authority derives only from the checked merge commit's second
parent. Exact parent count and order, checkout identity, ancestry, an
uninterrupted direct-parent lifecycle, and merge/head tree equality are all
mandatory. Multi-commit admission remains restricted to an exact G1 or POLICY
promotion with retrospective proposal, receipt, and final-byte validation.
Single-parent pushes are unchanged, event authorities remain separated, and
the negative coverage closes malformed and smuggled merge cases.

Proposal: 738c3b44db43ae60341028ecd06a87f5aa72909d.
Review: 3fb0d76f019dcd1b87ec8375f1da3f7ae2f83ddd9eba25c41ca62522779c0a44.
Evidence: 60f2004b864d88c11a73fb95a625ad9542c859e994daeb7b748b719008f3b6c9.
Promotion: 887d17b5a48fd8ce50d7df6f053ee2c2be5a278846ba850dee1458ad09f8fb1d.
