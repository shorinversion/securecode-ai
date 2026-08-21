# CR-022 architecture and contracts review

Reviewer: Fermat, an internal Codex AI reviewer.

Verdict: PASS.

The exact proposal, base, evidence, decoded target hashes, and promotion digest
were independently verified. The canonical committed-candidate oracle passes.

The design preserves direct single-parent push validation and recognizes a
protected merge only from the checked commit's exact ordered parents. It then
reuses the pull-request validator to bind checkout identity, ancestry, merge
and head trees, the uninterrupted lifecycle chain, receipts, and final bytes.
Pull-request and merge-group event authority remain separate. The error mapping
and negative tests are coherent and fail closed.

Proposal: 738c3b44db43ae60341028ecd06a87f5aa72909d.
Review: 3fb0d76f019dcd1b87ec8375f1da3f7ae2f83ddd9eba25c41ca62522779c0a44.
Evidence: 60f2004b864d88c11a73fb95a625ad9542c859e994daeb7b748b719008f3b6c9.
Promotion: 887d17b5a48fd8ce50d7df6f053ee2c2be5a278846ba850dee1458ad09f8fb1d.
