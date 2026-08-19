# Protected change control

Implementation packets cannot modify accepted specifications, evaluators,
effective gate evidence, or the specification gate itself. P1.13 and D-030
provide two closed protected-change lanes.

The accepted D-026 specification/gate-evidence process is:

1. add one `change_type=spec` CR packet with matching CHANGELOG CR and ADR;
2. commit a bounded `NO-GO` or `GO-PROPOSED` gate evidence bundle;
3. add three immutable, commit-separated review receipts and notes bound to the
   same reviewed bytes;
4. promote only by reproducing the exact final bytes stored in the reviewed
   promotion manifest.

The validator proves scope, byte identity, ancestry, and separation. It does
not infer that a candidate-declared reviewer identity or verdict is true. The
Primary Integrator remains responsible for accepting independent reviews, and
external branch/check enforcement remains P1.4 evidence.

`NO-GO` and `GO-PROPOSED` evidence may be revised only by a new CR/ADR proposal.
After an effective `GO`, the gate tree and its receipts are immutable.

The proposal review subject uses unsigned 64-bit length framing over every
exact changed path. To avoid a circular self-hash, only the change packet's
`review_subject_sha256` scalar is replaced by 64 ASCII zeroes during digest
calculation; the committed proposal and each receipt retain the real digest.
Review directories are
`reviews/<gate>/<role>-<review-subject>/receipt.json` with sibling `review.md`.

The D-030 CI evaluator amendment process is separate:

1. add one `change_type=policy_amendment` CR packet, a matching manifest,
   CHANGELOG entry and ADR; the proposal changes no protected target;
2. bind the proposal to exact final bytes for a policy-owned subset of CI/spec
   evaluator targets, with current-base and final SHA-256 for every target;
3. add product, architecture and security/evaluation PASS/BLOCK reviews under
   `reviews/POLICY/` in three separate ancestor commits;
4. promote only the exact manifest target set and exact final bytes.

Secret scanning never treats the manifest's Base64 as opaque metadata. A
closed-schema manifest is hash/subject validated, each final file is decoded,
and those exact bytes are scanned under the original policy-owned target path.
Invalid manifests and receipts receive no partial digest suppression.

Missing, duplicate, stale or BLOCK reviews, unchanged targets, target-set drift
and any post-review byte difference fail closed. Later amendments may reuse a
target set because selection also requires every manifest base hash to equal the
current base bytes and every final hash to equal the candidate bytes; competing
proposals for the same exact transition remain ambiguous and fail closed. The
proposal and the three review additions must also form one uninterrupted
single-parent chain ending at the promotion base; parallel review branches,
merge assembly and intervening commits fail closed. The lane cannot change
`specs/**`, frozen G0, gate evidence or `.secrets.baseline`. `CR-017` itself is
the one-time bootstrap exception: it requires an audited exact-commit ruleset
bypass followed by immediate bypass removal and an ordinary green P1.4 PR.
