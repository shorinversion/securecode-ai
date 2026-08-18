# Protected change control

Implementation packets cannot modify accepted specifications, evaluators,
effective gate evidence, or the specification gate itself. The only protected
change lane implemented by P1.13 is the accepted D-026 process:

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
