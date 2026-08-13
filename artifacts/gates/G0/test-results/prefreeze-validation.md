# G0 pre-freeze validation result

Date: 13 августа 2026 года  
Command: `python scripts/validate_g0.py`  
Exit code: `0`

## Result

- YAML/lock documents parsed: `10`;
- JSON Schema Draft 2020-12 meta-validation: `3/3`;
- egress/retention positive/negative fixtures: `9/9` expected outcomes;
- provider-profile positive/negative fixtures: `5/5` expected outcomes;
- provider/egress semantic preflight fixtures: `2/2` expected outcomes plus
  per-predicate in-memory negative mutations;
- unique normative requirements with oracle: `228`;
- source/change traceability rows: `38`; original brief `15/15`, accepted
  change requests `16/16`;
- normative requirement prefixes mapped to owner/test family: `22/22`;
- system and privacy threats mapped to requirement/task/test: `31/31`;
- baseline documents and local Markdown links: no missing target;
- dataset lock bytes/SHA-256: matched;
- critical unresolved accepted-spec tokens: none;
- secret-like value/private-key pattern files outside the quarantined raw
  research copy: `0`;
- normative baseline SHA-256:
  `dedb43be8ba055dfa47858b975630b4c870af3bed2dda842b0e8422c8354b5c9`;
- validator errors: `[]`.

Strict command `python scripts/validate_g0.py --require-frozen` exits `1` by
design before the first commit. It rejects non-frozen lifecycle, absent full
commit SHA/HEAD/ancestor, uncommitted evaluator/spec/gate bytes, any non-PASS
checklist row, missing/mismatched review hash or categories, and non-effective
decision/status/commit binding. This negative control prevents prose-only or
working-tree-only gate closure.

The hash algorithm is SHA-256 over sorted normative paths, then for every path
`UTF-8 path + NUL + exact file bytes + NUL`. `specs/baseline.yaml` and G0
attestations are intentionally outside the hashed set to avoid self-reference.

## Meaning

This proves definition consistency only. It does not prove scanner/model
accuracy, sandbox containment, enterprise reliability or any future executable
oracle. Those remain gated in `G1–G9`.
