# Task completion attestations

Completion attestations are immutable, metadata-only successor records. A
candidate may add exactly one `P*.json` file and may touch only the closed
documentation set enforced by `scripts/spec_gate_policy.json`.

The JSON object is strict: `schema_version`, `change_type`, `task_id`,
`starting_commit_sha`, `packet_sha256`, `implementation_commit_sha`,
`evidence_refs`, `allowed_paths`, and `budgets`. Evidence types and cardinality
are policy-owned. Receipt bodies, source, secrets, and raw command output do not
belong here.

An attestation records evidence that the Primary Integrator has already
verified. It cannot change implementation bytes, specifications, evaluators,
gate criteria, or the accepted baseline.

For `P1.13`, every evidence source is an unchanged repository-relative blob in
the authoritative base and its SHA-256 is recomputed. `P1.4` uses two HTTPS
GitHub API/receipt identities for one repository; their external truth remains
a Primary Integrator and repository-owner responsibility rather than a claim
derived from candidate prose.
