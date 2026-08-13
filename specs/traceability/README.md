# Traceability baseline

Spec version: `0.1.0`  
Lifecycle: `accepted`

[`requirements.yaml`](requirements.yaml) is the normative source-to-delivery
matrix. It covers all original assignment deliverables, accepted expansions,
security invariants, architecture and evaluation governance.

Traceability has two levels:

1. source requirement → normative IDs → plan tasks → test families → gates;
2. every normative `SC-<AREA>-NNN` prefix → owner phase and executable test
   family through `spec_prefix_coverage`.

At G0, test/evidence fields are commitments and oracles, not claims that code
already exists. From P1 onward CI generates an exact per-ID report linking
implementation paths, test node IDs and artifact hashes; missing IDs fail the
spec gate.

Breaking a mapping, removing an original brief requirement or marking planned
evidence as proven without an artifact requires a change request and gate review.
