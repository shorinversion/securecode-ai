# Report contract

Spec version: `0.2.0`  
Lifecycle: `accepted`

Formats: canonical JSON, SARIF 2.1, Markdown and HTML. JSON is the semantic
source for rendered reports; format conversion cannot change verdict or gate.

- `SC-REPORT-001`: Every report MUST contain schema/report version, run and exact
  revision, the canonical `execution_identity_hash`, workflow/policy/tool/model
  versions, outcome and CoverageManifest.
  **Oracle:** schema rejects missing provenance/coverage.
- `SC-REPORT-002`: Every finding MUST include stable fingerprint, locations,
  CWE, OWASP mapping, severity/confidence with provenance, verdict, Evidence
  references and patch/validation references if present. **Oracle:** finding
  schema and golden snapshots.
- `SC-REPORT-003`: A report MUST distinguish zero findings from incomplete,
  unsupported, refused, failed and skipped coverage. **Oracle:** non-success UX
  snapshots never contain a clean claim.
- `SC-REPORT-004`: Secret values and disallowed classified source MUST NOT appear
  in any report or link. **Oracle:** multi-format canary scan.
- `SC-REPORT-005`: Markdown/HTML/SARIF/terminal text MUST escape or strip active
  content, control sequences, unsafe schemes and path disclosure. **Oracle:**
  rendering attack corpus remains inert.
- `SC-REPORT-006`: SARIF export MUST validate against its pinned schema and use
  repository-relative normalized locations; platform upload is optional.
  **Oracle:** schema validation and unsafe-location cases.
- `SC-REPORT-007`: Patch content MAY be embedded only when policy permits its
  `DC3` destination; otherwise the report contains a classified ArtifactRef.
  **Oracle:** egress profile matrix.
- `SC-REPORT-008`: Cross-format normalized semantics MUST be equal. **Oracle:**
  parse/compare run outcome, findings, coverage and artifact hashes.
- `SC-REPORT-009`: Human decisions/waivers MUST preserve actor, scope, exact SHA,
  reason, expiry and underlying non-waived outcome. **Oracle:** audit report
  round trip.
- `SC-REPORT-010`: Generated HTML MUST be self-contained or load only pinned
  policy-approved assets; scripts are disabled by default. **Oracle:** CSP/static
  inspection and offline rendering test.
- `SC-REPORT-011`: Reports MUST show deterministic and model-native lane status,
  completed-zero versus non-success receipts, candidate origin/lineage and
  Auditor interpretation coverage. A failed or missing lane MUST identify the
  recovery action and MUST NOT render a clean summary. **Oracle:** cross-format
  lane/origin golden snapshots and provider-fault UX matrix.
