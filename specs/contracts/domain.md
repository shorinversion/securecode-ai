# Domain contract baseline

Spec version: `0.2.0`  
Lifecycle: `accepted`

Pydantic v2 models are the implementation source for Python validation and
generate JSON Schema Draft 2020-12 artifacts. Public backend HTTP contracts use
OpenAPI 3.1 generated from the same domain types. Generated schemas are checked
into the release and compared in CI; handwritten OpenAPI is not a competing
domain source of truth.

## Stable entities

| Entity | Identity/invariants |
|---|---|
| `RepositoryRevision` | tenant, SCM identity, immutable commit SHA, optional base SHA |
| `RunExecutionIdentity` | exact repository revision plus stage catalogue, workflow, policy, config, provider, capability and egress profile version/content hashes; canonical serialization has one stable hash |
| `AuditRun` | one `RunExecutionIdentity` over one exact revision; append-only event lineage |
| `CoverageManifest` | every required analyzer/node with completed/non-success reason |
| `RawSignal` | untrusted deterministic scanner fact with exact producer, rule, location/hash and payload classification; never a verdict |
| `DiscoveryCandidate` | pre-verdict root-cause hypothesis from one or both lanes with stable fingerprint, evidence/lineage references and origin |
| `FindingCase` | stable fingerprint, locations, CWE, EvidenceGraph, verdict lineage |
| `ModelDiscoveryReceipt` | immutable revision/scope, repository-view calls, budgets, status, hashes and candidate IDs, including a valid completed-zero result |
| `CandidateInterpretationReceipt` | candidate/Auditor/model/prompt/evidence hashes, call status, schema result and verdict reference; proves the candidate was not dropped |
| `Evidence` | typed fact with source, location/hash, producer/version and trust label |
| `PatchCandidate` | parent finding/revision, unified diff hash, author/version, status |
| `ValidationResult` | sandbox profile, ordered gates, immutable result/provenance |
| `Decision` | actor/policy/time/scope/SHA/reason; approve/reject/waive/escalate |
| `ArtifactRef` | tenant, content ID/hash/size/class/expiry, no embedded blob |
| `AuditEvent` | monotonic per-run sequence, previous-event hash and typed payload ref |

## Outcome types

```text
ModelCallStatus = SUCCEEDED | REFUSED | CONTENT_FILTERED | INCOMPLETE |
                  TRUNCATED | CONTEXT_EXHAUSTED | INVALID_SCHEMA |
                  EMPTY_OUTPUT | TIMEOUT | RATE_LIMITED | PROVIDER_ERROR |
                  BUDGET_EXHAUSTED | GUARDRAIL_BLOCKED | CANCELLED

FindingVerdict  = CONFIRMED | REJECTED_WITH_EVIDENCE |
                  NEEDS_MORE_EVIDENCE | CONFLICTING | NOT_EVALUATED

AuditRunOutcome = PASS | FAIL | INDETERMINATE | ERROR | CANCELLED | SUPERSEDED

CandidateOrigin = deterministic | model_native | hybrid
DiscoveryLane   = deterministic | model_native
```

- `SC-DOM-001`: These enums MUST remain disjoint; no serializer field may use a
  shared generic `status`. **Oracle:** schema and type test.
- `SC-DOM-002`: Only `SUCCEEDED` with schema-valid mandatory results may
  contribute positive coverage. **Oracle:** Cartesian fault/outcome table.
- `SC-DOM-003`: `PASS` MUST require a complete mandatory CoverageManifest and
  zero blocking findings under the pinned policy. **Oracle:** remove/fail each
  mandatory item and verify outcome is not `PASS`.
- `SC-DOM-004`: Every finding and SCM publication MUST bind to exact `head_sha`.
  **Oracle:** stale SHA fixture is `SUPERSEDED` and publishes no new status.
- `SC-DOM-005`: Domain objects MUST reject unknown fields at trust boundaries.
  **Oracle:** additional-property fuzz cases fail validation.
- `SC-DOM-006`: Source locations use normalized repository-relative path,
  1-based line/column intervals and content hash; absolute host paths are
  forbidden. **Oracle:** normalization/path corpus.
- `SC-DOM-007`: All wire objects MUST include `schema_version`; breaking changes
  increment major, additive optional changes increment minor, corrections with
  unchanged semantics increment patch. **Oracle:** compatibility checker.
- `SC-DOM-008`: A consumer MUST reject an unsupported major version and preserve
  unknown future minor data only through an explicit extension envelope.
  **Oracle:** version matrix.
- `SC-DOM-009`: Audit events MUST be append-only, idempotent by event ID and
  hash-linked within a run. **Oracle:** duplicate accepted once; reorder/tamper
  rejected.
- `SC-DOM-010`: `DC3/DC4` values MUST appear only as classified ephemeral
  content or ArtifactRef under an allowed policy, never as ordinary event/log
  fields. **Oracle:** schema lint and canary serialization test.
- `SC-DOM-011`: Every normalized candidate and `FindingCase` MUST carry one
  closed `CandidateOrigin` plus immutable producer/evidence lineage. `hybrid`
  is valid only when deterministic and model-native candidates resolve to the
  same root-cause fingerprint; origin is never inferred from the final verdict.
  **Oracle:** origin round-trip, invalid-enum and cross-lane merge/split tests.
- `SC-DOM-012`: A completed model-native pass with zero candidates MUST emit a
  `ModelDiscoveryReceipt`; absent, refused, invalid, timed-out or failed passes
  MUST remain distinguishable and cannot satisfy coverage. **Oracle:** receipt
  schema/fault Cartesian matrix and completed-zero golden fixture.
- `SC-DOM-013`: Every normalized candidate MUST have exactly one terminal
  `CandidateInterpretationReceipt` for its current version before coverage can
  complete; deduplication MUST retain all input signal/candidate lineage IDs.
  **Oracle:** dropped/duplicate/stale receipt and dedup-lineage mutation tests.
- `SC-DOM-014`: `RunExecutionIdentity` MUST canonically include tenant,
  repository/base/head SHA and the ID, version and content hash of the selected
  stage catalogue, workflow, policy, configuration, provider, capability and
  egress profiles. `execution_identity_hash` MUST be computed from that
  versioned canonical object and used unchanged by admission, SCM idempotency,
  worker leases, events, manifests and reports; `config_hash` MUST NOT stand in
  for omitted execution semantics. **Oracle:** cross-transport golden identity
  plus single-component mutation tests never collapse two runs or admit a
  mismatched lease/event/report.

## Error envelope

Public CLI/API/worker errors use:

```text
error_code, category, retryable, safe_message, correlation_id,
run_id?, finding_id?, details_ref?
```

`safe_message` contains no secret/source by construction. Stack traces and raw
provider/tool responses are not public fields. Stable error codes are additive;
removing or changing semantics is a breaking contract change.

## Schema and compatibility authority

- domain-first Pydantic types + checked-in JSON Schema are normative together;
- generated OpenAPI describes transport only and cannot weaken domain rules;
- events carry immutable historical schema version; migrations create a new
  projection and do not rewrite audit history;
- examples and negative fixtures are part of the compatibility suite;
- generator/tool versions are locked in P1; the choice of generator itself is
  not a public contract.
