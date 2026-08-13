# Event contract

Spec version: `0.2.0`  
Lifecycle: `accepted`

Envelope fields:

```text
schema_version, event_id, event_type, event_version, occurred_at, recorded_at,
tenant_id, run_id, sequence, previous_event_hash, actor,
correlation_id, causation_id, idempotency_key, data_class,
payload_ref_or_safe_payload
```

Initial types:

```text
RunRequested RunStarted RunCancelled RunSuperseded RunCompleted
IntakeCompleted CoverageUpdated ScannerCompleted RawSignalCreated
DiscoveryStarted DiscoveryCompleted CandidateNormalized
FindingCreated EvidenceAdded ModelCallCompleted CandidateInterpretationRecorded
VerdictRecorded
PatchProposed ValidationGateCompleted PatchValidated
HumanDecisionRecorded WaiverExpired
ArtifactRecorded EgressEvaluated ScmPublicationRecorded
```

- `SC-EVENT-001`: Events MUST be immutable and append-only; corrections append a
  compensating event. **Oracle:** update/delete interface is absent and tamper
  test fails verification.
- `SC-EVENT-002`: Per-run sequence and previous hash MUST detect gaps, reordering
  and substitution. **Oracle:** mutation matrix.
- `SC-EVENT-003`: Duplicate `event_id/idempotency_key` with identical content is
  accepted once; differing content is a conflict. **Oracle:** duplicate tests.
- `SC-EVENT-004`: Payload MUST contain only fields allowed for its data class;
  source-bearing content uses an authorized ArtifactRef. **Oracle:** schema lint
  and secret/source canary.
- `SC-EVENT-005`: Event versioning follows domain compatibility; consumers MUST
  reject unsupported major and preserve raw hash/provenance. **Oracle:** version
  matrix and replay.
- `SC-EVENT-006`: Projection rebuild from events MUST reproduce the same domain
  state and CoverageManifest. **Oracle:** golden replay hash.
- `SC-EVENT-007`: External publication events MUST record requested/current HEAD
  and platform response ID without storing SCM tokens or unsafe raw comments.
  **Oracle:** stale/publication and canary tests.
- `SC-EVENT-008`: Event timestamps are evidence, not ordering authority;
  sequence/causation determine run order. **Oracle:** skewed-clock replay.
- `SC-EVENT-009`: `schema_version` versions the envelope while `event_version`
  versions the event type/payload; both follow unsupported-major and additive-
  minor compatibility rules. **Oracle:** Cartesian envelope/payload version
  replay, including tampered and future-version fixtures.
- `SC-EVENT-010`: Discovery and normalization events MUST identify the lane,
  exact revision, producer/model/prompt/tool versions, input/output hashes,
  budgets, terminal reason, receipt and `CandidateOrigin`; a completed-zero
  model-native result remains an explicit event. **Oracle:** dual-lane golden
  replay plus missing-origin/receipt mutation tests.
- `SC-EVENT-011`: Discovery events MUST reference source-bearing context by
  classified content/evidence IDs and MUST NOT embed raw code, prompts or model
  output in ordinary event payloads. **Oracle:** event schemas and multi-sink
  source/secret canary scan.
- `SC-EVENT-012`: `CandidateInterpretationRecorded` MUST contain the complete
  safe `CandidateInterpretationReceipt` reference/fields required by
  `SC-DOM-013`; replay MUST reconstruct the one terminal receipt for each
  current candidate version before coverage can complete. **Oracle:** golden
  dual-lane replay plus missing/duplicate/stale receipt mutation matrix.
- `SC-EVENT-013`: `RunRequested`, `RunStarted` and every execution-derived
  event MUST carry or reference the exact admitted `execution_identity_hash`;
  replay MUST reject a component hash or event whose identity differs from the
  run. **Oracle:** cross-transport golden replay and per-component identity
  mutation matrix.
