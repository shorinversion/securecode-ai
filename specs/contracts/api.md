# Backend HTTP API contract

Spec version: `0.2.0`  
Lifecycle: `accepted for Enterprise Workflow MVP`; OpenAPI is generated from
domain models and this resource/behavior contract.

Base path: `/api/v1`. JSON only except artifact upload/download through bounded
signed URLs. Authentication is OIDC/OAuth2 bearer for users and short-lived
workload identity for workers/SCM adapters. Tenant is derived from verified
identity; a caller-supplied tenant ID never grants scope.

Resources:

```text
POST   /runs                    idempotently request a run
GET    /runs/{run_id}           safe state/coverage/provenance projection
POST   /runs/{run_id}:cancel    request cancellation
GET    /runs/{run_id}/events    paginated append-only safe events
GET    /runs/{run_id}/findings  paginated findings projection
GET    /findings/{finding_id}   one FindingCase projection
POST   /findings/{finding_id}/decisions approve/reject/escalate/waive with exact SHA
POST   /artifacts:authorize     purpose-bound upload/download authorization
GET    /policies                authorized policy versions
POST   /integrations/github/webhook raw-body verified adapter endpoint
POST   /integrations/gitlab/webhook raw-body verified adapter endpoint
GET    /health/live             process liveness only
GET    /health/ready            dependency readiness without secrets

POST   /worker-sessions         open an exact-run lease using workload identity
POST   /worker-sessions/{session_id}:heartbeat renew lease; receive cancel/supersede command
POST   /worker-sessions/{session_id}/events:append append an ordered idempotent event batch
POST   /worker-sessions/{session_id}/artifacts:commit commit an authorized ArtifactRef
POST   /worker-sessions/{session_id}:complete compare-and-set terminal worker result
```

- `SC-API-001`: Every mutating request MUST carry an idempotency key and exact
  resource/version preconditions where applicable. **Oracle:** duplicate/race
  suite produces one effect or `409/412`.
- `SC-API-002`: Authorization MUST evaluate verified subject, tenant, role,
  repository and action; object IDs alone grant nothing. **Oracle:** BOLA/IDOR
  matrix across tenants/roles.
- `SC-API-003`: `POST /runs` MUST carry one canonical `RunExecutionIdentity`
  referencing exact repository/base/head SHA plus stage catalogue, workflow,
  policy, config, provider, capability and egress profile identities/hashes; it
  MUST NOT upload a repository.
  **Oracle:** schema and no-code-egress integration test.
- `SC-API-004`: Decisions MUST include exact finding/revision, decision type,
  reason and optional bounded expiry/scope; stale/cross-scope decisions fail.
  **Oracle:** decision replay/scope matrix.
- `SC-API-005`: Artifact authorization MUST bind tenant, content hash, size,
  class, purpose, method and short expiry. **Oracle:** substitution, oversize,
  wrong-purpose and expired cases fail.
- `SC-API-006`: Errors MUST use the safe domain error envelope and MUST NOT
  expose stack, raw provider/tool content, source or credentials. **Oracle:**
  error snapshot/canary scan.
- `SC-API-007`: Listing endpoints MUST use opaque cursor pagination and stable
  deterministic ordering. **Oracle:** insert-between-pages scenario has no
  unauthorized duplicate/omission under documented snapshot semantics.
- `SC-API-008`: Webhook endpoints MUST validate the raw body before JSON parsing
  and then normalize to `ScmChangeEvent`. **Oracle:** webhook mutation corpus.
- `SC-API-009`: API MUST reject unsupported major schema/API versions and
  advertise supported versions/capabilities. **Oracle:** compatibility matrix.
- `SC-API-010`: Health/metrics endpoints MUST NOT reveal tenant/repository/
  provider/source/secret data. **Oracle:** unauthenticated snapshot/canary scan.
- `SC-API-011`: A worker MUST NOT receive application/Temporal database or SCM
  write credentials; durable writes pass through the typed control-plane API or
  a server-owned Temporal Activity. **Oracle:** worker credential inventory and
  direct-database connection attempt fail.
- `SC-API-012`: Worker session is bound to workload subject, tenant, run, the
  unchanged `execution_identity_hash` (therefore exact base/head SHA and every
  pinned execution component) and an expiring lease.
  **Oracle:** wrong worker/run/SHA, expired lease and replay are denied.
- `SC-API-013`: Event batches carry contiguous sequence, event/idempotency IDs
  and content hashes; exact replay is accepted once, divergent replay is `409`.
  **Oracle:** kill/retry/duplicate/mismatch matrix.
- `SC-API-014`: Heartbeat returns typed continue/cancel/supersede commands;
  after cancellation, supersession or lease loss, later artifact/event/terminal
  writes are denied. **Oracle:** race test produces no stale side effect.
- `SC-API-015`: Artifact upload authorization precedes transfer and
  `artifacts:commit` verifies tenant/purpose/class/hash/size before an ArtifactRef
  becomes durable. **Oracle:** incomplete/substituted/cross-purpose uploads do
  not create references.
- `SC-API-016`: `POST /runs` MUST pin the stage catalogue plus eligible provider,
  capability and egress profiles before admission; run/event/finding projections
  MUST expose both discovery-lane receipts and candidate origin without raw
  source. **Oracle:** request/projection schema, ineligible-profile preflight and
  local/worker semantic-equivalence tests.
- `SC-API-017`: Admission, worker-session creation, heartbeat/event/artifact/
  completion writes and projections MUST preserve the same canonical
  `RunExecutionIdentity` and reject an absent or mismatched
  `execution_identity_hash`. **Oracle:** component-by-component identity
  mutation across API and worker messages returns conflict before work or
  durable side effects.

HTTP semantics: `201` new resource, `200` idempotent replay/current projection,
`202` accepted asynchronous action, `400` malformed, `401` unauthenticated,
`403` authenticated but denied, `404` non-disclosing missing/out-of-scope,
`409` semantic conflict/duplicate mismatch, `412` stale revision/precondition,
`422` schema-valid but unsupported policy/capability, `429` bounded quota and
`5xx` safe operational failure. An HTTP status never replaces domain outcome.
