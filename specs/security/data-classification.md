# Data classification, egress and retention contract

Spec version: `0.2.0`  
Lifecycle: `accepted`  
Decision refs: `D-009`, `D-015`, `D-024`

`MUST`, `MUST NOT`, `SHOULD` and `MAY` are normative. Every requirement has a
stable ID and an oracle that will become an executable conformance test in P1.

## Classes and inheritance

| Class | Content | Default |
|---|---|---|
| `DC0_PUBLIC` | public fixtures, published rules/schemas | may leave tenant with provenance |
| `DC1_INTERNAL_METADATA` | run IDs, versions, aggregate counts/timings | control plane and redacted telemetry |
| `DC2_CONFIDENTIAL_SECURITY` | findings, CWE, location, evidence topology, repository identity | tenant-scoped storage; no public disclosure |
| `DC3_CONFIDENTIAL_SOURCE` | source/snippets, diffs, prompts/responses/build logs containing source | runner only by default |
| `DC4_RESTRICTED` | secrets, tokens, keys, regulated PII/customer data | quarantine/redact; never model/backend/SCM/telemetry |

- `SC-DATA-001`: Every source-derived object MUST carry `data_class`, `tenant_id`,
  `content_id` and provenance. **Oracle:** schema rejects a missing field.
- `SC-DATA-002`: A transformation MUST inherit the highest input class unless a
  named, versioned, approved irreversible downgrade rule applies. **Oracle:**
  property test over all input-class combinations.
- `SC-DATA-003`: Unknown source-derived content MUST default to `DC3`; suspected
  secret/regulated content MUST default to `DC4`. **Oracle:** unknown/secret
  fixtures receive those exact classes.
- `SC-DATA-004`: Secret findings MUST retain only location, type and keyed
  fingerprint/redaction, never the secret value. **Oracle:** canary is absent
  from serialized finding, logs, traces and reports.
- `SC-DATA-004a`: The named downgrade rule `secret-mask@1` turns a `DC4` source
  file into a `DC3` model view only when the secret stage verified every
  candidate span of the file at the analysed revision: each span is replaced by
  the detector's redaction marker, line breaks are kept, and raw evidence
  windows of the file stay unavailable to every tool. Without a verified secret
  stage the whole file stays `DC4` and is withheld. **Oracle:** a canary secret
  in an analysed file is absent from every model request, while the masked line
  numbers and surrounding code are present.
- `SC-DATA-005`: Prompts, responses, patches, crash dumps, caches and backups
  MUST inherit classification; “derived” MUST NOT imply safe. **Oracle:** sink
  inventory shows an equal-or-higher class.
- `SC-DATA-006`: Optimizer trials, prompt/skill/RLM candidates and synthetic
  cases MUST inherit the highest source/expectation class and remain segregated
  from production artifacts and locked-test expectations. **Oracle:** artifact
  classification matrix, protected-path check and cross-split canary test.

## Egress profiles

| Profile | Permitted behavior |
|---|---|
| `air_gap` | no network; local/fake model; explicit local output only |
| `no_code_egress` (default) | worker/local approved model; backend only `DC1` and policy-selected `DC2`; never `DC3/DC4` |
| `private_model_zdr` | minimal selected/redacted `DC0–DC3` to approved private endpoint; `DC4` denied; verified retention/residency |
| `metadata_external` | approved external provider receives only `DC0–DC2` and no reconstructable source/secrets |
| `managed_scan_opt_in` | explicit tenant-admin opt-in; tenant-isolated sandbox may process `DC0–DC3`; `DC4` denied/quarantined |

- `SC-EGRESS-001`: A run MUST pin one profile and a policy version before
  repository content is read. **Oracle:** missing/mutable profile prevents start.
- `SC-EGRESS-002`: Every attempted transmission MUST be evaluated using source
  class, destination, purpose, tenant, profile and transformation provenance.
  **Oracle:** deny fixtures exercise every field and produce zero network bytes.
- `SC-EGRESS-003`: `air_gap` MUST cause zero network attempts. **Oracle:** a
  network interception test records zero connects/DNS queries.
- `SC-EGRESS-004`: `no_code_egress` MUST NOT transmit `DC3/DC4` to backend or
  provider outside the approved runner boundary. **Oracle:** source/secret
  canaries are absent from captured traffic.
- `SC-EGRESS-005`: `DC4` MUST NOT be transmitted to any model, backend, SCM
  comment, telemetry or analytics sink in any profile. **Oracle:** matrix of all
  sinks is denied and redacted.
- `SC-EGRESS-006`: Widening profile, destination, purpose or retention MUST
  require tenant-admin authorization and append an audit event. **Oracle:**
  ordinary users receive `DENY`; authorized change has actor/policy/time.
- `SC-EGRESS-007`: An egress manifest MUST enumerate destination, content IDs,
  classes, transformations and byte counts without including raw content.
  **Oracle:** manifest reconciles with proxy capture.
- `SC-EGRESS-008`: Before a supported semantic scan starts, the selected model
  and egress profiles MUST authorize the exact data classes and purposes needed
  by model-native discovery inside the approved execution boundary. An
  ineligible profile MUST fail preflight as incomplete analysis and MUST NOT
  silently downgrade to deterministic-only operation. **Oracle:** eligible
  local/private and ineligible metadata-only/DC3 provider fixtures bind exact
  tenant scope and planned/policy-required transform equality, exercise matching
  deny override, and produce zero
  unauthorized bytes and exact `INDETERMINATE` routing.

## Endpoint and provider policy

- `SC-ENDPOINT-001`: Remote endpoints MUST use HTTPS; only an explicitly marked
  loopback/local transport MAY use plaintext. **Oracle:** HTTP remote URL fails
  configuration validation.
- `SC-ENDPOINT-002`: Hostname, port and provider profile MUST be allowlisted;
  arbitrary URL fetch and redirect following are forbidden. **Oracle:** unknown
  host/port and redirect fixtures are denied.
- `SC-ENDPOINT-003`: DNS/IP MUST be validated before connect and after any
  resolution change; loopback, private, link-local and cloud-metadata addresses
  are denied unless the exact local profile permits the exact target. **Oracle:**
  SSRF, rebinding and alternative-IP-notation corpus is denied.
- `SC-ENDPOINT-004`: Credential reference MUST be bound to an approved provider
  profile/host and the credential value MUST NOT enter durable state. **Oracle:**
  cross-host credential use fails; canary absent from DB/history/logs.
- `SC-ENDPOINT-005`: Provider retention, residency, training use, model identity,
  native refusal and structured-output capabilities MUST be explicit verified
  attributes, not inferred from API compatibility. **Oracle:** capability
  mismatch prevents the mandatory node from starting.
- `SC-ENDPOINT-006`: Consumer chat/web products MUST NOT be configured as model
  endpoints. **Oracle:** provider-kind enum and endpoint validation reject them.

## Retention defaults

| Artifact | Default retention |
|---|---|
| Offline checkout/run state | process/run lifetime; user output is explicit |
| CI/managed raw checkout | terminal state; managed retry/forensics window ≤24h only by policy |
| Backend `DC1/DC2` run/finding metadata | 90 days |
| Audit decision/provenance metadata | 365 days |
| Backend source-bearing prompts/responses/snippets/patches | not stored in default profile |
| Optimizer/prompts/skills/RLM/synthetic candidates | isolated evaluation workspace; rejected candidates expire by policy and never enter production implicitly |
| Secret value | never stored; quarantine buffer is ephemeral and zeroed best-effort |

- `SC-RET-001`: Retention MUST be selected by artifact class/type/profile and
  recorded at creation. **Oracle:** each artifact has `expires_at` or approved
  immutable-policy reference.
- `SC-RET-002`: Expiry MUST make content inaccessible and produce deletion
  evidence without claiming guaranteed physical erasure. **Oracle:** expired
  object cannot be fetched and audit records deletion outcome.
- `SC-RET-003`: Backup, cache, replicas and derived artifacts MUST follow the
  same or stricter retention schedule. **Oracle:** inventory reconciliation has
  no live descendant after the permitted window.
- `SC-RET-004`: WORM/Object Lock MUST NOT be used for deletable raw source;
  immutable storage is limited to approved non-source audit exports. **Oracle:**
  policy compiler rejects incompatible class/storage mode.
- `SC-RET-005`: Evaluation-lab candidate artifacts MUST record lineage, split,
  generator/optimizer version, input hashes, decision and expiry; promotion
  creates a separately reviewed immutable release artifact rather than extending
  rejected-candidate retention. **Oracle:** retention/lineage reconciliation and
  rejected-candidate expiry fixtures.

## Required policy contract shape

Machine-readable policies are validated by
[`egress-policy.schema.json`](../contracts/policy/egress-policy.schema.json) and
[`retention-policy.schema.json`](../contracts/policy/retention-policy.schema.json).
Policy evaluation is deny-overrides-allow and default-deny. An evaluator error
is a denial plus `INDETERMINATE/ERROR`, never implicit permission.
