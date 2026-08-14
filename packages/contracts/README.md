# Contracts package boundary

This package owns the versioned domain/wire types shared by CLI, worker,
backend and integration adapters. Pydantic v2 models are the Python validation
source of truth. They do not import model-provider, SCM, database,
object-store, container or workflow-runtime SDKs.

The `0.2.x` contract exposes eight closed, immutable public roots: `AuditRun`
with canonical `RunExecutionIdentity`; `FindingCase` with discovery lineage and
model receipts; `Evidence` with metadata-only `ArtifactRef`; `PatchCandidate`
without embedded diff bytes; ordered-gate `ValidationResult`; and `AuditEvent`
with an independently versioned typed payload envelope; plus `ModelRequest`
and `ModelCallResult`, which carry immutable execution/policy identity and safe
normalized metadata without prompt, source, credential or raw response bytes.
The request explicitly pins its native API dialect; the result exposes the
unambiguous wire field `model_call_status`, never a generic root `status`.

Every wire object requires `schema_version`, rejects unknown fields and uses
specific outcome fields rather than a generic `status`. Same-major additive
data is retained only through a metadata-only typed extension envelope; the
envelope cannot claim `DC3_CONFIDENTIAL_SOURCE` or `DC4_RESTRICTED` and never
embeds arbitrary strings.

Sensitive source/diff content is never a normal model property. It is carried
only by a tenant-scoped, policy-governed content/hash reference that can record
expiry. Provider refusal, empty/invalid output and other non-success statuses
cannot satisfy model coverage or create a clean run.

## Checked-in JSON Schemas

Eight Draft 2020-12 artifacts live under
`src/securecode_ai/contracts/schemas/v0.2.0/` and are included in the wheel.
They are generated deterministically from the Pydantic roots. JSON Schema
closes the structural surface; cross-field rules such as canonical hash,
coverage/outcome precedence and sensitive-reference checks are enforced by the
strict Pydantic validator named in each schema's
`x-securecode-semantic-validator`. Full conformance always applies both
artifacts, as required by the frozen domain contract:

```powershell
.\.venv\Scripts\python.exe -I -m securecode_ai.contracts.schema_export --check
```

Omit `--check` only when intentionally regenerating artifacts during an
accepted contract change. Repository-wide compatibility and protected-drift
enforcement remain owned by `P1.13`. Stable IDs accept only validated hashed
semantic material. Event append/replay behavior lives in framework-independent
Core and is intentionally not claimed by the single-document schema validator.
