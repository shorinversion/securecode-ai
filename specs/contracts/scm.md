# SCM integration contract

Spec version: `0.2.0`  
Lifecycle: `accepted`  
Reference: GitHub App; GitLab implements semantic conformance by beta.

## Normalized inputs and outputs

`ScmChangeEvent` contains tenant/installation/repository IDs, event/delivery ID,
event time, actor, base/head SHA, PR/MR identity, source/target refs and trust
classification (including fork). Raw title/body/comments are untrusted data.

`ScmPublication` contains run ID, exact `execution_identity_hash`, exact head
SHA, normalized gate outcome, bounded annotations, safe summary and artifact
links.

- `SC-SCM-001`: Webhook MUST be authenticated over the exact raw body before
  parsing and rejected outside the replay window. **Oracle:** signature/body/
  timestamp mutation corpus creates no run.
- `SC-SCM-002`: Delivery/event ID is the transport-dedup key. Semantic key
  `(tenant_id, installation_id, repository_id, execution_identity_hash)` MUST
  make workflow start idempotent, where `execution_identity_hash` is the
  canonical `RunExecutionIdentity` and therefore pins base/head SHA, stage
  catalogue, workflow, policy, config, provider, capability and egress profile
  versions/content hashes. Same delivery/key with different canonical content
  is a conflict. **Oracle:** exact duplicates produce one semantic run; mutation
  of any identity component does not collapse; mismatch returns conflict.
- `SC-SCM-003`: Worker MUST fetch and verify the exact authorized commit; branch
  name alone is insufficient. **Oracle:** ref-move/TOCTOU fixture stops safely.
- `SC-SCM-004`: Publication MUST compare current source HEAD; stale run becomes
  `SUPERSEDED` and MUST NOT change the current check/comment. **Oracle:** race
  scenario.
- `SC-SCM-005`: Fork/untrusted contribution MUST receive no repository/provider/
  backend secrets unavailable to untrusted code. **Oracle:** fork canary/env
  inventory and egress test.
- `SC-SCM-006`: Summary MUST be one idempotently updated safe-rendered comment;
  inline annotations MUST be limited, precisely located and changed-line scoped.
  **Oracle:** duplicate run/comment-volume/rendering snapshots.
- `SC-SCM-007`: Only the check/commit status, never the comment or SARIF, MAY be
  configured as merge gate. **Oracle:** comment/SARIF deletion does not change
  normalized gate state.
- `SC-SCM-008`: `PASS/FAIL/INDETERMINATE/ERROR/CANCELLED/SUPERSEDED` MUST map without a
  fail-open platform conclusion. GitHub `neutral/skipped` MUST NOT represent
  indeterminate/cancelled in a required check. `CANCELLED` is explicit
  non-passing for the same HEAD; `SUPERSEDED` never publishes onto the current
  HEAD. **Oracle:** adapter outcome and cancel/supersede race matrix.
- `SC-SCM-009`: Adapter MUST request only documented minimum permissions and
  MUST expose optional capabilities separately. **Oracle:** permission manifest
  diff; Core flow works with optional SARIF permission absent.
- `SC-SCM-010`: SCM write tokens MUST be unavailable to repository sandbox and
  short-lived/scoped where the platform supports it. **Oracle:** sandbox env and
  unauthorized publication tests.
- `SC-SCM-011`: A non-passing summary MUST identify the exact incomplete or
  failed discovery/investigation coverage unit and recovery action; it MUST NOT
  collapse a model-native non-success into zero findings. **Oracle:** lane-fault
  summary snapshots and platform outcome mapping.

## GitHub reference behavior

Minimum App permissions are defined in
[PRODUCT.md](../../docs/PRODUCT.md#6-reference-scm-github-first). Required
webhook events are installation/repository lifecycle as needed and pull-request/
check lifecycle events with an allowlist. Check Run annotations are bounded and
the full report is linked. `action_required` represents policy-defined human
action; `failure` represents a confirmed blocking finding; infrastructure and
indeterminate states remain non-passing in a required-check profile.

## GitLab beta behavior

Universal mode uses a CI job/commit status with nonzero exit semantics. MR notes
and Discussions implement summary/inline UX. External Status Checks are an
optional capability because blocking behavior depends on GitLab tier/settings;
the adapter still binds every response to exact HEAD and passes the common
conformance suite.
