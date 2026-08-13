# System architecture baseline

Spec version: `0.2.0`  
Lifecycle: `accepted`  
Decision refs: `D-001–D-016`, `D-020–D-028`

## 1. Architectural invariant

```text
deterministic discovery ─┐
                        ├→ provenance-preserving convergence → EvidenceGraph
model-native discovery ─┘   → bounded investigation → independent gate
                            → root-cause patch candidate → sandbox validation
                            → policy/human decision → report/SCM publication
```

- `SC-SYS-001`: Domain packages MUST NOT import a graph runtime, SCM SDK,
  database driver, object-store SDK, container runtime or provider SDK.
  **Oracle:** architecture/import test over `packages/core` and
  `packages/contracts`.
- `SC-SYS-002`: CLI, worker and backend MUST use the same domain contracts,
  rule implementations, workflow transition table and reporters. **Oracle:**
  golden run serialized by each entry point has the same semantic state.
- `SC-SYS-003`: WorkflowGraph and EvidenceGraph MUST be separate typed objects.
  **Oracle:** schemas have different IDs and no runtime edge is accepted as an
  evidence edge.
- `SC-SYS-004`: Every loop MUST have attempt, token, time, tool and no-progress
  limits with an explicit terminal route. **Oracle:** fault fixtures terminate
  within the configured budget.
- `SC-SYS-005`: A node MUST obtain only named capabilities required for its
  role; generic shell and arbitrary URL-fetch capabilities are forbidden.
  **Oracle:** capability matrix rejects undeclared calls.
- `SC-SYS-007`: Deterministic and model-native discovery MUST be independently
  observable lanes over the same immutable revision and MUST converge through
  one normalization/EvidenceGraph contract. Neither lane may declare the other
  complete or convert its non-success into clean coverage. **Oracle:** lane
  isolation, zero-signal and cross-lane deduplication transition fixtures.

## 2. Ports and adapters

Normative ports:

| Port | Responsibility | Initial adapters |
|---|---|---|
| `WorkflowRuntime` | start/resume/signal/cancel/versioned state transition | `LocalRuntime`, `TemporalRuntime` |
| `RunRepository` | transactional domain metadata and append-only events | in-memory tests, PostgreSQL |
| `BlobStore` | tenant-scoped content-addressed artifacts | filesystem, S3-compatible |
| `SandboxExecutor` | isolated command plans and bounded results | rootless OCI, Kubernetes gVisor Job |
| `ModelProvider` | capability negotiation and normalized model outcome | fake, OpenAI, Anthropic, limited OpenAI-compatible |
| `EgressPolicy` | classify/authorize/manifest every transmission | deterministic policy evaluator |
| `ScmAdapter` | webhook normalization, check/comment publication | GitHub reference, GitLab beta |
| `Scanner` | bounded `RawSignal` facts and provenance; never a finding verdict | own CWE-89/secret/SCA plus approved external adapters |
| `RepositoryView` | typed bounded listing, symbol lookup, range/evidence reads over one immutable revision | local checkout view, CI checkout view |

- `SC-PORT-001`: Every port request MUST include `request_id`, `run_id`,
  `tenant_id`, schema version and idempotency key where side effects are
  possible. **Oracle:** contract schema rejects missing identity/version fields.
- `SC-PORT-002`: Every side-effect adapter MUST be idempotent or perform a
  compare-and-set on the exact semantic key. **Oracle:** duplicated request
  produces one externally observable effect.
- `SC-PORT-003`: Adapter failure MUST return a typed status; exceptions or
  transport success MUST NOT be interpreted as a domain success. **Oracle:**
  provider/storage/SCM fault matrix maps to exact domain outcomes.
- `SC-PORT-004`: Model roles MUST access code only through `RepositoryView`
  requests pinned to the run revision, normalized repository-relative paths,
  allowlisted operations and byte/token/call budgets. Repository content remains
  untrusted data and the port exposes no shell, arbitrary filesystem or network
  primitive. **Oracle:** traversal, revision-swap, oversized-read, free-form
  command and injected-content fixtures have zero unauthorized effects.

## 3. Runtime decision

`LocalRuntime` is normative for offline CLI, unit/contract tests and Core MVP.
It executes the same transition table in-process and persists only an explicit
local run manifest/content-addressed artifacts.

`TemporalRuntime` is normative for connected CI/backend workflows and durable
human approvals. Workflow histories contain IDs, hashes, enum state and artifact
references—not raw source, prompts, patches or logs. External effects occur in
idempotent Activities.

LangGraph is non-normative and MAY be used only in a time-boxed experiment
behind `WorkflowRuntime`; it cannot become a second state authority.

- `SC-RUNTIME-001`: The complete golden transition suite MUST pass unchanged
  against Local and Temporal adapters. **Oracle:** parameterized contract test.
- `SC-RUNTIME-002`: Worker/process kill after each transition MUST resume from
  durable state without repeating completed SCM/artifact side effects.
  **Oracle:** kill-point integration matrix.
- `SC-RUNTIME-003`: Human approval, cancellation and SHA supersession MUST
  survive restart. **Oracle:** restart/signal scenarios reach exact final state.
- `SC-RUNTIME-004`: Temporal payload/history MUST contain no `DC3/DC4` canary.
  **Oracle:** decoded history scan.

## 4. Persistence and queue

PostgreSQL 18 is the connected application system of record. Application data
and Temporal persistence use separate databases/schemas, roles and credentials.
Application authorization is primary; forced Row-Level Security is defense in
depth and the application role is neither owner, superuser nor `BYPASSRLS`.

Temporal task queues are the connected work queue. A transactional PostgreSQL
inbox/outbox bridges authenticated SCM webhook ingestion to idempotent workflow
start. No Redis/Kafka/Celery/RabbitMQ is part of the pilot baseline.

- `SC-STORE-001`: Fresh and forward migrations MUST succeed and schema version
  MUST be recorded. **Oracle:** empty-database migration test.
- `SC-STORE-002`: Tenant identity MUST appear in every application primary key,
  authorization decision and artifact namespace. **Oracle:** forged/cross-
  tenant CRUD and existence-probe suite returns no data.
- `SC-STORE-003`: Crash before/after inbox/outbox dispatch MUST produce exactly
  one semantic run. **Oracle:** deterministic crash-point test.
- `SC-STORE-004`: Workflow and application credentials MUST NOT be reusable
  across persistence planes. **Oracle:** privilege/conformance test.

## 5. Artifact storage

`BlobStore` uses SHA-256 content IDs plus tenant namespace. Local development
uses filesystem; connected pilot uses an S3-compatible service. Database rows
store metadata/references, never unbounded blobs. Encryption, integrity,
short-lived access and lifecycle policy are mandatory.

- `SC-BLOB-001`: Read MUST verify expected digest and size. **Oracle:** modified
  bytes are rejected.
- `SC-BLOB-002`: Cross-tenant access and existence probing MUST be denied.
  **Oracle:** same content hash in two tenants remains independently authorized.
- `SC-BLOB-003`: Signed access MUST be purpose-bound and expire. **Oracle:**
  wrong purpose/tenant and expired link fail.
- `SC-BLOB-004`: Storage lifecycle MUST implement the accepted retention spec.
  **Oracle:** retention conformance suite.

## 6. Sandbox profiles

Local Core MVP uses rootless Docker/Podman where available: non-root process,
read-only root filesystem, dropped capabilities, no host/Docker socket mounts,
network disabled, ephemeral workspace and CPU/RAM/PID/disk/output/time limits.
If the platform cannot meet mandatory controls, validation is `INDETERMINATE`;
there is no silent unsandboxed fallback.

Connected pilot uses one Kubernetes Job per sandbox on a dedicated node pool,
mandatory gVisor `RuntimeClass`, `Restricted` pod security, seccomp, no
service-account token, no host mounts/capabilities, digest-pinned image,
ephemeral volumes, quotas and an enforcing default-deny network policy. MicroVM
is deferred to a high-assurance profile after compatibility evidence.

- `SC-SBX-001`: Runtime MUST verify the requested isolation profile actually ran.
  **Oracle:** missing rootless/gVisor enforcement fails before commands execute.
- `SC-SBX-002`: Sandbox MUST have no SCM write, signing, model-admin or database
  credentials. **Oracle:** credential canaries/env inventory are absent.
- `SC-SBX-003`: Host filesystem, socket, service account and network canaries
  MUST be unreachable. **Oracle:** escape/exfiltration suite fails closed.
- `SC-SBX-004`: All terminal routes MUST attempt teardown and record bounded
  cleanup evidence. **Oracle:** success/failure/cancel/timeout fixtures leave no
  live workload or reusable volume.
- `SC-SBX-005`: Repository code MUST NOT execute during intake/scanning outside
  SandboxExecutor. **Oracle:** lifecycle-script sentinel remains untouched.
- `SC-SBX-006`: Evaluation-lab generated programs MUST use a distinct
  credential-free, no-network sandbox profile with immutable read-only
  `CodeIndex`, protected evaluator/test paths and bounded resources; this
  profile cannot be selected by production workflow nodes. **Oracle:** profile
  identity, isolation and generated-program abuse matrix.

## 7. Provider request/result contract

`ModelRequest` contains IDs, role/mode, provider/model profile, prompt/schema/
tool policy versions, immutable repository scope and `RepositoryView` policy,
optional evidence IDs/hashes/classes, budgets and idempotency key. Evidence IDs
are optional only for model-native discovery, which starts without a scanner
seed but must produce a discovery receipt tied to its repository/tool scope.
`ModelCallResult` separately contains normalized call status, native request and
finish/refusal/filter reason, schema result/error, usage/latency/retryability and
redacted content provenance.

- `SC-MODEL-001`: Fake, OpenAI-native, Anthropic-native and OpenAI-compatible
  adapters MUST pass one normalization suite. **Oracle:** fault/response fixtures
  produce identical normalized outcomes.
- `SC-MODEL-002`: HTTP success MUST NOT imply completed/valid model call.
  **Oracle:** HTTP-200 refusal/empty/invalid/filtered fixtures are non-success.
- `SC-MODEL-003`: Capability mismatch MUST be detected before mandatory work.
  **Oracle:** unsupported structured/refusal profile prevents run start.
- `SC-MODEL-004`: No raw key/source MAY enter logs, DB or workflow history.
  **Oracle:** multi-sink canary scan.
- `SC-MODEL-005`: Every provider MUST validate against the normative
  [`ProviderProfile`](../contracts/provider-profile.schema.json) and pin its
  profile version plus canonical content hash before context assembly. **Oracle:**
  schema/semantic profile fixtures and immutable-version conflict test.
- `SC-MODEL-006`: Remote provider URL/credential, model identity, verified data
  terms, native outcome signals, egress compatibility and budgets MUST come only
  from that profile; repository/SCM content cannot override them. **Oracle:**
  hostile config/host/credential/capability matrix fails before network bytes.
- `SC-MODEL-007`: Before source-bearing model-native discovery, a machine
  preflight MUST jointly validate the immutable provider profile and selected
  egress policy. Eligibility requires structured output, native refusal and
  incomplete signals, source-analysis capability, bounded repository tool calls
  with all four `RepositoryView` operations, an exact authorized purpose and
  data class, an approved execution boundary, a provider-supported egress
  profile and a deny-overrides allow evaluation for the exact tenant scope,
  destination, byte budget and transformation set. The planned/applied
  transformation set MUST exactly equal the selected allow rule's required set;
  a matching deny always wins. Failure
  MUST assemble zero context bytes, send zero network bytes, disable
  deterministic-only fallback and terminate as `INDETERMINATE`. **Oracle:** the
  accepted provider/egress semantic fixtures are recomputed by the G0 validator;
  each predicate mutation changes the eligible case to the exact ineligible
  outcome before I/O.
- `SC-SYS-006`: Executable dependencies, CI actions, scanners and container
  images MUST be locked and verified before use; release evidence adds SBOM,
  provenance and signatures at `G8`. **Oracle:** modified/unpinned artifact is
  rejected and supply-chain manifest is complete for the applicable gate.
- `SC-RUNTIME-005`: Connected admission/queues MUST enforce tenant quotas,
  bounded backpressure and cancellation without cross-tenant starvation.
  **Oracle:** webhook-storm/load test preserves configured fairness and ceilings.

## 8. Repository layout contract for P1

```text
packages/
  contracts/
  core/
  adapters/
    runtime/{local,temporal}/
    persistence/postgres/
    artifacts/{filesystem,s3}/
    sandbox/{oci,kubernetes_gvisor}/
    providers/{fake,openai,anthropic,openai_compatible}/
apps/{cli,server,worker}/
integrations/{github,gitlab}/
deploy/{compose,kubernetes}/
tests/{unit,contract,integration,security,fixtures}/
examples/demo-repositories/
notebooks/
report/
README.md
pyproject.toml
Dockerfile
```

The layout may add directories without a breaking change. Moving a normative
port across ownership boundaries or exposing adapter types through public
contracts requires an ADR and migration note.

- `SC-SYS-008`: The final repository MUST expose the assignment delivery roots
  above (or manifest-declared equivalents) and one locked dependency authority;
  generated/build outputs MUST NOT become competing sources of truth. **Oracle:**
  repository-layout/submission-manifest lint and clean-room build.
