# Core package boundary

Core owns framework-independent domain behavior, policy-selected state
transitions and port definitions. It may depend on `packages/contracts`, while
adapters and applications depend inward on Core.

Core must not import a graph runtime, SCM SDK, database driver, object-store
SDK, container runtime or model-provider SDK. `WorkflowGraph` orchestration and
`EvidenceGraph` security evidence remain separate typed concepts.

`P1.6` adds only the immutable in-memory `EventStream` and deterministic
`RunProjection`: trust-boundary revalidation, tenant/run/execution-identity
plus admitted-HEAD binding, sequence and canonical previous-hash verification,
exact idempotent replay and current-coverage reconstruction. Persistence,
workflow execution, transport and side effects remain outside Core and are
owned by later tasks.

`P1.7` adds only the typed `ProviderProfile`/`EgressProfileId` configuration
port so infrastructure adapters continue to depend inward through Core. Profile
parsing and environment credential access remain adapter concerns.

`P1.8` adds framework-independent provider and egress ports, an
immutable policy registry, exact deny-overrides-allow preflight and issuer-owned
single-use pre-context/pre-send authorizations. The authorization chain binds
the complete request scope, provider/policy hashes, profile-owned budgets/native
dialect and actual keyed egress manifest; it owns no HTTP client, provider SDK,
retry loop or workflow transition.

The locally verified `P1.9` candidate adds the framework-independent
`WorkflowRuntime` port and a pure exact-definition state machine. It owns closed
dual-lane fan-out/fan-in, bounded investigation/repair accounting, deterministic
reason precedence, node-producer admission and replay regeneration, while
remaining separate from the
`EvidenceGraph`. It imports no adapter, graph engine, persistence layer,
provider SDK, `AuditEvent` implementation or specification file.

The `P1.12` candidate adds internal exact-version foundation telemetry values,
trace/source/clock/sink ports, a process-local HMAC trace authority and a
fail-closed multi-sink emitter. Its guarded payload is an internal Core
capability checked by exact object identity inside the active, unchanged
`TelemetryEmitter.emit` code/globals/builtins environment; it expires when
synchronous fan-out returns and is not a contracts-package wire root. Core renders one canonical
DC1-only JSONL snapshot and owns no OpenTelemetry SDK, backend, persistence or
product instrumentation. This operational `TelemetryRecord` neither replaces
nor duplicates the immutable `AuditEvent`; workflow/node telemetry begins in
`P3.8`, while durable and remote observability export remains owned by `P6.10`.
The process-local object contract is not a Python runtime sandbox; coordinated
mutation of code objects, frames, closure cells or resolved runtime objects is
outside `P1.12`.
