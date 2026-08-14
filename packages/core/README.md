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

The `P1.8` candidate adds framework-independent provider and egress ports, an
immutable policy registry, exact deny-overrides-allow preflight and issuer-owned
single-use pre-context/pre-send authorizations. The authorization chain binds
the complete request scope, provider/policy hashes, profile-owned budgets/native
dialect and actual keyed egress manifest; it owns no HTTP client, provider SDK,
retry loop or workflow transition.
