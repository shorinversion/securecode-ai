# Core package boundary

Core will own framework-independent domain behavior, policy-selected state
transitions and port definitions. It may depend on `packages/contracts`, while
adapters and applications depend inward on Core.

Core must not import a graph runtime, SCM SDK, database driver, object-store
SDK, container runtime or model-provider SDK. `WorkflowGraph` orchestration and
`EvidenceGraph` security evidence remain separate typed concepts.

No business logic is implemented by `P1.1`.
