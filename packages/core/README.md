# Core package

Core contains framework-independent security behavior and ports. It depends on
`securecode-ai-contracts`; applications and adapters depend inward on Core.
Core imports no SCM SDK, database driver, container runtime, model-provider SDK
or external graph engine.

Implemented capabilities include:

- repository discovery, normalization, symbols and language-neutral program graphs;
- deterministic and model-native candidate convergence;
- Auditor, Skeptic, finding admission and evidence graphs;
- root-cause localization, bounded repair planning and patch lifecycle;
- validation, regressions, security invariants and resource governance;
- immutable workflow transitions, replay, cancellation and supersession;
- policy, egress, model authorization and structured telemetry;
- baseline fingerprints, SCM run state and performance budgets;
- evaluation, ablation, release metrics, provenance and promotion decisions.

`WorkflowGraph` coordinates execution. `EvidenceGraph` records why a finding or
repair decision exists. They remain distinct typed concepts. Provider failure,
missing mandatory coverage and unverifiable evidence produce an indeterminate
outcome rather than a clean result.

Infrastructure effects are exposed through explicit ports and implemented in
`securecode-ai-adapters` or the application packages. Core never owns HTTP,
filesystem credentials, SQLite, Docker invocation or SCM publication.
