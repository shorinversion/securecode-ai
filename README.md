# SecureCode AI

SecureCode AI is a security-oriented code-audit platform under staged,
evidence-gated development. The frozen definition baseline is `0.2.0`; the
current implementation phase is `P1 — Engineering Foundation`.

This repository currently contains the completed specification baseline and
the `P1.1` ownership skeleton. It does **not** yet contain a working scanner,
agent workflow, backend, SCM bot, sandbox or installable Python distribution.

## Repository ownership

| Path | Owns | Must not own |
|---|---|---|
| `packages/contracts/` | versioned wire/domain contract implementation | provider, SCM, database or runtime SDKs |
| `packages/core/` | framework-independent domain behavior and ports | transport, persistence, graph-runtime or provider implementations |
| `packages/adapters/` | implementations of Core ports | alternate business rules or duplicate domain models |
| `apps/cli/` | offline command-line composition | a private copy of Core |
| `apps/server/` | control-plane HTTP composition | repository scanning inside the backend |
| `apps/worker/` | exact-run worker composition | control-plane database or SCM write credentials |
| `integrations/` | GitHub/GitLab transport adaptation | security verdict authority |
| `deploy/` | deployment packaging owned by later phases | domain or product behavior |
| `tests/` | product verification by test layer | normative specification changes |
| `examples/` | non-sensitive demonstration repositories | proprietary or production source |
| `notebooks/` | reproducible assignment demonstrations | production runtime logic |
| `report/` | final assignment report sources/artifacts | canonical machine-readable findings |

Dependency direction is inward: applications and integrations may depend on
adapters and Core; adapters may depend on Core ports; Core may depend on
contracts. Core and contracts never import adapters, applications,
infrastructure SDKs or a graph runtime. `WorkflowGraph` and `EvidenceGraph`
remain separate domain concepts.

## Planned adapter namespaces

The accepted layout reserves these adapter families; they are intentionally not
implemented by `P1.1`:

```text
packages/adapters/
  runtime/{local,temporal}/
  persistence/postgres/
  artifacts/{filesystem,s3}/
  sandbox/{oci,kubernetes_gvisor}/
  providers/{fake,openai,anthropic,openai_compatible}/
```

## Development handoff

- `P1.2` owns the installable `pyproject.toml`, Python version decision within
  the accepted baseline, dependency authority and lock file.
- `P1.3` owns formatter, linter, type-checker and unit-test configuration.
- `P1.5` owns the first domain/contract Python modules.
- `P6.12` owns a buildable production/demo `Dockerfile` and web-service launch
  instructions.

Until those tasks are completed, do not interpret the placeholder
`pyproject.toml` or `Dockerfile` as build/install support.

## Durable project documentation

- Current position: `docs/CONTEXT.md`
- Master plan and gates: `docs/PLAN.md`
- Architecture: `docs/ARCHITECTURE.md`
- Frozen specifications: `specs/`
- Change history: `CHANGELOG.md`

No secrets or proprietary source belong in this repository.
