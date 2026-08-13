# SecureCode AI

SecureCode AI is a security-oriented code-audit platform under staged,
evidence-gated development. The frozen definition baseline is `0.2.0`; the
current implementation phase is `P1 — Engineering Foundation`.

This repository contains the completed specification baseline, the `P1.1`
ownership skeleton and the reproducible `P1.2` Python workspace. It does
**not** yet contain a working scanner, agent workflow, backend, SCM bot or
sandbox.

## Reproducible Python environment

The workspace supports CPython `>=3.12,<3.15`; `.python-version` selects the
mature `3.13` line for local development. The project command is pinned to
`uv 0.12.0`. From a fresh clone, after installing that uv release, the complete
non-editable runtime environment is created in one instruction:

```powershell
uv sync --locked --no-dev --no-editable
```

`--locked` rejects metadata/lock drift instead of silently resolving new
versions. `--no-editable` builds and installs all first-party distributions,
so the clean-install path does not depend on source-tree import behavior.

The root `uv.lock` is the only resolved Python dependency authority. It covers
all workspace members, exact transitive versions, registry artifact hashes and
the build-backend dependency. Do not add a second `requirements.txt`, nested
lockfile, VCS dependency or mutable URL dependency. A dependency update is an
explicit reviewed change: update the relevant package metadata, regenerate
with pinned uv, inspect `uv.lock`, then require `uv lock --check` and the clean
install oracle to pass.

Current first-party package graph:

```text
securecode-ai-adapters
  -> securecode-ai-core
       -> securecode-ai-contracts
            -> pydantic v2
```

All three distributions are private pre-alpha packages under the shared
implicit namespace `securecode_ai`. Their `__init__.py` files are packaging
markers only; P1.5 owns the first domain models and behavior.

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

- `P1.2` completed the uv workspace, Python compatibility decision, private
  installable package boundaries and the single locked dependency authority.
- `P1.3` owns formatter, linter, type-checker and unit-test configuration.
- `P1.5` owns the first domain/contract Python modules.
- `P6.12` owns a buildable production/demo `Dockerfile` and web-service launch
  instructions.

The current `Dockerfile` remains a non-buildable ownership marker until P6.12;
the clean Python install above is supported, but no product entry point exists
yet.

## Durable project documentation

- Current position: `docs/CONTEXT.md`
- Master plan and gates: `docs/PLAN.md`
- Architecture: `docs/ARCHITECTURE.md`
- Frozen specifications: `specs/`
- Change history: `CHANGELOG.md`

No secrets or proprietary source belong in this repository.
