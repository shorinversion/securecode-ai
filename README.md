# SecureCode AI

SecureCode AI is a security-oriented code-audit platform under staged,
evidence-gated development. The frozen definition baseline is `0.2.0`; the
current implementation phase is `P1 — Engineering Foundation`.

This repository contains the completed specification baseline, the `P1.1`
ownership skeleton, the reproducible `P1.2` Python workspace, the `P1.3`
quality gate, versioned domain contracts and the current `P1.6` append-only
event-stream candidate. It does
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

## Deterministic quality gate

Provision the exact non-editable runtime plus the locked quality tool group:

```powershell
uv sync --locked --exact --no-editable --group quality
```

Then run the canonical gate without dependency resolution or network access:

```powershell
uv run --locked --offline --no-sync --group quality python -I scripts/quality.py
```

The runner checks every Python file under `packages/`, `apps/`, `integrations/`,
`scripts/` and `tests/` except the immutable G0 validator. Static format, lint and strict-type
checks must pass before repository tests may execute. Child processes receive a
minimal credential/proxy/injection-free environment, each stage is bounded by a
timeout, pytest plug-in autoloading is disabled, and any non-ignored repository
mutation fails the run. Unit tests also deny common socket and child-process
APIs as a defense-in-depth test boundary; this is not a substitute for the
product sandbox delivered in later phases.

Branch coverage is measured against `securecode_ai.core` alone and must be at
least 80%. Core currently contains only its packaging marker, so the displayed
100% is evidence that the gate is wired—not a claim of behavioral test quality.

## Local pre-commit checks

After provisioning the locked quality group, install both supported hook types:

```powershell
uv run --locked --offline --no-sync --group quality pre-commit install --hook-type pre-commit --hook-type pre-push
uv run --locked --offline --no-sync --group quality pre-commit run --all-files
```

The hooks run four closed commands: CI/dependency policy validation, staged
secret detection, offline strict workflow analysis and the canonical quality
gate. A standard-library launcher resolves `uv 0.12.0` from the project
`.venv` on Windows or POSIX, checks its version and fails if the locked
environment is missing. It does not download a second hook environment.

## GitHub CI and merge protection

The single workflow `.github/workflows/ci.yml` runs on pull requests, merge
queues and pushes to `master`. It pins every action to a full commit SHA,
persists no checkout credential, disables action/dependency caches and grants
only `contents: read`. Mandatory jobs are policy, secret-history scan, locked
dependency audit and the Python 3.12–3.14 quality matrix. The stable aggregate
status is `ci / gate`; skipped, cancelled or failed mandatory jobs make it fail.

The repository has no GitHub remote yet, so CI configuration alone is **not a
merge guarantee**. Before `P1.4` can be accepted, the repository owner must:

1. push the reviewed commit to GitHub;
2. protect `master` with a ruleset requiring `ci / gate` and merge-queue checks;
3. require trusted review for changes to `.github/workflows/**`,
   `scripts/ci_policy.py`, `.secrets.baseline` and branch/ruleset policy;
4. demonstrate that a deliberately failing pull request cannot merge and retain
   the ruleset/check-run receipt as gate evidence.

Until that external evidence exists, the local P1.4 implementation is a
verified candidate and the task remains open. Full untrusted-code execution
isolation belongs to the later scanner/agent sandbox phases; the P1 workflow
is configured for an ephemeral GitHub-hosted runner with no declared
secrets, write/OIDC permission, cache or persisted checkout credential.

Current first-party package graph:

```text
securecode-ai-adapters
  -> securecode-ai-core
       -> securecode-ai-contracts
            -> pydantic v2
```

All three distributions are private pre-alpha packages under the shared
implicit namespace `securecode_ai`. Adapters remains a packaging marker. The
contracts package now owns stable-ID derivation, closed Pydantic v2 models and
six checked-in Draft 2020-12 JSON Schemas for `AuditRun`, `FindingCase`,
`Evidence`, `PatchCandidate`, `ValidationResult` and `AuditEvent`; it
deliberately imports no provider, SCM, database or graph-runtime SDK.
Conformance requires both structural JSON Schema validation and its resolvable
`x-securecode-semantic-validator`. Core owns the immutable, hash-linked
in-memory `EventStream` and `RunProjection`; provider
execution, persistence and workflow runtime remain owned by later P1 tasks.
The exact schema drift command is in the contracts package README.

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
- `P1.3` completed the pinned Ruff/mypy/pytest quality toolchain and the single
  fail-closed local/CI entrypoint described above.
- `P1.4` has a locally verified pre-commit/CI candidate, including secret and
  dependency policy jobs; external GitHub ruleset and failing-PR evidence are
  still required before completion.
- `P1.5` completed the versioned domain contracts and independent acceptance.
- `P1.6` has a locally verified append-only event/stable-ID candidate awaiting
  independent product, architecture and security/evaluation acceptance.
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
