# SecureCode AI

SecureCode AI is a security-oriented code-audit platform under staged,
evidence-gated development. The frozen definition baseline is `0.2.0`; the
current implementation phase is `P1 — Engineering Foundation`.

This repository contains the completed specification baseline, reproducible
Python workspace and quality gate, versioned domain/event/model contracts, the
completed `P1.7` secret-safe configuration, `P1.8` model boundary and `P1.9`
workflow-runtime substrate, the completed `P1.10` foundation CLI and the
completed `P1.11` fixture-repository factory. The current `P1.12` candidate
adds internal exact-version structured telemetry without creating a new public
wire contract.
`P1.8`
provides
provider-neutral request/result contracts, a hermetic fake, profile-bound
budgets/dialects, fail-closed native outcome normalization, payload/attempt
identity, process-local idempotency and connect-time endpoint authorization.
`P1.9` adds a graph-SDK-independent workflow state machine, replay-complete
transition journal, definition-bound producer admission and a fail-closed
in-memory adapter. It does **not** yet contain a working scanner, model agent,
backend, SCM bot, durable runtime or sandbox.

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
least 80%. The threshold is a regression gate, not a claim that coverage alone
proves security or product quality.

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
implicit namespace `securecode_ai`. The contracts package owns stable-ID
derivation, closed Pydantic v2 models and fifteen checked-in Draft 2020-12 JSON
Schemas: the original domain/event/model roots plus `WorkflowDefinition`,
`WorkflowRuntimeRequest`, `WorkflowRuntimeResult`, `WorkflowSnapshot` and
`WorkflowTransitionEvent`; it deliberately imports no provider, SCM, database
or graph-runtime SDK.
Conformance requires both structural JSON Schema validation and its resolvable
`x-securecode-semantic-validator`. Core owns the immutable, hash-linked
`EventStream`/`RunProjection`, the two-phase model/egress authorization boundary
and the exact-definition workflow transition rules. Adapters owns the hermetic
provider fake, native-envelope normalization, endpoint peer checks and the
lock-backed process-local `LocalWorkflowRuntime`. Live provider HTTP, durable
persistence and external workflow engines remain outside this increment.
The exact schema drift command is in the contracts package README.

The locally verified `P1.12` candidate keeps operational telemetry inside
Core: closed event/measurement enums, authority-issued trace/span IDs,
canonical DC1-only JSONL, exact result precedence and an emitter-issued guarded
payload capability. First-party in-memory and binary-stream sinks independently
validate its exact object identity inside the active, unchanged
`TelemetryEmitter.emit` execution environment before storage or I/O; the
capability expires when synchronous fan-out returns. Raw source, prompts, model
responses, patches, exceptions, credentials, tenant/repository identifiers and
arbitrary labels have no telemetry input slot. This is structural
non-disclosure, not semantic taint proof for a valid-shaped numeric value. No
public schema, OpenTelemetry dependency, network exporter, persistence or P2
instrumentation is introduced. This process-local object contract is not a
Python runtime sandbox: coordinated mutation of code objects, frames, closure
cells or resolved runtime objects is outside `P1.12`.

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
- `P1.6` completed append-only events/stable IDs after independent product,
  architecture and security/evaluation acceptance.
- `P1.7` completed immutable provider profiles, selection-only precedence and
  registry/host-bound ephemeral credential leases after independent acceptance.
- `P1.8` completed provider/egress preflight, issuer-owned single-use permits,
  SSRF/rebinding-safe endpoint authorization, normalized non-success outcomes,
  lock-backed process-local idempotency and a no-network fake.
- `P1.9` completed public workflow contracts,
  exact-definition dual-lane routing, bounded loop accounting, replay-complete
  transition events and a process-local in-memory runtime after independent
  product/architecture/security-evaluation acceptance and clean post-commit
  verification on implementation commit `0431ba66f2a288ee1978950fb01e77e5430c5f04`.
- `P1.10` completed the installable `securecode` entry point, stable exit/error
  contracts and the source-free `doctor` diagnostic after independent
  product/architecture/security-evaluation acceptance and clean post-commit
  verification on implementation commit
   `a0dd7849db3e372ca5cc396706f3a166329a1f8a`. It exposes no
   scan/fix/validate/apply/ci behavior and does not claim product scan readiness.
- `P1.11` completed six opaque, non-sensitive
  Python repository templates and a test-only deterministic factory. Evaluator
  tree hashes were frozen first in commit
  `ad84f403224af55db19b8e2e2e3374e8f178f669`; path-specific LF checkout policy
  preserves those bytes on Windows/POSIX. Product, architecture and
  security/evaluation reviews accepted exact digest
  `f194a1bd66da95642a37487a743144389f229699`; clean post-commit verification on
  `f2bb7cbbcfe3e1e80e1c236300c755315fa561bc` passes 43 targeted and 739 full
  tests, Ruff/mypy, 89.72% Core branch coverage, schema check and strict G0.
- `P1.12` is an independently specified internal-telemetry candidate. Its
  14-path packet passed product/architecture/security-evaluation review before
  implementation; 162 targeted and all 885 repository tests currently pass
  with Ruff/mypy and 85.80% Core branch coverage, while exact staged-digest
  reviews and clean post-commit evidence remain required before completion.
- `P6.12` owns a buildable production/demo `Dockerfile` and web-service launch
  instructions.

The current `Dockerfile` remains a non-buildable ownership marker until P6.12.
The clean Python install and foundation CLI entry point are supported, but the
product scan commands remain intentionally unavailable until their later tasks.

## Durable project documentation

- Current position: `docs/CONTEXT.md`
- Master plan and gates: `docs/PLAN.md`
- Architecture: `docs/ARCHITECTURE.md`
- Frozen specifications: `specs/`
- Change history: `CHANGELOG.md`

No secrets or proprietary source belong in this repository.
