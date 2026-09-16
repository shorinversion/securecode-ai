# SecureCode AI

SecureCode AI is a security-oriented code-audit platform under staged,
evidence-gated development. The frozen definition baseline is `0.2.0`.

## Current academic snapshot

`P9.16` assembles the M-A2026 academic evidence snapshot from effective G4 and
the integrated development candidate. The bounded builder creates
[`report/m-a2026`](report/m-a2026) with a deterministic manifest, Markdown,
self-contained HTML and PDF reports, a machine-readable quality receipt,
clean-replay instructions, an executed notebook, raw benchmark records and a
redacted real-local demo receipt. Its recorded delivery status is `NOT_READY`:
instructor confirmations, durable independent-review receipts and protected
delivery remain pending. It does not claim G7, G9, v1.0,
`PROJECT CLOSED`, or release readiness.

Build and validate an empty local output directory with the locked project
environment:

```powershell
.venv\Scripts\python.exe -I scripts\build_m_a2026_submission.py --output <new-empty-output-directory>
.venv\Scripts\python.exe -I scripts\build_m_a2026_submission.py --validate <new-empty-output-directory>
```

Run the offline pinned CWE-89 product demonstration without network access or
changes to the source checkout:

```powershell
.venv\Scripts\python.exe -I demo\mvp_cwe89_demo.py --output <new-empty-output-directory>
```

The expected manifest reports one vulnerable signal, zero safe-control signals,
zero signals after the reference repair, a suggested patch, and completed
ephemeral validation. It does not claim general product accuracy. For the
executed academic walkthrough, open
[`notebooks/m_a2026_submission.ipynb`](notebooks/m_a2026_submission.ipynb). It
replays that public demonstration, summarizes the 312-cell experiment, shows
the redacted real-local model receipt, and states the bounded interpretation.
Re-execute it with the locked project Python environment registered as a Jupyter
kernel. Re-executing the separate real-model path additionally requires Ollama
on the literal loopback endpoint and the exact model described in the retained
P9.17 receipt; the submission notebook itself makes no model call.

This repository contains the completed specification baseline, reproducible
Python workspace and quality gate, versioned domain/event/model contracts, the
effective G2 deterministic analysis, effective G3 investigation workflow and
effective G4 repair/validation MVP. The M-A2026 candidate adds bounded
JavaScript, TypeScript and Go analysis, a language-neutral ProgramGraph,
conservative CWE portfolio examples, a 312-cell development study and a real
literal-loopback instructor demo. These additions remain development evidence
until their integrated quality, review and protected delivery complete.
`P1.8`
provides
provider-neutral request/result contracts, a hermetic fake, profile-bound
budgets/dialects, fail-closed native outcome normalization, payload/attempt
identity, process-local idempotency and connect-time endpoint authorization.
`P1.9` adds a graph-SDK-independent workflow state machine, replay-complete
transition journal, definition-bound producer admission and a fail-closed
in-memory adapter. Backend, SCM bot, durable runtime and final production
sandbox remain later gate work.

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

The runner first executes the read-only specification snapshot gate, then checks
every Python file under `packages/`, `apps/`, `integrations/`, `scripts/` and
`tests/` except the immutable G0 validator. Static format, lint and strict-type
checks must pass before repository tests may execute. Child processes receive a
minimal credential/proxy/injection-free environment, each stage is bounded by a
timeout, pytest plug-in autoloading is disabled, and any non-ignored repository
mutation fails the run. Unit tests also deny common socket and child-process
APIs as a defense-in-depth test boundary; this is not a substitute for the
product sandbox delivered in later phases.

Branch coverage is measured against `securecode_ai.core` alone and must be at
least 80%. The threshold is a regression gate, not a claim that coverage alone
proves security or product quality.

## Specification and candidate gate

`scripts/spec_gate.py` has three read-only entry modes. `snapshot` validates the
current frozen baseline, requirement IDs and traceability, Draft 2020-12
schemas, indexed examples and exact public-schema bytes. `index-candidate`
checks the exact staged delta against an authoritative base and rejects any
unstaged or untracked byte. `committed-candidate` is the corresponding CI mode;
the `ci` wrapper selects snapshot only for manual dispatch and otherwise uses
the event-provided base and candidate commit IDs.

```powershell
.\.venv\Scripts\python.exe -I scripts/spec_gate.py snapshot
.\.venv\Scripts\python.exe -I scripts/spec_gate.py index-candidate --base <40-hex-base>
```

Candidate admission is closed to one implementation packet, completion
attestation, D-026 gate-evidence proposal, immutable independent-review receipt
or byte-exact gate promotion. Mixed and unknown kinds fail. This is local
logical enforcement; protection against a candidate replacing its own CI or
gate implementation still depends on the external `P1.4` ruleset evidence.

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
dependency audit, specification/candidate validation and the Python 3.12–3.14
quality matrix. The spec job uses full history and event-authoritative base and
candidate SHAs. The stable aggregate status is `ci / gate`; skipped, cancelled
or failed mandatory jobs make it fail.

The repository has a configured GitHub `origin`. `P1.4` is complete: protected
rules require the stable `ci / gate` result, an intentional failing pull request
was blocked, and a later ordinary pull request confirmed the successful path
without bypass. Full untrusted-code execution isolation remains a separate
scanner and agent boundary; the CI workflow uses ephemeral GitHub-hosted runners
with no declared secrets, write/OIDC permission, cache or persisted checkout
credential.

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

The completed `P1.12` increment keeps operational telemetry inside
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
- `P1.4` completed the pre-commit and protected CI path, including secret and
  dependency policy jobs, blocking evidence and a later green no-bypass pull
  request.
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
- `P1.12` completed an independently specified internal-telemetry increment. Its
  14-path packet passed product/architecture/security-evaluation review before
  implementation; the same roles accepted exact staged digest
  `879f41ceef64e76fb7daab2398f8ab39e8559cd4`. Clean post-commit verification on
  `5ace16e80730d56f994cb6a24fa4748867a49646` passes 162 targeted and all 885
  repository tests, Ruff/mypy, 85.80% Core branch coverage, schema check and
  strict G0.
- `P1.13` completed the offline specification/candidate gate, closed D-026
  completion/review/promotion records and mandatory CI composition. Its clean
  implementation checkpoint is `307a24a71cea25829c0b5541494bf01e13a2e6ed`;
  effective G1 through G4 evidence is recorded in `docs/CONTEXT.md`.
- `P6.12` owns a buildable production/demo `Dockerfile` and web-service launch
  instructions.

The clean Python install, foundation CLI entry point, offline CWE-89 demo and
M-A2026 submission notebook are supported. Production server, SCM integration
and protected-delivery claims remain governed by their later tasks.

## Durable project documentation

- Current position: `docs/CONTEXT.md`
- Master plan and gates: `docs/PLAN.md`
- Architecture: `docs/ARCHITECTURE.md`
- Frozen specifications: `specs/`
- Change history: `CHANGELOG.md`

No secrets or proprietary source belong in this repository.
