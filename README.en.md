# SecureCode AI

[Русский](README.md) | **English**

[Video (RU), 2:40](docs/media/securecode-demo.mp4) · [Final report (RU)](report/final-submission.html) · [Benchmark](report/submission-benchmark/report.html) · [Notebook](notebooks/securecode_demo.ipynb) · [Project site](https://mydev.stream/) · [Releases](https://github.com/shorinversion/securecode-ai/releases)

SecureCode AI is a local AI assistant for security auditing of Python, JavaScript,
TypeScript and Go code. Deterministic tools (AST, secrets, vulnerable dependencies,
CWE scanners) and a quantized LLM acting as the **Auditor** and the **Architect** find
vulnerabilities, propose fixes as diffs and validate them in an ephemeral copy; the
result is a report classified by OWASP Top 10.

> **Status: 1.0.** The Auditor → Architect demo completes with `COMPLETED` on local
> Qwen 2.5 Coder 7B Q4_K_M and on DeepSeek: CWE-89 is found and the patch is validated.
> On 600 CVEfixes cases the scanners + LLM combination is on par with Semgrep in recall,
> not better. Production readiness is not claimed.

## Quick start

```bash
python deploy/docker/quickstart.py --demo
```

Only Docker is required. The command builds the image, audits the vulnerable demo code
and prints the report: finding, CWE, OWASP Top 10 category, line and, with a model,
the validated Auto-Fix patch. With `DEEPSEEK_API_KEY` in the environment or the root
`.env`, the Auditor and Architect run on DeepSeek; without it only the deterministic
lane runs (outcome `INDETERMINATE`).

```bash
python deploy/docker/quickstart.py --demo --provider local
```

The same run on a local quantized Qwen: needs [uv](https://docs.astral.sh/uv/) and a
running [Ollama](https://ollama.com); the `qwen2.5-coder:7b-instruct-q4_K_M` model
(about 4.7 GB) is pulled automatically. Reports go to `output/demo-report/`.

A full walkthrough of the tools (AST, secrets, vulnerable dependencies, CWE scanners,
the unified contract, agents, report, metrics) with stored outputs:
[notebooks/securecode_demo.ipynb](notebooks/securecode_demo.ipynb).

## Overview

SecureCode AI audits an exact Git revision, combines deterministic discovery
with independent local-model investigation, normalizes candidates into one
evidence graph, and publishes a result only after mandatory interpretation and
validation. Repairs are retained as separate artifacts, validated in an
ephemeral environment, and never applied to the source checkout without an
explicit approval.

The main product surfaces are:

- a standalone CLI for local audits, repair proposals, and validation;
- a Linux worker for exact-run CI execution;
- an ASGI control plane with a queue, run state, approvals, and an audit trail;
- GitHub and GitLab adapters for exact-SHA status and bounded publication;
- reproducible academic experiments, notebooks, and reports.

## Architecture

```text
Git checkout at an exact commit
             |
             v
  deterministic discovery  +  model-native discovery
             \                    /
              v                  v
           normalized candidates
                     |
                     v
          Auditor and Skeptic checks
                     |
                     v
      EvidenceGraph + policy decision + reports
                     |
          +----------+-----------+
          |                      |
          v                      v
   local CLI / worker      control plane / SCM
```

The two graphs have separate responsibilities:

- `WorkflowGraph` controls transitions, budgets, retries, approvals, and stop
  conditions;
- `EvidenceGraph` links findings, source locations, tool/model observations,
  patches, validation, and provenance.

Domain behavior lives in `packages/core/` and does not depend on a transport or
graph runtime. `packages/contracts/` owns closed Pydantic contracts and JSON
Schema. `packages/adapters/` implements Git, CST, model, sandbox, and SCM
boundaries. The CLI, server, and worker compose these shared layers.

Read the [architecture](docs/ARCHITECTURE.md),
[product model](docs/PRODUCT.md), and
[threat model](docs/security/THREAT_MODEL.md) for the detailed design.

## Supported languages and CWEs

| Area | Current implementation | Boundary |
| --- | --- | --- |
| Python | `.py`, `.pyi`; AST and CST, symbol index, CWE-89 and about 30 other CWE scanners | Coverage depends on supported source/sink patterns |
| JavaScript / TypeScript | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`; CST, symbol index, CWE-89 and about 30 other CWEs | TypeScript types do not make this a full compiler pass |
| Go | `.go`; CST, symbol index, CWE-89 and about 30 other CWEs | A limited set of verified patterns |
| All files | hardcoded secrets; pip, npm and Go manifests checked against OSV | Secret values are never stored |

The scanners cover injection (CWE-78, 79, 89, 90, 94), path traversal (22), SSRF
(918), missing authorization and authentication (862, 306), unsafe deserialization
(502), weak cryptography and randomness (327, 338), hardcoded credentials (798),
ReDoS (1333) and more. Each CWE maps to an OWASP Top 10 2021 category.

This is an inventory of implemented rules. It is not a complete-CWE coverage
claim or a claim of superiority over SAST. The current 600-case comparison is
in the [submission benchmark](report/submission-benchmark/README.md). The earlier
development benchmark and its limits remain available separately:
[protocol and results](report/development-benchmark/README.md),
[limitations](report/development-benchmark/limitations.md).

## Candidate verification

`uv run --locked python -I scripts/quality.py` runs Ruff format and lint, mypy for
Linux and Windows, and pytest (unit tests plus the demo integration tests) with an 80%
core coverage floor. On the current `main` it reports `QUALITY=PASS` with 3292 tests;
CI repeats these checks on Python 3.12, 3.13 and 3.14 and also scans secrets and
dependencies.

## Requirements and installation

- Git;
- CPython `>=3.12,<3.15`;
- [uv](https://docs.astral.sh/uv/) exactly `0.12.0`;
- Docker for server/worker images, isolated repair validation, and the opt-in
  corpus oracle;
- Ollama only for the local model path.

From a clean clone:

```powershell
git clone <repository-url> securecode-ai
Set-Location securecode-ai
uv --version
uv sync --locked --no-dev --no-editable
uv run --locked --offline --no-sync securecode --version
```

`uv.lock` is the single resolved Python dependency authority. `--locked`
rejects lock drift, and `--no-editable` verifies the installed path instead of
importing directly from the source tree. Install the quality group for
development:

```powershell
uv sync --locked --no-editable --group quality
```

## Model-free quickstart

The reproducible public demo does not read private code, call an LLM, or change
the source checkout:

```powershell
$output = Join-Path $PWD '.securecode/demo-cwe89'
New-Item -ItemType Directory -Path $output | Out-Null
uv run --locked --offline --no-sync python -I demo/mvp_cwe89_demo.py --output $output
```

The bounded expected result is one CWE-89 signal for the vulnerable Python
fixture, zero signals for the safe control, a proposed reference repair, and
validation in an ephemeral copy.

Basic installed CLI diagnostics:

```powershell
uv run --locked --offline --no-sync securecode doctor
uv run --locked --offline --no-sync securecode scan . --diagnostic --format json
```

A full `securecode scan` requires a protected host approval record and exact
matches for the approved profile, policy, provider evidence, and Git executable.
Missing or changed authority fails closed.

## Local Ollama configuration

The recorded academic path uses literal loopback and these exact values:

| Setting | Value |
| --- | --- |
| Endpoint | `http://127.0.0.1:11434/v1` |
| Ollama | `0.34.4` |
| Model | `qwen2.5-coder:7b-instruct-q4_K_M` |
| Quantization | `Q4_K_M` |
| Expected model digest | `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364` |

To repeat the current real-local demonstration, start Ollama locally and pull
the model. The command does not contact a cloud provider:

```bash
uv run --locked python -I demo/p917_real_local_demo.py --repository demo/fixtures/real-local-cwe89 --output output/demo-report
```

The report is `output/demo-report/security-report.md` (and `.html`); the fixture is
read from an immutable snapshot and never modified.

The retained redacted receipt is
[`current-real-local-p917.json`](report/submission-benchmark/evidence/current-real-local-p917.json).
In the 29 September 2026 run Qwen found the CWE-89 candidate the deterministic
scanner also reported and proposed a parameterized query; the patch parsed, the
rescan found 0 signals, `outcome=COMPLETED`, and the source checkout was unchanged.

The same scenario runs on DeepSeek (profile `deepseek-owner-authorized`, owner
consent recorded in [`deploy/deepseek/owner-consent.json`](deploy/deepseek/owner-consent.json)).
The key comes from `DEEPSEEK_API_KEY` or a `DEEPSEEK_API_KEY=...` line in the
repository-root `.env` (ignored by Git); spend is capped at $0.10 per run.

```bash
uv run --locked python -I demo/p917_real_local_demo.py --repository demo/fixtures/real-local-cwe89 --output output/demo-report --provider deepseek
```

Receipt: [`current-deepseek-p917.json`](report/submission-benchmark/evidence/current-deepseek-p917.json)
(`outcome=COMPLETED`, 2 calls, $0.00014). DeepSeek retention and training terms
are not verified; send only code you are entitled to disclose.

Example local preparation:

```powershell
$env:OLLAMA_HOST = '127.0.0.1:11434'
ollama serve
```

In another terminal:

```powershell
ollama pull qwen2.5-coder:7b-instruct-q4_K_M
ollama list
uv run --locked --offline --no-sync python -I demo/p917_real_local_demo.py --help
```

Before source dispatch, the gateway checks bounded `/api/version` and
`/api/tags` responses, exact model name and digest, and repeats the identity
check after generation. Arbitrary `SECURECODE_LLM_*` overrides for endpoint,
model, or API key are intentionally unavailable. The product accepts selectors
for already approved values only:

```powershell
$env:SECURECODE_PROVIDER_PROFILE = 'local-source-model@1.0.0'
$env:SECURECODE_POLICY_PROFILE = 'private-model-source'
$env:SECURECODE_EGRESS_PROFILE = 'private_model_zdr'
```

Selectors do not create or admit an approval record. The installed product path
also needs OS-protected authority in HKLM on Windows or root-owned files on
Linux. This repository does not provide a general end-user provisioning command
for that authority.

## Online DeepSeek for the benchmark

The tested online provider was DeepSeek V4.1 Flash (`deepseek-flash`), with temperature `0`, JSON mode, and reasoning disabled. The benchmark sends source only from the public CVEfixes corpus. Do not use this route for private repositories: it makes direct classification API calls and is not the complete SecureCode product pipeline.

Set the key only in the current PowerShell process. Never save it in Git, README, notebooks, or reports:

```powershell
$secureKey = Read-Host 'DeepSeek API key' -AsSecureString
$env:DEEPSEEK_API_KEY = [System.Net.NetworkCredential]::new('', $secureKey).Password
$env:DEEPSEEK_BASE_URL = 'https://api.deepseek.com'
$env:DEEPSEEK_MODEL = 'deepseek-flash'
```

A short run needs the local CVEfixes SQLite v1.0.8 database and an explicit spend guard. Replace `$database` with its actual path; this example processes only five public cases:

```powershell
$database = 'C:\data\CVEfixes_v1.0.8.sqlite'
$candidate = (git rev-parse HEAD).Trim()
$profile = (Get-FileHash report/submission-benchmark/evidence/model-profile.json -Algorithm SHA256).Hash.ToLowerInvariant()
New-Item -ItemType Directory -Force output | Out-Null
try {
  uv run --locked --offline --no-sync --group quality python -m scripts.run_release_benchmark `
  --manifest report/submission-benchmark/evidence/cvefixes-manifest.json `
  --database $database --configuration model_native `
  --output output/deepseek-smoke.json --limit 5 --repetitions 1 `
  --allow-public-remote --spend-ledger output/deepseek-smoke-spend.sqlite `
  --budget-phase development --total-budget-microusd 10000000 `
  --candidate-sha $candidate --profile-sha256 $profile `
  --max-input-tokens 1000000 --max-output-tokens 64 `
  --input-microusd-per-million 150000 --output-microusd-per-million 600000
} finally {
  Remove-Item Env:DEEPSEEK_API_KEY -ErrorAction SilentlyContinue
  $secureKey.Dispose()
}
```

To recompute retained results without new API calls, use the [benchmark report](report/submission-benchmark/README.md). DeepSeek in the product worker additionally requires approved provider/egress profiles, spend limits, and protected host approval. API environment variables alone are insufficient, and an end-to-end product benchmark through DeepSeek has not been completed.

## CLI commands

```text
securecode doctor
securecode scan TARGET [--config FILE] [--format json|sarif|markdown|html] [--output FILE]
securecode scan TARGET --diagnostic [--format json|sarif|markdown|html] [--output FILE]
securecode fix TARGET [--format json|sarif|markdown|html|diff] [--output FILE]
securecode validate TARGET --patch SELECTOR [--format json|sarif|markdown|html|diff]
securecode approve TARGET --patch SELECTOR --artifact-sha256 SHA256 \
  --capability SHA256 --approval-id ID --approver-id ID [--output FILE]
securecode release --config FILE
securecode release --config FILE --publish --authorization FILE
```

Examples:

```powershell
securecode scan C:\src\project --format sarif --output C:\reports\securecode.sarif
securecode fix C:\src\project --format json --output C:\reports\repair.json
securecode validate C:\src\project --patch <retained-selector> --format json
securecode release --config C:\release\candidate.json
```

`release` is a dry run by default. Publication requires a separately protected
config, authority key, and short-lived authorization bound to the exact
candidate digest. It writes an immutable local release store, not a GitHub
Release.

| Code | Meaning |
| ---: | --- |
| `0` | completed |
| `2` | policy fail |
| `3` | indeterminate |
| `4` | operational error |
| `5` | invalid usage or configuration |
| `6` | cancelled or superseded |

## Docker server and worker

Build the three local images from the repository root:

```powershell
pwsh -NoProfile -File deploy/docker/build-images.ps1
```

The script creates `securecode-ai/runtime:1.0.1`,
`securecode-ai/server:1.0.1`, and `securecode-ai/worker:1.0.1`, then prints their
immutable image IDs. Linux `amd64` is the default; pass `-Platform linux/arm64`
for ARM64.

The server runs as unprivileged UID `65532`, writes only to
`/var/lib/securecode` and `/tmp/securecode`, requires TLS when bound to
`0.0.0.0`, and needs either OIDC or bootstrap identities on first start:

```bash
docker network create securecode
docker volume create securecode-data
docker run --rm --name securecode-server --network securecode -p 8443:8080 \
  --mount type=volume,src=securecode-data,dst=/var/lib/securecode \
  --mount type=bind,src=/absolute/securecode-secrets,dst=/run/secrets,readonly \
  -e SECURECODE_BOOTSTRAP_TENANT_ID=tenant-1 \
  -e SECURECODE_BOOTSTRAP_ADMIN_TOKEN_FILE=/run/secrets/admin_token \
  -e SECURECODE_BOOTSTRAP_WORKER_TOKEN_FILE=/run/secrets/worker_token \
  -e SECURECODE_BOOTSTRAP_WORKER_REPOSITORIES=repository-1 \
  securecode-ai/server:1.0.1
```

The secrets directory must provide UID `65532` with readable
`securecode_tls_cert`, `securecode_tls_key`, `admin_token`, and `worker_token`
files. The private TLS key must be a regular file without group/other
permissions, the certificate must be trusted by the worker image, and each
token must contain at least 32 characters. Use OIDC and an external secret
manager for production according to the
[threat model](docs/security/THREAT_MODEL.md).

The worker connects to the control plane, claims an exact-run job, executes the
shared Core in the local checkout, and publishes bounded artifacts and metadata:

```bash
docker run --rm --name securecode-worker --network securecode \
  --mount type=bind,src=/absolute/source-checkout,dst=/workspace,readonly \
  --mount type=bind,src=/absolute/securecode-secrets,dst=/run/secrets,readonly \
  -e SECURECODE_CONTROL_PLANE_URL=https://securecode-server:8080 \
  -e SECURECODE_WORKER_TOKEN_FILE=/run/secrets/worker_token \
  -e SECURECODE_WORKER_ID=worker-1 \
  -e SECURECODE_WORKER_TARGET=/workspace \
  securecode-ai/worker:1.0.1
```

Set `SECURECODE_WORKER_RUN_ID` for one specific run. GitLab supplies
`CI_PROJECT_ID`, `CI_MERGE_REQUEST_IID`, and the exact `CI_COMMIT_SHA` instead.
Use `SECURECODE_WORKER_ARTIFACT_HOSTS` to narrow artifact destinations. The
Compose deployment and its required configuration are documented in
[`deploy/docker/README.md`](deploy/docker/README.md). Kubernetes manifests are
not included.

## GitHub CI setup

The included [`.github/workflows/ci.yml`](.github/workflows/ci.yml) is the
project's own CI. It runs for pull requests, merge queues, and pushes to
`master`:

1. validate CI/dependency policy and pinned Actions;
2. scan the current tree and candidate history for secrets;
3. audit the hash-complete locked dependency graph;
4. execute the specification/candidate gate;
5. run the quality matrix on Python 3.12, 3.13, and 3.14;
6. aggregate mandatory jobs into `gate`.

For a fork, enable GitHub Actions and configure branch protection to require
`gate`. The workflow has only `contents: read`, does not persist checkout
credentials, and declares no repository secrets.

For the product GitHub App, configure the control plane with:

- `SECURECODE_GITHUB_API_URL`;
- `SECURECODE_GITHUB_INSTALLATION_ID`;
- `SECURECODE_GITHUB_TOKEN_FILE`;
- `SECURECODE_GITHUB_WEBHOOK_SECRET_FILE`;
- `SECURECODE_SCM_PINS_FILE` and `SECURECODE_SCM_TENANT_ID`.

Point the GitHub App webhook to
`POST /api/v1/integrations/github/webhook`. For GitLab, use
`POST /api/v1/integrations/gitlab/webhook` and set
`SECURECODE_GITLAB_API_URL`, `SECURECODE_GITLAB_TOKEN_FILE`, and
`SECURECODE_GITLAB_WEBHOOK_SECRET_FILE`. Build both URLs from the external
HTTPS address of the control plane.

`SECURECODE_SCM_PINS_FILE` must contain a JSON object with exactly seven keys.
Every pin has `schema_version: "0.2.0"`, a `component_id`, a SemVer `component_version`, and the actual
64-character lowercase SHA-256 of the accepted artifact:
`schema_version` identifies the wire contract, while `component_version`
identifies the accepted component itself.

```json
{
  "stage_catalogue": {"schema_version": "0.2.0", "component_id": "stage-catalogue", "component_version": "1.0.0", "content_sha256": "1111111111111111111111111111111111111111111111111111111111111111"},
  "workflow": {"schema_version": "0.2.0", "component_id": "workflow", "component_version": "1.0.0", "content_sha256": "2222222222222222222222222222222222222222222222222222222222222222"},
  "policy": {"schema_version": "0.2.0", "component_id": "policy", "component_version": "1.0.0", "content_sha256": "3333333333333333333333333333333333333333333333333333333333333333"},
  "configuration": {"schema_version": "0.2.0", "component_id": "configuration", "component_version": "1.0.0", "content_sha256": "4444444444444444444444444444444444444444444444444444444444444444"},
  "provider_profile": {"schema_version": "0.2.0", "component_id": "provider-profile", "component_version": "1.0.0", "content_sha256": "5555555555555555555555555555555555555555555555555555555555555555"},
  "capability_profile": {"schema_version": "0.2.0", "component_id": "capability-profile", "component_version": "1.0.0", "content_sha256": "6666666666666666666666666666666666666666666666666666666666666666"},
  "egress_profile": {"schema_version": "0.2.0", "component_id": "egress-profile", "component_version": "1.0.0", "content_sha256": "7777777777777777777777777777777777777777777777777777777777777777"}
}
```

The repeated digits are placeholders. Replace them with hashes of the accepted
bytes, keep the file outside the checkout, and mount it read-only with mode
`0600`. An extra or missing key, invalid SemVer, or invalid digest blocks
startup.

The App needs Metadata read, Pull requests read/write, Checks read/write,
Contents read, and Code scanning alerts/Security events write only when SARIF
upload is enabled. It does not need Administration, Workflows write, or merge
permissions. Keep installation tokens, webhook secrets, and provider
credentials in separate scopes and lifecycles.

## GitLab CI setup

The root [`.gitlab-ci.yml`](.gitlab-ci.yml) does not execute an untrusted audit
inside the source pipeline. For a same-project merge request, it triggers a
protected downstream project and forwards only project ID, MR IID, and exact
commit SHA.

1. Create a separate trusted audit project on a protected runner.
2. Use [the trusted audit pipeline](deploy/gitlab/trusted-audit.yml) as its CI
   configuration.
3. Replace `registry.example.invalid/...` with the real registry path while
   preserving the reviewed image digest, or review a new digest.
4. In the source project, define protected variables
   `SECURECODE_TRUSTED_AUDIT_PROJECT` and `SECURECODE_TRUSTED_AUDIT_REF`.
5. In the trusted project, define `SECURECODE_ALLOWED_SOURCE_PROJECT_ID`,
   `SECURECODE_CONTROL_PLANE_URL`, and a file-type
   `SECURECODE_WORKER_TOKEN_FILE`. Add `SECURECODE_WORKER_ARTIFACT_HOSTS` when
   needed.
6. In the source project, open **Settings > CI/CD > Job token permissions** and
   add the trusted audit project to the authorized projects allowlist. This
   gives its `CI_JOB_TOKEN` narrow access to the source-project API and MR-head
   ref used by `trusted-audit.yml`.
7. Protect the audit ref and provide a runner with tag `securecode-ai-gpu`.

The pipeline rejects fork MRs, an unexpected project ID, an unprotected ref,
and a SHA that differs from the open MR head. The worker job receives neither
control-plane database access nor SCM write credentials.

## Security model

- The dual lane is mandatory: zero deterministic signals never skips
  model-native discovery.
- A mandatory timeout, refusal, invalid schema, or unavailable provider becomes
  `INDETERMINATE`, never a clean result.
- Analysis is bound to an exact Git SHA; a changed HEAD revokes publication.
- Source stays in the runner by default. Telemetry has no fields for raw source,
  prompts, model replies, patches, credentials, or arbitrary labels.
- A private model endpoint is admitted only on literal loopback after profile,
  policy, and protected host-authority checks.
- Model output is untrusted data and passes closed-schema validation.
- A patch is retained as a digest-bound artifact, validated in isolation, and
  requires a separate approval before any later action.
- Workers do not receive control-plane database or SCM write credentials.
- Secrets must not enter the repository, reports, notebooks, or durable project
  memory. Git ignores `.env`, keys, runtime state, and local outputs.

Read [data classification](specs/security/data-classification.md),
[prompt injection guidance](docs/security/PROMPT_INJECTION.md), and the
[threat model](docs/security/THREAT_MODEL.md).

## Status and limitations

- The Auditor → Architect demo on the CWE-89 fixture completes with `COMPLETED` on
  local Qwen 2.5 Coder 7B Q4_K_M (Ollama 0.34.4) and on DeepSeek Flash: the finding
  matches the deterministic scanner, and the patch passes parsing, a rescan and
  `git apply --check`. Receipts:
  [Qwen](report/submission-benchmark/evidence/current-real-local-p917.json),
  [DeepSeek](report/submission-benchmark/evidence/current-deepseek-p917.json).
  The demo covers one rule; no behavioral tests are run on the patch.
- 600-case CVEfixes benchmark: the deterministic lane completed 508 cases (92
  unparseable files count as incomplete), and the hybrid reached 32.8% held-out recall
  versus 32.5% for Semgrep; the interval includes zero, so the hybrid is on par with
  SAST but not better. The model lanes are direct DeepSeek classifications, not the full
  Auditor/Skeptic pipeline, and repair was not evaluated on the corpus. Precision is
  near 50% for every configuration. Details:
  [benchmark report](report/submission-benchmark/README.md).
- A full `securecode scan` needs pre-provisioned OS-protected authority; a general
  provisioning workflow is not published, so reviewers should use the demo and the
  notebook.
- Server/worker Docker images and Compose exist; `quickstart.py --up` was not
  re-verified on Linux and there is no verified production deployment. The GitLab
  trusted worker image path is an explicit placeholder.
- Production readiness is not claimed; quality receipts establish reproducibility,
  not the absence of vulnerabilities.

See [current context](docs/CONTEXT.md) and the [canonical plan](docs/PLAN.md)
for current task and gate status.

## Repository layout

| Path | Purpose |
| --- | --- |
| `apps/cli/` | `securecode` command |
| `apps/server/` | ASGI control plane and maintenance CLI |
| `apps/worker/` | one-shot and connected Linux worker |
| `packages/contracts/` | versioned domain, event, model, and runtime contracts |
| `packages/core/` | framework-independent workflow, evidence, policy, repair, and evaluation logic |
| `packages/adapters/` | Git, CST, provider, sandbox, report, and SCM adapters |
| `integrations/` | GitHub/GitLab transport integration boundaries |
| `deploy/` | Dockerfiles and GitLab trusted audit pipeline |
| `specs/` | accepted normative specifications and schemas |
| `tests/` | unit, contract, integration, negative, and security regression tests |
| `demo/` | public offline demo and real-local Ollama demo |
| `evaluation/` | development corpus, run plan, and machine-readable results |
| `notebooks/` | reproducible academic notebooks |
| `report/` | academic bundle and development benchmark |
| `artifacts/gates/` | retained gate evidence packets |
| `docs/` | architecture, product, decisions, plan, research, and security docs |

## Development commands

```powershell
uv run --locked --offline --no-sync --group quality python -I scripts/quality.py
uv run --locked --offline --no-sync --group quality ruff format --check .
uv run --locked --offline --no-sync --group quality ruff check .
uv run --locked --offline --no-sync --group quality mypy
uv run --locked --offline --no-sync --group quality pytest tests/unit -q
```

Hooks:

```powershell
uv run --locked --offline --no-sync --group quality pre-commit install --hook-type pre-commit --hook-type pre-push
uv run --locked --offline --no-sync --group quality pre-commit run --all-files
```

## Academic reproducibility

- [M-A2026 Markdown report](report/m-a2026/report.md)
- [M-A2026 self-contained HTML](report/m-a2026/report.html)
- [M-A2026 PDF](report/m-a2026/report.pdf)
- [Delivery manifest](report/m-a2026/delivery-manifest.json)
- [Quality receipt](report/m-a2026/quality-receipt.json)
- [Clean replay](report/m-a2026/clean-replay.md)
- [Executed notebook](notebooks/m_a2026_submission.ipynb)
- [Offline CWE-89 demo](demo/mvp_cwe89_demo.py)
- [Development corpus](evaluation/development/README.md) and its
  [manifest](evaluation/development/corpus-manifest.yaml)
- [Raw run records](evaluation/development/results/run-records.jsonl),
  [aggregate](evaluation/development/results/aggregate.json), and
  [independent recomputation](evaluation/development/results/recomputed.json)
- [Benchmark protocol and results](report/development-benchmark/README.md) and
  [limitations](report/development-benchmark/limitations.md)
- [Expanded 600-case submission benchmark](report/submission-benchmark/README.md),
  [HTML report](report/submission-benchmark/report.html),
  [machine-readable metrics](report/submission-benchmark/aggregate.json),
  [stratified table](report/submission-benchmark/stratified-metrics.csv), and
  [PDF report](site/benchmark.pdf)
- [Final HTML project report with the current local-model run](report/final-submission.html)
- [Redacted Qwen receipt](report/submission-benchmark/evidence/current-real-local-p917.json)
- [Video](docs/media/securecode-demo.mp4) and [narration script](docs/media/narration.ru.txt)

The primary external benchmark dataset is [CVEfixes v1.0.8 on Zenodo](https://zenodo.org/records/13118970).
This repository contains the source-free manifest and its builder, not the
SQLite database or vulnerable project source. The manifest records the license
as NOASSERTION; check the dataset terms and individual source repository
licenses before redistributing those materials.

The archived M-A2026 bundle is bound to the exact `subject_sha256` recorded in
`quality-receipt.json`. It is retained as academic evidence and is intentionally
not reissued for every later product change. The recorded commit is a base
anchor, not a complete snapshot of the subject. Full replay therefore requires
the separately preserved exact subject bytes; this repository does not contain
a Git ref for them. On the current release-candidate checkout the validator must
reject the archived bundle after the subject changes. A new bundle is published
only with a new quality receipt bound to the candidate's exact bytes.

The notebook replays the public synthetic demo and reads the retained aggregate
and redacted local receipt. Its normal replay makes no model call.

The current full test run and canonical quality check can fail. See the
[final HTML report](report/final-submission.html) for the exact observed status;
the existence of test files is not evidence that this checkout passes them.

The current full test run and canonical quality check can fail. See the
[final HTML report](report/final-submission.html) for the exact observed status;
the existence of test files is not evidence that this checkout passes them.

## License

The current tree has no root `LICENSE`, and package metadata says
`Private :: Do Not Upload`. No public license to use, modify, or redistribute
this code is therefore granted at this time. Before public publication, the
repository owner must add the chosen license and review licenses for external
datasets, models, and dependencies. The self-authored educational corpus in
`evaluation/development/` is separately identified as `CC0-1.0`.
