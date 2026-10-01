# SecureCode AI

[![CI](https://github.com/shorinversion/securecode-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/shorinversion/securecode-ai/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/shorinversion/securecode-ai)](https://github.com/shorinversion/securecode-ai/releases)
![Python](https://img.shields.io/badge/python-3.12%20%7C%203.13%20%7C%203.14-blue)

[Русский](README.md) | **English**

SecureCode AI is a multi-agent assistant for security auditing of Python,
JavaScript/TypeScript and Go code. It finds vulnerabilities, classifies them by CWE and
OWASP Top 10 and proposes fixes as diffs that are validated automatically before they are
reported. The model can run locally, so source code does not leave the developer's machine.

[Project site](https://mydev.stream/) ·
[Final report](https://mydev.stream/final-submission.html) ·
[Experiments](https://mydev.stream/benchmark.html) ·
[Notebook](notebooks/securecode_demo.ipynb) ·
[Releases](https://github.com/shorinversion/securecode-ai/releases)

## Video

https://github.com/user-attachments/assets/64b92705-5b49-4424-b656-cb100d147ece

The Russian version is in [README.md](README.md#видео).

## Features

- **Analysis tools** built on `ast` and `tree-sitter`: deterministic rules for 35 CWEs,
  hard-coded secret detection, pip, npm and Go dependency checks against OSV.
- **Four LLM agents:** Discovery, Auditor, Skeptic and Architect (see [Architecture](#architecture)).
- **Validated fixes:** every diff applies to the analysed revision (`git apply --check`),
  parses and passes a rescan.
- **Reports** in Markdown, HTML, JSON and SARIF: CWE, OWASP Top 10 2021 category,
  severity, code fragment and fix.
- **Unified tool contract:** every signal carries the rule (CWE), path, lines and a
  reference to the code fragment.
- **Model choice:** local quantized Qwen 2.5 Coder 7B (Ollama) or DeepSeek over its API.
- **CI integration:** GitHub and GitLab, SARIF for GitHub code scanning.

## Architecture

```text
          Git revision (exact commit)
                    │
      ┌─────────────┴─────────────┐
      ▼                           ▼
deterministic scanners      Discovery (LLM)
      └─────────────┬─────────────┘
                    ▼
       evidence graph (EvidenceGraph)
                    │
                    ▼
      Auditor → Skeptic → finding decision
                    │
                    ▼
      Architect: diff + validation
                    │
                    ▼
      report: CWE, OWASP Top 10, fixes
```

| Agent | Task |
| --- | --- |
| Discovery | Explores the code independently of the scanners and proposes vulnerability candidates |
| Auditor | Checks a candidate: does untrusted data reach a dangerous operation across a trust boundary |
| Skeptic | Tries to refute the Auditor: looks for sanitization, a safe API, an unreachable path |
| Architect | Writes a minimal fix for a confirmed finding; the patch is validated before it is reported |

Claim verification follows the open methodologies of
[Anthropic](https://github.com/anthropics/claude-code-security-review) and
[Cloudflare](https://github.com/cloudflare/security-audit-skill). Details:
[architecture](docs/ARCHITECTURE.md), [threat model](docs/security/THREAT_MODEL.md).

## Quick start

Demonstration on a vulnerable example in Docker:

```bash
python deploy/docker/quickstart.py --demo
```

With the local model ([uv](https://docs.astral.sh/uv/) and [Ollama](https://ollama.com)
required; `qwen2.5-coder:7b-instruct-q4_K_M`, about 4.7 GB, is downloaded automatically):

```bash
python deploy/docker/quickstart.py --demo --provider local
```

Reports are written to `output/demo-report/`. All tools with saved outputs:
[notebooks/securecode_demo.ipynb](notebooks/securecode_demo.ipynb).

## Installation

Requirements: Git, CPython 3.12–3.14, [uv](https://docs.astral.sh/uv/) 0.12.0.
Docker is needed only for the images, Ollama only for the local model.

```bash
git clone https://github.com/shorinversion/securecode-ai.git
cd securecode-ai
uv sync --locked
uv run securecode --version
```

## Usage

### Auditing a repository

```bash
uv run securecode analyze path/to/repo --output report.md
```

The command runs the full pipeline: scanners, Discovery, Auditor, Skeptic, a decision for
every finding and Architect fixes.

| Option | Purpose |
| --- | --- |
| `--provider deepseek\|local` | Model: DeepSeek (`DEEPSEEK_API_KEY` in the environment or `.env`) or local via Ollama |
| `--format markdown\|html\|json\|sarif` | Report format |
| `--output FILE` | Write the report to a file |
| `--patch-dir DIR` | Save validated fixes as `.diff` files |
| `--no-fix` | Do not request fixes |
| `--max-cost-usd N` | API spend cap per run (default 1.0) |

Exit codes: `0` — no vulnerabilities, `2` — vulnerabilities found, `3` — analysis
incomplete, `4` — configuration error. The Markdown and HTML reports are in Russian;
JSON and SARIF are language-neutral.

### Fix as a pull request

```bash
uv run python -I demo/p917_real_local_demo.py --repository path/to/repo --output out --provider deepseek --open-pr
```

The Architect commits the validated fix to a `securecode/fix-…` branch and opens a pull
request with the GitHub CLI. Example:
[shorinversion/securecode-demo-app#1](https://github.com/shorinversion/securecode-demo-app/pull/1).

### CI and server mode

`securecode scan` is the blocking CI check on a pre-approved host: bound to the exact
commit, with approved model and egress profiles. Deploying the control plane, the worker
and the GitHub and GitLab integrations is described in [docs/OPERATIONS.md](docs/OPERATIONS.md)
(in Russian).

## Results

**Auditor → Architect demonstration** on local Qwen 2.5 Coder 7B Q4_K_M and on DeepSeek:
SQL injection (CWE-89, A03:2021) found, the parameterized-query fix validated. Receipts:
[Qwen](report/submission-benchmark/evidence/current-real-local-p917.json),
[DeepSeek](report/submission-benchmark/evidence/current-deepseek-p917.json).

**Real repositories** in Python, JavaScript and Go: SQL injection, command injection, open
redirect, path traversal and missing JWT signature verification confirmed; a CSRF false
positive rejected. A run costs less than $0.01.

**OWASP Benchmark for Python** (1230 cases, 14 categories; score TPR − FPR, 1 is perfect):

| Tool | Score |
| --- | ---: |
| GPT-5.6 Luna | 0.73 |
| SecureCode scanners + Luna | 0.64 |
| SecureCode scanners + DeepSeek | 0.45 |
| SecureCode scanners | 0.21 |
| Bandit 1.9.4 | 0.16 |
| Semgrep 1.177.0 | 0.16 |

**CVEfixes** (3000 files: before/after CVE-fix pairs, 118 CWEs; held-out split of 1200 files):

| Configuration | Recall | Difference to Semgrep, pp (95% CI) |
| --- | ---: | ---: |
| SecureCode scanners + Luna | 50.5% | +16.2 [+11.3; +21.0] |
| SecureCode scanners + Semgrep | 43.8% | +9.5 [+7.2; +11.8] |
| Semgrep 1.177.0 | 34.3% | — |
| SecureCode scanners | 25.2% | −9.2 [−13.3; −5.0] |

Method, Bandit, gosec, ESLint, open-weight models, per-language results and limitations:
[experiments report](report/benchmark-v2/README.md) (in Russian). Datasets:
[CVEfixes](https://zenodo.org/records/13118970),
[OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython).

## Languages and rules

| Language | Files | Analysis |
| --- | --- | --- |
| Python | `.py`, `.pyi` | AST and CST, symbol table, 35 CWEs |
| JavaScript / TypeScript | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx` | CST, symbol table, 35 CWEs |
| Go | `.go` | CST, symbol table, 35 CWEs |
| All | pip, npm and Go manifests; any file | vulnerable dependencies (OSV), secrets |

The deterministic rules cover injection (CWE-78, 79, 89, 90, 94), path traversal (22),
SSRF (918), missing authentication and authorization (306, 862), unsafe deserialization
(502), weak cryptography (327, 338), hard-coded credentials (798), ReDoS (1333) and more.
The agents are not limited to this list: the model can report any of the 139 CWEs in the
OWASP Top 10 2021 mapping table.

## Security

- Analysis is bound to the exact commit; a changed revision cancels publication.
- An incomplete check yields `INDETERMINATE`, never "no vulnerabilities".
- Model output is untrusted data and is validated against a closed schema.
- Files with secrets are not sent to the model; secret values are never stored.
- The local model is reachable only over loopback; an external API is used only with
  explicit owner consent.
- Fixes are never applied to the source checkout without an explicit user decision.

More: [data classification](specs/security/data-classification.md),
[prompt injection defence](docs/security/PROMPT_INJECTION.md).

## Development

```bash
uv sync --locked --group quality
uv run --locked python -I scripts/quality.py
```

`scripts/quality.py` runs Ruff formatting and linting, mypy for Linux and Windows, unit and
integration tests with an 80% core coverage threshold. CI repeats the checks on Python
3.12, 3.13 and 3.14 and additionally scans secrets and dependencies.

## Repository layout

| Path | Contents |
| --- | --- |
| `apps/cli/` | the `securecode` CLI |
| `apps/server/`, `apps/worker/` | control plane and CI worker |
| `packages/contracts/` | versioned contracts and JSON Schema |
| `packages/core/` | domain logic: evidence graph, policy, reports, fixes |
| `packages/adapters/` | Git, tree-sitter, models, sandbox, reports, SCM |
| `demo/` | demonstrations and vulnerable examples |
| `notebooks/` | demonstration notebook |
| `report/` | final report and experiments |
| `tests/` | unit, contract and integration tests |
| `docs/` | architecture, decisions, security, operations |

## Documentation

- [Final report](https://mydev.stream/final-submission.html) — problem, solution, experiments, conclusions
- [Architecture](docs/ARCHITECTURE.md) and [product model](docs/PRODUCT.md)
- [Operations: Docker, CI, GitHub and GitLab](docs/OPERATIONS.md)
- [Reproducing the results](docs/REPRODUCIBILITY.md)
- [Threat model](docs/security/THREAT_MODEL.md)
- [Original assignment](docs/PROJECT_BRIEF.md)

## License

No license has been chosen; all rights reserved by the author. The training corpus in
`evaluation/development/` is CC0-1.0.
