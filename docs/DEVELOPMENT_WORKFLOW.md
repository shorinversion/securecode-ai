# Development workflow

Status: active from 29 September 2026 (D-114). Replaces the packet-, gate- and
review-record-driven workflow of CR-045/D-043, which is kept in git history.

## Flow

1. Branch from `main`.
2. Make a focused change with tests.
3. Open a PR whose description says what changed and why.
4. CI must be green: `policy`, `secrets`, `dependency`, `quality`
   (format, lint, mypy on Linux and Windows, unit tests on Python 3.12–3.14).
5. Merge. `main` accepts changes only through PRs with a green `gate`.

No task packets, change-control YAML, attestation files or file/line budgets are
required. Large PRs are allowed; reviewers ask for a split when it helps review.

## Local checks

```bash
uv run --locked python -I scripts/quality.py
```

`pre-commit` runs the CI policy, staged secret scan and workflow audit.

## Contracts

`specs/` documents product contracts (CWE and OWASP mapping, report formats,
provider and policy schemas). Public JSON schemas are generated from the models
(`python -m securecode_ai.contracts.schema_export`); unit tests fail when they
drift, and schema changes are reviewed as normal diffs.

## Secrets

The secret scan blocks new unreviewed high-entropy strings. When a finding is a
legitimate digest, add it to `.secrets.baseline` in the same PR; the PR review
approves it. Detectors and filters themselves are pinned in `scripts/ci_policy.py`.

## Decisions and planning

Record real architectural or product decisions briefly in `docs/DECISIONS.md`.
Plan work as milestones in `docs/PLAN.md` and track changes in `CHANGELOG.md`.
The former gates G0–G9 are a roadmap, not machine-enforced blockers.
