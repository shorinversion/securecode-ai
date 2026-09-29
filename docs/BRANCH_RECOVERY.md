# Branch consolidation and recovery backlog

Date: 28 September 2026.

All local branches, 36 dirty Codex worktrees, the stash and 31 remote branches
were consolidated into `main`. Every old ref is preserved as a tag
`archive/<name>`. Remote-branch tags are on GitHub; tags of uncommitted
worktree snapshots (`archive/wip-*`, `archive/wt-2893`,
`archive/stash-p59-sarif-wip`) are local only because they were archived
without the secret scan and the repository is public.

## Method

1. `git cherry` and three-way application of each branch diff onto `main`.
2. For conflicting branches: the branch's own test files were run against
   `main` code; a branch was treated as covered when its tests did not fail
   more than the same files on `main`.
3. Remaining differences were reviewed by hand (small branches) or by three
   read-only review passes over the WIP snapshot families.

## Result

- Assignment-critical areas (AST/tree-sitter tools, secrets, vulnerable
  dependencies, Auditor/Architect, patch generation and validation, reports,
  local Ollama) lost nothing: `main` holds the same or stricter code.
- Recovered into `main`: worker guard against forged contribution trust and
  regression tests from `code-first-oidc`, `code-first-telemetry`, `speed-p74`.
- Deliberately not ported (superseded by `main`): early compose draft, CSRF
  adapter drafts, older CWE-862/portfolio detectors, dependency-inventory
  facts as findings, Skeptic verdict restriction, Timer-based remote deadline,
  per-tenant artifact folder naming, human-capability binding table.

## Missing server fixes (post-v1, not assignment scope)

| # | Area | Source | Extract |
|---|---|---|---|
| 1 | Replayed worker lease keeps a stale command, so a run cancelled after leasing never stops its worker (~10 lines) | `archive/wip-45e9` | `git diff archive/wip-2223 archive/wip-45e9 -- apps/server/src/securecode_ai/server/worker_queue.py` |
| 2 | Backup restore may resurrect deleted data and legal holds; `IN_PROGRESS` restore retry (~60 lines). Conflicts with `main`'s documented no-replay decision; needs a design review first | `archive/wip-e919` | `git diff archive/wip-2223 archive/wip-e919 -- apps/server/src/securecode_ai/server/backup_executor_runtime.py` |
| 3 | SCM reconciler always reads the first 256 pending publications; later ones are never reconciled (~80 lines) | `archive/wip-60b4` | `git diff archive/wip-2223 archive/wip-60b4 -- apps/server/src/securecode_ai/server/scm_*.py` |
| 4 | Query cursors are bare offsets; scope-bound keyset cursors (~60 lines, tests need updating) | `archive/wip-85e2` | `git diff archive/wip-85e2^ archive/wip-85e2 -- apps/server/src/securecode_ai/server/query_service.py` |
| 5 | `test_server_policy_operations.py` (159 lines) never reached `main`; 3 of 4 tests disagree with current status codes | `archive/wip-securecode-v1-code-integration` | `git show archive/wip-securecode-v1-code-integration:tests/unit/test_server_policy_operations.py` |

Port each item only together with the matching failing-test cluster in
`apps/server`, and run its tests after porting: none of these were import-tested.
