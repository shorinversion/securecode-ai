# Development workflow and model routing

Status: active operating instructions, accepted by the user on 2026-09-05
under CR-045 / D-043. This governs development agents, not product runtime
agents. Accepted specifications and executable gates retain their authority.

## 1. Unit of delivery

One cycle delivers a coherent, independently reviewable component or feature,
including its tests. An edit, commit, chat response or reviewer finding is not
a new delivery cycle. P2.5 is one example of a complete increment.

Prefer one P-task per increment. Split a large task by independently testable
outcomes; group small related fixes only within an explicitly scoped packet.
Roughly 200-800 changed product-code lines is a sizing heuristic, not a gate,
quota or reason to split coupled changes. Review complexity includes tests.

User refinement accepted 2026-09-05: after the protected amendment in section 6
becomes effective, the ordinary full-quality and independent-review cycle belongs
to the integrated whole-gate candidate after all required P-tasks are implemented.
Individual P-tasks retain focused acceptance/negative checks and are not separate
full-review cycles. Until then, current executable checks remain mandatory.

## 2. Model assignments

Use Codex models and Codex task/agent tools only. The user explicitly excluded
the `delegating-subagents-and-deepseek` skill on 2026-09-05; do not load that
skill or use DeepSeek/external model services for this development workflow.

| Role | Requested model | Reasoning |
|---|---|---|
| Primary Integrator / orchestrator | `gpt-5.6-sol` | `medium` |
| Component implementation | `gpt-5.6-terra` | `high` |
| Bounded mechanical edits and documentation | `gpt-5.6-luna` | `medium` |
| Independent product and architecture review | `gpt-5.6-sol` | `high` |
| Ordinary independent security/evaluation review | `gpt-5.6-sol` | `high` |
| Critical security, evaluator/gate changes, difficult architecture | `gpt-6-astra` | `medium` |

These are initial routing defaults, not measured cost/performance guarantees.
User cost ceiling accepted on 2026-09-05: Astra reasoning must never exceed
`medium`; use focused packets and targeted evidence instead of raising effort.
Use Astra for secret non-disclosure boundaries, fail-open risks and protected
policy changes. The current CR-045 policy integration is such an assignment.
Check callable host model availability before creation; do not silently fall
back to another model. An explicit user model choice overrides defaults.

After two unsuccessful attempts on the same reproducible defect, the
orchestrator revisits scope/acceptance or escalates Terra to Sol, then Astra
for a justified unresolved critical issue. Do not escalate merely because a
test took time. Track elapsed time and returned usage when available; never
invent usage. Compare cost per accepted increment including remediation.

## 3. Model check and task transfer

At entry and each role transition, determine required role/model/reasoning.
Record actual identity only when supplied by reliable runtime/app metadata.
A requested model in a dispatch receipt records configuration, not proof of
the executing model. Writing style and self-guessing are not identity evidence.

User routing correction accepted on 2026-09-05: internal development and review
use bounded Codex subagents, not separate user-visible Codex chats. The
orchestrator supplies an explicit `model` and reasoning setting when spawning
each subagent. A successful spawn receipt proves that the dispatcher accepted
that configuration; it does not prove runtime identity when the platform does
not expose reliable model metadata. Record such observed identity as `unknown`.
Separate Codex chats are not created for internal project stages. This is not
authorization for unrelated work, publishing or external messages.

On a confirmed mismatch:

1. Prepare a concise task packet with the remaining work, exact base/candidate,
   changed files, check results, exclusive writer lease and return address.
   Exclude secrets and raw private sources.
2. Persist transfer intent before spawn and inspect the live agent tree to
   avoid duplicate replacements.
3. Spawn one bounded subagent with the explicit role model and reasoning from
   section 2. Use a limited context fork when an override is supplied and put
   all required repository, scope, candidate and return information in the
   prompt. Read-only review subagents may share a stable checkout. Concurrent
   writers require separate inspected worktrees; one writer owns each path.
4. Record the returned canonical agent path and the configured model/reasoning.
   If the platform exposes no reliable runtime identity, record `unknown` and
   do not infer identity from prose or behavior.
5. Release the old lease before granting the replacement its exact paths. Stop
   duplicate execution; the orchestrator inspects and revalidates every result.

If actual identity is unknown, record `unknown`. At most one explicit-model
replacement may be configured for a given stage/candidate; the replacement
may proceed using that recorded dispatch configuration when runtime identity
remains unavailable, but must not claim it was independently verified. A
confirmed mismatch in the replacement stops dependent execution and returns
to the orchestrator. Never create a chain of unknown-identity replacements.

If model selection or subagent creation is unavailable, report the exact blocker
and retain state; do not claim a switch succeeded. Safe read-only preparation
can continue. Tools and platform permissions remain authoritative.

Workers do not fan out further work unless the orchestrator explicitly assigns
that bounded coordination. Model replacement is a transfer of the same
assignment, not authority to expand scope. The root Primary Integrator retains
dispatch, acceptance and integration authority.

## 4. Execution and return path

Task: `READY -> IMPLEMENTING -> TARGETED_CHECKS -> INTEGRATED`.
Gate: `ALL_REQUIRED_TASKS_INTEGRATED -> FULL_QUALITY -> INDEPENDENT_REVIEWS ->
FIXING_AND_DELTA_CHECKS (if needed) -> EFFECTIVE_GATE_DECISION`.

The orchestrator spawns one bounded developer subagent per active increment and
fresh read-only subagents after the integrated gate candidate is stable. Required product,
architecture and security/evaluation reviews remain independent with distinct
agent identities and role scopes.
Do not replace an independent review with the author's self-review, even if
the author changes models. Reviewers do not edit or merge.

The orchestrator uses the collaboration agent tree and bounded waits for
completion, sends corrections to the existing subagent, and accepts only the
subagent's structured return. No notifications to people or external apps.

Required handoff: task/role, candidate commit or scoped content digest, files
changed, acceptance mapping, exact commands/results/skips, findings with
reproduction and severity, unresolved issues and next action. Review outcomes
are candidate evidence until the integrator inspects the diff and verifies
the applicable integrated checks. A new subagent does not reset approvals or scope.

For pending work, maintain `work/development-runs/<run-id>.json` as an
operational record owned by the orchestrator only. Include: task ID, phase,
orchestrator/return IDs, agent paths, required/observed model and identity
source, transfer intent/status/count, base/candidate identity, writer owner and
allowed paths, findings, checks with invalidation reasons, and next action.
Use null for unknown IDs; update atomically at transitions, not per tool call.
This record is not a gate attestation and cannot make a task DONE. Existing
closed-schema task packets are not extended without their own amendment;
attach routing metadata as this separate record and in the dispatch prompt.
Workers report results to the orchestrator and do not edit its operational
record. Only the orchestrator grants or transfers a write lease. No
acknowledged transfer means no new writes.

A running orchestrator explicitly waits for dispatched work; subagent creation
alone is not completion. No Markdown file is a background scheduler. If the
orchestrator stops, resume from the record on the next user turn; unattended
wakeups require an explicitly configured automation.

## 5. Verification cadence

During implementation run changed-component tests and immediate boundaries,
plus relevant negative/contract cases. Do not apply global coverage thresholds
to a targeted subset. Do not run the complete matrix or broad review per P-task.

After the protected cadence amendment is effective, the integrator runs
canonical full local quality once on the integrated gate candidate after all
required tasks are implemented. Required independent product, architecture and
security/evaluation reviews cover that candidate. Until then, existing hooks,
CI and completion contracts still run and must not be bypassed.

Repeat full quality only when product code, dependencies,
test behavior, executable configuration or relevant contracts changed, or a
failure invalidated the result. Record the reason before rerunning. A commit
operation, new subagent, status note or unchanged-byte handoff alone is not a
reason. Required exact-SHA evidence must still be freshly bound and validated;
do not relabel old evidence as a new-SHA PASS.

Review corrections require affected regression checks and the affected role's
delta review. Each required reviewer must cover the final candidate, directly or through
an explicit original-review plus inspected-delta reconciliation. Do not call
an old review an exact-final-tree PASS. Restart broad review only when scope,
trust boundaries or shared contracts invalidate previous conclusions.

Blocking findings require a violated contract or reproducible defect and a
closure condition. Optional refactoring does not reopen delivery. Do not
discard a real security finding to meet iteration budgets; return the specific
blocker instead. Documentation-only operating instructions need link/diff and
consistency checks plus required independent review, not product regression.

## 6. Protected automation transition

The instructions above reduce discretionary reruns immediately. Current
pre-commit/pre-push full quality, mandatory CI and completion attestations
remain effective. Do not bypass them with `SKIP`, `--no-verify`, hook removal,
environment tricks or branch-rule changes.

CR-045's protected automation follow-up is pending, not implemented here:

- Amend `.pre-commit-config.yaml`, `scripts/precommit_entry.py` and the closed
  expectations in `scripts/ci_policy.py` together: keep required secret/policy
  checks; move repeated hook full quality to explicit publication verification.
- Provide a bounded development-check entrypoint without weakening canonical
  `scripts/quality.py`; preserve sanitized execution and negative tests.
- Amend `scripts/spec_gate.py` / `scripts/spec_gate_policy.json` and affected
  tests for one protected implementation PR, with immutable externally
  verifiable review/CI completion evidence instead of a second attestation PR.
  Preserve exact merged SHA, required checks and effective G2 completion audit.
- Use the existing protected amendment procedure and independent reviews;
  implementation packets cannot promote their own evaluator changes.

Do not advertise the one-PR lifecycle or removal of hook reruns as effective
until the amendment has passed protected delivery. Historical evidence remains
unchanged. See [PLAN.md](PLAN.md) and [CHANGELOG.md](../CHANGELOG.md).
