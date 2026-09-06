# Development workflow and model routing

Status: active operating instructions under effective CR-050 / D-047,
superseding the earlier CR-045 cadence. This governs development agents, not product runtime
agents. Accepted specifications and executable gates retain their authority.

## 1. Unit of delivery

One cycle delivers a coherent, independently reviewable component or feature,
including its tests. An edit, commit, chat response or reviewer finding is not
a new delivery cycle. P2.5 is one example of a complete increment.

Prefer one P-task per increment. Split a large task by independently testable
outcomes; group small related fixes only within an explicitly scoped packet.
Roughly 200-800 changed product-code lines is a sizing heuristic, not a gate,
quota or reason to split coupled changes. Review complexity includes tests.

Between P-tasks, author implementation and its test code and make local checkpoint
commits only. Do not run tests, lint, types, full quality or independent reviews
between tasks. One canonical full quality cycle and one ordinary protected PR/CI
cycle belong to the integrated gate candidate. G2-G8 have no independent product,
architecture or security/evaluation reviews. After G9 implementation and quality,
one combined final cycle supplies three distinct product, architecture and
security/evaluation receipts on the exact G9 subject before PROJECT CLOSED promotion.
Hooks and protected CI remain mandatory.

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

Task: `READY -> IMPLEMENTING -> LOCAL_CHECKPOINT -> INTEGRATED`.
Gate: `ALL_REQUIRED_TASKS_INTEGRATED -> FULL_QUALITY -> PROTECTED_PR_AND_CI ->
EFFECTIVE_GATE_DECISION`. Failed closing checks return the candidate to fixing.
G9: `IMPLEMENTATION_AND_QUALITY_COMPLETE -> THREE_FINAL_REVIEW_RECEIPTS ->
PROTECTED_CLOSURE_PROMOTION -> FINAL_HANDOFF`.

The orchestrator spawns bounded developer subagents per active increment and
three distinct read-only reviewers for the combined final product, architecture
and security/evaluation cycle after G9 implementation and quality, before closure.
Protected POLICY amendment receipts are a
distinct existing enforcement mechanism and do not authorize extra gate reviews.
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

During implementation supply changed-component, negative and contract test code;
execution waits for closing the integrated gate. Local checkpoint commits preserve
rollback history and do not constitute acceptance evidence.

The integrator runs canonical full local quality once after all required gate
tasks are implemented, followed by the ordinary protected PR/CI cycle. No
independent gate reviews run for G2-G8. G9 requires three distinct final review
receipts on its exact integrated subject after implementation and quality and
before PROJECT CLOSED promotion. This is one combined final review cycle.

Repeat full quality only when product code, dependencies,
test behavior, executable configuration or relevant contracts changed, or a
failure invalidated the result. Record the reason before rerunning. A commit
operation, new subagent, status note or unchanged-byte handoff alone is not a
reason. Required exact-SHA evidence must still be freshly bound and validated;
do not relabel old evidence as a new-SHA PASS.

Closing corrections require checks for the concrete invalidated evidence. Final
review corrections require reconciliation by the final reviewer. Do not relabel
an old review as an exact-final-tree PASS or create per-task review cycles.

Blocking findings require a violated contract or reproducible defect and a
closure condition. Optional refactoring does not reopen delivery. Do not
discard a real security finding to meet iteration budgets; return the specific
blocker instead. Documentation-only operating instructions need link/diff and
consistency inspection; they do not require a separate independent review.

## 6. Protected automation transition

CR-048 moved full quality out of repeated hooks; CR-050 became effective through
protected PR #38. Secret/policy/workflow hooks and protected CI remain mandatory.
Never use `SKIP`, `--no-verify`, hook removal or branch-rule changes.

The G3-G9 successor implementation (CR-055 / D-051) is effective as the
successor-evaluator authority: protected PR #50, merge
`d8edb4c4fe30af4c6b7f2d27d48ed917b7464356`, protected postmerge run
`34020445912` with `PASS`. CR-050 / D-047 remains the cadence authority. G3 bootstraps exact
historical packet hashes and fixed path budgets. G4-G9 consume immutable full-schema
packets seeded in the preceding protected gate candidate and carried unchanged
through promotion. Each gate seeds its successor before the next implementation
starts. No gate candidate can broaden its own packet authority. A missing seed,
stale hash, unmet acceptance criterion or failed required CI keeps the gate open.

POLICY amendments still require their existing three separated receipts; the
integrator must obtain authorization for those receipts when they are not already
assigned. This does not restore product reviews for G2-G8. Historical evidence
remains unchanged. See [PLAN.md](PLAN.md) and [CHANGELOG.md](../CHANGELOG.md).
