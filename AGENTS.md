# SecureCode AI — instructions for coding agents

For every task in this repository, read and follow
[`.agents/skills/securecode-project-navigator/SKILL.md`](.agents/skills/securecode-project-navigator/SKILL.md)
before planning or editing, and run its end-of-task memory protocol before
handoff.

Project-specific rules:

- Treat `docs/PROJECT_BRIEF.md` as immutable baseline requirements.
- Use `docs/CONTEXT.md` to restore current state and `docs/PLAN.md` as the
  canonical task/gate plan.
- Map implementation to a `P*.*` task and verify its acceptance evidence.
- Record material changes in `CHANGELOG.md`; architecture changes also require
  an ADR in `docs/DECISIONS.md`.
- After the `G0` baseline, treat accepted files in `specs/` as normative.
  Implementation tasks must use a constrained task packet and may not modify
  accepted specifications, acceptance evaluators or gate evidence unless the
  user explicitly assigned a spec/change-control task.
- Preserve unrelated worktree changes and never place secrets or proprietary
  raw source in durable project-memory files.
- Store concise decisions, rationale and evidence, not hidden chain-of-thought.
- The root Codex agent is Primary Integrator and remains accountable for scope,
  architecture coherence, integration, final verification and user handoff.
- Delegate only bounded independent subtasks with a task packet. Use read-only
  or proposal-only subagents for research/review; allow writes only to exclusive
  non-overlapping paths. One writer per path; nested delegation is off by
  default.
- Treat every subagent result as a candidate. The Primary Integrator must inspect
  changes and rerun relevant verification before accepting or reporting it.

## Permanent code-first execution policy

For the entire project, prioritize implementation of working product code.
Planning, documentation, tests, reviews, Git and CI exist to guide and verify
the implementation; they must not become the primary output or consume a
disproportionate share of execution time and model usage.

- Start each task with the smallest necessary context and move promptly to code
  whenever its dependencies and acceptance contract are already clear.
- Under effective CR-050, between P-tasks make local checkpoint commits only,
  without tests or independent reviews. Run one canonical full quality and
  protected PR/CI cycle at gate closing. G2-G8 have no independent gate reviews;
  one combined final review cycle closes G9 before promotion. Repeat a closing cycle only
  after a material change invalidates its evidence.
- Inspect CI through compact status summaries. Fetch detailed logs only for a
  failed or ambiguous job; do not continuously stream successful runs.
- Do not reload large durable-context files when the current task state is
  intact. After context loss, follow the project navigator recovery protocol and
  load only the relevant plan/gate sections beyond the required context file.
- Delegate bounded implementation to the stage-appropriate model under
  [DEVELOPMENT_WORKFLOW.md](docs/DEVELOPMENT_WORKFLOW.md). Use bounded internal
  subagents with explicit model/reasoning configuration; do not create separate
  user-visible tasks for internal stages. One writer owns each path; the Primary Integrator
  retains acceptance and integration authority.
- Combine related read-only checks and avoid redundant reports, commits, test
  reruns, and intermediate publication artifacts.
- After `P2.5`, review the delivery lifecycle for the remaining project tasks and
  remove duplicate PR, attestation, review and verification steps wherever the
  same acceptance evidence can be preserved through one ordinary protected PR.
  Apply the resulting streamlined lifecycle for the rest of the project. Do not
  use bypass or weaken required gates.
- Never economize by weakening secret non-disclosure, fail-closed behavior,
  protected-branch enforcement, independent final review, or the effective G2
  completion audit.

## Model routing and verification cadence

- Use Codex models and native Codex coordination only for this workflow.
  Do not apply the `delegating-subagents-and-deepseek` skill or call DeepSeek
  services; the user explicitly excluded that skill on 2026-09-05.
- Read [DEVELOPMENT_WORKFLOW.md](docs/DEVELOPMENT_WORKFLOW.md) before dispatch
  or implementation. Check the assigned role, requested model and reliable
  runtime identity; never infer model identity from writing style.
- On a confirmed mismatch, transfer to a bounded subagent with the explicit
  model and reasoning setting. Preserve the return address and candidate identity,
  release the old writer lease, and stop duplicate execution. Unknown identity
  and failed/uncertain creation follow the bounded recovery rules in the policy.
- One full local quality and protected PR/CI cycle belongs to the integrated
  gate candidate. No tests or reviews run between P-tasks; record a concrete
  invalidation reason before repeating closing verification. The final combined
  independent review cycle closes G9 before promotion.
- Existing executable hooks, protected CI and completion evidence remain
  mandatory until their separately reviewed amendment is effective. Never use
  SKIP, --no-verify, hook removal or branch bypass to implement this policy.

- CR-050 / D-047 remains the current cadence authority. CR-055 / D-051 is the
  effective G3-G9 successor-evaluator authority, delivered by protected PR #50
  at merge `d8edb4c4fe30af4c6b7f2d27d48ed917b7464356`; protected postmerge run
  `34020445912` completed `PASS`.
