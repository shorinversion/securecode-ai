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
