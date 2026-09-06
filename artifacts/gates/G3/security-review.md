# G3 security and boundary evidence

result: PASS

- Auditor verdicts require selected-evidence citations; Skeptic inputs are
  immutable and its capability set is read-only.
- Policy code, not model prose, selects routes. Refusal, filtering, empty or
  invalid output, truncation, timeout, provider faults, budget exhaustion and
  no-progress are typed non-success outcomes and cannot become product PASS.
- Repository, SCM and tool text has no instruction authority. The injection
  corpus cannot extend tools or policy and raw source/prompt/response material
  is excluded from durable receipts.
- RepositoryView exposes only bounded typed read operations with exact
  revision/scope binding. Invalid tools, arguments, budgets and backend faults
  fail closed.
- Model-native discovery remains mandatory at zero scanner signals; dual-lane
  convergence preserves deterministic and model lineage with Auditor receipts.
- Incompatible source, provider or egress profiles stop before socket activity
  and return `INDETERMINATE` rather than deterministic-only fallback.

The active G3 policy requires no independent gate review. These claims remain
in scope for the combined independent product/architecture/security review
after G9.
