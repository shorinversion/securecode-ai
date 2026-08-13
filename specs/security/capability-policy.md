# Capability and trust policy

Spec version: `0.2.0`  
Lifecycle: `accepted`

- `SC-CAP-001`: Repository, SCM and tool/model content MUST have
  `instruction_authority=NONE`. **Oracle:** trust-label validator and injection
  corpus.
- `SC-CAP-002`: Auditor and Skeptic MUST be read-only; Architect MAY emit only a
  structured patch/test candidate; Validator MAY execute only a host-selected
  command plan in sandbox. **Oracle:** per-role allow/deny matrix.
- `SC-CAP-003`: A role MUST NOT grant itself a new tool, permission, budget,
  destination or execution location. **Oracle:** self-escalation fixtures denied.
- `SC-CAP-004`: Tool calls MUST use versioned typed arguments and exact resource
  scope; free-form shell/URL-fetch is forbidden. **Oracle:** malformed/unknown/
  out-of-scope argument suite makes zero side effects.
- `SC-CAP-005`: Policy/evaluator/spec/golden expected results are protected
  resources and MUST NOT be writable by implementation/repair roles. **Oracle:**
  protected-path diff gate.
- `SC-CAP-006`: High-impact external writes require deterministic authorization
  and, where policy says so, human approval bound to exact inputs. **Oracle:**
  approval replay/input-change tests.
- `SC-CAP-007`: Capability use MUST append a safe audit event including role,
  resource, decision, version and outcome. **Oracle:** trace completeness with
  secret/source canary absence.
- `SC-CAP-008`: Denial/evaluator failure MUST stop the attempted effect and route
  to typed non-success; it MUST NOT be retried with broader privilege. **Oracle:**
  denial/failure matrix.
- `SC-CAP-009`: Model-native discovery, Auditor and Skeptic MAY receive only
  read-only typed repository capabilities (`list_paths`, `lookup_symbol`,
  `read_range`, `read_evidence`) with exact revision/path scope and cumulative
  call/byte/token budgets. They MUST NOT receive shell, process execution,
  arbitrary filesystem, network or write capabilities. **Oracle:** per-role
  allow/deny matrix plus traversal, symlink, revision-swap and budget tests.
- `SC-CAP-010`: Source, comments, identifiers, documentation and all repository
  tool results MUST retain `instruction_authority=NONE` through model-native
  discovery and later investigation. **Oracle:** direct, encoded and
  cross-fragment injection cases preserve tool policy, route and coverage.
- `SC-CAP-011`: Evaluation optimizers MUST have train/dev-only read scope and a
  candidate-artifact write scope; locked expectations, evaluator, policy,
  capability rules, schemas, thresholds and production prompt/skill aliases are
  protected. **Oracle:** optimizer allow/deny matrix records zero protected
  reads/writes and zero alias changes.
- `SC-CAP-012`: RLM-generated programs MUST execute only through the dedicated
  evaluation sandbox with immutable `CodeIndex` reads, no credentials/network/
  host filesystem and explicit CPU/RAM/PID/disk/output/time limits. **Oracle:**
  generated-program escape, exfiltration and resource-abuse suite is contained.
