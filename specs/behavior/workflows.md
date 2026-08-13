# Workflow behavior contract

Spec version: `0.2.0`  
Lifecycle: `accepted`

## AuditRun state machine

```text
REQUESTED → INTAKE → DISCOVERY_FORK
  ├→ DETERMINISTIC_ANALYSIS ─┐
  └→ MODEL_NATIVE_DISCOVERY ─└→ NORMALIZATION → EVIDENCE_GRAPH
    → INVESTIGATION? → FINDING_GATE? → REPAIR? → VALIDATION?
    → HUMAN_GATE? → COVERAGE_GUARD → REPORTING
    → PASS | FAIL | INDETERMINATE | ERROR

any non-terminal → CANCELLED | SUPERSEDED
```

Only after both applicable discovery lanes complete and normalization produces
zero candidates may policy skip per-candidate investigation and route through
`COVERAGE_GUARD` to reporting. Zero deterministic candidates alone never skips
model-native discovery. `PASS` remains guarded by complete mandatory coverage.

- `SC-WF-001`: Every transition MUST be selected by deterministic policy over
  typed state; a model MUST NOT name or execute the next node. **Oracle:** state
  transition table rejects an LLM-provided route field.
- `SC-WF-002`: Every state change MUST append an idempotent event with actor,
  node, attempt, input/output hashes, versions and reason. **Oracle:** event
  replay reconstructs the same state; reorder/tamper fails.
- `SC-WF-003`: A transition MUST validate its precondition, exact run/revision
  and schema version. **Oracle:** illegal/out-of-order/stale events are rejected.
- `SC-WF-004`: Cancellation or newer HEAD MUST prevent later external writes;
  newer HEAD maps the run to `SUPERSEDED`. **Oracle:** race matrix.

## Finding investigation loop

```text
HYPOTHESIS → COLLECT_EVIDENCE → VERIFY_DATA_FLOW → SKEPTIC_REVIEW
→ CONFIRMED | REJECTED_WITH_EVIDENCE | NEEDS_MORE_EVIDENCE | CONFLICTING
```

- `SC-WF-005`: Investigation MUST stop on a terminal verdict, no-progress,
  two additional context rounds, or the configured smaller budget. **Oracle:**
  loop simulation never exceeds the bound and emits the exact reason.
- `SC-WF-006`: Every positive claim MUST cite existing Evidence IDs; invented or
  inaccessible IDs invalidate the result. **Oracle:** citation mutation tests.
- `SC-WF-007`: Skeptic MUST be read-only and independent of Auditor mutable
  context. **Oracle:** capability and state-diff tests show no modification.
- `SC-WF-008`: Conflicting High/Critical verdicts MUST route to human review and
  MUST NOT become confirmed or rejected automatically. **Oracle:** conflict
  scenario ends at `HUMAN_GATE`.

## Repair loop

```text
ROOT_CAUSE → PATCH_AND_SECURITY_TEST → SANDBOX_VALIDATION
→ VALIDATED_CANDIDATE | RETRY | HUMAN_ESCALATION | REJECTED
```

- `SC-WF-009`: Repair MUST target the recorded root cause and emit both unified
  diff and security regression test. **Oracle:** missing linkage/test rejects
  candidate.
- `SC-WF-010`: Repair MUST stop after three attempts, no-progress, budget or the
  configured smaller bound. **Oracle:** attempt matrix reaches escalation.
- `SC-WF-011`: Retry feedback MUST contain only typed failed-gate evidence and
  MUST NOT grant new capabilities. **Oracle:** injection in tool log cannot
  alter capabilities/route.
- `SC-WF-012`: Architect MUST NOT modify protected policy/evaluator/golden tests
  or paths outside the checkout. **Oracle:** diff-tamper corpus is rejected.

## Validation ladder

Order is mandatory:

1. diff parse/path/scope;
2. clean ephemeral checkout and exact parent SHA;
3. patch apply;
4. language parse/format/lint policy;
5. compile/type check where applicable;
6. existing relevant tests;
7. generated security test/PoC;
8. strengthened negative/PoC+ tests;
9. post-patch deterministic scan;
10. new-vulnerability/regression scan;
11. resource/network/secret policy evidence;
12. optional human approval by risk policy.

- `SC-WF-013`: A failed mandatory validation gate MUST stop positive approval;
  later diagnostics MAY run only in an explicitly non-authoritative branch.
  **Oracle:** each-gate failure matrix never yields validated candidate.
- `SC-WF-014`: Passing generated tests alone MUST NOT prove a patch; existing
  tests, strengthened negative tests and post-scan are mandatory. **Oracle:**
  weak-test/symptom-suppression fixtures are rejected.
- `SC-WF-015`: Validation MUST record sandbox profile, commands, exit/resource
  outcomes and artifact hashes without leaking classified content. **Oracle:**
  validation manifest schema and canary scan.

## Run outcome guard

The run stores `finding_gate_state` and `analysis_health` independently before
deriving `AuditRunOutcome`. A confirmed blocking finding is not erased by later
coverage or infrastructure degradation; the degradation remains a separate
reason on the resulting `FAIL`.

- `SC-WF-016`: `PASS` requires: exact current HEAD, completed mandatory intake/
  scanners/required model stages, valid coverage manifest, no blocking finding,
  no unresolved validation/human gate and successful publication preconditions.
  **Oracle:** guard truth table with one omitted/failed condition at a time.
- `SC-WF-017`: Known security finding maps to `FAIL`; incomplete trustworthy
  analysis—including any mandatory model refusal, invalid output, timeout or
  provider error—maps to `INDETERMINATE`; failure to start/read the run at all
  maps to `ERROR`. A known blocking finding remains `FAIL` while degradation is
  recorded separately. **Oracle:** outcome precedence and provider-fault table.
- `SC-WF-018`: An auditable waiver MAY permit an SCM merge policy exception but
  MUST NOT rename underlying `FAIL/INDETERMINATE/ERROR` as `PASS`. **Oracle:**
  waiver serialization preserves both outcomes.

## Versioned mandatory-stage catalogue

Catalogue `core-mvp-0.2.0` is selected before intake. Its machine-readable
authority is [`stage-catalogue.yaml`](stage-catalogue.yaml). The policy, not a stage,
sets `required` and `applicable`. Every `CoverageUnit` records
`stage_id, required, applicable, status, reason_code, producer_version,
input_hashes, output_hashes`; its closed status enum is `COMPLETED |
NOT_APPLICABLE | UNSUPPORTED | FAILED | CANCELLED | SKIPPED`. Only `COMPLETED`,
or policy-proven `NOT_APPLICABLE`, satisfies coverage.

| Scenario | Mandatory stages |
|---|---|
| `DEMO-CWE89-001` scan | intake, language discovery, Python parse/symbols, secret scan, dependency scan, CWE-89 scan, model-native discovery, normalize/deduplicate, EvidenceGraph, Auditor for every candidate, Skeptic, finding gate, coverage guard, report |
| clean/no candidate | intake, language discovery, every applicable deterministic scanner, model-native discovery, normalize/deduplicate, coverage guard, report; per-candidate Auditor/Skeptic/finding-gate stages are policy-marked not applicable only after both discovery lanes completed with zero candidates |
| confirmed finding without repair | all scan stages plus Auditor, Skeptic and finding gate; repair stages are not applicable only when repair was not requested |
| repair requested | all confirmed-finding stages plus root-cause localization, security-test generation, Architect, every validation-ladder gate, coverage guard and report |
| unsupported required language | intake, language discovery and available scanners complete; missing language stages are `UNSUPPORTED`, so repository outcome cannot be `PASS` |

- `SC-WF-019`: Stage applicability MUST be derived from the pinned catalogue,
  repository inventory and requested operation before execution. **Oracle:** a
  producer cannot self-declare its failed stage `NOT_APPLICABLE`.
- `SC-WF-020`: Omission, unknown producer version, missing hash or every
  non-success status of a mandatory applicable stage MUST make `PASS`
  impossible. **Oracle:** one-field/stage mutation matrix.
- `SC-WF-021`: `core-mvp-0.2.0` MUST pass the five catalogue scenarios above;
  adding/removing a mandatory stage requires a new catalogue version. **Oracle:**
  scenario snapshots and compatibility test.
- `SC-WF-022`: For every repository/language in supported semantic scope,
  deterministic analysis and model-native discovery MUST both be mandatory and
  independently receipted. Model-native discovery MUST NOT become
  `NOT_APPLICABLE` because deterministic analysis produced zero candidates.
  **Oracle:** machine-catalogue invariant and zero-signal transition fixture.
- `SC-WF-023`: Normalization MUST take the union of both discovery lanes,
  preserve `deterministic | model_native | hybrid` provenance, and route every
  resulting candidate through Auditor investigation before a finding verdict.
  Scanner output alone is never a finding verdict. **Oracle:** deterministic-
  only, model-native-only, same-root hybrid and distinct-root merge fixtures.

## Retry and idempotency

Transient adapter failures use bounded exponential backoff with jitter under a
total node budget. Semantic validation errors are not blindly retried. All SCM,
artifact and workflow-start writes use idempotency keys. Side effects completed
before an interrupt/retry are not repeated without compare-and-set proof.
