# Gate and decision policy contract

Spec version: `0.2.0`  
Lifecycle: `accepted`

Initial policies are versioned typed YAML/JSON evaluated deterministically.
Deny/non-pass overrides allow/pass. OPA/Rego may replace the evaluator later
without changing this public semantic contract.

Every policy document has immutable `policy_id + policy_version`; the run
manifest additionally pins the canonical document SHA-256. Reusing a version
with different canonical bytes is a conflict. Egress/retention schemas and their
accepted positive/negative fixture catalogue live under `contracts/policy/`.

Required policy inputs:

```text
tenant/repository/revision, gate_mode, calibration_record?,
finding severity/verdict/confidence provenance/new-code relation,
coverage and model/tool statuses, change-risk labels,
human decision/waiver, workflow/provider/sandbox/egress profiles
```

- `SC-POLICY-001`: `gate_mode` MUST be `advisory | new_code | strict`; before a
  valid calibration record only `advisory` is allowed for statistical finding
  thresholds. **Oracle:** compiler fixture rejects uncalibrated blocking.
- `SC-POLICY-002`: `PASS` MUST use the workflow guard in `SC-WF-016`; no policy
  may redefine refusal/error/incomplete as clean. **Oracle:** policy mutation and
  fault matrix.
- `SC-POLICY-003`: New-code relation MUST be determined from stable fingerprint,
  exact base/head and changed-line/data-flow policy, not model assertion.
  **Oracle:** baseline/ref-move scenarios.
- `SC-POLICY-004`: Auth/authz/crypto/public API change, conflicting verdict and
  configured critical cases MUST route to human review. **Oracle:** risk-label
  scenario matrix.
- `SC-POLICY-005`: Waiver MUST be tenant/repository/finding/SHA/scope/actor/
  reason/expiry bound and MUST preserve the underlying outcome. **Oracle:**
  forged/stale/expired/cross-scope suite.
- `SC-POLICY-006`: Policy evaluation MUST record version, input hashes, matched
  rules and result without raw classified content. **Oracle:** deterministic
  replay and canary scan.
- `SC-POLICY-007`: Evaluator error, missing input or unknown enum MUST yield
  non-pass typed error and zero external permission. **Oracle:** malformed/future
  input matrix.
- `SC-POLICY-008`: Policy/evaluator changes MUST be reviewed/versioned and cannot
  alter completed run history. **Oracle:** old-run replay pins old version.

Decision precedence:

```text
cancel/supersede
→ confirmed blocking finding under the active gate policy
→ security invariant violation or missing mandatory/model coverage
→ unrelated platform error that prevents run intake/repository access
→ mandatory human gate
→ complete non-blocking/advisory result
```

The evaluator first records `finding_gate_state` and `analysis_health` as
independent facts. A known confirmed blocking finding therefore remains `FAIL`
even if a later provider or reporter fails; health reasons remain visible on the
run. Without such a finding, missing/untrustworthy mandatory coverage—including
model refusal, filter, empty/invalid output, timeout, budget exhaustion or
provider error—maps to `INDETERMINATE`. An unrelated platform failure that
prevents run intake or repository access maps to `ERROR`. Cancel/supersede
remain terminal control outcomes.

The result remains one of domain `AuditRunOutcome`; platform adapters map it but
cannot weaken it.

- `SC-POLICY-009`: The mixed-condition truth table MUST preserve a confirmed
  blocking finding as `FAIL` and attach every degradation reason. **Oracle:**
  blocking-finding × coverage/provider/infrastructure/human-state Cartesian
  suite has no finding-erasing outcome.
- `SC-POLICY-010`: A supported-scope product scan MUST require successful
  deterministic and model-native discovery receipts plus Auditor receipts for
  every normalized candidate. No repository/provider/prompt/model stage may
  self-declare these requirements `NOT_APPLICABLE`. **Oracle:** catalogue/policy
  mutation suite and dropped-candidate coverage test.
