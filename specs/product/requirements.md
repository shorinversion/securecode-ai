# Product requirements baseline

Spec version: `0.2.0`  
Lifecycle: `accepted`  
Source: immutable project brief plus accepted `CR-001–CR-016`

## Goals and non-goals

SecureCode AI provides evidence-grounded vulnerability investigation and
validated patch candidates through one Core used by offline CLI and connected
workflows. It augments, rather than replaces, deterministic analysis and human
security review.

It does not guarantee security, declare SAST/model output ground truth,
auto-merge by default, execute unrestricted tools, or claim enterprise
production readiness before `G8/G9`.

## Normative requirements

- `SC-PROD-001`: Core MVP MUST complete `DEMO-CWE89-001` end to end for Python:
  intake, deterministic evidence, Auditor, Skeptic, Architect, sandbox
  validation and reports. **Oracle:** pinned demo command produces all expected
  artifacts/states and passes its golden scenario.
- `SC-PROD-002`: The final project MUST semantically analyze Python, JS/TS and
  Go; Core MVP MAY implement only Python when unsupported languages are
  explicitly represented in CoverageManifest. **Oracle:** beta conformance suite
  runs positive/negative cases for all three; v0.1 mixed repo cannot be `PASS`.
- `SC-PROD-003`: The system MUST provide repository intake, AST/Tree-sitter
  parsing, hardcoded-secret detection and vulnerable-dependency detection.
  **Oracle:** positive/negative fixtures for every tool and supported language.
- `SC-PROD-004`: Findings MUST use one language-neutral contract containing
  file/location, fragment reference, CWE, severity/confidence, evidence and
  producer provenance. **Oracle:** schema and round-trip tests across all
  scanner adapters.
- `SC-PROD-005`: Auditor MUST investigate context and cite Evidence IDs;
  Architect MUST generate a minimal unified diff; both MUST be bounded by
  workflow policy. **Oracle:** loop budget and structured-output contract tests.
- `SC-PROD-006`: High/Critical finding and every patch candidate MUST receive an
  independent read-only Skeptic/Validator decision. **Oracle:** workflow refuses
  approval if independent evidence is absent.
- `SC-PROD-007`: Patch candidates MUST be applied only to an ephemeral sandbox
  until explicit human/application action; auto-merge is disabled by default.
  **Oracle:** original checkout hash remains unchanged through generation and
  validation.
- `SC-PROD-008`: Reports MUST include JSON, SARIF, Markdown/HTML, CWE/OWASP,
  evidence, coverage and patch/validation references without unsafe rendering.
  **Oracle:** schema/golden/security rendering suite.
- `SC-PROD-009`: Offline CLI MUST operate without backend and network when an
  air-gap compatible model/fake is selected. **Oracle:** full demo under network
  interceptor makes zero connects.
- `SC-PROD-010`: Connected mode MUST execute repository operations in a CI
  worker by default and exchange only policy-approved classified data with the
  control plane/provider. **Oracle:** egress canary/conformance suite.
- `SC-PROD-011`: GitHub reference integration MUST publish one idempotently
  updated summary, bounded inline annotations and an exact-HEAD Check Run;
  GitLab MUST reach equivalent semantic outcomes by beta. **Oracle:** adapter
  conformance suite including duplicate and stale events.
- `SC-PROD-012`: A comment MUST NOT be the merge-gate source; only a status/check
  bound to exact HEAD and calibrated policy MAY block. **Oracle:** comment
  deletion has no gate effect; stale status is rejected.
- `SC-PROD-013`: Before threshold calibration, connected operation MUST default
  to advisory. After calibration, `new_code` MUST be the first blocking rollout
  and legacy baseline findings MUST NOT block by default. **Oracle:** policy
  fixtures before/after calibration.
- `SC-PROD-014`: Refusal, filtering, empty/incomplete/invalid response, timeout,
  provider error or missing mandatory coverage MUST NOT yield `PASS` or
  `no_finding`. **Oracle:** complete provider fault matrix has zero fail-open.
- `SC-PROD-015`: Every run MUST be reproducible/auditable by repository SHA,
  schemas, workflow, policy, scanners, prompts, model profile and tool versions.
  **Oracle:** manifest completeness and replay fixture.
- `SC-PROD-016`: The final project MUST include documentation, unit/integration/
  security tests, a demonstrational vulnerable repository and a runnable
  notebook. **Oracle:** clean-environment release checklist at `G9`.
- `SC-PROD-017`: Enterprise pilot MUST provide tenant-scoped authz, expiring
  waivers, audit trail, retention/egress policy and bounded budgets; SSO/HA and
  stronger supply-chain/operations controls are RC requirements. **Oracle:**
  `G6` pilot and `G8` RC checklists respectively.
- `SC-PROD-018`: Users MUST see exact incomplete coverage and recovery action;
  unsupported, failed or skipped analysis MUST NOT be described as clean.
  **Oracle:** UX snapshot tests for every non-success cause.
- `SC-PROD-019`: Every supported semantic scan MUST execute both an independent
  deterministic discovery lane and a bounded model-native discovery lane. Every
  normalized deterministic candidate MUST be investigated by the Auditor, and
  the model-native lane MUST run even when deterministic analyzers emit zero
  candidates. **Oracle:** zero-signal, deterministic-only and cross-lane merge
  fixtures prove Auditor invocation, mandatory coverage and exact provenance.
- `SC-PROD-020`: Final submission MUST provide an accessible Git repository with
  source, README installation/run/example instructions, a locked dependency
  declaration, unit tests, configuration, runnable notebook, reproducible
  dataset links or fixed-seed generators, and a PDF or HTML report containing
  the problem, solution, experiments, metrics and conclusions. A submitted web
  service MUST additionally include a Dockerfile, launch instructions and a
  2–5 minute demonstration screencast; every submitted link MUST be readable by
  the evaluator. **Oracle:** versioned submission manifest plus clean-room
  install, notebook/report, Docker build, duration and anonymous-link checks.
- `SC-PROD-021`: Before final submission, the project MUST record the
  instructor-confirmed deadline year/timezone and evidence that the team-size
  rule is satisfied or individual execution was approved. **Oracle:** G9
  administrative checklist contains dated confirmation references and no
  unresolved submission assumption.

## Personas and journeys

| Persona | Goal and authority | Normative journey | Recovery/success oracle |
|---|---|---|---|
| Developer | inspect own checkout/results and explicitly apply a patch; cannot modify protected evaluator/policy | local scan → evidence/verdict → patch → sandbox validation → diff review → explicit apply → ordinary human review | incomplete/refusal is explicit non-pass; checkout unchanged before apply; safe control has no confirmed finding |
| AppSec Reviewer | tenant/repository-scoped triage, approval and expiring waiver; cannot rewrite history or reuse waiver across SHA/scope | inspect root cause/evidence → review Skeptic/patch/test → approve/reject/escalate/waive → audit export | decision binds actor/time/SHA/policy/evidence; conflicting High/Critical goes to human; waiver has scope/reason/expiry |
| Platform Administrator | configure integration, runner, provider, egress/retention and budgets; cannot read another tenant implicitly | install with minimum permissions → select profiles/policy → conformance run → health/budget/retention → revoke/incident action | capability/isolation failure stops positive gate; canaries absent from telemetry; duplicate webhook creates one run |

Repository, SCM and tool content are untrusted for all personas. Platform admin
does not replace AppSec approval; AppSec does not receive infrastructure secrets;
Developer cannot make a patch bypass validation.

## Release scope

| Capability | v0.1 Core | v0.2 Workflow pilot | v0.5 beta | v0.9 RC | v1.0 |
|---|---:|---:|---:|---:|---:|
| Python CWE-89 detect/repair | yes | yes | yes | yes | yes |
| Own secret/dependency checks | basic | yes | yes | yes | yes |
| JS/TS and Go semantic support | coverage-only | coverage-only | yes | yes | yes |
| Offline CLI/reports | yes | yes | yes | yes | yes |
| Backend/SCM | no | GitHub | GitHub + GitLab | hardened | yes |
| Production blocking | no | advisory | calibrated new-code | policy-controlled | yes |
| Tenant pilot controls | no | basic | expanded | hardened | yes |
| SSO/HA/enterprise operations | no | no | no | required | yes |
| Independent model-native discovery | yes | yes | yes | yes | yes |

`v0.2` is pilot-only. Core MVP excludes web UI, auto-merge, unrestricted shell/
network, multi-tenant backend, production SLO and general accuracy claims.

### `DEMO-CWE89-001`

Pinned Python endpoint reads HTTP `user_id` and interpolates it into a SQL
execute sink. Deterministic analysis builds source/flow/interpolation/sink and
missing-binding evidence while an independent model-native pass reads bounded
repository context without requiring a scanner seed. The two lanes converge
with provenance before the Auditor investigates every normalized candidate and
the independent Skeptic reaches a bounded verdict. Architect emits a minimal
parameterized-query unified diff and security test. Ephemeral sandbox applies
it, parses/compiles, runs existing + PoC/PoC+, rescans, and emits
JSON/SARIF/Markdown/HTML while original checkout stays unchanged until explicit
apply.

Mandatory controls:

1. equivalent parameterized query → zero confirmed CWE-89 and zero patch;
2. vulnerable code plus “ignore security” comment → same finding/evidence;
3. refusal/empty/schema-invalid model → `INDETERMINATE`, never `PASS`;
4. malformed/path-escaping/regressive patch → rejected, checkout unchanged;
5. mixed Python/JS/Go in v0.1 → exact unsupported coverage, no repository pass;
6. connected pilot duplicate webhook → one summary/run; stale HEAD → superseded;
   fork/untrusted contribution → no secrets.
7. deterministic lane returns zero candidates while the model-native fixture
   discovers a seeded root cause → Auditor runs and provenance is
   `model_native`;
8. both lanes discover the same root cause → one deduplicated finding with
   provenance `hybrid`;
9. both lanes complete with zero candidates → model-native coverage is still
   present; model refusal/error instead yields `INDETERMINATE`, never `PASS`.

The reviewed case specification is
[`mvp-cwe89.yaml`](../evaluation/cases/mvp-cwe89.yaml). Narrative product
explanation in `docs/PRODUCT.md` is informative and cannot override this spec.
