# Evaluation protocol

Spec version: `0.2.0`  
Lifecycle: `accepted and frozen for Core MVP`; beta datasets, calibration and
restricted Evaluation Lab extensions are explicitly deferred to `P7.6–P7.16`
with the risks below.

## 1. Claims boundary

Core MVP evaluation demonstrates contract correctness and the pinned Python
CWE-89 vertical slice. It is not generalized to broad vulnerability,
language or enterprise production accuracy. Beta claims require grouped external
and temporal holdouts, calibration and independent review.

- `SC-EVAL-001`: Confirmatory inputs, evaluator and metrics MUST be frozen before
  a confirmatory run; amendments create a new version and preserve history.
  **Oracle:** run manifest hashes match [`datasets.lock`](datasets.lock),
  [`metrics.yaml`](metrics.yaml) and [`thresholds.yaml`](thresholds.yaml).
- `SC-EVAL-002`: Implementation/repair agents MUST NOT read or modify locked
  expected results during a run. **Oracle:** path/capability enforcement test.
- `SC-EVAL-003`: Failure, refusal, timeout and invalid output MUST be counted as
  explicit outcomes, never relabelled negative/clean. **Oracle:** result table
  reconciliation and zero fail-open counters.

## 2. Dataset strata and governance

1. `SC-MVP-CWE89`: first-party hermetic case specification, locked now.
2. `SC-REPAIR-CWE89`: vulnerable revision, PoC/PoC+, invariant and reference
   patch generated from the locked cases in P4 and versioned before repair runs.
3. `SC-ADVERSARIAL`: injection/refusal/tool/egress corpus specified by the
   focused threat model; initial fixed cases plus later adaptive attempts.
4. `SC-BETA-EXTERNAL`: repository/CVE benchmarks selected and pinned in P7 only
   after license, acquisition, deduplication and leakage review.

- `SC-EVAL-004`: Every dataset entry MUST declare ID/version/source/revision,
license, content/build hashes, case IDs, split, root-cause group, exclusions and
ground-truth status. **Oracle:** dataset-lock schema/lint.
- `SC-EVAL-005`: Splits MUST group repository, CVE/fix lineage, clones and
root-cause families; random snippet split is forbidden. **Oracle:** leakage
checker reports zero group intersection.
- `SC-EVAL-006`: Development MAY tune rules/prompts; calibration MAY select
thresholds; locked test MUST NOT influence them; temporal holdout SHOULD be
after relevant model knowledge cutoffs. **Oracle:** access log and split manifest.
- `SC-EVAL-007`: External data MUST NOT enter confirmatory evaluation until
license, immutable revision, hashes and acquisition procedure resolve. **Oracle:**
unresolved candidate is excluded automatically.

Deferral/risk: external benchmarks are not yet downloaded because implementation
has not started and licenses/revisions can change. `G0` accepts only the locked
MVP specification corpus and forbids broad claims; `G7` cannot pass until exact
external data is pinned and independently checked.

## 3. Baselines and ablations

Mandatory baselines: `deterministic_only`, scanner-seeded investigation without
independent discovery, `model_native_only`, `one_shot_llm`, and full dual-lane
`hybrid`. Comparable model strategies receive matched accessible facts and
declared model/tool budgets; deterministic-only reports actual resources rather
than pretending token equivalence. Beta ablations remove EvidenceGraph, Skeptic,
root-cause localization, PoC+ and provider fallback one at a time. Repair
compares no repair, one-shot patch, bounded repair and reference patch.

These baseline/ablation modes are evaluation configurations, not silent product
fallbacks: an operational supported-scope scan cannot publish `PASS` without the
mandatory dual-lane catalogue.

- `SC-EVAL-008`: Model snapshot/profile, prompt/schema/tool/policy versions,
seeds, temperature, token/time/call/retry budgets MUST be recorded. **Oracle:**
run manifest completeness check.
- `SC-EVAL-009`: Stochastic configurations MUST report individual runs and an
aggregate over the predeclared repetition count. **Oracle:** no missing run IDs
and aggregation recomputes exactly.
- `SC-EVAL-010`: Baselines MUST receive equivalent input facts and resource
budgets except for the intentionally ablated component. **Oracle:** comparison
manifest diff allowlist.
- `SC-EVAL-018`: Evaluation MUST report complete confusion matrices for
  deterministic-only, model-native-only and full-hybrid configurations,
  including the stratum where deterministic analysis emits zero candidates,
  and MUST verify that every deterministic candidate receives an Auditor
  receipt. Full-hybrid origin reporting MUST attribute confirmed TP/FP and
  recall contribution to `deterministic|model_native|hybrid`, retain missed
  cases as explicit unattributed FN/TN, and reconcile exactly to the full-
  hybrid global matrix; it MUST NOT invent an origin-specific recall for a
  case with no candidate. **Oracle:** independent configuration/origin
  recomputation, zero-signal cases and dropped-candidate reconciliation.

## 4. Metrics

Detection: case/finding precision, recall, F1, security-weighted F2, FP/KLOC,
false blocks/PR, source/sink/root-cause localization, CWE accuracy, evidence
completeness, coverage, abstention/indeterminate and refusal-induced FN.

Repair: apply/parse/build/existing-test/security-PoC/PoC+ pass rates,
`correct_and_secure`, new blocking regressions, root-cause versus symptom repair
and human acceptance reason.

Adversarial/fault: `ASR@1/10/100`, benign defensive-security over-refusal,
`non_success_to_pass_count`, `refusal_to_no_finding_count`, unauthorized
tool/network/egress/evaluator operations, tenant/secret leakage and cost
amplification.

Operations: p50/p95 latency, tokens/cost per run and confirmed finding, peak
CPU/RAM/disk, attempt count and deterministic replay stability.

- `SC-EVAL-011`: Metric formulas and denominators MUST come from
  [`metrics.yaml`](metrics.yaml); missing outcomes MUST remain in the denominator
  defined there. **Oracle:** independent recomputation from event-level output.
- `SC-EVAL-012`: Beta repository metrics MUST use repository/root-cause clustered
  confidence intervals. **Oracle:** bootstrap unit is validated by metric code.

## 5. Required fault/adversarial matrices

Provider: HTTP-200 refusal/filter/empty/semantic-empty/invalid schema/max-token,
context exhaustion, timeout, 429, 5xx, interrupted/duplicated stream, stale or
replayed response and all-fallback failure.

Injection: attack family × code/comment/docs/SCM/tool output × encoding ×
provider/model × attempt count × sought capability × expected route.

- `SC-EVAL-013`: Every mandatory provider case MUST have one exact normalized
  status and run outcome. **Oracle:** exhaustive table test.
- `SC-EVAL-014`: Repeated/adaptive attacks MUST be reported as `ASR@k`, not only
  a single average. **Oracle:** predeclared attempt sets exist for k=1/10/100 at
  the applicable beta gate.

## 6. Promotion and threshold policy

Zero-tolerance conformance failures: fail-open routing; unauthorized tool/
network/egress; tenant or secret leakage; stale-SHA publication; evaluator/
policy tampering; sandbox silent downgrade; and `PASS` without coverage. One
occurrence is a failed gate.

Statistical confidence/severity thresholds are not guessed. Until calibration,
operation is advisory. At beta, thresholds are selected only on calibration
data under AppSec constraints (recall lower bound, FP/KLOC upper bound,
correct-and-secure lower bound and cost/latency envelope), frozen, and then
evaluated once on locked test. Rejected alternatives are retained.

- `SC-EVAL-015`: Pre-calibration policy MUST be advisory. **Oracle:** policy
  compiler rejects statistical blocking without a signed calibration record.
- `SC-EVAL-016`: Threshold selection MUST NOT read locked-test outcomes.
  **Oracle:** access/provenance separation and freeze timestamp.
- `SC-EVAL-017`: A release claim MUST name corpus/version, languages/CWEs,
  configuration, uncertainty and known exclusions. **Oracle:** claim checklist
  rejects an unscoped statement.

## 7. Reproducibility

The evaluation image, OS/architecture, dependency locks, tool/model/prompt/
policy/schema versions, dataset hashes and commands are part of the run manifest.
Computational replay and replication across a changed provider/repository set are
reported separately.

## 8. Restricted P7 Evaluation Lab

RLM-inspired exploration, DSPy/GEPA prompt optimization, SkillOpt-style skill
optimization and synthetic-case generation are optional offline evaluation
strategies in `P7`; none is a Core MVP runtime dependency or a product-quality
claim. Production agents never edit or promote their own prompts, skills,
policies, capabilities, evaluators or thresholds.

- `SC-EVAL-019`: A generated case MUST remain a candidate until it has fixed
  seed/generator/version/input hashes, an executable oracle, independent
  root-cause review, license/provenance metadata and lineage-grouped split
  assignment. **Oracle:** candidate acceptance checklist and deliberate
  duplicate/wrong-oracle/leakage fixtures.
- `SC-EVAL-020`: Prompt and skill optimization MUST run offline on train/dev
  only and may reuse only datasets registered in `datasets.lock` with verified
  license/provenance, purpose authorization and lineage-safe split assignment;
  locked-test expectations, evaluator, policies, capabilities, schemas and
  thresholds are inaccessible and immutable. **Oracle:** dataset registry and
  license/purpose checks pass, while filesystem/capability canaries and the
  access log show zero protected reads/writes.
- `SC-EVAL-021`: RLM-generated programs MUST execute only in a credential-free,
  no-network, resource-bounded sandbox over an immutable read-only `CodeIndex`;
  they receive no host shell or production repository write access. **Oracle:**
  escape/network/write/resource-abuse corpus has zero unauthorized effects.
- `SC-EVAL-022`: Every prompt/skill/RLM candidate MUST be a versioned immutable
  artifact with optimizer/model/data/tool provenance and rejected-candidate
  history. Promotion requires held-out improvement, all zero-tolerance security
  gates and explicit human/AppSec approval. **Oracle:** promotion-state machine,
  rejected-candidate archive and rollback/replay test.
- `SC-EVAL-023`: Lab comparisons MUST use predeclared resource-equivalent
  ablations where strategies are comparable and report quality, coverage,
  variance, cost, latency, hard-constraint violations, generalization gap and
  cross-model transfer. **Oracle:** manifest-diff allowlist and independent
  metric recomputation.
- `SC-EVAL-024`: Any candidate causing fail-open routing, unauthorized access or
  egress, leakage, evaluator/locked-test access, production self-modification or
  a worse accepted false-block safety floor MUST be rejected regardless of an
  aggregate score. **Oracle:** promotion negative matrix has zero unsafe
  promotions.
