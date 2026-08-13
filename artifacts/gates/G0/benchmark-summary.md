# G0 evaluation baseline summary

G0 contains no model accuracy benchmark result. It freezes the measurement
contract and a first-party definition corpus:

- dataset: `SC-MVP-CWE89` version `1.1.0`;
- cases: 21 detection/safe/interprocedural/dual-lane/injection/provider-fault/
  patch/coverage/replay specifications;
- file SHA-256:
  `436843b02bee53cc2997903b3e61afb9734ff5fa2580756ecba7344e92c12663`;
- scope: Python CWE-89 Core MVP contract only;
- operation before calibration: advisory;
- zero-tolerance: fail-open, unauthorized capability/egress, tenant/secret leak,
  stale SHA, evaluator tamper, sandbox downgrade, PASS without coverage.

External datasets, repeated model runs, uncertainty and numerical promotion
thresholds are required at G7. Their absence at G0 is an explicit deferral and
prevents broad or production blocking claims.

The same source file supplies the separately locked eight-case
`SC-ADVERSARIAL-SEED` for G3 definition conformance. Adaptive/provider-wide
attacks remain a distinct `P8.3/G8` dataset and cannot be reported as if run.

P7 additionally defines an isolated Evaluation Lab, but no RLM/DSPy/GEPA/
SkillOpt or synthetic-case quality result is claimed at G0. A generated case is
not ground truth until its executable oracle, independent review, provenance and
lineage-safe split pass.
