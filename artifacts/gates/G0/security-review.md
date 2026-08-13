# G0 security review

Verdict: `PASS — DEFINITION SECURITY/EVALUATION ONLY`.

Reviewed boundaries: untrusted repository/SCM, prompt injection/refusal, tools,
provider/egress, worker/sandbox, backend/tenant/storage, patch/report output,
supply chain and operations.

Accepted design invariants:

- no generic shell/network capability for models;
- repository content has no instruction authority;
- non-success model/coverage state cannot become clean/pass;
- source stays in runner by default; `DC4` never crosses protected sinks;
- exact SHA/idempotency for SCM and workflow side effects;
- rootless/gVisor isolation profiles with no silent downgrade;
- separate tenant-scoped metadata/artifacts and least-privilege credentials;
- protected evaluator/policy/spec and independent validation;
- advisory only before calibration.
- mandatory dual-lane discovery; zero scanner signals never skips model-native;
- provider/egress incompatibility produces zero network bytes and
  `INDETERMINATE`, not deterministic-only fallback;
- Evaluation Lab has no production credentials/network/locked-test access or
  self-promotion path.

Required first security evidence is enumerated by TM-001–TM-026, PV-001–PV-005
and `specs/traceability/requirements.yaml`. Until those tests run, residual risks
remain open and no claim of production readiness is allowed.

Normal validation verifies canonical outcomes, fixed/adaptive dataset
separation, metric denominators, machine-enforced policy/provider fixtures and
31/31 threat mappings. The final independent verdict for baseline `0.2.0` is
recorded in `independent-reviews.md`; implementation security remains unproven.
