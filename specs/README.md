# SecureCode AI specifications

Статус: `baseline 0.2.0 — G0 delta review`. Документы с lifecycle `accepted` образуют
нормативный definition baseline; его content hash и gate decision фиксируются в
`artifacts/gates/G0/`. Это разрешение начать P1, а не доказательство реализации.

Operating model описан в
[docs/SPEC_DRIVEN_DEVELOPMENT.md](../docs/SPEC_DRIVEN_DEVELOPMENT.md).

## Правила

- Accepted specifications являются нормативным источником для реализации.
- Каждый нормативный `MUST` получает стабильный requirement ID и acceptance
  oracle.
- Implementation task не изменяет accepted specs, acceptance evaluator или
  gate evidence без явного spec/change-control scope.
- Breaking change требует `CR-NNN`, ADR, migration/compatibility plan и новой
  версии baseline.
- Критический `TBD` запрещён в accepted baseline.
- Примеры, schemas, transition tables и policy fixtures проверяются CI.
- Raw secrets, proprietary source и private chain-of-thought здесь не хранятся.

## Текущий baseline

- [product/requirements.md](product/requirements.md) — goals, releases and
  stable product requirements.
- [system/architecture.md](system/architecture.md) — ports, runtime, persistence,
  artifact and sandbox baseline.
- Contracts: [domain](contracts/domain.md), [API](contracts/api.md),
  [events](contracts/events.md), [CLI](contracts/cli.md),
  [policy](contracts/policy.md), [SCM](contracts/scm.md),
  [reports](contracts/reports.md), machine-readable
  [provider profile](contracts/provider-profile.schema.json) and
  [egress/retention policy fixtures](contracts/policy/fixtures.yaml).
- [behavior/workflows.md](behavior/workflows.md) и machine-readable
  [stage catalogue](behavior/stage-catalogue.yaml) — dual-lane state machines,
  mandatory coverage, guards, bounded loops, retries and validation ladder.
- Security: [capabilities](security/capability-policy.md) and
  [classification/egress/retention](security/data-classification.md); full risk
  register is in [docs/security/THREAT_MODEL.md](../docs/security/THREAT_MODEL.md).
- Evaluation: [protocol](evaluation/protocol.md),
  [dataset lock](evaluation/datasets.lock), [metrics](evaluation/metrics.yaml),
  [threshold policy](evaluation/thresholds.yaml) and pinned cases.
- [traceability](traceability/README.md) — source requirement → normative IDs →
  task → test → gate evidence.
- [templates](templates/implementation-task.yaml) — constrained implementation
  task packet.

## Baseline lifecycle

```text
draft → in_review → accepted → deprecated/superseded
```

`accepted` требует review, отсутствия критических `TBD`, валидных contracts и
полной traceability обязательных требований. Baseline фиксируется версией,
commit SHA и content hash. После freeze implementation task не может менять
accepted spec/evaluator/gate evidence без отдельного CR.
