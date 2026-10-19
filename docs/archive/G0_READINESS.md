# G0 Definition Ready — readiness assessment

Дата: 13 августа 2026 года  
Baseline: `securecode-definition-0.2.0`  
Текущий verdict: `PASS — GO FOR P1 ONLY`

## Outcome first

CR-014, CR-015 и CR-016 приняты и синхронизированы с нормативными
контрактами. Normal validator проходит на content hash
`dedb43be8ba055dfa47858b975630b4c870af3bed2dda842b0e8422c8354b5c9`:
228 требований, 38 source/change mappings, 31 threat/privacy mappings,
9 policy fixtures, 5 provider-schema fixtures и 2 исполнимых
provider/egress preflight fixtures.

Формальный `GO FOR P1 ONLY` эффективен. Три независимых `PASS` относятся к
одним нормативным байтам; immutable baseline commit является строгим предком
отдельной successor attestation, а `python scripts/validate_g0.py
--require-frozen` завершился с exit `0`.
Никакая implementation correctness, benchmark accuracy или production
security на G0 не заявляется.

## Closure map

| G0 criterion | Evidence | Assessment |
|---|---|---|
| Original assignment and delivery bundle | `PROJECT_BRIEF.md`, `BRIEF-001–015`, `SC-PROD-020/021` | definition PASS |
| Accepted change control | `CR-001–016`, `D-001–028` | definition PASS |
| Mandatory dual-lane audit | `D-027`, `SC-PROD-019`, workflow/stage catalogue | definition PASS |
| Direct model code reading | bounded `RepositoryView`, model-native receipts | definition PASS |
| Scanner interpretation | `RawSignal` → normalized candidate → Auditor receipt | definition PASS |
| Refusal/error/profile fail-closed | outcome contracts plus evaluation/provider fixtures | definition PASS |
| Exact provider/egress preflight | `SC-MODEL-007`, `SC-EGRESS-008`, semantic fixtures | machine PASS |
| Origin-stratified quality metrics | explicit per-origin confusion counts/micro/macro formulas | definition PASS |
| Restricted Evaluation Lab | `D-028`, `SC-EVAL-019–024`, P7.12–P7.16 | definition PASS; optional |
| Full threat/privacy mapping | `TM-001–026`, `PV-001–005` | 31/31 mapped |
| Reproducible evaluation baseline | locked cases/dataset hashes/metrics/thresholds | definition PASS |
| Independent final reviews | G0 review packet | PASS/PASS/PASS current hash |
| Immutable/effective gate | two-commit proof + strict validator | PASS |

## Explicit deferrals that do not block P1

- External benchmark selection and exact hashes are owned by `P7.6`; current
  accuracy claims remain limited to a 21-case first-party specification corpus.
- Numeric production thresholds are owned by `P7.9`; SCM remains advisory
  until calibration is signed.
- RLM-inspired search, DSPy/GEPA, SkillOpt-style optimization and synthetic
  generation are isolated P7 experiments, not Core dependencies.
- Web UI is outside the API/CLI/SCM definition baseline.
- Deadline year/timezone and approval for individual work remain external
  administrative inputs and block `P9.12/G9`, not P1 contracts.

## Authorized boundary after effective GO

The first allowed work is `P1 Engineering foundation`: repository ownership
layout, packaging and locked dependencies, one quality command, versioned
contracts, fake provider, bounded `RepositoryView`, LocalRuntime, CLI skeleton,
fixture factory and drift protection. Scanner implementation waits for the
relevant P2 task; agent investigation for P3; repair/sandbox for P4; SCM/backend
for later gates.
