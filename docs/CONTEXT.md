# SecureCode AI — актуальный контекст

Последнее обновление: 13 августа 2026 года.

## Текущая позиция

- Фаза: `P1 — Engineering foundation` выполняется.
- Последняя завершённая задача: `P1.5 — versioned domain contracts`, commit
  `cb7fdb6d3efdc6feb4417d3483bb75ede0a3a98f`.
- Текущая внешняя задача: `P1.4` ожидает GitHub ruleset/failing-PR receipt;
  следующий независимый increment — `P1.6 — append-only events/stable IDs`.
- Gate: `G0 Definition Ready` эффективен; strict validator `PASS`.
- Normative baseline: `0.2.0`, lifecycle `frozen`; immutable commit
  `f5cd4ef2a0f7130d16cb2c206091908be71b0702`.
- Normal validator: `PASS`; normative hash
  `dedb43be8ba055dfa47858b975630b4c870af3bed2dda842b0e8422c8354b5c9`.
- Final independent reviews baseline `0.2.0`: `PASS/PASS/PASS` на exact
  normative hash; отдельная successor attestation закоммичена.
- P1.1 verification: required inventory present, no executable code/imports/
  dependencies, protected diff empty, strict G0 `PASS`, independent
  architecture review `PASS`.
- P1.2 verification: one `uv.lock`; clean non-editable install/imports on
  Python 3.12/3.13/3.14; Python 3.11 and lock drift rejected; six distributions
  built; protected diff empty; strict G0 and independent review `PASS`.
- P1.3 verification: exact Ruff 0.15.22, mypy 2.3.0, pytest 9.1.1 and
  pytest-cov 7.1.0 in the root lock; one offline/no-sync quality entrypoint;
  clean non-editable Python 3.12/3.13/3.14 runs; 17 tests; closed Core/contracts
  import allow-lists; Core-only branch coverage floor; sanitized child env;
  static-preflight, low-coverage, zero-test and repository-mutation negatives;
  independent architecture and security/evaluation reviews `PASS/PASS`.
- P1.4 local candidate verification: closed pre-commit/CI policy, staged and
  reachable-history secret scanning, permanent vulnerable-dependency negative,
  strict zizmor and Python 3.12–3.14 quality matrix pass; independent
  product/architecture/security-evaluation reviews are `PASS/PASS/PASS` on the
  staged candidate. This proves the local increment only, not the external
  GitHub ruleset or failing-PR merge-block criterion.
- P1.5 candidate verification: 92 contract/schema tests at 86.54% branch
  coverage; 152 repository tests pass on CPython 3.12/3.13/3.14; deterministic
  schema drift check, strict G0, Ruff/mypy, ECMAScript regex compilation and a
  wheel containing all five schemas pass. Architecture/security reviews found
  and remediation now tests manifest identity binding, unsupported-language
  fail-closed semantics and recursive extension tenant binding. Independent
  product/architecture/security-evaluation reviews are `PASS/PASS/PASS`;
  clean post-commit schema/contract/quality/strict-G0 verification PASS.
- Решение `GO FOR P1 ONLY` не разрешает начинать P2+ или ослаблять frozen
  contracts; `G1 Foundation Ready` остаётся открытым.

## Принятые последние изменения

### CR-014 / D-027 — mandatory dual-lane discovery

Каждый product scan в supported semantic scope запускает два
независимых lane на одной immutable revision:

```text
deterministic analyzers → RawSignal ─┐
                                  ├→ normalization/EvidenceGraph
model-native code discovery ─────┘   → Auditor per candidate
                                      → Skeptic/Finding Gate
```

Инварианты:

- scanner output не является finding/verdict;
- каждый normalized deterministic/model-native candidate имеет Auditor
  interpretation receipt;
- model-native discovery обязателен даже при нуле scanner signals;
- completed-zero — schema-valid `SUCCEEDED` с `candidates=[]` и complete
  receipt; empty/refused/invalid/timeout/provider error — не completed-zero;
- mandatory model non-success даёт `INDETERMINATE`, не clean/PASS;
  уже confirmed blocking finding остаётся `FAIL` с health degradation;
- provenance закрыт: `deterministic | model_native | hybrid`;
- code читается только через bounded read-only `RepositoryView`; no
  shell/write/arbitrary filesystem/network;
- incompatible DC3/provider/egress profile отклоняется до network bytes
  и не включает silent deterministic-only fallback.

### CR-015 — complete assignment delivery

В product spec, plan и traceability включены:

- Git repository, source, README installation/run/example;
- locked dependency file, configuration, unit tests, runnable notebook;
- PDF/HTML report с problem/solution/experiments/metrics/conclusions;
- dataset links или fixed-seed generator;
- clean-room reproducibility и anonymous/public link check;
- Dockerfile, web-service launch instructions и 2–5 minute screencast;
- tracked confirmation deadline year/timezone и team-size/individual approval.

Два последних административных факта пока внешне не подтверждены.
Они не меняют P1 contracts, но являются blocking criteria `P9.12/G9`;
спросить преподавателя нужно заранее.

### CR-016 / D-028 — restricted P7 Evaluation Lab

RLM-inspired exploration, DSPy/GEPA, SkillOpt-style optimization и synthetic
generation приняты только как optional offline `P7.12–P7.16`.
Они не Core/runtime dependency и не product claim.

- optimizer видит train/dev, но не locked expectations/evaluator/policy/specs;
- generated code имеет immutable read-only `CodeIndex`, no network/
  credentials и bounded sandbox;
- synthetic case остаётся candidate до executable oracle, independent
  root-cause review, fixed provenance и lineage-safe split;
- promotion требует held-out improvement, zero-tolerance security gates
  и human/AppSec approval;
- production agents никогда не self-modify/self-promote.

## Продукт и порядок релизов

Целевой `v1.0`: один Core для offline CLI, CI worker и backend
control plane; GitHub-first, GitLab beta; Python-first Core, обязательные
Python/JS/Go к beta/final. Backend по умолчанию не получает checkout.
До `P7.9` SCM режим advisory; затем первый rollout — calibrated
new-code blocking. Auto-Fix — candidate до sandbox validation и required
human/policy gate.

## Модель разработки

Основной Codex-agent — единственный `Primary Integrator` и owner
решений/baseline. Субагенты — bounded read-only reviewers или
path-isolated implementers; они не self-accept и не меняют baseline.
Постоянное разделение review: product — scope/traceability;
architecture — wire contracts; security/evaluation — fail-open, policy и
metric loopholes. Главный агент сводит corrections и повторно
валидирует integrated bytes.

## Ближайшие действия

1. Начать `P1.6` append-only events/stable IDs и затем независимый от него
   `P1.7` secret-safe config только через отдельные constrained task packets.
2. Получить от владельца GitHub remote/ruleset authority, потребовать `ci / gate`
   и зафиксировать failing-PR merge-block evidence для закрытия `P1.4`; не
   закрывать G1 до всех доказательств `P1.4–P1.13`.
3. После P1.6/P1.7 реализовать fake provider (`P1.8`) и graph-independent
   in-memory runtime (`P1.9`) без начала P2 до эффективного G1.

## Критические запреты

- не обещать гарантированную безопасность;
- не считать SAST, LLM или generated synthetic cases ground truth;
- не позволять code/docs/SCM/tool output инструктировать agent;
- не интерпретировать refusal/empty/incomplete/error как clean;
- не давать LLM/generator свободный shell/network или evaluator access;
- не позволять implementation agent менять specs/evaluator/gate evidence;
- не хранить API keys, secrets и raw source в telemetry;
- не создавать расходящиеся Core для CLI/backend.
