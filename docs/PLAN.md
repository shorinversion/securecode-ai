# SecureCode AI — master plan

Версия плана: `0.7`  
Статус: `active`  
Последнее обновление: 18 августа 2026 года
Текущая фаза: `P1 — Engineering foundation` — выполняется
Текущий gate: `G0 — Definition Ready` — пройден

Этот файл является каноническим планом проекта от исходной постановки до
релиза и закрытия. Он задаёт порядок работ, зависимости, проверяемые результаты
и условия перехода между фазами. История изменений хранится в
[CHANGELOG.md](../CHANGELOG.md), причины архитектурных решений — в
[DECISIONS.md](DECISIONS.md).

## 1. Как читать и обновлять план

### Уровни планирования

- `L0 — Outcome`: итоговый результат проекта.
- `L1 — Release`: проверяемый продуктовый инкремент.
- `L2 — Phase/Epic`: крупный этап, завершающийся gate review.
- `L3 — Task`: ограниченная работа с одним проверяемым результатом.
- `L4 — PR/Test`: минимальная единица реализации и доказательства.

### Статусы

- `TODO` — работа ещё не начата;
- `IN PROGRESS` — ведётся сейчас;
- `BLOCKED` — указан конкретный внешний blocker;
- `DONE` — результат существует и приложено доказательство;
- `DEFERRED` — сознательно перенесено с причиной и целевой фазой;
- `CANCELLED` — отменено, история и причина сохранены.

Процент готовности сам по себе не используется. Задача считается завершённой
только при выполнении acceptance criteria и наличии воспроизводимого evidence.

## 2. Итоговый outcome

Проект закрыт, когда существует воспроизводимая, документированная и защищённая
система, которая:

1. анализирует локальные репозитории Python, JavaScript/TypeScript и Go;
2. объединяет детерминированные сигналы и evidence-grounded LLM reasoning;
3. классифицирует findings по CWE/OWASP и показывает проверяемый evidence path;
4. предлагает минимальные patch candidates и security regression tests;
5. валидирует патчи в sandbox через многоступенчатый gate;
6. работает как offline CLI и как CI-connected worker с backend control plane;
7. интегрируется с GitHub и GitLab, комментирует PR/MR и выставляет SHA-bound
   blocking status согласно policy;
8. имеет benchmark evidence, threat model, audit trail, документацию, тесты,
   notebook, демонстрационный репозиторий и сценарий защиты.

## 3. Лестница релизов

| Инкремент | Результат | Exit gate |
|---|---|---|
| `R0 Definition baseline` | Решения, threat model, scope и evaluation plan достаточны для реализации | `G0` |
| `R1 Engineering foundation` | Воспроизводимый skeleton, contracts, CLI и CI качества | `G1` |
| `R2 Core MVP v0.1` | Полный локальный vertical slice: finding → evidence → verdict → patch → validation → report | `G4` |
| `R3 Enterprise Workflow MVP v0.2` | CI + backend + GitHub reference integration в advisory pilot | `G6` |
| `R4 Multi-language beta v0.5` | Python + JS/TS + Go, обе SCM, benchmark и calibration | `G7` |
| `R5 Release candidate v0.9` | Security/reliability/operations готовы к ограниченному пилоту | `G8` |
| `R6 v1.0 / final project` | Pilot-ready релиз, учебные артефакты, защита и handoff завершены | `G9` |

`Core MVP` и `Enterprise MVP` разделены намеренно. Сначала проверяется ценность
и корректность ядра на одном сквозном сценарии; затем вокруг устойчивого ядра
строятся control plane и SCM-интеграции.

Календарные даты намеренно не выдумываются до фиксации дедлайна, доступной
команды и закрытия `G0`. После `G0` задачи критического пути оцениваются,
раскладываются по итерациям и получают целевые даты; изменение даты после этого
проходит обычный change-control процесс.

## 4. Критический путь

```text
P0 Definition
  → P1 Foundation
  → P2 Deterministic analysis
  → P3 Evidence + agent investigation
  → P4 Repair + validation                  = Core MVP v0.1
  → P5 CI + reference SCM
  → P6 Backend control plane                = Enterprise Workflow MVP v0.2 pilot
  → P7 Multi-language + evaluation          = Beta v0.5
  → P8 Enterprise hardening                 = RC v0.9
  → P9 Release, defense and handoff          = v1.0 / closure
```

Documentation, tests, security review, observability and change control идут
сквозным потоком, а не откладываются на конец.

## 5. Общие gates и доказательства

### Definition of Ready для задачи

- цель и границы сформулированы;
- зависимости доступны или отмечены;
- acceptance criteria проверяемы;
- известны security/privacy последствия;
- определено, какой артефакт или тест докажет завершение.

### Definition of Done для задачи

- реализация и документация находятся в репозитории;
- unit/integration/security tests проходят;
- ошибки, негативные сценарии и rollback рассмотрены;
- telemetry не раскрывает source code или secrets;
- результат связан с issue/task ID и review;
- changelog обновлён, если изменилось наблюдаемое поведение, контракт,
  архитектура, безопасность или scope.

### Gate evidence packet

Каждый `G*` получает отдельный пакет доказательств:

```text
artifacts/gates/Gx/
├── checklist.md
├── test-results/
├── benchmark-summary.md
├── security-review.md
├── open-risks.md
└── decision.md
```

Gate нельзя закрыть фразой «работает на моей машине». `decision.md` фиксирует
дату, проверенный commit SHA, версии policy/workflow/tools/models, решение
`GO | CONDITIONAL GO | NO-GO` и оставшиеся риски. Для учебного этапа reviewer —
автор и куратор; для пилота добавляются AppSec и владелец платформы.

### Контрольные точки внутри каждой фазы

1. **Entry review:** входные зависимости, риски и scope подтверждены.
2. **Midpoint demo:** показан работающий инкремент, а не только код или слайды.
3. **Adversarial review:** проверены негативные и security-сценарии.
4. **Exit gate:** собран evidence packet и принято формальное решение.

## 6. P0 — Definition and risk retirement

Цель: превратить исследовательскую идею в decision-complete техническое
задание и снять самые дорогие неопределённости до написания платформы.

| ID | Подзадача | Зависит от | Проверяемый результат | Статус |
|---|---|---|---|---|
| `P0.1` | Зафиксировать исходное задание | — | `PROJECT_BRIEF.md` | `DONE` |
| `P0.2` | Собрать научные, отраслевые и стандартные источники | P0.1, P0.17 | `RESEARCH.md`, search log и claim ledger с первичными ссылками/ограничениями | `DONE` |
| `P0.3` | Импортировать и критически проверить внешний Deep Research | P0.2 | полная hash-verified копия, impact review и resolution/quarantine всех material claims | `DONE` |
| `P0.4` | Зафиксировать пользовательские роли и top-3 journeys | P0.1 | developer, AppSec, platform admin journeys | `DONE` |
| `P0.5` | Зафиксировать границы Core MVP и Enterprise Workflow MVP | P0.2 | release scope, out-of-scope, `DEMO-CWE89-001` и negative controls | `DONE` |
| `P0.6` | Выбрать Python-first или full multi-language для v0.1 | P0.2 | `D-017`; final scope включает Python/JS/Go | `DONE` |
| `P0.7` | Выбрать reference SCM: GitHub-first или GitLab-first | P0.4 | `D-018`, GitHub minimum permission matrix и SCM conformance contract | `DONE` |
| `P0.8` | Сравнить graph runtimes | P0.2 | `D-020`: LocalRuntime + TemporalRuntime; LangGraph non-normative | `DONE` |
| `P0.9` | Выбрать storage, queue и sandbox profile | P0.8 | `D-021–D-023`, local/pilot profiles и verification oracles | `DONE` |
| `P0.10` | Создать threat model и abuse-case catalogue | P0.4 | full trust-boundary/risk register + prompt-injection subset | `DONE` |
| `P0.11` | Определить data classification и egress profiles | P0.10 | `D-024`, `DC0–DC4`, deny-default profiles, retention/endpoint schemas | `DONE` |
| `P0.12` | Создать evaluation protocol | P0.2, P0.10, P0.11 | pinned MVP corpus, metrics/baselines/anti-leakage/fault/threshold governance | `DONE` |
| `P0.13` | Создать requirements traceability matrix | P0.1–P0.12 | source requirement → normative IDs → task → test → evidence | `DONE` |
| `P0.14` | Сформировать decision-complete ТЗ через Spec-Driven Development | P0.6–P0.13, P0.16 | versioned `specs/` baseline product/system/contracts/workflow/security/evaluation | `DONE` |
| `P0.15` | Создать project-local context/navigation skill | P0.1, P0.5 | skill, read-only snapshot helper и agent instructions | `DONE` |
| `P0.16` | Зафиксировать SDD, contract-first loop и constraint stack для LLM | P0.1, P0.5 | SDD operating model, spec namespace и task-packet template | `DONE` |
| `P0.17` | Ввести project-specific research protocol и evidence ledger | P0.1–P0.3 | protocol, claim statuses, provenance manifest, exact search/amendment logs | `DONE` |
| `P0.18` | Провести independent completion audit и immutable G0 freeze | P0.1–P0.17 | три substantive PASS, normal validator exit 0, strict frozen validator exit 0, exact baseline commit и effective decision | `DONE` |

### G0 — Definition Ready

Gate пройден, если:

- критические решения P0.6–P0.12 имеют accepted ADR или явный defer с риском;
- у MVP есть один сквозной demo scenario и negative controls;
- threat model покрывает untrusted repository, prompt injection, tool abuse,
  secret leakage, SSRF, tenant isolation и supply chain;
- каждая исходная обязательная поставка отражена в traceability matrix;
- каждый material external claim в ADR/spec имеет resolvable primary source,
  scope/limitation check и запись в claim ledger;
- каждый нормативный `MUST` имеет stable ID и acceptance oracle, а accepted
  specs не содержат критических `TBD`;
- отсутствует нерешённый вопрос, способный изменить repository structure или
  публичные contracts в первой итерации.
- product, architecture и security/evaluation independent reviews дали `PASS`;
- normal definition validator проходит, normative content hash зафиксирован;
- strict frozen validator доказывает существование baseline commit, совпадение
  его normative bytes, полностью закрытый checklist и `GO FOR P1 ONLY`.

## 7. P1 — Engineering foundation

Цель: получить воспроизводимую основу, в которой архитектурные границы и
качество обеспечиваются автоматикой.

| ID | Подзадача | Зависит от | Проверяемый результат | Статус |
|---|---|---|---|---|
| `P1.1` | Создать repository/monorepo layout | G0 | отдельные Core, CLI, server, integrations, tests, fixtures | `DONE` |
| `P1.2` | Настроить packaging и locked dependencies | P1.1 | clean install в новой среде по одной инструкции | `DONE` |
| `P1.3` | Настроить lint, format, type-check, unit tests | P1.1 | единая quality-команда локально и в CI | `DONE` |
| `P1.4` | Настроить pre-commit и базовый CI | P1.3 | PR с ошибкой гарантированно блокируется | `IN PROGRESS` |
| `P1.5` | Ввести versioned domain contracts | P1.1 | schemas `AuditRun`, `FindingCase`, `Evidence`, `Patch`, `Validation` | `DONE` |
| `P1.6` | Ввести append-only events и stable IDs | P1.5 | serialization/round-trip/idempotency tests | `DONE` |
| `P1.7` | Реализовать config и secret-safe env loading | P1.2 | validation, redaction, missing-key diagnostics | `DONE` |
| `P1.8` | Реализовать provider-agnostic model adapter | P1.5, P1.7 | fake provider + endpoint contract tests; native refusal/incomplete/filter/error normalization | `DONE` |
| `P1.9` | Создать `WorkflowRuntime` interface и in-memory adapter | P1.5 | graph-independent domain tests | `DONE` |
| `P1.10` | Создать CLI skeleton и стабильные exit codes | P1.2, P1.5 | `securecode --help`, config diagnostics, machine-readable errors | `DONE` |
| `P1.11` | Создать fixture repository factory | P1.3 | deterministic positive/negative repos и golden files | `DONE` |
| `P1.12` | Настроить structured logs, tracing IDs и redaction tests | P1.6 | raw code/API keys отсутствуют в telemetry snapshots | `DONE` |
| `P1.13` | Ввести spec validation, contract compatibility и drift checks | P1.3, P1.5 | CI валидирует IDs, schemas, examples, compatibility, traceability и protected paths | `DONE` |

### G1 — Foundation Ready

- fresh-clone install и test suite воспроизводимы;
- schemas версионированы и проходят compatibility tests;
- доменная логика не импортирует конкретный graph runtime;
- fake LLM позволяет выполнять тесты без сети и платного API;
- CI блокирует formatting, typing, tests, secret и dependency policy failures;
- CI блокирует invalid spec/contracts, breaking drift без migration и изменение
  protected spec/evaluator paths implementation-задачей;
- минимальное покрытие Core unit tests — `80%`, а policy/security-critical ветви
  имеют отдельные branch и negative tests.

## 8. P2 — Deterministic analysis and reporting

Цель: построить доверенный слой фактов до подключения агентного reasoning.

| ID | Подзадача | Зависит от | Проверяемый результат | Статус |
|---|---|---|---|---|
| `P2.1` | Repository intake и безопасный file inventory | G1 | symlink/path traversal/size-limit tests | `TODO` |
| `P2.2` | Ignore policy, language и dependency discovery | P2.1 | корректные manifests и changed-files map | `TODO` |
| `P2.3` | Tree-sitter/CST adapter и symbol index | P2.2 | location-stable symbols на fixtures | `TODO` |
| `P2.4` | Python `ast` adapter | P2.2 | syntax/error recovery tests | `TODO` |
| `P2.5` | Собственный secret detector + approved external adapter | P2.1 | positive/negative/entropy fixtures, redacted output | `TODO` |
| `P2.6` | Dependency scanner adapter и OSV normalization | P2.2 | pinned vulnerable/safe manifests | `TODO` |
| `P2.7` | Первый semantic rule: Python CWE-89 | P2.3, P2.4 | source → interpolation → SQL sink evidence | `TODO` |
| `P2.8` | Scanner plugin contract и time/resource budgets | P2.5–P2.7 | timeout/crash isolation tests | `TODO` |
| `P2.9` | Normalize, fingerprint и deduplicate `RawSignal`/candidates | P2.8 | stable root-cause IDs, preserved lane lineage and origin across unchanged lines/commits | `TODO` |
| `P2.10` | Evidence graph v1 | P2.3, P2.9 | typed nodes/edges and provenance validation | `TODO` |
| `P2.11` | Severity/confidence/CWE/OWASP mapping | P2.9 | deterministic mapping fixtures | `TODO` |
| `P2.12` | JSON, Markdown/HTML и SARIF reporters | P2.9–P2.11 | schema validation и golden snapshots | `TODO` |
| `P2.13` | CLI deterministic diagnostic/evaluation mode | P2.12 | end-to-end facts/report tests без LLM; mode не выдаёт product `PASS` | `TODO` |

### G2 — Deterministic Core Ready

- обязательные positive и negative fixtures проходят без flaky результатов;
- один и тот же commit/config даёт идентичные normalized signals/candidates;
- каждый `RawSignal` содержит detector provenance и точную location,
  но не сериализуется как final finding/verdict;
- invalid/untrusted repository не выходит за workspace и не выполняет код;
- JSON/SARIF проходят schema validation; Markdown/HTML не допускают injection;
- внешние scanners не являются единственной собственной реализацией проекта.

## 9. P3 — Evidence-grounded agent investigation

Цель: добавить контекстное рассуждение, сохранив детерминированные границы.

| ID | Подзадача | Зависит от | Проверяемый результат | Статус |
|---|---|---|---|---|
| `P3.1` | EvidencePackage и context selection | G2 | source policy, token budget, provenance и truncation tests | `TODO` |
| `P3.2` | Structured Auditor contract | P3.1 | independent `ModelCallStatus` + schema-valid `FindingVerdict` with evidence citations | `TODO` |
| `P3.3` | Auditor bounded investigation loop | P3.2 | stop on confirmation/rejection/budget; no-progress detection | `TODO` |
| `P3.4` | Read-only Skeptic | P3.2 | independent objections; no mutation permissions | `TODO` |
| `P3.5` | Finding Gate и deterministic routing policy | P3.3, P3.4 | confirm/reject/more-evidence/human routes; non-success cannot become pass | `TODO` |
| `P3.6` | Prompt-injection and untrusted-text boundary | P3.1–P3.5 | code/docs/SCM/tool-output/refusal attack corpus cannot alter policy, tools or suppress coverage | `TODO` |
| `P3.7` | Tool allowlist и argument schema validation | P3.3 | unauthorized tool/argument tests fail closed | `TODO` |
| `P3.8` | Replay, cost, latency и node telemetry | P3.3–P3.5 | deterministic fake replay and trace completeness | `TODO` |
| `P3.9` | Human escalation case format | P3.5 | conflicts/budget exhaustion preserve all evidence | `TODO` |
| `P3.10` | Mandatory model-native discovery over `RepositoryView` | P3.1, P3.2, P3.7 | zero-scanner native finding, completed-zero receipt, provider/profile fault and bounded read-only tool tests | `TODO` |
| `P3.11` | Dual-lane convergence and interpretation coverage | P2.9, P2.10, P3.3, P3.10 | deterministic/model-native/hybrid lineage; every normalized candidate has Auditor receipt | `TODO` |

### G3 — Investigation Ready

- Auditor не может подтвердить finding без evidence references;
- Skeptic технически не может редактировать evidence или Auditor verdict;
- route выбирает policy code, а не свободный текст модели;
- повтор loop разрешён только с новым evidence и ограничен budget;
- prompt-injection corpus не расширяет capabilities и не раскрывает secrets;
- refusal, content filter, empty/invalid output, truncation, timeout и provider
  error никогда не переходят в `no_finding/PASS`;
- model-native discovery выполняется даже при нуле scanner signals;
- каждый deterministic candidate и model-native candidate имеет
  доказуемый Auditor receipt; cross-lane merge сохраняет оба lineage;
- incompatible source/egress/provider profile даёт zero network bytes и
  `INDETERMINATE`, а не deterministic-only fallback;
- `PASS` требует coverage manifest всех mandatory stages;
- replay связывает verdict с commit, model, prompt, tools и policy versions.

## 10. P4 — Root-cause repair and validation

Цель: завершить первый полностью проверяемый vertical slice и выпустить Core
MVP `v0.1`.

| ID | Подзадача | Зависит от | Проверяемый результат | Статус |
|---|---|---|---|---|
| `P4.1` | Root-cause localizer | G3 | root cause отделён от surface symptom | `TODO` |
| `P4.2` | Security invariant contract | P4.1 | invariant машинно связан с finding и tests | `TODO` |
| `P4.3` | Security regression test/PoC generator | P4.2 | vulnerable revision fails, fixed candidate passes | `TODO` |
| `P4.4` | Architect structured patch contract | P4.1–P4.3 | minimal unified diff + rationale + touched symbols | `TODO` |
| `P4.5` | Ephemeral sandbox executor | P4.4 | no network/secrets, limits, teardown и escape tests | `TODO` |
| `P4.6` | Validation ladder | P4.5 | apply, parse, lint, types, build, tests, PoC+, rescan | `TODO` |
| `P4.7` | Bounded repair loop | P4.6 | max attempts, diagnostic progress, escalation | `TODO` |
| `P4.8` | Semantic diff/blast-radius review | P4.4–P4.6 | auth/API/crypto changes marked human-required | `TODO` |
| `P4.9` | Patch status model и local human approval | P4.6–P4.8 | suggestion → candidate → validated → approved transitions | `TODO` |
| `P4.10` | End-to-end CWE-89 reference scenario | P4.1–P4.9 | reproducible vulnerable and negative-control repos | `TODO` |
| `P4.11` | `scan`, `fix`, `validate` CLI UX | P4.10 | documented exit codes, JSON/SARIF/MD/diff outputs | `TODO` |
| `P4.12` | MVP notebook и demo script | P4.10 | clean environment executes from start to final report | `TODO` |

### G4 — Core MVP v0.1

- reference CWE-89 run воспроизводит полный путь от intake до validated patch;
- safe negative control не создаёт confirmed finding или patch;
- исходный repository остаётся неизменным до явного human action;
- patch применяется только в ephemeral copy и проходит весь validation ladder;
- failure каждого уровня сохраняет diagnostics и корректный status;
- offline run работает с fake/local profile, remote provider задаётся только
  через environment/secret manager;
- все обязательные MVP tests, notebook и reports проходят на чистой машине.

## 11. P5 — CI and reference SCM integration

Цель: превратить Core MVP в рабочий review/gating flow для одной SCM.

| ID | Подзадача | Зависит от | Проверяемый результат | Статус |
|---|---|---|---|---|
| `P5.1` | CI worker mode и machine exit contract | G4 | runner job produces artifacts and correct exit code | `TODO` |
| `P5.2` | Baseline/new-code fingerprinting | P2.9, P5.1 | legacy debt не блокирует new-code mode | `TODO` |
| `P5.3` | Policy-as-code v1 | P5.1, P5.2 | advisory/new_code/strict golden tests | `TODO` |
| `P5.4` | SHA-bound run state и supersession | P5.1 | stale run cannot update newest status | `TODO` |
| `P5.5` | Reference GitHub App adapter | P0.7, P5.4 | webhook/signature/minimum-permission contract tests | `TODO` |
| `P5.6` | Idempotent summary comment | P5.5 | repeated delivery updates one comment | `TODO` |
| `P5.7` | High-signal inline comments | P5.5 | only changed, precise, confirmed findings are posted | `TODO` |
| `P5.8` | SHA-bound advisory check/job | P5.2–P5.5 | exact HEAD outcome mapping; production blocking disabled before P7.9 | `TODO` |
| `P5.9` | SARIF and artifact publishing | P5.5 | upload success/failure is observable and retry-safe | `TODO` |
| `P5.10` | Fork/untrusted contributor security | P5.5 | secrets unavailable to attacker-controlled code | `TODO` |

### G5 — CI/SCM Ready

- PR/MR end-to-end run работает на реальном тестовом репозитории;
- повторные webhooks/jobs идемпотентны;
- новый commit делает старый run `superseded`;
- comments не блокируют merge; source of truth — check/job для точного SHA;
- до calibration check работает advisory и проверяет точное outcome mapping;
- production blocking не может быть включён без P7.9 calibration record;
- токен имеет минимальные permissions, webhook signature проверяется.

## 12. P6 — Backend control plane

Цель: завершить Enterprise Workflow MVP `v0.2` pilot с централизованными state, policies,
approvals и audit trail без обязательной передачи полного кода.

| ID | Подзадача | Зависит от | Проверяемый результат | Статус |
|---|---|---|---|---|
| `P6.1` | Versioned API/OpenAPI и auth foundation | G5 | contract, authn/authz negative tests | `TODO` |
| `P6.2` | Tenant/repository/run/finding persistence | P6.1 | migrations, constraints, tenant isolation tests | `TODO` |
| `P6.3` | Durable workflow/checkpoints | P6.2, P0.8 | restart/resume and duplicate-delivery tests | `TODO` |
| `P6.4` | Artifact storage with content hashes | P6.2 | integrity, retention and access-policy tests | `TODO` |
| `P6.5` | Policy/model/budget profiles | P6.1–P6.3 | version pinning and immutable run provenance | `TODO` |
| `P6.6` | Connected CLI/worker protocol | P6.1, P6.3 | retry, heartbeat, cancellation, least privilege | `TODO` |
| `P6.7` | EvidencePackage egress enforcement | P6.5, P6.6 | `no_code_egress` integration tests | `TODO` |
| `P6.8` | Human approval, suppression and expiring waiver | P6.2 | audit-complete state transitions and expiry tests | `TODO` |
| `P6.9` | Minimal developer/AppSec UI or API view | P6.2, P6.8 | run/finding/evidence/approval journey | `TODO` |
| `P6.10` | Immutable audit export and operational telemetry | P6.2–P6.8 | provenance completeness and redaction checks | `TODO` |
| `P6.11` | Enterprise MVP end-to-end scenario | P6.1–P6.10 | CI runner + backend + SCM + approval + supersession | `TODO` |
| `P6.12` | Containerize backend/worker and document launch | P6.11 | Dockerfile image build, health, non-root runtime and clean-start instructions | `TODO` |

### G6 — Enterprise Workflow MVP v0.2 pilot

- worker и server переживают restart/network retry без duplicate side effects;
- tenant A не может читать metadata/artifacts tenant B;
- backend не получает repository snapshot в default profile;
- policy, workflow, model, prompt и tool versions неизменно связаны с run;
- waiver имеет автора, причину, scope, срок и audit event;
- эталонный PR/MR проходит scan → finding → gate → approval → updated status.
- Docker image для web/backend path собирается и запускается по
  опубликованной clean-environment инструкции.

## 13. P7 — Multi-language, second SCM and evaluation

Цель: выполнить полный исходный language scope и получить измеримое beta
качество.

| ID | Подзадача | Зависит от | Проверяемый результат | Статус |
|---|---|---|---|---|
| `P7.1` | JavaScript/TypeScript parser, symbols и rules | G6 | positive/negative multi-file fixtures | `TODO` |
| `P7.2` | Go parser, symbols и rules | G6 | positive/negative multi-file fixtures | `TODO` |
| `P7.3` | Language-neutral call/data-flow contracts | P7.1, P7.2 | shared graph invariants across 3 languages | `TODO` |
| `P7.4` | Расширить CWE portfolio | P7.3 | SQLi, command injection, path traversal, SSRF, authz sample | `TODO` |
| `P7.5` | Подключить вторую SCM | G5 | feature parity matrix and E2E test | `TODO` |
| `P7.6` | Pin benchmark datasets and licenses | P0.12 | commit/hash/license manifest | `TODO` |
| `P7.7` | Baseline comparison | P7.6 | deterministic-only, scanner-seeded LLM, model-native-only, one-shot and full hybrid results | `TODO` |
| `P7.8` | Ablations | P7.7 | lanes/graph/skeptic/validator/root-cause contribution under declared comparable budgets | `TODO` |
| `P7.9` | Confidence calibration and gate thresholds | P7.7, P7.8 | held-out reliability curves and chosen thresholds | `TODO` |
| `P7.10` | Cost/latency/resource budgets | P7.7 | per-run/per-finding profile and regression limits | `TODO` |
| `P7.11` | False-positive UX pilot | P7.5, P7.9 | acceptance/rejection reasons and comment-volume metrics | `TODO` |
| `P7.12` | Build isolated Evaluation Lab | P7.6 | train/dev/locked-test access separation, immutable candidate store and no-network generated-code sandbox | `TODO` |
| `P7.13` | Governed synthetic-case pipeline | P7.12 | fixed seed/hash/provenance, executable oracle, independent root-cause review and lineage leakage tests | `TODO` |
| `P7.14` | Offline DSPy/GEPA and SkillOpt-style experiments | P7.7, P7.12 | versioned prompt/skill candidates, development/held-out metrics and zero protected access | `TODO` |
| `P7.15` | Sandboxed RLM-inspired discovery experiment | P7.7, P7.12 | read-only CodeIndex ablation, bounded resources and no unauthorized effects | `TODO` |
| `P7.16` | Candidate promotion/no-promotion decision | P7.13–P7.15 | AppSec-reviewed Pareto/security report; promoted immutable artifact or documented rejection | `TODO` |

### G7 — Multi-language Beta v0.5

- Python, JS/TS и Go проходят единый contract/evidence/report pipeline;
- обе SCM поддерживают summary, status и SHA correctness;
- benchmark protocol воспроизводим и защищён от train/test leakage насколько
  практически возможно;
- release report публикует precision/recall, FP/KLOC, localization,
  correct-and-secure repair rate, latency и стоимость вместе с ограничениями;
- blocking thresholds основаны на calibration data, а не на интуиции;
- ни один benchmark score не объявляется гарантией безопасности.
- Evaluation Lab не имеет доступа к locked expectations/production aliases;
  ни один unsafe candidate не promoted, а отсутствие improvement
  допускает документированный `no-promotion` без блокировки Core.

## 14. P8 — Enterprise security and reliability hardening

Цель: подготовить release candidate к ограниченному корпоративному пилоту.

| ID | Подзадача | Зависит от | Проверяемый результат | Статус |
|---|---|---|---|---|
| `P8.1` | Обновить threat model по фактической системе | G7 | все trust boundaries и mitigations связаны с tests | `TODO` |
| `P8.2` | Sandbox hardening/red-team | P8.1 | escape, network, fork bomb, output/resource attacks | `TODO` |
| `P8.3` | Prompt/tool/data poisoning red-team | P8.1 | direct/encoded/compositional/refusal attacks, adaptive ASR and fail-closed evidence | `TODO` |
| `P8.4` | SSO/OIDC и production RBAC/ABAC | P6.1 | role/tenant/privilege-escalation tests | `TODO` |
| `P8.5` | Secret manager и credential rotation | P8.4 | no static production keys; rotation drill | `TODO` |
| `P8.6` | Retention, deletion, residency and audit policies | P6.4, P8.4 | policy enforcement and deletion evidence | `TODO` |
| `P8.7` | Rate limits, quotas and spend budgets | P6.5 | overload/abuse/cost ceiling tests | `TODO` |
| `P8.8` | OpenTelemetry, dashboards and alerts | P6.10 | SLI dashboards and alert drills | `TODO` |
| `P8.9` | Backup/restore and disaster recovery | P6.2–P6.4 | timed restore drill and documented RPO/RTO | `TODO` |
| `P8.10` | Load, soak, cancellation and chaos tests | P6.3, P8.8 | no cross-run corruption; measured capacity | `TODO` |
| `P8.11` | Supply-chain security | P1.2 | SBOM, provenance, signed artifacts, dependency policy | `TODO` |
| `P8.12` | Independent security review and remediation | P8.1–P8.11 | no unresolved release-blocking findings | `TODO` |

### G8 — Release Candidate v0.9

- все threat-model mitigations имеют owner, test или accepted residual risk;
- нет открытых release-blocking Critical/High уязвимостей продукта;
- sandbox и untrusted-repository boundaries прошли adversarial suite;
- restore, rotation, incident and stale-run drills воспроизводимы;
- telemetry/exports соответствуют data handling policy;
- capacity, latency, availability и cost envelope измерены;
- release artifacts содержат SBOM, provenance и подпись.

## 15. P9 — v1.0, academic closure and handoff

Цель: завершить продуктовый и учебный проект без скрытой незакрытой работы.

| ID | Подзадача | Зависит от | Проверяемый результат | Статус |
|---|---|---|---|---|
| `P9.1` | Freeze scope and release checklist | G8 | no untriaged blockers; deferred list versioned | `TODO` |
| `P9.2` | User/admin/deployment/API documentation | P9.1 | clean-room installation and operations review | `TODO` |
| `P9.3` | Финальный notebook и demo repositories | P9.1 | offline and enterprise demos from clean environments | `TODO` |
| `P9.4` | Итоговый benchmark and limitations report | P9.1 | rerunnable commands, raw metrics and caveats | `TODO` |
| `P9.5` | Учебный отчёт и архитектурные диаграммы | P9.2–P9.4 | traceability to original assignment | `TODO` |
| `P9.6` | Презентация и rehearsed defense scenario | P9.5 | timed rehearsal, fallback demo/video | `TODO` |
| `P9.7` | Limited pilot and feedback triage | G8 | signed pilot outcomes and known limitations | `TODO` |
| `P9.8` | Fix release blockers and rerun gates | P9.7 | regression evidence for every blocker | `TODO` |
| `P9.9` | Tag/sign/publish `v1.0` | P9.2–P9.8 | immutable release, checksums, SBOM, release notes | `TODO` |
| `P9.10` | Handoff, backlog and ownership | P9.9 | runbooks, owners, support/escalation and next roadmap | `TODO` |
| `P9.11` | Retrospective and project archive | P9.9, P9.10 | outcomes vs goals, lessons, archived gate evidence | `TODO` |
| `P9.12` | Confirm submission administration | P9.1 | recorded deadline year/timezone and team-size or individual-approval evidence | `TODO` |
| `P9.13` | Build reproducible academic submission bundle | P9.2–P9.5, P9.12 | Git URL, README, dependency/config files, tests, notebook, dataset links/fixed-seed generator, PDF/HTML report and clean-room replay | `TODO` |
| `P9.14` | Record and verify web-service delivery | P6.12, P9.3, P9.13 | Dockerfile/instructions, 2–5 minute screencast and anonymous public-link checks | `TODO` |

### G9 — Project Closed / v1.0

- все требования исходного задания имеют evidence или formal accepted defer;
- release воспроизводим из pinned source и dependencies;
- installation, demo, CI gate, patch validation и restore проверены третьим
  лицом или по clean-room инструкции;
- известные ограничения и residual risks опубликованы;
- документация, tests, notebook, report, presentation и release artifacts
  доступны и согласованы;
- submission manifest доказывает README-based reproduction,
  dependency/config completeness, PDF/HTML experiments/metrics, data provenance,
  Docker build, 2–5 minute screencast и доступность всех ссылок;
- deadline year/timezone и team/individual approval подтверждены;
- открытая работа перенесена в versioned post-v1 backlog с owner/priority;
- итоговое решение `PROJECT CLOSED` записано в gate packet и changelog.

## 16. Traceability исходного задания

| Исходное требование | План реализации | Финальная проверка |
|---|---|---|
| Loader Python/JS/Go | P2.1–P2.4, P7.1–P7.3 | G7, G9 |
| AST/Tree-sitter tools | P2.3–P2.8 | G2 |
| Secret detection | P2.5 | G2 |
| Vulnerable dependencies | P2.6 | G2 |
| Единый контракт/CWE/строки | P1.5–P1.6, P2.9–P2.11 | G1, G2 |
| Auditor, model-native discovery и Architect | P3.2–P3.11, P4.4 | G3, G4 |
| Auto-Fix diff | P4.4–P4.11 | G4 |
| Validation | P4.5–P4.9 | G4, G8 |
| Markdown/HTML report | P2.12, P4.11 | G2, G4 |
| OWASP/CWE classification | P2.11 | G2, G7 |
| Documentation/unit tests/notebook | P1–P9 continuous, P4.12, P9.2–P9.6 | G4, G9 |
| Git/README/dependencies/report/Docker/screencast/data links/reproducibility | P1.1–P1.3, P6.12, P7.6, P9.12–P9.14 | G1, G6, G7, G9 |

Полная machine-readable matrix, включая `CR-001–CR-016`, security/architecture
requirements и каждый нормативный prefix, находится в
[specs/traceability/requirements.yaml](../specs/traceability/requirements.yaml).

## 17. Управление изменениями

Изменение scope, архитектуры, gate или acceptance criteria проходит одинаковый
процесс:

1. Создать `CR-NNN` в [CHANGELOG.md](../CHANGELOG.md): причина, инициатор,
   затронутые задачи, риски и ожидаемый эффект.
2. Провести impact analysis: product, architecture, security, privacy,
   evaluation, сроки и миграция.
3. Для архитектурного изменения создать или обновить ADR в
   [DECISIONS.md](DECISIONS.md).
4. Принять решение `accepted | rejected | deferred`.
5. Обновить IDs/status/dependencies/acceptance criteria и версию этого плана.
6. Добавить запись в секцию `Unreleased` changelog и обновить
   [CONTEXT.md](CONTEXT.md).
7. Если gate уже был закрыт, не переписывать историю: создать новую ревизию
   evidence packet и явно указать, какой результат superseded.

Мелкие исправления текста не требуют CR. Любое изменение публичного контракта,
security boundary, набора обязательных языков, blocking policy, способа передачи
кода или критерия gate требует CR и ADR.

## 18. Текущий фокус

G0 закрыт immutable baseline `0.2.0` и отдельной effective attestation.
`P1.1–P1.3` завершены. Локальный кандидат `P1.4` проходит pre-commit, CI policy,
secret/dependency checks и Python 3.12–3.14 matrix, но остаётся `IN PROGRESS`
до GitHub ruleset и failing-PR merge-block receipt. `P1.5–P1.9` завершены:
schema/contracts, events/stable IDs, secret-safe config и provider-neutral
model boundary, а также graph-independent `WorkflowRuntime` прошли полную
матрицу, independent acceptance и clean post-commit validation. `P1.10` CLI
  skeleton со стабильными exit codes завершён после трёх independent reviews и
  clean post-commit verification. `P1.11` fixture repository factory также
  завершён: evaluator golden был заморожен отдельно до реализации, exact digest
  принят тремя reviewers, а implementation commit прошёл clean post-commit 43
  targeted и 739 full tests. `P1.12` internal telemetry завершён: exact staged
  digest принят product/architecture/security-evaluation reviewers, а
  implementation commit прошёл clean post-commit 162 targeted и 885 full tests,
  Ruff/mypy, schema check и strict G0. Затем следует `P1.13` spec-drift gate;
  `G1` остаётся открыт из-за `P1.4` и `P1.13`.
Узкий Python CWE-89 vertical slice начинается после G1. Enterprise adapters не
строятся до стабилизации Core contracts и deterministic evidence layer.
