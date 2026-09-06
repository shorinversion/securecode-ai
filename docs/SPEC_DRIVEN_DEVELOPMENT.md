# SecureCode AI — Spec-Driven Development

Статус: `accepted operating model`; продуктовая спецификация ещё не прошла `G0`.  
Версия: `0.1`  
Дата: 12 августа 2026 года  
Связанные записи: `D-013`, `CR-006`, `P0.14`, `P0.16`, `P1.5`, `P1.13`.

Этот документ определяет, как SecureCode AI будет проектироваться и
разрабатываться. Он не подменяет будущее техническое задание: decision-complete
спецификация появится после Deep Research и закрытия решений `P0.6–P0.12`.

## 1. Основной принцип

```text
Requirement
  → normative specification
  → executable contract
  → failing acceptance test
  → constrained implementation
  → independent verification
  → gate evidence
```

Prompt не является спецификацией. LLM не должна угадывать архитектуру,
интерфейсы, разрешения, критерии готовности или границы безопасности. Все эти
параметры задаются до реализации и проверяются машинно там, где это возможно.

Короткая формула проекта:

> Спецификация определяет допустимое поведение, контракты делают требования
> исполняемыми, ограничения сужают пространство действий LLM, а gates требуют
> воспроизводимого доказательства.

## 2. Нормативные и информационные источники

После прохождения `G0` приоритет источников для реализации:

1. принятая спецификация и executable contracts в `specs/`;
2. accepted ADR в `docs/DECISIONS.md`;
3. task packet и соответствующая задача `P*.*`;
4. архитектурная и продуктовая документация;
5. исходное задание как immutable baseline;
6. история разговора и черновики.

Если код, тест или документация противоречат принятой спецификации, это defect
или change request, а не повод молча интерпретировать требование иначе.

Статусы спецификации:

- `draft` — можно обсуждать, нельзя использовать как обязательный контракт;
- `in_review` — содержание стабилизируется, breaking changes ещё допустимы;
- `accepted` — нормативный источник для реализации и acceptance tests;
- `superseded` — сохранён для истории и ссылается на замену;
- `deprecated` — ещё совместим, но имеет срок удаления.

## 3. Иерархия спецификаций

| Уровень | Что фиксирует | Основной формат |
|---|---|---|
| Product | цели, non-goals, роли, journeys, release scope | Markdown с requirement IDs |
| System | компоненты, trust boundaries, deployment profiles | Markdown + diagrams |
| Domain | сущности, поля, invariants, lifecycle | JSON Schema + typed models |
| Interfaces | HTTP, events, CLI, SCM adapters, reports | OpenAPI/AsyncAPI/schema/CLI contract |
| Workflow | nodes, state, transitions, guards, retries, budgets | transition tables + typed schemas |
| Security | capabilities, egress, sandbox, secrets, approvals | policy schemas + abuse cases |
| Behavior | scenarios, errors, negative controls | Given/When/Then + fixtures |
| Evaluation | datasets, metrics, thresholds, anti-leakage | versioned protocol + manifests |
| Operations | SLO, telemetry, retention, recovery | runbooks + machine policies |

Предлагаемая структура:

```text
specs/
├── README.md
├── product/
│   ├── vision-and-scope.md
│   ├── personas-and-journeys.md
│   └── releases.md
├── system/
│   ├── architecture.md
│   ├── deployment-profiles.md
│   └── trust-boundaries.md
├── contracts/
│   ├── domain/*.schema.json
│   ├── api/openapi.yaml
│   ├── events/asyncapi.yaml
│   ├── cli/cli-contract.md
│   ├── workflow/*.yaml
│   ├── policy/*.schema.json
│   └── reports/
├── behavior/
│   ├── audit-run/
│   ├── finding-investigation/
│   ├── repair-validation/
│   └── scm-gating/
├── security/
│   ├── threat-model.md
│   ├── capability-policy.md
│   └── abuse-cases/
├── evaluation/
│   ├── protocol.md
│   ├── datasets.lock
│   └── thresholds.yaml
├── traceability/
│   └── requirements.yaml
└── templates/
```

Точные форматы и tool versions фиксируются в `P0.14`/`P1`; дерево выше задаёт
границы ответственности, а не преждевременно выбирает все библиотеки.

## 4. Идентификация и формулировка требований

Каждое нормативное требование получает стабильный ID:

```text
SC-PROD-###   product behavior
SC-DOM-###    domain invariant
SC-API-###    HTTP/event interface
SC-CLI-###    command-line behavior
SC-WF-###     workflow/state transition
SC-SEC-###    security/privacy constraint
SC-EVAL-###   evaluation requirement
SC-OPS-###    operational requirement
```

Требование обязано содержать:

- `MUST`, `SHOULD` или `MAY` с однозначным субъектом и действием;
- rationale и источник;
- preconditions и postconditions;
- happy path, ошибки и negative cases;
- security/privacy implications;
- observability и audit evidence;
- compatibility/migration impact;
- acceptance oracle: команда, schema validation, test или reviewer gate;
- ссылки на план, ADR и связанные требования.

Критический `TBD` блокирует `G0`. Некритический `TBD` получает owner, причину,
срок решения и явно ограниченный impact. Слова «быстро», «безопасно», «умно»,
«масштабируемо» и «корректно» недопустимы без измеримого определения.

## 5. Contract-first development loop

Для каждого изменения используется один цикл:

1. **Requirement delta:** сформулировать проблему и requirement IDs.
2. **Spec delta:** обновить normative behavior, ошибки, ограничения и примеры.
3. **Impact review:** проверить совместимость, security, privacy, данные,
   операции и миграцию.
4. **Executable contract:** создать/изменить schema, transition table, API/CLI
   contract или policy.
5. **Acceptance first:** добавить failing acceptance/contract/negative test.
6. **Task packet:** выдать LLM узкую задачу, разрешённые файлы, инструменты,
   budgets, stop conditions и команды проверки.
7. **Implementation:** реализовать минимальный diff, не меняя normative inputs.
8. **Independent validation:** отдельный validator запускает gates и проверяет
   отсутствие ослабления tests/specs.
9. **Traceability:** связать requirement → contract → code → test → evidence.
10. **Change record:** обновить changelog, ADR и context при материальном
    изменении.

Код не пишется по `draft`-требованию, если задача не обозначена как spike.
Результат spike не становится production contract без отдельного review.

## 6. Constraint stack для LLM-разработки

Ограничения применяются слоями. Текстовая инструкция — только один из них.

### 6.1. Scope constraints

- один task ID и ограниченная цель;
- явные `in_scope`, `out_of_scope` и `non_goals`;
- allowlist изменяемых путей;
- protected paths для specs, acceptance tests, evaluator и gate evidence;
- лимит changed files/diff size или обязательный escalation при превышении;
- запрет незапрошенного public API, dependency или architecture change.

### 6.2. Data and schema constraints

- structured input/output;
- strict field types, enums, ranges и required fields;
- `additionalProperties: false` там, где расширение не предусмотрено;
- stable IDs и explicit schema versions;
- parse/serialize/compatibility tests;
- invalid output не исправляется догадкой: он отклоняется или повторяется в
  пределах budget с точной validation error.

### 6.3. Behavioral constraints

- state machine задаёт разрешённые transitions;
- preconditions, postconditions и invariants проверяются кодом;
- policy code, а не модель, выбирает следующий workflow node;
- операции имеют idempotency key и определённую retry semantics;
- no-progress detection и stop conditions обязательны.

### 6.4. Capability constraints

- default-deny tool model;
- отдельные read-only и write capabilities;
- shell недоступен агенту без узкой allowlist-команды;
- сеть запрещена в sandbox по умолчанию;
- секреты не передаются модели, subprocess или fixture repository;
- repository content является данными, а не инструкциями;
- implementation agent не принимает собственный patch.

### 6.5. Resource constraints

- max iterations/tool calls/tokens/time;
- ограничения CPU, RAM, процессов, disk и output;
- context budget и правила truncation;
- cost ceiling и provider timeout;
- retry разрешён только при новом diagnostic signal.

### 6.6. Security and privacy constraints

- data classification и egress profile;
- endpoint allowlist и SSRF validation;
- ephemeral workspace, non-root execution и guaranteed teardown;
- secret and source redaction в logs/telemetry;
- tenant boundaries и artifact access policy;
- human-required категории: auth, authz, crypto, public API, conflicting
  verdicts и budget exhaustion.

### 6.7. Quality constraints

- deterministic lint/type/schema/contract tests;
- positive, negative, boundary и adversarial cases;
- existing tests + security regression test + rescan;
- no new blocking findings;
- reproducible evidence tied to exact commit and versions;
- benchmark thresholds принимаются только после calibration.

### 6.8. Governance constraints

- implementation task не может редактировать accepted specification,
  acceptance tests, evaluator, hidden tests или gate decision;
- spec-authoring task отделён от implementation task;
- автор patch не является единственным validator;
- breaking change требует CR, ADR, migration и version bump;
- `DONE`, `validated` и `safe` нельзя заявлять без соответствующего evidence.

## 7. LLM implementation task packet

Каждая задача реализации передаётся модели не свободным prompt, а
типизированным task packet. Базовый шаблон находится в
[`specs/templates/implementation-task.yaml`](../specs/templates/implementation-task.yaml).

Минимальный состав:

```yaml
task_id: P2.7
spec_refs: [SC-CAP-001, SC-DOM-003]
objective: Implement the Python CWE-89 deterministic rule.
allowed_paths: []
forbidden_paths: []
allowed_tools: []
inputs: []
outputs: []
constraints: []
acceptance_commands: []
required_evidence: []
budgets: {}
stop_conditions: []
```

Task packet не заменяет спецификацию; он выбирает из неё узкий реализуемый
срез. Пустой allowlist означает «ничего нельзя изменять», а не «разрешено всё».

## 8. Separation of duties

| Роль | Может | Не может |
|---|---|---|
| Spec owner | формулировать requirements/contracts | объявлять реализацию прошедшей gates |
| Implementer/LLM | менять разрешённые implementation/tests paths | менять accepted spec/evaluator/gate evidence |
| Validator | запускать проверки и записывать результаты | исправлять patch во время той же validation |
| Security reviewer | принимать risk/waiver/human-required change | подменять raw tool evidence |
| Gate reviewer | `GO/CONDITIONAL GO/NO-GO` | закрывать gate без evidence packet |

Для небольшого учебного проекта один человек может физически выполнять разные
роли, но шаги, артефакты и permissions остаются логически разделёнными.

### 8.1. Модель разработки Codex и субагентами

Действующие правила моделей, внутренних субагентов, возврата результата и частоты
проверок: [DEVELOPMENT_WORKFLOW.md](DEVELOPMENT_WORKFLOW.md), effective CR-050 / D-047.
Bounded implementation выполняется субагентом с одним writer. Между P-задачами
допустимы только локальные checkpoint-коммиты без тестов и ревью; test code
готовится вместе с реализацией. Один canonical quality и protected PR/CI cycle
выполняется при закрытии gate. Для G2-G8 независимые reviews отключены; один
combined independent final review выполняется после реализации и quality G9, до PROJECT CLOSED promotion. Повтор закрывающей
проверки требует конкретной причины invalidation. Protected evaluator amendment
сохраняет отдельный действующий порядок receipts без расширения gate reviews.
CR-050 / D-047 remains the cadence authority. CR-055 / D-051 is the effective
G3-G9 successor-evaluator authority, delivered by protected PR #50 at merge
`d8edb4c4fe30af4c6b7f2d27d48ed917b7464356`; protected postmerge run
`34020445912` completed `PASS`.

Не путать две разные системы ролей:

- `Auditor`, `Skeptic`, `Architect`, `Validator` — runtime-роли внутри
  разрабатываемого продукта SecureCode AI;
- `Primary Integrator`, `Researcher`, `Spec Author`, `Implementer`, `Test
  Designer`, `Reviewer` — роли Codex при разработке самого проекта.

`Primary Integrator` — основной Codex-agent в пользовательской задаче. Он
остаётся единым owner результата и отвечает за:

- восстановление project context и выбор канонического task ID;
- decomposition, dependency order и назначение path ownership;
- архитектурную и контрактную согласованность;
- интеграцию всех предложений в общий worktree;
- повторный запуск acceptance/negative tests;
- обновление durable memory и итоговый handoff пользователю.

Субагент не является автономным совладельцем проекта. Он получает ограниченный
task packet и одну из ролей:

| Development role | Типичная работа | Режим записи |
|---|---|---|
| Researcher | первичные источники, alternatives, claim/evidence table | `read_only/proposal_only` |
| Spec Author | draft requirement/schema/transition delta | отдельные spec paths; не implementation |
| Implementer | один ограниченный component или adapter | exclusive allowlisted paths |
| Test Designer | acceptance, negative, adversarial fixtures | exclusive test paths; не ослабляет oracle |
| Reviewer/Security Reviewer | diff, threat, compatibility и failure analysis | `read_only` |
| Validator | воспроизводимый запуск gates и evidence capture | `read_only` для patch |

#### Когда делегировать

Субагенты используются, когда подзадача:

- имеет один результат и проверяемый acceptance oracle;
- может выполняться независимо от текущей интеграционной работы;
- читает общий контекст, но пишет только в непересекающиеся пути либо возвращает
  proposal без записи;
- даёт реальную параллельность: research fan-out, provider comparison,
  независимый review, test/fixture design или разные adapters;
- не требует скрытого product/architecture решения по ходу реализации.

Основной агент выполняет работу сам, когда изменение маленькое, проходит через
несколько тесно связанных contracts, затрагивает shared state/schema/migration,
требует частых решений по одному и тому же файлу или стоимость merge/conflict
выше потенциального выигрыша.

#### Правила параллельной работы

1. Один writer на путь в каждый момент; overlapping writes запрещены.
2. Research/review agents по умолчанию read-only и возвращают structured
   handoff, а не редактируют канонические ADR/specs.
3. Spec author не реализует и не валидирует тот же change без независимого
   review; implementer не изменяет acceptance oracle.
4. Nested delegation запрещена по умолчанию; субагент не создаёт собственную
   команду без явного разрешения task packet.
5. Critical path и shared contracts изменяются последовательно Primary
   Integrator.
6. Не более необходимого числа параллельных workers; количество агентов не
   является метрикой прогресса.
7. Любой subagent result считается candidate до проверки Primary Integrator.
8. Primary Integrator повторно читает diff, запускает проверки при закрытии gate и единолично
   выполняет финальный merge/handoff; утверждение субагента `tests pass` не
   является достаточным evidence.

#### Обязательный structured handoff

```text
task_id / role
objective and scope completed
files read / files changed
commands and exact results
evidence produced
assumptions
risks and unresolved questions
recommended integration order
```

Если два субагента пришли к разным выводам, Primary Integrator сохраняет оба как
alternatives, проверяет evidence и принимает/эскалирует решение; голосование
агентов не заменяет ADR или acceptance test.

## 9. Spec validation и drift prevention

В `P1.13` CI должен проверять:

- metadata и уникальность requirement IDs;
- отсутствие broken references;
- JSON Schema/OpenAPI/policy validation;
- examples против schemas;
- contract tests для providers, CLI, API, events и reporters;
- backward compatibility или наличие migration record;
- requirement → test → evidence traceability;
- generated artifact drift;
- запрет изменения protected specification/evaluator paths implementation-задачей;
- отсутствие критических `TBD` в accepted specs.

Если spec и code расходятся, pipeline завершается failure. Автоматическое
«подгоняние» спецификации под существующий код запрещено.

## 10. Quality gate технического задания

`P0.14` готов только когда:

- scope MVP и v1, роли, journeys и non-goals приняты;
- domain glossary и все публичные сущности имеют contract;
- workflows содержат states, transitions, guards, retries и stop conditions;
- error model, idempotency и versioning определены;
- threat model и data/egress policies связаны с requirements;
- CLI/API/events/reports/SCM behavior имеют примеры и negative cases;
- каждый `MUST` имеет acceptance oracle;
- traceability не содержит обязательных требований без plan/test owner;
- нет критических `TBD`;
- независимый review не обнаружил противоречащих требований.

После принятия baseline получает версию и hash. Любое изменение идёт через
change control; прошлый baseline не переписывается.

## 11. Последовательность внедрения

### Сейчас, до результата Deep Research

- принять SDD как operating model;
- создать namespace `specs/`, templates и правила;
- не придумывать незакрытые продуктовые решения;
- собирать вопросы и evidence для `P0.6–P0.12`.

### После Deep Research

1. проверить claims и источники;
2. принять P0 decisions;
3. написать product/system/security/evaluation specifications;
4. определить domain/API/CLI/workflow contracts;
5. провести consistency и adversarial review;
6. собрать traceability matrix;
7. baseline spec и закрыть `G0`.

### Во время реализации

- каждая задача начинается со spec refs и failing contract/acceptance test;
- LLM работает только внутри task packet;
- CI проверяет spec/code/test drift;
- gate evidence и changelog завершают изменение.

## 12. Инструментальный baseline для P1

`D-026` закрывает вопросы, способные изменить P1 repository/public contracts:

- Pydantic v2 domain-first models генерируют checked-in JSON Schema Draft
  2020-12; FastAPI/OpenAPI 3.1 генерируется из тех же типов;
- schema/events следуют major/minor/patch compatibility rules из domain spec;
- policy v1 — versioned typed YAML/JSON и deterministic deny-overrides
  evaluator; OPA/Rego отложен до данных pilot;
- workflow v1 — typed Python state/transition definitions за
  `WorkflowRuntime`; framework-specific graph definitions остаются adapters;
- scenarios v1 — parameterized pytest/typed fixture runner, без обязательного
  Gherkin/BDD framework;
- protected paths v1 — task packet declares `exclusive_paths` и
  `forbidden_paths`; CI compares them with git diff and отдельно требует
  `change_type=spec` + CR/ADR для `specs/`, evaluator и gate evidence.

Точные generator/linter package versions фиксируются lockfile в `P1.2` и могут
быть заменены без breaking contract, если generated schemas/compatibility tests
остаются эквивалентны. Эти решения выбраны за воспроизводимость, прозрачность,
минимальную магию, language neutrality и локальный запуск.
