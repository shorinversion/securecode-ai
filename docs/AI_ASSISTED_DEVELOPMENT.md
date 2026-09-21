# Как SecureCode AI разрабатывается с помощью ИИ

Статус: действующий operating model разработки.  
Последнее обновление: 5 сентября 2026 года.
Нормативные детали: [Spec-Driven Development](SPEC_DRIVEN_DEVELOPMENT.md),
[план и gates](PLAN.md) и решение [`D-016`](DECISIONS.md). Локальные инструкции
агентов не входят в публикуемый продуктовый репозиторий.

## 1. Основной принцип

Проект не разрабатывается по схеме «один prompt → много кода». Используется
управляемый AI-assisted engineering:

```text
исходное требование
→ исследование и change control
→ versioned specification и contracts
→ ограниченный task packet
→ независимый acceptance oracle
→ реализация обязательных задач и focused acceptance/negative tests
→ интегрированный кандидат гейта
→ полный quality и независимый product/architecture/security review
→ исправления и только затронутые delta checks/review
→ evidence packet и gate
→ следующая фаза
```

Код считается завершённым не тогда, когда агент написал файлы, а когда
воспроизводимые проверки доказали выполнение требования на точной версии
исходников и конфигурации.

## 2. Роли

Пользователь остаётся владельцем продукта и утверждает существенные изменения
целей, scope и риска.

Основной Codex-agent — единственный `Primary Integrator`. Он владеет:

- архитектурной и контрактной согласованностью;
- decomposition и порядком зависимостей;
- назначением ограниченных задач;
- объединением изменений;
- целевой проверкой задач и полным quality/review интегрированного гейта;
- решениями о принятии candidate result;
- актуальным контекстом и итоговым handoff.

Субагенты — bounded reviewers/исполнители. Они получают task packet, scope,
разрешённые paths/tools, budgets, stop conditions и ожидаемый structured
handoff. Они не могут самостоятельно менять baseline, evaluator, gate evidence,
принимать собственный результат или выполнять финальную интеграцию.

Такое разделение уже дало наблюдаемую пользу:

- product reviewer нашёл дефекты scope/traceability;
- architecture reviewer — несовместимые wire contracts;
- security/evaluation reviewer — fail-open и metric/policy loopholes;
- Primary Integrator свёл исправления и повторно провёл validation/delta review.

## 3. Spec-Driven и contract-first разработка

До реализации определяются:

- goals/non-goals и поддерживаемые сценарии;
- domain types и state machines;
- API/CLI/event/report/SCM contracts;
- capability, egress, retention и sandbox policies;
- точные состояния отказа и неполного анализа;
- acceptance criteria и исполняемые oracles;
- traceability `исходное требование → SC-* → задача → тест → gate evidence`.

Implementation-agent не может ослабить requirement или тест, чтобы получить
зелёный результат. Изменение accepted scope проходит через `CR`, impact
analysis, ADR/spec update и повторный review.

## 4. Test- и evidence-driven реализация

Частота проверок, модели по ролям и передача между задачами определены в
[DEVELOPMENT_WORKFLOW.md](DEVELOPMENT_WORKFLOW.md). После effective CR-045
полный цикл относится к интегрированному gate-кандидату, не к каждой задаче,
строке, коммиту или ответу reviewer. Во время реализации выполняются focused
acceptance/negative tests; локальное исправление повторяет только затронутую
проверку и роль review, если изменение не затронуло общие контракты.
Существующие обязательные hooks/CI остаются действующими до protected amendment.

Каждая задача начинается с failing или независимо наблюдаемого oracle:

- unit/branch test;
- schema/contract fixture;
- golden output;
- negative/adversarial case;
- integration/e2e scenario;
- security PoC/PoC+;
- replay/restart/idempotency test;
- clean-environment reproduction.

Тесты самого SecureCode AI отделены от security regression tests, которые
продукт генерирует для пользовательского кода. Прохождение одного слоя не
заменяет другой.

## 5. Формальные gates

Переход между фазами разрешает не текстовое мнение агента, а gate:

- точный checklist;
- обязательные raw test results;
- provenance исходников, конфигурации, модели, prompts, tools и policy;
- независимый review;
- эффективное решение `GO/NO-GO`;
- привязка к immutable commit.

Пропуск, flaky result, stale SHA или неполное evidence не считаются `PASS`.
Новые данные, обнаружившие дефект ранее проверенного baseline, снова открывают
gate до reconciliation и delta review.

## 6. Исследование и долговременная память

Внешний отчёт или ответ LLM является candidate map. Существенное утверждение
попадает в архитектуру/spec только после проверки primary source, версии,
scope, limitations и provenance.

Репозиторий служит долговременной памятью: brief, context, plan, changelog,
ADRs, specs, research ledger, task packets, gate evidence и test results.
Project navigator восстанавливает позицию после сжатия контекста и обновляет
только решения, доказательства, риски и следующие действия, а не скрытые
черновые рассуждения.

## 7. Улучшение LLM-компонентов

Качество prompts, agent procedures и discovery strategies улучшается не
интуитивным редактированием, а через evaluation lab:

```text
frozen model/harness + train split
→ scored trajectories и stage-specific feedback
→ candidate prompt/skill/strategy
→ held-out validation + hard security constraints
→ human/diff review
→ versioned artifact
→ один confirmatory locked-test run
```

Сравниваются `deterministic-only`, `LLM-only`, `one-shot`, bounded tool loop,
RLM-inspired discovery и полный hybrid. DSPy/GEPA могут оптимизировать prompts,
а SkillOpt — отдельные role skills. Эти механизмы работают только офлайн и не
видят locked expected results. Production-agent никогда сам не продвигает
собственный prompt или skill.

LLM-generated benchmark cases допустимы как кандидаты после executable oracle,
root-cause review, generator provenance, fixed seed/hash и lineage-grouped
split. Они не являются самостоятельным ground truth.

Подробности: [RLM/DSPy/SkillOpt research note](research/RLM_DSPY_SKILLOPT.md) и
[evaluation protocol](../specs/evaluation/protocol.md).

## 8. Два разных мультиагентных уровня

Нельзя смешивать:

1. AI-агентов, которые **разрабатывают** SecureCode AI: Primary Integrator,
   reviewers и path-isolated implementers;
2. runtime-агентов **внутри продукта**: Orchestrator, Repository Mapper,
   Semantic Scout, Evidence Builder, Auditor, Skeptic, Architect и Validator.

В обоих уровнях LLM формулирует candidates и выполняет bounded reasoning, но
финальные переходы задают contracts, deterministic policy, tests и human gates.
