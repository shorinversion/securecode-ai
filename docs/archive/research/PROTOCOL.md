# SecureCode AI — research protocol

Версия: `0.1-draft`  
Статус: `active exploratory protocol`, не preregistered  
Дата: 12 августа 2026 года  
Владелец решения: автор проекта; reviewer для `G0`: автор и куратор.

## 1. Decision statement

Какая evidence-backed архитектура, продуктовая форма и evaluation strategy
позволят построить реалистичный SecureCode AI: high-signal, воспроизводимый,
privacy-aware аудит кода с проверяемыми patch candidates и корпоративным
CI/SCM workflow?

Исследование должно уменьшить неопределённость перед `G0`, а не максимизировать
число источников или объём текста.

## 2. Research questions

| ID | Вопрос | Решение, которое поддерживает |
|---|---|---|
| `RQ-01` | Где гибрид static/program analysis + LLM превосходит LLM-only и scanner-only? | boundaries Core и роли LLM |
| `RQ-02` | Какие graph/harness patterns дают controlled state, recovery, budgets и verification? | workflow/evidence graph и runtime |
| `RQ-03` | Как безопасно разделить CLI/CI execution plane и backend control plane? | deployment, egress, tenant model |
| `RQ-04` | Как GitHub/GitLab реализуют SHA-bound blocking checks и high-signal comments? | reference SCM и integration contracts |
| `RQ-05` | Какие benchmarks и метрики честно измеряют detection и correct-and-secure repair? | P0.12 evaluation baseline |
| `RQ-06` | Какие agent-specific threats критичны: prompt injection, tool abuse, sandbox escape, data exfiltration? | threat model и capability policy |
| `RQ-07` | Какой scope является защищаемым Core MVP и какой — Enterprise MVP? | release scope и demo scenario |

## 3. Scope

### Включается

- peer-reviewed papers и релевантные preprints с явным статусом;
- официальные standards/specifications/security guidance;
- официальная документация GitHub, GitLab, выбранных runtimes и scanners;
- reproducible benchmarks/datasets с version/license/hash;
- empirical industry studies и practitioner evidence, если provenance доступна;
- контраргументы, negative results и limitations.

### Исключается или понижается

- LLM-generated reports без разрешимых источников — только candidate maps;
- SEO/marketing claims без методологии или проверяемых данных;
- benchmark numbers без pinned release, split и leakage analysis;
- vendor pricing/capability claims без даты и официальной страницы;
- opinions/X posts как единственное доказательство технического решения;
- papers, доступные только по abstract, для claims, требующих методов/чисел.

## 4. Evidence classes

1. `standard_or_official_contract` — нормативное/официальное поведение.
2. `peer_reviewed_empirical` — предпочтительно для quality claims.
3. `preprint_empirical` — допустим с явной оговоркой.
4. `reproducible_artifact` — code/data/benchmark с pin/hash/license.
5. `official_vendor_docs` — продуктовые capabilities, не нейтральная оценка.
6. `practitioner_signal` — discovery/risks; не достаточен для ADR в одиночку.
7. `llm_candidate` — требует обязательного resolution до использования.

Peer review не заменяет проверку методологии, artifact availability и
применимости к нашему контексту.

## 5. Search protocol

Для каждого RQ выполнить:

1. exploratory seed search и concept/synonym matrix;
2. academic search: arXiv + DOI/venue/author resolution; ACM/IEEE/Scholar или
   доступные предметные индексы;
3. official-source search по standards, SCM, runtime и security documentation;
4. backward/forward citation search для ключевых работ;
5. поиск контраргументов, failure cases и replication;
6. запись exact query, platform, date, purpose и selected URLs в
   [search-log.csv](search-log.csv).

Web search не считается полностью воспроизводимым: сохраняются дата, exact
query и выбранные URL, а нестабильные claims перепроверяются перед защитой.

## 6. Screening и extraction

Каждый candidate получает:

```text
source_id
RQ IDs
title/authors/year/status
stable URL/DOI
source class
inclusion decision/reason
method/sample/benchmark
claim and exact scope
limitations/bias/leakage
artifact/version/license/hash
project implication
review status/reviewer/date
```

Дубликаты связываются, а не уничтожаются: сохраняется provenance всех каналов.

## 7. Claim promotion gate

Claim может повлиять на ADR/specification только если:

- имеет стабильный ID и разрешимый источник;
- формулировка не сильнее evidence;
- scope источника совпадает с нашим use case или перенос обоснован;
- известны статус peer review, limitations и conflicts;
- для high-impact claim найден primary/official source;
- рассмотрен хотя бы один counterexample/alternative;
- reviewer может воспроизвести путь claim → source → implication.

Результат: `accepted`, `accepted_with_limits`, `needs_more_evidence`, `rejected`.

## 8. Evaluation preregistration

До основных benchmark runs `P0.12` фиксирует:

- primary datasets/splits и hashes;
- primary detection/repair metrics;
- scanner-only, LLM-only и hybrid baselines;
- models/prompts/tools/policies и randomization/seeds;
- exclusion/failure/timeout rules;
- resource/cost measurement;
- основной analysis и confidence reporting;
- leakage checks и immutable holdout;
- exploratory analyses, которые не считаются confirmatory.

После freeze изменения не скрываются: они идут в
[AMENDMENTS.md](AMENDMENTS.md), а исходный baseline сохраняется.

## 9. Quality gates

| Gate | Проверка SecureCode AI |
|---|---|
| Question validity | Claim отвечает одному RQ и реальному решению |
| Search validity | Не пропущен очевидный класс evidence |
| Eligibility validity | Inclusion/exclusion применены последовательно |
| Evidence quality | Метод, dataset, status и provenance известны |
| Scope validity | Laboratory/benchmark claim не выдан за enterprise result |
| Reproducibility | Query/artifact/version/hash сохранены |
| Robustness | Models/prompts/seeds/baselines не переворачивают вывод без оговорки |
| Independent review | Автор claim не единственный reviewer high-impact вывода |
| Claim calibration | Текст ADR/spec не сильнее evidence |

## 10. Stop conditions

Исследовательский вопрос готов к решению, когда:

- evidence покрывает основные альтернативы и классы источников;
- claims, conflicts и limitations прослеживаемы;
- дальнейший поиск даёт преимущественно дубликаты/низкую marginal value;
- решение можно принять с явно записанным residual risk;
- reviewer способен восстановить путь к выводу.

«Найдено много источников» и «отчёт получился длинным» не являются stop
conditions.

## 11. Текущий статус

Protocol создан после ранней exploratory фазы, поэтому он честно помечен как
retrospective draft, а не preregistration. До `G0` нужно завершить source
resolution импортированного Deep Research, заполнить ledger по `RQ-01–RQ-07` и
заморозить evaluation protocol.

