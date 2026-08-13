# Deep Research: влияние на SecureCode AI

Статус: targeted technical impact review  
Дата: 12 августа 2026 года  
Задача плана: `P0.3`  
Исходный материал:
[deep-research-methodology-2026-08-12.md](deep-research-methodology-2026-08-12.md).

## Техническое резюме

Исследование полезно и заметно усиливает проект, но **не как готовый ответ о
SecureCode AI**. Оно описывает методологию глубокого исследования вообще и
поэтому влияет прежде всего на путь принятия решений: от найденного тезиса до
ADR, спецификации и benchmark gate.

Главный принятый эффект:

> В архитектуру и ТЗ попадает не текст Deep Research, а только claim, прошедший
> разрешение первичного источника, scope check, проверку ограничений и
> прослеживаемый decision gate.

Текущие решения о hybrid analysis, evidence/workflow graphs, bounded loops,
CLI + CI/backend и SHA-bound gates не опровергнуты. Напротив, идея
`claim → evidence → transformation → uncertainty → validation → provenance`
усиливает их. Но отчёт не сравнивает наши конкретные runtime, SCM, sandbox или
storage alternatives, поэтому не закрывает соответствующие P0 decisions.

## Что изменено немедленно

1. Создан project-specific [research protocol](PROTOCOL.md) с `RQ-01–RQ-07`.
2. Введён [claim ledger](CLAIMS.md) со статусами качества и scope.
3. Exact queries и выбранные URL записываются в
   [search log](search-log.csv).
4. Retrospective/exploratory работа отделена от будущего frozen protocol через
   [amendment log](AMENDMENTS.md).
5. Deep Research сохранён как immutable raw input с hash/provenance, а не
   смешан с `RESEARCH.md`.
6. `G0` получает research evidence gate; `P0.12` должен заморозить primary
   evaluation plan до основных benchmark runs.

## Самый важный quality finding

Импортированный отчёт содержит `74` внутренних citation markers, но не содержит
разрешимых URL или bibliography. Это не означает, что его тезисы ложны: targeted
spot-check подтвердил ключевые идеи о PRISMA, documented search, FAIR,
reproducibility и OSF. Однако исходный файл нельзя напрямую цитировать на защите
и нельзя считать полным audit trail.

Следствие: отчёт имеет высокую ценность как **структура и генератор кандидатов**,
но среднюю/низкую готовность как самостоятельный evidence package. Детали — в
[CLAIMS.md](CLAIMS.md).

## Влияние по областям проекта

| Область | Изменение | Эффект |
|---|---|---|
| Research | Protocol, search log, eligibility и claim ledger становятся обязательными | Меньше citation hallucination, cherry-picking и post-hoc rationalization |
| SDD | Каждый архитектурный `MUST` должен ссылаться на accepted decision/evidence | ТЗ становится проверяемым, а не компиляцией красивых claims |
| EvidenceGraph | Добавляются provenance, contradiction, uncertainty и validation semantics | Finding объясняет не только путь к sink, но и качество доказательства |
| Evaluation | Primary datasets/metrics/baselines freeze до основных runs; exploratory результаты маркируются | Снижается benchmark overfitting и выбор удачных runs постфактум |
| Gates | `G0` проверяет source resolution и calibrated claims; release gates хранят immutable evidence | Решения можно воспроизвести и защитить |
| LLM harness | LLM — candidate generator; structured output должен включать evidence refs и uncertainty | Модель не может превратить внутреннюю ссылку или уверенный текст в факт |
| Project memory | Raw inputs отделены от verified conclusions | Сжатие контекста не уничтожает provenance и не повышает статус непроверенных claims |

## Как это усиливает продуктовую архитектуру

### 1. FindingCase становится настоящим case file

Нужно сохранить уже предусмотренные поля и позже формализовать:

```text
hypothesis
supporting_evidence[]
contradicting_evidence[]
transformations[]
uncertainty
validation_results[]
provenance
decision_history[]
```

Это не новый третий graph. Это усиление EvidenceGraph и append-only state,
которые уже приняты в `D-004`.

### 2. Evaluation получает разделение reproduce/replicate

- **Reproduce:** тот же commit, fixtures, tools, model profile, prompt, policy и
  seed дают согласованный replay либо документированную nondeterminism envelope.
- **Replicate/generalize:** результат сохраняется на других репозиториях,
  языках, моделях, seeds и свежем holdout.

Одна успешная демонстрация CWE-89 подтверждает vertical slice, но не
generalization продукта.

### 3. Robustness становится частью harness

Для high-impact finding/patch недостаточно одного model run. В пределах бюджета
проверяются разумные варианты: independent Skeptic, alternative context,
детерминированный rescan, PoC+ и negative control. При расхождении результат
эскалируется, а не усредняется до удобного verdict.

## Что исследование не решило

- GitHub-first или GitLab-first;
- Python-first или три языка в Core MVP;
- LangGraph/Temporal/другой durable runtime;
- storage, queue и artifact backend;
- Docker/Kubernetes job/microVM sandbox;
- конкретные blocking thresholds;
- scope первой UI.

Эти решения по-прежнему требуют предметного evidence и trade-off analysis.
Generic research methodology не является доказательством в пользу конкретной
технологии.

## Пропорциональность процесса

Мы не будем превращать каждую библиотечную зависимость в медицинский systematic
review. Применяется risk-based assurance:

- low-impact reversible choice — официальный источник + короткий ADR;
- architecture/security choice — несколько независимых источников,
  counterevidence и prototype evidence;
- benchmark/scientific claim — frozen protocol, pinned data, reproducible code,
  sensitivity и independent review;
- claim для публичной защиты — разрешимый primary source и точная оговорка scope.

PRISMA/PRISMA-S используются как источник полезных механизмов прозрачности, но
проект не заявляет формальную PRISMA compliance, пока не проведён соответствующий
systematic review.

## Следующие действия

1. Завершить resolution ключевых `turn…` claims, относящихся к `RQ-01–RQ-07`.
2. Заполнить evidence matrix для выбора language scope, reference SCM и runtime.
3. Заморозить `P0.12` evaluation protocol и holdout до benchmark tuning.
4. Только после этого перенести accepted claims в decision-complete `P0.14`
   specification baseline.

## Ограничения impact review

- Выполнена targeted, а не исчерпывающая проверка всех claims исходного отчёта.
- Некоторые стандарты отчёта относятся к biomedical/systematic review context;
  их перенос в software engineering является осознанной адаптацией.
- Никакая методология не устраняет необходимость инженерных prototypes,
  benchmark data и security testing.

