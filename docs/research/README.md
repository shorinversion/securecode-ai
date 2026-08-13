# SecureCode AI — research artifacts

Этот каталог хранит исходные исследовательские материалы отдельно от
проверенных выводов. Наличие файла в каталоге не означает, что все его claims
подтверждены или приняты в архитектуру.

## Импортированный Deep Research

- Репозиторная копия:
  [deep-research-methodology-2026-08-12.md](deep-research-methodology-2026-08-12.md)
- Исходный файл пользователя: `deep-research-report.md`.
- Дополнительная копия: приложенный `pasted-text.txt`.
- Дата импорта: 12 августа 2026 года.
- Строк: `1020`.
- Размер исходного Markdown: `80159` bytes.
- SHA-256 исходного Markdown:
  `537c8c5c1fd0c016d214f21dee3b369a4838715c6fc4ae2be60690ae093bb9ac`.
- SHA-256 приложенного текстового контейнера:
  `cd200dfcdcbf05feea83c03874f703b99733d8a71d30ed1db7cccba6e38388f5`.
- Нормализованный UTF-8/LF content hash обеих пользовательских копий и
  репозиторной копии:
  `537c8c5c1fd0c016d214f21dee3b369a4838715c6fc4ae2be60690ae093bb9ac`.

Две пользовательские копии различались только файловым представлением;
нормализованный текст совпадает полностью. Репозиторная копия проверена по всем
`1020` строкам и нормализованному SHA-256.

## Ограничение источника

В импортированном отчёте найдено `74` внутренних citation markers вида
`turn…`, но `0` разрешимых URL и `0` отдельным образом перечисленных references.
Поэтому отчёт используется как **candidate map и методологический input**, а не
как цитируемый источник истины. Проверенные claims и их первичные ссылки
фиксируются отдельно в [CLAIMS.md](CLAIMS.md).

## Производные артефакты

- [IMPACT.md](IMPACT.md) — влияние исследования на SecureCode AI.
- [PROTOCOL.md](PROTOCOL.md) — адаптированный research protocol проекта.
- [CLAIMS.md](CLAIMS.md) — claim/evidence/quality ledger.
- [search-log.csv](search-log.csv) — журнал воспроизводимых поисковых действий.
- [RLM_DSPY_SKILLOPT.md](RLM_DSPY_SKILLOPT.md) — targeted review RLM,
  DSPy/GEPA, SkillOpt, synthetic eval generation и безопасного promotion loop.
- [AMENDMENTS.md](AMENDMENTS.md) — изменения protocol и честное разделение
  предварительно заданной и exploratory работы.
- [verify-deep-research.ps1](verify-deep-research.ps1) — воспроизводимая
  проверка целостности, строк и citation quality исходника.
- [report-data.sql](report-data.sql) — воспроизводимые reviewed rows для
  технического impact report.

## Правило продвижения evidence

```text
raw report / search result
  → candidate claim
  → resolvable primary source
  → scope and limitation check
  → independent/adversarial review
  → accepted ADR or specification requirement
```

Raw report никогда не обновляет `DECISIONS.md` или accepted `specs/` напрямую.
