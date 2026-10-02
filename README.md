# SecureCode AI

[![CI](https://github.com/shorinversion/securecode-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/shorinversion/securecode-ai/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/shorinversion/securecode-ai)](https://github.com/shorinversion/securecode-ai/releases)
![Python](https://img.shields.io/badge/python-3.12%20%7C%203.13%20%7C%203.14-blue)

**Русский** | [English](README.en.md)

SecureCode AI — мультиагентный ассистент для аудита безопасности кода на Python,
JavaScript/TypeScript и Go. Система находит уязвимости, классифицирует их по CWE и
OWASP Top 10 и предлагает исправления в виде diff, которые перед публикацией проходят
автоматическую проверку. Модель может работать локально, поэтому исходный код не
покидает машину разработчика.

[Сайт проекта](https://mydev.stream/) ·
[Итоговый отчёт](https://mydev.stream/final-submission.html) ·
[Эксперименты](https://mydev.stream/benchmark.html) ·
[Notebook](notebooks/securecode_demo.ipynb) ·
[Релизы](https://github.com/shorinversion/securecode-ai/releases)

## Видео

https://github.com/user-attachments/assets/93075dcc-41a4-412d-a9ae-f54154e414b4

Английская версия — в [README.en.md](README.en.md#video).

## Возможности

- **Инструменты анализа** на `ast` и `tree-sitter`: детерминированные правила для 35 CWE,
  поиск захардкоженных секретов, проверка зависимостей pip, npm и Go по базе OSV.
- **Четыре агента на LLM:** Поиск, Аудитор, Скептик и Архитектор (см. [Архитектура](#архитектура)).
- **Проверенные исправления:** каждый diff применяется к анализируемой ревизии
  (`git apply --check`), проходит синтаксическую проверку и повторное сканирование.
- **Отчёты** в Markdown, HTML, JSON и SARIF: CWE, категория OWASP Top 10 2021,
  критичность, фрагмент кода и исправление.
- **Единый контракт инструментов:** каждый сигнал содержит правило (CWE), путь, строки
  и ссылку на фрагмент кода.
- **Выбор модели:** локальная квантованная Qwen 2.5 Coder 7B (Ollama) или DeepSeek по API.
- **Интеграция с CI:** GitHub и GitLab, SARIF для GitHub code scanning.

## Архитектура

```text
         Git-ревизия (точный commit)
                    │
      ┌─────────────┴─────────────┐
      ▼                           ▼
детерминированные сканеры   Поиск (LLM)
      └─────────────┬─────────────┘
                    ▼
      граф доказательств (EvidenceGraph)
                    │
                    ▼
      Аудитор → Скептик → решение по находке
                    │
                    ▼
      Архитектор: diff + проверка
                    │
                    ▼
      отчёт: CWE, OWASP Top 10, исправления
```

| Агент | Задача |
| --- | --- |
| Поиск | Исследует код независимо от сканеров и предлагает кандидатов в уязвимости |
| Аудитор | Проверяет кандидата: достигают ли недоверенные данные опасной операции через границу доверия |
| Скептик | Пытается опровергнуть вывод Аудитора: ищет санитизацию, безопасный API, недостижимый путь |
| Архитектор | Пишет минимальное исправление подтверждённой находки; патч проверяется до попадания в отчёт |

Проверка утверждений опирается на открытые методики
[Anthropic](https://github.com/anthropics/claude-code-security-review) и
[Cloudflare](https://github.com/cloudflare/security-audit-skill). Подробное описание:
[архитектура](docs/ARCHITECTURE.md), [модель угроз](docs/security/THREAT_MODEL.md).

## Быстрый старт

Демонстрация на уязвимом примере в Docker:

```bash
python deploy/docker/quickstart.py --demo
```

С локальной моделью (требуются [uv](https://docs.astral.sh/uv/) и
[Ollama](https://ollama.com); модель `qwen2.5-coder:7b-instruct-q4_K_M`, около 4.7 ГБ,
загружается автоматически):

```bash
python deploy/docker/quickstart.py --demo --provider local
```

Отчёты сохраняются в `output/demo-report/`. Прогон всех инструментов с сохранёнными
выводами: [notebooks/securecode_demo.ipynb](notebooks/securecode_demo.ipynb).

## Установка

Требования: Git, CPython 3.12–3.14, [uv](https://docs.astral.sh/uv/) 0.12.0.
Docker нужен только для образов, Ollama — только для локальной модели.

```bash
git clone https://github.com/shorinversion/securecode-ai.git
cd securecode-ai
uv sync --locked
uv run securecode --version
```

## Использование

### Аудит репозитория

```bash
uv run securecode analyze path/to/repo --output report.md
```

Команда выполняет полный конвейер: сканеры, Поиск, Аудитор, Скептик, решение по каждой
находке и исправления Архитектора.

| Параметр | Назначение |
| --- | --- |
| `--provider deepseek\|local` | Модель: DeepSeek (`DEEPSEEK_API_KEY` в окружении или `.env`) или локальная через Ollama |
| `--format markdown\|html\|json\|sarif` | Формат отчёта |
| `--output FILE` | Записать отчёт в файл |
| `--patch-dir DIR` | Сохранить проверенные исправления в `.diff`-файлы |
| `--no-fix` | Не запрашивать исправления |
| `--max-cost-usd N` | Лимит расходов на API за прогон (по умолчанию 1.0) |

Коды возврата: `0` — уязвимостей не найдено, `2` — найдены, `3` — анализ не завершён,
`4` — ошибка конфигурации.

Пример фрагмента отчёта:

```text
| № | Уязвимость           | OWASP Top 10       | Критичность | Место    | Исправление          |
| 1 | CWE-89 SQL Injection | A03:2021 Injection | HIGH        | app.py:5 | исправление проверено |
```

### Исправление в виде pull request

```bash
uv run python -I demo/p917_real_local_demo.py --repository path/to/repo --output out --provider deepseek --open-pr
```

Архитектор коммитит проверенное исправление в ветку `securecode/fix-…` и открывает pull
request через GitHub CLI. Пример:
[shorinversion/securecode-demo-app#1](https://github.com/shorinversion/securecode-demo-app/pull/1).

### CI и серверный режим

`securecode scan` — блокирующая проверка для CI на заранее одобренном хосте: привязка к
точному commit, одобренные профили модели и политики исходящих данных. Развёртывание
control plane, worker и интеграций с GitHub и GitLab описано в
[docs/OPERATIONS.md](docs/OPERATIONS.md).

## Результаты

**Демонстрация Аудитор → Архитектор** на локальной Qwen 2.5 Coder 7B Q4_K_M и на
DeepSeek: SQL-инъекция (CWE-89, A03:2021) найдена, исправление с параметризованным
запросом прошло проверку. Квитанции:
[Qwen](report/submission-benchmark/evidence/current-real-local-p917.json),
[DeepSeek](report/submission-benchmark/evidence/current-deepseek-p917.json).

**Реальные репозитории** на Python, JavaScript и Go: подтверждены SQL-инъекции, внедрение
команд, открытый редирект, обход пути, отсутствие проверки подписи JWT; ложное
срабатывание CSRF отклонено. Стоимость прогона — менее $0.01.

**OWASP Benchmark for Python** (1230 кейсов, 14 категорий; оценка TPR − FPR, 1 — идеально).
В SecureCode решение принимается согласием трёх проверок: Поиск (модель без подсказок),
Аудитор (модель проверяет находки сканеров) и вторая модель; CWE попадает в отчёт, если её
назвали минимум две из трёх. «Только модель» — та же модель без сканеров, для сравнения:

| Конфигурация | Оценка | Precision |
| --- | ---: | ---: |
| **SecureCode: согласие трёх проверок (gpt-oss-120b, Luna)** | **0,82** | **88,9%** |
| SecureCode: согласие трёх проверок (gpt-oss-120b, DeepSeek Flash) | 0,81 | 86,8% |
| SecureCode: сканеры + проверка gpt-oss-120b | 0,78 | 89,0% |
| SecureCode: сканеры + проверка DeepSeek Flash | 0,50 | 59,7% |
| SecureCode: только сканеры | 0,21 | 70,4% |
| Только модель: gpt-oss-120b | 0,80 | 85,6% |
| Только модель: DeepSeek Flash | 0,39 | 53,8% |
| Bandit 1.9.4 | 0,16 | 87,8% |
| Semgrep 1.177.0 | 0,16 | 57,8% |

**CVEfixes** (3000 файлов: пары «до и после исправления CVE», 118 CWE; отложенная
выборка 1200 файлов):

| Конфигурация | Recall | Разница с Semgrep, п. п. (95% ДИ) |
| --- | ---: | ---: |
| SecureCode: сканеры ∪ GPT-5.6 Luna | 50,5% | +16,2 [+11,3; +21,0] |
| Сканеры SecureCode ∪ Semgrep | 43,8% | +9,5 [+7,2; +11,8] |
| Semgrep 1.177.0 | 34,3% | — |
| SecureCode: только сканеры | 25,2% | −9,2 [−13,3; −5,0] |

Методика, Bandit, gosec, ESLint, модели с открытыми весами, разбивка по языкам и
ограничения: [отчёт об экспериментах](report/benchmark-v2/README.md). Датасеты:
[CVEfixes](https://zenodo.org/records/13118970),
[OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython).

## Языки и правила

| Язык | Файлы | Анализ |
| --- | --- | --- |
| Python | `.py`, `.pyi` | AST и CST, таблица символов, 35 CWE |
| JavaScript / TypeScript | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx` | CST, таблица символов, 35 CWE |
| Go | `.go` | CST, таблица символов, 35 CWE |
| Все | манифесты pip, npm, Go; любые файлы | уязвимые зависимости (OSV), секреты |

Детерминированные правила покрывают инъекции (CWE-78, 79, 89, 90, 94), обход пути (22),
SSRF (918), отсутствие аутентификации и авторизации (306, 862), небезопасную
десериализацию (502), слабую криптографию (327, 338), захардкоженные учётные данные (798),
ReDoS (1333) и другие. Агенты не ограничены этим списком: модель может сообщить о любой из
139 CWE таблицы соответствия OWASP Top 10 2021.

## Безопасность

- Анализ привязан к точному commit; изменение ревизии отменяет публикацию результата.
- Незавершённая проверка даёт итог `INDETERMINATE`, а не «уязвимостей нет».
- Ответы модели — недоверенные данные: они проходят проверку по закрытой схеме.
- Файлы с секретами не передаются модели; значения секретов не сохраняются.
- Локальная модель доступна только через loopback; внешний API используется лишь с
  явным согласием владельца.
- Исправления не применяются к исходному checkout без явного решения пользователя.

Подробнее: [классификация данных](specs/security/data-classification.md),
[защита от prompt injection](docs/security/PROMPT_INJECTION.md).

## Разработка

```bash
uv sync --locked --group quality
uv run --locked python -I scripts/quality.py
```

`scripts/quality.py` запускает форматирование и линтер Ruff, mypy для Linux и Windows,
unit- и интеграционные тесты с порогом покрытия ядра 80%. CI повторяет проверки на
Python 3.12, 3.13 и 3.14 и дополнительно сканирует секреты и зависимости.

## Структура репозитория

| Путь | Содержимое |
| --- | --- |
| `apps/cli/` | CLI `securecode` |
| `apps/server/`, `apps/worker/` | control plane и worker для CI |
| `packages/contracts/` | версионированные контракты и JSON Schema |
| `packages/core/` | доменная логика: граф доказательств, политика, отчёты, исправления |
| `packages/adapters/` | Git, tree-sitter, модели, песочница, отчёты, SCM |
| `demo/` | демонстрации и уязвимые примеры |
| `notebooks/` | демонстрационный notebook |
| `report/` | итоговый отчёт и эксперименты |
| `tests/` | unit-, контрактные и интеграционные тесты |
| `docs/` | архитектура, решения, безопасность, эксплуатация |

## Документация

- [Итоговый отчёт](https://mydev.stream/final-submission.html) — постановка, решение, эксперименты, выводы
- [Архитектура](docs/ARCHITECTURE.md) и [продуктовая модель](docs/PRODUCT.md)
- [Эксплуатация: Docker, CI, GitHub и GitLab](docs/OPERATIONS.md)
- [Воспроизведение экспериментов](docs/REPRODUCIBILITY.md)
- [Модель угроз](docs/security/THREAT_MODEL.md)
- [Исходное задание](docs/PROJECT_BRIEF.md)

## Лицензия

Лицензия не выбрана; все права принадлежат автору. Учебный корпус в
`evaluation/development/` распространяется под CC0-1.0.
