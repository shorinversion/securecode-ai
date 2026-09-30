# Воспроизведение результатов

Документ описывает, как повторить демонстрации и эксперименты из
[итогового отчёта](https://mydev.stream/final-submission.html).

## Окружение

```bash
git clone https://github.com/shorinversion/securecode-ai.git
cd securecode-ai
uv sync --locked --group quality
```

`uv.lock` — единственный источник версий Python-зависимостей; флаг `--locked`
запрещает его неявное обновление.

## Демонстрация без модели

Синтетический пример CWE-89 без обращения к модели:

```bash
uv run --locked python -I demo/mvp_cwe89_demo.py --output output/demo-cwe89
```

Уязвимый пример даёт один сигнал CWE-89, безопасный — ноль; эталонное исправление
проверяется во временной копии.

## Демонстрация с локальной моделью

| Параметр | Значение |
| --- | --- |
| Endpoint | `http://127.0.0.1:11434/v1` |
| Ollama | `0.34.4` |
| Модель | `qwen2.5-coder:7b-instruct-q4_K_M` |
| Квантование | `Q4_K_M` |
| Digest модели | `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364` |

```bash
ollama serve
ollama pull qwen2.5-coder:7b-instruct-q4_K_M
uv run --locked python -I demo/p917_real_local_demo.py --repository demo/fixtures/real-local-cwe89 --output output/demo-report
```

Перед отправкой кода шлюз проверяет версию Ollama, имя и digest модели и повторяет
проверку после генерации. Отчёт: `output/demo-report/security-report.md` и `.html`.
Квитанция прогона:
[current-real-local-p917.json](../report/submission-benchmark/evidence/current-real-local-p917.json).

## Демонстрация с DeepSeek

Ключ читается из `DEEPSEEK_API_KEY` в окружении или из файла `.env` в корне
репозитория (файл исключён из Git). Расход ограничен $0.10 на прогон.

```bash
uv run --locked python -I demo/p917_real_local_demo.py --repository demo/fixtures/real-local-cwe89 --output output/demo-report --provider deepseek
```

Квитанция: [current-deepseek-p917.json](../report/submission-benchmark/evidence/current-deepseek-p917.json).
Согласие владельца на передачу кода: [deploy/deepseek/owner-consent.json](../deploy/deepseek/owner-consent.json).
DeepSeek не подтверждает условия хранения данных; передавайте только код, который
разрешено раскрывать.

## Бенчмарк CVEfixes

Корпус: [CVEfixes v1.0.8](https://zenodo.org/records/13118970). В репозитории хранится
манифест без исходного кода; база SQLite загружается отдельно. Лицензия набора указана
как NOASSERTION, поэтому перед распространением материалов проверьте условия набора и
исходных репозиториев.

Сохранённые результаты пересчитываются без обращения к API:

```bash
uv run --locked python report/submission-benchmark/aggregate_benchmark.py
```

Прогон модельных конфигураций на пяти кейсах (PowerShell):

```powershell
$database = 'C:\data\CVEfixes_v1.0.8.sqlite'
$candidate = (git rev-parse HEAD).Trim()
$profile = (Get-FileHash report/submission-benchmark/evidence/model-profile.json -Algorithm SHA256).Hash.ToLowerInvariant()
uv run --locked --group quality python -m scripts.run_release_benchmark `
  --manifest report/submission-benchmark/evidence/cvefixes-manifest.json `
  --database $database --configuration model_native `
  --output output/deepseek-smoke.json --limit 5 --repetitions 1 `
  --allow-public-remote --spend-ledger output/deepseek-smoke-spend.sqlite `
  --budget-phase development --total-budget-microusd 10000000 `
  --candidate-sha $candidate --profile-sha256 $profile `
  --max-input-tokens 1000000 --max-output-tokens 64 `
  --input-microusd-per-million 150000 --output-microusd-per-million 600000
```

Прогон полного конвейера (Поиск, Аудитор, Скептик) по каждому кейсу:

```bash
uv run --locked python -m scripts.run_pipeline_benchmark \
  --manifest report/submission-benchmark/evidence/cvefixes-manifest.json \
  --database path/to/cvefixes.sqlite --split held-out \
  --output output/pipeline.jsonl --summary output/pipeline-summary.json
```

Скрипт возобновляет прерванный прогон и останавливается при достижении лимита расходов
(`--stop-at-usd`, по умолчанию $5).

## Проверка качества

```bash
uv run --locked python -I scripts/quality.py
```

Команда запускает Ruff, mypy для Linux и Windows, unit- и интеграционные тесты с порогом
покрытия ядра 80% и завершается строкой `QUALITY=PASS`.
