# SecureCode AI

[Русский](#русский) | [English](#english)

[Видео, 4:12](docs/media/securecode-demo.mp4) · [Итоговый отчёт](report/final-submission.html) · [Сайт проекта](http://82.202.143.138/)

Видео содержит монтаж сохранённых результатов и ИИ-озвучку; это не запись нового живого запуска.

SecureCode AI - локальный прототип аудита безопасности и управляемого
предложения исправлений для Python, JavaScript, TypeScript и Go. Он объединяет
детерминированный анализ с локальной LLM, сохраняет evidence решений и
отказывает закрыто, если обязательный этап не завершился.

> **Статус:** прототип по курсовому заданию. Демо Аудитор → Архитектор
> завершается `COMPLETED` и на локальной Qwen, и на DeepSeek: CWE-89 найден, patch
> проверен в эфемерной копии; на 600 кейсах CVEfixes комбинация сканеров и LLM на
> уровне Semgrep, но не лучше. Production readiness не заявляется. Соответствие
> заданию по пунктам — в [итоговом отчёте](report/final-submission.html#соответствие-заданию).

## Быстрый старт / Quick start

```bash
python deploy/docker/quickstart.py --demo
```

Нужен только Docker. Команда собирает образ, проверяет демонстрационный уязвимый
код и печатает отчёт: находка, CWE, категория OWASP Top 10, строка и, при
наличии модели, проверенный Auto-Fix patch. Если в окружении или в корневом `.env`
задан `DEEPSEEK_API_KEY`, Аудитор и Архитектор работают на DeepSeek; без ключа
работает только детерминированный lane (итог `INDETERMINATE`).

Only Docker is required. The command builds the image, audits the vulnerable demo
code and prints the report: finding, CWE, OWASP Top 10 category, line and, with a
model, the validated Auto-Fix patch. With `DEEPSEEK_API_KEY` in the environment or
the root `.env`, the Auditor and Architect run on DeepSeek; without it only the
deterministic lane runs (outcome `INDETERMINATE`).

```bash
python deploy/docker/quickstart.py --demo --provider local
```

Тот же сценарий на локальной квантованной Qwen: нужны [uv](https://docs.astral.sh/uv/)
и запущенный [Ollama](https://ollama.com); модель `qwen2.5-coder:7b-instruct-q4_K_M`
(около 4.7 ГБ) скачается автоматически. Отчёты: `output/demo-report/`.
The same run on a local quantized Qwen: needs uv and a running Ollama; the model is
pulled automatically. Reports go to `output/demo-report/`.

Полный прогон инструментов (AST, секреты, уязвимые зависимости, CWE-сканеры,
единый контракт, агенты, отчёт, метрики) с сохранёнными выводами:
[notebooks/securecode_demo.ipynb](notebooks/securecode_demo.ipynb).
A full walkthrough with stored outputs is in the same notebook.

## Русский

### Назначение

SecureCode AI проверяет точную Git-ревизию, объединяет детерминированный поиск и
независимое исследование локальной LLM, нормализует кандидаты в единый граф
доказательств и публикует результат только после обязательной интерпретации и
проверок. Исправления создаются как отдельные артефакты, проверяются во временной
среде и не применяются к исходному checkout без явного одобрения.

Основные поверхности продукта:

- автономная CLI для локального аудита, подготовки исправлений и валидации;
- Linux worker для выполнения точного задания в CI;
- ASGI control plane с очередью, состоянием запусков, approvals и audit trail;
- адаптеры GitHub и GitLab для exact-SHA статусов и ограниченной публикации;
- воспроизводимые учебные эксперименты, notebook и отчеты.

### Архитектура

```text
Git checkout at an exact commit
             |
             v
  deterministic discovery  +  model-native discovery
             \                    /
              v                  v
           normalized candidates
                     |
                     v
          Auditor and Skeptic checks
                     |
                     v
      EvidenceGraph + policy decision + reports
                     |
          +----------+-----------+
          |                      |
          v                      v
   local CLI / worker      control plane / SCM
```

Два графа решают разные задачи:

- `WorkflowGraph` управляет переходами, бюджетами, retry, approval и stop
  conditions;
- `EvidenceGraph` связывает finding, source location, tool/model observations,
  patch, validation и provenance.

Доменная логика находится в `packages/core/` и не зависит от транспорта или
конкретного graph runtime. `packages/contracts/` владеет закрытыми Pydantic
контрактами и JSON Schema. `packages/adapters/` реализует Git, CST, model,
sandbox и SCM границы. CLI, server и worker только собирают эти общие части.

Подробности: [архитектура](docs/ARCHITECTURE.md),
[продуктовая модель](docs/PRODUCT.md) и
[модель угроз](docs/security/THREAT_MODEL.md).

### Языки и CWE

| Область | Поддержка в текущем коде | Ограничение |
| --- | --- | --- |
| Python | `.py`, `.pyi`; CST/AST, symbol index, CWE-89 и portfolio rules | Покрытие зависит от поддерживаемых source/sink patterns |
| JavaScript | `.js`, `.mjs`, `.cjs`, `.jsx`; CST, symbol index, CWE-89 | Ограниченный набор проверенных patterns |
| TypeScript | `.ts`, `.tsx`; CST, symbol index, CWE-89 | TypeScript types не превращают анализ в полный compiler pass |
| Go | `.go`; CST, symbol index, CWE-89 и часть portfolio rules | Ограниченный набор проверенных patterns |

Закрытый портфель классификации включает `CWE-89` SQL Injection, `CWE-78` OS
Command Injection, `CWE-22` Path Traversal, `CWE-862` Missing Authorization и
`CWE-918` Server-Side Request Forgery.

Это описание реализованных правил, а не обещание полного покрытия CWE и не
утверждение о превосходстве над SAST. Текущие результаты расширенного сравнения
на 600 кейсах приведены в [submission benchmark](report/submission-benchmark/README.md).
Ранний development benchmark и его ограничения сохранены отдельно:
[протокол и результаты](report/development-benchmark/README.md),
[ограничения](report/development-benchmark/limitations.md).

### Проверка кандидата

Команда `uv run --locked python -I scripts/quality.py` запускает Ruff format и
lint, mypy для Linux и Windows и pytest (unit-тесты и интеграционные тесты демо) с
порогом покрытия ядра 80%. На текущем `main` результат `QUALITY=PASS`, 3292 теста;
CI повторяет те же проверки на Python 3.12, 3.13 и 3.14, а также проверяет секреты
и зависимости.

### Требования и установка

- Git;
- CPython `>=3.12,<3.15`;
- [uv](https://docs.astral.sh/uv/) строго версии `0.12.0`;
- Docker только для образов server/worker, изолированной repair validation и
  opt-in corpus oracle;
- Ollama только для локального model path.

Из чистого clone:

```powershell
git clone <repository-url> securecode-ai
Set-Location securecode-ai
uv --version
uv sync --locked --no-dev --no-editable
uv run --locked --offline --no-sync securecode --version
```

`uv.lock` является единственным источником разрешенных Python-зависимостей.
`--locked` запрещает незаметное обновление lock, а `--no-editable` проверяет
установочный путь без импорта прямо из исходного дерева. Для разработки:

```powershell
uv sync --locked --no-editable --group quality
```

### Быстрый старт без модели

Воспроизводимая публичная демонстрация не читает приватный код, не вызывает LLM
и работает во временном workspace:

```powershell
$output = Join-Path $PWD '.securecode/demo-cwe89'
New-Item -ItemType Directory -Path $output | Out-Null
uv run --locked --offline --no-sync python -I demo/mvp_cwe89_demo.py --output $output
```

Ожидаемый узкий сценарий: vulnerable Python fixture дает один CWE-89 signal,
safe control дает ноль, reference repair предлагается и проверяется только в
эфемерной копии, исходный checkout остается неизменным.

Базовая диагностика установленной CLI:

```powershell
uv run --locked --offline --no-sync securecode doctor
uv run --locked --offline --no-sync securecode scan . --diagnostic --format json
```

Полный `securecode scan` требует защищенный host approval record и точное
совпадение одобренных profile, policy, provider evidence и исполняемого Git.
Отсутствующая или измененная authority приводит к безопасному отказу.

### Локальный Ollama

Записанный учебный путь использует только literal loopback и точные значения:

| Параметр | Значение |
| --- | --- |
| Endpoint | `http://127.0.0.1:11434/v1` |
| Ollama | `0.34.4` |
| Model | `qwen2.5-coder:7b-instruct-q4_K_M` |
| Quantization | `Q4_K_M` |
| Expected model digest | `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364` |

Чтобы повторить текущую real-local демонстрацию, запустите Ollama локально и
загрузите модель. Команда не обращается к облачному провайдеру:

```bash
uv run --locked python -I demo/p917_real_local_demo.py --repository demo/fixtures/real-local-cwe89 --output output/demo-report
```

Отчёт: `output/demo-report/security-report.md` (и `.html`); фикстура читается из
неизменяемого снимка и не изменяется.

Текущая обезличенная квитанция находится в
[`report/submission-benchmark/evidence/current-real-local-p917.json`](report/submission-benchmark/evidence/current-real-local-p917.json).
Прогон 29 сентября 2026: Qwen нашла CWE-89, совпавший с детерминированным
сканером, и предложила параметризованный запрос; patch распарсился, повторный
скан дал 0 сигналов, `outcome=COMPLETED`, исходный checkout не изменён.

Тот же сценарий на DeepSeek (профиль `deepseek-owner-authorized`, согласие
владельца в [`deploy/deepseek/owner-consent.json`](deploy/deepseek/owner-consent.json)):
ключ берётся из `DEEPSEEK_API_KEY` или из строки `DEEPSEEK_API_KEY=...` в
корневом `.env` (файл игнорируется Git), расход ограничен $0.10 на прогон.

```bash
uv run --locked python -I demo/p917_real_local_demo.py --repository demo/fixtures/real-local-cwe89 --output output/demo-report --provider deepseek
```

Квитанция: [`current-deepseek-p917.json`](report/submission-benchmark/evidence/current-deepseek-p917.json)
(`outcome=COMPLETED`, 2 вызова, $0.00014). Условия хранения и обучения у
DeepSeek не проверены; отправляйте только код, который вы вправе раскрыть.

Пример локальной подготовки:

```powershell
$env:OLLAMA_HOST = '127.0.0.1:11434'
ollama serve
```

В другом терминале:

```powershell
ollama pull qwen2.5-coder:7b-instruct-q4_K_M
ollama list
uv run --locked --offline --no-sync python -I demo/p917_real_local_demo.py --help
```

Перед отправкой source gateway проверяет bounded `/api/version` и `/api/tags`,
точные model name и digest, а после generation повторяет проверку. Endpoint,
model и API key нельзя переопределить произвольными `SECURECODE_LLM_*`
переменными. Продукт выбирает только заранее одобренные значения:

```powershell
$env:SECURECODE_PROVIDER_PROFILE = 'local-source-model@1.0.0'
$env:SECURECODE_POLICY_PROFILE = 'private-model-source'
$env:SECURECODE_EGRESS_PROFILE = 'private_model_zdr'
```

Эти selectors не создают approval record и не допускают provider сами по себе.
Installed product path дополнительно требует защищенную OS authority: HKLM на
Windows или root-owned files на Linux. Публичная команда автоматического
provisioning этой authority в репозитории отсутствует.

### Онлайн DeepSeek для benchmark

Проверенный онлайн-провайдер в эксперименте: DeepSeek V4.1 Flash (`deepseek-flash`), temperature `0`, JSON mode, reasoning отключен. Benchmark отправляет исходники только из публичного CVEfixes корпуса. Не подключайте этот маршрут к приватному репозиторию: он делает прямые классификационные запросы к API и не является полным SecureCode product pipeline.

В PowerShell задайте ключ только в текущем процессе. Не сохраняйте его в Git, README, notebook или отчет:

```powershell
$secureKey = Read-Host 'DeepSeek API key' -AsSecureString
$env:DEEPSEEK_API_KEY = [System.Net.NetworkCredential]::new('', $secureKey).Password
$env:DEEPSEEK_BASE_URL = 'https://api.deepseek.com'
$env:DEEPSEEK_MODEL = 'deepseek-flash'
```

Короткий запуск требует локальную CVEfixes SQLite v1.0.8 базу и явный spend guard. Укажите свой путь в `$database`; пример обрабатывает пять публичных кейсов:

```powershell
$database = 'C:\data\CVEfixes_v1.0.8.sqlite'
$candidate = (git rev-parse HEAD).Trim()
$profile = (Get-FileHash report/submission-benchmark/evidence/model-profile.json -Algorithm SHA256).Hash.ToLowerInvariant()
New-Item -ItemType Directory -Force output | Out-Null
try {
  uv run --locked --offline --no-sync --group quality python -m scripts.run_release_benchmark `
  --manifest report/submission-benchmark/evidence/cvefixes-manifest.json `
  --database $database --configuration model_native `
  --output output/deepseek-smoke.json --limit 5 --repetitions 1 `
  --allow-public-remote --spend-ledger output/deepseek-smoke-spend.sqlite `
  --budget-phase development --total-budget-microusd 10000000 `
  --candidate-sha $candidate --profile-sha256 $profile `
  --max-input-tokens 1000000 --max-output-tokens 64 `
  --input-microusd-per-million 150000 --output-microusd-per-million 600000
} finally {
  Remove-Item Env:DEEPSEEK_API_KEY -ErrorAction SilentlyContinue
  $secureKey.Dispose()
}
```

Для сохраненных результатов без новых API вызовов запустите агрегатор из [benchmark report](report/submission-benchmark/README.md). Подключение DeepSeek в product worker требует отдельно принятых provider/egress профилей, лимитов расходов и защищенного host approval. Одних переменных API недостаточно, а end-to-end benchmark продукта через DeepSeek пока не выполнен.

### CLI

```text
securecode doctor
securecode scan TARGET [--config FILE] [--format json|sarif|markdown|html] [--output FILE]
securecode scan TARGET --diagnostic [--format json|sarif|markdown|html] [--output FILE]
securecode fix TARGET [--format json|sarif|markdown|html|diff] [--output FILE]
securecode validate TARGET --patch SELECTOR [--format json|sarif|markdown|html|diff]
securecode approve TARGET --patch SELECTOR --artifact-sha256 SHA256 \
  --capability SHA256 --approval-id ID --approver-id ID [--output FILE]
securecode release --config FILE
securecode release --config FILE --publish --authorization FILE
```

Примеры:

```powershell
securecode scan C:\src\project --format sarif --output C:\reports\securecode.sarif
securecode fix C:\src\project --format json --output C:\reports\repair.json
securecode validate C:\src\project --patch <retained-selector> --format json
securecode release --config C:\release\candidate.json
```

`release` выполняет dry run по умолчанию. Публикация требует отдельно
защищенный config, authority key и короткоживущую authorization, привязанную к
точному candidate digest. Команда создает immutable локальный release store, а
не GitHub Release.

| Код | Значение |
| ---: | --- |
| `0` | операция завершена |
| `2` | policy fail |
| `3` | indeterminate |
| `4` | operational error |
| `5` | invalid usage or configuration |
| `6` | cancelled or superseded |

### Docker: server и worker

Сборка трех локальных образов из корня репозитория:

```powershell
pwsh -NoProfile -File deploy/docker/build-images.ps1
```

Скрипт создает `securecode-ai/runtime:1.0.0rc1`,
`securecode-ai/server:1.0.0rc1` и `securecode-ai/worker:1.0.0rc1`, затем печатает их
immutable image IDs. Linux `amd64` используется по умолчанию; `linux/arm64`
можно передать через `-Platform`.

Server запускается непривилегированным UID `65532`, пишет только в
`/var/lib/securecode` и `/tmp/securecode`, требует TLS при bind на `0.0.0.0` и
при первом запуске требует OIDC либо bootstrap identities:

```bash
docker network create securecode
docker volume create securecode-data
docker run --rm --name securecode-server --network securecode -p 8443:8080 \
  --mount type=volume,src=securecode-data,dst=/var/lib/securecode \
  --mount type=bind,src=/absolute/securecode-secrets,dst=/run/secrets,readonly \
  -e SECURECODE_BOOTSTRAP_TENANT_ID=tenant-1 \
  -e SECURECODE_BOOTSTRAP_ADMIN_TOKEN_FILE=/run/secrets/admin_token \
  -e SECURECODE_BOOTSTRAP_WORKER_TOKEN_FILE=/run/secrets/worker_token \
  -e SECURECODE_BOOTSTRAP_WORKER_REPOSITORIES=repository-1 \
  securecode-ai/server:1.0.0rc1
```

Каталог secrets должен содержать доступные UID `65532` файлы
`securecode_tls_cert`, `securecode_tls_key`, `admin_token` и `worker_token`.
Приватный TLS key должен быть обычным файлом без group/other permissions, а
сертификат должен быть доверенным worker-образом. Каждый token содержит не
менее 32 символов.

Worker подключается к control plane и исполняет общий Core в local checkout:

```bash
docker run --rm --name securecode-worker --network securecode \
  --mount type=bind,src=/absolute/source-checkout,dst=/workspace,readonly \
  --mount type=bind,src=/absolute/securecode-secrets,dst=/run/secrets,readonly \
  -e SECURECODE_CONTROL_PLANE_URL=https://securecode-server:8080 \
  -e SECURECODE_WORKER_TOKEN_FILE=/run/secrets/worker_token \
  -e SECURECODE_WORKER_ID=worker-1 \
  -e SECURECODE_WORKER_TARGET=/workspace \
  securecode-ai/worker:1.0.0rc1
```

Можно ограничить один запуск через `SECURECODE_WORKER_RUN_ID`. Для GitLab
worker получает `CI_PROJECT_ID`, `CI_MERGE_REQUEST_IID` и точный
`CI_COMMIT_SHA`. Разрешенные artifact hosts задаются через
`SECURECODE_WORKER_ARTIFACT_HOSTS`. Дополнительная Compose-конфигурация и
ограничения запуска описаны в [deploy/docker/README.md](deploy/docker/README.md).
Kubernetes manifests в текущем дереве отсутствуют.

### GitHub CI

Файл [`.github/workflows/ci.yml`](.github/workflows/ci.yml) уже содержит CI
самого проекта. Он запускается на pull request, merge queue и push в `master`:

1. проверяет CI/dependency policy и pinned Actions;
2. сканирует текущее дерево и candidate history на secrets;
3. аудирует hash-complete locked dependency graph;
4. выполняет specification/candidate gate;
5. запускает quality matrix на Python 3.12, 3.13 и 3.14;
6. объединяет обязательные результаты в `gate`.

Для fork включите GitHub Actions и настройте branch protection с required check
`gate`. Workflow использует только `contents: read`, не сохраняет checkout
credential и не объявляет repository secrets.

Для product GitHub App control plane ожидает:

- `SECURECODE_GITHUB_API_URL`;
- `SECURECODE_GITHUB_INSTALLATION_ID`;
- `SECURECODE_GITHUB_TOKEN_FILE`;
- `SECURECODE_GITHUB_WEBHOOK_SECRET_FILE`;
- `SECURECODE_SCM_PINS_FILE` и `SECURECODE_SCM_TENANT_ID`.

Webhook GitHub App направьте на
`POST /api/v1/integrations/github/webhook`. Для GitLab используйте
`POST /api/v1/integrations/gitlab/webhook` и задайте
`SECURECODE_GITLAB_API_URL`, `SECURECODE_GITLAB_TOKEN_FILE` и
`SECURECODE_GITLAB_WEBHOOK_SECRET_FILE`. В обоих случаях URL строится от
внешнего HTTPS-адреса control plane.

`SECURECODE_SCM_PINS_FILE` должен быть JSON-объектом ровно с семью ключами.
Каждый pin содержит `schema_version: "0.2.0"`, `component_id`, SemVer в `component_version` и фактический
64-символьный lowercase SHA-256 соответствующего принятого артефакта:
`schema_version` обозначает версию wire-контракта, а `component_version` версию
самого принятого компонента.

```json
{
  "stage_catalogue": {"schema_version": "0.2.0", "component_id": "stage-catalogue", "component_version": "1.0.0", "content_sha256": "1111111111111111111111111111111111111111111111111111111111111111"},
  "workflow": {"schema_version": "0.2.0", "component_id": "workflow", "component_version": "1.0.0", "content_sha256": "2222222222222222222222222222222222222222222222222222222222222222"},
  "policy": {"schema_version": "0.2.0", "component_id": "policy", "component_version": "1.0.0", "content_sha256": "3333333333333333333333333333333333333333333333333333333333333333"},
  "configuration": {"schema_version": "0.2.0", "component_id": "configuration", "component_version": "1.0.0", "content_sha256": "4444444444444444444444444444444444444444444444444444444444444444"},
  "provider_profile": {"schema_version": "0.2.0", "component_id": "provider-profile", "component_version": "1.0.0", "content_sha256": "5555555555555555555555555555555555555555555555555555555555555555"},
  "capability_profile": {"schema_version": "0.2.0", "component_id": "capability-profile", "component_version": "1.0.0", "content_sha256": "6666666666666666666666666666666666666666666666666666666666666666"},
  "egress_profile": {"schema_version": "0.2.0", "component_id": "egress-profile", "component_version": "1.0.0", "content_sha256": "7777777777777777777777777777777777777777777777777777777777777777"}
}
```

Числа в примере являются заглушками. Замените их хэшами реально принятых
bytes, сохраните файл вне checkout и смонтируйте read-only с правами `0600`.
Лишний или отсутствующий ключ, неверный SemVer либо digest блокирует запуск.

App требует только Metadata read, Pull requests read/write, Checks read/write,
Contents read и Code scanning alerts/Security events write, если используется
SARIF upload. Administration, Workflows write и merge permissions не нужны.

### GitLab CI

Корневой [`.gitlab-ci.yml`](.gitlab-ci.yml) не запускает untrusted audit в
source pipeline. Для merge request из того же проекта он инициирует защищенный
downstream project и передает только project ID, MR IID и exact commit SHA.

1. Создайте отдельный trusted audit project на защищенном runner.
2. Используйте [trusted audit pipeline](deploy/gitlab/trusted-audit.yml) как его
   CI config.
3. Замените `registry.example.invalid/...` на реальный registry path, сохранив
   проверенный image digest или повторно проведя review нового digest.
4. В source project задайте protected variables
   `SECURECODE_TRUSTED_AUDIT_PROJECT` и `SECURECODE_TRUSTED_AUDIT_REF`.
5. В trusted project задайте `SECURECODE_ALLOWED_SOURCE_PROJECT_ID`,
   `SECURECODE_CONTROL_PLANE_URL` и file-type variable
   `SECURECODE_WORKER_TOKEN_FILE`. При необходимости добавьте
   `SECURECODE_WORKER_ARTIFACT_HOSTS`.
6. В source project откройте **Settings > CI/CD > Job token permissions** и
   добавьте trusted audit project в authorized projects allowlist. Это дает его
   `CI_JOB_TOKEN` узкий доступ к API source project и MR-head ref, которые
   проверяет и получает `trusted-audit.yml`.
7. Защитите audit ref и предоставьте runner tag `securecode-ai-gpu`.

Pipeline отклоняет fork MR, неподходящий project ID, незащищенный ref и SHA,
который не совпадает с открытым MR head. Итоговый job не имеет доступа к
control-plane database или SCM write credentials.

### Модель безопасности

- Mandatory dual lane: ноль deterministic signals не пропускает model-native
  discovery.
- Любой mandatory timeout, refusal, invalid schema или недоступный provider
  дает `INDETERMINATE`, а не clean result.
- Анализ привязан к exact Git SHA; изменение HEAD отменяет публикацию.
- По умолчанию source остается в runner. Telemetry не имеет полей для raw
  source, prompts, model replies, patches, credentials и arbitrary labels.
- Private model endpoint допускается только на literal loopback после
  профильно-политической и host-authority проверки.
- Model output считается untrusted data и проходит closed-schema validation.
- Patch сначала сохраняется как отдельный digest-bound artifact, затем
  проверяется в изоляции и требует отдельного approval.
- Worker не получает control-plane database и SCM write credentials.
- Secrets не должны попадать в repository, отчеты, notebook или durable
  project memory. `.env`, keys, runtime state и local outputs исключены Git.

Полные правила: [data classification](specs/security/data-classification.md),
[prompt injection](docs/security/PROMPT_INJECTION.md) и
[threat model](docs/security/THREAT_MODEL.md).

### Статус и ограничения

- Демо Аудитор → Архитектор на фикстуре CWE-89 завершается `COMPLETED` на
  локальной Qwen 2.5 Coder 7B Q4_K_M (Ollama 0.34.4) и на DeepSeek Flash:
  находка совпадает с детерминированным сканером, patch проходит парсинг, повторный
  скан и `git apply --check`. Квитанции:
  [Qwen](report/submission-benchmark/evidence/current-real-local-p917.json),
  [DeepSeek](report/submission-benchmark/evidence/current-deepseek-p917.json).
  Демонстрация охватывает одно правило; поведенческие тесты патча не запускаются.
- Бенчмарк на 600 кейсах CVEfixes: детерминированный lane завершил 508 кейсов
  (92 непарсящихся файла учтены как незавершённые), hybrid получил 32.8% recall на
  held-out против 32.5% у Semgrep; интервал включает ноль, то есть hybrid на уровне
  SAST, но не лучше. Модельные lanes — прямые запросы к DeepSeek, а не полный
  конвейер с Аудитором и Скептиком; repair на корпусе не оценивался. Precision всех
  конфигураций около 50%. Подробности:
  [отчёт бенчмарка](report/submission-benchmark/README.md).
- Полный `securecode scan` требует заранее подготовленной защищённой OS authority;
  общий сценарий её подготовки не опубликован, поэтому для проверки предназначены
  демо и notebook.
- Docker-образы server/worker и Compose есть; `quickstart.py --up` на Linux не
  перепроверялся, проверенного production deployment нет. Путь образа trusted worker
  для GitLab — явный placeholder.
- Скринкаст снят до исправлений 29 сентября и показывает прежние результаты.
- Production readiness не заявляется; quality receipts подтверждают
  воспроизводимость, а не отсутствие уязвимостей.

### Структура репозитория

| Путь | Содержимое |
| --- | --- |
| `apps/cli/` | команда `securecode` |
| `apps/server/` | ASGI control plane и maintenance CLI |
| `apps/worker/` | one-shot и connected Linux worker |
| `packages/contracts/` | versioned domain, event, model и runtime contracts |
| `packages/core/` | framework-independent workflow, evidence, policy, repair и evaluation logic |
| `packages/adapters/` | Git, CST, provider, sandbox, report и SCM adapters |
| `integrations/` | границы GitHub/GitLab transport integration |
| `deploy/` | Dockerfiles и GitLab trusted audit pipeline |
| `specs/` | принятые нормативные спецификации и schemas |
| `tests/` | unit, contract, integration, negative и security regression tests |
| `demo/` | публичная offline demo и real-local Ollama demo |
| `evaluation/` | development corpus, run plan и machine-readable results |
| `notebooks/` | воспроизводимые учебные notebooks |
| `report/` | academic bundle и development benchmark |
| `artifacts/gates/` | сохраненные gate evidence packets |
| `docs/` | архитектура, продукт, решения, план, research и security docs |

### Разработка и проверки

```powershell
uv run --locked --offline --no-sync --group quality python -I scripts/quality.py
uv run --locked --offline --no-sync --group quality ruff format --check .
uv run --locked --offline --no-sync --group quality ruff check .
uv run --locked --offline --no-sync --group quality mypy
uv run --locked --offline --no-sync --group quality pytest tests/unit -q
uv run --locked --offline --no-sync --group quality python -I scripts/spec_gate.py snapshot
```

Hooks:

```powershell
uv run --locked --offline --no-sync --group quality pre-commit install --hook-type pre-commit --hook-type pre-push
uv run --locked --offline --no-sync --group quality pre-commit run --all-files
```

### Академическая воспроизводимость

- [M-A2026 Markdown report](report/m-a2026/report.md)
- [M-A2026 self-contained HTML](report/m-a2026/report.html)
- [M-A2026 PDF](report/m-a2026/report.pdf)
- [Delivery manifest](report/m-a2026/delivery-manifest.json)
- [Quality receipt](report/m-a2026/quality-receipt.json)
- [Clean replay](report/m-a2026/clean-replay.md)
- [Executed notebook](notebooks/m_a2026_submission.ipynb)
- [Offline CWE-89 demo](demo/mvp_cwe89_demo.py)
- [Development corpus](evaluation/development/README.md) и
  [manifest](evaluation/development/corpus-manifest.yaml)
- [Raw run records](evaluation/development/results/run-records.jsonl),
  [aggregate](evaluation/development/results/aggregate.json) и
  [independent recomputation](evaluation/development/results/recomputed.json)
- [Benchmark protocol and results](report/development-benchmark/README.md) и
  [limitations](report/development-benchmark/limitations.md)
- [Expanded 600-case submission benchmark](report/submission-benchmark/README.md),
  [HTML report](report/submission-benchmark/report.html),
  [machine-readable metrics](report/submission-benchmark/aggregate.json),
  [stratified table](report/submission-benchmark/stratified-metrics.csv) и
  [PDF report](site/benchmark.pdf)
- [Итоговый HTML-отчёт с текущим local-model прогоном](report/final-submission.html)
- [Обезличенная квитанция Qwen](report/submission-benchmark/evidence/current-real-local-p917.json)
- [Сценарий 3-минутного скринкаста](docs/SUBMISSION_VIDEO_SCRIPT.md)

Основной внешний набор benchmark: [CVEfixes v1.0.8 на Zenodo](https://zenodo.org/records/13118970).
В репозитории лежат source-free manifest и скрипт его построения, но нет
SQLite-базы или исходников уязвимых проектов. Manifest помечает лицензию как
NOASSERTION; перед повторным распространением материалов нужно отдельно
проверить условия набора и лицензии исходных репозиториев.

Архивный M-A2026 bundle привязан к точному `subject_sha256` из
`quality-receipt.json`. Он сохраняется как академическое evidence и намеренно
не переиздается для каждого последующего изменения продукта. Указанный там
commit является базовым якорем, а не полным снимком subject. Поэтому полный
replay требует отдельно сохраненных точных байтов subject; такого Git ref в
этом репозитории нет. На текущем release-candidate checkout валидатор обязан
отклонить архивный bundle после изменения subject. Новый bundle публикуется
только вместе с новой quality receipt, привязанной к точным байтам кандидата.

Notebook повторяет публичную synthetic demo и читает сохраненные aggregate и
redacted local receipt. Его обычное выполнение не делает model call.

### Лицензия

В текущем дереве нет корневого `LICENSE`, а package metadata содержит
`Private :: Do Not Upload`. Публичная лицензия на использование, изменение или
распространение кода сейчас не предоставлена. Перед публичной публикацией владелец должен
добавить выбранный license и проверить лицензии внешних datasets, моделей и
зависимостей. Учебный corpus в `evaluation/development/` отдельно обозначен как
`CC0-1.0`.

---

## English

SecureCode AI is a local-first prototype for security auditing and controlled
repair proposals across Python, JavaScript, TypeScript, and Go. Its current
Qwen run found one CWE-89 candidate but did not produce a patch. The expanded
benchmark does not establish superiority over Semgrep. M-A2026 remains
`NOT_READY`; this is not a v1.0 or production-readiness claim.

### Overview

SecureCode AI audits an exact Git revision, combines deterministic discovery
with independent local-model investigation, normalizes candidates into one
evidence graph, and publishes a result only after mandatory interpretation and
validation. Repairs are retained as separate artifacts, validated in an
ephemeral environment, and never applied to the source checkout without an
explicit approval.

The main product surfaces are:

- a standalone CLI for local audits, repair proposals, and validation;
- a Linux worker for exact-run CI execution;
- an ASGI control plane with a queue, run state, approvals, and an audit trail;
- GitHub and GitLab adapters for exact-SHA status and bounded publication;
- reproducible academic experiments, notebooks, and reports.

### Architecture

```text
Git checkout at an exact commit
             |
             v
  deterministic discovery  +  model-native discovery
             \                    /
              v                  v
           normalized candidates
                     |
                     v
          Auditor and Skeptic checks
                     |
                     v
      EvidenceGraph + policy decision + reports
                     |
          +----------+-----------+
          |                      |
          v                      v
   local CLI / worker      control plane / SCM
```

The two graphs have separate responsibilities:

- `WorkflowGraph` controls transitions, budgets, retries, approvals, and stop
  conditions;
- `EvidenceGraph` links findings, source locations, tool/model observations,
  patches, validation, and provenance.

Domain behavior lives in `packages/core/` and does not depend on a transport or
graph runtime. `packages/contracts/` owns closed Pydantic contracts and JSON
Schema. `packages/adapters/` implements Git, CST, model, sandbox, and SCM
boundaries. The CLI, server, and worker compose these shared layers.

Read the [architecture](docs/ARCHITECTURE.md),
[product model](docs/PRODUCT.md), and
[threat model](docs/security/THREAT_MODEL.md) for the detailed design.

### Supported languages and CWEs

| Area | Current implementation | Boundary |
| --- | --- | --- |
| Python | `.py`, `.pyi`; CST/AST, symbol index, CWE-89, and portfolio rules | Coverage is limited to supported source/sink patterns |
| JavaScript | `.js`, `.mjs`, `.cjs`, `.jsx`; CST, symbol index, CWE-89 | Bounded set of reviewed patterns |
| TypeScript | `.ts`, `.tsx`; CST, symbol index, CWE-89 | Type information does not make this a full compiler pass |
| Go | `.go`; CST, symbol index, CWE-89, and part of the portfolio rules | Bounded set of reviewed patterns |

The closed classification portfolio contains `CWE-89` SQL Injection, `CWE-78`
OS Command Injection, `CWE-22` Path Traversal, `CWE-862` Missing Authorization,
and `CWE-918` Server-Side Request Forgery.

This is an inventory of implemented rules. It is not a complete-CWE coverage
claim or a claim of superiority over SAST. The current 600-case comparison is
in the [submission benchmark](report/submission-benchmark/README.md). The earlier
development benchmark and its limits remain available separately:
[protocol and results](report/development-benchmark/README.md),
[limitations](report/development-benchmark/limitations.md).

### Candidate verification

`uv run --locked python -I scripts/quality.py` runs Ruff format and lint, mypy for
Linux and Windows, and pytest (unit tests plus the demo integration tests) with an 80%
core coverage floor. On the current `main` it reports `QUALITY=PASS` with 3292 tests;
CI repeats these checks on Python 3.12, 3.13 and 3.14 and also scans secrets and
dependencies.

### Requirements and installation

- Git;
- CPython `>=3.12,<3.15`;
- [uv](https://docs.astral.sh/uv/) exactly `0.12.0`;
- Docker for server/worker images, isolated repair validation, and the opt-in
  corpus oracle;
- Ollama only for the local model path.

From a clean clone:

```powershell
git clone <repository-url> securecode-ai
Set-Location securecode-ai
uv --version
uv sync --locked --no-dev --no-editable
uv run --locked --offline --no-sync securecode --version
```

`uv.lock` is the single resolved Python dependency authority. `--locked`
rejects lock drift, and `--no-editable` verifies the installed path instead of
importing directly from the source tree. Install the quality group for
development:

```powershell
uv sync --locked --no-editable --group quality
```

### Model-free quickstart

The reproducible public demo does not read private code, call an LLM, or change
the source checkout:

```powershell
$output = Join-Path $PWD '.securecode/demo-cwe89'
New-Item -ItemType Directory -Path $output | Out-Null
uv run --locked --offline --no-sync python -I demo/mvp_cwe89_demo.py --output $output
```

The bounded expected result is one CWE-89 signal for the vulnerable Python
fixture, zero signals for the safe control, a proposed reference repair, and
validation in an ephemeral copy.

Basic installed CLI diagnostics:

```powershell
uv run --locked --offline --no-sync securecode doctor
uv run --locked --offline --no-sync securecode scan . --diagnostic --format json
```

A full `securecode scan` requires a protected host approval record and exact
matches for the approved profile, policy, provider evidence, and Git executable.
Missing or changed authority fails closed.

### Local Ollama configuration

The recorded academic path uses literal loopback and these exact values:

| Setting | Value |
| --- | --- |
| Endpoint | `http://127.0.0.1:11434/v1` |
| Ollama | `0.34.4` |
| Model | `qwen2.5-coder:7b-instruct-q4_K_M` |
| Quantization | `Q4_K_M` |
| Expected model digest | `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364` |

To repeat the current real-local demonstration, start Ollama locally and pull
the model. The command does not contact a cloud provider:

```bash
uv run --locked python -I demo/p917_real_local_demo.py --repository demo/fixtures/real-local-cwe89 --output output/demo-report
```

The report is `output/demo-report/security-report.md` (and `.html`); the fixture is
read from an immutable snapshot and never modified.

The retained redacted receipt is
[`current-real-local-p917.json`](report/submission-benchmark/evidence/current-real-local-p917.json).
In the 29 September 2026 run Qwen found the CWE-89 candidate the deterministic
scanner also reported and proposed a parameterized query; the patch parsed, the
rescan found 0 signals, `outcome=COMPLETED`, and the source checkout was unchanged.

The same scenario runs on DeepSeek (profile `deepseek-owner-authorized`, owner
consent recorded in [`deploy/deepseek/owner-consent.json`](deploy/deepseek/owner-consent.json)).
The key comes from `DEEPSEEK_API_KEY` or a `DEEPSEEK_API_KEY=...` line in the
repository-root `.env` (ignored by Git); spend is capped at $0.10 per run.

```bash
uv run --locked python -I demo/p917_real_local_demo.py --repository demo/fixtures/real-local-cwe89 --output output/demo-report --provider deepseek
```

Receipt: [`current-deepseek-p917.json`](report/submission-benchmark/evidence/current-deepseek-p917.json)
(`outcome=COMPLETED`, 2 calls, $0.00014). DeepSeek retention and training terms
are not verified; send only code you are entitled to disclose.

Example local preparation:

```powershell
$env:OLLAMA_HOST = '127.0.0.1:11434'
ollama serve
```

In another terminal:

```powershell
ollama pull qwen2.5-coder:7b-instruct-q4_K_M
ollama list
uv run --locked --offline --no-sync python -I demo/p917_real_local_demo.py --help
```

Before source dispatch, the gateway checks bounded `/api/version` and
`/api/tags` responses, exact model name and digest, and repeats the identity
check after generation. Arbitrary `SECURECODE_LLM_*` overrides for endpoint,
model, or API key are intentionally unavailable. The product accepts selectors
for already approved values only:

```powershell
$env:SECURECODE_PROVIDER_PROFILE = 'local-source-model@1.0.0'
$env:SECURECODE_POLICY_PROFILE = 'private-model-source'
$env:SECURECODE_EGRESS_PROFILE = 'private_model_zdr'
```

Selectors do not create or admit an approval record. The installed product path
also needs OS-protected authority in HKLM on Windows or root-owned files on
Linux. This repository does not provide a general end-user provisioning command
for that authority.

### Online DeepSeek for the benchmark

The tested online provider was DeepSeek V4.1 Flash (`deepseek-flash`), with temperature `0`, JSON mode, and reasoning disabled. The benchmark sends source only from the public CVEfixes corpus. Do not use this route for private repositories: it makes direct classification API calls and is not the complete SecureCode product pipeline.

Set the key only in the current PowerShell process. Never save it in Git, README, notebooks, or reports:

```powershell
$secureKey = Read-Host 'DeepSeek API key' -AsSecureString
$env:DEEPSEEK_API_KEY = [System.Net.NetworkCredential]::new('', $secureKey).Password
$env:DEEPSEEK_BASE_URL = 'https://api.deepseek.com'
$env:DEEPSEEK_MODEL = 'deepseek-flash'
```

A short run needs the local CVEfixes SQLite v1.0.8 database and an explicit spend guard. Replace `$database` with its actual path; this example processes only five public cases:

```powershell
$database = 'C:\data\CVEfixes_v1.0.8.sqlite'
$candidate = (git rev-parse HEAD).Trim()
$profile = (Get-FileHash report/submission-benchmark/evidence/model-profile.json -Algorithm SHA256).Hash.ToLowerInvariant()
New-Item -ItemType Directory -Force output | Out-Null
try {
  uv run --locked --offline --no-sync --group quality python -m scripts.run_release_benchmark `
  --manifest report/submission-benchmark/evidence/cvefixes-manifest.json `
  --database $database --configuration model_native `
  --output output/deepseek-smoke.json --limit 5 --repetitions 1 `
  --allow-public-remote --spend-ledger output/deepseek-smoke-spend.sqlite `
  --budget-phase development --total-budget-microusd 10000000 `
  --candidate-sha $candidate --profile-sha256 $profile `
  --max-input-tokens 1000000 --max-output-tokens 64 `
  --input-microusd-per-million 150000 --output-microusd-per-million 600000
} finally {
  Remove-Item Env:DEEPSEEK_API_KEY -ErrorAction SilentlyContinue
  $secureKey.Dispose()
}
```

To recompute retained results without new API calls, use the [benchmark report](report/submission-benchmark/README.md). DeepSeek in the product worker additionally requires approved provider/egress profiles, spend limits, and protected host approval. API environment variables alone are insufficient, and an end-to-end product benchmark through DeepSeek has not been completed.

### CLI commands

```text
securecode doctor
securecode scan TARGET [--config FILE] [--format json|sarif|markdown|html] [--output FILE]
securecode scan TARGET --diagnostic [--format json|sarif|markdown|html] [--output FILE]
securecode fix TARGET [--format json|sarif|markdown|html|diff] [--output FILE]
securecode validate TARGET --patch SELECTOR [--format json|sarif|markdown|html|diff]
securecode approve TARGET --patch SELECTOR --artifact-sha256 SHA256 \
  --capability SHA256 --approval-id ID --approver-id ID [--output FILE]
securecode release --config FILE
securecode release --config FILE --publish --authorization FILE
```

Examples:

```powershell
securecode scan C:\src\project --format sarif --output C:\reports\securecode.sarif
securecode fix C:\src\project --format json --output C:\reports\repair.json
securecode validate C:\src\project --patch <retained-selector> --format json
securecode release --config C:\release\candidate.json
```

`release` is a dry run by default. Publication requires a separately protected
config, authority key, and short-lived authorization bound to the exact
candidate digest. It writes an immutable local release store, not a GitHub
Release.

| Code | Meaning |
| ---: | --- |
| `0` | completed |
| `2` | policy fail |
| `3` | indeterminate |
| `4` | operational error |
| `5` | invalid usage or configuration |
| `6` | cancelled or superseded |

### Docker server and worker

Build the three local images from the repository root:

```powershell
pwsh -NoProfile -File deploy/docker/build-images.ps1
```

The script creates `securecode-ai/runtime:1.0.0rc1`,
`securecode-ai/server:1.0.0rc1`, and `securecode-ai/worker:1.0.0rc1`, then prints their
immutable image IDs. Linux `amd64` is the default; pass `-Platform linux/arm64`
for ARM64.

The server runs as unprivileged UID `65532`, writes only to
`/var/lib/securecode` and `/tmp/securecode`, requires TLS when bound to
`0.0.0.0`, and needs either OIDC or bootstrap identities on first start:

```bash
docker network create securecode
docker volume create securecode-data
docker run --rm --name securecode-server --network securecode -p 8443:8080 \
  --mount type=volume,src=securecode-data,dst=/var/lib/securecode \
  --mount type=bind,src=/absolute/securecode-secrets,dst=/run/secrets,readonly \
  -e SECURECODE_BOOTSTRAP_TENANT_ID=tenant-1 \
  -e SECURECODE_BOOTSTRAP_ADMIN_TOKEN_FILE=/run/secrets/admin_token \
  -e SECURECODE_BOOTSTRAP_WORKER_TOKEN_FILE=/run/secrets/worker_token \
  -e SECURECODE_BOOTSTRAP_WORKER_REPOSITORIES=repository-1 \
  securecode-ai/server:1.0.0rc1
```

The secrets directory must provide UID `65532` with readable
`securecode_tls_cert`, `securecode_tls_key`, `admin_token`, and `worker_token`
files. The private TLS key must be a regular file without group/other
permissions, the certificate must be trusted by the worker image, and each
token must contain at least 32 characters. Use OIDC and an external secret
manager for production according to the
[threat model](docs/security/THREAT_MODEL.md).

The worker connects to the control plane, claims an exact-run job, executes the
shared Core in the local checkout, and publishes bounded artifacts and metadata:

```bash
docker run --rm --name securecode-worker --network securecode \
  --mount type=bind,src=/absolute/source-checkout,dst=/workspace,readonly \
  --mount type=bind,src=/absolute/securecode-secrets,dst=/run/secrets,readonly \
  -e SECURECODE_CONTROL_PLANE_URL=https://securecode-server:8080 \
  -e SECURECODE_WORKER_TOKEN_FILE=/run/secrets/worker_token \
  -e SECURECODE_WORKER_ID=worker-1 \
  -e SECURECODE_WORKER_TARGET=/workspace \
  securecode-ai/worker:1.0.0rc1
```

Set `SECURECODE_WORKER_RUN_ID` for one specific run. GitLab supplies
`CI_PROJECT_ID`, `CI_MERGE_REQUEST_IID`, and the exact `CI_COMMIT_SHA` instead.
Use `SECURECODE_WORKER_ARTIFACT_HOSTS` to narrow artifact destinations. The
Compose deployment and its required configuration are documented in
[`deploy/docker/README.md`](deploy/docker/README.md). Kubernetes manifests are
not included.

### GitHub CI setup

The included [`.github/workflows/ci.yml`](.github/workflows/ci.yml) is the
project's own CI. It runs for pull requests, merge queues, and pushes to
`master`:

1. validate CI/dependency policy and pinned Actions;
2. scan the current tree and candidate history for secrets;
3. audit the hash-complete locked dependency graph;
4. execute the specification/candidate gate;
5. run the quality matrix on Python 3.12, 3.13, and 3.14;
6. aggregate mandatory jobs into `gate`.

For a fork, enable GitHub Actions and configure branch protection to require
`gate`. The workflow has only `contents: read`, does not persist checkout
credentials, and declares no repository secrets.

For the product GitHub App, configure the control plane with:

- `SECURECODE_GITHUB_API_URL`;
- `SECURECODE_GITHUB_INSTALLATION_ID`;
- `SECURECODE_GITHUB_TOKEN_FILE`;
- `SECURECODE_GITHUB_WEBHOOK_SECRET_FILE`;
- `SECURECODE_SCM_PINS_FILE` and `SECURECODE_SCM_TENANT_ID`.

Point the GitHub App webhook to
`POST /api/v1/integrations/github/webhook`. For GitLab, use
`POST /api/v1/integrations/gitlab/webhook` and set
`SECURECODE_GITLAB_API_URL`, `SECURECODE_GITLAB_TOKEN_FILE`, and
`SECURECODE_GITLAB_WEBHOOK_SECRET_FILE`. Build both URLs from the external
HTTPS address of the control plane.

`SECURECODE_SCM_PINS_FILE` must contain a JSON object with exactly seven keys.
Every pin has `schema_version: "0.2.0"`, a `component_id`, a SemVer `component_version`, and the actual
64-character lowercase SHA-256 of the accepted artifact:
`schema_version` identifies the wire contract, while `component_version`
identifies the accepted component itself.

```json
{
  "stage_catalogue": {"schema_version": "0.2.0", "component_id": "stage-catalogue", "component_version": "1.0.0", "content_sha256": "1111111111111111111111111111111111111111111111111111111111111111"},
  "workflow": {"schema_version": "0.2.0", "component_id": "workflow", "component_version": "1.0.0", "content_sha256": "2222222222222222222222222222222222222222222222222222222222222222"},
  "policy": {"schema_version": "0.2.0", "component_id": "policy", "component_version": "1.0.0", "content_sha256": "3333333333333333333333333333333333333333333333333333333333333333"},
  "configuration": {"schema_version": "0.2.0", "component_id": "configuration", "component_version": "1.0.0", "content_sha256": "4444444444444444444444444444444444444444444444444444444444444444"},
  "provider_profile": {"schema_version": "0.2.0", "component_id": "provider-profile", "component_version": "1.0.0", "content_sha256": "5555555555555555555555555555555555555555555555555555555555555555"},
  "capability_profile": {"schema_version": "0.2.0", "component_id": "capability-profile", "component_version": "1.0.0", "content_sha256": "6666666666666666666666666666666666666666666666666666666666666666"},
  "egress_profile": {"schema_version": "0.2.0", "component_id": "egress-profile", "component_version": "1.0.0", "content_sha256": "7777777777777777777777777777777777777777777777777777777777777777"}
}
```

The repeated digits are placeholders. Replace them with hashes of the accepted
bytes, keep the file outside the checkout, and mount it read-only with mode
`0600`. An extra or missing key, invalid SemVer, or invalid digest blocks
startup.

The App needs Metadata read, Pull requests read/write, Checks read/write,
Contents read, and Code scanning alerts/Security events write only when SARIF
upload is enabled. It does not need Administration, Workflows write, or merge
permissions. Keep installation tokens, webhook secrets, and provider
credentials in separate scopes and lifecycles.

### GitLab CI setup

The root [`.gitlab-ci.yml`](.gitlab-ci.yml) does not execute an untrusted audit
inside the source pipeline. For a same-project merge request, it triggers a
protected downstream project and forwards only project ID, MR IID, and exact
commit SHA.

1. Create a separate trusted audit project on a protected runner.
2. Use [the trusted audit pipeline](deploy/gitlab/trusted-audit.yml) as its CI
   configuration.
3. Replace `registry.example.invalid/...` with the real registry path while
   preserving the reviewed image digest, or review a new digest.
4. In the source project, define protected variables
   `SECURECODE_TRUSTED_AUDIT_PROJECT` and `SECURECODE_TRUSTED_AUDIT_REF`.
5. In the trusted project, define `SECURECODE_ALLOWED_SOURCE_PROJECT_ID`,
   `SECURECODE_CONTROL_PLANE_URL`, and a file-type
   `SECURECODE_WORKER_TOKEN_FILE`. Add `SECURECODE_WORKER_ARTIFACT_HOSTS` when
   needed.
6. In the source project, open **Settings > CI/CD > Job token permissions** and
   add the trusted audit project to the authorized projects allowlist. This
   gives its `CI_JOB_TOKEN` narrow access to the source-project API and MR-head
   ref used by `trusted-audit.yml`.
7. Protect the audit ref and provide a runner with tag `securecode-ai-gpu`.

The pipeline rejects fork MRs, an unexpected project ID, an unprotected ref,
and a SHA that differs from the open MR head. The worker job receives neither
control-plane database access nor SCM write credentials.

### Security model

- The dual lane is mandatory: zero deterministic signals never skips
  model-native discovery.
- A mandatory timeout, refusal, invalid schema, or unavailable provider becomes
  `INDETERMINATE`, never a clean result.
- Analysis is bound to an exact Git SHA; a changed HEAD revokes publication.
- Source stays in the runner by default. Telemetry has no fields for raw source,
  prompts, model replies, patches, credentials, or arbitrary labels.
- A private model endpoint is admitted only on literal loopback after profile,
  policy, and protected host-authority checks.
- Model output is untrusted data and passes closed-schema validation.
- A patch is retained as a digest-bound artifact, validated in isolation, and
  requires a separate approval before any later action.
- Workers do not receive control-plane database or SCM write credentials.
- Secrets must not enter the repository, reports, notebooks, or durable project
  memory. Git ignores `.env`, keys, runtime state, and local outputs.

Read [data classification](specs/security/data-classification.md),
[prompt injection guidance](docs/security/PROMPT_INJECTION.md), and the
[threat model](docs/security/THREAT_MODEL.md).

### Status and limitations

- The Auditor → Architect demo on the CWE-89 fixture completes with `COMPLETED` on
  local Qwen 2.5 Coder 7B Q4_K_M (Ollama 0.34.4) and on DeepSeek Flash: the finding
  matches the deterministic scanner, and the patch passes parsing, a rescan and
  `git apply --check`. Receipts:
  [Qwen](report/submission-benchmark/evidence/current-real-local-p917.json),
  [DeepSeek](report/submission-benchmark/evidence/current-deepseek-p917.json).
  The demo covers one rule; no behavioral tests are run on the patch.
- 600-case CVEfixes benchmark: the deterministic lane completed 508 cases (92
  unparseable files count as incomplete), and the hybrid reached 32.8% held-out recall
  versus 32.5% for Semgrep; the interval includes zero, so the hybrid is on par with
  SAST but not better. The model lanes are direct DeepSeek classifications, not the full
  Auditor/Skeptic pipeline, and repair was not evaluated on the corpus. Precision is
  near 50% for every configuration. Details:
  [benchmark report](report/submission-benchmark/README.md).
- A full `securecode scan` needs pre-provisioned OS-protected authority; a general
  provisioning workflow is not published, so reviewers should use the demo and the
  notebook.
- Server/worker Docker images and Compose exist; `quickstart.py --up` was not
  re-verified on Linux and there is no verified production deployment. The GitLab
  trusted worker image path is an explicit placeholder.
- The screencast predates the 29 September fixes and shows the earlier results.
- Production readiness is not claimed; quality receipts establish reproducibility,
  not the absence of vulnerabilities.

See [current context](docs/CONTEXT.md) and the [canonical plan](docs/PLAN.md)
for current task and gate status.

### Repository layout

| Path | Purpose |
| --- | --- |
| `apps/cli/` | `securecode` command |
| `apps/server/` | ASGI control plane and maintenance CLI |
| `apps/worker/` | one-shot and connected Linux worker |
| `packages/contracts/` | versioned domain, event, model, and runtime contracts |
| `packages/core/` | framework-independent workflow, evidence, policy, repair, and evaluation logic |
| `packages/adapters/` | Git, CST, provider, sandbox, report, and SCM adapters |
| `integrations/` | GitHub/GitLab transport integration boundaries |
| `deploy/` | Dockerfiles and GitLab trusted audit pipeline |
| `specs/` | accepted normative specifications and schemas |
| `tests/` | unit, contract, integration, negative, and security regression tests |
| `demo/` | public offline demo and real-local Ollama demo |
| `evaluation/` | development corpus, run plan, and machine-readable results |
| `notebooks/` | reproducible academic notebooks |
| `report/` | academic bundle and development benchmark |
| `artifacts/gates/` | retained gate evidence packets |
| `docs/` | architecture, product, decisions, plan, research, and security docs |

### Development commands

```powershell
uv run --locked --offline --no-sync --group quality python -I scripts/quality.py
uv run --locked --offline --no-sync --group quality ruff format --check .
uv run --locked --offline --no-sync --group quality ruff check .
uv run --locked --offline --no-sync --group quality mypy
uv run --locked --offline --no-sync --group quality pytest tests/unit -q
uv run --locked --offline --no-sync --group quality python -I scripts/spec_gate.py snapshot
```

Hooks:

```powershell
uv run --locked --offline --no-sync --group quality pre-commit install --hook-type pre-commit --hook-type pre-push
uv run --locked --offline --no-sync --group quality pre-commit run --all-files
```

### Academic reproducibility

- [M-A2026 Markdown report](report/m-a2026/report.md)
- [M-A2026 self-contained HTML](report/m-a2026/report.html)
- [M-A2026 PDF](report/m-a2026/report.pdf)
- [Delivery manifest](report/m-a2026/delivery-manifest.json)
- [Quality receipt](report/m-a2026/quality-receipt.json)
- [Clean replay](report/m-a2026/clean-replay.md)
- [Executed notebook](notebooks/m_a2026_submission.ipynb)
- [Offline CWE-89 demo](demo/mvp_cwe89_demo.py)
- [Development corpus](evaluation/development/README.md) and its
  [manifest](evaluation/development/corpus-manifest.yaml)
- [Raw run records](evaluation/development/results/run-records.jsonl),
  [aggregate](evaluation/development/results/aggregate.json), and
  [independent recomputation](evaluation/development/results/recomputed.json)
- [Benchmark protocol and results](report/development-benchmark/README.md) and
  [limitations](report/development-benchmark/limitations.md)
- [Expanded 600-case submission benchmark](report/submission-benchmark/README.md),
  [HTML report](report/submission-benchmark/report.html),
  [machine-readable metrics](report/submission-benchmark/aggregate.json),
  [stratified table](report/submission-benchmark/stratified-metrics.csv), and
  [PDF report](site/benchmark.pdf)
- [Final HTML project report with the current local-model run](report/final-submission.html)
- [Redacted Qwen receipt](report/submission-benchmark/evidence/current-real-local-p917.json)
- [Three-minute screencast script](docs/SUBMISSION_VIDEO_SCRIPT.md)

The primary external benchmark dataset is [CVEfixes v1.0.8 on Zenodo](https://zenodo.org/records/13118970).
This repository contains the source-free manifest and its builder, not the
SQLite database or vulnerable project source. The manifest records the license
as NOASSERTION; check the dataset terms and individual source repository
licenses before redistributing those materials.

The archived M-A2026 bundle is bound to the exact `subject_sha256` recorded in
`quality-receipt.json`. It is retained as academic evidence and is intentionally
not reissued for every later product change. The recorded commit is a base
anchor, not a complete snapshot of the subject. Full replay therefore requires
the separately preserved exact subject bytes; this repository does not contain
a Git ref for them. On the current release-candidate checkout the validator must
reject the archived bundle after the subject changes. A new bundle is published
only with a new quality receipt bound to the candidate's exact bytes.

The notebook replays the public synthetic demo and reads the retained aggregate
and redacted local receipt. Its normal replay makes no model call.

The current full test run and canonical quality check can fail. See the
[final HTML report](report/final-submission.html) for the exact observed status;
the existence of test files is not evidence that this checkout passes them.

The current full test run and canonical quality check can fail. See the
[final HTML report](report/final-submission.html) for the exact observed status;
the existence of test files is not evidence that this checkout passes them.

### License

The current tree has no root `LICENSE`, and package metadata says
`Private :: Do Not Upload`. No public license to use, modify, or redistribute
this code is therefore granted at this time. Before public publication, the
repository owner must add the chosen license and review licenses for external
datasets, models, and dependencies. The self-authored educational corpus in
`evaluation/development/` is separately identified as `CC0-1.0`.
