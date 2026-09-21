# SecureCode AI

[Русский](#русский) | [English](#english)

SecureCode AI is a local-first security audit and controlled repair platform for
Python, JavaScript, TypeScript, and Go repositories. It combines deterministic
analysis with bounded model-native investigation, records evidence for every
decision, and fails closed when a mandatory stage cannot complete.

> **Release status:** the Python packages are versioned `1.0.0rc1`, but this
> repository is still a v1.0 release candidate. The academic M-A2026 bundle is
> recorded as `NOT_READY`; G9, public release, and production readiness are not
> claimed. See [Статус и ограничения](#статус-и-ограничения) or
> [Status and limitations](#status-and-limitations).

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
утверждение о превосходстве над SAST. Текущие численные результаты приведены
только в [development benchmark](report/development-benchmark/README.md) вместе
с [ограничениями](report/development-benchmark/limitations.md).

### Проверка кандидата

Текущий staged-кандидат проверен командой
`uv run --locked --offline --no-sync --group quality python -I scripts/quality.py`:
`2554 passed`, `32 skipped`, branch coverage Core `80.10%`, `QUALITY=PASS`.
Отдельный opt-in прогон `tests/unit/test_development_corpus.py` с
`SECURECODE_RUN_DOCKER_ORACLE=1` завершился как `22 passed`, поэтому все пять
Docker oracle сценариев исполнены. Остальные skips платформенные: Linux worker
и POSIX file-race/FIFO проверки не исполняются на Windows.

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
| Ollama | `0.16.2` |
| Model | `qwen2.5-coder:7b-instruct-q4_K_M` |
| Quantization | `Q4_K_M` |
| Expected model digest | `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364` |

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
`SECURECODE_WORKER_ARTIFACT_HOSTS`. Docker Compose и Kubernetes manifests в
текущем дереве отсутствуют.

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

- M-A2026 bundle имеет статус `NOT_READY`. Не подтверждены все внешние
  instructor details, durable final reviews и protected delivery.
- G9 не закрыт, поэтому тег v1.0, production readiness и `PROJECT CLOSED` не
  заявляются.
- Development benchmark содержит 312 запланированных и записанных cells, но
  171 model cell завершилась fail-closed ошибкой structured output. Это
  диагностический результат, не release benchmark.
- В benchmark не выполнялся repair; repair-rate claim отсутствует.
- Текущий corpus мал и имеет topology confound. Результаты нельзя использовать
  как доказательство преимущества над полным SAST.
- Docker server/worker существуют, но готового Compose/Kubernetes deployment и
  production operations proof в репозитории нет.
- GitLab trusted worker image path является явным placeholder.
- Installed CLI требует заранее подготовленную защищенную OS authority; общий
  end-user provisioning workflow еще не опубликован.
- Quality receipts доказывают воспроизводимость конкретного subject, а не
  отсутствие уязвимостей и не production security.

Текущий статус задач и gates: [docs/CONTEXT.md](docs/CONTEXT.md) и
[docs/PLAN.md](docs/PLAN.md).

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
claim or a claim of superiority over SAST. Numerical results are reported only
in the [development benchmark](report/development-benchmark/README.md) together
with its [limitations](report/development-benchmark/limitations.md).

### Candidate verification

The current staged candidate was checked with
`uv run --locked --offline --no-sync --group quality python -I scripts/quality.py`:
`2554 passed`, `32 skipped`, `80.10%` Core branch coverage, `QUALITY=PASS`.
A separate opt-in run of `tests/unit/test_development_corpus.py` with
`SECURECODE_RUN_DOCKER_ORACLE=1` finished with `22 passed`, so all five Docker
oracle scenarios executed. The remaining skips are platform-specific Linux
worker and POSIX file-race/FIFO checks that do not run on Windows.

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
| Ollama | `0.16.2` |
| Model | `qwen2.5-coder:7b-instruct-q4_K_M` |
| Quantization | `Q4_K_M` |
| Expected model digest | `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364` |

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
current tree does not include Docker Compose or Kubernetes manifests.

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

- The M-A2026 bundle is `NOT_READY`: external instructor details, durable final
  reviews, and protected delivery are still pending.
- G9 is open, so this repository does not claim a v1.0 tag, production
  readiness, or `PROJECT CLOSED`.
- The development benchmark records all 312 planned cells, but 171 model cells
  failed closed on structured output. It is a diagnostic study, not a release
  benchmark.
- No repair was attempted in that benchmark, so no repair-rate claim exists.
- The corpus is small and has a topology confound. Results do not establish an
  advantage over a full SAST product.
- Docker server/worker images exist, but the repository has no ready Compose or
  Kubernetes deployment and no production operations proof.
- The GitLab trusted worker image path is an explicit operator placeholder.
- Installed CLI execution needs pre-provisioned OS-protected authority; a
  general end-user provisioning workflow is not published yet.
- Quality receipts establish reproducibility for one exact subject. They do not
  prove the absence of vulnerabilities or production security.

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

### License

The current tree has no root `LICENSE`, and package metadata says
`Private :: Do Not Upload`. No public license to use, modify, or redistribute
this code is therefore granted at this time. Before public publication, the
repository owner must add the chosen license and review licenses for external
datasets, models, and dependencies. The self-authored educational corpus in
`evaluation/development/` is separately identified as `CC0-1.0`.
