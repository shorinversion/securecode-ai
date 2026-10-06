# Эксплуатация SecureCode AI

Документ описывает производственный режим: CLI `securecode`, образы control plane и
worker, интеграцию с GitHub и GitLab. Для локального аудита достаточно команды
`securecode analyze`, описанной в [README](../README.md).

## CLI

```text
securecode doctor
securecode analyze TARGET [--provider deepseek|local] [--format markdown|html|json|sarif] [--output FILE | --output-dir DIR] [--patch-dir DIR] [--no-fix]
securecode scan TARGET [--config FILE] [--format json|sarif|markdown|html] [--output FILE]
securecode scan TARGET --diagnostic [--format json|sarif|markdown|html] [--output FILE]
securecode fix TARGET [--format json|sarif|markdown|html|diff] [--output FILE]
securecode validate TARGET --patch SELECTOR [--format json|sarif|markdown|html|diff]
securecode approve TARGET --patch SELECTOR --artifact-sha256 SHA256 \
  --capability SHA256 --approval-id ID --approver-id ID [--output FILE]
securecode release --config FILE [--publish --authorization FILE]
```

`scan`, `fix`, `validate` и `approve` работают только на хосте с защищённой записью об
одобрении: HKLM в Windows или файлы, принадлежащие root, в Linux. Запись фиксирует
профиль модели, политику исходящих данных и исполняемый файл Git; любое расхождение
приводит к отказу. `release` по умолчанию выполняет пробный прогон; публикация требует
защищённой конфигурации, ключа и краткоживущей авторизации, привязанной к digest
кандидата.

| Код | Значение |
| ---: | --- |
| `0` | операция завершена, нарушений нет |
| `2` | нарушение политики (найдены уязвимости) |
| `3` | результат не определён |
| `4` | операционная ошибка |
| `5` | неверные параметры или конфигурация |
| `6` | операция отменена или заменена |

## Образы Docker

Сборка образов из корня репозитория:

```powershell
pwsh -NoProfile -File deploy/docker/build-images.ps1
```

Скрипт собирает `securecode-ai/runtime:1.2.1`, `securecode-ai/server:1.2.1` и
`securecode-ai/worker:1.2.1` и выводит их неизменяемые идентификаторы. По умолчанию
используется `linux/amd64`; `linux/arm64` задаётся параметром `-Platform`.

### Control plane

Сервер работает под непривилегированным UID `65532`, пишет только в
`/var/lib/securecode` и `/tmp/securecode`, требует TLS при привязке к `0.0.0.0` и при
первом запуске — OIDC или начальные учётные записи:

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
  securecode-ai/server:1.2.1
```

Каталог секретов содержит файлы `securecode_tls_cert`, `securecode_tls_key`,
`admin_token` и `worker_token`, доступные UID `65532`. Закрытый ключ TLS не должен быть
доступен группе и остальным пользователям; сертификат должен быть доверенным для
worker. Длина каждого токена — не менее 32 символов.

### Worker

Worker подключается к control plane и выполняет анализ локального checkout:

```bash
docker run --rm --name securecode-worker --network securecode \
  --mount type=bind,src=/absolute/source-checkout,dst=/workspace,readonly \
  --mount type=bind,src=/absolute/securecode-secrets,dst=/run/secrets,readonly \
  -e SECURECODE_CONTROL_PLANE_URL=https://securecode-server:8080 \
  -e SECURECODE_WORKER_TOKEN_FILE=/run/secrets/worker_token \
  -e SECURECODE_WORKER_ID=worker-1 \
  -e SECURECODE_WORKER_TARGET=/workspace \
  securecode-ai/worker:1.2.1
```

Переменная `SECURECODE_WORKER_RUN_ID` ограничивает worker одним запуском. Для GitLab
worker получает `CI_PROJECT_ID`, `CI_MERGE_REQUEST_IID` и `CI_COMMIT_SHA`. Разрешённые
хосты артефактов задаются в `SECURECODE_WORKER_ARTIFACT_HOSTS`. Конфигурация Compose и
ограничения запуска: [deploy/docker/README.md](../deploy/docker/README.md).

## GitHub

### CI проекта

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) запускается на pull request,
merge queue и push:

1. проверка политики CI и зависимостей, закреплённых версий Actions;
2. поиск секретов в дереве и истории;
3. аудит графа зависимостей по lock-файлу;
4. проверка спецификаций и кандидата;
5. матрица качества на Python 3.12, 3.13 и 3.14;
6. итоговая проверка `gate`.

Workflow использует только `contents: read`, не сохраняет учётные данные checkout и не
объявляет секретов репозитория. Для fork включите GitHub Actions и задайте
обязательную проверку `gate` в правилах защиты ветки.

### GitHub App

Control plane ожидает переменные `SECURECODE_GITHUB_API_URL`,
`SECURECODE_GITHUB_INSTALLATION_ID`, `SECURECODE_GITHUB_TOKEN_FILE`,
`SECURECODE_GITHUB_WEBHOOK_SECRET_FILE`, `SECURECODE_SCM_PINS_FILE` и
`SECURECODE_SCM_TENANT_ID`. Webhook направляется на
`POST /api/v1/integrations/github/webhook` внешнего HTTPS-адреса control plane.

Приложению нужны права Metadata (read), Pull requests (read/write), Checks
(read/write), Contents (read) и, при загрузке SARIF, Code scanning alerts (write).
Права Administration, Workflows (write) и слияния не требуются.

`SECURECODE_SCM_PINS_FILE` — JSON-объект ровно с семью ключами: `stage_catalogue`,
`workflow`, `policy`, `configuration`, `provider_profile`, `capability_profile`,
`egress_profile`. Каждое значение содержит `schema_version` (`"0.2.0"`, версия
контракта), `component_id`, `component_version` (SemVer компонента) и `content_sha256`
принятого артефакта:

```json
{
  "workflow": {
    "schema_version": "0.2.0",
    "component_id": "workflow",
    "component_version": "1.0.0",
    "content_sha256": "<sha256 принятого артефакта>"
  }
}
```

Файл хранится вне checkout и монтируется только для чтения с правами `0600`. Лишний или
отсутствующий ключ, неверный SemVer или digest блокируют запуск.

## GitLab

Корневой [`.gitlab-ci.yml`](../.gitlab-ci.yml) не выполняет аудит в недоверенном
pipeline. Для merge request из того же проекта он запускает отдельный защищённый
проект и передаёт только ID проекта, IID merge request и SHA commit.

1. Создайте проект доверенного аудита на защищённом runner.
2. Используйте [trusted-audit.yml](../deploy/gitlab/trusted-audit.yml) как его конфигурацию CI.
3. Замените `registry.example.invalid/...` на путь к своему registry, сохранив проверенный digest образа.
4. В исходном проекте задайте защищённые переменные `SECURECODE_TRUSTED_AUDIT_PROJECT` и `SECURECODE_TRUSTED_AUDIT_REF`.
5. В проекте аудита задайте `SECURECODE_ALLOWED_SOURCE_PROJECT_ID`, `SECURECODE_CONTROL_PLANE_URL` и файловую переменную `SECURECODE_WORKER_TOKEN_FILE`; при необходимости — `SECURECODE_WORKER_ARTIFACT_HOSTS`.
6. В исходном проекте в **Settings > CI/CD > Job token permissions** добавьте проект аудита в список разрешённых.
7. Защитите ref аудита и назначьте runner тег `securecode-ai-gpu`.

Для GitLab webhook направляется на `POST /api/v1/integrations/gitlab/webhook`; нужны
переменные `SECURECODE_GITLAB_API_URL`, `SECURECODE_GITLAB_TOKEN_FILE` и
`SECURECODE_GITLAB_WEBHOOK_SECRET_FILE`.

Pipeline отклоняет merge request из fork, чужой ID проекта, незащищённый ref и SHA,
не совпадающий с head открытого merge request. Итоговый job не имеет доступа к базе
control plane и учётным данным записи в SCM.
