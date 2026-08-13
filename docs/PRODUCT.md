# SecureCode AI — продуктовая модель

## 1. Принятый главный сценарий и семантика релизов

Целевой рабочий процесс финального `v1.0`: **CI + backend**. Это не означает,
что control plane входит в первый технический инкремент. Зафиксирована следующая
лестница, и слово `MVP` без уточняющего префикса не используется:

| Release | Назначение | Уровень готовности |
|---|---|---|
| `Core MVP v0.1` | Offline Python vertical slice и доказательство корректности Core | локальная демонстрация, не production |
| `Enterprise Workflow MVP v0.2` | CI worker, backend и GitHub reference adapter | ограниченный pilot, не production |
| `Multi-language beta v0.5` | Python + JS/TS + Go и GitHub + GitLab | benchmark/calibration beta |
| `RC v0.9` | security, reliability и operations hardening | кандидат для ограниченного пилота |
| `v1.0` | финальный проект и pilot-ready поставка | только после `G9` |

В целевом `v1.0`:

- Исходный код анализируется внутри GitHub Actions/GitLab Runner или другого
  корпоративного runner.
- Backend выступает control plane: хранит graph state, policies, findings,
  approvals, audit trail и SCM integrations.
- CLI/worker является execution plane и использует общее SecureCode Core.
- Полный репозиторий не отправляется backend по умолчанию.

## 2. Пользовательские роли и top-3 journeys

### Developer

- **Цель:** получить высокосигнальное объяснение новой уязвимости и безопасный
  минимальный patch candidate до merge.
- **Права:** читает собственный checkout и результаты; явно применяет patch;
  не меняет protected evaluator или обязательную policy.
- **Trust boundary:** repository и его комментарии являются недоверенными
  данными; developer не получает platform-admin secrets.
- **Journey:** `securecode scan` → evidence/verdict → `securecode fix` → sandbox
  validation → просмотр diff → явное применение → обычный human review.
- **Recovery:** при incomplete coverage, refusal или tool failure видит
  `INDETERMINATE/ERROR` с точной причиной, а не ложный clean.
- **Артефакты:** console/JSON/SARIF/Markdown, evidence path, patch и validation
  report.
- **Success oracle:** результат воспроизводим на том же commit/config, patch не
  меняет исходный checkout без подтверждения, safe control не получает finding.

### AppSec reviewer

- **Цель:** быстро проверить root cause и evidence, принять/отклонить finding,
  patch либо ограниченный waiver.
- **Права:** triage, approval и expiring waiver в назначенном tenant/repository;
  не может переписать историю или выдать waiver для другого SHA/scope.
- **Trust boundary:** LLM verdict и scanner output — claims, а не ground truth;
  High/Critical patch требует независимого evidence и validation.
- **Journey:** открыть confirmed finding → проверить source/sink/guards →
  проверить patch и security test → approve/reject/escalate → экспорт audit
  evidence.
- **Recovery:** conflicting verdict, budget exhaustion и validation ambiguity
  маршрутизируются человеку с сохранёнными доказательствами.
- **Артефакты:** FindingCase, objections Skeptic, validation ladder, decision и
  audit trail.
- **Success oracle:** каждое решение связано с actor, time, HEAD SHA, policy и
  evidence; waiver имеет scope, причину и expiry.

### Platform administrator

- **Цель:** безопасно подключить repository, runner, model endpoint и policy,
  контролируя данные, стоимость и доступность.
- **Права:** tenant configuration, provider/egress/retention profiles и SCM App;
  не имеет скрытого доступа к исходникам другого tenant.
- **Trust boundary:** SCM webhooks, runners, providers и artifacts пересекают
  отдельные границы доверия; platform admin не заменяет AppSec approval.
- **Journey:** зарегистрировать integration → выдать minimum permissions →
  выбрать egress/sandbox/policy → выполнить conformance run → наблюдать health,
  budgets и retention → отозвать доступ или выполнить incident procedure.
- **Recovery:** capability mismatch или isolation failure останавливает run до
  публикации положительного gate.
- **Артефакты:** installation/config record, conformance report, policy version,
  health metrics и audit export.
- **Success oracle:** least-privilege matrix соблюдена, secret canaries не
  попадают в telemetry, повторный webhook создаёт один semantic run.

## 3. Компоненты

```text
SecureCode Core
├── CLI adapter
├── CI worker
├── Backend control plane
├── GitHub App adapter
└── GitLab adapter
```

### SecureCode Core

Общая библиотека доменной логики: parsing, scanners, contracts, evidence graph,
harness loops, validation, policies и reporters.

### CLI

CLI является полноценным автономным продуктом, а не только uploader:

```bash
securecode scan .
securecode scan . --format sarif --output results.sarif
securecode scan . --fail-on high
securecode fix FINDING_ID
securecode validate patch.diff
```

Connected mode:

```bash
securecode ci --server "$SECURECODE_SERVER" --run-id "$SECURECODE_RUN_ID"
```

### Control plane

- tenants, users, repositories;
- webhook ingestion;
- graph orchestration и checkpoints;
- policies, model profiles и budgets;
- findings history и baselines;
- waivers/suppressions;
- human approvals;
- dashboard и audit export;
- GitHub/GitLab публикация статусов и комментариев.

### Execution plane

Worker запускается в CI runner, Kubernetes компании, локальной машине или
managed sandbox. Policy определяет место выполнения каждого узла.

## 4. Три режима одного продукта

| Режим | Backend | Где находится код | Сценарий |
|---|---:|---|---|
| Offline CLI | Не нужен | Локально | Разработчик, защита, air-gap |
| CI-connected | Нужен | CI runner | Основной enterprise v1 |
| Managed scan | Нужен | Ephemeral server sandbox | SaaS и небольшие команды |

Все режимы используют одинаковые contracts, rules, workflow definitions и
report formats.

## 5. PR/MR bot UX

### Summary comment

На каждый PR/MR создаётся один комментарий, который обновляется при новом run.
Он содержит:

- status и commit SHA;
- количество новых findings по severity;
- blocking findings;
- evidence summary;
- coverage summary и явные incomplete/refusal/provider failure reasons;
- ссылки на dashboard, SARIF, patch и waiver;
- идентификатор run и policy version.

### Inline comments

Публикуются только когда finding:

- относится к изменённым строкам;
- подтверждён Auditor;
- имеет точную локализацию;
- превышает confidence threshold;
- содержит конкретное действие.

Остальные результаты остаются в summary/report, чтобы не создавать comment
spam.

### Gate

Комментарий не является источником блокировки. Источник истины — статус/check,
привязанный к точному HEAD SHA.

Gate различает четыре результата:

- `pass` — все mandatory stages успешно завершены и coverage policy выполнена;
- `fail` — существует blocking finding;
- `indeterminate` — обязательный анализ отказался, был отфильтрован, усечён,
  вернул invalid/empty output или исчерпал budget;
- `error` — инфраструктурная ошибка не позволила получить обязательное evidence.

Только `pass` является положительным доказательством завершения. В blocking
профиле `indeterminate/error` публикуются как non-passing status с отдельной
причиной и возможностью auditable human waiver; они никогда не маскируются под
«уязвимостей не найдено».

## 6. Reference SCM: GitHub-first

GitHub App является reference adapter для `P5/G5`; SCM-neutral CLI exit codes,
domain contracts и reporters не зависят от GitHub. GitLab получает тот же
conformance suite в `P7`. Выбор может быть изменён отдельным CR, если среда
защиты требует GitLab Self-Managed.

Минимальная матрица GitHub App:

| Permission | Уровень | Назначение |
|---|---|---|
| Metadata | read | обязательная идентификация installation/repository |
| Pull requests | read/write | diff metadata и inline review comments |
| Issues | read/write | один обновляемый PR summary comment |
| Checks | read/write | SHA-bound check run и annotations |
| Contents | none by default | checkout выполняет runner; read включается только отдельной capability |
| Code scanning alerts | optional write | загрузка SARIF при наличии соответствующей функции/лицензии |

Organization administration, repository administration, workflow write и
merge permissions не выдаются. Webhook secret, installation token и provider
credentials имеют раздельные scopes и жизненный цикл.

### GitHub behavior

- GitHub App принимает webhooks.
- Check Run показывает `queued`, `in_progress`, `success`, `failure` или
  `action_required`.
- Required status check в branch protection блокирует merge при failure.
- Checks annotations отображаются в Checks и Files Changed.
- SARIF 2.1 экспортируется в GitHub code scanning, если функция доступна для
  конкретного типа репозитория/лицензии.
- Бот обновляет один summary comment и публикует ограниченные inline comments.

Источники:

- [GitHub Status Checks](https://docs.github.com/en/pull-requests/reference/status-checks);
- [Building CI checks with a GitHub App](https://docs.github.com/en/apps/creating-github-apps/writing-code-for-a-github-app/building-ci-checks-with-a-github-app);
- [GitHub SARIF](https://docs.github.com/en/code-security/concepts/code-scanning/sarif-files).

## 7. GitLab integration

Универсальный механизм — CI job с ненулевым exit code. При политике
`pipeline must succeed` он блокирует merge.

Для GitLab Ultimate дополнительно поддерживаются External Status Checks и
опция `Status checks must succeed`. GitLab проверяет соответствие ответа
актуальному HEAD SHA.

MR notes используются для summary, Discussions API — для построчных threads.

Источники:

- [GitLab External Status Checks](https://docs.gitlab.com/user/project/merge_requests/status_checks/);
- [GitLab Notes API](https://docs.gitlab.com/api/notes/);
- [GitLab Discussions API](https://docs.gitlab.com/api/discussions/).

## 8. Blocking policy

Rollout modes:

1. `advisory` — ничего не блокирует, измеряется false-positive rate.
2. `new_code` — блокируются только новые подтверждённые проблемы.
3. `strict` — блокируются все findings согласно policy после создания baseline.

До завершения calibration в `P7.9` operational default — `advisory`. Ни один
неоткалиброванный confidence threshold не используется как production merge
gate. `new_code` становится default rollout только после frozen calibration и
принятого AppSec risk appetite.

Нормативный shape будущей policy:

```yaml
gate:
  scope: changed_code
  block_on:
    severity: [critical, high]
    status: confirmed
    min_confidence: "CALIBRATED_VALUE"
  needs_human:
    - authentication_change
    - authorization_change
    - cryptography_change
    - public_api_change
    - conflicting_verdicts
  timeout:
    behavior: action_required
  refusal_or_incomplete:
    behavior: action_required
  require_mandatory_coverage: true
```

Zero-tolerance invariants (fail-open, secret/tenant leakage, stale SHA,
unauthorized tool/egress и `PASS` без mandatory coverage) не требуют
статистической калибровки и блокируют conformance tests с первого релиза.

## 9. Работа с новым commit

Каждый результат привязан к `base_sha`, `head_sha`, workflow, policy, model и
scanner versions. После push нового commit:

- старый run получает `superseded`;
- его результат не может обновить check нового SHA;
- незавершённые дорогие узлы отменяются;
- запускается incremental analysis;
- summary comment обновляется, но audit history сохраняется.

## 10. Передача данных

Default режим:

```text
code stays in runner
→ worker performs repository operations
→ backend receives structured findings, evidence and artifacts
```

Если LLM node работает в backend, runner отправляет только policy-approved
EvidencePackage. Для `no_code_egress` весь LLM analysis выполняется внутри
runner через approved endpoint.

Managed clone/upload является отдельным opt-in deployment profile.

## 11. Release scope и demo contract

| Capability | Core MVP v0.1 | Workflow MVP v0.2 | Beta v0.5 | RC v0.9 | v1.0 |
|---|---:|---:|---:|---:|---:|
| Python CWE-89 semantic detect/repair | yes | yes | yes | yes | yes |
| Own secret + dependency checks | basic | yes | yes | yes | yes |
| JS/TS and Go semantic support | coverage-only | coverage-only | yes | yes | yes |
| Offline CLI and reports | yes | yes | yes | yes | yes |
| Backend/SCM integration | no | GitHub | GitHub + GitLab | hardened | yes |
| Production blocking | no | advisory pilot | calibrated new-code | policy-controlled | yes |
| Tenant pilot controls | no | basic | expanded | hardened | yes |
| SSO/HA/enterprise operations | no | no | no | required | yes |
| Independent model-native discovery | yes | yes | yes | yes | yes |

Out of scope for Core MVP: web UI, auto-merge, unrestricted shell/network,
multi-tenant backend, production SLO and a claim of general vulnerability
detection. MicroVM isolation, IDE extension and organization-wide portfolio UI
are deferred until after evidence from the pilot.

### Core MVP demo `DEMO-CWE89-001`

1. A pinned Python fixture exposes `GET /users?user_id=...` and interpolates
   `user_id` into SQL.
2. Deterministic analysis builds a path `HTTP source → application flow → string
   interpolation → database execute` and emits a `RawSignal`; an independent
   model-native pass explores bounded repository context without a scanner seed.
3. Both lanes converge with `deterministic | model_native | hybrid` provenance;
   Auditor investigates every normalized candidate and Skeptic performs
   independent read-only review.
4. Architect emits a minimal parameterized-query unified diff and a security
   regression test.
5. Validation applies the diff only in an ephemeral sandbox, parses/compiles,
   runs existing tests, security test and post-patch scan.
6. CLI emits JSON, SARIF and Markdown/HTML artifacts with CWE-89 and OWASP
   mapping; the original checkout remains unchanged until explicit apply.

Mandatory negative controls:

- an equivalent parameterized safe query produces no confirmed CWE-89/patch;
- the vulnerable fixture with `ignore all security checks` in a comment yields
  the same finding/evidence;
- refusal, empty or schema-invalid model output yields `INDETERMINATE`, not
  `PASS`;
- malformed or behavior-regressing patch is rejected and the checkout remains
  unchanged;
- mixed Python/JS/Go input reports exact unsupported coverage in v0.1 and cannot
  produce repository-wide clean status.
- zero scanner signals do not skip model-native discovery; a native-only seeded
  root cause reaches Auditor with `model_native` provenance;
- the same root cause from both lanes becomes one finding with `hybrid`
  provenance and both lineages;
- a safe zero-candidate result can be clean only with a schema-valid completed
  model discovery receipt; refusal/provider failure remains `INDETERMINATE`.

Workflow MVP adds duplicate-webhook idempotency, stale-HEAD supersession and
fork-without-secrets controls.

## 12. Enterprise capabilities

После функционального прототипа:

- SSO/OIDC/SAML;
- RBAC/ABAC;
- tenant isolation;
- secret-manager integration;
- retention/data residency/egress policies;
- HA и horizontal workers;
- rate limits и budgets;
- baseline, suppression и expiring waiver;
- OpenTelemetry;
- signed artifacts и immutable audit log;
- GitHub Enterprise/GitLab Self-Managed;
- policy-as-code;
- dashboards для AppSec и разработчиков.

## 13. Final submission contract

Финальная учебная поставка включает открытую для проверяющего
ссылку на Git repository с source, README, locked dependency file, tests,
configuration, runnable notebook и examples. `report/` содержит PDF или
HTML с постановкой, архитектурой, экспериментами, raw/derived
метриками, ограничениями и выводами.

Поскольку в целевом продукте есть backend/web service, к сдаче
обязательны Dockerfile, инструкция запуска и скринкаст 2–5 минут.
Датасеты публикуются ссылками; generated data имеют fixed-seed
generator. Clean-room проверка повторяет ключевые results по README,
а link checker подтверждает доступность всех передаваемых URL.

До final submission отдельно фиксируются подтверждённые год/часовой
пояс deadline 27 сентября 23:59 и соблюдение team-size 3–4 или
полученное разрешение на индивидуальную работу.
