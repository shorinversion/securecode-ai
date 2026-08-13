# SecureCode AI — журнал решений

Статусы: `accepted`, `proposed`, `superseded`.

## D-001 — Гибридный нейросимволический анализ

- Статус: accepted
- Решение: объединять детерминированные scanners/program analysis и LLM
  reasoning; не использовать LLM как единственный detector или validator.
- Причина: исследования IRIS, RepoAudit, MoCQ, PrimeVul и реальные review data
  показывают ограничения обеих сторон по отдельности.
- Последствие: каждый LLM verdict должен ссылаться на evidence и проходить
  независимый gate.

## D-002 — Provider-agnostic LLM

- Статус: accepted
- Решение: локальная LLM необязательна; поддерживать URL, API key, model и
  capability profile.
- Причина: продукт не должен зависеть от одного поставщика или hardware profile.
- Последствие: нужен собственный model adapter и feature negotiation вместо
  предположения о полной OpenAI compatibility.

## D-003 — Graph of bounded loops

- Статус: accepted
- Решение: workflow строится как graph/state machine; каждый agent node содержит
  ограниченный loop со stop condition.
- Причина: проект требует специализации, fan-out/fan-in, independent review,
  failure isolation и auditable routing.
- Последствие: edges выбираются policy code; LLM имеет свободу только внутри
  разрешённого узла.

## D-004 — Разделить workflow graph и evidence graph

- Статус: accepted
- Решение: execution routing и программные доказательства имеют отдельные
  модели данных.
- Причина: смешение orchestration graph с GraphRAG/program graph создаёт
  неясные контракты и усложняет проверку.
- Последствие: EvidenceGraph является артефактом FindingCase, а не runtime
  workflow.

## D-005 — Независимый Skeptic/Verifier

- Статус: accepted
- Решение: High/Critical findings и patches проверяет отдельный read-only узел,
  который не является автором результата.
- Причина: self-verification и общая история рассуждений повышают риск
  confirmation bias.
- Последствие: Skeptic не может изменять evidence или patch, только добавлять
  verdict/objections.

## D-006 — Patch candidate, не автоматическая гарантия

- Статус: accepted
- Решение: Auto-Fix создаёт `validated_candidate`; автоматический merge выключен
  по умолчанию.
- Причина: SecureVibeBench, CVE-Bench, SEC-bench и PVBench демонстрируют низкую
  надёжность и слабость базовой patch validation.
- Последствие: validation ladder и human approval обязательны.

## D-007 — Одно ядро, несколько режимов

- Статус: accepted
- Решение: CLI, CI worker и backend используют общее SecureCode Core.
- Причина: отдельные реализации быстро расходятся по rules, schemas и verdicts.
- Последствие: CLI является полноценным offline executor, а не uploader.

## D-008 — CI + backend как основной v1

- Статус: accepted
- Решение: основным enterprise-сценарием v1 является execution внутри CI runner
  с backend control plane.
- Причина: сочетает SCM UX, централизованные policies и хранение кода рядом с
  существующей корпоративной инфраструктурой.
- Последствие: GitHub/GitLab adapters публикуют comments/checks, а CLI/worker
  выполняет анализ.

## D-009 — Код не покидает runner по умолчанию

- Статус: accepted
- Решение: backend не получает полный repository snapshot без явного opt-in.
- Причина: privacy, data residency, bandwidth и tenant isolation.
- Последствие: нужен EvidencePackage и per-node `execution_location`.

## D-010 — Gate привязан к SHA

- Статус: accepted
- Решение: merge блокирует SCM check/job, а не комментарий; результат связан с
  точным HEAD SHA.
- Причина: comments можно удалить или устареть; параллельные runs могут
  завершаться не по порядку.
- Последствие: stale runs получают `superseded` и не обновляют новый check.

## D-011 — New-code gate как default rollout

- Статус: accepted
- Решение: до statistical calibration работать в `advisory`; после calibration
  первым blocking rollout делать только новые подтверждённые findings,
  относящиеся к изменённому коду, по принятому AppSec threshold profile.
- Причина: немедленная блокировка существующего security debt делает внедрение
  непрактичным.
- Последствие: required baseline/fingerprinting и режимы advisory/new_code/strict.

## D-012 — Framework-independent domain layer

- Статус: superseded by `D-020`
- Решение: первым graph runtime рассмотреть LangGraph, но скрыть его за
  WorkflowRuntime interface.
- Причина: LangGraph удобен для прототипа, но enterprise durability может
  потребовать Temporal или другой runtime.
- До принятия: сравнить persistence, recovery, concurrency, testing,
  observability, лицензирование и сложность эксплуатации.

## D-013 — Spec-Driven Development и executable contracts

- Статус: accepted
- Решение: accepted specification в `specs/` становится нормативным источником
  для реализации. Каждая implementation-задача получает requirement refs,
  allowlist путей/инструментов, budgets, stop conditions и проверяемые
  acceptance commands. Текстовые требования дополняются schemas, contract
  tests, transition guards, policies и negative controls.
- Причина: большой prompt не устраняет неоднозначность и не ограничивает
  capabilities модели. LLM-разработка становится предсказуемее, когда
  пространство действий ограничено контрактами и независимыми gates.
- Последствие: `P0.14` создаёт versioned specification baseline; `P1.13`
  вводит spec validation и drift checks. Implementation agent не может менять
  accepted spec, acceptance evaluator или gate evidence без отдельного CR/task.
- Компромисс: спецификации требуют поддержки, compatibility/migration правил и
  дисциплины change control, но снижают скрытый drift и стоимость поздних
  переделок.

## D-014 — Research evidence gate перед ADR и specification

- Статус: accepted
- Решение: external report, LLM answer, X post или search result сначала
  становится candidate claim. Для promotion в ADR/specification требуются
  стабильный claim ID, разрешимый primary/official source, scope/limitation
  check, consideration of contrary evidence и provenance в research ledger.
- Причина: импортированный Deep Research содержал 74 внутренних citation
  markers без разрешимых URL; содержательно полезный текст сам по себе не даёт
  воспроизводимого evidence trail.
- Последствие: вводятся `docs/research/PROTOCOL.md`, `CLAIMS.md`, exact search
  log и amendments. `G0` не принимает material claim с unresolved citation.
- Компромисс: формальная проверка замедляет решения, поэтому assurance
  пропорционален риску; формальная PRISMA compliance не заявляется без
  полноценного systematic review.

## D-015 — Fail-closed LLM outcome и недоверенный код как data plane

- Статус: accepted
- Решение: весь repository/SCM/tool content имеет `instruction_authority=NONE`.
  `ModelCallStatus`, `FindingVerdict` и `AuditRunOutcome` являются независимыми
  типами. Refusal, safety filter, empty/invalid response, truncation, timeout,
  provider error и budget exhaustion не могут быть преобразованы в
  `no_finding` или `PASS`.
- Причина: prompt injection может не только заставить модель выполнить команду,
  но и вызвать отказ/неполный ответ, который наивная orchestration ошибочно
  интерпретирует как отсутствие уязвимости. OpenAI и Anthropic используют
  layered defenses и прямо не считают model-level robustness абсолютной.
- Последствие: provider adapter нормализует native outcome metadata; blocking
  gate имеет отдельные `FAIL`, `INDETERMINATE` и `ERROR`; `PASS` требует
  положительного coverage manifest. Вводится adversarial corpus с direct,
  encoded, compositional и refusal-induction attacks.
- Компромисс: fail-closed может создавать availability/DoS риск. Его ограничивают
  bounded fallback, минимальный evidence slice, точная причина и auditable
  human waiver, но waiver не переименовывает run в доказанный clean.
- Детали: [security/PROMPT_INJECTION.md](security/PROMPT_INJECTION.md).

## D-016 — Primary Integrator с ограниченными специализированными субагентами

- Статус: accepted
- Решение: основной Codex-agent является единственным Primary Integrator и
  owner пользовательского результата. Субагенты применяются только для
  ограниченных независимых task packets: research, draft specification,
  path-isolated implementation, test design и read-only review/validation.
- Причина: параллельность полезна для fan-out и независимой проверки, но
  overlapping writes, shared context drift и распределённые архитектурные
  решения повышают стоимость интеграции и риск противоречий.
- Последствие: один writer на путь, nested delegation запрещена по умолчанию,
  canonical contracts/critical path интегрируются последовательно. Primary
  Integrator проверяет каждый subagent result и повторяет acceptance commands.
- Наблюдаемое подтверждение: независимый product reviewer обнаружил дефекты
  scope/traceability, architecture reviewer — несовместимые wire contracts,
  security/evaluation reviewer — fail-open и metric/policy loopholes. Primary
  Integrator свёл исправления, разрешил конфликты и повторно запустил validator
  и delta reviews. Это evidence в пользу гибридной модели ролей, а не право
  субагентов самостоятельно принимать решения или менять baseline.
- Компромисс: часть работы выполняется последовательно и медленнее по wall-clock,
  зато сохраняются единая архитектура, воспроизводимость и ясная ответственность.
- Детали: [SPEC_DRIVEN_DEVELOPMENT.md](SPEC_DRIVEN_DEVELOPMENT.md), раздел 8.1,
  и `specs/templates/implementation-task.yaml`.

## D-017 — Python-first Core MVP при обязательном multi-language финале

- Статус: accepted
- Решение: `Core MVP v0.1` реализует semantic detection/repair для Python и
  reference rule CWE-89. Domain, EvidenceGraph, scanner plugin и report
  contracts остаются language-neutral. JS/TS и Go распознаются в coverage и не
  могут молча считаться clean; их полноценная поддержка обязательна к `G7/G9`.
- Причина: один проверяемый vertical slice снижает риск одновременной разработки
  трёх разных semantic extractors/toolchains, не отменяя исходный scope.
- Последствие: mixed-language fixture до P7 даёт incomplete coverage; public
  schemas не имеют Python-specific обязательных полей.

## D-018 — GitHub-first reference SCM

- Статус: accepted
- Решение: GitHub App является reference adapter в `P5/G5`; GitLab получает тот
  же SCM-neutral conformance contract в `P7`. Если фактическая среда защиты
  требует GitLab Self-Managed, изменение оформляется CR без изменения Core.
- Причина: Checks/annotations/required checks дают удобный эталонный путь;
  GitLab External Status Checks зависят от tier, тогда как CI job/commit status
  всё равно поддерживаются через общий adapter.
- Последствие: minimum GitHub permission matrix зафиксирована в
  [PRODUCT.md](PRODUCT.md#6-reference-scm-github-first); SARIF является optional
  capability, не источником blocking truth.

## D-019 — Однозначная семантика релизов

- Статус: accepted
- Решение: использовать названия `Core MVP v0.1`, `Enterprise Workflow MVP
  v0.2 — pilot only`, `Multi-language beta v0.5`, `RC v0.9`, `v1.0`.
- Причина: слово enterprise рядом с MVP ошибочно обещало production readiness,
  хотя SSO/HA/supply-chain/operations hardening появляются в P8.
- Последствие: production/pilot claims всегда привязаны к gate, corpus и
  known limitations.

## D-020 — LocalRuntime и TemporalRuntime за единым портом

- Статус: accepted
- Решение: typed domain state machine и `WorkflowRuntime` являются authority.
  `LocalRuntime` обслуживает offline CLI/tests/Core MVP; `TemporalRuntime` —
  connected CI/backend, durable workers и human approvals. LangGraph остаётся
  non-normative time-boxed experiment и не является второй state authority.
- Причина: LangGraph удобен для agent graphs/checkpoints, но replay поздних
  nodes может повторно вызвать внешние side effects. Temporal отделяет durable
  workflow history от idempotent Activities и persistent task queues.
- Последствие: domain не импортирует runtime; один golden transition suite
  проходит на обоих adapters; Temporal history не содержит raw source.
- Источники: [LangGraph persistence](https://docs.langchain.com/oss/python/langgraph/persistence),
  [Temporal workflows](https://docs.temporal.io/workflows) и
  [task queues](https://docs.temporal.io/task-queue).

## D-021 — PostgreSQL и Temporal task queues без дополнительного broker

- Статус: accepted
- Решение: PostgreSQL 18 — connected application system of record; Temporal
  task queues — workflow work; transactional inbox/outbox связывает webhook и
  idempotent workflow start. Generic broker отсутствует в pilot baseline.
- Причина: отдельный Redis/Kafka/Celery слой не добавляет требуемой семантики,
  но создаёт ещё один recovery/operations surface.
- Последствие: application и Temporal persistence используют раздельные
  databases/roles/credentials; application authz дополняется forced RLS.
- Источник/ограничение: [PostgreSQL RLS](https://www.postgresql.org/docs/18/ddl-rowsecurity.html)
  даёт default-deny при включённой RLS без policy, но owner/superuser/`BYPASSRLS`
  требуют отдельного контроля.

## D-022 — Content-addressed BlobStore

- Статус: accepted
- Решение: filesystem adapter для local development и S3-compatible adapter для
  pilot; tenant namespace, SHA-256, size, classification и retention являются
  контрактом. PostgreSQL хранит ссылки/metadata, не blobs.
- Причина: large/source-bearing artifacts требуют независимого integrity,
  lifecycle и access layer.
- Последствие: WORM/Object Lock разрешён только для одобренных non-source audit
  exports и не применяется к удаляемому raw source.

## D-023 — Tiered sandbox без silent downgrade

- Статус: accepted
- Решение: rootless OCI локально; Kubernetes Job на отдельном node pool с
  обязательным gVisor для untrusted connected pilot. MicroVM отложен до
  high-assurance profile. Невозможность применить профиль даёт
  `INDETERMINATE`, а не обычный container fallback.
- Причина: rootless снижает daemon/runtime privilege; gVisor добавляет userspace
  application-kernel boundary, но имеет compatibility/syscall overhead.
- Последствие: требуются conformance и compatibility suites, enforcing CNI,
  no service-account token/host mounts/capabilities и resource limits.
- Источники: [Docker rootless](https://docs.docker.com/engine/security/rootless/),
  [gVisor](https://gvisor.dev/docs/) и [Kubernetes security](https://kubernetes.io/docs/concepts/security/).

## D-024 — Классификация, egress и retention как policy contract

- Статус: accepted
- Решение: классы `DC0–DC4`, deny-by-default egress profiles `air_gap`,
  `no_code_egress`, `private_model_zdr`, `metadata_external`,
  `managed_scan_opt_in` и type/class-specific retention нормативно определены в
  [data-classification.md](../specs/security/data-classification.md).
- Причина: URL/key в env не определяют допустимость передачи source/secrets,
  retention, residency или provider capabilities.
- Последствие: `DC4` никогда не уходит в model/backend/SCM/telemetry;
  `no_code_egress` — default; every transmission получает manifest.

## D-025 — Frozen evaluation и отсутствие выдуманных thresholds

- Статус: accepted
- Решение: MVP использует pinned first-party specification corpus и делает
  только узкий contract/CWE-89 claim. До calibration режим advisory; thresholds
  выбираются на calibration data, замораживаются и затем проверяются на locked
  test. Zero-tolerance security invariants действуют сразу.
- Причина: универсальный confidence `0.85` не имел empirical evidence, а
  blocking до P7.9 создавал fail-open/false-block risk.
- Последствие: `G5/G6` означает advisory pilot; production `new_code` blocking
  появляется только после P7.9 и AppSec acceptance.
- Детали: [evaluation protocol](../specs/evaluation/protocol.md).

## D-026 — Domain-first schemas и typed policy/workflow contracts

- Статус: accepted
- Решение: Pydantic v2 domain models + checked-in JSON Schema Draft 2020-12 —
  normative domain contract; FastAPI/OpenAPI 3.1 генерируется из тех же типов.
  Workflow — typed state/transition contract; initial policy — versioned typed
  YAML/JSON plus deterministic evaluator. OPA/Rego, BDD framework и конкретный
  code generator не являются P1 public contract и могут быть выбраны позже.
- Причина: нужно зафиксировать public data/behavior before repository skeleton,
  не связывая домен с конкретным framework/tool syntax.
- Последствие: compatibility rules, examples, negative fixtures и protected-path
  checks обязательны в P1; accepted spec изменяется только CR/ADR.
- Источники: [Pydantic JSON Schema](https://docs.pydantic.dev/latest/concepts/json_schema/)
  и [FastAPI open standards](https://fastapi.tiangolo.com/features/).

## D-027 — Mandatory dual-lane semantic discovery

- Статус: accepted
- Решение: каждый product scan в supported semantic scope запускает
  два независимых discovery lane на одной immutable revision:
  deterministic analyzers возвращают только `RawSignal`, а model-native
  discovery напрямую исследует код через bounded read-only
  `RepositoryView` без scanner seed. После общей normalization каждый
  candidate обязан пройти Auditor, затем Skeptic/Finding Gate.
- Инвариант clean path: ноль deterministic signals не делает
  model-native stage `NOT_APPLICABLE`. Clean допустим только после
  schema-valid `SUCCEEDED` с `candidates=[]`, complete receipt и полного
  остального coverage. Refusal/filter/empty/invalid/timeout/provider error дают
  `INDETERMINATE`, а не clean; уже confirmed blocking finding остаётся
  `FAIL` с отдельной health degradation.
- Причина: scanner-seeded цикл может пропустить логическую
  уязвимость и ложно объявить clean; при этом чистая LLM-only
  архитектура не даёт проверяемых program-analysis facts.
- Последствия: baseline и mandatory-stage catalogue повышены до
  `0.2.0`; provider/egress eligibility проверяется до передачи кода;
  deterministic-only остаётся diagnostic/evaluation mode и не может
  выдать product `PASS`.

## D-028 — Restricted offline Evaluation Lab

- Статус: accepted with limited P7 scope
- Решение: RLM-inspired code exploration, DSPy/GEPA prompt optimization,
  SkillOpt-style skill optimization и synthetic generation допускаются
  только в isolated offline `P7 Evaluation Lab`. Они не являются
  Core MVP/runtime dependency, public API или product accuracy claim.
- Границы: optimizer видит только train/dev; locked expectations,
  evaluator, policy, capabilities, schemas и thresholds protected. Generated
  code исполняется без network/credentials на read-only immutable
  `CodeIndex`. Synthetic case — candidate, а не ground truth, пока нет
  executable oracle, independent root-cause review, fixed provenance и
  lineage-safe split.
- Promotion: versioned candidate повышается только после held-out
  improvement, zero-tolerance security gates и human/AppSec approval.
  Production agents никогда не self-modify и не self-promote.
- Причина: эти методы могут улучшить coverage/quality, но без
  isolation и held-out governance создают leakage, overfitting и
  self-modification risks.

<!-- OPEN_DECISIONS -->

## Открытые решения, не блокирующие P1

- Конкретные external beta datasets после license/leakage review (`P7.6`).
- Численные blocking thresholds после calibration (`P7.9`); до этого advisory.
- OPA/Rego против расширения typed policy evaluator после pilot evidence.
- Web UI scope: до `P6` достаточно API + SCM/CLI; dashboard не входит в Core MVP.
- MicroVM high-assurance sandbox после gVisor compatibility/performance evidence.
