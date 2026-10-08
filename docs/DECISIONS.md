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

## D-029 — Единый uv workspace и locked Python supply chain для P1

- Статус: accepted
- Решение: repository — один `uv` workspace с единственным корневым
  `uv.lock`. Contracts, Core и adapters являются отдельными private pre-alpha
  distributions в общем implicit namespace `securecode_ai`; зависимость
  направлена только внутрь: adapters → Core → contracts.
- Python: поддерживаются CPython `3.12–3.14`, development default — `3.13`;
  prerelease `3.15` исключён до отдельной compatibility-проверки. Семантика
  project commands фиксируется `uv==0.12.0`.
- Dependencies: P1.2 вводит только уже принятый Pydantic v2 и `uv_build`;
  точные runtime/transitive/build versions и registry hashes находятся в
  `uv.lock`. Resolution ограничен явным PyPI index и upload-time cutoff
  `2026-08-13T00:00:00Z`; изменение dependency metadata и lockfile проходит
  review вместе.
- Clean install: `uv sync --locked --no-dev --no-editable` обязан из новой
  среды собрать и установить все first-party packages; drift не может молча
  обновить lock. Package markers не содержат domain behavior.
- Границы: P1.3 добавляет quality/test dependencies в тот же lock; P8.11
  добавляет SBOM, provenance/signatures и artifact verification. Сам lockfile
  не считается доказательством полной supply-chain security.
- Причина: workspace сохраняет ownership boundaries и единый dependency graph,
  а exact tool/lock + clean-room oracle дают воспроизводимость без второго
  requirements/lock source of truth.

## D-030 — Typed attestation metadata и byte-exact CI evaluator amendments

- Статус: accepted (`CR-017`); bootstrap implementation under exact review.
- Решение secret scan: криптографический digest не считается секретом только
  внутри exact-path completion attestation, которая проходит закрытые identity,
  key, type, budget, evidence-catalog/order и lowercase SHA-1/SHA-256 проверки.
  Scanner заменяет в своём временном view только typed OID/digest values; все
  остальные поля сканируются обычными detector plugins. Invalid/unknown input
  не получает частичного исключения. `.secrets.baseline` не изменяется.
- Решение local/CI equivalence: pre-commit больше не вызывает отдельный raw
  hook; он запускает тот же index-blob scanner, что и CI. Scanner читает Git
  blobs, не checkout path, и сохраняет secret-safe diagnostics. Trusted Git
  subprocess явно использует check-in normalization `autocrlf=input/eol=lf`,
  поэтому Windows и CI вычисляют один и тот же candidate diff.
- Решение manifest/receipt scanning: digest/OID/Base64 поля G1/POLICY promotion
  manifest и independent-review receipt заменяются во временном scan-view
  только после exact-path closed-schema и subject/hash validation. Manifest
  final bytes декодируются и отдельно сканируются под policy-owned target path;
  invalid manifest не получает частичного исключения.
- Решение evaluator change control: proposal меняет только один CR packet,
  promotion manifest, CHANGELOG и ADR. Manifest ограничен policy-owned target
  paths и содержит base/final hashes и final bytes. Три роли
  product/architecture/security-evaluation добавляют immutable reviews в трёх
  отдельных ancestor commits; promotion может воспроизвести только exact
  manifest bytes. Selector связывает повторные amendments того же target set с
  exact текущими base hashes и candidate final hashes; два конкурирующих
  proposal для одного exact byte-transition остаются ambiguous и отклоняются.
  Proposal, три review additions и promotion base обязаны образовать
  непрерывную single-parent цепь; parallel reviews, merge assembly и
  промежуточные commits отклоняются. Missing/BLOCK/stale/tampered/mixed
  candidates отклоняются.
- Bootstrap: действующая версия evaluator по определению не может авторизовать
  новую lane. Поэтому `CR-017` допускает один вручную наблюдаемый ruleset bypass
  только после PASS/PASS/PASS на exact commit. Bypass удаляется немедленно;
  следующий P1.4 PR обязан пройти обычный required `ci / gate`. Это не
  постоянный code path, wildcard allowlist или скрытый runtime switch.
- Ограничения: локальная механика доказывает scope, bytes, ancestry и separation,
  но не человеческую identity/truth review. Primary Integrator и внешний GitHub
  ruleset остаются отдельными authority layers.

## D-031 — G1 Foundation Ready promotion

- Status: proposed (`CR-018`); not effective before exact promotion.
- Decision: G1 becomes `GO` only when P1.1-P1.13 are DONE, seven criteria have
  current evidence, and three independent roles accept one exact subject in
  sequential commits.
- Promotion changes only the decision, CHANGELOG, PLAN and CONTEXT to manifest
  bytes; BLOCK, missing receipt, ancestry gap or drift is rejected.
- Effective GO permits P2.1 without weakening frozen G0 or later gates.

## D-032 — Dual-authority validation of GitHub pull-request merge commits

- Status: accepted (`CR-019`); exact evaluator bytes require protected promotion.
- Decision: keep `github.sha` as the checked synthetic merge authority and pass
  `github.event.pull_request.head.sha` as a separate event-owned logical head.
  Pull-request validation requires the checked commit to have exactly the
  ordered parents `[base, head]`, requires a linear base-to-head chain, and
  requires identical synthetic/head tree object IDs. Only then may the existing
  closed candidate validator inspect the head-side lifecycle.
- Multi-commit boundary: an ordinary pull request remains one candidate. A
  multi-commit head is admitted only when its final commit is a validated G1 or
  POLICY promotion whose existing verifier proves the proposal, three separated
  reviews, exact bytes and uninterrupted ancestry. Merge-group and push events
  are never unwrapped as pull requests.
- Security consequence: the check-run stays bound to the GitHub synthetic SHA;
  an attacker cannot substitute a head, reorder parents, add merge-only bytes,
  hide a parallel commit or use a caller-provided ref. Missing, malformed,
  mismatched or unexpected event authority fails closed.
- Delivery: the installed evaluator rejects its own synthetic-merge repair.
  Any bootstrap therefore requires separate explicit authorization for one
  audited exact promotion, immediate bypass removal, and an ordinary green
  pull request proving the repaired path. This decision creates no persistent
  bypass, wildcard exemption or runtime switch.

## D-033 — Typed change-control packet identities in secret scanning

- Status: accepted (`CR-020`); exact evaluator bytes require protected promotion.
- Decision: suppress Git object IDs and SHA-256 identities only after a
  change-control packet passes exact path, duplicate-key, schema, identity,
  allowed-path, budget, and policy-catalog validation.
- Fail-closed boundary: unknown fields, malformed hashes, mismatched CR paths,
  unsupported change types, wrong gate decisions, changed budgets, or expanded
  path sets fall back to the ordinary secret detectors unchanged.
- Scope: this recognizes typed metadata only. Non-identity fields remain scanned,
  manifests still decode and scan their target bytes, and no baseline finding,
  gate criterion, specification, or runtime behavior is weakened.

## D-034 — Canonical formatting is part of evaluator acceptance

- Status: accepted (`CR-021`); exact formatting bytes require protected
  promotion.
- Decision: apply the repository-pinned Ruff formatter to the three evaluator
  files reported by the ordinary Python 3.12–3.14 quality matrix. The resulting
  diff is limited to line wrapping and preserves the parsed Python syntax and
  evaluator behavior.
- Delivery: use the existing POLICY proposal, three independent sequential
  reviews, exact manifest promotion, and an ordinary pull request. No ruleset
  bypass is required or authorized for this formatting repair.
- Consequence: future evaluator evidence must include both `ruff check` and
  `ruff format --check`; a lint-only result is insufficient for quality-gate
  acceptance.

## D-035 — Dual-authority validation of protected push merge commits

- Status: proposed (`CR-022`); exact evaluator bytes require protected
  promotion.
- Decision: keep ordinary single-parent push validation unchanged. For an exact
  two-parent push merge, require the event `before` SHA as parent one, derive
  parent two only from the checked commit object, require the merge tree to
  equal that head tree, and reuse the closed linear lifecycle validator on the
  head chain.
- Fail-closed boundary: malformed or extra parents, swapped base, tree drift,
  non-linear ancestry, an ordinary multi-commit chain, missing/BLOCK reviews,
  receipt gaps, or altered promotion bytes reject the push. Pull requests and
  merge groups retain their existing event-authority behavior.
- Consequence: a protected merge no longer reinterprets proposal, three reviews
  and promotion as one mixed candidate; the post-merge push run can attest the
  same exact chain already accepted by the required PR gate.

## D-036 — Read-only protected-merge authority for P2 completion

- Status: proposed (`CR-035`); exact evaluator bytes require protected
  promotion. CR-023 through CR-034 were rejected, failed review/preflight or
  failed protected audit; none was merged. PR #16 was closed without bypass.
- Decision: preserve CR-030's P2.1/P2.14-only completion catalog, immutable
  attempt, successful gate-before-merge, exact merged PR/parents/protected push,
  ancestry, fixed-host bounded transport and true end-to-end 15-second deadline.
- Least authority: only `spec` has exact `actions: read`, `contents: read` and
  `pull-requests: read`; only its validator step receives `${{ github.token }}`.
  No write or ruleset-administration authority is admitted.
- Secret-scan compatibility: five public test-only identities are assembled
  from fixed eight-character fragments; three repeated GitHub identities use
  constants. Scanner code, baseline, suppression and resulting values are
  unchanged. The delta from CR-034 is Ruff formatting only.
- Fail-closed boundary: CR-030 substitution, timing, transport, permission and
  P1 invariants remain unchanged. PR #16 proved policy/spec/dependency/secrets
  green; full formatted quality and protected gate remain mandatory.
- Delivery: POLICY proposal, three separated reviews, exact promotion, ordinary
  protected PR and green post-merge CI. No bypass.

## D-038 — Identity-bound external-evidence scan view

- Status: proposed (`CR-037`). CR-036 was blocked by product review before any
  review receipt, promotion, publication or merge.
- Decision: recognize P2.1/P2.14 external evidence only after the complete
  type-dependent key set, exact GitHub Actions source/repository/run identity,
  whitespace-free branch, event, conclusion, workflow, typed Git object IDs,
  protected-master post-run, merge-to-post-head consistency and GitHub UTC
  timestamp shapes validate. Only then replace typed digests and Git OIDs in
  the detector view.
- Fail-closed boundary: any missing, extra, malformed, cross-reference-mismatched
  or value-incompatible field returns the original document to ordinary secret
  detection. Baseline, detectors, thresholds, completion catalog, external API
  validation and merge policy are unchanged.
- Delivery: POLICY proposal, sequential product/architecture/security reviews,
  exact-byte promotion, ordinary protected PR and green post-merge CI.

## D-039 — Canonical-LF pre-attestation fixture promotion

- Status: proposed (`CR-041`). CR-038 and CR-039 were blocked before complete
  reviews. CR-040 passed all three reviews, but exact promotion preflight
  rejected its CRLF working-copy target against Git's canonical LF index; no
  promotion commit, publication or merge occurred. PR #20 remains unmerged.
- Decision: preserve CR-040's reviewed fixture behavior while deriving manifest
  final bytes from the normalized Git index. For each P2.14 and P2.1 assertion,
  the isolated clone anchors at the parent of the unique task-attestation
  addition, requires `IN PROGRESS` with no attestation, completes the task and
  verifies an exact Git `A` addition before unchanged validation.
- Fail-closed boundary: exact manifest/index byte mismatch, zero or multiple
  additions, missing or non-`IN PROGRESS` task state, surviving attestation,
  non-addition diff status and any completion error reject the lifecycle.
- Scope: only `tests/unit/test_spec_gate.py` changes. Production evaluator,
  specifications, catalogs, CI policy and gate semantics remain unchanged.
- Delivery: repeat sequential product/architecture/security reviews on the new
  LF promotion subject, then exact promotion and ordinary protected PR with
  green post-merge CI. No bypass.

## D-040 — Catalog-derived protected completion evidence for P2

- Status: proposed (`CR-042`); exact evaluator bytes require protected
  promotion.
- Decision: predeclare P2.2–P2.13 in the policy-owned completion catalog with
  the same targeted-test, full-quality, independent-review, protected-PR and
  post-merge evidence required for P2.1/P2.14. Derive the protected-run task
  set from paired external evidence types in that closed catalog rather than a
  separate hard-coded set.
- Fail-closed boundary: an unpaired protected-PR or post-merge evidence type is
  invalid policy; unknown tasks remain rejected; GitHub repository, immutable
  run attempt, successful required gate, exact merge parents/tree, ancestry and
  protected-master push validation remain unchanged.
- Scope: policy catalog, completion evaluator and focused policy self-tests
  only. Product implementation, accepted specifications, gate evidence,
  evidence schemas, credentials, permissions and secret scanning do not
  change.
- Delivery: POLICY proposal, sequential product/architecture/security reviews,
  exact-byte promotion, ordinary protected PR and green post-merge CI. No
  bypass.

<!-- OPEN_DECISIONS -->

## D-042 — State-independent CR-043 dependency-policy self-test

- Status: proposed (`CR-044`); exact test bytes require protected promotion.
- Decision: make the focused CR-043 regression construct both admitted adapter
  dependency lists explicitly before assertion, then add one unreviewed grammar
  and require rejection. Do not change evaluator code, admitted dependencies or
  lock/source/integrity rules.
- Rationale: the original test extended whatever workspace metadata was
  currently present. It passed during policy-first delivery but duplicated both
  Tree-sitter requirements after P2.3 adopted them, causing a false failure.
- Scope: `tests/unit/test_ci_policy.py` only. Specifications, evaluator behavior,
  package metadata, lockfile, workflows, permissions and gate criteria remain
  unchanged.
- Delivery: POLICY proposal, sequential product/architecture/security reviews,
  exact-byte promotion, ordinary protected PR and green post-merge CI. No
  bypass.

## D-041 — Closed Tree-sitter dependency admission for P2.3

- Status: proposed (`CR-043`); exact evaluator bytes require protected
  promotion.
- Decision: admit only `tree-sitter>=0.25,<0.26` and
  `tree-sitter-python>=0.25,<0.26` beside the existing exact Core dependency in
  the adapters package. Keep the exact legacy Core-only dependency list valid
  during the policy-first transition so the evaluator amendment can be
  delivered before P2.3; all other additions, alternate sources, build hooks
  and metadata drift remain rejected.
- Rationale: P2.3 requires a real CST runtime and Python grammar, while the CI
  workspace metadata evaluator correctly rejects dependency changes that were
  not independently reviewed. A closed two-state transition avoids bypass and
  does not authorize JavaScript, TypeScript, Go or repository-selected grammar
  packages.
- Scope: `scripts/ci_policy.py` and focused CI-policy self-tests only. Accepted
  specifications, application packages, lockfile, workflows, permissions,
  secret scanning and gate criteria do not change in this amendment.
- Delivery: POLICY proposal, sequential product/architecture/security reviews,
  exact-byte promotion, ordinary protected PR and green post-merge CI. No
  bypass.

## D-043 — Stage-specific development models and bounded task transfer

- Refinement accepted by user 2026-09-05: ordinary full quality and independent
  product/architecture/security review occur after integration of all required
  gate tasks, with focused tests during implementation. Critical security and
  evaluator changes require early review before downstream reliance. This
  supersedes the original per-increment verification default recorded below.
  Shared checkout is preferred for management, stable read-only review and
  sequential branch-based development; worktrees isolate concurrent writers or
  fixed review inputs. Track their owners and cleanup conditions.
  Rationale: reduce repeated context, review and disk copies while preserving
  complete integrated review. Consequence: freeze review inputs, retain early
  critical-change checks and amend per-task completion enforcement through the
  protected procedure before the new gate cadence can replace mandatory checks.
- Status: accepted operating policy by explicit user instruction 2026-09-05
  (CR-045); protected automation migration remains pending.
- Decision: Sol medium orchestrates, Terra high implements, Luna medium handles
  bounded mechanical work, Sol high performs independent reviews, and Astra is
  capped at medium for narrowly justified critical security/evaluator work.
  Internal implementation and review use bounded Codex subagents with explicit
  model/reasoning configuration and one writer per path, not separate
  user-visible tasks. A spawn receipt proves accepted configuration, not runtime
  identity when the platform does not expose it; unknown identity never causes
  recursive transfers.
- Rationale: use strong reasoning where defects are costly while reducing
  repeated context loading, redundant full tests and coordination overhead.
- Alternative rejected: use the strongest model for every action or create a
  fresh task for every fix; both repeat expensive work without new evidence.
- Consequences: orchestrator validates results and final candidate, records
  task IDs/ownership, and reuses worker context for corrections. One full local
  quality belongs to the final increment; independent review and exact-SHA
  protected evidence remain mandatory. No runtime product architecture changes.
- Scope: [DEVELOPMENT_WORKFLOW.md](DEVELOPMENT_WORKFLOW.md) and agent operating
  instructions. This decision alone does not alter hooks, evaluator, accepted
  specs, branch rules or task-packet schemas.

## D-044 — Academic deadline checkpoint before enterprise expansion

- Status: accepted planning direction by explicit user instruction 2026-09-05
  (`CR-046`); exact documentation reviews/integration are recorded in development-run CR-046.
- Decision: user confirmed defense on 27 September 2026, Asia/Yekaterinburg,
  and one-person execution. First working instructor demo targets 16 September, feedback 17–18;
  meeting confirmation is pending. Readiness target is 24 September 18:00; rehearse on
  the 25th, retain the 26th as reserve. Source time 23:59 is not the defense
  slot. Record outstanding defense/upload slot and instructor/individual-approval
  reference distinctly. Start P9.12 immediately.
- M-A2026 is an additional unversioned academic evidence checkpoint, not a
  replacement for G7/G9, release version, enterprise readiness or PROJECT CLOSED.
  Preserve all original languages/tools/agents/patch/report/notebook requirements,
  real local quantized-model demonstration, applicable submission artifacts and
  independent exact-candidate acceptance. Existing G7/G9 oracles are refreshed
  later for their full product releases.
- Schedule: retain effective G2 → G3 → G4; then prioritize P7.1–P7.3 language
  support, separate P7.17 diagnostic comparisons and P9.16 academic bundle before
  P5/P6 and enterprise hardening. Add explicit P3.12 live connector and P3.13
  model/hardware qualification; do not rewrite completed P1.8 scope.
- Rationale: validate useful audit/repair behavior and complete the assignment
  before investing further in infrastructure. Source-controlled calendar and
  daily active-run reforecast expose missed milestones without inventing results.
- Alternatives rejected: presenting Python-only G4 as complete academic work;
  claiming v1/G9 without enterprise gates; forcing all enterprise components
  into the deadline; editing frozen specs merely to record additional early
  evidence. Each either omits requirements, misstates readiness or delays the
  decisive product evidence.
- Evaluation: supplemental development_e2e_remediation_rate counts independently
  verified repaired expected root causes over all predeclared eligible vulnerable
  root causes. Frozen formulas/thresholds and locked tests are unchanged; early
  diagnostics do not certify production blocking or replace confirmatory tests.
- Compatibility: no public schema, runtime security boundary, current gate
  criterion, evaluator or normative baseline mutation. Changed operational
  dependencies and added task acceptance are tracked in PLAN; their future
  packets/completion catalog admission still need the applicable protected route.
- Scope: [SUBMISSION_PLAN.md](SUBMISSION_PLAN.md),
  [DEVELOPMENT_EVALUATION.md](DEVELOPMENT_EVALUATION.md) and linked operational
  docs. Product code, PROJECT_BRIEF.md, specs and historical gate evidence remain
  intact. Publishing/submitting to people is not performed by this decision.

## D-045 — Explicit local quality and bounded development checks

- Status: proposed evaluator amendment CR-048; not effective before protected
  review, exact-byte promotion and ordinary protected delivery.
- Decision: retain the policy, staged-secret and workflow-security hooks for
  ordinary commit/push. Keep full quality available as the explicit `quality`
  launcher selection and preserve the mandatory protected CI quality matrix.
  A separate `development` selection accepts at most eight distinct regular
  `tests/unit/test_*.py` files, rejects arbitrary options/path traversal, uses
  isolated Python and a locked offline environment, strips parent credentials
  and plugin overrides, and imposes a 360-second execution deadline. Development
  subprocesses have explicit ownership: Windows uses the absolute OS-resolved
  taskkill executable with tree termination; POSIX starts a new session and
  kills the process group. Timeout/interruption cleanup precedes leader reaping
  and has bounded 10-second termination/reap windows. Failure to clean up is an
  error, never a successful test result. Its exit status is
  the targeted pytest result; it is never a full-quality or gate attestation.
- Rationale: reduce repeated full-suite execution while retaining policy and
  secret checks at each commit/push and all protected publication checks.
- Review correction: a direct-child subprocess timeout can leave uv/Python
  descendants alive. Process-tree termination replaces that unpublished design,
  with a real child/descendant regression and OS-termination error negatives.
- Alternatives rejected: hook bypass, removing mandatory CI, arbitrary pytest
  arguments and treating targeted checks as a completed gate. Each loses a
  required control or misstates evidence. The canonical quality script is intact.
- Scope: the hook configuration, launcher, closed CI-policy hook expectations
  and focused CI-policy self-tests only. Product code, frozen specifications,
  gate artifacts and task-completion requirements are unchanged.
- Consequence: the separate CR-049 successor must implement and independently
  review the effective G2 completion audit before per-task completion evidence
  can be consolidated. This amendment alone does not enable that lifecycle.

## D-047 — CR-050 candidate admission and checkpoint provenance

- Status: proposed evaluator successor; effective only after the
  existing protected policy route accepts the exact candidate and its three
  POLICY receipts. The owner-authorized methodology remains: Terra/Luna own
  bounded implementation and mechanics, local checkpoints may preserve
  rollback history, G2-G8 have no independent gate reviews, and one
  product/architecture/security evaluation reviews the complete project after
  G9.
- Decision: bind this policy amendment to the five declared evaluator target
  blobs. The resulting gate evaluator admits product task packets from the
  candidate only after validating their declared base and scope against
  protected authority. Validate every checkpoint delta and the final scope.
  Reject scope
  laundering through unlisted protected files, detached or rewritten checkpoint
  history, alternate packet paths, or self-admission by the candidate PR.
  The only authorized independent receipts are the three POLICY reviews;
  this does not create product reviews for G2-G8.
- Consequence: the successor closes the gap between evaluator amendment
  delivery and later gate-candidate admission while retaining exact-byte,
  fail-closed promotion and the mandatory protected CI/PR path. Historical
  evidence and accepted specifications remain unchanged.

## D-048 — Executable catalog activation at G2 closing

- Status: proposed evaluator amendment CR-052; effective only after the
  existing protected policy route accepts the exact target byte and its three
  specifically authorized POLICY receipts.
- Decision: when G2 promotes P2.12 to `DONE`, promote its already implemented
  `html_markdown_sarif_terminal_rendering` test-catalog entry from `planned` to
  `executable` and bind it to the existing canonical
  `python scripts/quality.py` command. On the integrated G2 candidate, that
  command collects the reporter contract and golden-output tests and remains
  the single integrated gate cycle.
- Rationale: a completed owner may not retain a planned-only test entry. The
  stale state makes the otherwise valid exact G2 promotion fail closed with
  `CATALOG_STALE_PLANNED` even though the executable tests and quality evidence
  exist.
- Scope: one declarative entry in `scripts/spec_gate_policy.json`. No product
  code, accepted specification, evaluator algorithm, test bytes, G2 evidence,
  review cadence, hooks, protected CI or branch protection changes.
- Consequence: G2 can close through its existing exact-byte integrated gate
  path. The three receipts are only for this protected policy mutation; G2-G8
  still have no independent gate reviews, with the combined final review after
  G9 unchanged.

## D-049 — Candidate-first lookup for first integrated gate evidence

- Status: proposed evaluator amendment CR-053; effective only after the
  existing protected policy route accepts the exact target byte and its three
  specifically authorized POLICY receipts.
- Decision: when an integrated-gate promotion path is already present in the
  proposal candidate, use those candidate bytes without evaluating a fallback
  read from the protected base. Read the base only when the candidate does not
  provide that path.
- Rationale: `dict.get(key, fallback())` evaluates `fallback()` eagerly. The
  previous expression therefore rejected the first promotion of a gate whose
  evidence directory correctly did not exist in the base, even though the
  candidate contained the required exact bytes.
- Scope: one lookup expression in `scripts/spec_gate.py`. No accepted spec,
  product implementation, G2 evidence, review cadence, budgets, hook,
  protected CI or branch-protection change.
- Consequence: first-time integrated gate evidence can traverse the existing
  fail-closed chain; missing paths still fail because the evaluator reads the
  base only when no candidate document exists.

## D-050 — State-independent G2 promotion regression fixture

- Status: proposed evaluator amendment CR-054; effective only after the
  existing protected policy route accepts the exact target byte and its three
  specifically authorized POLICY receipts.
- Decision: derive a synthetic pre-promotion plan inside the G2 promotion unit
  test by normalizing only P2.6-P2.13 from either `TODO` or `DONE` to `TODO`,
  then verify that the evaluator promotes exactly those tasks to `DONE`.
- Rationale: the previous test read the live plan and therefore failed after
  the very promotion it was designed to validate, although the integrated
  evaluator and promotion bytes were correct.
- Scope: one regression test in `tests/unit/test_spec_gate.py`; no evaluator
  algorithm, accepted spec, product implementation, evidence rule, hook,
  protected CI or branch-protection change.
- Consequence: canonical quality remains valid on both sides of G2 promotion
  while still proving the exact completion-task transition.

## D-051 — Reusable gate succession and immutable successor admission

- Status: proposed evaluator amendment CR-055; effective only after exact-byte
  POLICY promotion and ordinary protected delivery. It does not advance G3.
- Version 8 replaces `664df0d`, `6b31e38`, `12fd257`, `98d99b2`, `7fc33c8`
  `d12ad81`, `cc5316f` and `d2bb408`. Version 8 copies the path lists
  in two seed-test fixtures to avoid unintended YAML aliases; evaluator and
  policy bytes remain identical to v7. The positive fixture uses an allowed
  adapter path, preserving its inherited forbidden scope. Nonessential
  docstrings were removed
  to keep the
  exact-byte manifest within existing parser scalar limits, preserving v6
  executable AST and all budget enforcement. Parser limits are unchanged.
  Both G3 bootstrap and protected-base successor task budgets
  cover the full scoped base-to-subject retained delta,
  including direct subject-commit writes. Immutable packet identity alone
  does not establish compliance with its execution budget. Per-task file/line
  overflow fails closed even within the global gate budget. G3 pinned packet
  hash checks and cumulative checkpoint/history rules retain their semantics;
  changed final bytes require fresh proposal subjects and all three
  sequential POLICY receipts before promotion. G3 budgets
  are bounded at 96 file touches / 16000 lines using the measured checkpoint
  history plus successor seeds and gate evidence; later gate limits are unchanged.
- G3 packet history requires one addition, permits later scoped modifications,
  rejects deletion/rename/copy, and still binds final exact pinned packet hashes.
  Per-task touch caps include four touches of remediation headroom within the
  global budget. Protected-base successor packet history remains immutable.
- Decision: declare G3-G9 gate requirements and completion tasks once. G3 uses
  exact historical packet hashes and policy-owned fixed scopes as a bounded
  bootstrap, without falsely treating simplified packets as old P2 schema.
  G4-G9 use full-schema packets admitted in the predecessor gate subject and
  carried unchanged through promotion into the next protected base. Admission
  checks the declared base ancestry, exact packet bytes, constrained paths,
  budgets and seed provenance. No candidate can grant itself broader authority.
- Test catalog entries owned by future tasks bind to their final owner's gate
  and canonical quality command. Completed owners require that gate's effective
  GO; declared catalog state alone is never test PASS evidence.
- Alternatives rejected: candidate-owned wildcard scopes, repeated evaluator
  amendments for each P-task/gate, and rewriting historical evidence.
- Consequences: each gate closing must include its successor's constrained
  packets. Missing packets, hash drift or unmet required evidence fail closed.
  G3-G8 use no independent gate reviews. After all G9 implementation and quality,
  one combined final cycle requires three independent product, architecture and
  security/evaluation receipts on the exact G9 subject before closure promotion.
  Ordinal digest ordering and canonical committed-byte readback are mandatory.
  Existing POLICY receipts are a separate protected
  mutation requirement, not authorization for extra product reviews.

## D-052 — Transition-safe closed grammar dependency admission

- Status: proposed evaluator amendment CR-059; effective only after the
  established three-review POLICY route, exact-byte promotion and ordinary
  protected delivery.
- Decision: extend the exact adapter dependency allowlist with the reviewed Go,
  JavaScript and TypeScript Tree-sitter grammar versions while retaining the
  historical minimal state and the current Python-only Tree-sitter state as
  explicit transition states.
- Rationale: `scripts/ci_policy.py` and its self-test are protected evaluator
  targets and cannot be modified by the same implementation candidate they
  authorize. The policy must become effective first, while the current protected
  base must continue to pass before package metadata and the lockfile change.
- Scope: exact final bytes for `scripts/ci_policy.py` and
  `tests/unit/test_ci_policy.py`, encoded in the protected amendment manifest.
  No package metadata, lockfile, product implementation, accepted specification,
  gate evidence, workflow, hook, branch protection or secret-detector behavior
  changes in the proposal.
- Consequence: after protected promotion, a separate constrained P7.1/P7.2
  implementation candidate may add only the three exact registry packages and
  their hash-complete lock records. Any additional dependency or version drift
  remains rejected.

## D-108: Atomic workspace policy migration

21 September 2026, CR-090. The policy migration accepts exactly two complete
workspace states: the current five-package `0.1.0a0` state and the future
six-package `1.0.0rc1` state with the server. One selector compares version,
root dependencies, workspace sources, members and mypy roots as a single
closed tuple. Cross-state mixtures fail. Package metadata and lock checks then
use only the selected state. Secrets, SpecGate and publication checks remain
unchanged.

## D-109: Bind the rc1 migration to the clean publication base

21 September 2026, CR-091. The effective migration selector uses the exact
four-package `0.1.0a0` workspace present on the clean publication base and the
complete six-package `1.0.0rc1` workspace containing worker and server. Test
fixtures construct both missing rc1 packages before any mixed-state mutation.
This supersedes the unpromoted CR-090 target, whose legacy tuple assumed an
intermediate worker state that is absent from the clean base.

## D-110: Validate every commit behind a protected PR tail

21 September 2026, CR-092. A multi-commit pull request may end in one protected
promotion, but every preceding commit is independently classified and validated
against its direct parent. The final checkout snapshot is checked once; earlier
commit checks reuse that immutable checkout only for repository-state binding.
Any invalid earlier member returns its original diagnostic together with a
chain-member diagnostic. Push validation translates the chain diagnostic.

## Открытые решения, не блокирующие P1

- Конкретные external beta datasets после license/leakage review (`P7.6`).
- Численные blocking thresholds после calibration (`P7.9`); до этого advisory.
- OPA/Rego против расширения typed policy evaluator после pilot evidence.
- Web UI scope: до `P6` достаточно API + SCM/CLI; dashboard не входит в Core MVP.
- MicroVM high-assurance sandbox после gVisor compatibility/performance evidence.

## D-111: Deduplicate immutable secret-scan inputs

- Status: proposed by CR-093.
- Decision: scan each unique repository path and Git object ID pair once across the index and candidate commit trees.
- Reason: an unchanged immutable blob has identical bytes, while retaining the path in the identity preserves path-sensitive baselines and forces renamed content to be checked again.
- Consequence: secret coverage is unchanged and repeated CI work is bounded by unique path-object pairs.

## D-112: Validate both supported platform API surfaces

21 September 2026, CR-094. Canonical quality runs distinct Linux and Windows
mypy stages over the same deterministic source inventory before executing unit
tests. Either platform failure blocks unit execution and the candidate. This
prevents a host-native check from hiding invalid guarded platform APIs.

## D-113: Land the de6eabe repair through one owner-approved bypass merge

28 September 2026, CR-095 (owner decision, retroactive). Commit `de6eabe`
reached `main` while `master` was still the protected default branch, so it
never ran the quality gate. It broke 254 unit tests, left 229 files
unformatted, added about 130 lint findings and about 570 mypy errors, and
changed three public schemas (`audit-event`, `audit-run`, `finding-case`:
additive optional `command_operation_evidence`) without a policy amendment.
Because every PR is validated against the whole repository and limited to 64
files, no incremental repair PR can pass. The owner approved one repair PR that
restores a passing `scripts/quality.py`, updates the three
`public_schema_sha256` entries, and is merged once with the ruleset bypassed.
The ruleset is re-enabled immediately and later changes use ordinary gated PRs.
No review record is fabricated for CR-095; this entry is its only record.
The advisory SCM mode keeps publishing a passing check while findings remain
in the audit record and report (SC-CLI-004), as confirmed by the owner.

## D-114: Replace the packet-driven gate with an agile PR workflow

29 September 2026, owner decision. The specification-driven gate (task packets,
PR kinds, 64-file budgets, frozen schema-hash registry with three-review policy
amendments, exact-count secret baseline) cost more effort than it prevented
defects and made the de6eabe repair impossible to land incrementally. CI now
requires `policy`, `secrets`, `dependency` and `quality` only; the `spec` job and
the quality `spec` stage are removed. The secret baseline pins detectors and
filters, while new reviewed digests are approved in the PR that adds them.
`scripts/spec_gate.py` remains available as an optional tool. The workflow is
described in `docs/DEVELOPMENT_WORKFLOW.md`.

## D-115: Advisory findings publish a neutral GitHub check

29 September 2026, owner decision, refining D-113. In advisory mode a FAIL
audit still does not block the merge and the stored outcome stays PASS, but the
GitHub check conclusion is `neutral` with the title "SecureCode AI (advisory):
findings reported" instead of a green `success`. A clean advisory run remains
`success`. Blocking policies and the `new_code` allowance for legacy findings are
unchanged, and GitLab external statuses keep their existing mapping.

## D-116: Mask secret values instead of withholding the whole file

5 October 2026, owner request after independent E2E testing of 1.2.0. A file with a
detected secret was withheld from every model, and the discovery seed read it anyway,
so one credential turned the whole run `INDETERMINATE`. Now such a file is served to
Discovery and the Auditor with every detected secret value replaced by the detector's
redaction marker (`secret-mask@1`, the named downgrade rule that `SC-DATA-002`
requires): line breaks are kept, raw evidence windows of the file stay unavailable,
and the discovery seed skips the file. Masking applies only when the secret stage is
verified for the exact revision; otherwise the file stays `DC4` and withheld, as
before. Masking is applied for every provider, local ones included: the value is
not needed to judge the surrounding code, and one rule is easier to audit than two.

6 October 2026, extension after the 1.2.1 E2E series. Masking now covers every
model-facing input: discovery anchors and scanner evidence windows of such files are
rebuilt over the masked text (same evidence ids and lines, hashes of the masked bytes),
the secret finding itself carries the masked lines around the value, and the Architect
and the readable report read the masked file. A fix that changes a masked line cannot
apply to the original file; it is shown in the report and left for a manual change
together with rotating the secret.

## D-117: A verified secret-detector finding is confirmed by the detector

7 October 2026, owner decision after the 1.2.3 E2E series. Models review a secret
finding with the value masked (D-116); they cannot see whether the literal is a real
credential and often disagree (Auditor CONFIRMED, Skeptic NEEDS_MORE_EVIDENCE), which
left an obvious hard-coded key without a decision. The finding gate gains an authority:
`MODEL_REVIEW` (default, Auditor and Skeptic must agree) and `DETERMINISTIC_DETECTOR`, used only
for deterministic candidates of the `secret-*` rules. With `DETERMINISTIC_DETECTOR` a bound,
successful Auditor receipt is enough and the route is `CONFIRMED` with reason
`DETECTOR_CONFIRMED`; the Auditor and Skeptic verdicts stay on the decision as review
notes. Every other weakness still needs both reviews, and a failed Auditor investigation
still leaves the secret without a decision. The report says "подтверждено детектором
секретов" for such findings.

## D-118: The operator of a trial run may name any OpenAI-compatible endpoint

7 October 2026, owner request. `securecode analyze` reached only DeepSeek (host pinned in
the core admission rule) or a loopback Ollama; base URL, model and key of another service
could not be set. `--provider openai-compatible` reads `SECURECODE_MODEL_BASE_URL`,
`SECURECODE_MODEL` and `SECURECODE_MODEL_API_KEY`. The core admits the profile
`openai-compatible-operator` only under `managed_scan_opt_in` with tenant approval, an
HTTPS base URL whose host equals the endpoint authority, unverified terms and the consent
reference `consent://operator/openai-compatible/<host>`: the operator who names the host
and supplies its key consents to send the masked source there. Everything else is
unchanged: the contract refuses private addresses, plain HTTP and consumer chat sites, the
resolver connects only to globally routable addresses of that host, secrets are masked
(D-116) and data-class limits apply. The request carries only standard Chat Completions
fields (no DeepSeek `thinking`); `max_completion_tokens` is used for `api.openai.com`. The
response check accepts the standard extras other providers add (empty `annotations`,
`refusal: null`, a dated model snapshot, gateway accounting numbers) and still rejects
anything the pipeline cannot use. Without operator prices the spend cap cannot be applied:
the cost is reported as unknown and the 20M-token window bounds the run. The Architect now
calls the same endpoint as the rest of the run; `DEEPSEEK_BASE_URL` no longer redirects it
alone. Loopback servers other than Ollama (vLLM, LM Studio) are not covered yet. The
protected `securecode scan` path is unchanged: it still needs a reviewed provider bundle.

8 October 2026, addendum after the 1.2.7 E2E series: `chat.deepseek.com` was accepted and
received requests. The contract's list of chat products now names more vendor chat hosts
(exact hosts, so `api.perplexity.ai` stays allowed), and an operator endpoint whose host
starts with `chat.` is refused before any profile is built.

## D-119: Each hard-coded credential is its own weakness group

8 October 2026, after the 1.2.7 E2E series. `weakness_group` (and the SARIF
`partialFingerprints` entry) meant "count and alert once", but it was keyed by CWE and file,
so two hard-coded keys of one file became one weakness although each must be rotated. For
credential CWEs (798, 259, 321) a group is now the CWE at overlapping lines of one file: the
narrowest cited ranges seed the groups and a wider finding (the whole file cited by the
model) joins the first group it overlaps without merging two. Code weaknesses keep the CWE
and file as the group: the model often cites another line of the same flow than the scanner
(the import line versus the sink), and splitting them would show one injection twice. The SARIF key becomes `securecodeWeakness/v2` because the
value changed meaning. The Architect still proposes one fix per CWE and file (two patches of
one file would conflict), so one fix may serve two groups. An undecided candidate is folded
into a confirmed finding only when that finding points at the place at least as precisely
(a finding spanning the whole file does not hide a key on one line); folded candidates are
exported in `covered_candidates` with their model counters.

## D-120: Sealed Git calls carry the operator's safe.directory decision

8 October 2026, after the 1.2.7 E2E series. Product Git calls run with system and global
configuration disabled, so a checkout owned by another user (a CI container, a mounted
volume) was refused as dubious ownership even when the operator trusted it, and the run
stopped with an anonymous `LocalProductUnavailableError`. When the checkout belongs to
another user, the operator's own Git (with their configuration) decides once; only if it
accepts the checkout do sealed calls get `safe.directory` for that path, and every other
configuration value stays excluded. Without that trust the run stops before analysis with a
message naming `safe.directory`. `LocalProductUnavailableError` now carries a fixed,
source-free reason code that the CLI prints, and a revision without supported source files
ends with exit code 4 and `NO_SUPPORTED_SOURCE`.
