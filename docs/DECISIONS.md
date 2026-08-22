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

## Открытые решения, не блокирующие P1

- Конкретные external beta datasets после license/leakage review (`P7.6`).
- Численные blocking thresholds после calibration (`P7.9`); до этого advisory.
- OPA/Rego против расширения typed policy evaluator после pilot evidence.
- Web UI scope: до `P6` достаточно API + SCM/CLI; dashboard не входит в Core MVP.
- MicroVM high-assurance sandbox после gVisor compatibility/performance evidence.
