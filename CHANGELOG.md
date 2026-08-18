# Changelog

Здесь фиксируются значимые изменения SecureCode AI: продукта, scope,
архитектуры, безопасности, требований, планов и пользовательского поведения.
Формат основан на [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), а
версии продукта после первого релиза следуют Semantic Versioning.

Changelog отвечает на вопрос «что и когда изменилось». Причины и альтернативы
архитектурных решений находятся в [docs/DECISIONS.md](docs/DECISIONS.md),
текущий план — в [docs/PLAN.md](docs/PLAN.md).

## Правила ведения

- Каждое наблюдаемое изменение попадает в `Unreleased` в день принятия.
- Используются категории `Added`, `Changed`, `Fixed`, `Security`, `Deprecated`,
  `Removed` и `Decisions`.
- Запись содержит дату, краткий эффект и ссылки на документ/ADR/CR.
- История не переписывается. Ошибочное решение помечается `superseded` новой
  записью.
- При релизе содержимое `Unreleased` переносится в версионную секцию с датой,
  commit/tag и ссылкой на release evidence.

## [Unreleased]

### Added

- 2026-08-18 — завершён `P1.12`: internal
  exact-version structured telemetry в Core, HMAC trace authority, closed
  DC1-only event/measurement surface, canonical JSONL, fail-closed multi-sink
  result precedence и emitter-issued guarded payload capability. First-party
  bounded memory/binary-stream sinks перепроверяют issuer/type/seal/hash/current
  canonical record до I/O; direct raw/forged/copied/mutated payloads, source/
  clock faults, stream short-write/flush failures и exception canaries покрыты
  adversarial tests. Review remediation дополнительно закрыл module-visible
  mint helpers, reentrant stream-wiring, nested-draft и retained-authority TOCTOU,
  exact-enum/non-echo boundary errors, concurrent memory-cap/stream-record
  atomicity, bounded same-thread stream re-entry, flush-time wiring mutation,
  self-signed/resealed capability forgery через emission-scoped exact-object
  provenance с проверкой real emitter code/globals/builtins resolution, истечение
  retained payload после fan-out, exact emitter-owned issuer identity,
  nested-record render race, mutable retained memory storage и parser exception
  echo.
  Новый public wire root/schema, raw-content redactor,
  OpenTelemetry/backend/persistence и P2 instrumentation не добавлены. Packet
  SHA `19a00d3842773a0a91b616abe29c87c9ab5f7e1b73ef590d05b872084aa1cbed`
  получил preimplementation `PASS/PASS/PASS`; product/architecture/
  security-evaluation reviews приняли exact staged digest
  `879f41ceef64e76fb7daab2398f8ab39e8559cd4`. Clean post-commit verification
  implementation commit `5ace16e80730d56f994cb6a24fa4748867a49646`
  повторно прошла 162 targeted и все 885 tests, Ruff/mypy, 85,80% Core branch
  coverage, schema check и strict frozen G0.
- 2026-08-14 — завершён `P1.11`: шесть opaque
  non-sensitive Python CWE-89 repository templates, canonical catalog и
  test-only deterministic factory. Evaluator-side case/tree mapping был
  независимо вычислен и заморожен отдельным commit
  `ad84f403224af55db19b8e2e2e3374e8f178f669` до implementation; golden недоступен
  factory, а LF checkout policy сохраняет hash-pinned bytes на Windows/POSIX.
  Factory использует closed IDs/errors, single-read template validation,
  no-overwrite destination reservation и non-recursive safe cleanup; не читает
  specs/golden, не исполняет source и не реализует scanner/finding/repair.
  Product/architecture/security-evaluation reviews дали `PASS/PASS/PASS` на
  exact digest `f194a1bd66da95642a37487a743144389f229699`. Clean post-commit verification
  implementation commit `f2bb7cbbcfe3e1e80e1c236300c755315fa561bc` повторно
  прошла 43 targeted и все 739 tests, Ruff, mypy, 89,72% Core branch coverage,
  schema exact-byte и strict frozen G0.
- 2026-08-14 — завершён `P1.10`: installable
  first-party `securecode` entry point, closed `CliDoctorResult`/
  `CliErrorResult`, стабильные exit codes `0/2/3/4/5/6`, canonical JSON errors и
  source-free `doctor` с `scan_readiness=NOT_EVALUATED`. CLI не читает исходный
  код, credentials или repository, не открывает сеть/процессы и не реализует
  scan/fix/validate/apply/ci. CI lock authority синхронизирован с новым
  first-party workspace package без ослабления closed policy; schema inventory
  расширен с 13 до 15. Первый implementation review выявил неверную атрибуцию
  mixed unknown command и доверие к unsafe `model_copy` result; remediation
  привязала command только к top-level позиции и ввела повторную canonical/
  runtime-shape validation с fail-closed `INTERNAL_ERROR`. Локально проходят 165
  targeted и все 696 tests, Ruff,
  mypy, 89,72% Core branch coverage, schema/CI-policy/strict-G0 gates, offline
  wheel build, exact 15-schema inventory и clean offline install/entrypoint
  smoke. Independent product/architecture/security-evaluation acceptance дала
  `PASS/PASS/PASS` на exact digest
  `c36748f084e71f3639943b860e5f07538a6b6646`. Clean post-commit verification
  implementation commit `a0dd7849db3e372ca5cc396706f3a166329a1f8a`
  повторно прошла 165 targeted, все 696 tests, Ruff/mypy, 89,72% Core branch
  coverage, schema/CI-policy/strict-G0 gates, offline build, 15-schema wheel и
  clean offline entrypoint smoke.
- 2026-08-14 — завершён `P1.9`: пять versioned
  public workflow roots и deterministic schemas, exact-definition
  graph-independent state machine, обязательный dual-lane fan-out/fan-in,
  bounded investigation/repair accounting, replay-complete hash-linked
  `WorkflowTransitionEvent` и lock-backed process-local `LocalWorkflowRuntime`.
  Runtime-owned journal, run-wide semantic idempotency, exact CAS, cancellation
  и supersession проверяются позитивными, negative, replay/tamper и concurrent
  tests. `AuditEvent`, durable persistence/restart, provider retries, Temporal,
  P2-анализ и trusted outcome routing не добавлялись. После первого review-pass
  registry хранит immutable canonical bytes, investigation действительно
  допускает два дополнительных раунда, superseding HEAD hash-bound в journal,
  transition hashes обязательны, а adapter/policy faults и overflow receipts
  закрываются typed errors. Повторная reliability-проверка добавила обнаружение
  скрытых Pydantic fields, definition-owned producer admission, строгую привязку
  public method к operation, typed error precedence и assignment-immutable
  registry. Portable conformance-suite и матрицы покрывают все model non-success
  outcomes, 31 комбинацию exhaustion, cumulative Architect+validation usage и
  factory-driven snapshot/resume/replay/terminal-state authority. Independent
  product/architecture/security-evaluation acceptance дала `PASS/PASS/PASS` на
  exact digest `f8f34d2d58cdf452857ff5379130e74d269d7df9`. Clean post-commit
  verification implementation commit
  `0431ba66f2a288ee1978950fb01e77e5430c5f04` прошла расширенные 249 targeted и
  все 603 repository tests, Ruff/mypy, 89,72% Core branch coverage, exact-byte
  schema check, 13-schema wheel inventory и strict frozen G0.
- 2026-08-14 — завершён `P1.8`: public
  `ModelRequest`/`ModelCallResult`, exact provider/egress preflight,
  issuer-owned single-use authorization chain, hermetic fake, cross-dialect
  fail-closed normalization и SSRF/DNS-rebinding/peer policy. После первого
  independent review добавлены profile-owned budget/dialect checks,
  manifest-bound provider attempts, immutable keyed payload snapshot,
  restricted-output guard, execution-identity-bound egress manifest, verified
  private-ZDR terms и lock-backed process-local idempotency с concurrent race/
  timeout tests. Второй review-pass закрыл unknown nested native controls,
  permissive validator bypass, remote local-exemption и произвольные callback
  exceptions. Следующий adversarial pass закрыл весь поддерживаемый remote
  control surface: top-level provider errors, неизвестные terminal-поля и
  дополнительные вложенные content/message controls больше не могут
  сопровождать success-shaped envelope и нормализоваться в `SUCCEEDED`.
  Durable/restart idempotency, live provider SDK, retries, workflow routing и
  P2-анализ не добавлялись. Итоговая independent product/architecture/
  security-evaluation acceptance — `PASS/PASS/PASS` на exact digest
  `841fbdfc36a92d0de77d96083bc1d349990f1304`; clean post-commit targeted/full/
  schema/strict-G0 verification прошла на implementation commit
  `030fad9f4567f59def348387d9484a0b4a5eea29`.
- 2026-08-13 — завершён `P1.7`: immutable provider profiles,
  selection-only config precedence и host-bound ephemeral credential leases с
  safe diagnostics/zeroization; DNS/connect/provider execution остаются `P1.8`.
- 2026-08-13 — завершён `P1.6`: versioned `AuditEvent`, stable IDs
  из hashed semantic material, immutable hash-linked `EventStream` и
  deterministic replay projection с fail-closed tenant/run/revision/identity,
  data-class, idempotency, gap/reorder/tamper и exact coverage-snapshot гейтами;
  persistence, transports и workflow runtime не добавлялись.
- 2026-08-13 — подготовлен кандидат `P1.5`: пять closed immutable Pydantic v2
  public roots и deterministic Draft 2020-12 schemas с canonical identity,
  tenant/lineage/coverage/outcome invariants и resolvable semantic validator;
  92 contract/schema tests и 86.54% branch coverage; три reviews и clean
  post-commit verification `cb7fdb6d3efdc6feb4417d3483bb75ede0a3a98f` PASS.
- 2026-08-13 — реализован локально проверенный кандидат `P1.4`: закрытый
  pre-commit launcher на project-owned `uv 0.12.0`, full-SHA GitHub Actions,
  read-only/fork-safe jobs, Python 3.12–3.14 quality matrix, secret-history,
  dependency-integrity/vulnerability и strict zizmor checks. Задача остаётся
  открытой до внешнего GitHub ruleset receipt и демонстрации реально
  заблокированного failing PR; сильная product sandbox isolation не заявляется.
- 2026-08-13 — реализован `P1.3`: exact-pinned Ruff/mypy/pytest/pytest-cov,
  единый offline/no-sync quality runner для format/lint/strict typing/tests,
  Core-only branch coverage `>=80%`, закрытые import allow-lists и fail-closed
  проверки изоляции окружения, static preflight и мутаций репозитория; clean
  matrix подтверждена на CPython 3.12–3.14.
- 2026-08-13 — реализован `P1.2`: один private `uv` workspace и корневой
  `uv.lock` для contracts → Core → adapters, CPython `3.12–3.14` с default
  `3.13`, exact `uv 0.12.0`, Pydantic v2 и hashed build/runtime artifacts;
  non-editable clean install и imports подтверждены на всех трёх Python minor,
  Python 3.11 и metadata/lock drift отклоняются fail-closed (`D-029`).
- 2026-08-13 — завершён `P1.1`: создан ownership-aware repository skeleton
  для contracts/Core/adapters, CLI/server/worker, GitHub/GitLab integrations,
  deployment, tests, demo repositories, notebooks и report; executable code и
  зависимости не добавлялись, packaging/lockfile переданы `P1.2`, а buildable
  Docker image — `P6.12`.
- 2026-08-13 — добавлено единое понятное описание operating model разработки с
  ИИ: Spec-Driven/contract-first, task packets, Primary Integrator и bounded
  subagents, test/evidence gates, durable memory и controlled optimization.
- 2026-08-12 — добавлен targeted research note по RLM, DSPy/GEPA, SkillOpt,
  LLM-generated eval cases, sandbox constraints и staged ablation/promotion;
  методы остаются experimental candidates и не объявлены runtime dependency.
- 2026-08-12 — сохранена исходная постановка проекта и отделена от дальнейших
  расширений: [PROJECT_BRIEF.md](docs/PROJECT_BRIEF.md).
- 2026-08-12 — создана исследовательская база с научными работами, стандартами,
  benchmarks и конкурентной рамкой: [RESEARCH.md](docs/RESEARCH.md).
- 2026-08-12 — зафиксированы целевая graph-based архитектура, evidence graph,
  bounded investigation/repair loops и validation ladder:
  [ARCHITECTURE.md](docs/ARCHITECTURE.md).
- 2026-08-12 — зафиксирована продуктовая модель offline CLI, CI worker,
  backend control plane и GitHub/GitLab adapters:
  [PRODUCT.md](docs/PRODUCT.md).
- 2026-08-12 — создан журнал архитектурных решений:
  [DECISIONS.md](docs/DECISIONS.md).
- 2026-08-12 — создан master plan от definition baseline до v1.0 и закрытия
  проекта с фазами `P0–P9`, gates `G0–G9` и traceability:
  [PLAN.md](docs/PLAN.md).
- 2026-08-12 — создан постоянный компактный контекст проекта:
  [CONTEXT.md](docs/CONTEXT.md).
- 2026-08-12 — добавлен project-local skill
  [securecode-project-navigator](.agents/skills/securecode-project-navigator/SKILL.md),
  read-only context snapshot helper и обязательное подключение через
  [AGENTS.md](AGENTS.md).
- 2026-08-12 — принят Spec-Driven Development operating model, создан
  [specification guide](docs/SPEC_DRIVEN_DEVELOPMENT.md), namespace
  [`specs/`](specs/README.md) и constrained LLM
  [task-packet template](specs/templates/implementation-task.yaml).
- 2026-08-12 — импортирован полный Deep Research report: hash-verified raw
  source, provenance manifest, impact review, project research protocol, claim
  ledger, search log и amendment log в [`docs/research/`](docs/research/README.md).
- 2026-08-12 — создан focused
  [prompt-injection threat model](docs/security/PROMPT_INJECTION.md) для
  untrusted code/SCM/tool content, refusal induction, provider fault states,
  attack corpus и acceptance oracles.
- 2026-08-12 — SDD operating model дополнен правилами разработки основным
  Codex-agent и ограниченными субагентами; task-packet template теперь фиксирует
  owner role, execution mode, exclusive paths и structured handoff.
- 2026-08-12 — создан decision-complete specification baseline `0.1.0`:
  product/system/domain/API/events/CLI/policy/SCM/report contracts, workflow
  state machines, data/capability policies, frozen MVP evaluation и полная
  [traceability](specs/traceability/README.md).
- 2026-08-12 — создан полный [system threat model](docs/security/THREAT_MODEL.md)
  с trust boundaries и `TM-001–TM-024`, а также G0 evidence packet в
  [`artifacts/gates/G0/`](artifacts/gates/G0/checklist.md).

### Changed

- 2026-08-13 — `G0 Definition Ready` закрыт: CR-014/015/016 интегрированы,
  baseline `0.2.0` получил три independent exact-hash `PASS`, immutable commit
  `f5cd4ef2a0f7130d16cb2c206091908be71b0702`, отдельную effective attestation
  и strict frozen-validator `PASS`; разрешён только `P1 Engineering Foundation`.

- 2026-08-13 — принят `CR-014`: baseline `0.2.0` требует два
  independent discovery lane. SAST/AST/taint/SCA/secret output — `RawSignal`;
  LLM Auditor интерпретирует каждый normalized candidate, а mandatory
  model-native lane ищет candidates без scanner seed и не пропускается
  при zero deterministic signals. Non-success даёт `INDETERMINATE`, а не clean.
- 2026-08-13 — `CR-015` синхронизирован с product/plan/traceability:
  Git/README/dependencies/tests/notebook, PDF/HTML experiments report, data
  links/fixed-seed generator, clean-room reproducibility, Dockerfile, web launch
  instructions, 2–5 minute screencast, public-link и administrative checks теперь
  имеют normative IDs, tasks, tests и G9 evidence.
- 2026-08-13 — ограниченно принят `CR-016`: RLM/DSPy/GEPA/SkillOpt и
  synthetic generation разрешены только в isolated offline P7 Evaluation Lab;
  они не Core/runtime dependency, production agents не self-promote, а promotion
  требует held-out/security/human gates.
- 2026-08-12 — `D-016` дополнен фактическим evidence роли субагентов: product,
  architecture и security/evaluation reviewers нашли разные классы дефектов,
  после чего единый Primary Integrator свёл исправления и повторил validation;
  право самостоятельно менять baseline субагентам не предоставляется.
- 2026-08-12 — targeted source review OpenAI Codex Security выявил, что
  заявленный гибрид не полностью закреплён в normative workflow: clean scanner
  path допускает отсутствие model-native discovery. Открыт `CR-014`; G0 freeze
  приостановлен до явного решения и delta review.
- 2026-08-12 — project navigator усилен обязательной проверкой predecessor gate
  до implementation-изменений, явным fail-closed переходом между фазами и
  протоколом тестовых доказательств, разделяющим self-tests платформы и
  генерируемые security regression tests.
- 2026-08-12 — требование «только локальная LLM» расширено до
  provider-agnostic model layer; локальный endpoint остаётся поддерживаемым
  deployment profile (`D-002`).
- 2026-08-12 — целевой продукт расширен от локального прототипа до единого Core
  с CLI, CI-connected и managed режимами (`D-007`, `D-008`).
- 2026-08-12 — Auto-Fix определён как проверяемый patch candidate, а не
  автоматическая гарантия безопасности (`D-006`).
- 2026-08-12 — план разделяет Core MVP `v0.1` и Enterprise MVP `v0.2`, чтобы
  control plane строился после проверки сквозного security vertical slice.
- 2026-08-12 — master plan обновлён до `0.2`: `P0.14` теперь создаёт
  decision-complete specification baseline, добавлены `P0.16`, `P1.13` и
  contract/spec gates.
- 2026-08-12 — master plan обновлён до `0.3`: добавлен `P0.17`, усилены
  acceptance criteria `P0.2/P0.3` и research evidence gate `G0`.
- 2026-08-12 — master plan обновлён до `0.4`: `P0.10` начат, provider/agent
  contracts и `G3/P8.3` требуют fail-closed обработки refusal, incomplete,
  filtered, invalid и provider-error outcomes.
- 2026-08-12 — master plan обновлён до `0.5`: P0 definition tasks получили
  проверяемые артефакты; `G5/G6` до calibration являются advisory pilot, а
  production `new_code` blocking перенесён после `P7.9`.
- 2026-08-12 — master plan обновлён до `0.6`: добавлен `P0.18` с обязательным
  independent completion audit и strict frozen-commit oracle перед effective
  G0; создан `READINESS_AUDIT.md`.
- 2026-08-12 — перед первым baseline commit добавлен repository hygiene
  `.gitignore` для secrets, environment, Python/build/cache и local runtime
  artifacts; prefreeze secret-pattern scan не нашёл candidate files.
- 2026-08-12 — подготовлен, но не запущен первый constrained implementation
  packet `work/task-packets/P1.1.yaml`; его precondition требует effective G0 и
  strict validator exit `0`.
- 2026-08-12 — релизы названы однозначно: `Core MVP v0.1`, `Enterprise Workflow
  MVP v0.2 — pilot only`, multi-language beta, RC и v1.0.

### Fixed

- 2026-08-12 — полная копия задания восстановила пропущенные в первоначальной
  выдержке условия: дедлайн, команду 3–4 человека/согласование индивидуального
  выполнения, формат репозитория и отчёта, Dockerfile/скринкаст для веб-сервиса,
  data-link/fixed-seed policy, clean-room воспроизводимость и открытые ссылки.
  Исправление зафиксировано в `PROJECT_BRIEF.md`; G0 traceability требует delta.
- 2026-08-12 — context snapshot helper сделан совместимым с Windows PowerShell
  5: исходник остаётся ASCII-only, а Markdown явно читается как UTF-8.
- 2026-08-12 — G0 evidence recheck исправил research drift: arXiv `2509.22097`
  в актуальной v5 называется SecureVibeBench и сообщает 23,8%, а не старые
  15,2%; ledger сохраняет version/scope limitation и не делает число KPI.
- 2026-08-12 — два независимых G0 review cycles устранили несовместимые outcome
  enums, fail-open precedence, неполные evaluation denominators, policy/provider
  schema loopholes, stale PVBench source, SCM identity, worker protocol и
  threat/privacy traceability; три финальных definition reviews дали `PASS`.

### Security

- 2026-08-12 — код не покидает CI runner по умолчанию; передача полного
  repository snapshot требует opt-in (`D-009`).
- 2026-08-12 — blocking status привязан к точному HEAD SHA, stale runs получают
  `superseded` (`D-010`).
- 2026-08-12 — default rollout использует `new_code` gate и не блокирует весь
  legacy debt (`D-011`).
- 2026-08-12 — untrusted repository, sandbox, prompt injection, tool allowlist,
  secret redaction и human approval включены в обязательные gates плана.
- 2026-08-12 — принят двухконтурный outcome protocol: отказ модели, safety
  filter, пустой/неполный ответ, invalid schema, timeout или provider error не
  могут означать `no_finding/PASS`; blocking run становится явно
  `INDETERMINATE/ERROR` (`D-015`).

### Decisions

- 2026-08-12 — приняты `D-001–D-011`; `D-012` о runtime abstraction остаётся
  proposed до сравнительного исследования.
- 2026-08-12 — принят `D-013`: accepted specs и executable contracts становятся
  нормативным источником реализации; implementation agent не может ослаблять
  спецификацию, evaluator или gate evidence.
- 2026-08-12 — принят `D-014`: external/LLM research становится основанием для
  ADR/spec только после primary-source resolution, scope check и provenance.
- 2026-08-12 — принят `D-015`: repository/SCM/tool content не имеет instruction
  authority, а `ModelCallStatus`, `FindingVerdict` и `AuditRunOutcome`
  разделены, чтобы исключить refusal-induced false pass.
- 2026-08-12 — принят `D-016`: основной Codex-agent остаётся Primary Integrator,
  а субагенты получают только независимые task packets с непересекающимися
  writes и обязательной повторной проверкой результата.
- 2026-08-12 — приняты `D-017–D-026`: Python-first Core MVP с обязательными
  Python/JS/Go к финалу; GitHub-first reference SCM; LocalRuntime +
  TemporalRuntime; PostgreSQL/Temporal queues; content-addressed BlobStore;
  rootless OCI/gVisor sandbox; `DC0–DC4` egress/retention; frozen evaluation;
  domain-first schemas и typed policy/workflow contracts.
- 2026-08-12 — канонический порядок реализации: deterministic facts → evidence
  and agent investigation → root-cause repair → sandbox validation → CI/SCM →
  backend → multi-language → enterprise hardening.

## Change request register

| ID | Дата | Изменение | Статус | Влияние/ссылки |
|---|---|---|---|---|
| `CR-001` | 2026-08-12 | Разрешить local/cloud/corporate LLM endpoints через env/config | `accepted` | `D-002`, provider adapter и egress policies |
| `CR-002` | 2026-08-12 | Использовать workflow graph, evidence graph и bounded harness loops | `accepted` | `D-003–D-005`, P3–P4 |
| `CR-003` | 2026-08-12 | Добавить CLI, CI bot и backend control plane как режимы одного Core | `accepted` | `D-007–D-009`, P5–P6 |
| `CR-004` | 2026-08-12 | Ввести master plan, формальные gates и change control | `accepted` | [PLAN.md](docs/PLAN.md), G0–G9 |
| `CR-005` | 2026-08-12 | Ввести обязательный project-local skill для восстановления и сохранения контекста | `accepted` | `P0.15`, `AGENTS.md`, `securecode-project-navigator` |
| `CR-006` | 2026-08-12 | Перейти на Spec-Driven Development и constrained task packets для LLM | `accepted` | `D-013`, `P0.14`, `P0.16`, `P1.13`, `specs/` |
| `CR-007` | 2026-08-12 | Ввести research protocol и evidence gate для Deep Research/LLM claims | `accepted` | `D-014`, `P0.17`, `docs/research/`, усиленный `G0` |
| `CR-008` | 2026-08-12 | Защитить аудит от прямой/скрытой prompt injection и refusal-induced fail-open | `accepted` | `D-015`, `P0.10–P0.12`, `P1.8`, `P3.2/P3.5/P3.6`, `P8.3`, threat model |
| `CR-009` | 2026-08-12 | Зафиксировать Python-first Core MVP, GitHub-first reference SCM и pilot-only release semantics | `accepted` | `D-017–D-019`, P0.4–P0.7, product spec |
| `CR-010` | 2026-08-12 | Выбрать LocalRuntime + TemporalRuntime и connected infrastructure baseline | `accepted` | `D-020–D-023`, system architecture spec |
| `CR-011` | 2026-08-12 | Ввести normative data classification/egress/retention и full-system threat model | `accepted` | `D-024`, TM-001–TM-024, security specs |
| `CR-012` | 2026-08-12 | Убрать выдуманный confidence 0.85 и запретить production blocking до calibration | `accepted` | `D-011` amended, `D-025`, P5/G5/P7.9 |
| `CR-013` | 2026-08-12 | Заморозить SDD baseline 0.1.0, contracts, evaluation и traceability для G0 | `accepted` | `D-026`, `specs/`, G0 evidence packet |
| `CR-014` | 2026-08-12 | Добавить независимый model-native discovery lane с прямым bounded read-only анализом кода наряду с deterministic analyzers | `accepted` | `D-027`, baseline/stage catalogue `0.2.0`, provider/egress/capability/workflow/domain/evaluation/traceability delta; evidence `PA-011–PA-013` |
| `CR-015` | 2026-08-12 | Восстановить пропущенные обязательные условия сдачи из полной исходной формулировки | `accepted` | Corrected product/plan/traceability; deadline year/timezone and individual approval remain tracked external G9 inputs |
| `CR-016` | 2026-08-12 | Добавить evaluation lab для synthetic cases и контролируемой офлайн-оптимизации prompt/skill; проверить sandboxed RLM как discovery strategy | `accepted — limited P7 scope` | `D-028`, P7.12–P7.16; not Core/runtime dependency, no production self-modification; evidence `EO-001–EO-006` |

## Release history

Релизов пока нет. Первый планируемый продуктовый инкремент — Core MVP `v0.1`
после прохождения `G4`; дата определяется после закрытия `G0` и оценки
трудоёмкости decision-complete scope.
