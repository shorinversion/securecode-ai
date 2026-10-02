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

- 2026-10-02: OWASP Benchmark for Python, конфигурация «согласие трёх проверок»: Поиск
  (модель без подсказок), Аудитор (модель проверяет находки сканеров) и вторая модель;
  CWE остаётся, если её назвали минимум две проверки из трёх (`--consensus` в
  `scripts/owasp_benchmark_python.py`). С gpt-oss-120b и Luna — 0,82 и precision 88,9%
  против 0,80 и 85,6% у модели без сканеров; пересчитано по сохранённым ответам моделей,
  без новых запросов. [report/benchmark-v2](report/benchmark-v2/README.md).
- `scripts/build_site_pages.py` собирает страницы отчётов сайта из Markdown.

### Fixed

- 2026-10-02: CI запускается на push в `main` (раньше — в несуществующую `master`).

## [1.1.0] - 2026-10-01

### Added

- `securecode analyze`: полный конвейер (сканеры, Поиск, Аудитор, Скептик) с
  исправлениями Архитектора. Исправление проверяется `git apply --check`, синтаксическим
  разбором и повторным сканированием; `--patch-dir` сохраняет `.diff`, `--no-fix`
  отключает исправления.
- Отчёт Markdown/HTML на русском: фрагмент уязвимого кода, названия CWE и категорий
  OWASP Top 10, объяснение и diff, список незавершённых проверок.
- Бенчмарк v2: CVEfixes (3000 файлов, 118 CWE) и OWASP Benchmark for Python (1230 кейсов);
  Semgrep, Bandit, gosec, ESLint, DeepSeek, GPT-5.6 Luna, GLM-5.3 и модели с открытыми
  весами (gpt-oss, Gemma 4, Qwen). Отчёт: [report/benchmark-v2](report/benchmark-v2/README.md).
  На OWASP модель проверяет находки сканеров, как Аудитор: SecureCode с gpt-oss-120b —
  оценка 0,78 и precision 89,0% против 0,16 у Semgrep и Bandit.
- Notebook показывает фрагменты кода, полученные по ссылке из единого контракта.
- Документы [OPERATIONS](docs/OPERATIONS.md), [REPRODUCIBILITY](docs/REPRODUCIBILITY.md)
  и [IDEAS](docs/IDEAS.md); README в стиле проекта со встроенным видео.

### Fixed

- Детектор секретов принимал за секреты идентификаторы, URL, UUID, публичные ключи и
  сгенерированные имена с хешем; такие файлы не отправлялись модели (401 из 600 файлов
  CVEfixes, теперь 14 пар с настоящими секретами).
- Полный конвейер реже деградирует на крупных файлах: окно контекста DeepSeek, вызов
  инструмента, записанный текстом, пропущенное корневое доказательство в ответе Поиска,
  пояснения Скептика.
- urllib3 2.8.0 и virtualenv 21.7.15 закрывают опубликованные CVE в зависимостях.

## [1.0.1] - 2026-09-29

### Fixed

- `quickstart.py --demo` падал в Docker после клонирования на Windows с
  `core.autocrlf=true`: скрипт `demo-entrypoint.sh` получал окончания строк CRLF.
  `.gitattributes` закрепляет LF для `*.sh`, а образ дополнительно удаляет `\r`.
  Проверено в чистом клоне тега `v1.0.0`.

## [1.0.0] - 2026-09-29

Первый выпуск: полное покрытие курсового задания ([docs/PROJECT_BRIEF.md](docs/PROJECT_BRIEF.md)).
Соответствие по пунктам — в [итоговом отчёте](report/final-submission.md#соответствие-заданию).

### Added

- Демо Аудитор → Архитектор работает на локальной Qwen 2.5 Coder 7B Q4_K_M и на
  DeepSeek (`--provider deepseek`, профиль с согласием владельца и лимитом расходов);
  оба прогона `COMPLETED` с проверенным патчем (#91).
- Отчёт демо `security-report.md/.html` с CWE, категорией OWASP Top 10, severity,
  строкой, diff Auto-Fix и ограничениями; режим `--provider offline` (#93).
- `python deploy/docker/quickstart.py --demo`: запуск проверяющим одной командой
  (Docker; DeepSeek при наличии ключа, иначе детерминированный lane), `--provider local`
  для Ollama (#88, #93).
- Notebook `notebooks/securecode_demo.ipynb` с сохранёнными выводами: загрузчик, AST,
  секреты, OSV, CWE-сканеры, единый контракт, агенты, отчёт, метрики (#93).
- Итоговый отчёт `report/final-submission.md/.html` и README с быстрым стартом (#94).

### Changed

- Advisory-режим публикует GitHub check `neutral` при наличии находок вместо `success`
  (D-115, #92).
- Процесс разработки упрощён до agile PR-workflow (D-114, #87); интеграционные тесты
  демо входят в CI.

### Fixed

- Узлы tree-sitter сравнивались через `is` в 32 сканерах; исправлены дефекты
  Go-сканеров. Recall детерминированного lane на 600 кейсах CVEfixes вырос с 19.7% до
  25.7%, сбои сканера сократились с 253 до 92; hybrid на held-out на уровне Semgrep (#89).
- OSV-клиент впервые работает с api.osv.dev: чтение тела ответа при
  `Connection: close` и идентификаторы advisory в смешанном регистре (#93).
- Валидатор ответов удалённой модели принимает реальные поля DeepSeek (`logprobs`,
  учёт кеша в `usage`) (#91).
- Скептик получает собственную tool-сессию и бюджет; путь Аудитор → Скептик → FAIL
  снова даёт результат (#88).

### Security

- Инструменты модели не читают сырые файлы с обнаруженным секретом (#88).
- Контекст сборки демо-образа не включает `deploy/docker/.env` и `.local/` (#93).

## Before 1.0.0

- 2026-09-27: Подготовлены итоговый HTML-отчёт, сценарий скринкаста и обезличенная квитанция реального локального Qwen-прогона; README обновлён на русский-first и актуальную Ollama 0.34.4.
- 2026-09-27: Исправлены неверный SHA закреплённого foundation-профиля и устаревшие GitHub comment tests, чтобы соответствовать проверенному annotation receipt контракту.
- 2026-09-27: Итоговый отчёт и benchmark README уточняют binding кандидата: текущая правка CLI-профиля блокирует повторную агрегацию, поэтому сохранённые метрики обозначены архивными; добавлен фактический провал многоязыковой интеграционной suite.
- 2026-09-27: В итоговой таблице контракт finding со ссылкой на EvidenceGraph отделён от отсутствующего поля фрагмента кода; требование помечено частичным.
- 2026-09-27: P9.2-P9.6 отмечены `IN PROGRESS` по фактически подготовленным материалам и открытым критериям; дата сдачи P9.12 исправлена на 27 сентября по сообщению владельца.
- 2026-09-27: Fixed connected CLI facade imports needed by the submission demo; the focused MVP and P9.17 integration suites pass (57 tests).

- P8.7 now enforces bounded per-tenant API request ceilings from the durable SQLite control-plane store, surviving server restarts; quota storage failures return an explicit unavailable response.

- Worker scans now render canonical SARIF beside the JSON report and publish it
  through the existing content-addressed, retry-safe artifact upload path.
- P6.10 wires source-free run-action audit events to verified, repository-scoped audit exports and exposes bounded low-cardinality operational telemetry.
- P6.12 adds a Compose deployment for the HTTPS control plane and connected
  worker, with an API readiness probe, loopback-only host binding, non-root
  hardening and a source-verified runtime environment inventory.

- CR-094 makes canonical quality type-check every source file against both Linux and Windows APIs before unit tests.

- P9.21 replaces dynamic Windows-only CLI imports with ordinary guarded imports so package boundaries, Linux typing and Windows typing validate the same atomic-output implementation.

- CR-093 deduplicates immutable secret-scan blobs by repository path and object ID, retaining rename-sensitive coverage while reducing repeated CI work.

- P9.19 fixes cross-platform static analysis of guarded Windows and POSIX APIs; Linux and Windows mypy now validate the same runtime code without weakening platform checks.

- CR-092 makes a protected promotion tail validate every earlier pull-request
  commit against its direct parent. An invalid implementation or direct
  evaluator edit can no longer be hidden behind a valid final promotion.

- CR-091 supersedes the unpromoted CR-090 target after independent review
  found stale coupling to a five-package development base. The replacement
  binds the actual four-package legacy workspace and the complete six-package
  `1.0.0rc1` workspace, including both worker and server lock entries.

- CR-090 prepares an atomic workspace policy migration for the private
  `1.0.0rc1` publication candidate. The protected policy accepts exactly the
  complete legacy workspace or the complete six-package rc1 workspace,
  rejects mixed states and retains bounded quality execution.

### P9.16 academic-content and validator remediation (2026-09-16)

- Replace the metadata inventory report with a reproducible academic report
  containing the problem, architecture, method, 312-cell experiment metrics,
  bounded real-local result, limitations and conclusions in Markdown, HTML and
  PDF.
- Extend the executed submission notebook with the pinned public CWE-89 audit
  composition, aggregate benchmark results and the redacted real-local runtime
  receipt. The notebook executes no development-corpus source and makes no
  model call.
- Close semantic substitution of the manifest, Markdown, HTML and PDF by
  recomputing exact deterministic bytes and closed status/limitation values.
  A canonical quality receipt must bind the exact repository subject before a
  bundle can be built or validated. The builder also requires the benchmark
  aggregate and independent recomputation to be byte-identical at the accepted
  digest and checks the closed 312-cell, failure and repair facts.
- Update the root README with current demo and notebook commands, expected
  results, real-model prerequisites and the configured Git remote status.
- Normalize notebook files to LF and disable PDF newline normalization while
  retaining reviewable diffs, so staged artifacts have stable cross-platform
  bytes and pass Git's whitespace and candidate checks.
- Record Wazuh-derived design ideas as research only: staged event analysis,
  rule test traces, stable rule identities and file-integrity checks. No Wazuh
  code, ruleset or privileged active-response behavior is copied.

### M-A2026 independent-review remediation (2026-09-16)

- Route JavaScript, TypeScript and Go CWE-89 scanner facts through the production
  RawSignal normalization boundary instead of a test-only adapter. Add JSX/TSX,
  common callable forms and receiver-qualified Go method identities.
- Enforce ProgramGraph aggregate node and edge budgets before large allocation
  or sorting, including call edges and multi-index inputs.
- Isolate development-corpus execution from the trusted Docker observation and
  ACK channel. Adversarial tests now reject forged frames, stdin challenge theft
  and direct `/proc` descriptor access; all 24 pinned cases pass the hardened
  oracle.
- Replace stale benchmark outputs with a complete `not_run` matrix before model
  preflight and preserve unknown scanner counts. Rerun all 312 cells after the
  oracle change; aggregate and independent recomputation are byte-identical at
  `deae563fe08580a2ed3dc447ba19d020f31e63797eb8b83c8b6737ad3a674407`.
- Bind the P9.17 real-local receipt to observed Ollama `0.16.2`, the exact Qwen
  model digest and `Q4_K_M` before and after calls. The retained public evidence
  records lane agreement, proposed patch hash, passed ephemeral validation and
  unchanged input while excluding the raw patch.
- The canonical integrated candidate passes spec, format, lint, strict types and
  1,613 tests, with ten expected platform or opt-in Docker skips, 81.61% Core
  branch coverage and `QUALITY=PASS`.

### P9.16 PDF and semantic receipt hardening (2026-09-16)

- Add a deterministic PDF, machine-readable quality receipt and exact
  candidate subject digest to the academic bundle. The validator checks every
  deliverable and evidence hash, the quality claims, the complete notebook
  execution order, and the bounded `NOT_READY` statement.
- Include raw development run records, P7.4 implementation evidence and the
  redacted P9.17 runtime/validation receipts without retaining corpus source,
  prompts, raw model responses or the model-proposed patch body.

### M-A2026 integration - Core facade boundary repair (2026-09-15)

- Routed the P7.4 portfolio scanner's accepted contract value types through the
  existing Core facade so adapters retain the closed inward dependency rule.
- The integrated canonical quality cycle now passes with 1588 tests, 8 expected
  platform or opt-in skips, 81.56% Core branch coverage and `QUALITY=PASS`.

### P9.16 - reproducible M-A2026 academic snapshot (2026-09-15)

- Added a deterministic metadata-only builder and fail-closed validator for the
  M-A2026 bundle, with exact hashes for repository evidence and generated
  deliverables. It rejects missing evidence, output collisions, hash drift, and
  a notebook that is not executed.
- Added an executed submission notebook, Markdown and self-contained HTML
  reports, delivery manifest, and clean-replay instructions. The bundle records
  `NOT_READY` and its external and delivery blockers without claiming G7, G9,
  v1.0, `PROJECT CLOSED`, or release readiness.
### P9.17 - bounded real local instructor demo (2026-09-15)

- Added a path-isolated runner for a bounded local Python CWE-89 demonstration.
  It binds deterministic and independent model-native discovery to the same
  immutable snapshot, uses a separate authorized literal-loopback repair call,
  keeps source and raw model output out of JSON/HTML reports, and applies a
  proposed patch only to an ephemeral copy.
- The connector now supports explicit bounded temperature and seed controls for
  reproducible local sampling. Focused tests cover the runner, connector and
  local qualification boundary; a real local development case is recorded only
  as diagnostic evidence, with no gate, release, accuracy or readiness claim.

### P7.4 - conservative deterministic CWE portfolio (2026-09-08)

- Add sealed-index, source-free scanner facts for direct recognized flows in
  Python, JavaScript, TypeScript and Go: command injection (CWE-78), path
  traversal (CWE-22), SSRF (CWE-918) and an unguarded object-lookup sample
  (CWE-862).
- Route the deterministic facts through the existing RawSignal normalization
  boundary with exact revision/path/content provenance. The rules are bounded
  examples only; they do not claim general SAST coverage or produce verdicts.

### P7.17 - current-candidate development benchmark (2026-09-08)

- Bind the 24-case development corpus, current P7.1-P7.3 candidate, evaluator
  components and qualified loopback Qwen profile in a 312-cell run plan.
- Implement and execute all five configurations: the product deterministic
  baseline, scanner-seeded investigation, model-native discovery, one-shot
  review and full hybrid. Preserve every invalid structured model response as
  a fail-closed non-success in the original denominator.
- Independently recompute byte-identical aggregate evidence and publish exact
  limitations. All 312 cells are recorded with no `not_run` cells, but 171
  model cells failed structured-output validation; the study therefore remains
  incomplete, performs no repair, and makes no calibration, G7/G9, release or
  security claim.
- Add independent SC-EVAL-018 full-hybrid origin attribution, zero-scanner
  matrix, deterministic-candidate Auditor receipt coverage and exact global
  reconciliation; bind opaque aliases and reject deterministic model-fact or
  invalid category/alias contamination.

### P7.3 — sealed language-neutral program graph (2026-09-08)

- Add an internal authority-sealed ProgramGraph that binds exact repository,
  revision, path and content identities while retaining only structural ranges,
  symbol identities and source-free canonical hashes.
- Convert independently revalidated Python, JavaScript, TypeScript and Go
  symbol indexes plus current CWE-89 scanner facts into deterministic unique
  containment and local data-flow edges; explicit bounded source-free call
  facts can connect sealed callable symbols across files within one language.
  No call-target inference or interprocedural precision is claimed.
- Keep EvidenceGraph separate and all public wire schemas unchanged. This
  contributes P7.3 only; G7 remains open.

### P7.2 — bounded Go CWE-89 facts (2026-09-08)

- Add sealed Tree-sitter Go symbol indexes with exact parser and source-content
  binding, recovered-parse diagnostics, and the existing parser resource limits.
- Add deterministic bounded `net/http` query to `fmt.Sprintf` or string
  concatenation to `db.Query`/`Exec`/`Raw` facts; parameterized controls emit no
  fact and malformed parses fail closed.
- Extend synthetic multi-file common evidence/verdict/report ingress coverage to
  Go. This contributes P7.2 only; cross-file flow remains P7.3 and G7 is open.

### P7.1 — bounded JavaScript and TypeScript CWE-89 facts (2026-09-08)

- Add sealed Tree-sitter JavaScript/TypeScript symbol indexes with exact parser
  identity, content binding, recovered-parse diagnostics and the existing
  source/node/symbol/depth/diagnostic limits.
- Add deterministic source-to-interpolation-to-SQL scanner facts for admitted
  JavaScript/TypeScript bytes; parameterized controls emit no fact and parser
  non-success remains fail-closed.
- Add synthetic multi-file positive/negative focused coverage through the
  common deterministic signal-normalization ingress. This contributes P7.1
  only; it neither establishes G7 nor changes finding/verdict policy.

### CR-059 — transition-safe grammar dependency policy amendment (2026-09-08)

- Propose exact closed-policy admission for `tree-sitter-go==0.25.0`,
  `tree-sitter-javascript==0.25.0` and `tree-sitter-typescript==0.23.2` before
  the separate P7.1/P7.2 package-metadata change.
- Preserve both previously admitted adapter dependency states so the protected
  base remains green between policy promotion and implementation; unreviewed
  packages and version drift remain fail-closed.
- Exact target bytes pass 115 focused policy tests, Ruff, mypy, current-base
  lock/policy validation and canonical quality: 1514 tests passed, 5 expected
  Windows skips, 81.20% Core branch coverage and `QUALITY=PASS`.
- This proposal changes no active policy or product dependency. Three sequential
  POLICY reviews, exact-byte promotion and ordinary protected delivery remain
  required before the grammar packages can be admitted in product metadata.
### G4 — Core MVP v0.1 (2026-09-06)

- Integrated `P4.1`-`P4.12`: evidence-bound root-cause localization, security
  invariants, PoC/PoC+ regression descriptors, bounded patch construction,
  ephemeral sandbox validation, a twelve-stage validation ladder, bounded repair
  attempts, semantic diff review, monotonic patch lifecycle, reference CWE-89
  E2E, repair CLI receipts, and a reproducible demo/notebook.
- Implementation checkpoint `f76c4c803b3ca185e0c68c310a5d4674c49ba391`
  passed the canonical G4 cycle: 1514 unit tests passed, 5 platform skips,
  81.20% Core branch coverage, Ruff and mypy passed, and `QUALITY=PASS`.
  The two G4 integration files passed all 6 scenarios; the clean demo produced
  deterministic reports without network access or a product PASS claim.
- CR-057 exact-byte promotion records G4 `GO`; G5 is next. Independent
  G4 review is not required; the combined final review remains after G9.

### G3 — Investigation Ready (2026-09-06)

- Completed `P3.1`–`P3.13`: evidence-bound Auditor and read-only Skeptic,
  bounded investigation, deterministic routing, injection containment, typed
  RepositoryView tools, replay telemetry, escalation, mandatory model-native
  discovery, dual-lane convergence, a live local connector and source-free
  local-model qualification.
- The implementation checkpoint `c3f682bac863e6c46ea159f437179e643d4c3eeb`
  passed the canonical G3 cycle: 1443 tests passed, 5 expected Windows
  POSIX/FIFO skips, 82.43% Core branch coverage, Ruff and mypy passed, and
  terminal `QUALITY=PASS`. Exact-byte promotion records G3 `GO`; G4 is next.
- The active policy requires no independent G3 review. The combined final
  product/architecture/security review remains after G9.

### CR-055 — reusable protected G3-G9 gate succession (2026-09-06)

- Version 8 supersedes proposal commits `664df0d`, `6b31e38`, `12fd257`,
  `98d99b2`, `7fc33c8`, `d12ad81`, `cc5316f` and `d2bb408`. Version 8
  fixes two seed-test list aliases with independent copies, so YAML fixtures
  reach their intended validation boundary without generated anchors.
  The positive fixture uses an allowed adapter path instead of a Core path
  forbidden by its inherited scope; the forbidden list is unchanged.
  Evaluator and policy bytes are unchanged from v7. Version 7 removed
  nonessential evaluator docstrings to fit every Base64 scalar within the
  existing 262144-byte parser limit; executable AST is unchanged from v6.
  The prior security review found that G3
  bootstrap still skipped subject-commit task budgets. Both bootstrap and
  protected-base successor tasks now enforce packet file and line budgets
  on the scoped retained base-to-subject delta, including the subject commit.
  G3 pinned packet hashes/history, cumulative checkpoint caps and global
  chain caps are unchanged.
  G3 cumulative checkpoint
  limits are 96 file touches and 16000 changed lines, covering the measured
  59 touches / 10268 lines plus successor packet seeding and gate evidence.
  New boundary self-tests cover exact limits and rejection above either limit.
- G3 bootstrap permits scoped packet modifications after exactly one addition,
  while rejecting deletion, rename/copy or a final pinned-hash mismatch.
  Per-task touch budgets include four touches of remediation headroom; global
  96/16000 limits and fixed paths remain authoritative. Successor packets stay immutable.
- Proposal-only evaluator extension: declare G3-G9 task/checklist/evidence
  admission once, preserve exact-byte promotion and immutable checkpoint scope.
  G3 binds the exact historical packet bytes and fixed task scopes; successors
  consume full-schema packets seeded by the previous protected gate candidate.
  Candidate-created or changed successor authority is rejected. Planned tests
  remain explicitly gate-bound until completion rather than requiring a new
  evaluator amendment for each catalog activation.
- Reconcile active methodology with effective owner-authorized cadence: local
  checkpoint commits without tests/reviews between P-tasks, one canonical
  quality and protected PR/CI cycle per gate, no G2-G8 independent gate reviews,
  and one combined final review cycle after G9 implementation and quality,
  before PROJECT CLOSED promotion. Its three independent product, architecture
  and security/evaluation receipts bind the exact integrated G9 subject.
  P8.12 prepares security evaluation and remediation inputs for that cycle.
- Repair proposal digest construction with ordinal path ordering matching the
  canonical evaluator; committed proposal and decoded target blobs require
  canonical subject readback equality before this proposal is accepted.
- Existing POLICY amendment receipts remain required by executable policy;
  no receipts were authored here. Version 4 Ruff fixes remain in
  the proposed evaluator and its unit-test target: formatting, a raw regex string
  (RUF043) and dictionary literal (C408). Ruff 0.15.22 format/check pass for
  those two decoded targets. Version 8 test-target Ruff format/check passes.
  Nineteen focused evaluator tests pass: four seed-fixture cases plus bootstrap
  and successor subject-only file/line overflow and exact boundaries for
  G3/G4/G9, packet
  immutability, and G3 bootstrap hash/history negatives. File-count overflow
  is a defensive unit boundary; current literal seed admission also bounds
  scope cardinality. No types, full quality, reviews or CI were run for this
  preparation; normal commit hooks remain mandatory.
  All final hashes and canonical subjects are recalculated from exact bytes.
  Product code, frozen specifications and
  existing gate evidence are unchanged. Protected activation remains pending.

### G2 — deterministic core gate candidate (2026-09-06)

- Integrated P2.6-P2.13 as one frozen G2 candidate: dependency and CWE-89
  scanners, bounded scanner plugins, deterministic normalization and lineage,
  EvidenceGraph, classification, JSON/Markdown/HTML/SARIF reporting, and the
  diagnostic CLI mode.
- The exact implementation checkpoint `eb849b555ef8ff7e96b45baf866f2300d56d3b4c`
  passed the canonical gate cycle: 1296 unit tests passed, 5 Windows-only
  POSIX/FIFO oracles skipped, Core branch coverage 86.80%, and
  `QUALITY=PASS`. Exact-byte promotion advances G2 to `GO`; ordinary
  protected delivery remains the publication boundary.

### CR-054 — make G2 promotion test state-independent (2026-09-05)

- Build the G2 pre-promotion plan fixture inside the evaluator regression test
  instead of assuming the repository's current P2.6-P2.13 statuses are always
  `TODO`. The same test now remains valid before and after exact G2 promotion.
- Product code, accepted specifications, gate semantics, review cadence,
  protected CI and branch protection are unchanged.

### CR-053 — fix first integrated gate base lookup (2026-09-05)

- Correct the protected integrated-gate evaluator so a promotion path supplied
  by the proposal candidate is used directly instead of eagerly reading the
  same path from the protected base. First-time gate evidence, such as
  `artifacts/gates/G2/decision.md`, is intentionally absent from that base.
- The amendment changes only the lookup expression in `scripts/spec_gate.py`.
  It does not alter accepted specifications, G2 product bytes, review cadence,
  scope budgets, exact-byte promotion, protected CI or branch protection.

### CR-052 — activate completed G2 rendering evidence (2026-09-05)

- Closing-phase lifecycle correction for P2.12: promote the existing
  `html_markdown_sarif_terminal_rendering` catalog entry from `planned` to
  `executable`, bound to the canonical `python scripts/quality.py` command that
  collects the JSON/Markdown/HTML/SARIF reporter tests on the integrated G2
  candidate. This removes
  the stale-planned contradiction when exact G2 promotion marks P2.12 `DONE`;
  product code, accepted specifications and G2 evidence remain unchanged.
- The amendment uses the existing fail-closed POLICY route and its three
  specifically authorized receipts. It does not reintroduce independent gate
  reviews for G2-G8 or change the single post-G9 final review policy.

### CR-050 — protected candidate admission repair (2026-09-05)

- Successor proposal for the integrated gate lifecycle: preserve the
  owner-authorized Terra/Luna bounded methodology, local checkpoint history,
  no independent reviews for G2-G8 and the single final
  product/architecture/security review after G9. The protected evaluator binds
  the admitted candidate packet to its declared base, complete checkpoint
  ancestry and exact target scope, preventing protected-scope laundering or
  self-admission. The three POLICY receipts remain the only specifically
  authorized reviews for this evaluator amendment. Protected PR #38 merged as
  `7d6e150`; post-merge run `33978319717` passed, so the consolidated lifecycle
  is effective for G2 and later gates.

### CR-048 — bounded development checks and commit hook cadence (2026-09-05)

- Proposed protected follow-up to the accepted development workflow: ordinary
  commit and push retain the closed policy, staged-secret and workflow-security
  hooks. Canonical full quality becomes an explicit publication command instead
  of a repeated hook. The canonical quality implementation, protected CI matrix,
  branch protection and completion-evidence contracts remain unchanged.
- Add `python -I scripts/precommit_entry.py development tests/unit/test_NAME.py`:
  one to eight distinct existing unit-test files, no arbitrary pytest arguments,
  isolated interpreter, locked offline environment, credential-free child
  environment and a 360-second execution deadline. On timeout or interruption,
  terminate the owned process tree using the absolute OS-owned Windows taskkill
  executable or a new POSIX session/process group. Cleanup has bounded 10-second
  termination and reap windows; cleanup failures cannot become PASS. Test
  failures and empty collection fail.
- Architecture review identified descendant survival in the earlier unpublished
  direct-child timeout implementation; the replacement includes a real spawned
  descendant timeout regression and focused termination-error negatives.
- Candidate validation: 114 CI-policy tests through the new entrypoint; focused
  Ruff and mypy pass; unchanged-baseline snapshot passes after restoring Git's
  canonical LF checkout bytes. The real descendant timeout regression passes on
  Windows; POSIX group selection/termination unit checks and Linux-target mypy
  pass. No broad product regression was run by the worker.
- Not effective until independent POLICY review, exact-byte promotion and
  ordinary protected delivery. G2 lifecycle consolidation remains separate
  CR-049 work; current per-task completion evidence is still mandatory.

### CR-046 — deadline and academic submission snapshot (2026-09-05)

- User confirmed project defense on 27 September 2026, Asia/Yekaterinburg,
  and a one-person team; authorized the project correction. Plan 1.0 adds the
  supplemental M-A2026 snapshot ready by 24 September 18:00, rehearsal on the
  25th and reserve on the 26th. Source time 23:59 is not the defense slot;
  exact defense/upload slot and instructor/individual-approval reference remain tracked.
- Prioritize G2/G3/G4, real local-model connector/qualification P3.12/P3.13,
  early P7.1–P7.3 language support, P7.17 development comparison and P9.16
  complete academic artifacts before enterprise expansion. P9.12 starts now.
- Added [submission calendar](docs/SUBMISSION_PLAN.md) and
  [development evaluation](docs/DEVELOPMENT_EVALUATION.md); the supplemental
  E2E remediation denominator includes all predeclared eligible vulnerable
  root causes, including missed findings, absent patches and non-success.
- Frozen specs, existing metrics/oracles, mandatory languages, dual-lane,
  secret/sandbox/fail-closed contracts and G0–G9 remain unchanged. M-A2026
  does not imply beta, enterprise v1.0 or project closure. Existing release
  oracles are rerun later on their actual candidates; no product result is claimed.
- User requested a midpoint instructor demo: P9.17 targets 16 September,
  script ready Sep15 18:00 and feedback Sep17–18; meeting is not yet booked.
- Product review tightened qualification to a quantized open-source LLM and
  assigned the complete end-to-end demo to P9.16 with explicit P3.13 dependency.
- CR-047 repaired the evaluator timeout without changing its 114-node contract
  or 360-second deadline. Protected PR #33 merged as `d61d3d5`; its required
  jobs and post-merge run `33955936418` passed without bypass.
- P2.5 implementation then merged through protected PR #34 as `76d7601` after
  the final fail-open boundary fix. PR run `33957781524`, post-merge run
  `33957954712` and canonical quality passed. The exact completion attestation
  now binds those protected bytes and evidence and marks P2.5 `DONE`.
- D-044 records the bounded scheduling/evidence decision. Independent document
  reviews and integration handoff are tracked in development-run CR-046;
  accepted specs, evaluator behavior and product code are not modified.

### CR-045 — development workflow and model routing (2026-09-05)

- Latest user refinement replaces internal user-visible tasks with bounded
  Codex subagents using explicit model/reasoning configuration, caps Astra at
  medium, and makes the integrated gate candidate the next ordinary full
  quality/review unit after the protected amendment becomes effective.
- Additional user refinement: assignment/origin/reply_to IDs determine every
  result destination; the active chat does not. Informational coordination
  messages cannot overwrite the original assignment return path (section 4.1).
- User refinement: ordinary full quality and independent review move to the
  integrated whole-gate candidate; development retains focused acceptance and
  negative tests. Critical security/evaluator changes receive early review
  before dependent work. Shared checkout becomes the default for management,
  stable read-only review and sequential feature-branch development; isolated
  worktrees have explicit ownership and verified cleanup conditions.
  This supersedes the per-increment/default-worktree operating defaults below;
  executable migration remains pending and no existing gate evidence is relabeled.
- The original operating draft used bounded Codex tasks with return paths and
  one full local verification per completed increment. The refinements above
  supersede those mechanics with internal subagents and integrated-gate review;
  single-writer, identity and explicit invalidation safeguards remain.
- Operating instructions are implemented locally in
  [DEVELOPMENT_WORKFLOW.md](docs/DEVELOPMENT_WORKFLOW.md) and entrypoint docs;
  decision [D-043](docs/DECISIONS.md) records scope and consequences.
- Protected hook/evaluator/one-PR automation changes are pending separately
  under this CR; existing checks and gate evidence remain mandatory. No product
  completion, protected publication or automatic scheduler is claimed.

### Added

- 2026-09-05 — completed `P2.5`: bounded first-party pattern/entropy
  detection and the closed approved external-scanner adapter retain only
  immutable source identity, exact location, fixed redaction and keyed
  fingerprints. The accepted correction rejects the first byte above the
  4096-byte match budget before filtering. Completion evidence binds
  implementation commit `3415414`, protected merge `76d7601`, PR run
  `33957781524` and green post-merge run `33957954712`.
- 2026-08-29 - implemented the local `P2.5` candidate with bounded first-party
  pattern/entropy detection, a pinned `detect-secrets@1.5.0` injected adapter,
  immutable source-bound redacted metadata and keyed fingerprints. The current
  candidate rejects malformed, reordered, overlapping, oversized, identity-
  tampered and exception-bearing external output without retaining matched
  bytes. Targeted secret and package-boundary tests, Ruff, mypy, snapshot,
  CI-policy and strict frozen-G0 checks pass locally; full canonical quality
  and protected delivery evidence remain pending.
- 2026-08-23 — opened `P2.5` from exact completed P2.4 master `7171d5e` with
  a constrained implementation packet. The task is limited to bounded
  first-party secret detection and a closed injected external-scanner adapter;
  retained results may contain only type, location, fixed redaction and keyed
  fingerprint, never matched secret bytes. RawSignal normalization, reports,
  filesystem traversal, subprocesses and network access remain outside scope.
- 2026-08-23 — completed `P2.4`: the bounded CPython `ast` adapter passed
  sequential product, architecture and security/evaluation reviews on exact
  tree `d78d3827cb9f976598b86868e756f393153f5784` after remediation made isolated
  AST access copy-first and exact-snapshot validated. Protected PR #31 merged
  as `2c62e20`; PR run `32621529046` and post-merge run `32621680247` passed
  every mandatory job on Python 3.12–3.14 without bypass. The completion
  attestation binds the exact packet, implementation commit and protected
  delivery; `P2.5` is next.
- 2026-08-23 — opened `P2.4` from exact completed P2.3 master `0e085ff` with
  a constrained implementation packet. The candidate adds a bounded CPython
  `ast` adapter over the exact P2.3 source-bound index, typed syntax-error
  recovery, isolated tree access and fixed non-echo failures; semantic rules,
  filesystem access and source execution remain outside scope.
- 2026-08-23 — completed `P2.3`: the bounded Python Tree-sitter/CST adapter
  and source-bound stable symbol index passed sequential product, architecture
  and security/evaluation reviews on exact tree
  `f69939da5220ae93097653ce78f4bca48c095c0a`. Protected PR #29 merged as
  `e88b730`; PR run `32619424110` and post-merge run `32619578595` passed every
  mandatory job on Python 3.12–3.14 without bypass. The completion attestation
  binds the exact packet, implementation commit and protected delivery; P2.4 is
  the next sequential Core task.
- 2026-08-23 — completed `CR-044`: the state-independent dependency-policy
  self-test passed three sequential reviews, protected PR #28 and post-merge
  run `32593519555`. Evaluator behavior remained unchanged and no bypass was
  used.
- 2026-08-23 — opened `CR-044`: repair the CR-043 dependency-policy self-test
  so it constructs the legacy and reviewed Tree-sitter states explicitly
  instead of duplicating dependencies after P2.3 updates workspace metadata.
  Evaluator behavior and the closed dependency sets remain unchanged (`D-042`).
- 2026-08-22 — completed `CR-043`: the exact two-state adapters dependency
  policy passed three sequential independent reviews, protected PR #27 and
  post-merge run `32592043366`. Tree-sitter Python dependencies can now enter
  through the ordinary P2.3 task gate; no bypass was used.
- 2026-08-22 — opened `CR-043`: extend the closed adapters dependency policy
  with the bounded Tree-sitter Python runtime and grammar ranges required by
  P2.3. The amendment preserves the legacy dependency set only for the atomic
  policy-to-implementation transition, rejects every other adapter dependency,
  and changes no package bytes until exact reviewed promotion (`D-041`).
- 2026-08-23 — opened `P2.3` from exact post-CR-044 master commit `13d2b70`
  with a constrained implementation packet. The task adds a bounded
  Python Tree-sitter/CST adapter and immutable location-stable symbol index over
  caller-admitted exact bytes; Python `ast` semantics, rules, other languages,
  filesystem access and execution remain outside scope. Product-review
  remediation binds every range to exact source geometry, recomputes semantic
  symbol identities and rejects overlapping sibling declarations. Architecture
  remediation retains the immutable admitted bytes inside the internal index
  (excluded from its representation), revalidates their digest and proves each
  byte/point range plus symbol-name slice against those exact bytes. Security
  remediation removes the semantic index builder from the public Core API,
  seals adapter-issued indexes with process-local authority, binds module names
  to paths and enforces immutable maximum ceilings on every parser budget.
  Final security remediation raises sanitized boundary failures only after raw
  dependency exceptions leave scope, preventing source-derived messages from
  remaining reachable through Python exception context.
- 2026-08-22 — completed `CR-042`: the P2 completion catalog and
  catalog-derived protected-run enforcement passed three exact-byte reviews,
  protected PR #25 and post-merge run `32589272475`. All P2.1–P2.14 tasks now
  require the same closed five-class completion evidence without bypass.
- 2026-08-22 — opened `CR-042`: extend the closed completion-evidence catalog
  to P2.2–P2.13 and derive protected-run enforcement from that catalog instead
  of a second hard-coded task list. The proposed evaluator amendment keeps the
  existing five evidence classes, exact GitHub authority checks and ordinary
  protected delivery for every P2 completion (`D-040`).
- 2026-08-22 — completed `P2.2`: deterministic policy-owned ignore filtering,
  explicit language and dependency-manifest discovery, and immutable complete
  base-to-head changed-file mapping passed three independent reviews, protected
  PR #24 and post-merge run `32586165054`. The completion attestation binds the
  exact packet, implementation commit and green delivery evidence. No bypass
  was used; P2.3 is now the next sequential Core task.
- 2026-08-22 — opened `P2.2` from exact master commit `e1f88f3` with a
  constrained implementation packet. The candidate adds policy-owned bounded
  ignore rules, explicit Python/JavaScript/TypeScript/Go coverage discovery,
  dependency-manifest classification and complete deterministic base-to-head
  file mapping without reading repository content or trusting `.gitignore` as
  execution policy. P2.2 remains in progress pending independent reviews,
  protected delivery and completion evidence.
- 2026-08-22 — completed `P2.1`: safe repository intake, exact remediation and
  completion enablement are now bound to the independently reviewed task packet,
  protected PR #12 and its green post-merge run. P2.14 is already `DONE`, so
  P2.2 becomes the next sequential Core task. No bypass was used.
- 2026-08-22 — completed `P2.14`: repository-intake remediation and its task
  packet passed protected PR #12 plus post-merge CI. CR-035 and CR-037 repaired
  merge-commit validation and identity-bound evidence scanning; CR-041 then made
  completion self-tests lifecycle-independent through protected PR #21 and a
  green post-merge run. All delivery used the ordinary protected gate without
  bypass.
- 2026-08-22 — opened `CR-041` after CR-040 passed three reviews but its exact
  promotion preflight rejected a Windows working-copy CRLF manifest against the
  canonical LF Git index bytes. No CR-040 promotion commit was created. The
  successor keeps the reviewed pre-attestation fixture behavior and binds its
  manifest to the exact LF bytes that Git can publish (`D-039`). CR-038 through
  CR-040 and PR #20 remain unmerged.
- 2026-08-22 — opened `CR-037` after product review blocked CR-036 because its
  proposed external-evidence scan view did not bind source URL, repository and
  run identity and admitted whitespace branch names. The successor adds exact
  source/repository/run binding, protected-branch and merge-head consistency,
  timestamp shape checks and negative regressions before typed-hash
  sanitization (`D-038`).
- 2026-08-22 — opened `CR-035` after protected PR #16 passed policy, spec,
  dependency and secret-history checks but correctly rejected the new test-only
  identity constants on Ruff formatting. The successor changes only the
  mechanical formatting of that test refactor and repeats the complete POLICY
  lifecycle and protected delivery without bypass (`D-036`).
- 2026-08-22 — opened `P2.14` to remediate the independent P2.1 repository
  intake review findings. The candidate binds traversal to filesystem objects,
  enforces pre-materialization entry and depth ceilings, rejects link aliases,
  and adds adversarial replacement and mutation tests before P2.2 may start.
- 2026-08-20 — opened `CR-022`: make protected `push` validation understand an
  exact two-parent merge commit without aggregating its already reviewed
  proposal/review/promotion chain. Direct pushes remain unchanged; merge
  admission fails closed on parent order, tree identity, ancestry, lifecycle
  kind, receipts, or final-byte drift (`D-035`).
- 2026-08-20 — opened `CR-018`: all `P1.1–P1.13` work is complete and the
  current protected `master` passed the full Python 3.12–3.14 foundation
  matrix. The G1 evidence proposal awaits three independent sequential reviews
  and exact mechanical promotion (`D-031`).
- 2026-08-20 — G1 was mechanically promoted to effective `GO` through the validated D-026 lane; P2.1 is authorized while G2 and later gates remain enforced.
- 2026-08-20 — opened `CR-021`: restore canonical Ruff formatting for the
  protected CI/spec evaluator sources installed by the preceding amendments.
  The byte-only repair changes no evaluator behavior or policy contract and is
  delivered through the ordinary protected POLICY promotion lane (`D-034`).
- 2026-08-20 — opened `CR-020`: classify SHA identities in exact closed
  change-control packets as typed metadata during secret scanning. Unknown,
  malformed, path-mismatched, or policy-mismatched packets remain subject to
  ordinary secret detection (`D-033`).
- 2026-08-19 — opened `CR-019`: bind GitHub pull-request checks to both the event-owned synthetic merge SHA and its exact head SHA. The proposed fail-closed evaluator amendment verifies ordered parents, linear ancestry and identical trees before validating a protected lifecycle on the head chain (`D-032`).
- 2026-08-19 — принят и интегрирован `CR-017`: repair закрытого P1.4 CI gate
  различает schema-valid completion attestation metadata и секретные значения.
  Только exact SHA-1/SHA-256 поля закрытой attestation-формы исключаются из
  entropy-сигналов; неизвестный path/schema/key/catalog/order остаётся под
  обычным secret scan. Strict promotion manifests и review receipts аналогично
  различают только typed digests; Base64 final files обязательно декодируются
  и сканируются под исходными target paths. Local pre-commit и CI используют
  один scanner. Для последующих изменений evaluator добавлен
  manifest/review/promotion lane с тремя commit-separated ролями и byte-exact
  final files (`D-030`). Exact reviewed commit
  `84f6bd859b90bd4ea7fdc7635a31b2b1c207f6b0` интегрирован одним audited
  fast-forward admin bypass; bypass немедленно удалён, active ruleset `21006868`
  восстановлен без bypass actors.
- 2026-08-19 — завершён `P1.4`: private GitHub repository
  `shorinversion/securecode-ai` защищён active ruleset `21006868`, который
  требует pull request и exact status check `gate`, запрещает deletion и
  non-fast-forward update. Intentional failing PR #1 на commit
  `703817360a9966cc6858a5dc35cdecc50c76a14b` получил серверный
  `mergeStateStatus=BLOCKED`; Actions run `32175856948` завершился `failure`,
  после чего PR закрыт без merge и ветка удалена. External evidence hashes
  записаны в отдельной completion attestation; G1 ещё требует собственного
  evidence/review/promotion lifecycle.
- 2026-08-18 — открыт `P1.13`: один read-only fail-closed spec gate проверяет
  frozen baseline/digest, requirement IDs, traceability, Draft 2020-12 schemas,
  indexed examples, exact public-schema bytes, conservative compatibility и
  пять закрытых Git candidate lanes. Локальная quality-команда запускает
  snapshot gate первой, а обязательный CI spec job использует full history и
  event-authoritative base/candidate SHA; aggregate gate требует его успеха.
  D-026 admission разделяет implementation, completion, gate-evidence proposal,
  commit-separated review receipts и byte-exact promotion. Три прямые quality
  зависимости и их точная девяти-package closure закреплены в `uv.lock`.
  Механически обновлён `.secrets.baseline`: сохранены detector settings и все
  прежние findings, добавлены только проверенные false-positive hashes, а сам
  baseline включён в post-bootstrap protected inventory. Constrained packet
  SHA-256 `b1b7e6ce50a46e62212a6ef74383c3699f5f498542e684915778a87ca7c05673`
  включает remediation repository authority, strict JSON Pointer, trusted Git
  executable и committed-lifecycle checks. Exact staged digest
  `6cf55b7ce6d4db6a51f818e072c403dc4c124d9af352fdfc38b4e3c8ca52de5c`
  принят product/architecture/security-evaluation `PASS/PASS/PASS`; implementation
  commit `307a24a71cea25829c0b5541494bf01e13a2e6ed`. 136 targeted tests и clean-HEAD
  full quality с 978 tests, Ruff/mypy, 85,80% Core
  branch coverage, spec snapshot, CI policy, schema exact-byte и strict frozen
  G0 проходят. `P1.13` — `DONE`,
  `P1.4/G1` не закрыты и `P2` не разрешён.
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
  dependency-integrity/vulnerability и strict zizmor checks. Внешний ruleset и
  blocked failing-PR evidence позже приняты 2026-08-19; сильная product sandbox
  isolation не заявляется.
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
- 2026-08-12 — добавлен project-local skill `securecode-project-navigator`,
  read-only context snapshot helper и обязательное подключение через локальные
  инструкции агентов. Эти development-only файлы исключены из RC-публикации.
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
| `CR-017` | 2026-08-19 | Устранить конфликт completion digest metadata и secret scanner без baseline allowlist; добавить штатную byte-exact evaluator amendment lane | `implemented — exact reviewed commit integrated, bootstrap bypass removed` | `D-030`, P1.4 ordinary required-check proof in completion candidate |
| `CR-046` | 2026-09-05 | Подтверждённый дедлайн, ранняя академическая поставка и diagnostic evidence без замены G7/G9 | `accepted direction; exact review tracked in run` | `D-044`, P3.12–P3.13, P7.17, P9.12/P9.15/P9.16 |

## Release history

Релизов пока нет. Первый планируемый продуктовый инкремент — Core MVP `v0.1`
после прохождения `G4`, целевая дата 17 сентября 2026. M-A2026 — отдельный
академический снимок к 27 сентября, не новый product version и не G9 closure.
