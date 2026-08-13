# SecureCode AI — claim and evidence ledger

Статус: `active`, неполная проверка наиболее значимых тезисов.  
Дата проверки: 12 августа 2026 года.  
Источники кандидатов: импортированный
[deep-research-methodology-2026-08-12.md](deep-research-methodology-2026-08-12.md)
и targeted project research по отдельным security/architecture решениям.

## Статусы

- `verified_primary` — тезис сверён с разрешимым первичным/официальным источником;
- `verified_scoped` — подтверждён только в указанной предметной области;
- `supported_inference` — разумный проектный вывод из нескольких источников,
  но не дословное требование одного стандарта;
- `unresolved` — источник из исходного отчёта невозможно разрешить или claim
  ещё не проверен;
- `rejected` — первичный источник не поддерживает формулировку.

## Проверенные высоковлияющие claims

| ID | Claim | Статус | Evidence и ограничения | Влияние на проект |
|---|---|---|---|---|
| `DR-001` | PRISMA 2020 предоставляет checklist и flow diagrams для прозрачного reporting systematic reviews | `verified_primary` | [PRISMA 2020](https://www.prisma-statement.org/prisma-2020). Это reporting guideline, не универсальный research design | Заимствовать прозрачность flow/selection, не заявлять формальную PRISMA-compliance без полноценного review |
| `DR-002` | Поиск нужно планировать и документировать: sources, dates, terms, exact strategies | `verified_scoped` | [Cochrane Handbook, Chapter 4](https://www.cochrane.org/authors/handbooks-and-manuals/handbook/current/chapter-04), особенно documentation/reporting. Контекст — systematic reviews | Ввести protocol, search log и immutable query history для P0 research |
| `DR-003` | Несколько дополняющих баз и citation search снижают риск пропустить класс evidence | `verified_scoped` | [Cochrane Chapter 4](https://www.cochrane.org/authors/handbooks-and-manuals/handbook/current/chapter-04). Нужна topic-specific адаптация; «искать везде» не является правилом | Для SecureCode использовать академические, standards, vendor docs и practitioner sources с явным purpose |
| `DR-004` | PRISMA-S требует раскрывать databases/platforms и полные search strategies | `verified_primary` | [PRISMA-S](https://pmc.ncbi.nlm.nih.gov/articles/PMC7839230/), 16-item checklist | Search log хранит exact query/platform/date и выбранные результаты |
| `DR-005` | FAIR включает persistent IDs, rich metadata, license и provenance; controlled access совместим с FAIR | `verified_primary` | [FAIR Guiding Principles](https://doi.org/10.1038/sdata.2016.18) | Hash/version/provenance для datasets, benchmark manifests, reports и gate evidence; raw proprietary code не обязан быть публичным |
| `DR-006` | Computational reproducibility и replicability — разные проверки | `verified_primary` | [NASEM, Reproducibility and Replicability in Science](https://nap.nationalacademies.org/catalog/25303/reproducibility-and-replicability-in-science) | Отдельно проверять replay того же run и устойчивость на других repos/models/seeds |
| `DR-007` | OSF registration — постоянная time-stamped версия; registration может получить DOI | `verified_primary` | [OSF API documentation](https://developer.osf.io/) | Для финальной научной поставки можно заморозить protocol/evaluation release; до этого достаточно Git tag + hashes |
| `DR-008` | Каждый значимый вывод должен иметь цепочку claim → evidence → transformation → uncertainty → validation → provenance | `supported_inference` | Синтез DR-001–DR-007, не отдельный стандарт | Ввести research evidence ledger; принцип также усиливает существующий EvidenceGraph продукта |
| `DR-009` | LLM может генерировать кандидатов, но не является source of truth | `supported_inference` | Согласуется с `D-001`, source-verification requirement и найденным дефектом citations в самом отчёте | Запретить promotion LLM claim в ADR/spec без primary source и scope check |
| `DR-010` | Универсальные бюджеты, tool rankings и 16-недельный timeline применимы к SecureCode AI | `unresolved` | В отчёте нет разрешимых ссылок; диапазоны явно названы ориентировочными | Не использовать для календаря, бюджета или выбора инструментов без отдельного исследования |

## Prompt-injection и refusal claims

| ID | Claim | Статус | Evidence и ограничения | Влияние на проект |
|---|---|---|---|---|
| `PI-001` | Развитая prompt injection похожа на social engineering; source–sink analysis полезнее простого поиска фраз | `verified_primary` | [OpenAI](https://openai.com/index/designing-agents-to-resist-prompt-injection/) описывает собственный production framing; это vendor experience, не универсальный formal proof | Моделировать untrusted source, dangerous sink и разрешённые capabilities |
| `PI-002` | Отдельный injection classifier/«AI firewall» не ловит все развитые атаки | `verified_scoped` | Тот же [OpenAI source](https://openai.com/index/designing-agents-to-resist-prompt-injection/); применимо к agentic context и адаптивным атакам | Detector — дополнительный сигнал, не единственный gate |
| `PI-003` | Instruction hierarchy улучшает устойчивость к malicious tool output | `verified_scoped` | [OpenAI IH-Challenge](https://openai.com/index/instruction-hierarchy-challenge/); vendor experiments, переносимость к нашим providers нужно измерять | Trust labels и provider capability/eval, но не hard security boundary |
| `PI-004` | Ни один agent не иммунен; model training, classifiers и expert red team дают разные слои | `verified_primary` | [Anthropic prompt-injection defenses](https://www.anthropic.com/research/prompt-injection-defenses); опубликованные показатели относятся к browser product/configuration | Defense in depth и adaptive corpus вместо обещания «решено» |
| `PI-005` | Audited connector не делает загружаемые данные доверенными; poisoned README остаётся attack vector | `verified_primary` | [Anthropic containment experience](https://www.anthropic.com/engineering/how-we-contain-claude) | Repository, SCM и tool output всегда `instruction_authority=NONE` |
| `PI-006` | Для coding agent нужны filesystem и network isolation; domain allowlist следует считать capability grant | `verified_primary` | [Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing) и [containment incident analysis](https://www.anthropic.com/engineering/how-we-contain-claude); конкретные реализации Anthropic не копируются без собственной проверки | Sandbox, egress proxy и credential provenance проектируются совместно |
| `PI-007` | Provider refusal/incomplete состояния доступны отдельно от обычного output и transport error | `verified_primary` | [OpenAI response refusal event](https://platform.openai.com/docs/api-reference/responses-streaming/response/refusal/done); [Claude stop reasons](https://platform.claude.com/docs/en/build-with-claude/handling-stop-reasons), где refusal может быть HTTP 200 | Provider adapter обязан нормализовать native outcomes до security routing |
| `PI-008` | `refusal/empty/incomplete → no finding` является устранимой deterministic policy flaw | `supported_inference` | Инженерный вывод из PI-001–PI-007; vendor sources не специфицируют SecureCode AI gate | `D-015`: non-success не может стать `PASS`, только bounded fallback/escalation |
| `PI-009` | Fail-closed без recovery создаёт attacker-controlled availability/DoS риск | `supported_inference` | Синтез вероятностных miss/over-refusal и approval-fatigue observations в [Anthropic containment](https://www.anthropic.com/engineering/how-we-contain-claude) | Bounded fallback, precise `INDETERMINATE`, auditable waiver, отдельные availability metrics |
| `PI-010` | Attack corpus должен измерять повторные adaptive attempts и benign defensive-security over-refusal | `supported_inference` | Anthropic публикует adaptive Best-of-N/100-attempt framing; [OpenAI model guidance](https://developers.openai.com/api/docs/guides/latest-model) предупреждает о safeguard intervention на легитимных defensive tasks | `ASR@1/10/100`, refusal-induced FN и over-refusal входят в `P0.12/P8.3` |

## Проверка качества импортированного файла

| Проверка | Результат | Риск |
|---|---:|---|
| Строк | `1020` | Информационно |
| Внутренние citation markers | `74` | Требуют resolution |
| Разрешимые `http(s)` URL | `0` | Высокий для цитирования и аудита |
| Reference/bibliography headings | `0` | Высокий для воспроизводимости |
| Секреты по базовым token/private-key patterns | `0` | Проверка не заменяет DLP |
| Нормализованное совпадение двух пользовательских копий | `true` | Целостность подтверждена |

## Ограничение этой проверки

Это targeted verification наиболее значимых методологических тезисов, а не
полный systematic review всех утверждений в 1020-строчном отчёте. Любой новый
claim, влияющий на архитектуру, спецификацию, benchmark или защиту, добавляется
в этот ledger и проверяется отдельно.

## Architecture, SCM и contract claims

| ID | Claim | Статус | Evidence и ограничения | Влияние на проект |
|---|---|---|---|---|
| `AR-001` | LangGraph сохраняет checkpoints и поддерживает interrupt/replay, но replay поздних шагов повторно запускает их LLM/API calls | `verified_primary` | [LangGraph persistence](https://docs.langchain.com/oss/python/langgraph/persistence) и [interrupts](https://docs.langchain.com/oss/python/langgraph/interrupts). Idempotency остаётся обязанностью приложения | LangGraph не становится второй production state authority; adapters скрыты за port |
| `AR-002` | Temporal предназначен для durable workflow recovery и persistent task queues/worker polling | `verified_primary` | [Temporal docs](https://docs.temporal.io/), [workflows](https://docs.temporal.io/workflows), [task queues](https://docs.temporal.io/task-queue). Это не доказывает пригодность без нашей integration test | `D-020`: TemporalRuntime для connected mode, LocalRuntime для offline |
| `AR-003` | PostgreSQL RLS может давать default-deny, но owner и BYPASSRLS способны обходить policies | `verified_primary` | [PostgreSQL 18 RLS](https://www.postgresql.org/docs/18/ddl-rowsecurity.html) | RLS — defense in depth; application role не owner/superuser/BYPASSRLS |
| `AR-004` | Docker rootless запускает daemon и containers без root; gVisor добавляет userspace application-kernel boundary с compatibility/performance tradeoff | `verified_primary` | [Docker rootless](https://docs.docker.com/engine/security/rootless/), [gVisor](https://gvisor.dev/docs/). Изоляция всё равно требует configuration/conformance | `D-023`: rootless local, mandatory gVisor pilot, no silent downgrade |
| `AR-005` | Kubernetes NetworkPolicy требует фактической поддержки/enforcement, а security controls включают RuntimeClass, pod standards и network policy | `verified_scoped` | [Kubernetes security](https://kubernetes.io/docs/concepts/security/) и networking docs; конкретный CNI проверяется deployment test | Sandbox gate проверяет реальный runtime/network enforcement |
| `AR-006` | Pydantic генерирует JSON Schema Draft 2020-12/OpenAPI 3.1-compatible schemas; FastAPI строится на OpenAPI/JSON Schema | `verified_primary` | [Pydantic JSON Schema](https://docs.pydantic.dev/latest/concepts/json_schema/), [FastAPI features](https://fastapi.tiangolo.com/features/) | `D-026`: domain-first types + checked-in JSON Schema + generated OpenAPI |
| `AR-007` | GitHub Apps позволяют granular repository permissions; Checks/required status являются механизмом gate | `verified_primary` | [GitHub App permissions](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app), [status checks](https://docs.github.com/en/pull-requests/reference/status-checks) | `D-018`: GitHub-first, least privilege, comment/SARIF не gate truth |
| `AR-008` | GitLab external status response связан с current HEAD и stale SHA даёт conflict; отдельный status-check widget/blocking требует Ultimate | `verified_primary` | [GitLab status checks](https://docs.gitlab.com/user/project/merge_requests/status_checks/) и [API](https://docs.gitlab.com/api/status_checks/). Commit statuses/CI доступны шире | GitLab adapter использует capability profile и общий SHA contract |
| `AR-009` | Redis Streams имеют at-least-once/failover caveats, поэтому добавление их поверх durable workflow не даёт exactly-once side effects | `verified_primary` | [Redis Streams](https://redis.io/docs/latest/develop/data-types/streams/). Это не запрет Redis вообще | Generic broker исключён из pilot baseline; side effects остаются idempotent |
| `AR-010` | OWASP excessive agency рекомендует минимальные granular tools/permissions/autonomy, а не open-ended extensions | `verified_scoped` | [OWASP LLM06:2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/2_0_vulns/LLM06_ExcessiveAgency.html) | Capability policy запрещает generic shell/URL fetch и self-escalation |
| `AR-011` | SLSA enumerates source/build/dependency/verification threats and emphasizes automated controls and provenance | `verified_primary` | [SLSA 1.2 threats](https://slsa.dev/spec/v1.2/threats). Проект не заявляет SLSA level | Threat model и P8 supply-chain evidence use scoped controls |
| `AR-012` | NIST SSDF is a high-level set of practices integrated into SDLC, not a product certification | `verified_primary` | [NIST SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) | Security tasks/tests/evidence are planned across phases, no compliance claim |

## Program-analysis и repair claims, влияющие на D-001/D-006/D-017

| ID | Claim | Статус | Evidence и ограничения | Влияние на проект |
|---|---|---|---|---|
| `PA-001` | LLM и статический анализ могут давать взаимодополняющие сигналы | `verified_scoped` | [IRIS, ICLR 2025](https://proceedings.iclr.cc/paper_files/paper/2025/file/582d4e27fa24168f3af1f4582655034b-Paper-Conference.pdf) комбинирует LLM-generated CodeQL specs и analysis; [MoCQ](https://arxiv.org/abs/2504.16057) использует другой query/refinement pipeline. Результаты относятся к их datasets/configurations | Поддерживает hybrid architecture, но не гарантирует superiority каждого нашего workflow |
| `PA-002` | Repository-level audit выигрывает от structured facts/memory/validator в исследованной конфигурации | `verified_scoped` | [RepoAudit](https://arxiv.org/abs/2501.18160), включая ablations; препринт и конкретный benchmark | EvidenceGraph/validator являются проверяемыми components, их вклад измеряется ablation |
| `PA-003` | Leakage, duplicates и noisy labels способны завышать vulnerability-detection evaluation | `verified_primary` | [PrimeVul](https://arxiv.org/abs/2403.18624), scope — построенный authors dataset/analysis | Grouped splits, deduplication и leakage review обязательны в P0.12 |
| `PA-004` | Compiler/test/security feedback полезен для repair, но passing tests не доказывает безопасную корректность | `verified_scoped` | [VRpilot](https://arxiv.org/abs/2405.15690), [PVBench](https://arxiv.org/abs/2603.06858) и [RepairAgent](https://arxiv.org/abs/2403.17134); разные languages/datasets и repair settings | Bounded feedback loop + PoC+ + post-scan + human gate; никаких гарантий Auto-Fix |
| `PA-005` | Современные coding agents решают только часть realistic correct-and-secure tasks | `verified_scoped` | [SecureVibeBench v5](https://arxiv.org/abs/2509.22097v5) сообщает 23.8% для лучшего evaluated configuration на 105 C/C++ tasks; прежнее имя/15.2% относились к старой версии и исправлены 2026-08-12 | Patch называется candidate; число нельзя переносить на новые models/corpus, our evaluation must be pinned |
| `PA-008` | Basic tests + PoC способны переоценивать patch correctness | `verified_scoped` | [PVBench v2](https://arxiv.org/abs/2603.06858v2) сообщает, что >40% basic-validated patches трёх evaluated AVR systems провалили PoC+ на 209 cases/20 projects | Validation ladder требует PoC+, existing tests, post-scan и human gate; процент не универсален |
| `PA-009` | Полевые agentic review comments имеют существенную долю отклонений в изученной системе | `verified_scoped` | [CodeRabbit field study v2](https://arxiv.org/abs/2607.03316v2): 31,073 pairs, 36.4% accepted, 7.3% discussion, 56.3% rejected; одна система и observational design | High-signal/limited inline UX и human feedback metrics обязательны; rates не переносятся на наш product |
| `PA-010` | CRA-only review в изученном dataset связан с меньшим merge rate и low-signal feedback | `verified_scoped` | [MSR 2026 study](https://arxiv.org/abs/2604.03196): CRA-only 45.20% vs human-only 68.37%; association не доказывает causality | Бот дополняет human review; false-block/comment-volume metrics входят в pilot |
| `PA-006` | Общий parser API не устраняет language-specific semantic extractor/toolchain | `verified_primary` | [Tree-sitter parser usage](https://tree-sitter.github.io/tree-sitter/using-parsers/) использует language grammars; [CodeQL overview](https://codeql.github.com/docs/codeql-overview/about-codeql/) описывает language-specific extraction/database | `D-017`: Python-first implementation with language-neutral contracts, JS/Go in P7 |
| `PA-007` | Python standard library exposes a typed AST suitable for the first native adapter | `verified_primary` | [Python `ast`](https://docs.python.org/3/library/ast.html). AST alone does not supply interprocedural security semantics | Python CWE-89 first vertical combines AST/CST with explicit data-flow evidence |
| `PA-011` | OpenAI Codex Security performs model-native vulnerability discovery by directly reading repository source, building a threat map and tracing from inputs/sinks; a prior SAST finding is not a required seed | `verified_primary` | Official source at pinned commit [`455d7c8`](https://github.com/openai/codex-security/tree/455d7c8c68e515fec3756052863e94229e37a520): [security-scan skill](https://github.com/openai/codex-security/blob/455d7c8c68e515fec3756052863e94229e37a520/sdk/typescript/_bundled_plugin/skills/security-scan/SKILL.md) and [finding-discovery skill](https://github.com/openai/codex-security/blob/455d7c8c68e515fec3756052863e94229e37a520/sdk/typescript/_bundled_plugin/skills/finding-discovery/SKILL.md). Это source review одного продукта, не сравнительный benchmark | Добавить независимый model-native discovery lane; Auditor валидирует кандидатов обоих каналов, а не только scanner findings |
| `PA-012` | Codex Security represents scan coverage explicitly and treats incomplete execution separately from a successful clean scan | `verified_primary` | [coverage schema](https://github.com/openai/codex-security/blob/455d7c8c68e515fec3756052863e94229e37a520/sdk/typescript/_bundled_plugin/schemas/coverage.schema.json) и [SDK README](https://github.com/openai/codex-security/blob/455d7c8c68e515fec3756052863e94229e37a520/sdk/typescript/README.md); конкретные exit semantics относятся к версии `0.1.10` | Для обязательного semantic lane нужны coverage receipts; unavailable/refused/incomplete model run даёт `INDETERMINATE`, не `PASS` |
| `PA-013` | Repeated independent discovery can reduce run variance, but must be bounded and followed by centralized deduplication/validation | `verified_scoped` | [deep-security-scan skill](https://github.com/openai/codex-security/blob/455d7c8c68e515fec3756052863e94229e37a520/sdk/typescript/_bundled_plugin/skills/deep-security-scan/SKILL.md) задаёт stop-after-no-new/max-runs. Source не доказывает superiority на нашем corpus | Реализовать как optional deep profile; standard profile использует один baseline и focused packets, оба с budgets/terminal reason |

Точные числовые значения из отдельных papers остаются scoped к указанным
версиям и не являются product targets. Любой release claim использует только
собственный pinned evaluation protocol.

## Evaluation optimization и long-context exploration

| ID | Claim | Статус | Evidence и ограничения | Влияние на проект |
|---|---|---|---|---|
| `EO-001` | RLM позволяет модели программно исследовать внешний long context и рекурсивно вызывать подмодели | `verified_scoped` | [RLM v3](https://arxiv.org/abs/2512.24601v3) и [author-maintained code](https://github.com/alexzhang13/rlm). Результаты относятся к long-context tasks, не security detection | Рассматривать как experimental discovery strategy внутри model-native lane, не как finding validator |
| `EO-002` | Default local RLM REPL выполняет Python в host process и не предназначен для production security boundary | `verified_primary` | [Official RLM README](https://github.com/alexzhang13/rlm) прямо описывает host-process `exec`, isolated environments и production warning | Разрешать generated query code только в отдельном no-network/read-only sandbox с budgets и без evaluator/secrets |
| `EO-003` | DSPy выражает LM pipelines как optimizable modules; GEPA изменяет textual components по traces/feedback и held-out metric | `verified_primary` | [DSPy paper](https://arxiv.org/abs/2310.03714), [GEPA paper](https://arxiv.org/abs/2507.19457) и [official docs](https://github.com/stanfordnlp/dspy/blob/main/docs/docs/api/optimizers/GEPA/overview.md). Опубликованные gains task-specific | Офлайн prompt optimization допускается только на train/dev; candidate проходит hard constraints и один locked-test promotion |
| `EO-004` | SkillOpt оптимизирует skill document frozen-агента bounded edits с held-out acceptance gate | `verified_scoped` | [SkillOpt paper](https://arxiv.org/abs/2605.23904) и [Microsoft repo](https://github.com/microsoft/SkillOpt). Benchmarks не являются security-audit benchmark | Создать role-specific skills после executable harness; оптимизировать по одному, не позволяя менять policy/capabilities/evaluator |
| `EO-005` | Опубликованный DVSA RLM experiment является feasibility demo, а не достаточной оценкой security quality | `verified_primary` | [Авторский отчёт](https://kmad.ai/Recursive-Language-Models-Security-Audit) отмечает возможную contamination, run variance и 4/10 полностью пропущенных lesson categories | Не использовать `$0.87`, `50 lines` или screenshot F1 как project claim; воспроизвести только в locked ablation при необходимости |
| `EO-006` | LLM-generated eval data допустимы как candidates, но не как единственный ground truth | `supported_inference` | Следует из frozen-split/leakage требований `SC-EVAL-001–007` и ограничений EO-003–EO-005; ни один источник не задаёт наш полный corpus policy | Generated cases требуют deterministic/runtime oracle, human root-cause review, fixed provenance/seed и lineage-grouped split |
