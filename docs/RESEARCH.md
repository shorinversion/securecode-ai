# SecureCode AI — исследовательская база

Актуальность сводки: 12 августа 2026 года.

## 1. Главный исследовательский вывод

SecureCode AI следует позиционировать не как «LLM вместо SAST» и не как
«LLM только фильтрует алерты SAST», а как нейросимволическую evidence-first
систему с двумя независимыми каналами обнаружения:

1. Детерминированные анализаторы находят кандидатов и программные факты.
2. Model-native discovery читает разрешённый исходный код через ограниченные
   read-only инструменты и формулирует собственные security hypotheses, даже
   если детерминированный канал не создал кандидата.
3. Оба потока нормализуются и дедуплицируются с сохранением provenance.
4. Evidence layer связывает source, transformations, guards и sink.
5. LLM-аудитор независимо проверяет контекст и формирует объяснимый verdict.
6. Архитектор создаёт минимальный patch candidate.
7. Независимый валидатор проверяет патч в изолированной среде.
8. Policy engine и человек принимают окончательное решение.

LLM не является источником истины. Она формулирует гипотезы и варианты
исправления; переходы workflow определяют типизированное состояние,
детерминированные проверки и корпоративная политика.
SAST не является ни ground truth, ни обязательным seed для model-native
исследования. При этом модель не получает свободный shell или неограниченный
repository dump: доступ задают egress policy, budgets и узкие операции чтения,
поиска символов, references и data-flow facts.

## 2. Научные работы

### Repository-level detection

- [RepoAudit](https://arxiv.org/abs/2501.18160) — автономный аудит репозитория с
  памятью фактов, межпроцедурным обходом и отдельным validator. Абляции работы
  показывают, что abstraction, validation и caching существенно влияют на
  precision, recall и стоимость.
- [IRIS](https://proceedings.iclr.cc/paper_files/paper/2025/file/582d4e27fa24168f3af1f4582655034b-Paper-Conference.pdf)
  — peer-reviewed ICLR 2025 нейросимволическая система: LLM строит taint
  specifications, CodeQL выполняет анализ, LLM фильтрует результаты.
- [MoCQ](https://arxiv.org/abs/2504.16057) — LLM извлекает vulnerability
  patterns, синтезирует запросы статического анализа и уточняет их в feedback
  loop.
- [JitVul](https://arxiv.org/abs/2503.03586) — repository/JIT benchmark из 879
  CVE; ReAct agents лучше используют межпроцедурный контекст, но остаются
  нестабильными и могут неверно интерпретировать security guards.
- [QLPro](https://arxiv.org/abs/2506.23644) — интеграция LLM и статического
  анализа для whole-project vulnerability discovery.
- [PrimeVul](https://arxiv.org/abs/2403.18624) — показывает, насколько
  дубликаты, data leakage и шумная разметка завышают качество vulnerability
  detection на старых наборах данных.

### OpenAI Codex Security: review открытого исходного кода

12 августа 2026 года проверен официальный репозиторий
[openai/codex-security](https://github.com/openai/codex-security) на commit
[`455d7c8`](https://github.com/openai/codex-security/tree/455d7c8c68e515fec3756052863e94229e37a520)
(`@openai/codex-security` `0.1.10`). Наиболее полезны не маркетинговые формулировки,
а исполняемые skill-контракты и схемы:

- [standard security scan](https://github.com/openai/codex-security/blob/455d7c8c68e515fec3756052863e94229e37a520/sdk/typescript/_bundled_plugin/skills/security-scan/SKILL.md)
  запускает независимый baseline audit реального source, строит source-backed
  threat map и раздаёт focused investigation packets; SAST finding не является
  обязательным входом;
- [finding discovery](https://github.com/openai/codex-security/blob/455d7c8c68e515fec3756052863e94229e37a520/sdk/typescript/_bundled_plugin/skills/finding-discovery/SKILL.md)
  требует читать callers, data flow, guards, authorization/tenant boundaries,
  state transitions и counterevidence; используются прямой проход от
  attacker-controlled input и обратный проход от sensitive sink;
- [deep scan](https://github.com/openai/codex-security/blob/455d7c8c68e515fec3756052863e94229e37a520/sdk/typescript/_bundled_plugin/skills/deep-security-scan/SKILL.md)
  повторяет независимые discovery runs до bounded saturation/cap, затем
  централизованно выполняет validation и attack-path analysis;
- [coverage schema](https://github.com/openai/codex-security/blob/455d7c8c68e515fec3756052863e94229e37a520/sdk/typescript/_bundled_plugin/schemas/coverage.schema.json)
  делает scope, exclusions, deferred work, open questions и completeness
  machine-readable; incomplete coverage не должно превращаться в clean result;
- [validation](https://github.com/openai/codex-security/blob/455d7c8c68e515fec3756052863e94229e37a520/sdk/typescript/_bundled_plugin/skills/validation/SKILL.md)
  сохраняет disposition каждого кандидата и использует strongest-available
  proof ladder: PoC/sanitizer/debugger, focused test, realistic reproduction,
  затем static trace с явным proof gap;
- [finding schema](https://github.com/openai/codex-security/blob/455d7c8c68e515fec3756052863e94229e37a520/sdk/typescript/_bundled_plugin/schemas/findings.schema.json)
  хранит stable identity, code evidence, root cause, validation, attack path и
  remediation tests; [scan comparison](https://github.com/openai/codex-security/blob/455d7c8c68e515fec3756052863e94229e37a520/sdk/typescript/src/scan-comparison.ts)
  сначала использует identity, а затем изолированный structured LLM matching по
  root cause, без shell/network и без передачи secrets.

Официальное [описание продукта](https://help.openai.com/en/articles/20001107-codex-security)
также подтверждает прямое чтение кода, построение threat model, sandbox
validation и patch proposals. Это доказательство существующего design pattern,
но не независимая оценка precision/recall и не основание копировать реализацию.
Codex Security преимущественно демонстрирует model-native audit; SecureCode AI
добавляет к нему независимый deterministic lane, единый EvidenceGraph и явную
ablation-оценку `deterministic-only` / `model-native-only` / `hybrid`.

### Automated repair and validation

- [RepairAgent](https://arxiv.org/abs/2403.17134) — program repair как конечный
  автомат с инструментами, динамическим контекстом и валидацией.
- [VRpilot](https://arxiv.org/abs/2405.15690) — feedback от компилятора, тестов
  и security sanitizers повышает число корректных патчей относительно
  одношаговой генерации.
- [CVE-Bench](https://aclanthology.org/2025.naacl-long.212/) — 509 CVE в четырёх
  языках; демонстрирует, что реальное автономное исправление остаётся сложной
  задачей.
- [SEC-bench](https://arxiv.org/abs/2506.11791) — воспроизводимые vulnerability
  tasks, PoC и gold patches; современные агенты исправляют лишь часть случаев.
- [SecureVibeBench](https://arxiv.org/abs/2509.22097v5) — 105 реалистичных
  C/C++ multi-file задач. В актуальной v5 лучший evaluated вариант достиг 23,8%
  одновременно корректных и безопасных решений; простая security-инструкция
  заметно не решила проблему. Число относится только к версии/конфигурации
  работы и не является target SecureCode AI.
- [Patch Validation in Automated Vulnerability Repair / PVBench](https://arxiv.org/abs/2603.06858)
  — более 40% патчей, принятых базовыми тестами и PoC, провалили усиленные
  PoC+ проверки. Это обосновывает многоступенчатую validation ladder.
- [Root-Cause-Driven Automated Vulnerability Repair / Kumushi](https://arxiv.org/abs/2605.04251)
  — root-cause localization снижает вероятность поверхностного исправления
  симптома вместо дефекта.

### Agent harness и interfaces

- [SWE-agent](https://arxiv.org/abs/2405.15793) — специализированный
  Agent-Computer Interface существенно влияет на результат агента. Для
  SecureCode нужны узкие операции над репозиторием вместо свободного shell.
- [OpenHands](https://arxiv.org/abs/2407.16741) — sandboxed execution,
  coordination и benchmark integration для software engineering agents.
- [Graph Engineering Guide](https://www.aibuilderclub.com/blog/graph-engineering-guide-2026)
  — полезная практическая формулировка уровня над loop engineering. Это не новая
  фундаментальная парадигма, а явное проектирование directed workflow/state
  machine: nodes, edges и shared state.

### Human feedback и реальные code reviews

- [Persistent Human Feedback, LLMs, and Static Analyzers](https://arxiv.org/abs/2602.05868)
  — SAST нельзя считать единственным ground truth; подтверждённую обратную связь
  инженеров можно сохранять как tenant-scoped память.
- [Is Agentic Code Review Helpful?](https://arxiv.org/abs/2607.03316) — на
  31 073 парах review/feedback 36,4% комментариев были приняты, а 56,3%
  отклонены. Типичные проблемы: false positives, повторы и несоответствие intent
  проекта.
- [From Industry Claims to Empirical Reality](https://arxiv.org/abs/2604.03196)
  — AI-only reviews показывают более низкий merge rate и часто низкий
  signal-to-noise ratio; human oversight остаётся необходимым.

## 3. Бенчмарки

Предпочтительный evaluation portfolio:

- [RealVuln](https://realvuln.com/) — основной Python repository benchmark;
- [CVEfixes](https://arxiv.org/abs/2107.08760) — реальные CVE и fixing commits;
- [SecureVibeBench](https://arxiv.org/abs/2509.22097v5) — correct-and-secure
  multi-file changes;
- [PVBench](https://arxiv.org/abs/2603.06858) — проверка качества patch
  validation;
- [CyberSecEval](https://github.com/meta-llama/PurpleLlama/blob/main/CybersecurityBenchmarks/README.md)
  и [RedCode](https://openreview.net/forum?id=mAG68wdggA) — безопасность code
  agents;
- CodeIPI/QueryIPI — устойчивость к indirect prompt injection через README,
  issues и комментарии;
- небольшой вручную проверенный holdout из свежих CVE после knowledge cutoff
  используемых моделей.

Для каждого набора необходимо фиксировать release, commit SHA, лицензию и hash
ground truth. У RealVuln на момент исследования расходились числа на сайте и в
README репозитория, поэтому ссылка на «последнюю версию» без pinning недопустима.

## 4. Метрики

### Detection

- precision, recall, F1/F2/F3;
- false positives на KLOC;
- localization accuracy;
- CWE mapping accuracy;
- доля findings с воспроизводимым source-to-sink evidence;
- accepted/rejected rate после human review.

### Repair

- patch apply rate;
- syntax/build/test pass rate;
- security regression test pass rate;
- correct-and-secure rate;
- число новых findings после исправления;
- human acceptance rate;
- доля root-cause patches против symptom suppression.

### Operations

- latency;
- tokens и стоимость на confirmed finding;
- RAM/CPU/GPU;
- число model/tool calls;
- стабильность по нескольким независимым запускам.

## 5. Стандарты

- [OWASP Top 10:2025](https://owasp.org/Top10/);
- [CWE Top 25:2025](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html);
- [CWE Mapping Guidance](https://cwe.mitre.org/documents/cwe_usage/guidance.html);
- [OWASP Prompt Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html);
- [OWASP SCVS](https://scvs.owasp.org/);
- [CVSS v4](https://www.first.org/cvss/v4.0/);
- [SARIF 2.1](https://www.oasis-open.org/standard/sarif-v2-1-0/);
- [CycloneDX/VEX](https://cyclonedx.org/capabilities/vex/);
- [SPDX](https://spdx.dev/);
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework);
- [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/concepts/semantic-conventions/);
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices).

## 6. Инструменты-кандидаты

- Tree-sitter — общий CST/парсинг Python, JavaScript/TypeScript и Go;
- Python `ast` — глубокие Python-specific rules;
- Bandit — Python baseline;
- Semgrep — pattern/data-flow baseline;
- CodeQL — мощный optional baseline для interprocedural analysis, с учётом
  лицензирования и сложности установки;
- Gitleaks — baseline для secret detection;
- OSV-Scanner — SCA и уязвимые зависимости;
- Trivy — optional scan конфигураций, образов и secrets;
- Git — snapshots, diff, patch apply check и provenance.

Проект обязан содержать собственные анализаторы и контракты, а не быть только
обёрткой над готовыми CLI.

## 7. Конкурентная рамка

Актуальные продукты уже поддерживают цепочку «scanner alert → AI explanation →
suggested fix»:

- [GitHub Copilot Autofix](https://docs.github.com/en/code-security/concepts/code-scanning/autofix-for-code-scanning);
- [Snyk Agent Fix](https://docs.snyk.io/scan-with-snyk/snyk-code/manage-code-vulnerabilities/fix-code-vulnerabilities-automatically);
- [Semgrep Autofix](https://semgrep.dev/products/product-updates/accelerate-remediation-with-semgrep-autofix/);
- [Sonar AI CodeFix](https://docs.sonarsource.com/sonarqube-server/2025.5/ai-capabilities/ai-codefix).

Потенциальная дифференциация SecureCode AI:

- aggregation нескольких analyzers;
- evidence graph и проверяемый source-to-sink trace;
- contextual triage и business-logic findings;
- независимый Skeptic;
- root-cause repair;
- security test/PoC и PoC+ validation;
- provider independence и on-prem execution;
- воспроизводимый case file;
- policy-as-code и human approvals;
- одинаковое ядро для CLI, CI и managed service.

## 8. Ограничения исследований

- arXiv-препринт не равен peer-reviewed результату;
- синтетические датасеты часто переоценивают качество;
- публичные benchmarks могут присутствовать в training data моделей;
- успешный PoC test не доказывает общую корректность патча;
- SAST output не является безошибочным ground truth;
- X-публикации используются только как practitioner signals;
- любые числовые утверждения перед защитой нужно повторно сверить с первичным
  источником и актуальной версией.

## 9. Research protocol и Deep Research intake

Импортированный отчёт о методологии глубокого исследования сохранён отдельно:

- [исходная hash-verified копия](research/deep-research-methodology-2026-08-12.md);
- [impact review](research/IMPACT.md);
- [project-specific protocol](research/PROTOCOL.md);
- [claim/evidence ledger](research/CLAIMS.md);
- [search log](research/search-log.csv) и
  [amendments](research/AMENDMENTS.md).

Главный эффект: действует research evidence gate `D-014`. LLM-generated report
является candidate map, пока material claim не получил разрешимый
primary/official source, точный scope, limitations и provenance.

Targeted verification подтвердила полезность механизмов:

- [PRISMA 2020](https://www.prisma-statement.org/prisma-2020) — checklist и
  flow для прозрачного reporting;
- [Cochrane Handbook Chapter 4](https://www.cochrane.org/authors/handbooks-and-manuals/handbook/current/chapter-04)
  — planning, search design и полное документирование поиска;
- [PRISMA-S](https://pmc.ncbi.nlm.nih.gov/articles/PMC7839230/) — database,
  platform и exact search strategy reporting;
- [FAIR Guiding Principles](https://doi.org/10.1038/sdata.2016.18) — identifiers,
  metadata, license и provenance;
- [NASEM](https://nap.nationalacademies.org/catalog/25303/reproducibility-and-replicability-in-science)
  — разделение computational reproducibility и replication;
- [OSF](https://developer.osf.io/) — frozen/time-stamped registrations и DOI.

Это targeted adaptation, а не заявление о formal PRISMA-compliant systematic
review. Наиболее важное следствие для `P0.12`: primary evaluation protocol,
datasets/splits, metrics и baselines должны быть заморожены до основных
benchmark runs; последующие изменения фиксируются как amendments.

## 10. OpenAI и Anthropic: prompt injection в агентных системах

Targeted review официальных материалов от 12 августа 2026 года показывает
устойчивый общий паттерн:

1. **Untrusted content — data, не instructions.** OpenAI использует instruction
   hierarchy и source–sink framing; Anthropic отдельно предупреждает, что даже
   audited GitHub connector может внести poisoned README в context.
2. **Model robustness не является hard boundary.** OpenAI отмечает ограничения
   input classifiers/«AI firewalls» против развитой social engineering;
   Anthropic прямо пишет о ненулевом miss rate и риске adaptive repeated attacks.
3. **Нужны пересекающиеся слои.** Model training, classifiers, monitoring,
   red teaming, least privilege, sandbox, filesystem/network/egress controls и
   human gates решают разные части source–sink chain.
4. **Refusal — отдельный machine-readable outcome.** OpenAI API предоставляет
   refusal/incomplete/failed signals; Anthropic `stop_reason=refusal` может
   прийти с HTTP 200. Поэтому transport success или пустой список findings не
   являются доказательством завершённого security audit.
5. **Over-refusal тоже security-relevant.** Defensive code review и
   vulnerability research могут задевать cyber safeguards. Нужно измерять не
   только attack success, но и refusal-induced false negatives и availability.

Первичные источники:

- [OpenAI: Designing AI agents to resist prompt injection](https://openai.com/index/designing-agents-to-resist-prompt-injection/);
- [OpenAI: Improving instruction hierarchy](https://openai.com/index/instruction-hierarchy-challenge/);
- [OpenAI API: refusal response events](https://platform.openai.com/docs/api-reference/responses-streaming/response/refusal/done);
- [OpenAI model guidance: safeguards for defensive security work](https://developers.openai.com/api/docs/guides/latest-model);
- [Anthropic: Mitigating prompt injections](https://www.anthropic.com/research/prompt-injection-defenses);
- [Anthropic: How we contain Claude](https://www.anthropic.com/engineering/how-we-contain-claude);
- [Anthropic: Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing);
- [Claude Platform: stop reasons and fallback](https://platform.claude.com/docs/en/build-with-claude/handling-stop-reasons).

Проектное следствие принято в `D-015` и детализировано в
[prompt-injection threat model](security/PROMPT_INJECTION.md). Это targeted
vendor-evidence review, а не независимое измерение заявленных ими protection
rates; thresholds должны быть проверены на собственном corpus.

## 11. Evaluation-driven optimization: RLM, DSPy/GEPA и SkillOpt

Targeted review от 12 августа 2026 года разделил три разных механизма:

- [RLM](https://arxiv.org/abs/2512.24601v3) программно исследует внешний длинный
  context и делает recursive subcalls; для code audit это только sandboxed
  discovery strategy, не validator и не source of truth;
- [DSPy](https://arxiv.org/abs/2310.03714) задаёт модульную LM-программу, а
  [GEPA](https://arxiv.org/abs/2507.19457) офлайн оптимизирует её textual
  components по traces, feedback и held-out metrics;
- [SkillOpt](https://arxiv.org/abs/2605.23904) офлайн оптимизирует versioned
  skill document frozen-агента через bounded edits и validation gate.

LLM может генерировать vulnerable/fixed pairs, negative controls, metamorphic
variants, injection cases и patch bypasses, но только как candidates. Ground
truth подтверждается parse/build/test/PoC, deterministic oracle и human review;
generator/prompt/model/seed/hashes и lineage фиксируются, а производные одной
причины не разделяются между train и test.

Практический эксперимент
[kmad.ai](https://kmad.ai/Recursive-Language-Models-Security-Audit) подтверждает
feasibility `dspy.RLM` для обхода OWASP DVSA, но сам сообщает вариативность runs
и полный пропуск 4 из 10 lesson categories. Его стоимость/объём кода и любые
скриншотные F1 claims не являются benchmark evidence SecureCode AI.

Подробный проектный разбор, safety profile и staged ablation plan сохранены в
[RLM/DSPy/SkillOpt research note](research/RLM_DSPY_SKILLOPT.md). Эти методы
приняты в ограниченный offline scope `CR-016` и `P7.12–P7.16`, а не
обязательными runtime dependencies.

## 12. Wazuh patterns applicable to SecureCode AI

Проверено 16 сентября 2026 года по официальной документации и основному
репозиторию Wazuh.

Для текущего M-A2026 полезны четыре независимо реализуемых принципа:

1. Разделять сбор, декодирование, правило и alert. В SecureCode AI это
   соответствует цепочке `RawSignal -> normalization -> EvidenceGraph ->
   FindingCase -> verdict -> report`; сигнал сканера сам по себе не является
   вердиктом.
2. Давать тестовый трассировочный режим наподобие `wazuh-logtest`, где один
   фиксированный вход показывает извлеченные факты, стабильный rule ID,
   доказательства и итоговый verdict. M-A2026 notebook показывает такой
   поэтапный публичный CWE-89 пример.
3. Хранить пользовательские правила отдельно от поставляемых и версионировать
   `rule_id`, `rule_version`, CWE, source lane и evidence references.
4. Использовать file-integrity baseline для accepted specs, evaluator, исходного
   checkout и patch до и после sandbox validation.

После M-A2026 можно исследовать inventory и CVE/OSV correlation, разделение
collector/analysis/storage/dashboard и фильтрованные SARIF/webhook интеграции.
Wazuh Active Response с привилегированным запуском команд не переносится: для
SecureCode AI остаются обязательными dry-run, capability policy, явное
разрешение и обратимость. Код, XML rules и внутренние протоколы Wazuh не
копируются. Основной репозиторий указывает GPLv2, поэтому идеи реализуются
независимо, а любое повторное использование потребует отдельной лицензионной
проверки.

Первичные источники:

- [Wazuh architecture](https://documentation.wazuh.com/current/getting-started/architecture.html);
- [Testing decoders and rules](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html);
- [File integrity monitoring](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/how-it-works.html);
- [Wazuh vulnerability detection](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html);
- [Wazuh license](https://github.com/wazuh/wazuh/blob/main/LICENSE).
P7.23 provider terminal diagnosis, checked 2026-09-17

Live literal-loopback Ollama 0.16.2/Qwen2.5-Coder public probes with explicit non-streaming return native chat done=false, no parsed tool_calls and no final eval metrics. OpenAI equivalents have null finish_reason and zero usage. A simple weather-function comparator completes done=true/stop with positive metrics but still emits no parsed calls. The model remains unqualified for repository native-tool selection; advertised tools and template markers are insufficient evidence.

Primary source inspection explains why HTTP success is insufficient: the exact-version non-streaming [ChatHandler](https://raw.githubusercontent.com/ollama/ollama/v0.16.2/server/routes.go) drains the response channel, keeps the last response, accumulates parsed tool calls and returns HTTP200 without requiring Done=true (lines2286-2332). The [OpenAI mapper](https://raw.githubusercontent.com/ollama/ollama/v0.16.2/openai/openai.go) uses native metrics and an absent DoneReason yields a null finish reason when no parsed call exists (lines215-270). This supports the observed failure surface, not a proven cause of the missing terminal event. Template/parser/model behavior requires further qualification; arbitrary text containing function JSON is not a native event.

Two regression cases reject null terminal reason and an empty tool-call selection as gateway502 with dispatched=true, refusal=false. Keep failed attempts visible and production capability flags false. Public source and raw model replies were ephemeral and are absent from durable reports. Probe receipts contain bounded metadata only.

P7.23 final diagnostic before checkpoint: native streaming public probe HTTP200,58 events,111 content bytes,0 terminal events/0 parsed tool calls/0 error events,17.462s. Explicit stream=false native chat also returns done=false/no final metrics; simple tool comparator done=true/positive metrics but0 parsed calls. Root exact-version official ChatHandler/OpenAI source inspection confirms HTTP200 is not terminal authority, missing runner terminal cause still unlocalized. Two new gateway regressions31 PASS. Index-candidate SpecGate PASS against ec9cf5167aae80fb6062be8e0f25c95601b36973. P7.23 native-cycle code checkpoint may commit; real model qualification remains IN PROGRESS/false, no profile or gate promotion.

P7.24 candidate source checked 2026-09-17: official Ollama tags list qwen3:4b-instruct-2507-q4_K_M as a 2.5GB instruct model (https://ollama.com/library/qwen3/tags). Chosen only as a bounded development qualification candidate after Qwen2.5-Coder native probes failed; no held-out access or quality advantage is inferred. Existing local AMD adapters are observed, but Nvidia telemetry is unavailable and Win32 AdapterRAM values are not sufficient VRAM qualification. Official pull through current loopback daemon is active; raw source/generation providers remain excluded.
P7.24 transport diagnosis (2026-09-17): public source-free short tool prompt through native /api/chat now gives done=true/native call/positive184+46 metrics; with all four tools gives native call but wrong head rejected by host validation. Same all-four OpenAI short prompt with response_format=json_object gives stop/0 calls/368+52 tokens (3.884s); without response_format gives tool_calls/1 call/368+45 tokens (3.320s), schema/evidence/name correct but head wrong. This local comparator establishes a JSON-content-grammar/native-call conflict for this input, not full root cause of prior nonterminal replies. P7.24 packet includes gateway/test paths for native-only upstream format translation; policy hash version1.3, incoming envelope and host final/native argument validation unchanged (D-065). Root49 focused gateway/qualifier checks PASS; actual corrected four-probe run active in session31393, review pending. No capability/profile admission.
P7.24 code checkpoint committed765324822db70df80a6a9e0ab7c16bef7780275a: ordinary policy/secret/workflow hooks PASS, committed-candidate SpecGate PASS against32eebc2f2b7273a4e43e682fc9f8c23f0734cc4d. Real r3 terminal: three502/one504,0/4 accepted, no model admission. One subsequent real public lookup_symbol diagnostic using checked actual LoopbackOllamaBackend produced backend200/native terminal/one function/positive measured usage; exact head/version/symbol/path and closed argument keys all correct, but gateway still rejected before Core receipt. Injected diagnostic wrapper is correctly SIMULATED and not qualification evidence. This falsifies unsupported-native-calling as a sufficient explanation of the remaining failure; transport codec must be investigated before replacing models or running benchmarks. Official exactv0.16.2 OpenAI ToolCall struct includes mandatory index integer and ToToolCalls emits it (https://raw.githubusercontent.com/ollama/ollama/v0.16.2/openai/openai.go lines164-171,223-239, verified2026-09-17); our native argument parser accepts only id/type/function call envelope. Native transport index canonicalization is the next bounded P7.25 increment; allow only positively verified provider metadata and retain closed canonical argument schemas/head checks. No raw replies/source retained, all probe/commit sessions terminal, all writer leases released, goal active and G5-G9 unchanged.
P7.25 native provider framing correction (2026-09-17): packet starts765324822db70df80a6a9e0ab7c16bef7780275a, gateway/tests plus operational docs only; accepted specs/evaluators/gate evidence unchanged. Exact observed index regression failed502 before correction. Known Ollama envelope now canonicalizes optional exact-int index0..3 before unchanged closed arguments/head/full provider codec, raw call count1..4; policy1.4/D-066. Root205 nearby HTTP/native-cycle/connector/normalizer/public-qualifier checks PASS (8.97s), no failures/skips, Mypy1/Ruff2/diff-check PASS. Independent critical review scoped PASS gatewaySHA9773bf7c436f873639ef5b43d47d5183c60d03c217cfa94c364aa7cc4077b34a. Actual LIVE four-tool run terminal: list_paths1176+80 tokens, lookup_symbol1176+80, read_range1180+87 each native-terminal/one exact call/one Core guard receipt/QUALIFIED; read_evidence504/zero accepted receipt. Overall3/4, public_native_tools_conformant=false and production_admitted=false. Fixed fixture evidence alias length78; existing CPU-only execution and30s deadline retained, no alias/schema/budget weakening or blind success retry. Ignored source-free receipt p725-qwen3-four-tools-r1.json. No active probe process, writer leases root/review read-only. P7.25 remains IN PROGRESS for complete real qualification; next root-cause/latency diagnosis and host-owned receipt-bound profile/full Core conformance before actual CLI admission. G5-G9, independent quality/repair/pilot and full v1.0 remain open.

P7.40 serving-latency diagnosis, checked 2026-09-17

The P7.35 and P7.39 public-Core receipts reached a generation headers deadline before any response normalization. P7.36-P7.37 delivered HTTP200 and reached post-transport normalization; P7.38 additionally reached strict native arguments validation. These are separate failure boundaries and do not explain every historical structured-output failure. Local read-only inventory found Ollama 0.16.2, installed Qwen3/Qwen2.5 models, bundled HIP/Vulkan libraries, a Vulkan-visible AMD Radeon RX 6600M and no currently loaded model. The daemon startup record selected CPU and explicitly recorded Vulkan disabled. This proves neither a successful GPU execution nor cause of a prior timeout.

Ollama documents Vulkan support for Windows and Linux, discrete-GPU selection through `GGML_VK_VISIBLE_DEVICES`, and `OLLAMA_VULKAN=0` as a way to disable Vulkan ([GPU support](https://github.com/ollama/ollama/blob/main/docs/gpu.mdx), checked 2026-09-17). Its development guide describes GPU acceleration libraries as optional build/runtime components whose presence alone does not prove acceleration ([development guide](https://docs.ollama.com/development), checked 2026-09-17). D-082 therefore does not enable or force an experimental backend. The next single public diagnostic reduces only the existing profile output ceiling from 1024 to 256 tokens, keeps model/context/input/tools/sampling and all 30/60/120-second bounds pinned, and may run once after offline propagation checks and independent review. A result remains source-free and cannot admit a provider.

## P7.56 product classification sources, 18 September2026

The explicitly versioned OWASP Top10 2021 primary category pages list CWE-78 under [A03 Injection](https://top10.owasp.org/2021/A03_2021-Injection/), CWE-22 and CWE-862 under [A01 Broken Access Control](https://top10.owasp.org/2021/A01_2021-Broken_Access_Control/), and CWE-918 under [A10 SSRF](https://top10.owasp.org/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/). These taxonomy links support deterministic category mapping only; they establish neither per-case severity, calibrated confidence nor measured product detection quality. P7.56 must preserve historical CWE89 provenance and publish separate host-owned mapping identity for the existing wider portfolio.

## P7.6 public source eligibility and metadata acquisition, 18 September 2026

Root verified [CVEfixes v1.0.8](https://zenodo.org/records/13118970): published 28 July 2024, before/after fixing metadata; archive size 12,708,711,268 bytes and published MD5 4586a358977acfa4c60b1a2cdd096221. The [publisher API](https://zenodo.org/api/records/13118970) declares dataset CC-BY-4.0. The [collector license](https://raw.githubusercontent.com/secureIT-project/CVEfixes/main/LICENSE.txt) is MIT; individual upstream source licenses remain separate and unresolved until pair acquisition. Published fixing/function counts do not establish executable cases; archive SHA256 requires acquisition.

The [canonical Go database API](https://go.dev/doc/security/vuln/database) provides OSV metadata, not executable parent/fix pairs; internal repository YAML is not stable API. [Database entries](https://raw.githubusercontent.com/golang/vulndb/master/README.md) use CC-BY-4.0. Root acquired only public index/db metadata under ignored work/acquisitions/go-vulndb-20260918: 4,474 distinct vulnerability IDs, 465,857 index bytes, SHA256 6a920eeeb85d623cc639fe97ae33ea1ef9fce682e19c033504f5cd3b4018b52b, database modified 2026-09-16T18:00:43Z. Exact bytes match the independent source-intake snapshot. No source code was downloaded or executed; admitted cases remain zero. Fixed versions, reviewed reports and ID counts cannot substitute independently checked lineage-paired root causes/oracles. The required100 vulnerable/fixed pairs per language remain unproven. Source intake does not alter frozen data/evaluators, held-out expectations or benchmark results.

P7.6 Go metadata pool extended with40 canonical public OSV reports from pinned index (deterministic highest modified/id selection):8 publisherREVIEWED reports and35 distinct FIX URLs with full GitHub commit SHA. Raw metadata exact hashes/pool retained under ignored acquisition path; source code checkouts not downloaded/executed, root-cause/oracle and per-upstream licenses unresolved, admitted cases0. Publisher review/fix reference is not independent pair admission or global safe label.

P7.6 root public fixing-lineage metadata intake:4 full-SHA FIX references from publisherREVIEWED Go reports verified against public commit API;3 single-parent refs and1 multi-parent merge ref. Source-free parent/fix identifiers and API-response digests recorded under ignored acquisitions; no checkout/source-file import or code execution, no case admission. Merge parent choice, individual source licenses, root-cause and vulnerable-parent-red/fix-green oracle remain unresolved. No confirmatory dataset/evaluator/split or metrics changed.

## CR-088 Cloudflare security-audit-skill reference

Checked 19 September 2026 against the pinned upstream commit
`c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` in the public Cloudflare
`security-audit-skill` repository. The repository describes reconnaissance,
coverage-led hunting, independent candidate validation, structured findings and
target-neutral reporting. It includes source-free coverage-ledger and findings
validators, and requires bounded OS-enforced sandbox execution with trusted
parent-side promotion of allowlisted results. Its documented coverage domains
include AI/LLM misuse, data isolation and tenant lifecycle, resource
exhaustion and availability, supply chain and release, and desktop/mobile/local
IPC.

Primary sources:

- [Pinned repository tree](https://github.com/cloudflare/security-audit-skill/tree/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8)
- [Pinned README](https://raw.githubusercontent.com/cloudflare/security-audit-skill/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/README.md)
- [Pinned workflow](https://raw.githubusercontent.com/cloudflare/security-audit-skill/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/skills/security-audit/SKILL.md)
- [Pinned validation and reporting](https://raw.githubusercontent.com/cloudflare/security-audit-skill/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/skills/security-audit/VALIDATION-AND-REPORTING.md)
- [Pinned coverage-ledger validator](https://raw.githubusercontent.com/cloudflare/security-audit-skill/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/skills/security-audit/validate-coverage-ledger.cjs)
- [Pinned MIT license](https://raw.githubusercontent.com/cloudflare/security-audit-skill/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/LICENSE)

Project applicability is limited to independently implemented, source-free
release evidence. Cloudflare code, prompts, workflow text, validators and
schemas are not copied or installed. The reference does not prove SecureCode
AI detection quality, safe Auto-Fix, tenant isolation, sandbox capability,
local IPC controls or G8/G9 readiness. Those claims require SecureCode-owned
contracts, deterministic checks, independent reviews and the later normative
change-control path in P9.18. Upstream provenance is a primary-source fact;
the mapping to P8.13-P8.15 is an accepted project proposal under D-106.
