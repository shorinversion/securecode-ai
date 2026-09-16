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
