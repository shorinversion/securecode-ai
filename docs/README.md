# SecureCode AI — проектные документы

Этот каталог фиксирует проверяемые выводы, архитектурные решения, источники,
риски и открытые вопросы проекта. Документы должны обновляться после каждого
существенного изменения направления, чтобы проект можно было восстановить без
опоры на историю чата.

## Документы

- [PROJECT_BRIEF.md](PROJECT_BRIEF.md) — исходное задание и граница между baseline и расширениями.
- [PLAN.md](PLAN.md) — master plan от MVP до v1.0 с задачами, gates и контрольными точками.
- [SPEC_DRIVEN_DEVELOPMENT.md](SPEC_DRIVEN_DEVELOPMENT.md) — contract-first процесс, specification hierarchy и ограничения для LLM-разработки.
- [AI_ASSISTED_DEVELOPMENT.md](AI_ASSISTED_DEVELOPMENT.md) — понятное описание
  роли ИИ, Primary Integrator/субагентов, tests, gates и controlled optimization.
- [specs/README.md](../specs/README.md) — нормативный SDD baseline 0.2.0 и шаблоны.
- [CHANGELOG.md](../CHANGELOG.md) — хронология значимых изменений и change requests.
- [RESEARCH.md](RESEARCH.md) — научные работы, стандарты, инструменты и конкуренты.
- [research/README.md](research/README.md) — raw Deep Research, provenance, protocol, claim ledger и impact review.
- [research/RLM_DSPY_SKILLOPT.md](research/RLM_DSPY_SKILLOPT.md) — RLM,
  DSPy/GEPA, SkillOpt, synthetic eval cases и controlled optimization loop.
- [ARCHITECTURE.md](ARCHITECTURE.md) — целевая graph-based архитектура и контракты.
- [security/PROMPT_INJECTION.md](security/PROMPT_INJECTION.md) — threat model для untrusted code, refusal-induction и fail-closed LLM outcomes.
- [security/THREAT_MODEL.md](security/THREAT_MODEL.md) — полный system threat model, trust boundaries и risk register.
- [PRODUCT.md](PRODUCT.md) — CLI, CI, GitHub/GitLab и enterprise-сценарии.
- [DECISIONS.md](DECISIONS.md) — принятые решения с обоснованием и последствиями.
- [CONTEXT.md](CONTEXT.md) — компактная актуальная сводка для продолжения работы.
- [TEACHER_QUESTIONS.md](TEACHER_QUESTIONS.md) — вопросы куратору, default assumptions и gates, до которых нужен ответ.
- [READINESS_AUDIT.md](READINESS_AUDIT.md) — requirement-by-requirement completion audit и точная граница effective G0/P1.

## Навигация для агентов

- [securecode-project-navigator](../.agents/skills/securecode-project-navigator/SKILL.md) — обязательный протокол восстановления и сохранения контекста.
- [AGENTS.md](../AGENTS.md) — корневые инструкции, автоматически направляющие агента к skill.

## Правило ведения

Сохраняются не черновые рассуждения, а:

- принятое решение;
- факты и первичные источники;
- мотивировка и рассмотренные альтернативы;
- ограничения и риски;
- вопросы, которые ещё не закрыты;
- влияние решения на реализацию и проверку проекта.
