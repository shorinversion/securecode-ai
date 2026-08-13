# RLM, DSPy/GEPA, SkillOpt и evaluation-driven improvement

Статус: targeted research note, не ADR и не принятое runtime-решение.  
Дата проверки: 12 августа 2026 года.  
Область: model-native code discovery, prompt/program optimization, agent-skill
optimization и генерация evaluation cases для SecureCode AI.

## 1. Короткий вывод

Все четыре идеи полезны, но решают разные задачи:

| Механизм | Что оптимизируется/масштабируется | Роль в SecureCode AI |
|---|---|---|
| RLM | Исследование слишком большого контекста через программный доступ и recursive subcalls | Экспериментальная стратегия внутри model-native discovery lane |
| DSPy | Модульная LM-программа с typed signatures | Возможный research/eval adapter, не доменное ядро |
| GEPA | Prompts/instructions/tool descriptions по traces, feedback и метрикам | Офлайн-оптимизация только на train/development splits |
| SkillOpt | Версионируемый `SKILL.md` frozen-агента | Офлайн-оптимизация процедур отдельных ролей через held-out gate |
| LLM-generated cases | Новые vulnerable/safe/mutated/adversarial candidates | Расширение train/dev/red-team corpus; не самостоятельный ground truth |

Ни один механизм не заменяет deterministic analyzers, EvidenceGraph, sandbox,
locked test set или human review. Самоизменение в production запрещено: новый
prompt/skill/RLM policy становится candidate artifact и проходит обычный
promotion gate.

## 2. Что уже есть в evaluation baseline

Принятый протокол уже требует:

- сравнение `deterministic_only`, `llm_only`, `one_shot_llm` и `hybrid` при
  сопоставимых budgets;
- precision/recall/F1/F2, FP/KLOC, false blocks/PR, localization, CWE accuracy,
  evidence completeness, coverage, abstention и refusal-induced FN;
- apply/build/test/PoC/PoC+/`correct_and_secure` rates для патчей;
- prompt-injection ASR, benign over-refusal, unauthorized operations, leakage и
  cost amplification;
- latency, tokens, cost, CPU/RAM/disk и replay stability;
- frozen test inputs/evaluator, lineage-aware splits и запрет tuning по test.

RLM/DSPy/SkillOpt не требуют заменить этот контракт. Они добавляют candidate
configurations в `P7.7/P7.8` и должны выиграть на нём без нарушения hard
security invariants.

## 3. Evaluation harness

```text
Dataset registry + immutable split manifests
                    ↓
Configuration matrix
(model/prompt/skill/discovery/tools/budgets/seeds)
                    ↓
Isolated runner → append-only event/coverage/usage log
                    ↓
Deterministic graders + sandbox tests + calibrated human review
                    ↓
Per-case outcomes → metrics + uncertainty + failure reconciliation
                    ↓
Candidate promotion gate or rejection archive
```

LLM-as-a-judge может быть только дополнительным измерением для качественных
аспектов. Его verdict калибруется по human-labelled subset, не переопределяет
компиляцию/тест/PoC/schema/policy и не имеет доступа к identity оцениваемой
конфигурации.

## 4. Можно ли генерировать benchmark cases с LLM

Да, но модель генерирует **кандидаты**, а не истину. Безопасный pipeline:

1. Выбрать CWE/root-cause family и формальный invariant.
2. Сгенерировать пару vulnerable/fixed и независимый negative control.
3. Добавить metamorphic variants: rename/reorder/wrapper/indirection/decoy/
   межфайловый flow без изменения ground truth.
4. Проверить parse/build/runtime и vulnerability oracle/PoC.
5. Проверить вручную root cause, exploitability assumptions и отсутствие
   случайной второй уязвимости.
6. Зафиксировать generator model, prompt, seed, toolchain, hashes и lineage.
7. Группировать все производные одной причины в один split.
8. Использовать generated cases преимущественно для train/dev/fuzz/red-team;
   финальный locked test содержит независимые human-reviewed/real-world cases.

Особенно полезны автоматически генерируемые классы:

- vulnerable/fixed twins и safe hard negatives;
- multi-file data-flow mutations;
- authz/IDOR/business-logic cases без SAST seed;
- prompt injection в code/comments/README/SCM/tool output;
- refusal/timeout/invalid-schema provider fixtures;
- patch bypasses и PoC+ variants.

Запрещено измерять качество на тех же случаях, по которым оптимизатор менял
prompt/skill, или считать согласие нескольких LLM независимым ground truth.

## 5. RLM

[Recursive Language Models](https://arxiv.org/abs/2512.24601v3) рассматривают
длинный prompt как внешнюю среду: модель программно исследует, декомпозирует и
может вызывать LM/RLM на выбранных фрагментах. Результаты paper относятся к
long-context tasks, а не к security auditing.

Официальная [реализация](https://github.com/alexzhang13/rlm) поддерживает REPL и
recursive subcalls. Её default local environment использует host-process
Python execution, а авторы прямо не рекомендуют его для production. Для
SecureCode AI такой default неприемлем: repository content недоверенно, а
сгенерированный код является capability request.

Допустимый `RLM-inspired Code Explorer`:

- получает immutable read-only `CodeIndex`, не host filesystem;
- имеет whitelist pure query API: list paths, read bounded slice, symbol,
  references, callers, AST/call/data-flow facts;
- выполняет generated query code только в rootless isolated sandbox без сети,
  credentials, host mounts, evaluator/spec/golden data и write capability;
- ограничивает recursion depth, iterations, parallel subcalls, CPU/RAM/time,
  token/cost и максимальный read volume;
- сохраняет каждый query, source slice, subcall, terminal reason и coverage;
- возвращает только candidate hypotheses с evidence refs;
- refusal/error/budget exhaustion дают incomplete coverage, не clean result.

Сначала RLM сравнивается с обычным bounded tool loop при одинаковом model,
prompt, facts и budget. Он не становится обязательной зависимостью, пока не
улучшит held-out detection/evidence coverage в допустимом cost/safety envelope.

## 6. Разбор эксперимента kmad.ai

[Auditing a Codebase for 87 cents in 50 lines of code using RLMs](https://kmad.ai/Recursive-Language-Models-Security-Audit)
— полезный practitioner proof of concept на намеренно уязвимом OWASP DVSA.
Скрипт загружает всё дерево в nested dictionary и запускает `dspy.RLM` с
`max_iterations=35`.

Ограничения, которые сообщает сам автор:

- один выбранный успешный provider/model configuration;
- возможная training-data contamination;
- результаты менялись между повторными runs;
- четыре из десяти lesson categories полностью пропущены: authentication,
  denial of service, logic/TOCTOU и vulnerable dependencies;
- нет locked dataset protocol, precision/FP, uncertainty, resource-equivalent
  baselines или patch validation.

Следовательно, `$0.87`, `~50 lines` и скриншотные improvement claims нельзя
переносить на SecureCode AI. Статья поддерживает feasibility hypothesis, а не
accuracy или production readiness.

## 7. DSPy и GEPA

[DSPy](https://arxiv.org/abs/2310.03714) выражает LM pipeline как композицию
typed/declarative modules и оптимизирует его параметры по метрике. Это полезно
для research adapter поверх наших domain ports, но DSPy не должен становиться
источником workflow state или публичных contracts.

[GEPA](https://arxiv.org/abs/2507.19457) использует execution trajectories,
scalar score и богатый textual feedback, предлагает prompt mutations и ведёт
Pareto frontier кандидатов. Для SecureCode AI он применим только офлайн:

```text
frozen model + frozen harness + train cases
→ trajectories and stage-specific failures
→ bounded prompt mutation
→ validation split
→ accept only non-regressing candidate
→ one final locked-test evaluation
```

Hard constraints имеют приоритет над aggregate score:

- `non_success_to_pass_count == 0`;
- unauthorized operation/egress/leak counts равны нулю;
- schema/policy invariants проходят;
- precision/false-block floor не ухудшается ниже принятого порога.

После этого оптимизируется Pareto-набор: F2/recall, precision, evidence
completeness, `correct_and_secure`, coverage, cost и latency. Нельзя свести всё
к одному F1: оптимизатор способен поднять recall ценой неприемлемого шума или
fail-open поведения.

## 8. SkillOpt и набор agent skills

[SkillOpt](https://arxiv.org/abs/2605.23904) трактует skill document как
обучаемое внешнее состояние frozen agent: отдельная optimizer model предлагает
bounded add/delete/replace edits, а candidate принимается только после
held-out validation. Результаты paper получены на его benchmarks/models и не
доказывают улучшение security audit без нашего эксперимента.

Целевой набор узких skills:

1. `repository-mapper` — surfaces, boundaries, entry points и coverage plan;
2. `semantic-scout` — independent direct-source discovery;
3. `evidence-builder` — source/transform/guard/sink graph;
4. `auditor` — подтверждение/отклонение и proof gaps;
5. `skeptic` — counterevidence и adversarial review;
6. `architect` — root-cause repair и minimal diff;
7. `patch-validator` — test/PoC+/post-scan ladder;
8. `report-scm` — high-signal report, SARIF и bounded annotations.

Правила optimization:

- сначала вручную написать минимальные skills из accepted contracts;
- оптимизировать по одному skill при frozen остальных компонентах;
- train/selection/test разделены по repository/CVE/root-cause lineage;
- protected policy, capabilities, schemas, evaluator и expected outputs не
  входят в редактируемый skill;
- candidate skill проходит diff review, security regression, cross-model/
  cross-harness check и получает immutable version/hash;
- production agent никогда сам не продвигает собственный skill.

## 9. Экспериментальная последовательность

Полный Cartesian product слишком дорог и создаёт риск cherry-picking. Нужны
последовательные ablations:

1. `one-shot` против bounded tool loop против RLM-inspired explorer при одном
   prompt/skill/model.
2. Human prompt против GEPA candidate при фиксированных strategy/skill/model.
3. No-skill против manual skill против SkillOpt candidate при фиксированных
   strategy/prompt/model.
4. Лучшие validation candidates объединяются и один раз проверяются на locked
   test с повторными seeds и confidence intervals.
5. Победитель обязан подтвердить переносимость хотя бы на второй model profile;
   иначе artifact маркируется model-specific.

Решение о runtime adoption принимается только по ablation evidence. До этого
RLM/DSPy/GEPA/SkillOpt — experimental tooling, а не обещанная product feature.

## 10. Первичные источники

- [Recursive Language Models v3](https://arxiv.org/abs/2512.24601v3) и
  [официальный код](https://github.com/alexzhang13/rlm);
- [DSPy paper](https://arxiv.org/abs/2310.03714) и
  [официальный репозиторий](https://github.com/stanfordnlp/dspy);
- [GEPA paper](https://arxiv.org/abs/2507.19457) и
  [DSPy GEPA documentation](https://github.com/stanfordnlp/dspy/blob/main/docs/docs/api/optimizers/GEPA/overview.md);
- [SkillOpt paper](https://arxiv.org/abs/2605.23904) и
  [официальный репозиторий Microsoft](https://github.com/microsoft/SkillOpt).

