# SecureCode AI — защита от prompt injection и fail-open отказов

Статус: `accepted security baseline`; normative enums, provider profile,
mandatory-stage catalogue и evaluation protocol закрыты в `specs/`.  
Дата: 12 августа 2026 года.  
Область: исходный код, документация репозитория, SCM metadata, tool output,
model output и все workflow-решения, зависящие от LLM.

## 1. Решение

Весь контент репозитория считается **данными атакующего**, даже когда он
выглядит как инструкция, policy, system message или результат инструмента.
Это относится не только к `README` и комментариям, но и к:

- строковым литералам, docstrings, identifiers и именам файлов;
- test fixtures, snapshots, generated/vendor files и lockfiles;
- commit messages, branch names, PR/MR titles, descriptions и discussions;
- compiler/test/build logs, SARIF, scanner output и dependency metadata;
- Unicode/Bidi/zero-width text, кодировкам и инструкции, разделённой между
  несколькими файлами или этапами workflow.

Главное правило безопасности:

> Отсутствие корректного LLM verdict не является доказательством отсутствия
> уязвимости.

`refusal`, content-filter intervention, пустой ответ, invalid schema,
truncation, context overflow, timeout, provider error, exhausted budget и
остановленный tool loop никогда не преобразуются в `safe`, `clean`,
`no_finding` или успешный merge gate.

## 2. Почему prompt-only защиты недостаточно

Опыт OpenAI и Anthropic поддерживает defense in depth:

- OpenAI описывает современные injection-атаки как social engineering и
  использует source–sink framing; отдельный input classifier/«AI firewall» не
  ловит все развитые атаки, поэтому нужны ограничения capabilities,
  monitoring, sandboxing и red teaming
  ([OpenAI: Designing AI agents to resist prompt injection](https://openai.com/index/designing-agents-to-resist-prompt-injection/)).
- Instruction hierarchy улучшает устойчивость, но остаётся свойством модели,
  а не детерминированной security boundary
  ([OpenAI: Improving instruction hierarchy](https://openai.com/index/instruction-hierarchy-challenge/)).
- Anthropic прямо отмечает, что даже низкий attack success rate остаётся
  значимым, а ни один agent не иммунен; используются model training,
  classifiers и expert red teaming
  ([Anthropic: Mitigating prompt injections](https://www.anthropic.com/research/prompt-injection-defenses)).
- Anthropic рассматривает model defense как вероятностную и ограничивает blast
  radius через environment containment и permissions. Audited connector не
  означает trusted data: разрешённый GitHub connector всё равно может загрузить
  poisoned README
  ([Anthropic: How we contain Claude](https://www.anthropic.com/engineering/how-we-contain-claude)).
- Для coding agents Anthropic требует одновременно filesystem и network
  isolation; одного из этих барьеров недостаточно
  ([Anthropic: Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing)).

Следствие для проекта: injection detector полезен как сигнал, но не является
ни единственным барьером, ни oracle, ни основанием объявить анализ успешным.

## 3. Два независимых автомата состояния

### 3.1. ModelCallStatus

Provider adapter нормализует transport и model outcome до закрытого enum:

```text
SUCCEEDED
REFUSED
CONTENT_FILTERED
INCOMPLETE
TRUNCATED
CONTEXT_EXHAUSTED
INVALID_SCHEMA
EMPTY_OUTPUT
TIMEOUT
RATE_LIMITED
PROVIDER_ERROR
BUDGET_EXHAUSTED
GUARDRAIL_BLOCKED
CANCELLED
```

`SUCCEEDED` означает только успешное получение полного schema-valid ответа. Он
не означает, что код безопасен или verdict правилен.

### 3.2. FindingVerdict

Security verdict имеет отдельный enum:

```text
CONFIRMED
REJECTED_WITH_EVIDENCE
NEEDS_MORE_EVIDENCE
CONFLICTING
NOT_EVALUATED
```

Только `REJECTED_WITH_EVIDENCE` с достаточным coverage может отрицать конкретную
гипотезу. `NOT_EVALUATED` не эквивалентен `REJECTED_WITH_EVIDENCE`.

### 3.3. AuditRunOutcome

```text
PASS            все обязательные stages завершены и coverage policy выполнена
FAIL            найдено blocking finding
INDETERMINATE   обязательный анализ не завершён или не доказал coverage
ERROR           инфраструктурная ошибка до получения пригодного evidence
SUPERSEDED      результат относится не к текущему HEAD SHA
CANCELLED       run явно отменён и не является проходным
```

В blocking-профиле только `PASS` является проходным. `FAIL`, `INDETERMINATE` и
`ERROR` имеют разные причины и UX, но не могут молча открыть merge. В advisory
режиме `INDETERMINATE` может не блокировать, однако интерфейс обязан показать,
что проверка не завершена, и запрещено писать «уязвимостей не найдено».

## 4. Нормализация provider responses

| Provider signal | Нормализованный статус | Разрешённое действие |
|---|---|---|
| OpenAI output part `refusal` / refusal event | `REFUSED` | bounded fallback или human review; не pass |
| OpenAI response `incomplete` / content filter | `INCOMPLETE` или `CONTENT_FILTERED` | сохранить reason; не использовать частичный verdict |
| OpenAI response `failed` | `PROVIDER_ERROR` | retry по policy; затем indeterminate/error |
| Anthropic `stop_reason=refusal` | `REFUSED` | прочитать native details, bounded fallback; не pass |
| Anthropic `max_tokens` | `TRUNCATED` | не принимать частичный verdict |
| Anthropic `model_context_window_exceeded` | `CONTEXT_EXHAUSTED` | пересобрать bounded context или escalate |
| Anthropic `pause_turn` | промежуточное состояние | продолжить только в пределах loop budget |
| HTTP 2xx с пустым/невалидным body | `EMPTY_OUTPUT`/`INVALID_SCHEMA` | не считать transport success анализом |

OpenAI Responses API различает output text, refusal, incomplete и failed
responses
([OpenAI Responses API](https://platform.openai.com/docs/api-reference/responses-streaming/response/refusal/done)).
Anthropic предупреждает, что `stop_reason=refusal` приходит как нормальный HTTP
200, а `max_tokens` и context exhaustion требуют отдельной обработки
([Claude stop reasons](https://platform.claude.com/docs/en/build-with-claude/handling-stop-reasons)).

Адаптер обязан читать native metadata до анализа текста. Text heuristic вроде
`"I cannot"` используется только как дополнительная защита для provider без
нативного сигнала и никогда не превращает неизвестное состояние в успех.

## 5. Attack catalogue

### A. Прямая injection

- `ignore previous instructions` и поддельные system/developer/tool messages;
- инструкции отключить scanner, изменить severity, вернуть пустой список;
- просьбы открыть URL, прочитать secrets, вызвать shell или изменить evaluator.

### B. Скрытая и композиционная injection

- zero-width/Bidi/homoglyph/HTML comment/Markdown metadata;
- Base64 или иная кодировка, намеренно декодируемая моделью;
- части команды в разных symbols/files или source и tool output;
- инструкции в test output, stack traces, generated code и dependency data;
- benign-looking social engineering: срочность, авторитет, fake policy,
  ложная необходимость для выполнения аудита.

### C. Refusal induction / semantic denial of analysis

Атакующий оформляет уязвимый фрагмент как чувствительный dual-use контент или
добавляет слова/контекст, способные вызвать safety classifier. Цель — не
подчинить агента, а заставить его отказаться, оборвать structured output или
исчерпать context/budget. Опасная реализация затем интерпретирует отсутствие
verdict как `clean`.

### D. Coverage suppression

- убедить модель не цитировать evidence или пропустить source-to-sink path;
- перегрузить context большим нерелевантным файлом;
- заставить вернуть schema-valid, но семантически пустой ответ;
- отравить cache/memory или присвоить недоверенному выводу trusted provenance.

### E. Tool и egress escalation

- превратить анализ кода в чтение файлов вне checkout;
- инициировать сеть, upload или запрос с данными в URL/header/body;
- изменить policy, config, baseline, hidden tests или evidence store;
- использовать разрешённый домен как широкую capability grant.

## 6. Защитная архитектура

### 6.1. Provenance и trust labels

Каждый context span получает неизменяемые поля:

```text
content_id
content_hash
origin_type
origin_uri_or_path
repository_sha
trust_class
instruction_authority = NONE
parser/transformation provenance
```

Для `repo_code`, `repo_docs`, `scm_metadata`, `tool_output` и
`generated_output` значение `instruction_authority` всегда `NONE`. Контент
передаётся как цитируемые данные с stable IDs, а не конкатенируется с
system/developer instructions.

### 6.2. Детерминированный слой не может быть подавлен LLM

- raw scanner signals append-only;
- LLM может подтвердить, оспорить с evidence или запросить факты, но не удалить
  signal и не переписать provenance;
- suspicious injection сама создаёт evidence/event;
- existing deterministic High/Critical finding сохраняет blocking relevance,
  даже если Auditor отказался отвечать.

### 6.3. Least privilege и containment

- Auditor/Skeptic получают read-only evidence tools без shell и network;
- Architect пишет только patch candidate в ephemeral copy;
- Validator запускает заранее разрешённые команды в non-root sandbox;
- sandbox не содержит SCM/LLM/secrets; network deny-by-default;
- egress выдаётся на конкретную операцию и credential provenance, а не только
  на domain allowlist;
- policy engine находится вне model context и проверяет tool arguments.

### 6.4. Bounded recovery вместо молчаливого pass

При non-success разрешены в порядке policy:

1. повтор с меньшим, provenance-preserving context;
2. defensive-security reframe без удаления существенного evidence;
3. fallback на совместимую модель/provider с отдельным audit event;
4. independent deterministic/secondary-model review;
5. `INDETERMINATE` и human escalation после исчерпания budget.

Blind retry той же атаки запрещён: он повышает вероятность probabilistic bypass
и создаёт cost/availability DoS.

### 6.5. Защита от fail-closed DoS

Fail-closed поведение само может быть использовано для блокировки каждого PR.
Поэтому система не должна выбирать между «ложно пропустить» и «навсегда
заблокировать»:

- подозрительные spans изолируются, но сохраняются для forensic review;
- сначала выполняется deterministic coverage и минимальный evidence slice;
- fallback/retry ограничены числом попыток, токенами, временем и стоимостью;
- `INDETERMINATE` показывает точную причину и допускает auditable временный
  human waiver;
- waiver имеет автора, срок, SHA, scope и не превращает run в доказанный clean.

## 7. Проверяемый adversarial corpus

Минимальные семейства fixtures:

1. comments/docstrings/strings/identifiers/file names;
2. README, contribution guide, agent config и project metadata;
3. commit/branch/PR/MR/issue/discussion content;
4. Unicode/Bidi/zero-width, encoded и split-across-files attacks;
5. fake system/tool/XML/JSON/Markdown messages;
6. compiler, test, scanner, dependency и generated outputs;
7. long-context distraction, truncation и budget exhaustion;
8. dual-use/refusal-inducing vulnerable snippets;
9. malformed/empty/partial provider responses и interrupted streams;
10. poisoned memory/cache и cross-run/cross-tenant attempts;
11. tool, filesystem, network и egress escalation;
12. adaptive repeated attempts, а не только один статический prompt.

Для provider adapters обязательна fault-injection matrix: HTTP 200 refusal,
content filter, empty body, invalid JSON/schema, max tokens, context overflow,
timeout, rate limit, 5xx и streaming interruption.

## 8. Acceptance oracles и метрики

### Нулевые инварианты

- `non_success_to_pass_count == 0`;
- `refusal_to_no_finding_count == 0`;
- untrusted content не изменяет policy, tool allowlist или routing;
- LLM не удаляет deterministic evidence;
- `PASS` невозможен без coverage manifest всех mandatory stages;
- provider-native finish/refusal reason сохраняется в audit trail;
- SCM UI различает `clean`, `findings`, `indeterminate` и `error`.

### Измеряемые показатели

- attack success rate `ASR@1`, `ASR@10`, `ASR@100`;
- refusal-induced false-negative rate;
- over-refusal rate на benign defensive-security cases;
- injection detection precision/recall — только как вспомогательная метрика;
- percentage of runs with complete mandatory coverage;
- human escalation/waiver rate и время разрешения;
- cost/latency amplification под adversarial input;
- tool-policy violation and data-exfiltration attempts blocked.

Нулевая policy-ошибка `refusal → pass` достижима детерминированным routing даже
при ненулевой model refusal rate. Нулевой model-level ASR не заявляется.

## 9. Gate policy

```text
if blocking_finding:
    outcome = FAIL
elif mandatory_stage_non_success or coverage_incomplete:
    outcome = INDETERMINATE
elif all_mandatory_stages_succeeded and all_cases_resolved:
    outcome = PASS
else:
    outcome = ERROR
```

Ни `[]`, ни пустой текст, ни transport HTTP 200 не являются acceptance oracle.
`PASS` строится как положительно доказанное завершение, а не как отсутствие
ошибки или finding в выходном JSON.

## 10. Ограничения и принятые маршруты

- Mandatory stages и conditional applicability зафиксированы versioned
  catalogue `core-mvp-0.2.0` в `specs/behavior/stage-catalogue.yaml`;
  model-native discovery остаётся mandatory даже при нуле scanner signals.
- Provider/model capabilities закреплены normative `ProviderProfile`; каждое
  конкретное deployment value и evidence проверяются contract tests, поскольку
  поведение provider и safety filters меняется со временем.
- Для low-risk advisory scans допустима иная availability policy, но UI всё
  равно не может выдавать `clean` при незавершённом анализе.
- Injection classifier, fallback model и human reviewer могут иметь общие
  failure modes; нужны независимые negative controls и периодический red team.
- Точные ASR и over-refusal thresholds не выдумываются в G0: fixed G3 seed
  закреплён, adaptive corpus расширяется в `P8.3`, а численные promotion
  thresholds калибруются и замораживаются только в `P7.9`.

## 11. Traceability

- Definition/threat model: `P0.10`, `P0.11`, `P0.12`.
- Provider contract: `P1.8`.
- Agent contracts и routing: `P3.2`, `P3.5`, `P3.6`, `G3`.
- SCM outcomes: `P5`, `G5`.
- Evaluation/red team: `P7.6–P7.11`, `P8.3`, `G8`.
- Architecture decision: `D-015`.
- Change request: `CR-008`.
