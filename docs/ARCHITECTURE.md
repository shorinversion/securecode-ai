# SecureCode AI — целевая архитектура

CR-046 / D-044: к 27 сентября 2026 приоритетен академический снимок общего
Core с реальной локальной моделью и Python/JS/TS/Go. Connected архитектура ниже
сохраняется для дальнейших releases; M-A2026 не объявляет её реализованной.
Порядок работ и evidence определены в [SUBMISSION_PLAN.md](SUBMISSION_PLAN.md).

## 1. Архитектурная формула

> Evidence graph исследует код, workflow graph управляет расследованием, а
> bounded harness loops проверяют каждое решение до перехода дальше.

Граф не заменяет prompt, context, harness и loop. Он соединяет специализированные
узлы, каждый из которых имеет ограниченную ответственность, инструменты,
контекст, права и stop condition.

## 2. Два ортогональных графа

### Workflow graph

Отвечает на вопрос: кто, когда и после какой проверки выполняет следующий шаг.

Основные узлы:

1. Repository Intake.
2. Repository Mapper.
3. Parallel Scanners.
4. Normalizer/Deduplicator.
5. Prioritizer.
6. Evidence Builder.
7. Auditor.
8. Read-only Skeptic.
9. Finding Gate.
10. Root Cause Localizer.
11. Security Test/PoC Generator.
12. Architect.
13. Sandbox Validator.
14. Policy Gate.
15. Human Review.
16. Reporter/SCM Adapter.

### Evidence graph

Отвечает на вопрос: почему конкретный путь кода уязвим или безопасен.

Типы узлов:

- repository, commit, file, module;
- class, function, symbol;
- parameter, variable, return value;
- source, transformation, sanitizer, guard, sink;
- caller/callee и import;
- dependency/configuration;
- detector signal и finding;
- CWE/CVE/OWASP category;
- exploit hypothesis;
- patch, test и validation result.

Основные связи:

- `CONTAINS`, `DEFINES`, `IMPORTS`;
- `CALLS`, `RETURNS_TO`, `PASSES_ARGUMENT`;
- `DATA_FLOWS_TO`, `SANITIZED_BY`, `GUARDED_BY`;
- `TRIGGERS`, `EVIDENCES`, `CONTRADICTS`;
- `CLASSIFIED_AS`, `FIXED_BY`, `VERIFIED_BY`.

Evidence graph не является заменой точного program analysis. Он хранит
нормализованные факты и доказательства, полученные AST, call graph, taint
analysis, scanners и проверенными выводами агентов.

## 3. Основной workflow

```text
Audit requested
  → Repository intake
  → Repository mapping
  → Fan-out scanners
  → Normalize and deduplicate
  → Prioritize
  → Fan-out finding investigations
      → Build evidence
      → Auditor loop
      → Skeptic review
      → Finding gate
  → For confirmed findings: repair subgraph
      → Root cause
      → Security invariant
      → Test/PoC
      → Patch candidates
      → Sandbox validation
      → Policy gate
  → Human review where required
  → SARIF / JSON / HTML / diff / SCM status
```

### Гибридный discovery и интерпретация SAST

Срабатывание SAST, AST/CST rule, taint analysis, secret scanner или SCA не
является готовым finding/verdict. Это `RawSignal`, который обязан пройти:

```text
deterministic signal
→ normalize/deduplicate
→ Evidence Builder
→ contextual Auditor interpretation
→ independent Skeptic review
→ deterministic Finding Gate
```

Auditor проверяет реальную достижимость, attacker control, transformations,
guards, auth/authz/tenant boundaries, sensitive sink, counterevidence и
root-cause localization. Он может подтвердить, отклонить или запросить
дополнительные evidence, но не может объявить `PASS` по одному scanner alert.

Принятый `CR-014` добавляет независимый model-native discovery lane:
LLM напрямую исследует разрешённый source через bounded read-only tools и может
создать candidate без SAST seed. Оба канала сходятся на одной нормализации,
EvidenceGraph, Auditor/Skeptic validation и policy gate. Поэтому гибрид работает
в обе стороны: LLM интерпретирует deterministic findings и независимо ищет то,
что детерминированные анализаторы не нашли.
Даже при нуле deterministic signals model-native stage остаётся mandatory;
только schema-valid completed-zero receipt может поддержать clean outcome.

## 4. Investigation loop

```text
collect evidence
  → build source-to-sink path
  → locate guards and sanitizers
  → auditor verdict
  → independent skeptical review
  → confirm / reject / request more evidence / escalate
```

Повтор допустим только при появлении нового evidence. Предварительный предел —
два раунда расширения контекста.

## 5. Repair loop

```text
root-cause hypothesis
  → define security invariant
  → generate minimal patch
  → generate/select security test
  → apply in ephemeral workspace
  → parse/build/test/rescan
  → accept / retry with diagnostics / escalate
```

Повтор без нового диагностического сигнала запрещён. Предварительный предел —
три patch attempts.

## 6. Validation ladder

Патч проходит последовательно:

1. `git apply --check` или эквивалент.
2. Синтаксический parser.
3. Formatter/linter.
4. Type checking, если настроен проектом.
5. Build.
6. Существующие unit/integration tests.
7. Security regression test.
8. PoC и дополнительные PoC+ варианты.
9. Повторный SAST/SCA/secret scan.
10. Проверка отсутствия новых High/Critical findings.
11. Semantic diff и blast-radius review.
12. Human approval по policy.

Уровни результата:

- `unverified_suggestion`;
- `plausible_patch`;
- `validated_candidate`;
- `human_approved_remediation`.

Термин «гарантированно безопасный патч» не используется без формального
доказательства.

## 7. State model

### AuditRun

```text
run_id
tenant_id
repository_id
base_sha
head_sha
workflow_version
policy_version
status
analysis_health
finding_ids
budgets
coverage_manifest
model_call_records
provenance
created_at / completed_at
```

### FindingCase

```text
finding_id
status
verdict_status
detector_signals
evidence_graph_ref
source_to_sink_paths
cwe_id / owasp_category
severity / confidence
auditor_verdict
skeptic_verdict
model_call_status
inconclusive_reasons
root_cause
security_invariant
patch_attempts
validation_summary
human_decision
events
```

### Состояние и владение

- scanners только добавляют raw signals;
- normalizer создаёт canonical findings;
- Evidence Builder добавляет факты, но не финальный verdict;
- Auditor добавляет гипотезу и классификацию;
- Skeptic добавляет независимое возражение/verdict и не редактирует evidence;
- Architect создаёт patch candidates и не принимает их;
- Validator записывает результаты проверок и не редактирует patch;
- Policy Gate меняет workflow status, но не результаты инструментов;
- provider adapter записывает native finish/refusal/error metadata до разбора
  model text;
- отсутствие, отказ или неполнота model output не могут удалить signal или
  создать отрицательный security verdict;
- человек принимает, отклоняет или выдаёт временный waiver.

История должна быть append-only. Крупные артефакты хранятся по content hash.
Все node executions имеют idempotency key и optimistic locking.

## 8. Routing policy

Предпочтение отдаётся детерминированным edges:

```text
confirmed =
  evidence_complete
  AND auditor_verdict == vulnerable
  AND skeptic_verdict != rejected
  AND confidence >= configured_threshold

patch_accepted =
  patch_applies
  AND syntax_valid
  AND existing_tests_pass
  AND security_test_passes
  AND original_finding_removed
  AND no_new_blocking_findings

human_required =
  conflicting_verdicts
  OR budget_exhausted
  OR mandatory_stage_refused
  OR mandatory_stage_incomplete
  OR invalid_model_output
  OR authentication_or_authorization_change
  OR cryptography_change
  OR public_api_change
```

Модель возвращает structured output. Название следующего узла выбирает policy
code, а не LLM.

`ModelCallStatus`, `FindingVerdict` и `AuditRunOutcome` являются независимыми
контрактами. Только `REJECTED_WITH_EVIDENCE` может отрицать finding; `refusal`,
пустой ответ, invalid schema, truncation, timeout или provider error переводят
обязательный stage в `INDETERMINATE/ERROR`, а не в `PASS`. Полная модель
состояний и attack corpus: [security/PROMPT_INJECTION.md](security/PROMPT_INJECTION.md).

## 9. Provider-agnostic model layer

Реализованный P1.8 содержит порт, безопасную нормализацию и authorization
harness, но сознательно не включает live HTTP client. P3.12 реализует connector
через существующую endpoint/peer/egress boundary; P3.13 подтверждает реальную
локальную модель, capabilities, версии, лицензию и ресурсы. Fake остаётся
hermetic test double. Hardware/quantization evidence хранится в run manifest,
без новых полей публичного ProviderProfile и без ослабления native-status
контракта. Health endpoint не заменяет representative source-analysis request.

Runtime выбирает immutable профиль из одобренного registry; lower-trust слои
могут выбрать только exact `profile_id@version`, но не переопределить endpoint,
model, capabilities, terms, budgets или credential reference:

```dotenv
SECURECODE_PROVIDER_PROFILE=openai-approved@1.1.0
SECURECODE_POLICY_PROFILE=advisory-default
SECURECODE_EGRESS_PROFILE=metadata_external
OPENAI_API_KEY=<runtime secret referenced by env://OPENAI_API_KEY in the profile>
```

Прямые `SECURECODE_LLM_BASE_URL/MODEL/API_KEY/...` overrides запрещены: URL,
model и budgets принадлежат профилю, а credential value существует только в
ephemeral environment/secret-store lease и не входит в effective config/hash.

Нужен capability profile:

```text
supports_responses_api
supports_chat_completions
supports_json_schema
supports_tool_calls
supports_parallel_tool_calls
supports_streaming
supports_seed
supports_native_refusal_signal
supports_native_finish_reason
supports_content_filter_signal
context_window
max_output_tokens
data_residency
retention_policy
```

Допускаются только заранее зарегистрированные per-role profile selections.
Локальная модель, cloud API и
корпоративный gateway являются равноправными deployment profiles.

## 10. Runtime abstraction

До завершения Core и M-A2026 не вводить новые runtime frameworks или временное
второе ядро ради demo. Новые внутренние защитные механизмы должны иметь
достижимый threat scenario и проверяемый эффект. Изменение существующих
границ защиты требует собственного reviewed scope. Ранние сравнения
EvidenceGraph/Skeptic описаны в [DEVELOPMENT_EVALUATION.md](DEVELOPMENT_EVALUATION.md).

```text
Domain nodes and typed state
          ↓
Workflow runtime interface
          ├── LocalRuntime — offline CLI, unit/contract tests, Core MVP
          └── TemporalRuntime — connected CI/backend, durable workers/HITL
```

Domain logic не зависит от runtime framework. LangGraph разрешён только как
time-boxed non-normative experiment за тем же interface и не может быть второй
state authority. Connected side effects выполняются как idempotent activities;
workflow history хранит IDs/hashes/statuses/artifact references, но не raw code,
prompts, patches или logs. Один golden transition suite обязан проходить на
LocalRuntime и TemporalRuntime (`D-020`).

Connected storage baseline (`D-021–D-023`):

```text
PostgreSQL application state + transactional webhook inbox/outbox
Temporal persistence/task queues (отдельные database/roles/credentials)
Filesystem BlobStore locally / tenant-scoped S3-compatible BlobStore in pilot
Rootless OCI locally / Kubernetes Job + mandatory gVisor in pilot
```

Дополнительный Redis/Kafka/Celery broker не входит в pilot baseline. Sandbox
никогда не получает SCM write/signing/database/model-admin credentials и не
понижает isolation silently при отсутствии требуемого runtime.

## 11. Security boundaries

- репозиторий и его документация являются недоверенным вводом;
- любой repository/SCM/tool content имеет `instruction_authority=NONE`, включая
  code, strings, identifiers, comments, README, generated output и logs;
- tool allowlist и schema validation обязательны;
- repository snapshot read-only;
- patch применяется в ephemeral copy;
- sandbox non-root, без секретов и по умолчанию без сети;
- ограничения CPU, RAM, процессов, времени и объёма вывода;
- model endpoint и repository URL проходят SSRF/allowlist validation;
- source-derived data следует классам `DC0–DC4`, а egress — default-deny
  profiles; `DC4` никогда не отправляется в model/backend/SCM/telemetry;
- credentials короткоживущие и scoped;
- evaluator и hidden tests недоступны агенту;
- model refusal/filter/empty/incomplete/invalid response не может означать
  отсутствие уязвимости или успешное завершение обязательной проверки;
- merge/apply всегда требует policy/human gate;
- tenant memory пополняется только после подтверждённого human decision.

## 12. Observability и reproducibility

Каждый run фиксирует:

- repository/commit;
- workflow и policy versions;
- model/provider/version;
- prompt hash;
- scanner/tool versions;
- context sources;
- tool calls;
- state transitions;
- token usage и стоимость;
- patch attempts;
- sandbox commands и результаты;
- human decisions.

Operational telemetry не должна содержать raw source по умолчанию. Forensic
traces и source-containing artifacts имеют отдельные retention/access policies.

Normative detail: [system architecture spec](../specs/system/architecture.md),
[domain contracts](../specs/contracts/domain.md),
[data/egress contract](../specs/security/data-classification.md) и полный
[system threat model](security/THREAT_MODEL.md).

## 13. Isolated P7 Evaluation Lab

`CR-016` не добавляет self-modifying production agents. RLM-inspired
exploration, DSPy/GEPA, SkillOpt-style optimization и synthetic generation
работают в отдельном offline evaluation plane:

```text
train/dev corpus + immutable CodeIndex
→ isolated optimizer/generated-program sandbox
→ versioned prompt/skill/case candidate
→ executable oracle + independent review
→ held-out/security gates + human/AppSec approval
→ promoted immutable release artifact or archived rejection
```

Lab не имеет production credentials/network, не видит locked-test
expectations и не может менять evaluator, policies, capabilities,
schemas, thresholds или active production aliases.
