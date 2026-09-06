# SecureCode AI — актуальный контекст

Последнее обновление: 6 сентября 2026 года.

## Текущая позиция

- Deadline: пользователь подтвердил **защиту 27 сентября 2026**, Екатеринбург,
  **1 человек** (5 сентября, task `01a07049-3886-7a52-bc78-e53900cc816f`).
  Комплект готовится к **24 сентября 18:00 Asia/Yekaterinburg**, 25-го репетиция,
  26-го резерв. Слот защиты/загрузки и instructor reference/индивидуальное
  разрешение ещё нужны; source time 23:59 не считается временем защиты.
- `CR-046/D-044`, `P9.15`: добавочный `M-A2026 — Academic Submission Snapshot`,
  календарь и ранняя diagnostic evaluation; exact reviews/handoff фиксируются
  в development-run CR-046. Первое демо P9.17 — 16 сентября (сценарий
  15-го 18:00), feedback 17–18-го; встреча с преподавателем ещё не назначена.
  [SUBMISSION_PLAN.md](SUBMISSION_PLAN.md),
  [DEVELOPMENT_EVALUATION.md](DEVELOPMENT_EVALUATION.md). G0–G9 и frozen specs
  не меняются; M-A2026 не означает beta/v1/PROJECT CLOSED.
- G4 `Core MVP v0.1` is effective `GO`. `P4.1`-`P4.12` completed at
  implementation checkpoint `f76c4c803b3ca185e0c68c310a5d4674c49ba391`;
  canonical quality passed with 1514 unit tests, 5 platform skips, 81.20% Core
  branch coverage, and all 6 G4 integration scenarios passed. CR-057 exact-byte
  promotion authorizes G5 as the next gate.
- G3 `Investigation Ready` is effective `GO`: `P3.1`–`P3.13` completed on
  implementation checkpoint `c3f682bac863e6c46ea159f437179e643d4c3eeb`.
  The canonical G3 cycle passed with 1443 tests passed, 5 expected Windows
  POSIX/FIFO skips, 82.43% Core branch coverage and `QUALITY=PASS`; real
  local-model qualification reached `REAL_EVIDENCE_RECORDED`. G4 is next.
- Phase: `P5 - CI and reference SCM integration` is authorized to start.
- G2 `Deterministic Core Ready` is `GO`: P2.6-P2.13 are complete through
  exact-byte promotion of implementation checkpoint
  `eb849b555ef8ff7e96b45baf866f2300d56d3b4c`. Its canonical gate cycle passed
  with 1296 tests passed, 5 Windows-only POSIX/FIFO skips, 86.80% Core
  branch coverage and `QUALITY=PASS`. P3 is authorized after ordinary
  protected delivery confirms the promoted bytes.
- Latest completed task: `P2.5 — bounded secret detection`, implementation
  commit `34154148faef5281a2e4ddb8170b87294d1e4024`.
- P2.1 is authorized by effective G1; P3+ remain gated.
- `CR-017/D-030` evaluator repair интегрирован exact commit
  `84f6bd859b90bd4ea7fdc7635a31b2b1c207f6b0` одним audited fast-forward
  admin bypass; bypass немедленно удалён, ruleset `21006868` восстановлен без
  bypass actors.
- `P2.5` is `DONE`. Its implementation passed focused tests, canonical
  quality and final security delta review after closing the oversized-candidate
  fail-open boundary. Protected PR #34 merged as `76d7601`; PR run
  `33957781524` and post-merge run `33957954712` passed. The exact completion
  attestation binds those bytes and evidence. P3 remains blocked until
  effective G2 GO.
- `CR-047` repaired the evaluator timeout without changing the collected
  114-node contract or 360-second deadline. Protected PR #33 merged without
  bypass as `d61d3d5`; all required PR jobs and post-merge run `33955936418`
  passed. CR-046 changes no evaluator behavior or product code.
- P2.4 completion attestation merged through protected PR #32 as `7171d5e`;
  its post-merge run `32622194943` passed all mandatory jobs without bypass.
- P2.4 passed exact-tree product, architecture and security/evaluation review
  after closing cyclic-tree exception leakage and the validation/copy race.
  Protected PR #31 merged as `2c62e20`; PR run `32621529046` and post-merge run
  `32621680247` passed every mandatory job on Python 3.12–3.14 without bypass.
  The adapter revalidates the sealed P2.3 source index, represents syntax
  errors explicitly, enforces hard source/node/depth ceilings and exposes only
  isolated exact-snapshot-validated AST copies.
- P2.3 passed exact-tree product, architecture and security/evaluation review.
  Protected PR #29 merged as `e88b730`; PR run `32619424110` and post-merge run
  `32619578595` passed every mandatory job on Python 3.12–3.14 without bypass.
  The accepted internal index binds exact source bytes, byte/point geometry,
  names, path-derived module identity, hard parser ceilings and non-echo errors;
  direct public semantic reconstruction is sealed off inside the trusted
  first-party process boundary.
- `CR-043/D-041` passed three sequential reviews, protected PR #27 and green
  post-merge run `32592043366`; the closed dependency policy now admits only
  the legacy adapters set or Core plus the two reviewed Tree-sitter packages.
- `CR-044/D-042` repaired the transition-state self-test through protected PR
  #28; post-merge run `32593519555` passed without changing evaluator behavior.
- P2.2 passed product, architecture and security/evaluation review on the exact
  accepted tree. Protected PR #24 merged as `457a02b`; PR run `32585989207`
  and post-merge run `32586165054` passed every mandatory job without bypass.
- CR-042 completed through protected PR #25 at `abe4061`; post-merge run
  `32589272475` passed. The evaluator now applies the same closed protected-run
  completion evidence to every P2.1–P2.14 task from one policy catalog.
- P2.1 implementation was merged through protected PR #11 at `6765520` and its
  post-merge Python 3.12–3.14 run passed. Independent review then found release
  blockers in path/object binding, bounded traversal, link-alias handling and
  adversarial coverage; P2.14 is the constrained remediation lane.
- P2.14 remediation and task packet were merged through protected PR #12 at
  `b45a4b8`; PR run `32564092644` and post-merge run `32564227372` passed.
- Completion evidence scanning and lifecycle self-tests were repaired through
  protected PR #19 (`be9d5c1`) and PR #21 (`c2dcd99`). Post-merge runs
  `32578667057` and `32582315319` passed without bypass.
- G1 effective: `GO` through validated exact-byte promotion.
- Gate: `G1 Foundation Ready` is effective `GO`; G0 remains frozen and valid, and G2 is next.
- Normative baseline: `0.2.0`, lifecycle `frozen`; immutable commit
  `f5cd4ef2a0f7130d16cb2c206091908be71b0702`.
- Normal validator: `PASS`; normative hash
  `dedb43be8ba055dfa47858b975630b4c870af3bed2dda842b0e8422c8354b5c9`.
- Final independent reviews baseline `0.2.0`: `PASS/PASS/PASS` на exact
  normative hash; отдельная successor attestation закоммичена.
- P1.1 verification: required inventory present, no executable code/imports/
  dependencies, protected diff empty, strict G0 `PASS`, independent
  architecture review `PASS`.
- P1.2 verification: one `uv.lock`; clean non-editable install/imports on
  Python 3.12/3.13/3.14; Python 3.11 and lock drift rejected; six distributions
  built; protected diff empty; strict G0 and independent review `PASS`.
- P1.3 verification: exact Ruff 0.15.22, mypy 2.3.0, pytest 9.1.1 and
  pytest-cov 7.1.0 in the root lock; one offline/no-sync quality entrypoint;
  clean non-editable Python 3.12/3.13/3.14 runs; 17 tests; closed Core/contracts
  import allow-lists; Core-only branch coverage floor; sanitized child env;
  static-preflight, low-coverage, zero-test and repository-mutation negatives;
  independent architecture and security/evaluation reviews `PASS/PASS`.
- P1.4 completion verification: closed pre-commit/CI policy, staged and
  reachable-history secret scanning, permanent vulnerable-dependency negative,
  strict zizmor and Python 3.12–3.14 quality matrix pass; independent
  product/architecture/security-evaluation reviews are `PASS/PASS/PASS` on the
  staged candidate. Private repository `shorinversion/securecode-ai` имеет
  active ruleset `21006868` с required `gate`; intentional failing PR #1
  на commit `703817360a9966cc6858a5dc35cdecc50c76a14b` получил
  `mergeStateStatus=BLOCKED`, Actions run `32175856948` завершился failure и PR
  закрыт без merge. Позднее ordinary PR #7 подтвердил green required `gate`
  без bypass; после этого `P1.4` стал `DONE`.
- CR-017 implementation: completion SHA-1/SHA-256 исключаются из entropy scan
  только после exact-path closed-schema/evidence-catalog validation; non-digest
  fields и invalid/unknown documents продолжают обычный scan. Strict promotion
  manifest декодирует и сканирует Base64 final bytes под target paths; review
  receipt suppresses only validated typed digests/OID. Local pre-commit и CI
  используют общий Git-index/blob scanner, а trusted Git boundary фиксирует
  `autocrlf=input/eol=lf`; `.secrets.baseline` не изменён.
  D-030 добавляет policy-owned evaluator amendment proposal с exact final-byte
  manifest, current-base selector, тремя commit-separated reviews и mechanical
  promotion; повторный amendment того же target set выбирается по exact
  base-to-final hashes, а конкурирующий identical-transition proposal
  fail-closed. Proposal/review/promotion history обязана быть непрерывной
  single-parent chain без parallel merge assembly или промежуточных commits.
  Exact full run включает 159 CI/spec policy tests; Ruff/mypy, snapshot spec
  gate, все 1001 tests и 85,80% Core branch coverage прошли; strict frozen G0
  сохраняет normative digest. Exact staged reviews дали `PASS/PASS/PASS`;
  bootstrap bypass выполнен и удалён.
- P1.5 candidate verification: 92 contract/schema tests at 86.54% branch
  coverage; 152 repository tests pass on CPython 3.12/3.13/3.14; deterministic
  schema drift check, strict G0, Ruff/mypy, ECMAScript regex compilation and a
  wheel containing all five schemas pass. Architecture/security reviews found
  and remediation now tests manifest identity binding, unsupported-language
  fail-closed semantics and recursive extension tenant binding. Independent
  product/architecture/security-evaluation reviews are `PASS/PASS/PASS`;
  clean post-commit schema/contract/quality/strict-G0 verification PASS.
- P1.6 completion verification: versioned `AuditEvent`, stable IDs and
  immutable `EventStream` bind the revalidated complete execution identity and
  admitted HEAD while enforcing data-class/tenant/run, canonical previous-hash,
  idempotency and replay invariants; 58 targeted tests pass at 92.83% Core
  branch coverage, and 201 repository tests pass at the same coverage on fresh
  non-editable CPython 3.12/3.14 and the canonical 3.13 environment. Schema
  drift, six-schema wheel inventory, 317 ECMAScript regex compilations and
  strict G0 pass. Independent product/architecture/security-evaluation reviews
  are `PASS/PASS/PASS`; clean post-commit quality/schema/strict-G0 verification
  passes on commit `1ae2dddd14ffc7c23ce5db2c3185d714f0c64718`.
- P1.7 completion verification: immutable exact-version provider registry,
  closed selection precedence and host-bound ephemeral credential lease pass 97
  targeted tests; provider/config branch coverage is 96.45%. Fresh non-editable
  CPython 3.12/3.14 wheels and canonical CPython 3.13 each pass the full 285-test
  quality suite at 92.91% Core branch coverage; schema drift and strict G0 pass.
  Independent product/architecture/security-evaluation reviews are
  `PASS/PASS/PASS` on exact digest
  `8065e67898e9d75bf69203afabb5846fb3fb1510`; clean post-commit targeted,
  schema and strict-G0 verification passes on commit
  `2b21356f29df2d9d95e1a0155cdfd16f9ecfcf13`. На тот момент `G1` оставался open.
- P1.8 completion verification: public model request/result schemas, exact
  provider/egress authorization, profile-owned budget/dialect enforcement,
  manifest-bound provider attempts and payload snapshots, safe native
  normalization, restricted-output guard, hermetic fake, process-local concurrent
  idempotency, closed remote native control surfaces and endpoint
  SSRF/rebinding/peer checks pass 174 targeted tests.
  Canonical CPython 3.13 and fresh non-editable CPython 3.12/3.14 quality runs
  pass Ruff/mypy and all 459 tests at 91.65% Core branch coverage on these latest
  bytes. Schema exact-byte check and strict frozen G0 pass. Independent reviews
  produced bounded remediation rounds, then product/architecture/
  security-evaluation returned `PASS/PASS/PASS` on exact digest
  `841fbdfc36a92d0de77d96083bc1d349990f1304`. Clean post-commit verification on
  `030fad9f4567f59def348387d9484a0b4a5eea29` passed 174 targeted tests, all 459
  repository tests, schema drift and strict frozen G0. `P1.8` is `DONE`; after
  completion of `P1.11`, на тот момент `G1` оставался open, потому что `P1.4` и
  `P1.12–P1.13` ещё не были завершены.
- P1.9 completion verification: пять новых public workflow schema roots,
  exact-definition graph-independent state machine, обязательный dual-lane
  fan-out/fan-in, bounded investigation/repair loops, replay-complete transition
  journal и process-local `LocalWorkflowRuntime` прошли 166 целевых tests на
  independently reviewed exact digest
  `f8f34d2d58cdf452857ff5379130e74d269d7df9`.
  Canonical quality gate проходит Ruff/mypy, все 603 tests и 89,72% Core branch
  coverage; exact-byte check и wheel inventory подтверждают все 13 schemas,
  strict frozen G0 — `PASS`. Reliability-remediation закрывает hidden-field
  smuggling, unadmitted producer, cross-operation dispatch, typed precedence и
  обычное переназначение registry; multi-node repair usage теперь суммируется до
  retry boundary, а portable suite включает snapshot/resume/replay и запрет
  caller-owned terminal/loop state. Independent product/architecture/
  security-evaluation reviews дали `PASS/PASS/PASS`; security/evaluation
  дополнительно прогнал 269 adversarial contract/runtime/model tests без fail-open
  результатов. Clean post-commit verification
  implementation commit `0431ba66f2a288ee1978950fb01e77e5430c5f04`
  прошла расширенные 249 targeted tests, все 603 repository tests, Ruff/mypy,
  schema exact-byte, 13-schema wheel inventory и strict frozen G0. `P1.9` —
  `DONE`; на тот момент `G1` оставался открыт из-за `P1.4` и `P1.12–P1.13`.
- P1.10 completion verification: installable first-party `securecode`
  package, exact human/machine grammar, stable exit/error mapping, два public CLI
  schema roots и source-free foundation `doctor` проходят 165 targeted tests.
  Первый implementation review закрыл positional command attribution и
  fail-open через unsafe copied Doctor result: retained state теперь повторно
  валидируется и malformed result даёт typed `INTERNAL_ERROR`, не exit 0.
  Canonical quality gate проходит Ruff/mypy, все 696 tests и 89,72% Core branch
  coverage; CI lock/metadata authority, exact-byte schema check, 15-schema wheel
  inventory, clean offline install/entrypoint smoke и strict frozen G0 — `PASS`.
  `scan_readiness` всегда `NOT_EVALUATED`; scan/fix/validate/apply/ci и P2-анализ
  не реализованы. Independent product/architecture/security-evaluation reviews
  дали `PASS/PASS/PASS` на exact digest
  `c36748f084e71f3639943b860e5f07538a6b6646`. Clean post-commit verification
  implementation commit `a0dd7849db3e372ca5cc396706f3a166329a1f8a`
  повторно прошла 165 targeted, все 696 tests, schema/CI/strict-G0, offline
  build, 15-schema wheel и clean offline entrypoint smoke. `P1.10` — `DONE`;
  на тот момент `G1` оставался открыт из-за `P1.4` и `P1.12–P1.13`.
- P1.11 completion verification: evaluator-owned six-case tree golden заморожен
  до реализации в commit `ad84f403224af55db19b8e2e2e3374e8f178f669`, а
  path-specific LF policy в `46f24297fe76c274b88bb228febe3f3289198f17`
  сохраняет exact bytes на Windows/POSIX. Test-only factory материализует шесть
  opaque repos, не читает specs/golden, не исполняет source и не реализует P2/P4
  анализ. Product/architecture/security-evaluation reviews дали `PASS/PASS/PASS`
  на exact digest `f194a1bd66da95642a37487a743144389f229699`. Clean
  post-commit verification implementation commit
  `f2bb7cbbcfe3e1e80e1c236300c755315fa561bc` повторно прошла 43 targeted,
  Ruff/mypy, все 739 tests, 89,72% Core branch coverage, schema exact-byte и
  strict frozen G0; protected golden/spec/G0 не изменены. `P1.11` — `DONE`;
  на тот момент `G1` оставался открыт из-за `P1.4` и `P1.12–P1.13`.
- P1.12 completion verification: frozen/public-contract conflict устранён до
  реализации — telemetry record остаётся exact-version internal Core value,
  `packages/contracts/**` и public schema не меняются. Process-local HMAC trace
  authority выдаёт non-zero root/child IDs; emitter строит только closed DC1
  metadata, один раз рендерит canonical JSONL и fan-out-ит emitter-issued guarded
  capability. First-party sinks проверяют type/issuer/seal/hash/current canonical
  record до I/O; raw/forged/copied/mutated payload, TOCTOU, source/clock faults,
  exception non-echo, short-write/flush и bounded retention покрыты 162 targeted
  tests. Review remediation дополнительно закрыл module-visible mint helpers,
  reentrant stream-wiring, nested-draft и retained-authority TOCTOU, а также
  exact-enum/non-echo boundary errors, concurrent memory-cap/stream-record
  atomicity, bounded same-thread stream re-entry, flush-time wiring mutation,
  self-signed/resealed capability forgery через emission-scoped exact-object
  provenance с real emitter code/globals/builtins resolution, истечение retained
  payload после fan-out, exact emitter-owned issuer identity, nested-record
  render race, mutable retained memory storage и parser exception echo. Это
  process-local object contract, не Python runtime sandbox: coordinated mutation
  code/frame/closure cells или resolved
  runtime objects остаётся вне `P1.12`. Canonical quality проходит Ruff/mypy,
  все 885 repository tests и 85,80% Core branch coverage. Preimplementation
  product/architecture/security-evaluation reviews дали
  `PASS/PASS/PASS` на packet SHA `19a00d3842773a0a91b616abe29c87c9ab5f7e1b73ef590d05b872084aa1cbed`;
  те же роли приняли exact staged digest
  `879f41ceef64e76fb7daab2398f8ab39e8559cd4`. Clean post-commit verification
  implementation commit `5ace16e80730d56f994cb6a24fa4748867a49646`
  повторно прошла 162 targeted, Ruff/mypy, все 885 tests, 85,80% Core branch
  coverage, schema check и strict frozen G0. Protected specs/G0/contracts не
  менялись. `P1.12` — `DONE`; на тот момент P2 был закрыт, а `G1` оставался
  открыт из-за `P1.4` и `P1.13`.
- P1.13 packet после remediation repository authority, strict JSON Pointer,
  trusted Git executable и committed-lifecycle checks имеет exact SHA-256
  `b1b7e6ce50a46e62212a6ef74383c3699f5f498542e684915778a87ca7c05673`
  принят exact staged product/architecture/security-evaluation review
  `PASS/PASS/PASS` на digest
  `6cf55b7ce6d4db6a51f818e072c403dc4c124d9af352fdfc38b4e3c8ca52de5c`.
  Текущий candidate добавляет deterministic snapshot/index/committed spec gate,
  exact schema/example/traceability checks, пять закрытых candidate lanes,
  mandatory CI spec job и три прямые locked quality dependencies с точной
  девяти-package closure. `.secrets.baseline` механически обновлён только
  проверенными false-positive hashes с сохранением настроек и прежних findings
  и включён в post-bootstrap protected inventory. На текущих байтах 136 targeted
  tests и full quality с 978 tests, Ruff/mypy, 85,80% Core branch coverage и
  snapshot spec gate, CI policy, schema exact-byte и strict frozen G0 проходят,
  включая clean implementation HEAD `307a24a71cea25829c0b5541494bf01e13a2e6ed`.
  `P1.13` — `DONE`; completion attestation находится в отдельном successor commit.
- Историческое решение `GO FOR P1 ONLY` действовало до G1 promotion и не
  ослабляло frozen contracts; оно superseded эффективным `G1 Foundation Ready: GO`.

## Принятые последние изменения

### CR-014 / D-027 — mandatory dual-lane discovery

Каждый product scan в supported semantic scope запускает два
независимых lane на одной immutable revision:

```text
deterministic analyzers → RawSignal ─┐
                                  ├→ normalization/EvidenceGraph
model-native code discovery ─────┘   → Auditor per candidate
                                      → Skeptic/Finding Gate
```

Инварианты:

- scanner output не является finding/verdict;
- каждый normalized deterministic/model-native candidate имеет Auditor
  interpretation receipt;
- model-native discovery обязателен даже при нуле scanner signals;
- completed-zero — schema-valid `SUCCEEDED` с `candidates=[]` и complete
  receipt; empty/refused/invalid/timeout/provider error — не completed-zero;
- mandatory model non-success даёт `INDETERMINATE`, не clean/PASS;
  уже confirmed blocking finding остаётся `FAIL` с health degradation;
- provenance закрыт: `deterministic | model_native | hybrid`;
- code читается только через bounded read-only `RepositoryView`; no
  shell/write/arbitrary filesystem/network;
- incompatible DC3/provider/egress profile отклоняется до network bytes
  и не включает silent deterministic-only fallback.

### CR-015 — complete assignment delivery

В product spec, plan и traceability включены:

- Git repository, source, README installation/run/example;
- locked dependency file, configuration, unit tests, runnable notebook;
- PDF/HTML report с problem/solution/experiments/metrics/conclusions;
- dataset links или fixed-seed generator;
- clean-room reproducibility и anonymous/public link check;
- Dockerfile, web-service launch instructions и 2–5 minute screencast;
- tracked confirmation deadline year/timezone и team-size/individual approval.

Два последних административных факта пока внешне не подтверждены.
Они не меняют P1 contracts, но являются blocking criteria `P9.12/G9`;
спросить преподавателя нужно заранее.

### CR-016 / D-028 — restricted P7 Evaluation Lab

RLM-inspired exploration, DSPy/GEPA, SkillOpt-style optimization и synthetic
generation приняты только как optional offline `P7.12–P7.16`.
Они не Core/runtime dependency и не product claim.

- optimizer видит train/dev, но не locked expectations/evaluator/policy/specs;
- generated code имеет immutable read-only `CodeIndex`, no network/
  credentials и bounded sandbox;
- synthetic case остаётся candidate до executable oracle, independent
  root-cause review, fixed provenance и lineage-safe split;
- promotion требует held-out improvement, zero-tolerance security gates
  и human/AppSec approval;
- production agents никогда не self-modify/self-promote.

## Продукт и порядок релизов

Целевой `v1.0`: один Core для offline CLI, CI worker и backend
control plane; GitHub-first, GitLab beta; Python-first Core, обязательные
Python/JS/Go к beta/final. Backend по умолчанию не получает checkout.
До `P7.9` SCM режим advisory; затем первый rollout — calibrated
new-code blocking. Auto-Fix — candidate до sandbox validation и required
human/policy gate.

CR-046 приоритизирует до сдачи G2 → G3 → G4 → P7.1–P7.3 (языки), P7.17
(отдельное development сравнение), P9.16 (академический комплект). Backend,
вторая SCM и enterprise hardening сохраняются для последующих releases.
P3.12/P3.13 явно владеют live connector и реальной локальной моделью; P1.8
не переобъявляется готовым HTTP-клиентом. Все новые packets/catalog admissions
проверяются до исполнения; календарь не заменяет protected completion.

## Модель разработки

CR-050 / D-047 supersedes the earlier per-task lifecycle: пользователь принял
[DEVELOPMENT_WORKFLOW.md](DEVELOPMENT_WORKFLOW.md): Sol medium orchestrator,
Terra high developer, Sol high reviewers, Astra не выше medium для узких
critical-security/evaluator задач; Luna medium для механических задач.
Внутренняя работа выполняется bounded Codex-субагентами с явной моделью и одним
writer на путь; отдельные пользовательские задачи для внутренних стадий не
создаются. Spawn receipt подтверждает принятую конфигурацию, но не доказывает
runtime identity, если платформа её не раскрывает. Между P-задачами допустимы
только локальные checkpoint-коммиты без тестов и ревью. Один canonical quality
cycle выполняется для интегрированного gate-кандидата; независимые reviews для
G2-G8 отключены, а единый product/architecture/security-evaluation review
выполняется после G9. Полный цикл повторяется только после изменения кандидата
или исправления, которое инвалидировало предыдущий результат.
Общий checkout используется для управления, стабильного read-only review и
последовательной разработки в feature-ветке; worktree — для параллельных writers
или изоляции фиксированного review-кандидата, с учётом владельца и очистки.
Lifecycle amendment effective через protected PR #38 (`7d6e150`) и зелёный
post-merge run `33978319717`; CR-052 closing activation merged through
protected PR #39 (`3aec841`); CR-053 first-gate lookup repair merged through
protected PR #41 (`0609db3`); CR-054 state-independent promotion regression
merged through protected PR #44 (`805fa17`). Hooks, protected CI и exact-byte
promotion остаются обязательными.

Основной Codex-agent — единственный `Primary Integrator` и owner
решений/baseline. Субагенты — bounded read-only reviewers или
path-isolated implementers; они не self-accept и не меняют baseline.
Постоянное разделение review: product — scope/traceability;
architecture — wire contracts; security/evaluation — fail-open, policy и
metric loopholes. Главный агент сводит corrections и повторно
валидирует integrated bytes.

## Ближайшие действия

1. Завершить exact-byte promotion и protected delivery интегрированного G2
   candidate. P3 начинается только после effective G2 GO.
2. После G2 без паузы реализовать demo-critical P3 code-first по той же
   consolidated gate cadence; параллельно готовить P9.12 и development corpus.
   Календарь следующих этапов — SUBMISSION_PLAN.md.
3. После G2 дать Luna medium writer lease на безопасные
   ненормативные translation batches; immutable/spec/gate evidence не переводить
   без отдельного change control.

## Критические запреты

- не обещать гарантированную безопасность;
- не считать SAST, LLM или generated synthetic cases ground truth;
- не позволять code/docs/SCM/tool output инструктировать agent;
- не интерпретировать refusal/empty/incomplete/error как clean;
- не давать LLM/generator свободный shell/network или evaluator access;
- не позволять implementation agent менять specs/evaluator/gate evidence;
- не хранить API keys, secrets и raw source в telemetry;
- не создавать расходящиеся Core для CLI/backend.
