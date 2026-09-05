# SecureCode AI — ранняя диагностическая оценка

Версия протокола: `development-1.0-candidate`, 5 сентября 2026, `CR-046`.
Владелец реализации: `P7.17`; итоговое включение: `P9.16 / M-A2026`.
Это supplemental development study. Frozen
[protocol](../specs/evaluation/protocol.md),
[metrics](../specs/evaluation/metrics.yaml), datasets и thresholds не меняются.
Результаты не являются подтверждающим benchmark, calibration, G7/G9 evidence
или разрешением production blocking.

## Решение, ради которого проводится исследование

Установить, добавляет ли реализованный hybrid workflow полезные находки и
проверенные исправления относительно более простых конфигураций при явно
сопоставленных входных фактах и бюджетах. Отдельно измерить ручную проверку,
стоимость, задержку и незавершённые запуски. Отрицательный или неопределённый
результат сохраняется в отчёте.

## Корпус и замораживание конкретного сравнения

До первого сравнения создаётся development manifest с IDs кейсов и root-cause
групп, immutable source revisions/hashes, лицензиями, acquisition instructions,
language/scope, vulnerable/safe labels, independently reviewed oracles,
exclusions и разделением по repository/fix/clone lineage.

Начальная цель — не менее 24 вручную проверенных development cases из не менее
четырёх repository/lineage групп, включая vulnerable, безопасные исправленные
пары, guards/counterevidence, межфайловый поток и zero-scanner случаи. Это размер
для ранней диагностики, не статистическое доказательство общего качества.
Точный состав и denominators фиксируются до запуска; недобор отражается явно.

Использовать отдельные разрешённые исходники. Frozen expectations и закрытые
тесты недоступны implementation/repair agents и не используются для настройки.
Существующий маленький conformance corpus не переименовывается в независимый
benchmark. Родственные vulnerable/fixed/clone примеры остаются в одной lineage
группе; development study не экспортируется в будущий locked test без
отдельного leakage review. Synthetic/optimizer Lab не добавляется этим планом.

Недоступная лицензия, непроверяемая source revision или неоднозначный oracle
блокируют включение кейса до freeze; исключение записывается. После freeze
нельзя удалять трудные кейсы или отказы модели для улучшения метрики. Изменение
состава создаёт новую версию и новое сравнение с сохранением старых результатов.

## Конфигурации и бюджет

План сравнения сохраняет пять конфигураций принятого evaluation protocol:

1. `deterministic_only`;
2. `scanner_seeded_investigation` без независимого discovery;
3. `model_native_only`;
4. `one_shot_llm`;
5. `full_hybrid`.

Это evaluation configurations, не product fallback. Production-mode supported
scan по-прежнему требует оба lane и Auditor interpretation каждого кандидата.
Конфигурации получают одинаковый доступный набор фактов, кроме намеренно
исключённого компонента. Для модельных вариантов заранее фиксируются budget
tokens/calls/time/retries и контекст; для deterministic-only показываются
его реальные ресурсы, без выдуманной token equivalence.

Перед запуском закрепляются candidate commit, model artifact/profile,
quantization, runtime/server, prompts, tool/policy/schema versions и параметры.
Для stochastic configurations планируется три повторения; точное число, seed
или отсутствие поддержки seed фиксируются заранее. Публикуются индивидуальные
результаты и aggregate, включая все попытки, сбои и незавершённые повторы.
Протокол не обещает bitwise reproducibility живой модели по одному seed.

Каждая ячейка имеет состояние `planned | executed | not_run | failed` и причину.
Нереализованная возможность не получает вымышленный результат. Исследование
запускается только после необходимых effective gates; подготовка корпуса не
разрешает раннюю реализацию P3 или запуск недоверенного кода на хосте.

## Дополнительная сквозная метрика

`development_e2e_remediation_rate` для одной конфигурации и повторения:

```text
число уникальных заранее включённых vulnerable root causes,
для которых независимо подтверждено проверенное исправление
----------------------------------------------------------------
все заранее включённые eligible vulnerable root causes
```

Единица счёта: `(dataset_version, case_id, root_cause_group)` из manifest.
Eligibility, supported scope и exclusions задаются до результатов, а не
наличием finding, patch или успешного provider call.

Числитель требует независимо reviewed root-cause/oracle binding, провала
уязвимой ревизии, успеха кандидата, полной применимой validation ladder,
existing regression tests и отсутствия новых blocking regressions. Самооценка
модели и её собственный passing test без независимого oracle недостаточны.
Дубликаты, повторные findings и retries не увеличивают числитель.

Missed finding, absent patch, refusal, budget exhaustion, invalid output,
validation failure и infrastructure non-success остаются в знаменателе как
неуспехи. Успешный retry может дать один успех, но его полная стоимость
учитывается. При нулевом знаменателе результат `null` с count=0.

При нескольких повторениях показываются per-run rates/counts и micro aggregate
по всем предусмотренным `(case, configuration, repetition)` единицам.
Невыполненные предусмотренные запуски не исчезают из учёта; отсутствие полного
набора помечает aggregate как incomplete. Для безопасных контролей отдельно
считаются ложные findings, ненужные patches и ошибочные blocking outcomes.

Это дополнение не заменяет frozen `correct_and_secure_rate`,
`root_cause_repair_rate` или их attempted-patches denominator. Все нормативные
метрики продолжают рассчитываться по своему frozen определению. Новая метрика
не изменяет продуктовый verdict, gate threshold или release acceptance.

## Таблица обязательных диагностических результатов

| Измерение | Что хранить и показывать |
|---|---|
| Поиск | TP/FP/FN/TN, missing-safe, все denominators, detection metrics по frozen формулам в применимом scope |
| Исправление | attempts, applied/validated counts, frozen repair rates и отдельный development_e2e_remediation_rate |
| Дополнительные находки | Уникальные истинные root causes только model-native, только deterministic и overlap; zero-scanner stratum |
| Незавершённость | Frozen indeterminate_rate плюс planned/executed/missing runs, refusal/invalid/timeout/OOM и budget exhaustion |
| Затраты | Все attempts/retries, tokens, wall time p50/p95, peak RAM/VRAM и CPU; платёж provider отдельно от ресурсов локального запуска |
| Работа человека | Время на triage/проверку diff и evidence, решение/reason, что не удалось измерить |
| Безопасность | Непрошедшие sandbox/egress/secret/coverage проверки; safe-case false findings/patches; без подмены ошибок чистым результатом |

Неизвестная стоимость или отсутствующий hardware показатель — `unknown`, не
ноль. Производительность hardware приводится с конфигурацией и диапазоном
исходников; health endpoint и fake response не подтверждают готовность модели.
Проверка влияния Skeptic/EvidenceGraph проводится только на реализованных
конфигурациях с явно описанной ablation; общая модель или общее evidence могут
создавать коррелированные ошибки, поэтому голосование не считается oracle.

## Безопасность исполнения и передача

Полученные репозитории, notebooks, build scripts и patches — недоверенные.
Проверить provenance/hashes до использования; исполнять их только в
credential-free, network-disabled, resource-bounded sandbox без host socket
и небезопасных mounts. Зависимости/веса предварительно готовятся разрешённым
способом; отсутствие sandbox или model profile не разрешает silent fallback.
Нельзя отправлять private source на сторонний endpoint ради ускорения сравнения.

Выход study: versioned manifest, per-run metadata/results, команды повторения,
агрегированная таблица и короткий decision record: что измерено, что не
измерено, найденные ограничения, следующее изменение. Публичные артефакты не
содержат secrets, raw private source или приватные prompts. Фактическая внешняя
публикация остаётся отдельным действием пользователя/уполномоченного владельца.

Перед включением в M-A2026 независимый reviewer пересчитывает confusion
matrices и сквозной показатель из per-run записей, проверяет root-cause
matching, denominators, пропуски, повторения и ограничения. Подготовка этого
протокола не означает, что corpus создан, исследование выполнено или P7.17 DONE.
