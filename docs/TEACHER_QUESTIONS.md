# Вопросы куратору и зафиксированные default assumptions

Эти вопросы не останавливают разрешённую разработку P2. Подготовка P9.12
начинается сейчас; неполное административное подтверждение не допускает
M-A2026 READY_FOR_SUBMISSION или final submission. [Рабочий календарь](SUBMISSION_PLAN.md).

## Подтверждено пользователем 5 сентября 2026

- **Защита проекта — 27 сентября 2026**. Источник: явное сообщение пользователя
  в Codex task `01a07049-3886-7a52-bc78-e53900cc816f`.
- Часовой пояс: **Екатеринбург, UTC+05:00**. Работа **индивидуальная, 1 человек**.
- Время **23:59** из исходного задания не считается временем защиты. Точный
  слот и срок предварительной загрузки материалов ещё не записаны.
- Instructor reference и разрешение индивидуальной работы остаются открыты;
  факт одного участника сам по себе не подтверждает разрешение.
- Первое рабочее демо — целевой срок 16 сентября; обсудить feedback 17–18-го.
  Согласование встречи с преподавателем ещё требуется.
- Комплект готов к 24 сентября, 18:00 `Asia/Yekaterinburg`; 25-го репетиция,
  26-го резерв, 27-го защита.

## Спросить в первую очередь

1. Получить ссылку/дату подтверждения куратором слота **защиты 27 сентября 2026
   по Екатеринбургу**, срок загрузки материалов и формат демонстрации.
   Рабочий календарь уже ведётся по подтверждённым пользователем дате/timezone.
2. Для подтверждённой индивидуальной работы зафиксировать требуемое разрешение
   Ксюши/куратора. Исходный формат — команда 3–4 человека.
3. Где должен жить итоговый репозиторий и проходить защита: GitHub, GitLab SaaS
   или GitLab Self-Managed? Default: GitHub-first reference, GitLab к beta.
4. Можно ли зарегистрировать GitHub App/webhook endpoint и настроить required
   check? Если нет, reference demo использует локальный webhook simulator/CI
   job, не ослабляя SCM contract.
5. Допустимы ли внешние LLM API для учебного кода, и какие ограничения по
   data residency/retention? Default: provider-agnostic env configuration,
   `no_code_egress`, fake/local provider для воспроизводимых tests.
6. Что оценивается выше: глубина одного semantic rule или количество языков к
   первой демонстрации? Default: Python CWE-89 deep vertical сначала; все три
   языка обязательны к финалу.
7. Разрешено ли использовать внешние scanners/parsers как adapters, если
   собственными остаются contracts, evidence, orchestration, rule/normalization
   и validation? Default: да, но собственные secret/CWE-89 capabilities и
   adapters/tests обязательны.
8. Какие compute/OS/Docker/Kubernetes ресурсы доступны на защите? Default: Core
   demo должен работать offline на одной машине; Temporal/Kubernetes/gVisor
   показываются отдельно или эмулируются contract tests при отсутствии среды.
9. Ожидается ли реально развернутый backend или достаточно pilot-grade локального
   deployment? Default: `v0.2` pilot, production claims только после hardening.
10. Нужны ли UI и notebook как центральная демонстрация? Default: CLI + reports +
   notebook обязательны; web UI не входит в Core MVP.
11. Можно ли использовать публичные vulnerable repositories/benchmarks и
    публиковать результаты? Default: только license/hash-reviewed datasets,
    scoped claims, никакого proprietary source в артефактах.

## Критерии приёмки, которые стоит подтвердить

- обязательно ли показать Python, JS и Go live или достаточно test evidence для
  части языков;
- требуется ли локальная LLM буквально либо provider-agnostic endpoint принят;
- обязательно ли создавать настоящий PR/MR bot или допустим воспроизводимый
  integration harness;
- какие CWE/OWASP категории кроме CWE-89, secrets и vulnerable dependencies
  куратор ожидает к финалу;
- нужны ли сравнительные baselines/ablation и какая длительность выступления;
- кто формально принимает false-positive/patch safety thresholds;
- можно ли выложить проект open source и под какой лицензией;
- какие документы нужны: ТЗ, отчёт, презентация, видео, notebook, deployment
  guide, threat model, benchmark appendix.

## Что показать куратору

Вместо общего описания дать четыре коротких артефакта:

1. release scope и `DEMO-CWE89-001` из [PRODUCT.md](PRODUCT.md);
2. workflow/evidence graph из [ARCHITECTURE.md](ARCHITECTURE.md);
3. `SC-*` contracts из [specs](../specs/README.md);
4. G0 risk/evidence packet из [artifacts/gates/G0](../artifacts/gates/G0/checklist.md).

Попросить подтвердить assumptions письменно. Любой ответ, меняющий язык,
reference SCM, egress, public contract или gate, оформляется как CR/ADR; устная
оговорка не переписывает baseline незаметно.
