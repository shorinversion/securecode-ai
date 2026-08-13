# Вопросы куратору и зафиксированные default assumptions

Эти вопросы не останавливают `P1 Engineering foundation`: contracts изолируют
варианты. Ответы нужны до указанных gates, чтобы не строить демонстрацию на
неверной инфраструктуре или критериях оценки.

## Спросить в первую очередь

1. Подтвердить год и часовой пояс дедлайна «27 сентября, 23:59», а также точную
   дату защиты, промежуточные checkpoints и доступный формат демонстрации. До
   ответа календарь не выдумывается; после G0 оценивается critical path.
2. Если проект выполняется индивидуально, получено ли требуемое подтверждение
   Ксюши? Исходный формат — команда 3–4 человека.
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
