# SecureCode AI — research amendments

Protocol changes append-only. Прошлые версии и ранее сделанные exploratory
шаги не переименовываются задним числом в preregistered/confirmatory.

| ID | Дата | Изменение | Причина | Влияние |
|---|---|---|---|---|
| `RA-001` | 2026-08-12 | Создан `PROTOCOL.md` v0.1 после начальной exploratory подборки источников | Импортированный Deep Research показал необходимость formal evidence pipeline | Уже собранные claims остаются exploratory и проходят повторный source gate |
| `RA-002` | 2026-08-12 | Введён запрет promotion внутренних `turn…` citation markers | Маркеры не разрешаются вне исходного ChatGPT run | Требуется primary-source resolution в `CLAIMS.md` |
| `RA-003` | 2026-08-12 | Выполнен post-review source audit открытого OpenAI Codex Security на pinned commit `455d7c8`; добавлены `PA-011–PA-013` | Новый официальный исходный код даёт более сильное evidence прямого model-native чтения source и выявляет несоответствие текущего scanner-seeded workflow намерению проекта | Открыт `CR-014`; G0 freeze приостановлен до решения, синхронизации normative contracts и delta reviews |
| `RA-004` | 2026-08-12 | Добавлен targeted review RLM, DSPy/GEPA, SkillOpt и LLM-generated evaluation cases (`EO-001–EO-006`) | Пользователь предложил code-search через generated code и offline optimization prompts/skills | Методы остаются experimental candidates; staged ablations привязаны к `CR-014` и `P7.7–P7.10`, без изменения frozen Core MVP corpus |
| `RA-005` | 2026-08-13 | Приняты `CR-014` и limited `CR-016` | Post-review evidence показал, что scanner-seeded clean path не обеспечивает independent semantic discovery, а optimization требует isolation | Baseline `0.2.0` ввёл mandatory dual-lane workflow; RLM/DSPy/GEPA/SkillOpt/synthetic перенесены в isolated `P7.12–P7.16` без Core/runtime dependency |
