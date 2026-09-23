# Clean replay / Повторная сборка

## English

Run from a clean checkout with the locked local environment. These commands do not execute corpus source or contact a model provider. Choose a new, empty destination for every build.

```powershell
.venv\Scripts\python.exe -I scripts\build_m_a2026_submission.py --output <new-empty-output-directory>
.venv\Scripts\python.exe -I scripts\build_m_a2026_submission.py --validate <new-empty-output-directory>
```

The submission notebook was executed with the locked project interpreter. It runs the pinned public CWE-89 composition in an ephemeral workspace, reads the recorded benchmark aggregate and redacted real-local receipt, and makes no model call. Re-execute it from a clean checkout with the locked interpreter registered as a Jupyter kernel. Build the bundle separately with the command above, compare `delivery-manifest.json` hashes with the expected checkout, and retain `NOT_READY` until every external confirmation and durable final review is recorded.

## Русский

Выполняйте команды из чистой копии репозитория с зафиксированным локальным окружением. Они не запускают исходный код корпуса и не обращаются к поставщику модели. Для каждой сборки указывайте новый пустой каталог.

Ноутбук комплекта уже выполнен с интерпретатором из lock-файла. Он запускает закреплённый публичный пример CWE-89 во временном рабочем каталоге, читает сохранённые агрегаты бенчмарка и редактированную квитанцию локального запуска, не вызывая модель. Для повторного запуска зарегистрируйте locked-интерпретатор как Jupyter kernel и выполните ноутбук из чистой копии репозитория.

После этого отдельно соберите и проверьте комплект командами выше. Сверьте хеши `delivery-manifest.json` с ожидаемым состоянием репозитория. Сохраняйте `NOT_READY`, пока не получены внешние подтверждения и не завершены итоговые независимые проверки.
