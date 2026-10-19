# Сценарий скринкаста SecureCode AI, 3 минуты

Запись ещё не выполнена. Сценарий рассчитан на экран 1920×1080 и показывает
только публичный fixture и обезличенные результаты. Перед записью выключите
уведомления, закройте окна с ключами и не открывайте приватный исходный код.

## 0:00-0:25. Задача и архитектура

Покажите верх README и схему компонентов. Скажите: «SecureCode AI принимает
локальный Git checkout. Детерминированные правила и локальная модель создают
кандидаты; контракты нормализуют их; проверки и политика определяют результат.
Предложенный patch хранится отдельно от исходного checkout».

## 0:25-0:55. Детерминированная демонстрация

Из корня репозитория запустите в новом пустом каталоге:

```powershell
$output = Join-Path $env:TEMP ('securecode-offline-' + [guid]::NewGuid().ToString('N'))
uv run --locked --offline --no-sync python -I demo/mvp_cwe89_demo.py --output $output
Get-Content (Join-Path $output 'mvp-demo-manifest.json')
```

Покажите `vulnerable=1`, `safe_control=0`, `product_outcome=NOT_EVALUATED` и
`network_access=not_used`. Скажите, что это узкий offline reference demo, а не
заявление о точности или production verdict.

## 0:55-1:45. Настоящая локальная модель

Покажите `ollama list` без секретов, затем локальную версию и файл
`report/submission-benchmark/evidence/current-real-local-p917.json`. В квитанции
обратите внимание на `qwen2.5-coder:7b-instruct-q4_K_M`, `Q4_K_M`, версию Ollama
0.34.4, digest модели и endpoint `127.0.0.1`.

Скажите: «Модель и детерминированный поиск нашли CWE-89 на одной строке. Repair
запрос выполнился локально, но модель не вернула пригодный patch. Поэтому
результат INDETERMINATE. Применимость patch не оценивалась, синтаксическая и
security regression проверки не запускались. Исходный checkout не менялся».

При повторной живой записи команда создания временного fixture и запуска есть в
README в разделе Ollama. Если генерация выходит за тайминг, откройте сохранённую
квитанцию и не заменяйте её имитацией.

## 1:45-2:35. Эксперимент

Откройте `report/submission-benchmark/report.html` или README benchmark. Покажите
600 кейсов, три языка, split 40/20/40, затем held-out recall: derived hybrid
27.8%, Semgrep 32.5%. Отметьте 253 scanner failures из 600 и интервал разницы,
который включает ноль.

Скажите: «Эти результаты не доказывают преимущество LLM. Прямые DeepSeek
классификации и post-hoc hybrid не запускали весь SecureCode pipeline. Полный
repair study отсутствует».

## 2:35-3:00. Запуск и итог

Покажите `deploy/docker/README.md`, `pyproject.toml`, `uv.lock`, notebooks и
итоговый HTML-отчёт. Скажите: «В репозитории есть ASGI API и Docker Compose
инструкция, но нет browser dashboard и production deployment. Полный тестовый
прогон и quality gate текущего дерева не прошли. Это учебный прототип с честно
зафиксированными результатами и ограничениями».

Остановите запись после вывода итогового отчёта. Не показывайте API keys,
локальные `.env`, содержимое приватных проектов или незаписанные метрики.
