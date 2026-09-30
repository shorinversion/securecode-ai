# Видеодемонстрация

`securecode-demo.mp4`: 2 минуты 40 секунд, русский язык, 1920×1080. Восемь слайдов в стиле
mts-teta.team с результатами версии 1.0: задача, архитектура, живой прогон Аудитора и
Архитектора на локальной Qwen, отчёт с OWASP Top 10 и тот же результат на DeepSeek,
инструменты из notebook, эксперименты на 600 кейсах CVEfixes, итог.

Озвучка — голос владельца через ElevenLabs (`eleven_multilingual_v2`); текст сценария
сохранён в `narration.ru.txt`. В сервис озвучки передаётся только сценарий, без исходного
кода и ключей.

Пересборка (нужны `ffmpeg`, Chrome или Edge и `ELEVENLABS_API_KEY`/`ELEVENLABS_VOICE_ID`
в окружении или корневом `.env`):

```bash
uv run python docs/media/build_video.py
```
