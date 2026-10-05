# ruff: noqa: RUF001  (the slides and narration are Russian text)
"""Build docs/media/securecode-demo.mp4: styled slides, ElevenLabs narration, ffmpeg.

Run from the repository root with ELEVENLABS_API_KEY and ELEVENLABS_VOICE_ID in the
environment or the root ``.env``; needs ffmpeg and Chrome/Edge on PATH or default paths.
Only the narration text below is sent to ElevenLabs.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / "output" / "video"
MEDIA = ROOT / "docs" / "media"

STYLE = """
*{box-sizing:border-box}html,body{margin:0;width:1920px;height:1080px;overflow:hidden}
body{background:#f4f4f4;color:#1d2023;font:34px/1.45 MTSSans,"MTS Sans",Arial,"Segoe UI",sans-serif;padding:84px 110px}
.pills{display:flex;gap:14px;margin-bottom:44px}
.pill{background:#ff0032;color:#fff;border-radius:40px;padding:10px 28px;font-size:26px}
.pill.dark{background:#1d2023}.pill.light{background:#fff;color:#1d2023;border:1px solid #d9d9d9}
h1{font-size:150px;line-height:.95;font-weight:400;text-transform:uppercase;letter-spacing:-.03em;margin:0 0 36px}
h2{font-size:84px;line-height:1;font-weight:400;text-transform:uppercase;letter-spacing:-.02em;margin:0 0 44px}
.card{background:#fff;border-radius:44px;padding:44px 52px}
.grid{display:grid;gap:24px}.g2{grid-template-columns:1fr 1fr}.g3{grid-template-columns:1fr 1fr 1fr}.g4{grid-template-columns:repeat(4,1fr)}
.card h3{margin:0 0 12px;font-size:38px;font-weight:600}.muted{color:#626c77}
.num{font-size:110px;line-height:1;margin:10px 0}
pre{background:#1d2023;color:#f4f4f4;border-radius:32px;padding:34px 40px;font:28px/1.5 Consolas,monospace;margin:0;white-space:pre-wrap}
.add{color:#5bd48a}.del{color:#ff6b81}.red{color:#ff0032}
table{border-collapse:collapse;width:100%;font-size:32px}th,td{border-bottom:1px solid #e4e4e4;padding:16px 12px;text-align:left}
th{color:#626c77;font-weight:500;border-bottom:3px solid #1d2023}td.n{text-align:right}tr.hi td{font-weight:700}
.flow{display:flex;gap:16px;align-items:center;flex-wrap:wrap;font-size:32px}.flow span{background:#fff;border-radius:40px;padding:18px 30px}.flow b{color:#ff0032;font-size:40px}
"""

SLIDES: list[tuple[str, str]] = [
    (
        """<div class="pills"><span class="pill">МТС True Tech</span><span class="pill dark">Итоговый проект · задача № 2</span><span class="pill light">Версия 1.2</span></div>
<h1>SecureCode AI</h1><p style="font-size:48px;max-width:1400px">Локальный AI-ассистент для аудита безопасности кода: находит уязвимости, предлагает исправления и проверяет их, не отправляя код в облако.</p>""",
        "SecureCode AI — локальный ассистент для аудита безопасности кода. Он находит уязвимости, "
        "предлагает исправления и проверяет их, не отправляя исходный код в облако. "
        "Это итоговый проект, задача номер два.",
    ),
    (
        """<h2>Задача</h2><div class="grid g2"><div class="card"><h3>Проблема</h3><p class="muted">Статические анализаторы работают по жёстким правилам и дают много ложных срабатываний. Отправлять приватный код в публичные облачные API нельзя.</p></div>
<div class="card"><h3>Решение</h3><p class="muted">Квантованная open-source модель работает локально вместе с инструментами анализа кода: понимает контекст, находит уязвимость и пишет безопасный патч.</p></div></div>""",
        "Классические анализаторы работают по жёстким правилам и дают лавину ложных срабатываний, "
        "а отправлять приватный код во внешние облачные сервисы запрещено. Поэтому мы запускаем "
        "квантованную модель локально, вместе с инструментами анализа кода.",
    ),
    (
        """<h2>Архитектура</h2><div class="flow"><span>Git-снимок: Python, JS/TS, Go</span><b>→</b><span>Инструменты: AST, секреты, OSV, правила для 35 CWE</span><b>+</b><span>Поиск (LLM)</span><b>→</b><span>Граф доказательств</span><b>→</b><span>Аудитор (LLM)</span><b>→</b><span>Скептик (LLM)</span><b>→</b><span>Архитектор: diff</span><b>→</b><span>Проверка в копии</span><b>→</b><span>Отчёт OWASP Top 10</span></div>
<div class="grid g4" style="margin-top:56px"><div class="card"><h3>Поиск</h3><p class="muted">ищет уязвимости независимо от сканеров, любые из 139 CWE</p></div><div class="card"><h3>Аудитор</h3><p class="muted">проверяет каждого кандидата по коду</p></div><div class="card"><h3>Скептик</h3><p class="muted">пытается опровергнуть находку, прежде чем её примут</p></div><div class="card"><h3>Архитектор</h3><p class="muted">пишет патч только для подтверждённой находки</p></div></div>""",
        "Система читает точный снимок репозитория. Инструменты строят синтаксические деревья, ищут "
        "секреты, уязвимые версии библиотек и тридцать пять типов уязвимостей по правилам. "
        "Параллельно агент Поиск на языковой модели ищет уязвимости сам, без ограничения "
        "этим списком. Агент Аудитор проверяет каждого кандидата по коду, а агент Скептик "
        "пытается опровергнуть его вывод. Только "
        "подтверждённую находку агент Архитектор исправляет, а система проверяет патч во "
        "временной копии и формирует отчёт. В коротком демо роль второго мнения играет "
        "детерминированный сканер.",
    ),
    (
        """<h2>Живой прогон: Qwen</h2><pre>$ python deploy/docker/quickstart.py --demo --provider local

Модель      qwen2.5-coder:7b-instruct-q4_K_M (Ollama)
Аудитор     SUCCEEDED     находка совпала со сканером
Архитектор  SUCCEEDED     патч предложен
Проверка    PASSED        разбор OK, повторный скан: 0 сигналов
Итог        <span class="add">COMPLETED</span></pre>""",
        "Запускаем одной командой на локальной модели Qwen 2.5 Coder семь миллиардов параметров, "
        "квантование Q4. Аудитор нашёл SQL-инъекцию, и она совпала с детерминированным сканером. "
        "Архитектор предложил исправление, патч прошёл разбор и повторное сканирование. "
        "Итог — completed.",
    ),
    (
        """<h2>Отчёт аудита</h2><table><tr><th>CWE</th><th>OWASP Top 10</th><th>Уровень</th><th>Место</th><th>Нашли</th></tr><tr><td>CWE-89</td><td>A03:2021 Injection</td><td>HIGH</td><td>app.py:5</td><td>сканер + модель</td></tr></table>
<pre style="margin-top:36px"><span class="del">-    return conn.execute("SELECT * FROM users WHERE name = '" + name + "'")</span>
<span class="add">+    return conn.execute("SELECT * FROM users WHERE name = ?", (name,))</span></pre>
<p class="muted" style="margin-top:34px">Тот же результат на DeepSeek: 2 вызова, $0.00014.</p>""",
        "В отчёте — номер CWE, категория OWASP Top 10, уровень опасности, строка и готовый diff: "
        "конкатенация строки заменена параметризованным запросом. Тот же сценарий на DeepSeek "
        "дал такой же результат и стоил меньше сотой доли цента.",
    ),
    (
        """<h2>Инструменты</h2><div class="grid g4"><div class="card"><h3>Секреты</h3><p class="muted">пароль в app.py найден, значение скрыто</p></div><div class="card"><h3>Зависимости</h3><p class="muted">requests 2.19.0: 10 уязвимостей по OSV</p></div><div class="card"><h3>JavaScript</h3><p class="muted">SQL-инъекция и отсутствие аутентификации</p></div><div class="card"><h3>Контракт</h3><p class="muted">файл, строки, CWE и хеш в единой схеме</p></div></div>
<p class="muted" style="margin-top:44px">Полный прогон с сохранёнными выводами — на сайте проекта, раздел Notebook</p>""",
        "Notebook показывает все инструменты на небольшом проекте. Найден захардкоженный пароль, "
        "его значение скрыто. Для старой версии библиотеки requests база OSV вернула десять "
        "уязвимостей. В JavaScript-файле найдены SQL-инъекция и отсутствие аутентификации. "
        "Все находки описаны в единой схеме: файл, строки, CWE и хеш содержимого.",
    ),
    (
        """<h2>Эксперименты</h2><table><tr><th>OWASP Benchmark for Python, 1230 кейсов</th><th>Оценка</th></tr><tr class="hi"><td>SecureCode: согласие трёх проверок</td><td class="n">0,84</td></tr><tr><td>Только модель gpt-oss-120b</td><td class="n">0,80</td></tr><tr><td>SecureCode: только сканеры</td><td class="n">0,21</td></tr><tr><td>Bandit и Semgrep</td><td class="n">0,16</td></tr></table>
<p class="muted">CVEfixes, 3000 файлов: SecureCode с моделью находит 50,5% уязвимостей против 34,3% у Semgrep, разница статистически значима.</p>""",
        "Эксперименты проведены на двух открытых корпусах. На OWASP Benchmark для Python "
        "SecureCode принимает решение согласием трёх проверок: модель без подсказок, "
        "модель, проверяющая находки сканеров, и вторая модель. Так он получает оценку "
        "ноль восемьдесят четыре — выше, чем та же модель без сканеров, а Semgrep и Bandit — "
        "всего ноль шестнадцать. На трёх тысячах файлов CVEfixes SecureCode с моделью "
        "находит половину уязвимостей, на шестнадцать пунктов больше Semgrep.",
    ),
    (
        """<h2>Итог</h2><div class="grid g3"><div class="card"><div class="num">1</div><p class="muted">команда для запуска демо</p></div><div class="card"><div class="num">3300+</div><p class="muted">автотестов в CI</p></div><div class="card"><div class="num">2</div><p class="muted">модели: Qwen локально и DeepSeek</p></div></div>
<pre style="margin-top:48px">git clone https://github.com/shorinversion/securecode-ai
python deploy/docker/quickstart.py --demo</pre>""",
        "Проект запускается одной командой, покрыт более чем тремя тысячами автотестов и работает как "
        "с локальной моделью, так и с облачной. Дальше — точность детекторов и оценка полного "
        "агентного конвейера на большом корпусе. Спасибо за внимание.",
    ),
]


def _settings() -> dict[str, str]:
    values = {key: value for key, value in os.environ.items() if key.startswith("ELEVENLABS_")}
    dotenv = ROOT / ".env"
    if dotenv.is_file():
        for line in dotenv.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.strip().partition("=")
            if separator and key.startswith("ELEVENLABS_") and key not in values:
                values[key] = value.strip().strip("'\"")
    return values


def _browser() -> str:
    for candidate in (
        shutil.which("chrome"),
        shutil.which("msedge"),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    ):
        if candidate and Path(candidate).is_file():
            return candidate
    raise SystemExit("Chrome or Edge is required to render slides")


def _speak(text: str, target: Path, settings: dict[str, str]) -> None:
    body = json.dumps(
        {"text": text, "model_id": "eleven_multilingual_v2"}, ensure_ascii=False
    ).encode("utf-8")
    request = urllib.request.Request(
        "https://api.elevenlabs.io/v1/text-to-speech/"
        f"{settings['ELEVENLABS_VOICE_ID']}?output_format=mp3_44100_128",
        data=body,
        headers={"xi-api-key": settings["ELEVENLABS_API_KEY"], "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        target.write_bytes(response.read())


def _duration(path: Path) -> float:
    probe = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return float(probe.stdout.strip())


def main() -> int:
    for language in sys.argv[1:] or ["ru", "en"]:
        _build(language)
    return 0


def _english_slides() -> list[tuple[str, str]]:
    import importlib.util

    spec = importlib.util.spec_from_file_location("slides_en", MEDIA / "slides_en.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    slides: list[tuple[str, str]] = module.SLIDES_EN
    return slides


def _build(language: str) -> None:
    slides = _english_slides() if language == "en" else SLIDES
    suffix = "" if language == "ru" else "." + language
    target = MEDIA / f"securecode-demo{suffix}.mp4"
    narration_file = MEDIA / f"narration.{language}.txt"
    settings = _settings()
    if not settings.get("ELEVENLABS_API_KEY") or not settings.get("ELEVENLABS_VOICE_ID"):
        raise SystemExit("ELEVENLABS_API_KEY and ELEVENLABS_VOICE_ID are required")
    WORK.mkdir(parents=True, exist_ok=True)
    browser = _browser()
    segments = []
    for index, (body, narration) in enumerate(slides, start=1):
        page = WORK / f"{language}-slide-{index}.html"
        page.write_text(
            f'<!doctype html><html lang="{language}"><meta charset="utf-8"><style>{STYLE}</style>'
            f"<body>{body}</body></html>",
            encoding="utf-8",
        )
        image = WORK / f"{language}-slide-{index}.png"
        # A stale image from an earlier build must never reach the video.
        image.unlink(missing_ok=True)
        for _ in range(3):
            subprocess.run(
                [browser, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                 f"--user-data-dir={WORK / 'browser-profile'}",
                 "--window-size=1920,1080", f"--screenshot={image}", page.as_uri()],
                check=True, capture_output=True,
            )  # fmt: skip
            # Edge may write the screenshot after its launcher process has exited.
            for _ in range(30):
                if image.exists():
                    break
                time.sleep(0.5)
            if image.exists():
                break
        else:
            raise SystemExit(f"{image.name}: the browser wrote no screenshot")
        # Cache narration by its text so an edited sentence is always re-spoken.
        digest = hashlib.sha256(narration.encode("utf-8")).hexdigest()[:16]
        audio = WORK / f"{language}-{digest}.mp3"
        if not audio.exists():
            _speak(narration, audio, settings)
        segment = WORK / f"{language}-segment-{index}.mp4"
        length = _duration(audio) + 1.2
        subprocess.run(
            ["ffmpeg", "-y", "-loglevel", "error", "-loop", "1", "-i", str(image), "-i", str(audio),
             "-af", "adelay=500|500,apad", "-t", f"{length:.2f}", "-c:v", "libx264",
             "-tune", "stillimage", "-pix_fmt", "yuv420p", "-r", "30", "-c:a", "aac",
             "-b:a", "160k", "-ar", "44100", str(segment)],
            check=True,
        )  # fmt: skip
        segments.append(segment)
        print(f"slide {index}: {length:.1f}s")
    listing = WORK / f"{language}-segments.txt"
    listing.write_text(
        "".join(f"file '{item.as_posix()}'\n" for item in segments), encoding="utf-8"
    )
    subprocess.run(
        ["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(listing),
         "-c", "copy", "-movflags", "+faststart", str(target)],
        check=True,
    )  # fmt: skip
    narration_file.write_text(
        "\n\n".join(html.unescape(text) for _, text in slides) + "\n", encoding="utf-8"
    )
    shutil.copy(WORK / f"{language}-slide-1.png", MEDIA / f"poster.{language}.png")
    print(f"{target.relative_to(ROOT)}: {_duration(target):.1f}s")


if __name__ == "__main__":
    sys.exit(main())
