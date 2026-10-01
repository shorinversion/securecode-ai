# ruff: noqa: RUF001 - the report is written in Russian
"""Render the benchmark v2 report (Russian Markdown) from the aggregated results."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

_MODELS: Final = {
    "deepseek": "DeepSeek Flash",
    "luna": "GPT-5.6 Luna",
    "glm": "GLM-5.3",
    "qwen3.8-27b": "Qwen 3.8 27B",
    "qwen3.6-35b": "Qwen 3.6 35B-A3B",
    "qwen3.6-fp8": "Qwen 3.6 FP8",
    "gpt-oss-120b": "gpt-oss-120b",
    "gpt-oss-20b": "gpt-oss-20b",
    "gemma-4-31b": "Gemma 4 31B",
}
# SecureCode configurations first, then the baselines: open analyzers and models alone.
NAMES: Final = {
    "pipeline": "SecureCode: полный конвейер (Поиск, Аудитор, Скептик)",
    **{
        f"verified+{key}": f"SecureCode: сканеры + проверка {name}" for key, name in _MODELS.items()
    },
    **{f"securecode+{key}": f"SecureCode: сканеры ∪ {name}" for key, name in _MODELS.items()},
    "securecode+semgrep": "Сканеры SecureCode ∪ Semgrep",
    "securecode": "SecureCode: только сканеры",
    "semgrep": "Semgrep 1.177.0",
    "bandit": "Bandit 1.9.4",
    "gosec": "gosec",
    "eslint": "ESLint + eslint-plugin-security",
    **{key: f"Только модель: {name}" for key, name in _MODELS.items()},
}
SCOPES: Final = {
    "python": "Python",
    "javascript-typescript": "JavaScript/TypeScript",
    "go": "Go",
}
OWASP_NAMES: Final = {
    "pathtraver": "Path Traversal (CWE-22)",
    "hash": "Weak Hash (CWE-328)",
    "weakrand": "Weak Randomness (CWE-330)",
    "xss": "XSS (CWE-79)",
    "deserialization": "Deserialization (CWE-502)",
    "codeinj": "Code Injection (CWE-94)",
    "securecookie": "Secure Cookie (CWE-614)",
    "trustbound": "Trust Boundary (CWE-501)",
    "redirect": "Open Redirect (CWE-601)",
    "ldapi": "LDAP Injection (CWE-90)",
    "xxe": "XXE (CWE-611)",
    "cmdi": "Command Injection (CWE-78)",
    "sqli": "SQL Injection (CWE-89)",
    "xpathi": "XPath Injection (CWE-643)",
}


def _percent(value: float) -> str:
    return f"{value * 100:.1f}%".replace(".", ",")


def _row(name: str, metrics: Mapping[str, Any]) -> str:
    return (
        f"| {NAMES.get(name, name)} | {metrics['cases']} | {_percent(metrics['analyzed'])} | "
        f"{_percent(metrics['precision'])} | {_percent(metrics['recall'])} | "
        f"{_percent(metrics['f1'])} | {_percent(metrics['false_positive_rate'])} | "
        f"{_percent(metrics['pair_discrimination'])} |"
    )


_HEADER: Final = (
    "| Конфигурация | Файлов | Проанализировано | Precision | Recall | F1 | Ложные срабатывания "
    "| Различение пар |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
)


def render(cvefixes: Mapping[str, Any], owasp: Mapping[str, Any] | None, summary: str = "") -> str:
    configurations: Mapping[str, Mapping[str, Any]] = cvefixes["configurations"]
    order = [name for name in NAMES if name in configurations]
    out = [
        "# Эксперименты: бенчмарк v2",
        "",
        "Два корпуса с известной разметкой. Сравниваются сканеры SecureCode, открытые",
        "анализаторы Semgrep, Bandit (Python), gosec (Go) и ESLint с eslint-plugin-security",
        "(JavaScript/TypeScript), языковые модели DeepSeek Flash, GPT-5.6 Luna и GLM-5.3,",
        "гибриды сканеров с моделями и полный агентный конвейер SecureCode. Модели в этих",
        "конфигурациях классифицируют файл одним запросом; конвейер — это Поиск, Аудитор и",
        "Скептик с доступом к инструментам.",
        "",
        *([summary.strip(), ""] if summary.strip() else []),
        "## Датасеты",
        "",
        "| Датасет | Что взято | Ссылка |",
        "| --- | --- | --- |",
        "| CVEfixes v1.0.8 | 1500 пар «файл до / после исправления CVE», по 500 на Python, "
        "JavaScript/TypeScript и Go; 118 CWE | [Zenodo](https://zenodo.org/records/13118970), "
        "[GitHub](https://github.com/secureIT-project/CVEfixes) |",
        "| OWASP Benchmark for Python 0.1 | 1230 тестовых обработчиков в 14 категориях "
        "уязвимостей с эталонной разметкой | "
        "[GitHub](https://github.com/OWASP-Benchmark/BenchmarkPython) |",
        "",
        "Исходный код корпусов в репозиторий не входит: хранятся только манифест CVEfixes "
        "(идентификаторы и SHA-256 файлов) и скрипты, которые воспроизводят выборку.",
        "",
        "## CVEfixes: 3000 файлов",
        "",
        "Каждая пара — один и тот же файл до и после исправления уязвимости. Уязвимая версия",
        "должна быть найдена, исправленная — нет. «Различение пар» — доля пар, где",
        "инструмент сработал на уязвимой версии и не сработал на исправленной; эта метрика",
        "показывает, понимает ли инструмент суть исправления, а не просто реагирует на",
        "похожий код. Файлы, которые инструмент не смог разобрать, считаются",
        "непроверенными и в recall не засчитываются.",
        "",
        "Классические анализаторы, сканеры SecureCode и DeepSeek прогнаны на всех файлах;",
        "GPT-5.6 Luna и модели с открытыми весами — на отложенной выборке (1200 файлов),",
        "полный конвейер — на 246 файлах отложенной выборки. Колонка «Файлов» показывает",
        "фактический объём для каждой строки.",
        "",
        "### Все файлы",
        "",
        _HEADER,
    ]
    out += [_row(name, configurations[name]["all"]) for name in order if name != "pipeline"]
    out += ["", "### Отложенная выборка (1200 файлов)", "", _HEADER]
    out += [_row(name, configurations[name]["held-out"]) for name in order]
    for scope, title in SCOPES.items():
        out += ["", f"### {title}", "", _HEADER]
        out += [
            _row(name, configurations[name][scope])
            for name in order
            if configurations[name][scope]["cases"] and name != "pipeline"
        ]
    differences = cvefixes.get("recall_difference_vs_semgrep", {})
    if differences:
        out += [
            "",
            "### Разница recall с Semgrep",
            "",
            "Bootstrap по парам, 5000 итераций, 95% доверительный интервал (п. п.).",
            "",
            "| Конфигурация | Все файлы | Отложенная выборка |",
            "| --- | --- | --- |",
        ]
        for name in order:
            if name in differences:
                cells = []
                for scope in ("all", "held-out"):
                    value, low, high = differences[name][scope]
                    cells.append(
                        f"{value * 100:+.1f} [{low * 100:+.1f}; {high * 100:+.1f}]".replace(
                            ".", ","
                        )
                    )
                out.append(f"| {NAMES.get(name, name)} | {cells[0]} | {cells[1]} |")
    if owasp is not None:
        out += [
            "",
            "## OWASP Benchmark for Python",
            "",
            "Кейс засчитывается, только если инструмент сообщил CWE нужной категории, как в",
            "официальных scorecard OWASP Benchmark. Оценка категории — TPR − FPR (индекс",
            "Юдена); итоговая оценка — среднее по 14 категориям. Случайный классификатор",
            "получает 0, идеальный — 1.",
            "",
        ]
        out += _owasp_table(owasp["tools"], f"Все {owasp['cases']} кейсов")
        sample = owasp.get("sample")
        if sample:
            out += [""]
            out += _owasp_table(
                sample["tools"],
                f"Сбалансированная подвыборка (кейсов: {sample['cases']}, до "
                f"{sample['per_category']} на категорию) для GLM-5.3, самой дорогой модели",
            )
    out += [
        "",
        "## Воспроизведение",
        "",
        "```bash",
        "uv run python -m scripts.build_cvefixes_manifest --database CVEfixes_v1.0.8.sqlite \\",
        "  --output report/benchmark-v2/cvefixes-manifest.json --pairs-per-language 500",
        "uv run python -m scripts.benchmark_v2 cache --manifest report/benchmark-v2/cvefixes-manifest.json \\",
        "  --database CVEfixes_v1.0.8.sqlite --output cache.sqlite",
        "uv run python -m scripts.benchmark_v2 run --tool semgrep --manifest ... --database cache.sqlite \\",
        "  --output predictions/semgrep.jsonl --semgrep-config semgrep-rules",
        "uv run python -m scripts.benchmark_v2 aggregate --manifest ... --predictions predictions \\",
        "  --output report/benchmark-v2",
        "uv run python -m scripts.owasp_benchmark_python --benchmark BenchmarkPython \\",
        "  --semgrep-config semgrep-rules --output report/benchmark-v2/owasp-python.json",
        "```",
        "",
    ]
    return "\n".join(out)


def _owasp_table(tools: Mapping[str, Mapping[str, Any]], title: str) -> list[str]:
    out = [
        f"### {title}",
        "",
        "| Инструмент | Оценка | TPR | Precision |",
        "| --- | ---: | ---: | ---: |",
    ]
    for name, value in sorted(tools.items(), key=lambda item: -item[1]["score"]):
        score = f"{value['score']:.2f}".replace(".", ",")
        out.append(
            f"| {NAMES.get(name, name)} | {score} | {_percent(value['tpr'])} | "
            f"{_percent(value['precision'])} |"
        )
    key = (
        "verified+gpt-oss-120b",
        "gpt-oss-120b",
        "verified+deepseek",
        "deepseek",
        "glm",
        "securecode",
        "semgrep",
        "bandit",
    )
    names = [name for name in key if name in tools]
    out += [
        "",
        "| Категория | " + " | ".join(NAMES.get(name, name) for name in names) + " |",
        "| --- |" + " ---: |" * len(names),
    ]
    for category, label in OWASP_NAMES.items():
        cells = [
            f"{tools[name]['categories'][category]['score']:.2f}".replace(".", ",")
            for name in names
        ]
        out.append(f"| {label} | " + " | ".join(cells) + " |")
    return out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--owasp", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--summary", type=Path, help="hand-written conclusions in Markdown")
    arguments = parser.parse_args(argv)
    cvefixes = json.loads(arguments.results.read_text(encoding="utf-8"))
    owasp = (
        json.loads(arguments.owasp.read_text(encoding="utf-8"))
        if arguments.owasp is not None
        else None
    )
    summary = arguments.summary.read_text(encoding="utf-8") if arguments.summary is not None else ""
    arguments.output.write_text(render(cvefixes, owasp, summary), encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
