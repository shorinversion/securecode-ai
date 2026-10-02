# ruff: noqa: RUF001 - the pages are written in Russian
"""Regenerate the report pages of the site from the Markdown reports with pandoc.

Writes ``report/final-submission.html``, ``site/final-submission.html`` and
``site/benchmark.html``.  The site pages get the favicon, a description, navigation
between the pages and repository links instead of relative Markdown links.
"""

from __future__ import annotations

import posixpath
import re
import subprocess
from pathlib import Path
from typing import Final

BASE: Final = "https://github.com/shorinversion/securecode-ai/blob/main/"
STYLE: Final = "report/submission-benchmark/style.html"
NAV_STYLE: Final = """    .site-nav{font-size:14px;margin:0 0 8px}
    .site-nav a{text-decoration:none;border:1px solid #1a1a1a;border-radius:30px;padding:4px 14px;margin-right:6px;display:inline-block;margin-bottom:6px}
    .site-nav a:hover{background:#1a1a1a;color:#fff}
"""
NAV: Final = (
    ("index.html", "← Главная"),
    ("final-submission.html", "Итоговый отчёт"),
    ("benchmark.html", "Эксперименты"),
    ("https://github.com/shorinversion/securecode-ai", "GitHub"),
)


def _pandoc(source: str, title: str | None = None) -> str:
    command = ["pandoc", source, "-s", "-H", STYLE]
    if title is not None:
        command += ["--metadata", f"pagetitle={title}", "--metadata", "lang=ru"]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", check=True)
    return result.stdout.replace("\r\n", "\n")


def _site_page(source: str, target: str, prefix: str, title: str, description: str) -> None:
    html = _pandoc(source, title)

    def link(match: re.Match[str]) -> str:
        href = match.group(1)
        if href.startswith(("http", "#", "mailto")):
            return match.group(0)
        if href.endswith(("submission-benchmark/report.html", "benchmark-v2/README.md")):
            return 'href="benchmark.html"'
        return f'href="{BASE}{posixpath.normpath(prefix + href)}"'

    html = re.sub(r'href="([^"]*)"', link, html)
    name = Path(target).name
    nav = "".join(f'<a href="{href}">{text}</a>' for href, text in NAV if href != name)
    head = (
        f'  <meta name="description" content="{description}">\n'
        '  <link rel="icon" href="favicon.svg" type="image/svg+xml">\n'
    )
    html = html.replace("  <style>", head + "  <style>", 1)
    html = html.replace("  </style>\n</head>", NAV_STYLE + "  </style>\n</head>", 1)
    html = html.replace("<body>\n", f'<body>\n<nav class="site-nav">{nav}</nav>\n', 1)
    Path(target).write_text(html, encoding="utf-8", newline="\n")


def main() -> int:
    Path("report/final-submission.html").write_text(
        _pandoc("report/final-submission.md"), encoding="utf-8", newline="\n"
    )
    _site_page(
        "report/final-submission.md",
        "site/final-submission.html",
        "report/",
        "SecureCode AI: итоговый отчёт",
        "Итоговый отчёт SecureCode AI: постановка задачи, архитектура, эксперименты, "
        "ограничения и выводы.",
    )
    _site_page(
        "report/benchmark-v2/README.md",
        "site/benchmark.html",
        "report/benchmark-v2/",
        "SecureCode AI: эксперименты, бенчмарк v2",
        "SecureCode AI на OWASP Benchmark for Python и CVEfixes: сравнение с Semgrep, "
        "Bandit, gosec, ESLint и языковыми моделями.",
    )
    print("SITE_PAGES=OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
