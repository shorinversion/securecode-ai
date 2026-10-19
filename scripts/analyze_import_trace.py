# ruff: noqa: RUF001 - the report is written in Russian
"""Measure which modules ``securecode analyze`` needs, to find code nothing uses.

Three signals, none of which deletes anything:

* the modules a real ``securecode analyze`` run imports (measured in a fresh process);
* the modules the server and the worker and the other CLI commands import, found statically
  (the import closure over the source tree) - together with the first, "the product";
* the modules scripts and tests import, listed separately;
* optionally the line coverage of a test run (``--coverage coverage.json``).

A module the product does not use is a candidate for removal (it is still used by a script
or a test, or by nothing); the decision is the owner's.

    uv run python -m scripts.analyze_import_trace run --repo path/to/git/repo --provider local
    uv run python -m scripts.analyze_import_trace report --loaded loaded.json \\
        --coverage coverage.json --output report/analyze-import-trace.md
"""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
import tempfile
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[1]
PREFIX: Final = "securecode_ai"
SERVER_WORKER_ROOTS: Final = ("securecode_ai.server", "securecode_ai.worker")
CLI_ROOTS: Final = ("securecode_ai.cli",)


@dataclass(frozen=True, slots=True)
class Module:
    name: str
    path: str
    lines: int
    is_package: bool


@dataclass(frozen=True, slots=True)
class Row:
    module: Module
    used_by_analyze: bool
    used_by_server_worker: bool
    coverage: float | None  # percent, when a coverage file was given and measured it
    used_by_cli: bool = False
    used_by_scripts: bool = False
    used_by_tests: bool = False

    @property
    def unused(self) -> bool:
        """The product (analyze, server, worker, the CLI) does not use it."""

        return not (self.used_by_analyze or self.used_by_server_worker or self.used_by_cli)


def module_name(path: Path, root: Path = ROOT) -> str | None:
    """The dotted name of a source file of ``packages/*/src`` or ``apps/*/src``."""

    parts = path.relative_to(root).with_suffix("").parts
    if "src" not in parts:
        return None
    dotted = list(parts[parts.index("src") + 1 :])
    if not dotted or dotted[0] != PREFIX:
        return None
    if dotted[-1] == "__init__":
        dotted.pop()
    return ".".join(dotted)


def discover(root: Path = ROOT) -> dict[str, Module]:
    """Every module of the workspace by dotted name."""

    modules: dict[str, Module] = {}
    for base in ("packages", "apps"):
        for path in sorted((root / base).glob("*/src/**/*.py")):
            name = module_name(path, root)
            if name is None:
                continue
            lines = len(path.read_text(encoding="utf-8").splitlines())
            modules[name] = Module(
                name, path.relative_to(root).as_posix(), lines, path.name == "__init__.py"
            )
    return modules


def imports_of(name: str, source: str, *, is_package: bool) -> set[str]:
    """The dotted names a module imports (every ``import`` in it, functions included).

    ``from a.b import c`` yields ``a.b`` and ``a.b.c``: the caller keeps what is a module.
    """

    found: set[str] = set()
    package = name if is_package else name.rpartition(".")[0]
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return found
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                anchor = package.split(".")
                anchor = anchor[: len(anchor) - (node.level - 1)] if node.level > 1 else anchor
                base = ".".join([*anchor, *([base] if base else [])])
            if not base:
                continue
            found.add(base)
            found.update(f"{base}.{alias.name}" for alias in node.names if alias.name != "*")
    return found


def import_graph(modules: Mapping[str, Module], root: Path = ROOT) -> dict[str, set[str]]:
    """Edges between workspace modules; importing ``a.b.c`` also loads ``a.b`` and ``a``."""

    graph: dict[str, set[str]] = {}
    for name, module in modules.items():
        source = (root / module.path).read_text(encoding="utf-8")
        edges: set[str] = set()
        for target in imports_of(name, source, is_package=module.is_package):
            parts = target.split(".")
            for count in range(1, len(parts) + 1):
                candidate = ".".join(parts[:count])
                if candidate in modules and candidate != name:
                    edges.add(candidate)
        graph[name] = edges
    return graph


def closure(roots: Iterable[str], graph: Mapping[str, set[str]]) -> set[str]:
    """Modules reachable from the modules under ``roots`` (a root is a name or a package)."""

    start = {name for name in graph if any(name == r or name.startswith(r + ".") for r in roots)}
    seen = set(start)
    stack = list(start)
    while stack:
        for target in graph.get(stack.pop(), ()):
            if target not in seen:
                seen.add(target)
                stack.append(target)
    return seen


def classify(
    modules: Mapping[str, Module],
    loaded: set[str],
    server_worker: set[str],
    coverage: Mapping[str, float] | None = None,
    *,
    cli: Collection[str] = (),
    scripts: Collection[str] = (),
    tests: Collection[str] = (),
) -> list[Row]:
    """One row per module: who uses it (analyze run, server/worker, CLI, scripts, tests)."""

    return [
        Row(
            module,
            name in loaded,
            name in server_worker,
            None if coverage is None else coverage.get(name),
            name in cli,
            name in scripts,
            name in tests,
        )
        for name, module in sorted(modules.items())
    ]


def external_imports(
    files: Iterable[Path], modules: Mapping[str, Module], graph: Mapping[str, set[str]]
) -> set[str]:
    """Workspace modules that the given outside files import, with everything they pull in."""

    roots: set[str] = set()
    for file in files:
        try:
            source = file.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for target in imports_of("__main__", source, is_package=False):
            parts = target.split(".")
            roots.update(
                ".".join(parts[:count])
                for count in range(1, len(parts) + 1)
                if ".".join(parts[:count]) in modules
            )
    return closure(roots, graph)


def coverage_by_module(document: Mapping[str, object], root: Path = ROOT) -> dict[str, float]:
    """Percent covered per module from a ``coverage json`` document."""

    files = document.get("files")
    result: dict[str, float] = {}
    if not isinstance(files, dict):
        return result
    for filename, data in files.items():
        if not isinstance(data, dict):
            continue
        path = Path(filename)
        try:
            name = module_name(path if path.is_absolute() else root / path, root)
        except ValueError:
            continue
        summary = data.get("summary")
        percent = summary.get("percent_covered") if isinstance(summary, dict) else None
        if name is not None and isinstance(percent, int | float):
            result[name] = float(percent)
    return result


def render_report(rows: Sequence[Row], *, provider: str, coverage_note: str) -> str:
    total = sum(row.module.lines for row in rows)
    analyze = [row for row in rows if row.used_by_analyze]
    both_none = [row for row in rows if row.unused]
    dev_only = [row for row in both_none if row.used_by_scripts]
    only_tests = [row for row in both_none if not row.used_by_scripts and row.used_by_tests]
    nowhere = [row for row in both_none if not row.used_by_scripts and not row.used_by_tests]
    only_server = [
        row
        for row in rows
        if (row.used_by_server_worker or row.used_by_cli) and not row.used_by_analyze
    ]
    lines = [
        "# Какой код нужен `securecode analyze`",
        "",
        "Измерение, не удаление: список модулей, которых не касается продукт (прогон `analyze`,",
        "сервер, воркер, остальные команды CLI). Их по-прежнему могут импортировать скрипты и",
        "тесты. Решение об удалении принимает владелец отдельно.",
        "",
        "## Как измерено",
        "",
        f"- `analyze`: реальный прогон `securecode analyze --provider {provider}` в чистом процессе,",
        "  множество загруженных модулей `securecode_ai.*` (форматы отчёта, Архитектор, трасса — как в",
        "  обычном прогоне). Процессы сканеров (`spawn`) импортируют только уже загруженные модули.",
        "- сервер и воркер, остальные команды CLI (`securecode_ai.cli`), скрипты (`scripts/`, `demo/`):",
        "  статическое транзитивное замыкание импортов по исходникам (`ast`, включая импорты внутри",
        "  функций); тесты учтены отдельной колонкой.",
        f"- покрытие: {coverage_note}",
        "",
        "## Итог",
        "",
        "| Группа | Модулей | Строк |",
        "| --- | ---: | ---: |",
        f"| всего | {len(rows)} | {total} |",
        f"| нужны `analyze` | {len(analyze)} | {sum(r.module.lines for r in analyze)} |",
        f"| только сервер, воркер или другие команды CLI | {len(only_server)} | "
        f"{sum(r.module.lines for r in only_server)} |",
        f"| **не нужны продукту** | {len(both_none)} | {sum(r.module.lines for r in both_none)} |",
        f"| из них нужны только скриптам и тестам (бенчмарки, оценка, релизные утилиты) | "
        f"{len(dev_only)} | {sum(r.module.lines for r in dev_only)} |",
        f"| из них нужны только тестам | {len(only_tests)} | "
        f"{sum(r.module.lines for r in only_tests)} |",
        f"| из них не нужны никому | {len(nowhere)} | {sum(r.module.lines for r in nowhere)} |",
        "",
    ]
    lines += ["## Кандидаты на удаление", ""]
    if both_none:
        lines += [
            "| Модуль | Строк | Покрытие | Скрипты | Тесты |",
            "| --- | ---: | ---: | :---: | :---: |",
        ]
        lines += [
            f"| `{row.module.name}` | {row.module.lines} | {_percent(row.coverage)} | "
            f"{'да' if row.used_by_scripts else 'нет'} | {'да' if row.used_by_tests else 'нет'} |"
            for row in sorted(both_none, key=lambda value: -value.module.lines)
        ]
    else:
        lines.append("Таких модулей нет.")
    lines += [
        "",
        "## Все модули",
        "",
        "| Модуль | Строк | analyze | сервер/воркер | CLI | скрипты | тесты | Покрытие |",
        "| --- | ---: | :---: | :---: | :---: | :---: | :---: | ---: |",
    ]
    for row in rows:
        flags = (
            row.used_by_analyze,
            row.used_by_server_worker,
            row.used_by_cli,
            row.used_by_scripts,
            row.used_by_tests,
        )
        lines.append(
            f"| `{row.module.name}` | {row.module.lines} | "
            + " | ".join("да" if flag else "нет" for flag in flags)
            + f" | {_percent(row.coverage)} |"
        )
    return "\n".join(lines) + "\n"


def _percent(value: float | None) -> str:
    return "—" if value is None else f"{value:.0f}%"


# --- measurement in a fresh process -------------------------------------------------------


def _child(repo: str, provider: str, output: Path) -> int:
    """Run one analyze in this (fresh) process and write the loaded ``securecode_ai`` modules."""

    from securecode_ai.cli.application import main

    with tempfile.TemporaryDirectory() as directory:
        code = main(
            [
                "analyze",
                repo,
                "--provider",
                provider,
                "--output-dir",
                str(Path(directory) / "out"),
            ]
        )
    names = sorted(name for name in sys.modules if name == PREFIX or name.startswith(PREFIX + "."))
    output.write_text(json.dumps({"exit_code": code, "loaded": names}), encoding="utf-8")
    return 0


def measure(repo: str, provider: str) -> set[str]:
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "loaded.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "child",
                "--repo",
                repo,
                "--provider",
                provider,
                "--output",
                str(output),
            ],
            check=False,
            timeout=3600,
        )
        if completed.returncode != 0 or not output.is_file():
            raise SystemExit("the analyze run could not be measured")
        document = json.loads(output.read_text(encoding="utf-8"))
    return {str(name) for name in document["loaded"]}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="measure an analyze run and write loaded.json")
    run.add_argument("--repo", required=True)
    run.add_argument("--provider", default="local")
    run.add_argument("--output", type=Path, default=Path("loaded.json"))
    child = commands.add_parser("child")
    child.add_argument("--repo", required=True)
    child.add_argument("--provider", default="local")
    child.add_argument("--output", type=Path, required=True)
    report = commands.add_parser("report", help="classify the modules and write the report")
    report.add_argument("--loaded", type=Path, required=True)
    report.add_argument("--coverage", type=Path)
    report.add_argument("--provider", default="local")
    report.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    if arguments.command == "child":
        return _child(arguments.repo, arguments.provider, arguments.output)
    if arguments.command == "run":
        loaded = measure(arguments.repo, arguments.provider)
        arguments.output.write_text(json.dumps({"loaded": sorted(loaded)}), encoding="utf-8")
        print(f"{len(loaded)} securecode_ai modules loaded by one analyze run")
        return 0
    modules = discover()
    loaded = set(json.loads(arguments.loaded.read_text(encoding="utf-8"))["loaded"])
    graph = import_graph(modules)
    server_worker = closure(SERVER_WORKER_ROOTS, graph)
    cli = closure(CLI_ROOTS, graph)
    scripts = external_imports(
        [*sorted((ROOT / "scripts").glob("*.py")), *sorted((ROOT / "demo").glob("*.py"))],
        modules,
        graph,
    )
    tests = external_imports(sorted((ROOT / "tests").rglob("*.py")), modules, graph)
    coverage = None
    note = "не измерялось"
    if arguments.coverage is not None:
        coverage = coverage_by_module(json.loads(arguments.coverage.read_text(encoding="utf-8")))
        note = f"тесты stage unit `scripts/quality.py` (`tests/unit` и несколько интеграционных файлов), измерено модулей: {len(coverage)}"
    rows = classify(modules, loaded, server_worker, coverage, cli=cli, scripts=scripts, tests=tests)
    arguments.output.write_text(
        render_report(rows, provider=arguments.provider, coverage_note=note),
        encoding="utf-8",
        newline="\n",
    )
    print(f"{sum(row.unused for row in rows)} of {len(rows)} modules are not used by the product")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
