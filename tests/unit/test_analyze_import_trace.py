# ruff: noqa: RUF001 - the report under test is written in Russian
"""Classification of modules by what `securecode analyze` and the server import."""

from __future__ import annotations

from pathlib import Path

from scripts.analyze_import_trace import (
    Module,
    Row,
    classify,
    closure,
    coverage_by_module,
    discover,
    import_graph,
    imports_of,
    module_name,
    render_report,
)


def _tree(root: Path) -> None:
    files = {
        "packages/core/src/securecode_ai/core/__init__.py": "",
        "packages/core/src/securecode_ai/core/shared.py": "VALUE = 1\n",
        "packages/core/src/securecode_ai/core/orphan.py": "import json\n",
        "packages/adapters/src/securecode_ai/adapters/__init__.py": "",
        "packages/adapters/src/securecode_ai/adapters/used.py": (
            "from securecode_ai.core import shared\n"
        ),
        "packages/adapters/src/securecode_ai/adapters/relative.py": (
            "from . import used\nfrom .used import helper\nfrom ..core.shared import VALUE\n"
        ),
        "packages/adapters/src/securecode_ai/adapters/lazy.py": (
            "def run():\n    import securecode_ai.core.orphan\n"
        ),
        "packages/adapters/src/securecode_ai/adapters/broken.py": "def (:\n",
        "apps/server/src/securecode_ai/server/__init__.py": "",
        "apps/server/src/securecode_ai/server/handler.py": (
            "from securecode_ai.adapters.relative import x\n"
        ),
        "apps/cli/src/securecode_ai/cli/__init__.py": "",
        "tools/other/src/notme/__init__.py": "",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def test_module_names_follow_the_source_layout(tmp_path: Path) -> None:
    _tree(tmp_path)

    assert module_name(tmp_path / "packages/core/src/securecode_ai/core/shared.py", tmp_path) == (
        "securecode_ai.core.shared"
    )
    assert module_name(tmp_path / "apps/cli/src/securecode_ai/cli/__init__.py", tmp_path) == (
        "securecode_ai.cli"
    )
    assert module_name(tmp_path / "tools/other/src/notme/__init__.py", tmp_path) is None
    assert module_name(tmp_path / "scripts/x.py", tmp_path) is None


def test_discovery_lists_every_workspace_module_with_its_size(tmp_path: Path) -> None:
    _tree(tmp_path)

    modules = discover(tmp_path)

    assert "securecode_ai.core.shared" in modules and "notme" not in modules
    assert modules["securecode_ai.core.shared"].lines == 1
    assert modules["securecode_ai.core"].is_package


def test_imports_cover_absolute_relative_from_and_function_level_forms() -> None:
    assert imports_of("securecode_ai.adapters.x", "import a.b\nimport c", is_package=False) == {
        "a.b",
        "c",
    }
    relative = imports_of(
        "securecode_ai.adapters.x",
        "from . import used\nfrom .used import helper\nfrom ..core.shared import VALUE\n",
        is_package=False,
    )
    assert relative == {
        "securecode_ai.adapters",
        "securecode_ai.adapters.used",
        "securecode_ai.adapters.used.helper",
        "securecode_ai.core.shared",
        "securecode_ai.core.shared.VALUE",
    }
    inside_package = imports_of("securecode_ai.adapters", "from . import used", is_package=True)
    assert "securecode_ai.adapters.used" in inside_package
    assert imports_of("m", "def f():\n    import late\n", is_package=False) == {"late"}
    assert imports_of("m", "def (:", is_package=False) == set()


def test_closure_follows_imports_transitively_from_the_server(tmp_path: Path) -> None:
    _tree(tmp_path)
    modules = discover(tmp_path)

    graph = import_graph(modules, tmp_path)
    reachable = closure(("securecode_ai.server",), graph)

    assert {
        "securecode_ai.server.handler",
        "securecode_ai.adapters.relative",
        "securecode_ai.adapters.used",
        "securecode_ai.core.shared",
        "securecode_ai.core",  # importing a module imports its package
    } <= reachable
    assert "securecode_ai.adapters.lazy" not in reachable
    assert "securecode_ai.core.orphan" not in reachable


def test_a_module_used_by_nothing_is_a_candidate(tmp_path: Path) -> None:
    _tree(tmp_path)
    modules = discover(tmp_path)
    server = closure(("securecode_ai.server",), import_graph(modules, tmp_path))
    loaded = {"securecode_ai.adapters.lazy", "securecode_ai.core.orphan"}

    rows = classify(modules, loaded, server, {"securecode_ai.adapters.broken": 0.0})
    by_name = {row.module.name: row for row in rows}

    assert by_name["securecode_ai.core.orphan"].used_by_analyze
    assert by_name["securecode_ai.core.shared"].used_by_server_worker
    assert by_name["securecode_ai.adapters.broken"].unused
    assert by_name["securecode_ai.adapters.broken"].coverage == 0.0
    assert by_name["securecode_ai.core.shared"].coverage is None
    assert not by_name["securecode_ai.core.orphan"].unused


def test_coverage_json_is_read_per_module(tmp_path: Path) -> None:
    _tree(tmp_path)
    document = {
        "files": {
            "packages/core/src/securecode_ai/core/shared.py": {
                "summary": {"percent_covered": 87.5}
            },
            "tests/unit/test_x.py": {"summary": {"percent_covered": 100.0}},
            "packages/core/src/securecode_ai/core/orphan.py": {"summary": {}},
        }
    }

    assert coverage_by_module(document, tmp_path) == {"securecode_ai.core.shared": 87.5}
    assert coverage_by_module({"files": []}, tmp_path) == {}


def test_report_counts_groups_and_lists_candidates_by_size() -> None:
    def row(
        name: str,
        lines: int,
        analyze: bool,
        server: bool,
        coverage: float | None,
        *,
        cli: bool = False,
        scripts: bool = False,
        tests: bool = False,
    ) -> Row:
        return Row(
            Module(name, name + ".py", lines, False), analyze, server, coverage, cli, scripts, tests
        )

    rows = [
        row("a", 100, True, False, 80.0),
        row("b", 50, False, True, None),
        row("e", 20, False, False, None, cli=True),
        row("c", 30, False, False, 0.0, scripts=True, tests=True),
        row("d", 70, False, False, None, scripts=True),
        row("t", 10, False, False, None, tests=True),
        row("x", 5, False, False, None),
    ]

    text = render_report(rows, provider="local", coverage_note="note")

    assert "| всего | 7 | 285 |" in text
    assert "| нужны `analyze` | 1 | 100 |" in text
    assert "| только сервер, воркер или другие команды CLI | 2 | 70 |" in text
    assert "| **не нужны продукту** | 4 | 115 |" in text
    assert (
        "нужны только скриптам и тестам (бенчмарки, оценка, релизные утилиты) | 2 | 100 |" in text
    )
    assert "| из них нужны только тестам | 1 | 10 |" in text
    assert "| из них не нужны никому | 1 | 5 |" in text
    candidates = text.split("## Кандидаты на удаление")[1].split("## Все модули")[0]
    assert candidates.index("`d`") < candidates.index("`c`")  # the larger first
    assert "| `c` | 30 | 0% | да | да |" in candidates
    assert "| `d` | 70 | — | да | нет |" in candidates
    assert "`a`" not in candidates and "`e`" not in candidates


def test_report_without_candidates_says_so() -> None:
    rows = [Row(Module("a", "a.py", 10, False), True, False, None)]

    assert "Таких модулей нет." in render_report(rows, provider="local", coverage_note="n")
