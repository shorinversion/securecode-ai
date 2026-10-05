# ruff: noqa: RUF001 - the report under test is written in Russian
from __future__ import annotations

import json
from pathlib import Path

from securecode_ai.adapters.trial_architect import (
    FixFinding,
    ProposedFix,
    findings_from_report,
    propose_fixes,
)
from securecode_ai.adapters.trial_report import (
    TrialReportContext,
    render_trial_report,
    report_paths,
)

_VULNERABLE = (
    "import sqlite3\n"
    "\n"
    "\n"
    "def find_user(conn, name):\n"
    '    return conn.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n'
)
_FIXED_LINE = '    return conn.execute("SELECT * FROM users WHERE name = ?", (name,))'


def _applies(_path: str, _source: str, diff: str) -> bool:
    return diff.startswith("--- a/")


def _finding(path: str = "app.py", line: int = 5) -> FixFinding:
    return FixFinding("finding-1", "CWE-89", path, line, line, "model_native")


def _answer(start: int, end: int, replacement: str) -> str:
    return json.dumps(
        {
            "explanation": "Строка собирает SQL из ввода; исправление передаёт его параметром.",
            "edits": [{"start_line": start, "end_line": end, "replacement": replacement}],
        }
    )


def _fix(
    complete: object, *, source: str = _VULNERABLE, finding: FixFinding | None = None
) -> ProposedFix:
    (fix,) = propose_fixes(
        [finding or _finding()],
        complete,  # type: ignore[arg-type]
        read_source=lambda _path: source,
        apply_check=_applies,
    )
    return fix


def test_validated_fix_applies_parses_and_introduces_no_finding() -> None:
    prompts: list[str] = []

    def complete(system: str, _user: str) -> str:
        prompts.append(system)
        return _answer(5, 5, _FIXED_LINE)

    fix = _fix(complete)

    assert fix.status == "VALIDATED"
    assert {"apply:ok", "syntax:ok", "rescan:clean"} <= set(fix.checks)
    assert "+" + _FIXED_LINE in fix.diff and fix.diff.startswith("--- a/app.py")
    assert prompts[0].endswith("Write the explanation in Russian.")


def test_edit_far_from_the_finding_is_refused() -> None:
    fix = _fix(lambda _s, _u: _answer(1, 1, "import os"), finding=_finding(line=100))

    assert fix.status == "NO_FIX" and fix.diff == ""


def test_overlapping_edits_are_refused() -> None:
    answer = json.dumps(
        {
            "explanation": "x",
            "edits": [
                {"start_line": 4, "end_line": 5, "replacement": "a"},
                {"start_line": 5, "end_line": 5, "replacement": "b"},
            ],
        }
    )

    assert _fix(lambda _s, _u: answer).status == "NO_FIX"


def test_fix_that_breaks_syntax_is_not_validated() -> None:
    fix = _fix(lambda _s, _u: _answer(5, 5, "    return ("))

    assert fix.status == "NOT_VALIDATED"
    assert "syntax:failed" in fix.checks


def test_fix_that_does_not_apply_is_not_validated() -> None:
    (fix,) = propose_fixes(
        [_finding()],
        lambda _s, _u: _answer(5, 5, _FIXED_LINE),
        read_source=lambda _path: _VULNERABLE,
        apply_check=lambda _p, _s, _d: False,
    )

    assert fix.status == "NOT_VALIDATED" and "apply:failed" in fix.checks


def test_javascript_and_go_fixes_are_parsed_with_tree_sitter() -> None:
    js = "function run(db, id) {\n  return db.query('SELECT * FROM t WHERE id = ' + id);\n}\n"
    go = "package main\n\nfunc run() int {\n\treturn 1\n}\n"

    js_fix = _fix(
        lambda _s, _u: _answer(2, 2, "  return db.query('SELECT * FROM t WHERE id = ?', [id]);"),
        source=js,
        finding=_finding("src/db.js", 2),
    )
    go_fix = _fix(
        lambda _s, _u: _answer(4, 4, "\treturn 1 +"), source=go, finding=_finding("main.go", 4)
    )

    assert js_fix.status == "VALIDATED" and "syntax:ok" in js_fix.checks
    assert go_fix.status == "NOT_VALIDATED" and "syntax:failed" in go_fix.checks


def test_model_errors_and_unreadable_sources_become_no_fix() -> None:
    def failing(_system: str, _user: str) -> str:
        raise TimeoutError

    def unreadable(_path: str) -> str:
        raise OSError

    assert _fix(failing).status == "NO_FIX"
    (fix,) = propose_fixes(
        [_finding()], lambda _s, _u: "{}", read_source=unreadable, apply_check=_applies
    )
    assert fix.status == "NO_FIX"
    assert _fix(lambda _s, _u: "not json").status == "NO_FIX"


def _document() -> dict[str, object]:
    location = {
        "path": "app.py",
        "start": {"line": 5, "column": 12},
        "end": {"line": 5, "column": 70},
    }
    return {
        "outcome": "FAIL",
        "analysis_health": "DEGRADED",
        "findings": [
            {
                "finding_id": "finding-1",
                "cwe_id": "CWE-89",
                "owasp_category": "A03:2021",
                "severity": "HIGH",
                "verdict": "CONFIRMED",
                "candidate_origin": "model_native",
                "locations": [location],
            },
            {
                "finding_id": "finding-2",
                "cwe_id": "CWE-79",
                "owasp_category": "A03:2021",
                "severity": "MEDIUM",
                "verdict": "NEEDS_MORE_EVIDENCE",
                "candidate_origin": "deterministic",
                "locations": [location],
            },
        ],
        "coverage_manifest": {
            "units": [{"required": True, "coverage_status": "FAILED", "stage_id": "skeptic_review"}]
        },
    }


def test_only_confirmed_findings_go_to_the_architect() -> None:
    (finding,) = findings_from_report(_document())

    assert finding == FixFinding("finding-1", "CWE-89", "app.py", 5, 5, "model_native")
    assert report_paths(_document()) == ("app.py",)


def test_report_shows_code_owasp_names_fix_and_gaps() -> None:
    document = _document()
    findings = document["findings"]
    assert isinstance(findings, list)
    document["findings"] = findings[:1]
    fix = ProposedFix(
        "finding-1",
        "app.py",
        "VALIDATED",
        ("apply:ok", "syntax:ok", "rescan:clean", "original:gone"),
        "Параметризованный запрос.",
        "--- a/app.py\n+++ b/app.py\n@@ -5 +5 @@\n-old\n+" + _FIXED_LINE + "\n",
    )
    context = TrialReportContext(
        Path("repo"), "a" * 40, "deepseek", "deepseek-flash", 3100, {"app.py": _VULNERABLE}
    )

    markdown = render_trial_report(document, context, [fix], html_format=False).decode()
    page = render_trial_report(document, context, [fix], html_format=True).decode()

    assert "CWE-89 SQL Injection" in markdown and "A03:2021 Injection" in markdown
    assert "> 5 |" in markdown and "строка 5" in markdown
    assert "```diff" in markdown and "синтаксис корректен" in markdown
    assert "исходная находка устранена" in markdown and "$0.0031" in markdown
    assert "проверка Скептиком: не завершена (1)" in markdown
    assert page.startswith("<!doctype html>") and '<span class="hit">' in page
    assert "<script" not in page


def test_report_without_findings_or_sources_still_renders() -> None:
    document = {"outcome": "PASS", "analysis_health": "HEALTHY", "findings": []}
    context = TrialReportContext(Path("repo"), "b" * 40, "local", "qwen", 0, {})

    markdown = render_trial_report(document, context, [], html_format=False).decode()

    assert "Подтверждённых уязвимостей не найдено" in markdown
    assert "## Находки" not in markdown


_COMMAND = (
    "import subprocess\n"
    "\n"
    "\n"
    "def lookup(host):\n"
    '    return subprocess.check_output("nslookup " + host, shell=True)\n'
)


def _command_fix(replacement: str) -> ProposedFix:
    finding = FixFinding("finding-1", "CWE-78", "lookup.py", 5, 5, "deterministic")
    return _fix(lambda _s, _u: _answer(5, 5, replacement), source=_COMMAND, finding=finding)


def test_command_fix_that_lets_input_become_an_option_is_not_validated() -> None:
    fix = _command_fix('    return subprocess.check_output(["nslookup", host])')

    assert fix.status == "NOT_VALIDATED"
    assert "options:unguarded" in fix.checks


def test_command_fix_with_end_of_options_marker_or_dash_check_is_validated() -> None:
    marker = _command_fix('    return subprocess.check_output(["nslookup", "--", host])')
    checked = _command_fix(
        '    if host.startswith("-"):\n'
        '        raise ValueError("host")\n'
        '    return subprocess.check_output(["nslookup", host])'
    )

    assert marker.status == checked.status == "VALIDATED"
    assert "options:guarded" in marker.checks and "options:guarded" in checked.checks


def test_scanner_and_discovery_findings_of_one_weakness_get_one_fix() -> None:
    document = _document()
    findings = document["findings"]
    assert isinstance(findings, list)
    duplicate = dict(findings[0], finding_id="finding-3", candidate_origin="deterministic")
    findings.append(duplicate)

    (finding,) = findings_from_report(document)

    assert finding.finding_id == "finding-3" and finding.origin == "deterministic"


def test_get_with_a_default_is_not_a_none_dereference() -> None:
    from securecode_ai.adapters.trial_architect import _signals

    def rules(call: str) -> set[str]:
        source = (
            "from flask import request\n"
            "\n"
            "\n"
            "def lookup():\n"
            f"    host = {call}\n"
            '    return host.startswith("-")\n'
        )
        return {rule for rule, _ in _signals("lookup.py", source)}

    assert "securecode-python-cwe476" in rules('request.args.get("host")')
    assert "securecode-python-cwe476" in rules('request.args.get("host", None)')
    assert "securecode-python-cwe476" not in rules('request.args.get("host", "")')
    assert "securecode-python-cwe476" not in rules('request.args.get("host", default="")')


def test_report_takes_the_scanner_location_and_explains_indeterminate() -> None:
    document = _document()
    findings = document["findings"]
    assert isinstance(findings, list)
    line_one = dict(findings[0]["locations"][0], start={"line": 1}, end={"line": 1})
    model = dict(findings[0], locations=[line_one])
    scanner = dict(findings[0], finding_id="finding-3", candidate_origin="deterministic")
    document["findings"] = [model, scanner]
    document["outcome"] = "INDETERMINATE"
    context = TrialReportContext(Path("repo"), "c" * 40, "deepseek", "deepseek-flash", 0, {})

    markdown = render_trial_report(document, context, [], html_format=False).decode()

    assert "app.py:5" in markdown and "app.py:1 " not in markdown
    assert "сканер + модель" in markdown
    assert "не все этапы проверки завершены" in markdown
    assert "Этапы проверки:** есть незавершённые" in markdown
