"""A baseline of known findings: format, matching, expiry and the exit code."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from securecode_ai.adapters import trial_unresolved
from securecode_ai.adapters.trial_baseline import (
    Baseline,
    BaselineApplication,
    BaselineEntry,
    BaselineError,
    apply_baseline,
    baseline_document,
    effective_exit,
    load_baseline,
)
from securecode_ai.adapters.trial_groups import finding_groups
from securecode_ai.adapters.trial_report import TrialReportContext, render_trial_report
from securecode_ai.cli import analyze

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)


def _finding(finding_id: str, cwe: str, path: str, line: int, verdict: str = "CONFIRMED") -> Any:
    return {
        "finding_id": finding_id,
        "cwe_id": cwe,
        "verdict": verdict,
        "severity": "HIGH",
        "owasp_category": "A03:2021",
        "candidate_origin": "deterministic",
        "locations": [{"path": path, "start": {"line": line}, "end": {"line": line}}],
        "patch_refs": [],
        "validation_refs": [],
    }


FINDINGS = [
    _finding("f1", "CWE-89", "app.py", 5),
    _finding("f2", "CWE-798", "app.py", 10),
    _finding("f3", "CWE-798", "app.py", 12),
    _finding("f4", "CWE-79", "web.py", 3, verdict="NEEDS_MORE_EVIDENCE"),
]


def _groups() -> list[str | None]:
    return finding_groups(FINDINGS)


def _write(path: Path, *, groups: list[str], expires: str | None = None) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema": "securecode-baseline/v1",
                "created": "2026-10-01T00:00:00+00:00",
                "head_sha": "a" * 40,
                "weaknesses": [
                    {
                        "weakness_group": group,
                        "cwe_id": "CWE-798",
                        "path": "app.py",
                        "reason": "accepted",
                        "expires": expires,
                    }
                    for group in groups
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_known_groups_are_suppressed_and_the_rest_is_new(tmp_path: Path) -> None:
    groups = _groups()
    known = [group for group in groups[:2] if group]
    baseline = load_baseline(_write(tmp_path / "b.json", groups=known))

    application = apply_baseline(FINDINGS, baseline, now=NOW)

    assert set(application.suppressed) == set(known)
    assert application.suppressed[known[0]] == ("accepted", "2026-10-01T00:00:00+00:00")
    assert application.new_groups == {groups[2]}  # the second credential is not in the file
    assert application.expired == ()


def test_only_confirmed_findings_count(tmp_path: Path) -> None:
    baseline = load_baseline(_write(tmp_path / "b.json", groups=[]))

    application = apply_baseline(FINDINGS, baseline, now=NOW)

    assert len(application.new_groups) == 3  # CWE-79 is not confirmed


def test_an_expired_entry_is_ignored_and_reported(tmp_path: Path) -> None:
    group = _groups()[0]
    assert group is not None
    baseline = load_baseline(_write(tmp_path / "b.json", groups=[group], expires="2026-10-15"))

    application = apply_baseline(FINDINGS, baseline, now=NOW)

    assert application.suppressed == {} and group in application.new_groups
    assert [entry.weakness_group for entry in application.expired] == [group]
    still = load_baseline(_write(tmp_path / "c.json", groups=[group], expires="2026-10-17"))
    assert apply_baseline(FINDINGS, still, now=NOW).suppressed.keys() == {group}


def test_written_baseline_holds_each_confirmed_group_once() -> None:
    document = json.loads(baseline_document(FINDINGS + FINDINGS[:1], "b" * 40, now=NOW))

    assert document["schema"] == "securecode-baseline/v1" and document["head_sha"] == "b" * 40
    assert document["created"] == "2026-10-16T12:00:00+00:00"
    assert sorted(item["cwe_id"] for item in document["weaknesses"]) == [
        "CWE-798",
        "CWE-798",
        "CWE-89",
    ]
    assert {item["reason"] for item in document["weaknesses"]} == {"accepted"}
    assert all(item["expires"] is None for item in document["weaknesses"])


def test_a_written_baseline_reads_back_and_suppresses_its_own_run(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_bytes(baseline_document(FINDINGS, "b" * 40, now=NOW))

    application = apply_baseline(FINDINGS, load_baseline(path), now=NOW)

    assert len(application.suppressed) == 3 and application.new_groups == frozenset()


@pytest.mark.parametrize(
    "content",
    [
        b"not json",
        b"[]",
        json.dumps({"schema": "other/v1"}).encode(),
        json.dumps({"schema": "securecode-baseline/v1", "created": "x"}).encode(),
        json.dumps(
            {"schema": "securecode-baseline/v1", "created": "x", "weaknesses": ["no"]}
        ).encode(),
        json.dumps(
            {
                "schema": "securecode-baseline/v1",
                "created": "x",
                "weaknesses": [
                    {"weakness_group": "bad", "cwe_id": "CWE-1", "path": "a", "reason": "accepted"}
                ],
            }
        ).encode(),
        json.dumps(
            {
                "schema": "securecode-baseline/v1",
                "created": "x",
                "weaknesses": [
                    {
                        "weakness_group": "weakness-" + "a" * 32,
                        "cwe_id": "CWE-1",
                        "path": "a",
                        "reason": "because",
                    }
                ],
            }
        ).encode(),
    ],
)
def test_an_invalid_file_is_an_error(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "b.json"
    path.write_bytes(content)

    with pytest.raises(BaselineError):
        load_baseline(path)


def test_a_missing_file_and_a_repeated_group_are_errors(tmp_path: Path) -> None:
    with pytest.raises(BaselineError, match="cannot be read"):
        load_baseline(tmp_path / "missing.json")
    group = "weakness-" + "a" * 32
    with pytest.raises(BaselineError, match="twice"):
        load_baseline(_write(tmp_path / "b.json", groups=[group, group]))


def _application(*, suppressed: int, new: int) -> BaselineApplication:
    return BaselineApplication(
        {f"g{n}": ("accepted", "2026-10-01") for n in range(suppressed)},
        (),
        frozenset(f"n{n}" for n in range(new)),
    )


@pytest.mark.parametrize(
    ("core", "suppressed", "new", "complete", "undecided", "expected"),
    [
        (2, 2, 0, True, 0, 0),  # everything confirmed is known and nothing is open: PASS
        (2, 2, 0, False, 0, 3),  # known findings, but a stage did not complete
        (2, 2, 0, True, 1, 3),  # known findings, but a candidate is undecided
        (2, 1, 1, True, 0, 2),  # a new confirmed weakness
        (2, 0, 1, True, 0, 2),  # no known finding at all: unchanged
        (0, 0, 0, True, 0, 0),
        (3, 1, 0, True, 0, 3),
    ],
)
def test_exit_code_is_two_only_for_a_weakness_the_baseline_does_not_know(
    core: int, suppressed: int, new: int, complete: bool, undecided: int, expected: int
) -> None:
    application = _application(suppressed=suppressed, new=new)

    assert effective_exit(core, application, complete=complete, undecided=undecided) == expected


def test_readable_report_lists_known_findings_in_their_own_section() -> None:
    context = TrialReportContext(
        Path("repo"),
        "a" * 40,
        "local",
        "qwen",
        0,
        {},
        known=(("CWE-798", "app.py", 10, "accepted", "2026-10-01"),),
        effective_outcome="PASS",
    )
    document: dict[str, object] = {"outcome": "FAIL", "findings": []}

    markdown = render_trial_report(document, context, (), html_format=False).decode()
    html = render_trial_report(document, context, (), html_format=True).decode()

    assert "<details><summary>Известные находки (1)</summary>" in markdown
    assert "принято командой" in markdown and "app.py:10" in markdown
    assert "<details><summary>Известные находки (1)</summary>" in html
    assert "Итог:** " in markdown and "FAIL" not in markdown.split("Известные")[0]


# --- the CLI ---------------------------------------------------------------------------------


def _analysis(*, exit_code: int = 2, complete: bool = True) -> Any:
    report = {
        "outcome": "FAIL" if exit_code == 2 else "PASS",
        "repository_revision": {"head_sha": "a" * 40},
        "coverage_manifest": {"coverage_complete": complete, "units": []},
        "findings": FINDINGS,
    }
    return SimpleNamespace(
        provider="local",
        model_id="qwen",
        cost_microusd=0,
        result=SimpleNamespace(
            rendered=json.dumps(report).encode(),
            sarif_rendered=b'{"runs":[{"results":[]}]}',
            exit_code=exit_code,
            scope=None,
            composition=SimpleNamespace(
                json_report=json.dumps(report).encode(), host_inputs=None, report=None
            ),
        ),
    )


def _run(
    monkeypatch: pytest.MonkeyPatch, *arguments: str, analysis: Any | None = None
) -> tuple[int, str, str]:
    monkeypatch.setattr(analyze, "run_trial_analysis", lambda *a, **k: analysis or _analysis())
    monkeypatch.setattr(analyze, "unresolved_report", lambda composition: ((), ()))
    monkeypatch.setattr(trial_unresolved, "unresolved_report", lambda composition: ((), ()))
    monkeypatch.setattr(analyze, "finding_decisions", lambda composition: {})
    stdout, stderr = io.StringIO(), io.StringIO()
    code = analyze.run_analyze_command(
        ("analyze", ".", "--format", "json", "--no-fix", *arguments),
        stdout=stdout,
        stderr=stderr,
        environment={},
    )
    return code, stdout.getvalue(), stderr.getvalue()


def _known_baseline(tmp_path: Path, count: int) -> Path:
    groups = [group for group in _groups() if group][:count]
    return _write(tmp_path / "known.json", groups=groups)


def test_a_fully_known_run_passes_and_keeps_the_core_outcome(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, out, err = _run(monkeypatch, "--baseline", str(_known_baseline(tmp_path, 3)))

    document = json.loads(out)
    assert code == 0
    assert document["outcome"] == "FAIL" and document["effective_outcome"] == "PASS"
    assert [bool(item.get("suppressed")) for item in document["findings"]] == [
        True,
        True,
        True,
        False,
    ]
    assert document["findings"][0]["suppressed"] == {
        "reason": "accepted",
        "since": "2026-10-01T00:00:00+00:00",
    }
    assert (
        document["baseline"]["known_findings"] == 3 and document["baseline"]["new_weaknesses"] == 0
    )
    assert "outcome=PASS" in err and "3 known weakness group(s)" in err


def test_one_new_weakness_still_fails_the_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, out, err = _run(monkeypatch, "--baseline", str(_known_baseline(tmp_path, 2)))

    assert code == 2
    assert json.loads(out)["effective_outcome"] == "FAIL"
    assert "1 new" in err


def test_known_findings_with_an_unfinished_stage_are_indeterminate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, out, _ = _run(
        monkeypatch,
        "--baseline",
        str(_known_baseline(tmp_path, 3)),
        analysis=_analysis(complete=False),
    )

    assert code == 3 and json.loads(out)["effective_outcome"] == "INDETERMINATE"


def test_an_invalid_baseline_stops_the_run_before_any_model_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{}", encoding="utf-8")
    called: list[object] = []
    monkeypatch.setattr(analyze, "run_trial_analysis", lambda *a, **k: called.append(1))

    stdout, stderr = io.StringIO(), io.StringIO()
    code = analyze.run_analyze_command(
        ("analyze", ".", "--baseline", str(broken)), stdout=stdout, stderr=stderr, environment={}
    )

    assert code == 4 and called == [] and "baseline schema" in stderr.getvalue()


def test_write_baseline_creates_a_file_that_makes_the_next_run_pass(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "new-baseline.json"

    code, _out, err = _run(monkeypatch, "--write-baseline", str(target))
    second, out, _ = _run(monkeypatch, "--baseline", str(target))

    assert code == 2 and "baseline written" in err
    assert second == 0 and json.loads(out)["effective_outcome"] == "PASS"
    stdout, stderr = io.StringIO(), io.StringIO()
    again = analyze.run_analyze_command(
        ("analyze", ".", "--write-baseline", str(target)),
        stdout=stdout,
        stderr=stderr,
        environment={},
    )
    assert again == 4 and "already exists" in stderr.getvalue()


def test_sarif_marks_known_results_as_externally_suppressed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from securecode_ai.adapters.trial_fix_export import attach_baseline_to_sarif

    groups = _groups()
    results = [{"ruleId": item["cwe_id"], "locations": []} for item in FINDINGS]
    sarif = json.dumps({"runs": [{"results": results}]}).encode()
    report = json.dumps({"findings": FINDINGS}).encode()
    known = {group: ("false_positive", "2026-10-01") for group in groups[:1] if group}

    document = json.loads(attach_baseline_to_sarif(sarif, report, known))

    first, *rest = document["runs"][0]["results"]
    assert first["suppressions"] == [
        {"kind": "external", "justification": "baseline: false_positive (since 2026-10-01)"}
    ]
    assert all("suppressions" not in item for item in rest)


def test_entries_and_baseline_are_plain_values() -> None:
    entry = BaselineEntry("weakness-" + "a" * 32, "CWE-89", "a.py", "accepted", None)

    assert Baseline("now", "a" * 40, (entry,)).entries == (entry,)
