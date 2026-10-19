# ruff: noqa: RUF001 - the comments under test are written in Russian
"""`securecode publish github`: comment bodies, markers, limits, suggestions, reconciliation."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any, cast

import pytest
from securecode_ai.adapters.github_api import GitHubApi, GitHubError, GitHubResponse
from securecode_ai.adapters.github_publish import (
    INLINE_MARKER,
    SUMMARY_MARKER,
    build_publication,
    publish,
)
from securecode_ai.adapters.trial_groups import finding_groups
from securecode_ai.cli import publish as publish_cli

HEAD = "c" * 40
ONE_HUNK = (
    "--- a/app.py\n+++ b/app.py\n@@ -5,2 +5,3 @@\n"
    ' def find(conn, name):\n-    return conn.execute("SELECT " + name)\n'
    '+    query = "SELECT ?"\n+    return conn.execute(query, (name,))\n'
)
TWO_HUNKS = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-a\n+b\n@@ -40 +40 @@\n-c\n+d\n"
FAR_HUNK = "--- a/app.py\n+++ b/app.py\n@@ -200 +200 @@\n-c\n+d\n"


def _finding(
    finding_id: str,
    cwe: str,
    path: str,
    line: int,
    *,
    verdict: str = "CONFIRMED",
    origin: str = "deterministic",
    severity: str = "HIGH",
    diff: str | None = None,
    suppressed: bool = False,
    status: str = "VALIDATED",
) -> dict[str, object]:
    item: dict[str, object] = {
        "finding_id": finding_id,
        "cwe_id": cwe,
        "verdict": verdict,
        "severity": severity,
        "owasp_category": "A03:2021",
        "candidate_origin": origin,
        "locations": [{"path": path, "start": {"line": line}, "end": {"line": line}}],
        "patch_refs": [],
    }
    if diff is not None:
        item["patch_refs"] = [
            {
                "path": path,
                "status": status,
                "explanation": "Параметризованный запрос.",
                "diff": diff,
            }
        ]
    if suppressed:
        item["suppressed"] = {"reason": "accepted", "since": "2026-10-01"}
    return item


def _report(*findings: dict[str, object], **extra: object) -> dict[str, object]:
    return {
        "outcome": "FAIL",
        "repository_revision": {"head_sha": "a" * 40},
        "findings": list(findings),
        **extra,
    }


def test_one_inline_comment_per_new_confirmed_weakness_group() -> None:
    report = _report(
        _finding("model", "CWE-89", "app.py", 7, origin="model_native"),
        _finding("scanner", "CWE-89", "app.py", 6),
        _finding("key-a", "CWE-798", "cfg.py", 3, severity="CRITICAL"),
        _finding("key-b", "CWE-798", "cfg.py", 4),
        _finding("maybe", "CWE-79", "web.py", 2, verdict="NEEDS_MORE_EVIDENCE"),
    )

    publication = build_publication(report, max_inline=20)

    assert [(item.path, item.line) for item in publication.inline] == [
        ("cfg.py", 3),
        ("app.py", 6),
        ("cfg.py", 4),
    ]  # critical first, then by place; the scanner line represents the CWE-89 group
    for item in publication.inline:
        assert item.body.endswith(" -->") and INLINE_MARKER + item.group in item.body
    groups = finding_groups(cast(Any, report["findings"]))
    assert {item.group for item in publication.inline} == {groups[1], groups[2], groups[3]}
    assert "Новых подтверждённых слабостей: 3" in publication.summary
    assert "| CRITICAL | CWE-798 | `cfg.py:3` |" in publication.summary


def test_known_findings_are_counted_but_not_posted() -> None:
    report = _report(
        _finding("known", "CWE-89", "app.py", 6, suppressed=True),
        _finding("new", "CWE-78", "run.py", 9),
        effective_outcome="FAIL",
    )

    publication = build_publication(report, max_inline=20)

    assert [item.path for item in publication.inline] == ["run.py"]
    assert publication.known == 1 and "известных по baseline: 1" in publication.summary


def test_the_inline_limit_cuts_the_comments_and_names_the_rest_in_the_summary() -> None:
    report = _report(
        *(_finding(f"k{n}", "CWE-798", "cfg.py", n + 1) for n in range(5)),
    )

    publication = build_publication(report, max_inline=2)

    assert len(publication.inline) == 2 and publication.over_limit == 3
    assert "Ещё 3 слабост" in publication.summary
    assert build_publication(report, max_inline=0).inline == ()


def test_suggestion_only_for_one_validated_hunk_near_the_comment() -> None:
    def comment(diff: str | None, status: str = "VALIDATED", line: int = 6) -> str:
        return (
            build_publication(
                _report(_finding("f", "CWE-89", "app.py", line, diff=diff, status=status)),
                max_inline=5,
            )
            .inline[0]
            .body
        )

    single = comment(ONE_HUNK)
    assert "```suggestion" in single and 'query = "SELECT ?"' in single
    assert "Параметризованный запрос." in single
    assert "```suggestion" not in comment(TWO_HUNKS)
    assert "```suggestion" not in comment(FAR_HUNK)
    assert "```suggestion" not in comment(ONE_HUNK, status="NOT_VALIDATED")
    assert "```suggestion" not in comment(None)
    assert "```suggestion" not in comment(ONE_HUNK, line=300)


def test_suggestion_replaces_the_old_lines_of_the_hunk() -> None:
    item = build_publication(
        _report(_finding("f", "CWE-89", "app.py", 6, diff=ONE_HUNK)), max_inline=5
    ).inline[0]

    assert (item.start_line, item.line) == (5, 6)
    block = item.body.split("```suggestion\n")[1].split("\n```")[0]
    assert block.splitlines() == [
        "def find(conn, name):",
        '    query = "SELECT ?"',
        "    return conn.execute(query, (name,))",
    ]


def test_the_summary_names_the_scope_and_an_unfinished_run() -> None:
    report = _report(
        outcome="INDETERMINATE",
        scope={"kind": "changed_since_base", "base_sha": "b" * 40, "scanned_paths": ["a.py"]},
    )

    summary = build_publication(report, max_inline=5).summary

    assert "Итог: INDETERMINATE" in summary
    assert "изменённые с `bbbbbbbbbbbb` (1 шт.)" in summary
    assert "не «уязвимостей нет»" in summary


# --- the GitHub conversation -------------------------------------------------------------


class FakeApi:
    def __init__(
        self,
        *,
        head: str = HEAD,
        issue_comments: list[dict[str, object]] | None = None,
        review_comments: list[dict[str, object]] | None = None,
        refuse: set[str] | None = None,
        fail: str | None = None,
    ) -> None:
        self.head = head
        self.issue_comments = issue_comments or []
        self.review_comments = review_comments or []
        self.refuse = refuse or set()
        self.fail = fail
        self.calls: list[tuple[str, str, dict[str, object] | None]] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        installation_id: str,
        document: dict[str, object] | None = None,
        idempotency_key: str | None = None,
    ) -> GitHubResponse:
        self.calls.append((method, path, document))
        if self.fail is not None:
            raise GitHubError(self.fail)
        base = "/repos/acme/demo"
        if method == "GET" and path == f"{base}/pulls/7":
            return GitHubResponse(200, {"head": {"sha": self.head}}, {})
        if method == "GET" and "/issues/7/comments" in path:
            return GitHubResponse(200, list(self.issue_comments), {})
        if method == "GET" and "/pulls/7/comments" in path:
            return GitHubResponse(200, list(self.review_comments), {})
        if method == "POST" and path == f"{base}/pulls/7/comments":
            assert document is not None
            if any(marker in str(document["body"]) for marker in self.refuse):
                raise GitHubError("HTTP_422")
            return GitHubResponse(201, {"id": 1}, {})
        if method in {"POST", "PATCH"}:
            return GitHubResponse(201, {"id": 5}, {})
        raise AssertionError((method, path))


def _publication() -> Any:
    return build_publication(
        _report(
            _finding("a", "CWE-89", "app.py", 6, diff=ONE_HUNK),
            _finding("b", "CWE-798", "cfg.py", 3),
        ),
        max_inline=20,
    )


def test_a_first_run_creates_the_summary_and_the_inline_comments() -> None:
    api = FakeApi()

    result = publish(cast(GitHubApi, api), "acme", "demo", 7, _publication())

    assert result.summary == "created" and len(result.written) == 2 and result.existing == ()
    posts = [(path, doc) for method, path, doc in api.calls if method == "POST"]
    assert posts[0][0] == "/repos/acme/demo/issues/7/comments"
    assert str(posts[0][1]["body"]).endswith(SUMMARY_MARKER)  # type: ignore[index]
    inline = [doc for path, doc in posts[1:] if doc is not None]
    assert {doc["commit_id"] for doc in inline} == {HEAD}
    assert all(doc["side"] == "RIGHT" for doc in inline)
    assert any("start_line" in doc for doc in inline)  # the suggestion spans two lines


def test_a_second_run_updates_nothing_when_nothing_changed() -> None:
    publication = _publication()
    first = FakeApi()
    publish(cast(GitHubApi, first), "acme", "demo", 7, publication)
    summary = next(
        doc for method, path, doc in first.calls if method == "POST" and "issues" in path
    )
    inline = [doc for method, path, doc in first.calls if method == "POST" and "pulls" in path]
    second = FakeApi(
        issue_comments=[{"id": 11, "body": summary["body"]}],  # type: ignore[index]
        review_comments=[
            {"id": 21 + n, "body": doc["body"]} for n, doc in enumerate(inline) if doc
        ],
    )

    result = publish(cast(GitHubApi, second), "acme", "demo", 7, publication)

    assert result.summary == "unchanged" and result.written == ()
    assert len(result.existing) == 2
    assert [call for call in second.calls if call[0] in {"POST", "PATCH"}] == []


def test_a_changed_summary_is_updated_in_place() -> None:
    api = FakeApi(issue_comments=[{"id": 11, "body": "old text\n\n" + SUMMARY_MARKER}])

    result = publish(cast(GitHubApi, api), "acme", "demo", 7, _publication())

    assert result.summary == "updated"
    assert [path for method, path, _ in api.calls if method == "PATCH"] == [
        "/repos/acme/demo/issues/comments/11"
    ]


def test_a_line_outside_the_diff_is_reported_not_fatal() -> None:
    publication = _publication()
    refused = {INLINE_MARKER + publication.inline[0].group}
    api = FakeApi(refuse=refused)

    result = publish(cast(GitHubApi, api), "acme", "demo", 7, publication)

    assert result.not_in_diff == (publication.inline[0].group,)
    assert len(result.written) == 1


@pytest.mark.parametrize("code", ["HTTP_401", "HTTP_500", "TRANSPORT"])
def test_other_api_failures_stop_the_publication(code: str) -> None:
    with pytest.raises(GitHubError) as error:
        publish(cast(GitHubApi, FakeApi(fail=code)), "acme", "demo", 7, _publication())

    assert error.value.code == code


def test_a_pull_request_without_a_valid_head_is_refused() -> None:
    with pytest.raises(GitHubError) as error:
        publish(cast(GitHubApi, FakeApi(head="not-a-sha")), "acme", "demo", 7, _publication())

    assert error.value.code == "PULL_REQUEST_HEAD_INVALID"


def test_two_summary_comments_are_a_conflict_not_a_guess() -> None:
    body = "x\n\n" + SUMMARY_MARKER
    api = FakeApi(issue_comments=[{"id": 1, "body": body}, {"id": 2, "body": body}])

    with pytest.raises(GitHubError) as error:
        publish(cast(GitHubApi, api), "acme", "demo", 7, _publication())

    assert error.value.code == "SUMMARY_RECONCILIATION_CONFLICT"


# --- the command ---------------------------------------------------------------------------


def _run(
    tmp_path: Path,
    *arguments: str,
    environment: dict[str, str] | None = None,
    report: str | None = None,
) -> tuple[int, str, str]:
    path = tmp_path / "report.json"
    path.write_text(
        report
        if report is not None
        else json.dumps(_report(_finding("a", "CWE-89", "app.py", 6, diff=ONE_HUNK))),
        encoding="utf-8",
    )
    stdout, stderr = io.StringIO(), io.StringIO()
    code = publish_cli.run_publish_command(
        ("publish", "github", "--report", str(path), *arguments),
        stdout=stdout,
        stderr=stderr,
        environment=environment or {},
    )
    return code, stdout.getvalue(), stderr.getvalue()


def test_dry_run_prints_the_comments_without_a_token_or_a_network(tmp_path: Path) -> None:
    code, out, err = _run(tmp_path, "--repo", "acme/demo", "--pr", "7", "--dry-run")

    document = json.loads(out)
    assert code == 0 and err == ""
    assert document["repository"] == "acme/demo" and document["pull_request"] == 7
    assert document["summary"].startswith("## SecureCode AI")
    assert (
        document["inline"][0]["path"] == "app.py"
        and "```suggestion" in document["inline"][0]["body"]
    )


@pytest.mark.parametrize(
    "arguments",
    [
        ("--repo", "not-a-repo", "--pr", "7", "--dry-run"),
        ("--repo", "acme/demo", "--pr", "0", "--dry-run"),
        ("--repo", "acme/demo", "--pr", "7", "--max-inline", "51", "--dry-run"),
        ("--repo", "../x/y", "--pr", "7"),
    ],
)
def test_bad_arguments_are_exit_four(tmp_path: Path, arguments: tuple[str, ...]) -> None:
    code, _out, err = _run(tmp_path, *arguments)

    assert code == 4 and "securecode publish" in err


def test_a_missing_token_is_exit_four_and_names_only_the_variable(tmp_path: Path) -> None:
    code, _out, err = _run(tmp_path, "--repo", "acme/demo", "--pr", "7")

    assert code == 4 and "GITHUB_TOKEN" in err


@pytest.mark.parametrize("report", ["not json", "[]", '{"outcome": "FAIL"}'])
def test_an_invalid_report_is_exit_four(tmp_path: Path, report: str) -> None:
    code, _out, err = _run(tmp_path, "--repo", "acme/demo", "--pr", "7", "--dry-run", report=report)

    assert code == 4 and "report" in err


def test_an_api_failure_prints_only_the_code_never_the_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(*arguments: object, **keywords: object) -> object:
        raise GitHubError("HTTP_401")

    monkeypatch.setattr(publish_cli, "publish", failing)

    code, _out, err = _run(
        tmp_path,
        "--repo",
        "acme/demo",
        "--pr",
        "7",
        environment={"GITHUB_TOKEN": "ghs_example_token_value"},
    )

    assert code == 4 and "GITHUB_API_FAILED (HTTP_401)" in err
    assert "ghs_example_token_value" not in err


def test_a_successful_run_reports_the_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from securecode_ai.adapters.github_publish import PublishResult

    monkeypatch.setattr(
        publish_cli, "publish", lambda *a, **k: PublishResult("created", ("g",), (), ())
    )

    code, _out, err = _run(
        tmp_path, "--repo", "acme/demo", "--pr", "7", environment={"GITHUB_TOKEN": "t0k3n"}
    )

    assert code == 0 and "summary created" in err and "inline written 1" in err
