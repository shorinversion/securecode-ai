"""`securecode publish github` against a loopback server that speaks the GitHub REST API."""

from __future__ import annotations

import io
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from securecode_ai.cli.publish import run_publish_command

HEAD = "d" * 40
DIFF = (
    "--- a/app.py\n+++ b/app.py\n@@ -5,2 +5,2 @@\n def find(conn, name):\n"
    '-    return conn.execute("SELECT " + name)\n+    return conn.execute("SELECT ?", (name,))\n'
)


class State:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict[str, object] | None, str]] = []
        self.issue_comments: list[dict[str, object]] = []
        self.review_comments: list[dict[str, object]] = []
        self.refuse_path: str | None = None


@contextmanager
def github(state: State) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def _answer(self, status: int, document: object) -> None:
            body = json.dumps(document).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _handle(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            document = json.loads(self.rfile.read(length)) if length else None
            path = self.path.split("?")[0]
            state.requests.append((method, path, document, self.headers.get("Authorization", "")))
            if method == "GET" and path == "/repos/acme/demo/pulls/7":
                self._answer(200, {"head": {"sha": HEAD}})
            elif method == "GET" and path.endswith("/issues/7/comments"):
                self._answer(200, state.issue_comments)
            elif method == "GET" and path.endswith("/pulls/7/comments"):
                self._answer(200, state.review_comments)
            elif method == "POST" and path.endswith("/pulls/7/comments"):
                assert document is not None
                if state.refuse_path == document["path"]:
                    self._answer(422, {"message": "line is not part of the diff"})
                    return
                comment = {"id": 100 + len(state.review_comments), "body": document["body"]}
                state.review_comments.append(comment)
                self._answer(201, comment)
            elif method == "POST" and path.endswith("/issues/7/comments"):
                assert document is not None
                comment = {"id": 50, "body": document["body"]}
                state.issue_comments.append(comment)
                self._answer(201, comment)
            elif method == "PATCH" and "/issues/comments/" in path:
                assert document is not None
                state.issue_comments[0]["body"] = document["body"]
                self._answer(200, state.issue_comments[0])
            else:
                self._answer(404, {"message": "unexpected request"})

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

        def do_PATCH(self) -> None:
            self._handle("PATCH")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _report(path: Path) -> Path:
    def finding(
        finding_id: str, cwe: str, file: str, line: int, diff: str | None
    ) -> dict[str, object]:
        return {
            "finding_id": finding_id,
            "cwe_id": cwe,
            "verdict": "CONFIRMED",
            "severity": "HIGH",
            "candidate_origin": "deterministic",
            "locations": [{"path": file, "start": {"line": line}, "end": {"line": line}}],
            "patch_refs": []
            if diff is None
            else [{"path": file, "status": "VALIDATED", "explanation": "x", "diff": diff}],
        }

    path.write_text(
        json.dumps(
            {
                "outcome": "FAIL",
                "findings": [
                    finding("a", "CWE-89", "app.py", 6, DIFF),
                    finding("b", "CWE-798", "cfg.py", 3, None),
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _publish(url: str, report: Path) -> tuple[int, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    code = run_publish_command(
        (
            "publish",
            "github",
            "--report",
            str(report),
            "--repo",
            "acme/demo",
            "--pr",
            "7",
            "--api-url",
            url,
        ),
        stdout=stdout,
        stderr=stderr,
        environment={"GITHUB_TOKEN": "ghs_loopback_token"},
    )
    return code, stderr.getvalue()


def test_publish_posts_once_and_a_rerun_posts_nothing(tmp_path: Path) -> None:
    state = State()
    report = _report(tmp_path / "report.json")
    with github(state) as url:
        first, first_log = _publish(url, report)
        posted = len([item for item in state.requests if item[0] in {"POST", "PATCH"}])
        second, second_log = _publish(url, report)

    assert first == 0 and "summary created" in first_log and "inline written 2" in first_log
    assert posted == 3  # the summary and two inline comments
    assert second == 0 and "summary unchanged" in second_log and "already there 2" in second_log
    assert len([item for item in state.requests if item[0] in {"POST", "PATCH"}]) == posted
    assert {item[3] for item in state.requests} == {"Bearer ghs_loopback_token"}
    inline = [
        item[2]
        for item in state.requests
        if item[0] == "POST" and item[1].endswith("/pulls/7/comments")
    ]
    assert {doc["commit_id"] for doc in inline if doc} == {HEAD}
    assert any("```suggestion" in str(doc["body"]) for doc in inline if doc)
    assert "ghs_loopback_token" not in first_log + second_log


def test_a_comment_outside_the_diff_does_not_fail_the_publication(tmp_path: Path) -> None:
    state = State()
    state.refuse_path = "cfg.py"
    with github(state) as url:
        code, log = _publish(url, _report(tmp_path / "report.json"))

    assert code == 0 and "inline written 1" in log and "outside the diff 1" in log


def test_a_server_error_is_reported_by_code_only(tmp_path: Path) -> None:
    state = State()
    with github(state) as url:
        # Nothing is registered for this pull request number's repository: the server answers 404.
        stdout, stderr = io.StringIO(), io.StringIO()
        code = run_publish_command(
            (
                "publish",
                "github",
                "--report",
                str(_report(tmp_path / "report.json")),
                "--repo",
                "acme/unknown",
                "--pr",
                "7",
                "--api-url",
                url,
            ),
            stdout=stdout,
            stderr=stderr,
            environment={"GITHUB_TOKEN": "ghs_loopback_token"},
        )

    assert code == 4 and "GITHUB_API_FAILED (HTTP_404)" in stderr.getvalue()
    assert "ghs_loopback_token" not in stderr.getvalue()
