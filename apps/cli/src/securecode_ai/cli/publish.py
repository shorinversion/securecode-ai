"""``securecode publish github``: post an ``analyze`` JSON report into a pull request."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, TextIO

from securecode_ai.adapters.github_api import GitHubApi, GitHubError
from securecode_ai.adapters.github_publish import (
    MAX_INLINE_DEFAULT,
    build_publication,
    publish,
)

_EXIT_CONFIG: Final = 4
_MAX_REPORT_BYTES: Final = 16 * 1024 * 1024
_REPOSITORY: Final = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]{0,99})/([A-Za-z0-9._-]{1,100})\Z")
_ENVIRONMENT_NAME: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")


class _Token:
    """The token of the CI job; the GitHub client asks for it per request."""

    def __init__(self, value: str) -> None:
        self._value = value

    def token(self, installation_id: str) -> str:
        return self._value


def publish_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securecode publish",
        description=(
            "Post the findings of a `securecode analyze --format json` report into a GitHub "
            "pull request: one summary comment kept up to date and one inline comment per "
            "new confirmed weakness, with a `suggestion` block for a single-hunk validated fix."
        ),
        epilog="exit codes: 0 posted (or dry run); 4 invalid arguments, report or token",
    )
    parser.add_argument("target", choices=("github",), help="where to publish")
    parser.add_argument("--report", required=True, help="the JSON report of `securecode analyze`")
    parser.add_argument("--repo", required=True, help="owner/name of the repository")
    parser.add_argument("--pr", required=True, type=int, help="pull request number")
    parser.add_argument(
        "--token-env",
        default="GITHUB_TOKEN",
        help="environment variable holding the token (default GITHUB_TOKEN)",
    )
    parser.add_argument("--max-inline", type=int, default=MAX_INLINE_DEFAULT)
    parser.add_argument(
        "--api-url", default="https://api.github.com", help="GitHub API root (Enterprise Server)"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print the comments instead of posting them"
    )
    return parser


def run_publish_command(
    tokens: Sequence[str],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    try:
        arguments = publish_parser().parse_args(list(tokens[1:]))
    except SystemExit as exit_request:
        return int(exit_request.code or 0)
    match = _REPOSITORY.fullmatch(arguments.repo)
    if match is None or arguments.pr < 1 or not 0 <= arguments.max_inline <= 50:
        stderr.write("securecode publish: --repo owner/name, --pr N and --max-inline 0..50\n")
        return _EXIT_CONFIG
    try:
        report = _read_report(Path(arguments.report))
    except ValueError as error:
        stderr.write(f"securecode publish: {error}\n")
        return _EXIT_CONFIG
    publication = build_publication(report, max_inline=arguments.max_inline)
    if arguments.dry_run:
        stdout.write(
            json.dumps(
                {
                    "repository": arguments.repo,
                    "pull_request": arguments.pr,
                    "summary": publication.summary,
                    "inline": [
                        {
                            "path": item.path,
                            "line": item.line,
                            "start_line": item.start_line,
                            "body": item.body,
                        }
                        for item in publication.inline
                    ],
                    "over_limit": publication.over_limit,
                    "known": publication.known,
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        )
        return 0
    name = arguments.token_env
    token = environment.get(name, "") if _ENVIRONMENT_NAME.fullmatch(name) else ""
    if not token:
        stderr.write(f"securecode publish: the token variable {name} is not set\n")
        return _EXIT_CONFIG
    try:
        result = publish(
            GitHubApi(arguments.api_url, _Token(token)),
            match.group(1),
            match.group(2),
            arguments.pr,
            publication,
        )
    except (GitHubError, ValueError) as error:
        # The code only: a response or a request must never reach the log with the token.
        code = error.code if isinstance(error, GitHubError) else "INVALID_API_URL"
        stderr.write(f"securecode publish: GITHUB_API_FAILED ({code})\n")
        return _EXIT_CONFIG
    stderr.write(
        f"securecode publish: summary {result.summary}; inline written {len(result.written)}, "
        f"already there {len(result.existing)}, outside the diff {len(result.not_in_diff)}\n"
    )
    return 0


def _read_report(path: Path) -> dict[str, object]:
    try:
        raw = path.read_bytes()
    except OSError:
        raise ValueError("the report cannot be read") from None
    if len(raw) > _MAX_REPORT_BYTES:
        raise ValueError("the report is larger than 16 MiB")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise ValueError("the report is not valid JSON (use --format json)") from None
    if not isinstance(document, dict) or not isinstance(document.get("findings"), list):
        raise ValueError("the report is not a securecode analyze JSON report")
    return document


__all__ = ["publish_parser", "run_publish_command"]
