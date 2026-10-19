# ruff: noqa: RUF001 - the comments are written in Russian
"""Publish the findings of a ``securecode analyze`` JSON report into a GitHub pull request.

The summary is one comment kept up to date by a marker; each confirmed weakness group that
the baseline does not know gets one inline comment, with a ``suggestion`` block when its
validated fix is a single hunk close to the comment. Bodies are built without any network
(``build_publication``) so a dry run prints exactly what would be posted; ``publish`` talks to
the GitHub REST API through the same bounded client the GitHub App adapter uses.

Comments carry fixed texts, locations and the validated fix only: no model output and no
source beyond the replacement lines of that fix, which the reviewer sees in the diff anyway.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from .github_api import GitHubApi, GitHubError, repository_path
from .trial_groups import finding_groups
from .trial_report import CWE_NAMES, OWASP_2021

SUMMARY_MARKER: Final = "<!-- securecode-ai-summary:cli -->"
INLINE_MARKER: Final = "securecode-ai-inline:"
MAX_INLINE_DEFAULT: Final = 20
_NEAR_LINES: Final = 60
_HUNK: Final = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_MAX_PAGES: Final = 10
_PER_PAGE: Final = 100
_OUTCOMES: Final = {"PASS": "PASS", "FAIL": "FAIL", "INDETERMINATE": "INDETERMINATE"}
_SEVERITY_ORDER: Final = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@dataclass(frozen=True, slots=True)
class InlineComment:
    group: str
    path: str
    line: int
    start_line: int | None
    body: str


@dataclass(frozen=True, slots=True)
class Publication:
    summary: str
    inline: tuple[InlineComment, ...]
    # Weakness groups beyond ``max_inline``: named in the summary only.
    over_limit: int
    known: int


@dataclass(frozen=True, slots=True)
class PublishResult:
    summary: str  # "created", "updated" or "unchanged"
    written: tuple[str, ...]
    existing: tuple[str, ...]
    not_in_diff: tuple[str, ...]


def build_publication(report: Mapping[str, object], *, max_inline: int) -> Publication:
    """The summary and the inline comments of a JSON report; pure and deterministic."""

    findings = [item for item in _list(report.get("findings")) if isinstance(item, dict)]
    groups = finding_groups(findings)
    chosen: dict[str, dict[str, object]] = {}
    known = 0
    seen_known: set[str] = set()
    for item, group in zip(findings, groups, strict=True):
        if item.get("verdict") != "CONFIRMED" or group is None:
            continue
        if item.get("suppressed"):
            if group not in seen_known:
                seen_known.add(group)
                known += 1
            continue
        current = chosen.get(group)
        if current is None or _preferred(item, current):
            chosen[group] = item
    ranked = sorted(
        chosen.items(),
        key=lambda pair: (_rank(str(pair[1].get("severity"))), *_place(pair[1])),
    )
    inline = tuple(_inline(group, item) for group, item in ranked[: max(0, max_inline)])
    over = max(0, len(ranked) - len(inline))
    return Publication(_summary(report, ranked, known, over), inline, over, known)


def _preferred(candidate: Mapping[str, object], current: Mapping[str, object]) -> bool:
    """The scanner lane carries the exact sink line; otherwise the narrower location wins."""

    def key(item: Mapping[str, object]) -> tuple[bool, int]:
        locations = _locations(item)
        width = min((end - start for _, start, end in locations), default=10_000)
        return (item.get("candidate_origin") != "deterministic", width)

    return key(candidate) < key(current)


def _locations(item: Mapping[str, object]) -> list[tuple[str, int, int]]:
    result: list[tuple[str, int, int]] = []
    for location in _list(item.get("locations")):
        if not isinstance(location, dict) or not isinstance(location.get("path"), str):
            continue
        start, end = _line(location.get("start")), _line(location.get("end"))
        result.append((str(location["path"]), start, max(start, end)))
    return result


def _line(point: object) -> int:
    line = point.get("line") if isinstance(point, dict) else None
    return line if isinstance(line, int) and line >= 1 else 1


def _place(item: Mapping[str, object]) -> tuple[str, int]:
    locations = _locations(item)
    return (locations[0][0], locations[0][1]) if locations else ("", 0)


def _rank(severity: str) -> int:
    return _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else len(_SEVERITY_ORDER)


def _list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _inline(group: str, item: Mapping[str, object]) -> InlineComment:
    locations = _locations(item)
    path, start, end = min(locations, key=lambda value: value[2] - value[1])
    cwe_id = str(item.get("cwe_id"))
    name = CWE_NAMES.get(cwe_id)
    owasp = str(item.get("owasp_category", ""))
    lines = [
        f"**SecureCode AI: {cwe_id}" + (f" {name}" if name else "") + "**"
        f" (критичность: {item.get('severity', '?')}"
        + (f"; OWASP {owasp} {OWASP_2021[owasp]}" if owasp in OWASP_2021 else "")
        + ")",
        "",
        "Слабость подтверждена Аудитором и Скептиком или детектором секретов; проверьте и исправьте.",
    ]
    comment_line, comment_start = end, (start if end > start else None)
    patch = _validated_patch(item, path)
    if patch is not None:
        suggestion = _suggestion(str(patch.get("diff", "")), line=start)
        if suggestion is not None:
            first, last, text = suggestion
            comment_start = first if last > first else None
            comment_line = last
            explanation = patch.get("explanation")
            if isinstance(explanation, str) and explanation:
                lines += ["", explanation]
            lines += ["", "```suggestion", text.rstrip("\n"), "```"]
    body = "\n".join(lines) + "\n\n<!-- " + INLINE_MARKER + group + " -->"
    return InlineComment(group, path, comment_line, comment_start, body)


def _validated_patch(item: Mapping[str, object], path: str) -> Mapping[str, object] | None:
    for patch in _list(item.get("patch_refs")):
        if (
            isinstance(patch, dict)
            and patch.get("status") == "VALIDATED"
            and patch.get("path") == path
            and isinstance(patch.get("diff"), str)
        ):
            return patch
    return None


def _suggestion(diff: str, *, line: int) -> tuple[int, int, str] | None:
    """(first line, last line, replacement) of a diff that is exactly one hunk near ``line``.

    GitHub replaces the commented lines with the suggestion, so the replacement is the new
    text of the hunk and the comment spans the old lines of the hunk.
    """

    hunks = [index for index, text in enumerate(diff.splitlines()) if text.startswith("@@")]
    if len(hunks) != 1:
        return None
    rows = diff.splitlines()
    match = _HUNK.match(rows[hunks[0]])
    if match is None:
        return None
    old_start = int(match.group(1))
    old_count = 1 if match.group(2) is None else int(match.group(2))
    if old_count == 0:
        return None  # a pure insertion has no line to attach the suggestion to
    old_end = old_start + old_count - 1
    if old_end < line - _NEAR_LINES or old_start > line + _NEAR_LINES:
        return None
    new: list[str] = []
    for row in rows[hunks[0] + 1 :]:
        if row.startswith(("+", " ")):
            new.append(row[1:])
        elif row.startswith("-") or row.startswith("\\"):
            continue
        else:
            return None
    return old_start, old_end, "\n".join(new)


def _summary(
    report: Mapping[str, object],
    ranked: Sequence[tuple[str, dict[str, object]]],
    known: int,
    over: int,
) -> str:
    outcome = str(report.get("effective_outcome") or report.get("outcome") or "?")
    scope = report.get("scope")
    revision = report.get("repository_revision")
    head = str(revision.get("head_sha", ""))[:12] if isinstance(revision, dict) else ""
    lines = [
        "## SecureCode AI",
        "",
        f"**Итог: {_OUTCOMES.get(outcome, outcome)}**"
        + (f" (ревизия `{head}`)" if head else "")
        + f". Новых подтверждённых слабостей: {len(ranked)}"
        + (f", известных по baseline: {known}" if known else "")
        + ".",
    ]
    if isinstance(scope, dict) and scope.get("kind") == "changed_since_base":
        paths = scope.get("scanned_paths")
        lines += [
            "",
            f"Область: файлы, изменённые с `{str(scope.get('base_sha', ''))[:12]}`"
            + (f" ({len(paths)} шт.)" if isinstance(paths, list) else "")
            + "; потоки в неизменённые файлы не проверялись.",
        ]
    if ranked:
        lines += ["", "| Критичность | Уязвимость | Место |", "| --- | --- | --- |"]
        for _group, item in ranked[:50]:
            path, line = _place(item)
            lines.append(
                f"| {item.get('severity', '?')} | {item.get('cwe_id')} | `{path}:{line}` |"
            )
    if over:
        lines += ["", f"Ещё {over} слабост(ей) не вынесено в комментарии к строкам (лимит)."]
    if outcome == "INDETERMINATE":
        lines += [
            "",
            "Часть этапов или кандидатов осталась без решения: это не «уязвимостей нет». "
            "Подробности — в отчёте прогона.",
        ]
    return "\n".join(lines)


def publish(
    api: GitHubApi,
    owner: str,
    repository: str,
    pull_request: int,
    publication: Publication,
) -> PublishResult:
    """Post the summary (created or updated in place) and the inline comments not posted yet.

    A comment on a line outside the pull-request diff is refused by GitHub (HTTP 422); it is
    reported, not fatal. Any other API failure raises ``GitHubError``.
    """

    base = repository_path(owner, repository)
    number = str(pull_request)
    pull = api.request("GET", f"{base}/pulls/{number}", installation_id="cli")
    document = pull.document
    head_object = document.get("head") if isinstance(document, dict) else None
    head = head_object.get("sha") if isinstance(head_object, dict) else None
    if not isinstance(head, str) or re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise GitHubError("PULL_REQUEST_HEAD_INVALID")
    summary = _upsert_summary(api, base, number, publication.summary)
    existing_markers = _markers(_pages(api, f"{base}/pulls/{number}/comments"), INLINE_MARKER)
    written: list[str] = []
    existing: list[str] = []
    refused: list[str] = []
    for comment in publication.inline:
        if comment.group in existing_markers:
            existing.append(comment.group)
            continue
        payload: dict[str, object] = {
            "body": comment.body,
            "commit_id": head,
            "path": comment.path,
            "line": comment.line,
            "side": "RIGHT",
        }
        if comment.start_line is not None:
            payload.update(start_line=comment.start_line, start_side="RIGHT")
        try:
            api.request(
                "POST", f"{base}/pulls/{number}/comments", installation_id="cli", document=payload
            )
        except GitHubError as error:
            if error.code != "HTTP_422":
                raise
            refused.append(comment.group)
            continue
        written.append(comment.group)
    return PublishResult(summary, tuple(written), tuple(existing), tuple(refused))


def _upsert_summary(api: GitHubApi, base: str, number: str, summary: str) -> str:
    body = summary + "\n\n" + SUMMARY_MARKER
    comments = _pages(api, f"{base}/issues/{number}/comments")
    matches = [
        item
        for item in comments
        if isinstance(item.get("body"), str)
        and str(item["body"]).splitlines()[-1:] == [SUMMARY_MARKER]
    ]
    if len(matches) > 1:
        raise GitHubError("SUMMARY_RECONCILIATION_CONFLICT")
    if not matches:
        api.request(
            "POST",
            f"{base}/issues/{number}/comments",
            installation_id="cli",
            document={"body": body},
        )
        return "created"
    existing = matches[0]
    if existing.get("body") == body:
        return "unchanged"
    identity = existing.get("id")
    if not isinstance(identity, int) or identity < 1:
        raise GitHubError("SUMMARY_RECONCILIATION_INVALID")
    api.request(
        "PATCH",
        f"{base}/issues/comments/{identity}",
        installation_id="cli",
        document={"body": body},
    )
    return "updated"


def _pages(api: GitHubApi, path: str) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for page in range(1, _MAX_PAGES + 1):
        response = api.request(
            "GET", f"{path}?per_page={_PER_PAGE}&page={page}", installation_id="cli"
        )
        document = response.document
        if not isinstance(document, list):
            raise GitHubError("LISTING_INVALID")
        items += [item for item in document if isinstance(item, dict)]
        if len(document) < _PER_PAGE:
            return items
    raise GitHubError("LISTING_TOO_LARGE")


def _markers(comments: Sequence[Mapping[str, object]], prefix: str) -> set[str]:
    found: set[str] = set()
    pattern = re.compile(re.escape("<!-- " + prefix) + r"([A-Za-z0-9._:-]+) -->")
    for comment in comments:
        body = comment.get("body")
        if isinstance(body, str):
            found.update(pattern.findall(body))
    return found


__all__ = [
    "INLINE_MARKER",
    "MAX_INLINE_DEFAULT",
    "SUMMARY_MARKER",
    "InlineComment",
    "Publication",
    "PublishResult",
    "build_publication",
    "publish",
]
