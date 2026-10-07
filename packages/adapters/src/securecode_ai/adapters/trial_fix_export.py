"""Attach Architect fixes to the machine-readable reports of ``securecode analyze``.

The canonical report is built before the Architect runs, so its ``patch_refs`` and
``validation_refs`` are empty. This module fills them for every finding a fix covers
(same CWE and file) and adds standard SARIF ``fixes`` to the matching results.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from urllib.parse import quote, unquote

from .trial_architect import FixFinding, ProposedFix

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _targets(
    fixes: Sequence[ProposedFix], findings: Sequence[FixFinding]
) -> list[tuple[str, str, ProposedFix]]:
    by_id = {finding.finding_id: finding for finding in findings}
    targets: list[tuple[str, str, ProposedFix]] = []
    for fix in fixes:
        finding = by_id.get(fix.finding_id)
        if finding is not None:
            targets.append((finding.cwe_id, finding.path, fix))
    return targets


def _validation(fix: ProposedFix) -> dict[str, object]:
    return {"status": fix.status, "checks": list(fix.checks)}


def _patch(fix: ProposedFix) -> dict[str, object]:
    return {
        "path": fix.path,
        "status": fix.status,
        "explanation": fix.explanation,
        "diff_sha256": hashlib.sha256(fix.diff.encode("utf-8")).hexdigest(),
        "diff": fix.diff,
    }


def attach_fixes_to_json(
    rendered: bytes, fixes: Sequence[ProposedFix], findings: Sequence[FixFinding]
) -> bytes:
    """Fill ``patch_refs`` and ``validation_refs`` of findings covered by a fix."""

    targets = _targets(fixes, findings)
    if not targets:
        return rendered
    document = json.loads(rendered)
    for item in document.get("findings", []):
        if not isinstance(item, dict):
            continue
        paths = {
            location.get("path")
            for location in item.get("locations", [])
            if isinstance(location, Mapping)
        }
        for cwe_id, path, fix in targets:
            if item.get("cwe_id") == cwe_id and path in paths:
                item["validation_refs"] = [*item.get("validation_refs", []), _validation(fix)]
                if fix.status == "VALIDATED" and fix.diff:
                    item["patch_refs"] = [*item.get("patch_refs", []), _patch(fix)]
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _replacements(diff: str) -> list[dict[str, object]]:
    """SARIF replacements for a unified diff: each hunk replaces its old line range."""

    replacements: list[dict[str, object]] = []
    lines = diff.splitlines()
    index = 0
    while index < len(lines):
        match = _HUNK.match(lines[index])
        index += 1
        if match is None:
            continue
        old_start = int(match.group(1))
        old_count = 1 if match.group(2) is None else int(match.group(2))
        inserted: list[str] = []
        while index < len(lines) and not lines[index].startswith("@@"):
            line = lines[index]
            if line.startswith((" ", "+")):
                inserted.append(line[1:])
            elif line.startswith("\\"):
                pass
            elif not line.startswith("-"):
                break
            index += 1
        if old_count == 0:
            region = {"startLine": old_start + 1, "startColumn": 1, "endColumn": 1}
        else:
            region = {"startLine": old_start, "endLine": old_start + old_count - 1}
        replacements.append(
            {
                "deletedRegion": region,
                "insertedContent": {"text": "".join(line + "\n" for line in inserted)},
            }
        )
    return replacements


def attach_fixes_to_sarif(
    rendered: bytes, fixes: Sequence[ProposedFix], findings: Sequence[FixFinding]
) -> bytes:
    """Add SARIF ``fixes`` to results whose rule and file match a validated fix."""

    targets = [target for target in _targets(fixes, findings) if target[2].status == "VALIDATED"]
    if not targets:
        return rendered
    document = json.loads(rendered)
    for run in document.get("runs", []):
        for result in run.get("results", []):
            uris = {
                location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
                for location in result.get("locations", [])
            }
            for cwe_id, path, fix in targets:
                uri = quote(path, safe="/-._~")
                if result.get("ruleId") != cwe_id or uri not in uris:
                    continue
                replacements = _replacements(fix.diff)
                if not replacements:
                    continue
                result.setdefault("fixes", []).append(
                    {
                        "description": {"text": fix.explanation or "Validated SecureCode fix"},
                        "artifactChanges": [
                            {"artifactLocation": {"uri": uri}, "replacements": replacements}
                        ],
                    }
                )
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def weakness_group(cwe_id: str, path: str) -> str:
    """One weakness in one file, as the readable report and the Architect group it."""

    digest = hashlib.sha256(f"{cwe_id}\x00{path}".encode()).hexdigest()
    return "weakness-" + digest[:32]


def attach_groups_to_json(rendered: bytes) -> bytes:
    """Mark findings that describe the same weakness with one ``weakness_group``.

    The scanner lane and model Discovery may both confirm a weakness; both findings stay
    for traceability, and a consumer counts, fixes and alerts once per group.
    """

    document = json.loads(rendered)
    for item in document.get("findings", []):
        if not isinstance(item, dict):
            continue
        paths = [
            str(location["path"])
            for location in item.get("locations", [])
            if isinstance(location, Mapping) and isinstance(location.get("path"), str)
        ]
        if paths and isinstance(item.get("cwe_id"), str):
            item["weakness_group"] = weakness_group(item["cwe_id"], paths[0])
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def attach_groups_to_sarif(rendered: bytes) -> bytes:
    """Add the weakness group as a standard SARIF ``partialFingerprints`` entry."""

    document = json.loads(rendered)
    for run in document.get("runs", []):
        for result in run.get("results", []):
            uris = [
                location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
                for location in result.get("locations", [])
            ]
            rule = result.get("ruleId")
            if uris and isinstance(uris[0], str) and isinstance(rule, str):
                result.setdefault("partialFingerprints", {})["securecodeWeakness/v1"] = (
                    weakness_group(rule, unquote(uris[0]))
                )
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def attach_decisions_to_json(
    rendered: bytes, decisions: Mapping[str, Mapping[str, object]]
) -> bytes:
    """Add the finding gate ``decision`` to every finding that has one (by candidate id).

    ``verdict`` is the gate result; ``decision`` says who confirmed it and keeps the
    Auditor and Skeptic verdicts, so a detector decision (D-117) is explicit.
    """

    document = json.loads(rendered)
    for item in document.get("findings", []):
        if isinstance(item, dict) and item.get("candidate_id") in decisions:
            item["decision"] = dict(decisions[str(item["candidate_id"])])
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def attach_decisions_to_sarif(
    rendered: bytes, json_report: bytes, decisions: Mapping[str, Mapping[str, object]]
) -> bytes:
    """Add the gate decision to SARIF result ``properties``.

    SARIF results are rendered from the same findings in the same order; a result is
    matched to its finding only when the rule and the file also agree.
    """

    findings = [
        item for item in json.loads(json_report).get("findings", []) if isinstance(item, dict)
    ]
    document = json.loads(rendered)
    for run in document.get("runs", []):
        results = run.get("results", [])
        if len(results) != len(findings):
            continue
        for result, finding in zip(results, findings, strict=True):
            uris = [
                location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
                for location in result.get("locations", [])
            ]
            paths = [location.get("path") for location in finding.get("locations", [])]
            decision = decisions.get(str(finding.get("candidate_id")))
            if (
                decision is not None
                and result.get("ruleId") == finding.get("cwe_id")
                and uris
                and paths
                and unquote(str(uris[0])) == paths[0]
            ):
                result.setdefault("properties", {})["decision"] = dict(decision)
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
