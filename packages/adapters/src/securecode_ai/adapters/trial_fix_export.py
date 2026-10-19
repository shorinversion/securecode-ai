"""Attach Architect fixes to the machine-readable reports of ``securecode analyze``.

The canonical report is built before the Architect runs, so its ``patch_refs`` and
``validation_refs`` are empty. This module fills them for every finding a fix covers
(the same weakness group: ``trial_groups``) and adds standard SARIF ``fixes`` to the
matching results. A fix never lands on a finding of another group, so two credentials of
one file keep their own fixes.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from urllib.parse import quote, unquote

from .local_product_runner_config import LocalProductScanScope
from .trial_architect import FixFinding, ProposedFix
from .trial_groups import WEAKNESS_FINGERPRINT, finding_groups

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


def _covers(
    fix: ProposedFix, group: str | None, cwe_id: object, paths: set[object], target: tuple[str, str]
) -> bool:
    """Whether ``fix`` belongs to a finding: same group, or CWE and file without a group."""

    if fix.weakness_group:
        return group == fix.weakness_group
    return cwe_id == target[0] and target[1] in paths


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
    items = document.get("findings", [])
    for item, group in zip(items, finding_groups(items), strict=True):
        if not isinstance(item, dict):
            continue
        paths = {
            location.get("path")
            for location in item.get("locations", [])
            if isinstance(location, Mapping)
        }
        for cwe_id, path, fix in targets:
            if _covers(fix, group, item.get("cwe_id"), paths, (cwe_id, path)):
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
    rendered: bytes,
    fixes: Sequence[ProposedFix],
    findings: Sequence[FixFinding],
    json_report: bytes | None = None,
) -> bytes:
    """Add SARIF ``fixes`` to results whose weakness group matches a validated fix.

    SARIF results are rendered from the findings of the JSON report in the same order, so
    ``json_report`` gives each result its group; without it the rule and the file decide.
    """

    targets = [target for target in _targets(fixes, findings) if target[2].status == "VALIDATED"]
    if not targets:
        return rendered
    report = (
        [item for item in json.loads(json_report).get("findings", []) if isinstance(item, dict)]
        if json_report is not None
        else []
    )
    report_groups = finding_groups(report)
    document = json.loads(rendered)
    for run in document.get("runs", []):
        results = run.get("results", [])
        groups: list[str | None] = (
            report_groups if len(results) == len(report_groups) else [None] * len(results)
        )
        for result, group in zip(results, groups, strict=True):
            uris = {
                location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
                for location in result.get("locations", [])
            }
            for cwe_id, path, fix in targets:
                uri = quote(path, safe="/-._~")
                if result.get("ruleId") != cwe_id or uri not in uris:
                    continue
                if fix.weakness_group and group != fix.weakness_group:
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


def scope_document(scope: LocalProductScanScope | None) -> dict[str, object]:
    """What the run audited: the whole revision, or the files changed since a base."""

    if scope is None:
        return {
            "kind": "whole_revision",
            "note": "every supported file of the revision was audited",
        }
    return {
        "kind": "changed_since_base",
        "base_rev": scope.base_rev,
        "base_sha": scope.base_sha,
        "merge_base_sha": scope.merge_base_sha,
        "changed_paths": list(scope.changed_paths),
        "scanned_paths": list(scope.scanned_paths),
        "note": (
            "only the files changed since the merge base were audited; flows into unchanged "
            "files and dependency manifests that did not change were not re-checked"
        ),
    }


def attach_baseline_to_json(
    rendered: bytes,
    suppressed: Mapping[str, tuple[str, str]],
    *,
    effective_outcome: str,
    expired: Sequence[tuple[str, str]],
    new_weaknesses: int,
    known_findings: int,
) -> bytes:
    """Mark findings a baseline knows and add ``effective_outcome``.

    ``outcome`` stays the decision of the audit core; ``effective_outcome`` is what the
    run reports to a CI after the baseline. A suppressed finding keeps all its fields.
    """

    document = json.loads(rendered)
    findings = document.get("findings", [])
    for item, group in zip(findings, finding_groups(findings), strict=True):
        if isinstance(item, dict) and group is not None and group in suppressed:
            reason, since = suppressed[group]
            item["suppressed"] = {"reason": reason, "since": since}
    document["effective_outcome"] = effective_outcome
    document["baseline"] = {
        "known_findings": known_findings,
        "new_weaknesses": new_weaknesses,
        "expired_entries": [{"cwe_id": cwe_id, "path": path} for cwe_id, path in expired],
    }
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def attach_baseline_to_sarif(
    rendered: bytes, json_report: bytes, suppressed: Mapping[str, tuple[str, str]]
) -> bytes:
    """Add a standard SARIF ``suppressions`` entry to the results of known findings.

    SARIF results are rendered from the findings of the JSON report in the same order.
    """

    findings = [
        item for item in json.loads(json_report).get("findings", []) if isinstance(item, dict)
    ]
    groups = finding_groups(findings)
    document = json.loads(rendered)
    for run in document.get("runs", []):
        results = run.get("results", [])
        if len(results) != len(findings):
            continue
        for result, finding, group in zip(results, findings, groups, strict=True):
            if (
                group is not None
                and group in suppressed
                and result.get("ruleId") == finding.get("cwe_id")
            ):
                reason, since = suppressed[group]
                result.setdefault("suppressions", []).append(
                    {
                        "kind": "external",
                        "justification": f"baseline: {reason} (since {since})",
                    }
                )
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def attach_scope_to_json(rendered: bytes, scope: LocalProductScanScope | None) -> bytes:
    """Add ``scope`` to the JSON report."""

    document = json.loads(rendered)
    document["scope"] = scope_document(scope)
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def attach_scope_to_sarif(rendered: bytes, scope: LocalProductScanScope | None) -> bytes:
    """Add ``securecode_scope`` to the properties of the first SARIF run."""

    document = json.loads(rendered)
    runs = document.get("runs", [])
    if runs:
        runs[0].setdefault("properties", {})["securecode_scope"] = scope_document(scope)
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def attach_groups_to_json(rendered: bytes) -> bytes:
    """Mark findings that describe the same weakness with one ``weakness_group``.

    The scanner lane and model Discovery may both confirm a weakness; both findings stay
    for traceability, and a consumer counts and alerts once per group (see
    ``trial_groups``: the same CWE at overlapping lines of one file).
    """

    document = json.loads(rendered)
    findings = document.get("findings", [])
    for item, group in zip(findings, finding_groups(findings), strict=True):
        if isinstance(item, dict) and group is not None:
            item["weakness_group"] = group
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def attach_groups_to_sarif(rendered: bytes, json_report: bytes) -> bytes:
    """Add the weakness group as a standard SARIF ``partialFingerprints`` entry.

    SARIF results are rendered from the same findings in the same order; a result gets
    the group of its finding only when the rule and the file also agree.
    """

    findings = [
        item for item in json.loads(json_report).get("findings", []) if isinstance(item, dict)
    ]
    groups = finding_groups(findings)
    document = json.loads(rendered)
    for run in document.get("runs", []):
        results = run.get("results", [])
        if len(results) != len(findings):
            continue
        for result, finding, group in zip(results, findings, groups, strict=True):
            uris = [
                location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
                for location in result.get("locations", [])
            ]
            paths = [location.get("path") for location in finding.get("locations", [])]
            if (
                group is not None
                and result.get("ruleId") == finding.get("cwe_id")
                and uris
                and paths
                and unquote(str(uris[0])) == paths[0]
            ):
                result.setdefault("partialFingerprints", {})[WEAKNESS_FINGERPRINT] = group
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
