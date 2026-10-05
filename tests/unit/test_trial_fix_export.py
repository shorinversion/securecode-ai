from __future__ import annotations

import json

from securecode_ai.adapters.trial_architect import FixFinding, ProposedFix
from securecode_ai.adapters.trial_fix_export import attach_fixes_to_json, attach_fixes_to_sarif

_DIFF = (
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -5 +5 @@\n"
    '-    return conn.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n'
    '+    return conn.execute("SELECT * FROM users WHERE name = ?", (name,))\n'
)
_FINDING = FixFinding("finding-1", "CWE-89", "app.py", 5, 5, "deterministic")


def _fix(status: str = "VALIDATED") -> ProposedFix:
    return ProposedFix(
        "finding-1", "app.py", status, ("apply:ok", "syntax:ok"), "Parameterized query.", _DIFF
    )


def _report() -> bytes:
    location = {"path": "app.py", "start": {"line": 5}, "end": {"line": 5}}
    findings = [
        {"finding_id": f, "cwe_id": "CWE-89", "locations": [location]}
        for f in ("finding-1", "finding-2")
    ]
    findings.append({"finding_id": "finding-3", "cwe_id": "CWE-78", "locations": [location]})
    for item in findings:
        item.update(patch_refs=[], validation_refs=[])
    return json.dumps({"findings": findings}).encode()


def test_json_report_carries_the_fix_for_every_finding_of_the_weakness() -> None:
    document = json.loads(attach_fixes_to_json(_report(), [_fix()], [_FINDING]))
    first, second, other = document["findings"]

    assert first["patch_refs"] == second["patch_refs"]
    (patch,) = first["patch_refs"]
    assert patch["diff"] == _DIFF and patch["status"] == "VALIDATED"
    assert first["validation_refs"] == [
        {"status": "VALIDATED", "checks": ["apply:ok", "syntax:ok"]}
    ]
    assert other["patch_refs"] == other["validation_refs"] == []


def test_rejected_fix_is_recorded_as_validation_only() -> None:
    document = json.loads(attach_fixes_to_json(_report(), [_fix("NOT_VALIDATED")], [_FINDING]))
    first = document["findings"][0]

    assert first["patch_refs"] == []
    assert first["validation_refs"][0]["status"] == "NOT_VALIDATED"


def test_without_fixes_the_report_is_unchanged() -> None:
    assert attach_fixes_to_json(_report(), [], [_FINDING]) == _report()
    assert attach_fixes_to_sarif(b"{}", [_fix("NOT_VALIDATED")], [_FINDING]) == b"{}"


def test_sarif_result_gets_a_standard_fix() -> None:
    location = {"physicalLocation": {"artifactLocation": {"uri": "app.py"}}}
    sarif = {
        "runs": [
            {
                "results": [
                    {"ruleId": "CWE-89", "locations": [location]},
                    {"ruleId": "CWE-78", "locations": [location]},
                ]
            }
        ]
    }
    document = json.loads(attach_fixes_to_sarif(json.dumps(sarif).encode(), [_fix()], [_FINDING]))
    matched, other = document["runs"][0]["results"]

    (fix,) = matched["fixes"]
    (change,) = fix["artifactChanges"]
    (replacement,) = change["replacements"]
    assert change["artifactLocation"]["uri"] == "app.py"
    assert replacement["deletedRegion"] == {"startLine": 5, "endLine": 5}
    assert "WHERE name = ?" in replacement["insertedContent"]["text"]
    assert "fixes" not in other
