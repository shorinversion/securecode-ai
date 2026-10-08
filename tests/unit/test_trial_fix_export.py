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


def _grouped(*places: tuple[str, str, int, int]) -> list[str | None]:
    from securecode_ai.adapters.trial_groups import finding_groups

    return finding_groups(
        [
            {
                "cwe_id": cwe_id,
                "locations": [{"path": path, "start": {"line": start}, "end": {"line": end}}],
            }
            for cwe_id, path, start, end in places
        ]
    )


def test_findings_of_one_weakness_share_a_group_in_json_and_sarif() -> None:
    from securecode_ai.adapters.trial_fix_export import (
        attach_groups_to_json,
        attach_groups_to_sarif,
    )
    from securecode_ai.adapters.trial_groups import weakness_group

    document = json.loads(attach_groups_to_json(_report()))
    first, second, other = document["findings"]
    assert (
        first["weakness_group"] == second["weakness_group"] == weakness_group("CWE-89", "app.py", 0)
    )
    assert other["weakness_group"] != first["weakness_group"]

    location = {"physicalLocation": {"artifactLocation": {"uri": "src/my%20app.py"}}}
    sarif = {"runs": [{"results": [{"ruleId": "CWE-89", "locations": [location]}]}]}
    report = {
        "findings": [
            {
                "cwe_id": "CWE-89",
                "locations": [{"path": "src/my app.py", "start": {"line": 3}, "end": {"line": 3}}],
            }
        ]
    }
    (result,) = json.loads(
        attach_groups_to_sarif(json.dumps(sarif).encode(), json.dumps(report).encode())
    )["runs"][0]["results"]
    assert result["partialFingerprints"] == {
        "securecodeWeakness/v2": weakness_group("CWE-89", "src/my app.py", 0)
    }


def test_two_keys_in_one_file_are_two_weaknesses() -> None:
    # E2E of 1.2.7: two hard-coded credentials on lines 2 and 19 shared one group.
    first, second, scanner_twin = _grouped(
        ("CWE-798", "app.py", 2, 2), ("CWE-798", "app.py", 19, 19), ("CWE-798", "app.py", 19, 19)
    )

    assert first != second and second == scanner_twin


def test_a_wide_model_location_joins_one_group_and_never_merges_two() -> None:
    key_a, key_b, file_wide = _grouped(
        ("CWE-798", "app.py", 6, 6), ("CWE-798", "app.py", 18, 18), ("CWE-798", "app.py", 1, 21)
    )

    assert key_a != key_b and file_wide in {key_a, key_b}


def test_code_weaknesses_of_one_file_stay_one_group() -> None:
    # The model may cite the import line of the flow the scanner reports at the sink.
    model, scanner = _grouped(("CWE-89", "app.py", 1, 1), ("CWE-89", "app.py", 5, 5))

    assert model == scanner


def test_gate_decision_is_exported_to_json_and_matching_sarif_results() -> None:
    from securecode_ai.adapters.trial_fix_export import (
        attach_decisions_to_json,
        attach_decisions_to_sarif,
    )

    report = json.loads(_report())
    for index, item in enumerate(report["findings"]):
        item["candidate_id"] = f"candidate-{index}"
    report_bytes = json.dumps(report).encode()
    decision = {
        "authority": "DETERMINISTIC_DETECTOR",
        "route": "CONFIRMED",
        "reason": "DETECTOR_CONFIRMED",
        "auditor_verdict": "REJECTED_WITH_EVIDENCE",
        "skeptic_verdict": "NEEDS_MORE_EVIDENCE",
        "skeptic_effective_verdict": "CONFLICTING",
    }
    decisions = {"candidate-0": decision}

    document = json.loads(attach_decisions_to_json(report_bytes, decisions))
    assert document["findings"][0]["decision"] == decision
    assert "decision" not in document["findings"][1]

    location = {"physicalLocation": {"artifactLocation": {"uri": "app.py"}}}
    results = [
        {"ruleId": "CWE-89", "locations": [location]},
        {"ruleId": "CWE-89", "locations": [location]},
        {"ruleId": "CWE-78", "locations": [location]},
    ]
    sarif = json.dumps({"runs": [{"results": results}]}).encode()
    first, second, _ = json.loads(attach_decisions_to_sarif(sarif, report_bytes, decisions))[
        "runs"
    ][0]["results"]
    assert first["properties"]["decision"] == decision
    assert "properties" not in second


def test_a_model_finding_citing_source_and_sink_joins_the_scanner_group() -> None:
    from securecode_ai.adapters.trial_groups import finding_groups

    def finding(*spans: tuple[int, int]) -> dict[str, object]:
        return {
            "cwe_id": "CWE-89",
            "locations": [
                {"path": "sql.py", "start": {"line": a}, "end": {"line": b}} for a, b in spans
            ],
        }

    # Live 1.2.8 run: the model cited the function (1-21) and line 16; the scanner 18 and 20.
    model, scanner = finding_groups([finding((1, 21), (16, 16)), finding((18, 18), (20, 20))])

    assert model == scanner
