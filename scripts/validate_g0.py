"""Read-only G0 definition-baseline validator."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
SPECS = ROOT / "specs"
REQ_DEF = re.compile(
    r"^- `(?P<id>SC-[A-Z]+-\d+)`:(?P<body>.*?)(?=^- `SC-[A-Z]+-\d+`:|\Z)",
    re.MULTILINE | re.DOTALL,
)
REQ_REF = re.compile(r"\bSC-[A-Z]+-\d+\b")
MD_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def baseline_digest(paths: list[str]) -> str:
    digest = hashlib.sha256()
    for relative in sorted(paths):
        data = (SPECS / relative).read_bytes()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def committed_baseline_digest(paths: list[str], commit_sha: str) -> tuple[str | None, str | None]:
    digest = hashlib.sha256()
    for relative in sorted(paths):
        result = subprocess.run(
            ["git", "show", f"{commit_sha}:specs/{relative}"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            error = result.stderr.decode("utf-8", errors="replace").strip()
            return None, f"cannot read specs/{relative} from {commit_sha}: {error}"
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(result.stdout)
        digest.update(b"\0")
    return digest.hexdigest(), None


def git_bytes(revision: str, relative: str) -> tuple[bytes | None, str | None]:
    result = subprocess.run(
        ["git", "show", f"{revision}:{relative}"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None, result.stderr.decode("utf-8", errors="replace").strip()
    return result.stdout, None


def provider_preflight_result(provider: dict, egress: dict, case: dict) -> dict[str, object]:
    """Recompute the normative source-bearing model preflight without I/O."""
    class_rank = {
        "DC0_PUBLIC": 0,
        "DC1_INTERNAL_METADATA": 1,
        "DC2_CONFIDENTIAL_SECURITY": 2,
        "DC3_CONFIDENTIAL_SOURCE": 3,
        "DC4_RESTRICTED": 4,
    }
    required_tools = {"list_paths", "lookup_symbol", "read_range", "read_evidence"}
    capabilities = provider["capabilities"]
    data_terms = provider["data_terms"]
    required_class = case["required_data_class"]
    required_purpose = case["required_purpose"]
    required_destination = case["required_destination"]
    required_max_bytes = case["required_max_bytes"]
    required_tenant_scope = case["required_tenant_scope"]
    planned_transforms = set(case["planned_transforms"])
    matching_rules = [
        rule
        for rule in egress["rules"]
        if required_class in rule["data_classes"]
        and required_purpose in rule["purposes"]
        and required_destination in rule["destinations"]
    ]
    matching_deny = any(rule["effect"] == "deny" for rule in matching_rules)
    allow_rule = any(
        rule["effect"] == "allow"
        and rule.get("max_bytes", -1) >= required_max_bytes
        and set(rule.get("requires_transforms", [])) == planned_transforms
        for rule in matching_rules
    )
    eligible = all(
        (
            capabilities["structured_output"],
            capabilities["native_refusal_signal"],
            capabilities["native_incomplete_signal"],
            capabilities["tool_calling"],
            capabilities["source_code_analysis"],
            capabilities["repository_tool_calls"],
            set(capabilities["repository_tools"]) == required_tools,
            class_rank[data_terms["maximum_input_data_class"]] >= class_rank[required_class],
            required_purpose in data_terms["allowed_purposes"],
            data_terms["evidence_status"] in {"verified", "not_applicable_local"},
            provider["execution_boundary"] == case["required_execution_boundary"],
            egress["profile"] in provider["egress_profiles"],
            egress["tenant_scope"] == required_tenant_scope,
            not matching_deny,
            allow_rule,
        )
    )
    result: dict[str, object] = {
        "eligibility": "eligible" if eligible else "ineligible",
        "preflight_context_bytes": 0,
        "preflight_network_bytes": 0,
        "next_action": "CONTINUE_DUAL_LANE" if eligible else "STOP_BEFORE_CONTEXT_OR_NETWORK",
        "deterministic_only_fallback": False,
    }
    if not eligible:
        result["audit_run_outcome"] = "INDETERMINATE"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-frozen",
        action="store_true",
        help="also prove the signed G0 commit and effective GO attestation",
    )
    args = parser.parse_args()
    errors: list[str] = []
    stats: dict[str, object] = {}

    yaml_paths = sorted(SPECS.rglob("*.yaml")) + [SPECS / "evaluation" / "datasets.lock"]
    for path in yaml_paths:
        try:
            yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:  # pragma: no cover - diagnostic path
            fail(errors, f"YAML {path.relative_to(ROOT)}: {exc}")

    schema_paths = sorted(SPECS.rglob("*.schema.json"))
    schemas: dict[str, dict] = {}
    for path in schema_paths:
        try:
            schema = json.loads(path.read_text(encoding="utf-8"))
            jsonschema.Draft202012Validator.check_schema(schema)
            schemas[path.name] = schema
        except Exception as exc:
            fail(errors, f"JSON Schema {path.relative_to(ROOT)}: {exc}")

    fixtures_path = SPECS / "contracts" / "policy" / "fixtures.yaml"
    fixtures = yaml.safe_load(fixtures_path.read_text(encoding="utf-8"))["cases"]
    fixture_results: list[str] = []
    for case in fixtures:
        instance_path = fixtures_path.parent / case["instance"]
        instance = json.loads(instance_path.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schemas[case["schema"]])
        is_valid = not list(validator.iter_errors(instance))
        expected = case["expect"] == "valid"
        if is_valid != expected:
            fail(errors, f"policy fixture {case['id']}: expected {case['expect']}, got {'valid' if is_valid else 'invalid'}")
        fixture_results.append(f"{case['id']}={'PASS' if is_valid == expected else 'FAIL'}")

    provider_index_path = SPECS / "contracts" / "provider-profile.fixtures.yaml"
    provider_index = yaml.safe_load(provider_index_path.read_text(encoding="utf-8"))
    provider_schema = schemas[provider_index["schema"]]
    provider_fixture_results: list[str] = []
    for case in provider_index["cases"]:
        instance = json.loads((provider_index_path.parent / case["instance"]).read_text(encoding="utf-8"))
        is_valid = not list(jsonschema.Draft202012Validator(provider_schema).iter_errors(instance))
        expected = case["expect"] == "valid"
        if is_valid != expected:
            fail(errors, f"provider fixture {case['id']}: expected {case['expect']}, got {'valid' if is_valid else 'invalid'}")
        provider_fixture_results.append(f"{case['id']}={'PASS' if is_valid == expected else 'FAIL'}")
    provider_semantic_results: list[str] = []
    semantic_case_ids: set[str] = set()
    egress_schema = schemas["egress-policy.schema.json"]
    for case in provider_index.get("semantic_cases", []):
        semantic_case_ids.add(case["id"])
        provider = json.loads((provider_index_path.parent / case["provider_instance"]).read_text(encoding="utf-8"))
        egress = json.loads((provider_index_path.parent / case["egress_instance"]).read_text(encoding="utf-8"))
        if list(jsonschema.Draft202012Validator(provider_schema).iter_errors(provider)):
            fail(errors, f"provider semantic fixture {case['id']}: provider instance is schema-invalid")
        if list(jsonschema.Draft202012Validator(egress_schema).iter_errors(egress)):
            fail(errors, f"provider semantic fixture {case['id']}: egress instance is schema-invalid")
        actual = provider_preflight_result(provider, egress, case)
        expected = case["expect"]
        mismatches = {key: (expected[key], actual.get(key)) for key in expected if actual.get(key) != expected[key]}
        if mismatches:
            fail(errors, f"provider semantic fixture {case['id']}: mismatches={mismatches}")
        if actual["eligibility"] == "eligible":
            mutations: list[tuple[str, dict, dict]] = []
            for field in (
                "structured_output",
                "native_refusal_signal",
                "native_incomplete_signal",
                "tool_calling",
                "source_code_analysis",
                "repository_tool_calls",
            ):
                mutated_provider = copy.deepcopy(provider)
                mutated_provider["capabilities"][field] = False
                mutations.append((f"capability:{field}", mutated_provider, copy.deepcopy(egress)))
            mutated_provider = copy.deepcopy(provider)
            mutated_provider["capabilities"]["repository_tools"] = ["read_range"]
            mutations.append(("repository_tool_set", mutated_provider, copy.deepcopy(egress)))
            mutated_provider = copy.deepcopy(provider)
            mutated_provider["data_terms"]["maximum_input_data_class"] = "DC2_CONFIDENTIAL_SECURITY"
            mutations.append(("maximum_input_data_class", mutated_provider, copy.deepcopy(egress)))
            mutated_provider = copy.deepcopy(provider)
            mutated_provider["data_terms"]["allowed_purposes"] = ["evaluation"]
            mutations.append(("allowed_purposes", mutated_provider, copy.deepcopy(egress)))
            mutated_provider = copy.deepcopy(provider)
            mutated_provider["data_terms"]["evidence_status"] = "unverified"
            mutations.append(("data_terms_evidence", mutated_provider, copy.deepcopy(egress)))
            mutated_provider = copy.deepcopy(provider)
            mutated_provider["execution_boundary"] = "public_external"
            mutations.append(("execution_boundary", mutated_provider, copy.deepcopy(egress)))
            mutated_egress = copy.deepcopy(egress)
            mutated_egress["profile"] = "metadata_external"
            mutations.append(("provider_egress_profile", copy.deepcopy(provider), mutated_egress))
            mutated_egress = copy.deepcopy(egress)
            mutated_egress["rules"] = []
            mutations.append(("exact_allow_rule", copy.deepcopy(provider), mutated_egress))
            mutated_egress = copy.deepcopy(egress)
            mutated_egress["tenant_scope"] = "different-tenant"
            mutations.append(("tenant_scope", copy.deepcopy(provider), mutated_egress))
            mutated_egress = copy.deepcopy(egress)
            for rule in mutated_egress["rules"]:
                rule["requires_transforms"] = []
            mutations.append(("required_transforms_absent", copy.deepcopy(provider), mutated_egress))
            mutated_egress = copy.deepcopy(egress)
            for rule in mutated_egress["rules"]:
                rule["requires_transforms"] = ["wrong_transform"]
            mutations.append(("required_transforms_wrong", copy.deepcopy(provider), mutated_egress))
            mutated_egress = copy.deepcopy(egress)
            for rule in mutated_egress["rules"]:
                rule["requires_transforms"] = ["bounded_repository_view", "secret_redaction"]
            mutations.append(("required_transforms_strict_superset", copy.deepcopy(provider), mutated_egress))
            mutated_egress = copy.deepcopy(egress)
            deny_rule = copy.deepcopy(mutated_egress["rules"][0])
            deny_rule["rule_id"] = "EGR-EXACT-DENY-OVERRIDE"
            deny_rule["effect"] = "deny"
            mutated_egress["rules"].append(deny_rule)
            mutations.append(("matching_deny_override", copy.deepcopy(provider), mutated_egress))
            for mutation_id, mutated_provider, mutated_egress in mutations:
                mutated_result = provider_preflight_result(mutated_provider, mutated_egress, case)
                if mutated_result != {
                    "eligibility": "ineligible",
                    "preflight_context_bytes": 0,
                    "preflight_network_bytes": 0,
                    "next_action": "STOP_BEFORE_CONTEXT_OR_NETWORK",
                    "deterministic_only_fallback": False,
                    "audit_run_outcome": "INDETERMINATE",
                }:
                    fail(errors, f"provider semantic fixture {case['id']}: unsafe mutation result for {mutation_id}")
        provider_semantic_results.append(f"{case['id']}={'PASS' if not mismatches else 'FAIL'}")

    definitions: dict[str, str] = {}
    duplicate_ids: list[str] = []
    for path in sorted(SPECS.rglob("*.md")):
        text = path.read_text(encoding="utf-8")
        for match in REQ_DEF.finditer(text):
            requirement_id = match.group("id")
            if requirement_id in definitions:
                duplicate_ids.append(requirement_id)
            definitions[requirement_id] = str(path.relative_to(ROOT))
            if "**Oracle:**" not in match.group("body"):
                fail(errors, f"missing oracle: {requirement_id} in {path.relative_to(ROOT)}")
    if duplicate_ids:
        fail(errors, f"duplicate requirement IDs: {sorted(set(duplicate_ids))}")

    refs: set[str] = set()
    for base in (SPECS, ROOT / "docs", ROOT / "artifacts"):
        for path in base.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".md", ".yaml", ".lock", ".json", ".csv"}:
                refs.update(REQ_REF.findall(path.read_text(encoding="utf-8", errors="replace")))
    undefined = sorted(refs - definitions.keys())
    if undefined:
        fail(errors, f"undefined requirement IDs: {undefined}")

    trace = yaml.safe_load((SPECS / "traceability" / "requirements.yaml").read_text(encoding="utf-8"))
    plan_text = (ROOT / "docs" / "PLAN.md").read_text(encoding="utf-8")
    plan_task_ids = set(re.findall(r"^\| `(P\d+\.\d+)`", plan_text, re.MULTILINE))
    plan_gate_ids = set(re.findall(r"^### (G\d+)\b", plan_text, re.MULTILINE))
    plan_task_refs = set(re.findall(r"`(P\d+\.\d+)`", plan_text))
    plan_gate_refs = set(re.findall(r"\b(G\d+)\b", plan_text))
    if plan_task_refs - plan_task_ids:
        fail(errors, f"plan references undefined tasks: {sorted(plan_task_refs-plan_task_ids)}")
    if plan_gate_refs - plan_gate_ids:
        fail(errors, f"plan references undefined gates: {sorted(plan_gate_refs-plan_gate_ids)}")
    trace_rows = trace["requirements"]
    trace_row_ids = [row["id"] for row in trace_rows]
    if len(trace_row_ids) != len(set(trace_row_ids)):
        fail(errors, "duplicate source traceability IDs")
    expected_brief = {f"BRIEF-{index:03d}" for index in range(1, 16)}
    missing_brief = sorted(expected_brief - set(trace_row_ids))
    if missing_brief:
        fail(errors, f"original brief traceability missing: {missing_brief}")
    trace_sources = " ".join(str(row["source"]) for row in trace_rows)
    expected_crs = {f"CR-{index:03d}" for index in range(1, 17)}
    missing_crs = sorted(cr for cr in expected_crs if cr not in trace_sources)
    if missing_crs:
        fail(errors, f"accepted change requests missing from traceability sources: {missing_crs}")
    for row in trace_rows:
        for field in ("normative", "tasks", "tests", "evidence"):
            if not row.get(field):
                fail(errors, f"traceability {row['id']} has empty {field}")
        unknown_normative = sorted(set(row["normative"]) - definitions.keys())
        unknown_tasks = sorted(set(row["tasks"]) - plan_task_ids)
        unknown_gates = sorted(set(row["evidence"]) - plan_gate_ids)
        if unknown_normative:
            fail(errors, f"traceability {row['id']} undefined normative IDs: {unknown_normative}")
        if unknown_tasks:
            fail(errors, f"traceability {row['id']} undefined plan tasks: {unknown_tasks}")
        if unknown_gates:
            fail(errors, f"traceability {row['id']} undefined evidence gates: {unknown_gates}")
    covered_prefixes = set(trace["spec_prefix_coverage"])
    actual_prefixes = {requirement_id.rsplit("-", 1)[0] for requirement_id in definitions}
    missing_prefixes = sorted(actual_prefixes - covered_prefixes)
    if missing_prefixes:
        fail(errors, f"traceability missing prefixes: {missing_prefixes}")

    stage_catalogue = yaml.safe_load((SPECS / "behavior" / "stage-catalogue.yaml").read_text(encoding="utf-8"))
    semantic_scope = stage_catalogue.get("supported_semantic_scope", {})
    required_lanes = set(semantic_scope.get("mandatory_discovery_lanes", []))
    if required_lanes != {"deterministic_analysis", "model_native_discovery"}:
        fail(errors, f"dual-lane catalogue mismatch: {sorted(required_lanes)}")
    if semantic_scope.get("model_native_not_applicable_when_deterministic_zero") is not False:
        fail(errors, "model-native discovery may be skipped on zero deterministic candidates")
    clean_required = set(stage_catalogue.get("scenarios", {}).get("clean_no_candidate", {}).get("required", []))
    if "model_native_discovery" not in clean_required:
        fail(errors, "clean/no-candidate scenario lacks mandatory model-native discovery")
    stage_definitions = stage_catalogue.get("stage_definitions", {})
    deterministic_children = {"python_parse_symbols", "secret_scan", "dependency_scan", "cwe89_scan"}
    if not deterministic_children.issubset(stage_definitions):
        fail(errors, "deterministic stage catalogue lacks one or more accepted MVP units")
    deterministic_composite = stage_definitions.get("deterministic_analysis", {})
    if (
        deterministic_composite.get("kind") != "composite"
        or deterministic_composite.get("child_selection") != "select_child_when_operation_matches_and_required_inventory_tags_any_intersects_inventory_tags"
        or set(deterministic_composite.get("child_stage_ids", [])) != deterministic_children
        or deterministic_composite.get("completion_rule") != "every_selected_child_has_terminal_coverage_unit"
        or not deterministic_composite.get("zero_candidates_is_success_only_when_all_selected_children_completed")
    ):
        fail(errors, "deterministic composite completion contract is incomplete")
    snapshots = stage_catalogue.get("deterministic_selection_snapshots", [])
    snapshot_ids = [snapshot.get("id") for snapshot in snapshots]
    if len(snapshots) < 3 or len(snapshot_ids) != len(set(snapshot_ids)):
        fail(errors, "deterministic stage catalogue requires at least three unique selection snapshots")
    for snapshot in snapshots:
        operation = snapshot["operation"]
        inventory_tags = set(snapshot["inventory_tags"])
        actual_selected = {
            child_id
            for child_id in deterministic_composite["child_stage_ids"]
            if operation in stage_definitions[child_id].get("operations", [])
            and inventory_tags.intersection(stage_definitions[child_id].get("required_inventory_tags_any", []))
        }
        expected_selected = set(snapshot["expected_selected_child_ids"])
        if actual_selected != expected_selected:
            fail(errors, f"deterministic selection snapshot {snapshot['id']} mismatch: {sorted(actual_selected)}")
    defined_stages = set(stage_definitions)
    for scenario_id, scenario in stage_catalogue.get("scenarios", {}).items():
        unknown_stages = (
            set(scenario.get("required", []))
            | set(scenario.get("not_applicable_after_completed_zero_union", []))
        ) - defined_stages
        if unknown_stages:
            fail(errors, f"stage scenario {scenario_id} references undefined stages: {sorted(unknown_stages)}")
    evaluation_cases = yaml.safe_load((SPECS / "evaluation" / "cases" / "mvp-cwe89.yaml").read_text(encoding="utf-8"))
    for case in evaluation_cases["cases"]:
        if case.get("kind") == "provider_preflight":
            if case.get("semantic_fixture") not in semantic_case_ids:
                fail(errors, f"evaluation case {case['id']} references unknown provider semantic fixture")
            expected = case.get("expected", {})
            if expected.get("context_bytes") != 0 or expected.get("network_bytes") != 0:
                fail(errors, f"evaluation case {case['id']} must prove zero preflight I/O")
            if expected.get("audit_run_outcome") != "INDETERMINATE" or expected.get("deterministic_only_fallback") is not False:
                fail(errors, f"evaluation case {case['id']} has unsafe ineligible-provider outcome")
    product_spec = (SPECS / "product" / "requirements.md").read_text(encoding="utf-8")
    for required_product_id in ("SC-PROD-019", "SC-PROD-020", "SC-PROD-021"):
        if required_product_id not in product_spec:
            fail(errors, f"missing accepted product delta: {required_product_id}")
    execution_identity_components = {
        "tenant",
        "repository",
        "base",
        "head",
        "stage catalogue",
        "workflow",
        "policy",
        "configuration",
        "provider",
        "capability",
        "egress",
    }
    domain_spec = (SPECS / "contracts" / "domain.md").read_text(encoding="utf-8")
    identity_paragraph = re.search(
        r"- `SC-DOM-014`:(.*?)(?=\n- `SC-|\Z)", domain_spec, re.DOTALL
    )
    if not identity_paragraph or not all(
        component in identity_paragraph.group(1).lower() for component in execution_identity_components
    ):
        fail(errors, "RunExecutionIdentity omits a canonical execution component")
    for relative in (
        "contracts/api.md",
        "contracts/scm.md",
        "contracts/events.md",
        "contracts/reports.md",
    ):
        identity_text = (SPECS / relative).read_text(encoding="utf-8")
        if "execution_identity_hash" not in identity_text:
            fail(errors, f"cross-transport RunExecutionIdentity missing from {relative}")

    threat_text = (ROOT / "docs" / "security" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    threat_ids = set(re.findall(r"`((?:TM|PV)-\d{3})`", threat_text))
    mapped_threat_ids = {item["id"] for item in trace["threat_traceability"]}
    if threat_ids != mapped_threat_ids:
        fail(errors, f"threat traceability mismatch missing={sorted(threat_ids-mapped_threat_ids)} extra={sorted(mapped_threat_ids-threat_ids)}")
    for item in trace["threat_traceability"]:
        unknown_normative = sorted(set(item["normative"]) - definitions.keys())
        unknown_tasks = sorted(set(item["tasks"]) - plan_task_ids)
        if unknown_normative:
            fail(errors, f"threat {item['id']} undefined normative IDs: {unknown_normative}")
        if unknown_tasks:
            fail(errors, f"threat {item['id']} undefined plan tasks: {unknown_tasks}")
        if not item.get("tests"):
            fail(errors, f"threat {item['id']} has no planned test")

    baseline_path = SPECS / "baseline.yaml"
    baseline = yaml.safe_load(baseline_path.read_text(encoding="utf-8"))
    if len(baseline["normative_documents"]) != len(set(baseline["normative_documents"])):
        fail(errors, "baseline has duplicate normative document paths")
    for group in ("normative_documents", "supporting_documents"):
        for relative in baseline[group]:
            if not (SPECS / relative).resolve().is_file():
                fail(errors, f"baseline missing {group}: {relative}")

    dataset_lock = yaml.safe_load((SPECS / "evaluation" / "datasets.lock").read_text(encoding="utf-8"))
    for dataset in dataset_lock["datasets"]:
        source_path = ROOT / dataset["source_url"]
        raw = source_path.read_bytes()
        if len(raw) != dataset["bytes"]:
            fail(errors, f"dataset bytes mismatch: {dataset['dataset_id']}")
        if hashlib.sha256(raw).hexdigest() != dataset["sha256"]:
            fail(errors, f"dataset sha256 mismatch: {dataset['dataset_id']}")
        for required in ("build_hash", "root_cause_groups", "exclusions", "ground_truth", "splits"):
            if required not in dataset:
                fail(errors, f"dataset missing {required}: {dataset['dataset_id']}")

    for path in sorted([*ROOT.joinpath("docs").rglob("*.md"), *SPECS.rglob("*.md"), *ROOT.joinpath("artifacts").rglob("*.md")]):
        text = path.read_text(encoding="utf-8", errors="replace")
        for target in MD_LINK.findall(text):
            target = target.strip("<>").split("#", 1)[0]
            if not target or re.match(r"^(?:https?://|mailto:)", target):
                continue
            candidate = (path.parent / unquote(target)).resolve()
            if not candidate.exists():
                fail(errors, f"broken local link: {path.relative_to(ROOT)} -> {target}")

    critical_tokens = []
    for path in sorted(SPECS.rglob("*")):
        if path.is_file() and path.suffix.lower() in {".md", ".yaml", ".lock", ".json"}:
            for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if re.search(r"\b(?:TBD|FIXME)\s*:", line):
                    critical_tokens.append(f"{path.relative_to(ROOT)}:{line_no}")
    if critical_tokens:
        fail(errors, f"critical unresolved tokens: {critical_tokens}")

    content_sha = baseline_digest(baseline["normative_documents"])
    expected_sha = baseline["freeze"].get("content_sha256")
    if expected_sha is not None and expected_sha != content_sha:
        fail(errors, f"baseline content hash mismatch expected={expected_sha} actual={content_sha}")
    lifecycle = baseline.get("lifecycle")
    commit_sha = baseline["freeze"].get("commit_sha")
    allowed_lifecycles = {"in_final_review", "accepted_pending_repository_commit", "frozen", "superseded"}
    if lifecycle not in allowed_lifecycles:
        fail(errors, f"unsupported baseline lifecycle: {lifecycle}")
    if lifecycle == "frozen" and (expected_sha is None or commit_sha is None):
        fail(errors, "frozen baseline requires content_sha256 and commit_sha")
    if lifecycle == "accepted_pending_repository_commit" and expected_sha is None:
        fail(errors, "accepted_pending_repository_commit requires content_sha256")
    if lifecycle == "accepted_pending_repository_commit" and commit_sha is not None:
        fail(errors, "pending-commit baseline must not claim a commit_sha")

    frozen_commit_hash: str | None = None
    if args.require_frozen:
        if lifecycle != "frozen":
            fail(errors, f"effective G0 requires lifecycle frozen, got {lifecycle}")
        if not isinstance(commit_sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40,64}", commit_sha):
            fail(errors, "effective G0 requires a full hexadecimal baseline commit_sha")
        else:
            commit_check = subprocess.run(
                ["git", "cat-file", "-e", f"{commit_sha}^{{commit}}"],
                cwd=ROOT,
                capture_output=True,
                check=False,
            )
            if commit_check.returncode != 0:
                fail(errors, f"baseline commit does not exist locally: {commit_sha}")
            else:
                frozen_commit_hash, commit_error = committed_baseline_digest(
                    baseline["normative_documents"], commit_sha
                )
                if commit_error:
                    fail(errors, commit_error)
                elif frozen_commit_hash != expected_sha:
                    fail(errors, f"committed normative hash mismatch expected={expected_sha} actual={frozen_commit_hash}")
        head_result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        head_sha = head_result.stdout.strip() if head_result.returncode == 0 else None
        if head_sha is None:
            fail(errors, "effective G0 requires an existing attestation HEAD commit")
        elif isinstance(commit_sha, str) and re.fullmatch(r"[0-9a-fA-F]{40,64}", commit_sha):
            ancestor = subprocess.run(
                ["git", "merge-base", "--is-ancestor", commit_sha, head_sha],
                cwd=ROOT,
                capture_output=True,
                check=False,
            )
            if ancestor.returncode != 0 or commit_sha.lower() == head_sha.lower():
                fail(errors, "baseline commit must be a strict ancestor of the attestation HEAD")

        protected_gate_paths = [
            "scripts/validate_g0.py",
            "specs/baseline.yaml",
            "artifacts/gates/G0/checklist.md",
            "artifacts/gates/G0/decision.md",
            "artifacts/gates/G0/independent-reviews.md",
            "artifacts/gates/G0/test-results/prefreeze-validation.md",
        ]
        for relative in protected_gate_paths:
            working = (ROOT / relative).read_bytes()
            committed, committed_error = git_bytes("HEAD", relative)
            if committed_error:
                fail(errors, f"effective G0 attestation missing from HEAD: {relative}: {committed_error}")
            elif committed != working:
                fail(errors, f"effective G0 attestation differs from HEAD: {relative}")
        protected_status = subprocess.run(
            ["git", "status", "--porcelain", "--", "scripts/validate_g0.py", "specs", "artifacts/gates/G0"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if protected_status.returncode != 0 or protected_status.stdout.strip():
            fail(errors, "effective G0 requires clean committed specs and G0 evidence paths")

        checklist = (ROOT / "artifacts" / "gates" / "G0" / "checklist.md").read_text(encoding="utf-8")
        checklist_rows: list[tuple[str, str, str]] = []
        in_table = False
        for line in checklist.splitlines():
            if line.startswith("| Check |"):
                in_table = True
                continue
            if in_table and line.startswith("|---"):
                continue
            if in_table and line.startswith("|"):
                cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
                if len(cells) >= 3:
                    checklist_rows.append((cells[0], cells[1], cells[2]))
                continue
            if in_table and checklist_rows:
                break
        expected_check_names = {
            "Original brief preserved",
            "Material scope changes recorded",
            "Personas/top journeys",
            "Release scope/non-goals",
            "Python-first/final 3-language decision",
            "GitHub-first/minimum permissions",
            "Runtime/storage/artifact/sandbox decisions",
            "Full threat model",
            "Data/egress/retention",
            "Frozen MVP evaluation",
            "Traceability",
            "Normative baseline",
            "Machine syntax",
            "Local Markdown references",
            "Independent product/architecture/security review",
            "Normative content hash",
            "Baseline repository commit",
        }
        checklist_names = [name for name, _, _ in checklist_rows]
        checklist_results = [result for _, _, result in checklist_rows]
        if (
            len(checklist_rows) != len(expected_check_names)
            or set(checklist_names) != expected_check_names
            or len(checklist_names) != len(set(checklist_names))
            or any(not evidence for _, evidence, _ in checklist_rows)
            or any(not result.startswith("PASS") for result in checklist_results)
        ):
            fail(errors, f"effective G0 requires the exact complete checklist with PASS results, got {checklist_rows}")

        decision = (ROOT / "artifacts" / "gates" / "G0" / "decision.md").read_text(encoding="utf-8")
        decision_statuses = re.findall(r"^Status:\s*`([^`]+)`\s*$", decision, re.MULTILINE)
        decision_values = re.findall(r"^Decision:\s*`([^`]+)`\s*$", decision, re.MULTILINE)
        decision_commits = re.findall(r"^Baseline commit:\s*`([0-9a-fA-F]{40,64})`\s*$", decision, re.MULTILINE)
        if decision_statuses != ["EFFECTIVE"]:
            fail(errors, "effective G0 status must be exactly EFFECTIVE")
        if decision_values != ["GO FOR P1 ONLY"]:
            fail(errors, "effective G0 decision must be exactly GO FOR P1 ONLY")
        if len(decision_commits) != 1 or decision_commits[0].lower() != str(commit_sha).lower():
            fail(errors, "effective G0 decision must name the verified baseline commit_sha")

        reviews = (ROOT / "artifacts" / "gates" / "G0" / "independent-reviews.md").read_text(encoding="utf-8")
        review_rows = re.findall(r"^\| (Product/scope/traceability|Architecture/public contracts|Security/evaluation) \| `([^`]+)` \|", reviews, re.MULTILINE)
        expected_review_names = {
            "Product/scope/traceability",
            "Architecture/public contracts",
            "Security/evaluation",
        }
        if (
            len(review_rows) != 3
            or {name for name, _ in review_rows} != expected_review_names
            or any(verdict != "PASS" for _, verdict in review_rows)
        ):
            fail(errors, f"effective G0 requires three committed independent PASS rows, got {review_rows}")
        if reviews.count(str(expected_sha)) != 1:
            fail(errors, "independent review attestation must name the exact normative content hash once")

    stats.update(
        yaml_files=len(yaml_paths),
        json_schemas=len(schema_paths),
        policy_fixtures=fixture_results,
        provider_fixtures=provider_fixture_results,
        provider_semantic_fixtures=provider_semantic_results,
        requirement_definitions=len(definitions),
        requirement_prefixes=len(actual_prefixes),
        threat_mappings=len(mapped_threat_ids),
        source_traceability_rows=len(trace_rows),
        baseline_content_sha256=content_sha,
        frozen_commit_content_sha256=frozen_commit_hash,
        attestation_head=(head_sha if args.require_frozen else None),
        require_frozen=args.require_frozen,
        errors=errors,
    )
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
