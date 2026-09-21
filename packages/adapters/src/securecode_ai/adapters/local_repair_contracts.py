"""Source-free contract preparation for installed local repair."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Final, cast

from securecode_ai.contracts import (
    DiscoveryCandidate,
    Evidence,
    EvidenceKind,
    FindingCase,
    FindingVerdict,
)
from securecode_ai.core.evidence_graph import (
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceNodeKind,
    EvidenceNodeRef,
)
from securecode_ai.core.regression import (
    RegressionCase,
    RegressionCaseKind,
    SecurityRegressionDescriptor,
    build_security_regression_descriptor,
)
from securecode_ai.core.root_cause import (
    RootCauseEvidenceRefs,
    RootCauseLocalizationStatus,
    RootCauseRecord,
    localize_root_cause,
)
from securecode_ai.core.security_invariants import SecurityInvariant, build_security_invariant

from .local_product_runner_config import LocalProductScanResult

_MAX_GRAPH_BYTES: Final = 16 * 1024 * 1024
_LOCAL_ORACLE_DOMAIN: Final = b"securecode-ai/local-cwe89-root-oracle/v2\x00"
_SQL_SINK_CALL: Final = re.compile(rb"\.(?:execute|query|raw|exec)\s*\(", re.IGNORECASE)


class LocalRepairContractError(ValueError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__("local repair contract preparation failed")
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class LocalRepairBinding:
    finding: FindingCase
    root_cause: RootCauseRecord
    invariant: SecurityInvariant
    regression: SecurityRegressionDescriptor


def confirmed_blocking_findings(scan_result: object) -> tuple[FindingCase, ...]:
    try:
        scan = cast(LocalProductScanResult, scan_result)
        run = scan.composition.run
        report = scan.composition.report
        blocking = tuple(run.blocking_finding_ids)
        findings = tuple(item.finding for item in report.findings)
    except (AttributeError, TypeError, ValueError):
        raise LocalRepairContractError("SCAN_RESULT_INVALID") from None
    if (
        len(set(blocking)) != len(blocking)
        or tuple(sorted(blocking)) != blocking
        or tuple(sorted(item.finding_id for item in findings)) != blocking
        or any(
            type(item) is not FindingCase or item.finding_verdict is not FindingVerdict.CONFIRMED
            for item in findings
        )
    ):
        raise LocalRepairContractError("BLOCKING_FINDING_SET_INVALID")
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def parse_retained_graph(graph_bytes: bytes, finding: FindingCase) -> EvidenceGraph:
    if (
        type(graph_bytes) is not bytes
        or not graph_bytes
        or len(graph_bytes) > _MAX_GRAPH_BYTES
        or type(finding) is not FindingCase
    ):
        raise LocalRepairContractError("EVIDENCE_GRAPH_INVALID")
    document = _closed_json(graph_bytes)
    if set(document) != {
        "schema_version",
        "tenant_id",
        "head_sha",
        "candidates",
        "evidence",
        "edges",
    }:
        raise LocalRepairContractError("EVIDENCE_GRAPH_INVALID")
    try:
        raw_candidates = document["candidates"]
        raw_evidence = document["evidence"]
        raw_edges = document["edges"]
        if not all(type(value) is list for value in (raw_candidates, raw_evidence, raw_edges)):
            raise ValueError
        candidates = tuple(DiscoveryCandidate.model_validate(item) for item in raw_candidates)
        evidence = tuple(Evidence.model_validate(item) for item in raw_evidence)
        edges = tuple(_edge(item) for item in raw_edges)
        graph = EvidenceGraph(
            graph_id=finding.evidence_graph_ref.content_id,
            tenant_id=document["tenant_id"],
            head_sha=document["head_sha"],
            candidates=candidates,
            evidence=evidence,
            edges=edges,
            schema_version=document["schema_version"],
        )
    except Exception:
        raise LocalRepairContractError("EVIDENCE_GRAPH_INVALID") from None
    if (
        graph.graph_sha256 != finding.evidence_graph_ref.content_sha256
        or hashlib.sha256(graph_bytes).hexdigest() != finding.evidence_graph_ref.content_sha256
    ):
        raise LocalRepairContractError("EVIDENCE_GRAPH_HASH_MISMATCH")
    return graph


def build_local_repair_binding(finding: FindingCase, graph: EvidenceGraph) -> LocalRepairBinding:
    if type(finding) is not FindingCase or type(graph) is not EvidenceGraph:
        raise LocalRepairContractError("REPAIR_BINDING_INVALID")
    if finding.cwe_id != "CWE-89":
        raise LocalRepairContractError("REPAIR_INVARIANT_UNSUPPORTED")
    records = {
        item.evidence_id: item
        for item in graph.evidence
        if item.evidence_id in set(finding.evidence_ids)
    }
    locations = sorted(
        (
            item
            for item in records.values()
            if item.evidence_kind is EvidenceKind.SOURCE_LOCATION and item.location is not None
        ),
        key=_location_key,
    )
    data_flows = sorted(
        (item for item in records.values() if item.evidence_kind is EvidenceKind.DATA_FLOW),
        key=lambda item: item.evidence_id,
    )
    distinct_locations = []
    seen = set()
    for item in locations:
        location = item.location
        if location is None:
            raise LocalRepairContractError("ROOT_CAUSE_EVIDENCE_INCOMPLETE")
        location_key = location.model_dump_json()
        if location_key not in seen:
            seen.add(location_key)
            distinct_locations.append(item)
    if len(distinct_locations) < 2 or not data_flows:
        raise LocalRepairContractError("ROOT_CAUSE_EVIDENCE_INCOMPLETE")
    refs = RootCauseEvidenceRefs(
        source_evidence_id=distinct_locations[0].evidence_id,
        propagation_evidence_id=data_flows[0].evidence_id,
        sink_evidence_id=distinct_locations[-1].evidence_id,
    )
    receipt = localize_root_cause(finding, graph, refs)
    if receipt.status is not RootCauseLocalizationStatus.CONFIRMED or receipt.record is None:
        raise LocalRepairContractError("ROOT_CAUSE_NOT_CONFIRMED")
    invariant = build_security_invariant(finding, receipt.record)
    regression = build_security_regression_descriptor(
        receipt.record,
        invariant,
        _regression_cases(receipt.record, invariant),
    )
    return LocalRepairBinding(finding, receipt.record, invariant, regression)


def _location_key(item: Evidence) -> tuple[str, int, int, str]:
    location = item.location
    if location is None:
        raise LocalRepairContractError("ROOT_CAUSE_EVIDENCE_INCOMPLETE")
    return (
        location.path,
        location.start.line,
        location.start.column,
        item.evidence_id,
    )


def _regression_cases(
    root: RootCauseRecord, invariant: SecurityInvariant
) -> tuple[RegressionCase, ...]:
    result = []
    for kind in RegressionCaseKind:
        material = _regression_case_material(root, invariant, kind)
        oracle = _LOCAL_ORACLE_DOMAIN + kind.value.encode("ascii")
        result.append(
            RegressionCase(
                case_id=f"local-{kind.value.lower().replace('_', '-')}-{hashlib.sha256(material).hexdigest()[:24]}",
                kind=kind,
                input_sha256=hashlib.sha256(b"input\x00" + material).hexdigest(),
                input_size_bytes=len(material),
                oracle_sha256=hashlib.sha256(oracle).hexdigest(),
            )
        )
    return tuple(sorted(result, key=lambda item: item.case_id))


def _regression_case_material(
    root: RootCauseRecord,
    invariant: SecurityInvariant,
    kind: RegressionCaseKind,
) -> bytes:
    return json.dumps(
        {
            "finding_id": root.finding_id,
            "head_sha": root.head_sha,
            "invariant_sha256": invariant.invariant_sha256,
            "kind": kind.value,
            "root_cause_id": root.record_id,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _local_cwe89_parameter_binding_oracle(files: Mapping[str, bytes]) -> bool | None:
    """Independently require parameter binding for every SQL sink in scope.

    This oracle does not reuse the CWE-89 taint scanner. ``None`` means the
    supported-language root could not be evaluated and therefore must fail
    closed at the OCI boundary.
    """

    if not files or len(files) > 64:
        return None
    observations: list[bool] = []
    for path, source in sorted(files.items()):
        if (
            type(path) is not str
            or type(source) is not bytes
            or not source
            or len(source) > 2_000_000
            or PurePosixPath(path).as_posix() != path
        ):
            return None
        suffix = PurePosixPath(path).suffix.lower()
        if suffix == ".py":
            current = _python_binding_observations(source)
        elif suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go"}:
            current = _lexical_binding_observations(source)
        else:
            return None
        if current is None:
            return None
        observations.extend(current)
    return all(observations) if observations else None


def _python_binding_observations(source: bytes) -> list[bool] | None:
    try:
        tree = ast.parse(source.decode("utf-8", errors="strict"))
    except (SyntaxError, UnicodeError, ValueError):
        return None
    result: list[bool] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr.casefold() not in {"execute", "query", "raw", "exec"}:
            continue
        has_parameter_keyword = any(
            keyword.arg in {"params", "parameters"} for keyword in node.keywords
        )
        result.append(len(node.args) >= 2 or has_parameter_keyword)
    return result


def _lexical_binding_observations(source: bytes) -> list[bool] | None:
    result: list[bool] = []
    for match in _SQL_SINK_CALL.finditer(source):
        count = _top_level_argument_count(source, match.end() - 1)
        if count is None:
            return None
        result.append(count >= 2)
    return result


def _top_level_argument_count(source: bytes, opening: int) -> int | None:
    depth = 1
    commas = 0
    has_content = False
    quote: int | None = None
    escaped = False
    index = opening + 1
    while index < len(source):
        byte = source[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == quote:
                quote = None
            index += 1
            continue
        if byte in {34, 39, 96}:
            quote = byte
            has_content = True
        elif byte in {40, 91, 123}:
            depth += 1
            has_content = True
        elif byte in {41, 93, 125}:
            depth -= 1
            if depth == 0:
                return commas + 1 if has_content else 0
            if depth < 0:
                return None
        elif byte == 44 and depth == 1:
            commas += 1
        elif not chr(byte).isspace():
            has_content = True
        index += 1
    return None


def _edge(value: object) -> EvidenceGraphEdge:
    item = _mapping(value)
    source = _mapping(item.get("source"))
    target = _mapping(item.get("target"))
    if (
        set(item) != {"kind", "source", "target"}
        or set(source) != {"kind", "node_id"}
        or set(target) != {"kind", "node_id"}
    ):
        raise LocalRepairContractError("EVIDENCE_GRAPH_INVALID")
    return EvidenceGraphEdge(
        EvidenceEdgeKind(item["kind"]),
        EvidenceNodeRef(EvidenceNodeKind(source["kind"]), source["node_id"]),
        EvidenceNodeRef(EvidenceNodeKind(target["kind"]), target["node_id"]),
    )


def _mapping(value: object) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise LocalRepairContractError("EVIDENCE_GRAPH_INVALID")
    return dict(value)


def _closed_json(raw: bytes) -> dict[str, Any]:
    def closed(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if type(key) is not str or key in result or "\x00" in key:
                raise LocalRepairContractError("EVIDENCE_GRAPH_INVALID")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=closed)
    except LocalRepairContractError:
        raise
    except Exception:
        raise LocalRepairContractError("EVIDENCE_GRAPH_INVALID") from None
    return _mapping(value)


__all__ = [
    "LocalRepairBinding",
    "LocalRepairContractError",
    "build_local_repair_binding",
    "confirmed_blocking_findings",
    "parse_retained_graph",
]
