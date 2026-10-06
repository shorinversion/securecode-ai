"""First-party static facts through the existing isolated scanner worker.

Repository code is parsed, never imported or executed. This process boundary
does not qualify an OCI sandbox or a full SAST baseline.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic_ns

from securecode_ai.contracts import (
    DataClass,
    Evidence,
    EvidenceKind,
    ProducerRef,
    RawSignal,
    TrustLabel,
)
from securecode_ai.core.evidence_graph import (
    EvidenceGraph,
)
from securecode_ai.core.model_discovery import RepositoryToolSession
from securecode_ai.core.program_graph import ProgramGraph
from securecode_ai.core.repository import RepositoryFile
from securecode_ai.core.scanning import (
    ScannerBudget,
    ScannerExecution,
    ScannerIdentity,
    ScannerPluginOutput,
    ScannerRequest,
    ScannerRunStatus,
    ScannerWorkerTarget,
)
from securecode_ai.core.tool_policy import (
    RepositoryToolBudget,
    RepositoryToolGuard,
    RepositoryToolScope,
    RepositoryView,
)

from .masked_sources import MaskedSourceView
from .native_sources import NativeSourceCatalogue
from .product_scanner_evidence import _scanner_graph_from_signals
from .product_scanner_graph import (
    _catalogue_language_inventory_matches,
    _program_graph_call_facts,
    _program_graph_facts_match_receipts,
    _program_graph_scanner_results,
)
from .product_scanner_manifest import (
    SCANNER_SOURCE_NAMES,
    build_first_party_scanner_producer,
)
from .product_scanner_worker_common import FirstPartyStaticWorker as _FirstPartyStaticWorker
from .program_graph import build_program_graph
from .repository_view import SealedRepositoryView
from .scanner_plugin import ScannerPluginBinding, register_scanner_worker, run_scanner_plugin

_FIRST_PARTY_SCANNER_SOURCES = SCANNER_SOURCE_NAMES


def first_party_scanner_producer() -> ProducerRef:
    """Pin every host-installed parser and detector implementation source."""
    return build_first_party_scanner_producer(Path(__file__).resolve().parent)


class FirstPartyStaticWorker(_FirstPartyStaticWorker):
    """Compatibility facade preserving the historical worker class path."""

    def scan(self, request: ScannerRequest) -> ScannerPluginOutput:
        return self._scan(request, first_party_scanner_producer())


def create_first_party_static_worker() -> FirstPartyStaticWorker:
    return FirstPartyStaticWorker()


@dataclass(frozen=True, slots=True)
class ProductScannerSourceBinding:
    """Actual invocation inputs retained without source bytes."""

    request_id: str
    tenant_id: str
    repository_id: str
    head_sha: str
    path: str
    size_bytes: int
    content_sha256: str
    producer_sha256: str


@dataclass(frozen=True, slots=True)
class ProductDeterministicScanResult:
    graph: EvidenceGraph
    receipts: tuple[ScannerExecution, ...]
    is_complete: bool
    source_aliases: tuple[tuple[str, bytes, str], ...] = field(repr=False)
    source_bindings: tuple[ProductScannerSourceBinding, ...] = ()
    program_graph: ProgramGraph | None = None
    repository_id: str | None = None

    def repository_view(self, catalogue: NativeSourceCatalogue) -> SealedRepositoryView:
        index_repository_ids = {index.repository_id for index in catalogue.indexes}
        if (
            type(self.repository_id) is not str
            or not self.repository_id
            or (index_repository_ids and index_repository_ids != {self.repository_id})
            or self.graph.head_sha != catalogue.snapshot.head_sha
            or any(anchor.tenant_id != self.graph.tenant_id for anchor in catalogue.anchors)
        ):
            raise ValueError("deterministic source view binding is invalid")
        files = {file.path: file for file in catalogue.snapshot.files}
        aliases = {
            evidence_id: (content, digest) for evidence_id, content, digest in self.source_aliases
        }
        source_records = {
            record.evidence_id for record in self.graph.evidence if record.artifact_ref is not None
        }
        if len(aliases) != len(self.source_aliases) or set(aliases) != source_records:
            raise ValueError("deterministic source aliases are invalid")
        for record in self.graph.evidence:
            if record.evidence_kind is EvidenceKind.DATA_FLOW:
                if (
                    record.data_class is not DataClass.INTERNAL_METADATA
                    or record.trust_label is not TrustLabel.UNTRUSTED_TOOL_OUTPUT
                    or (
                        record.location is not None
                        and (
                            files.get(record.location.path) is None
                            or files[record.location.path].content_sha256
                            != record.location.content_sha256
                        )
                    )
                ):
                    raise ValueError("deterministic flow metadata is invalid")
                if record.artifact_ref is None:
                    continue
                content, digest = aliases[record.evidence_id]
                if (
                    record.artifact_ref.tenant_id != self.graph.tenant_id
                    or record.artifact_ref.data_class is not DataClass.INTERNAL_METADATA
                    or record.artifact_ref.content_sha256 != digest
                    or record.artifact_ref.size_bytes != len(content)
                    or hashlib.sha256(content).hexdigest() != digest
                ):
                    raise ValueError("deterministic flow artifact is invalid")
                continue
            if record.artifact_ref is None:
                if (
                    record.evidence_kind is not EvidenceKind.SOURCE_LOCATION
                    or record.location is None
                    or record.data_class is not DataClass.INTERNAL_METADATA
                    or record.trust_label is not TrustLabel.UNTRUSTED_TOOL_OUTPUT
                ):
                    raise ValueError("deterministic source location is invalid")
                file = files.get(record.location.path)
                if file is None or record.location.content_sha256 != file.content_sha256:
                    raise ValueError("deterministic source location is invalid")
                continue
            file = files.get(record.location.path) if record.location else None
            content, digest = aliases[record.evidence_id]
            if (
                file is None
                or record.location is None
                or record.location.content_sha256 != file.content_sha256
                or record.artifact_ref is None
                or record.artifact_ref.tenant_id != self.graph.tenant_id
                or record.artifact_ref.content_sha256 != digest
                or record.artifact_ref.size_bytes != len(content)
                or hashlib.sha256(content).hexdigest() != digest
            ):
                raise ValueError("deterministic source bytes are invalid")
        native = tuple(
            (
                anchor.evidence_id,
                catalogue._window_bytes(anchor),
                anchor.read_artifact.content_sha256,
            )
            for anchor in catalogue.anchors
        )
        return SealedRepositoryView(catalogue.indexes, evidence=(*native, *self.source_aliases))


def scan_product_sources(
    catalogue: NativeSourceCatalogue,
    *,
    tenant_id: str,
    repository_id: str | None = None,
    total_budget_ns: int = 60_000_000_000,
) -> ProductDeterministicScanResult:
    if (
        type(catalogue) is not NativeSourceCatalogue
        or (repository_id is not None and (type(repository_id) is not str or not repository_id))
        or type(total_budget_ns) is not int
        or not (0 < total_budget_ns <= 60_000_000_000)
    ):
        raise ValueError("product scanner request is invalid")
    index_repository_ids = {index.repository_id for index in catalogue.indexes}
    if len(index_repository_ids) > 1 or (
        repository_id is not None
        and index_repository_ids
        and index_repository_ids != {repository_id}
    ):
        raise ValueError("product scanner repository binding is invalid")
    result_repository_id = repository_id or next(iter(index_repository_ids), None)
    language_inventory_bound = _catalogue_language_inventory_matches(catalogue) and all(
        index.revision == catalogue.snapshot.head_sha
        and index.repository_id == result_repository_id
        for index in catalogue.indexes
    )
    started = monotonic_ns()
    catalogue.repository_view()  # Validate and seal all source/window bindings before workers.
    if any(anchor.tenant_id != tenant_id for anchor in catalogue.anchors):
        raise ValueError("product scanner tenant is invalid")
    producer = first_party_scanner_producer()
    target = ScannerWorkerTarget(__name__, "create_first_party_static_worker")
    register_scanner_worker(target, create_first_party_static_worker)
    binding = ScannerPluginBinding(ScannerIdentity(producer), target)
    receipts = []
    source_bindings = []
    signals: list[RawSignal] = []
    complete = language_inventory_bound
    for index in catalogue.indexes:
        remaining = total_budget_ns - (monotonic_ns() - started)
        if remaining <= 0:
            complete = False
            break
        request = ScannerRequest(
            request_id="static-" + hashlib.sha256(index.path.encode()).hexdigest(),
            tenant_id=tenant_id,
            repository_id=index.repository_id,
            head_sha=index.revision,
            file=RepositoryFile(index.path, len(index.source), index.content_sha256),
            source=index.source,
        )
        receipt = run_scanner_plugin(
            binding, request, budget=ScannerBudget(max_elapsed_ns=remaining)
        )
        receipts.append(receipt)
        source_bindings.append(
            ProductScannerSourceBinding(
                request.request_id,
                request.tenant_id,
                request.repository_id,
                request.head_sha,
                request.file.path,
                request.file.size_bytes,
                request.file.content_sha256,
                producer.producer_sha256,
            )
        )
        if receipt.status is not ScannerRunStatus.SUCCEEDED:
            complete = False
        signals.extend(receipt.signals)
        if monotonic_ns() - started > total_budget_ns:
            complete = False
    complete = (
        complete
        and (bool(catalogue.indexes) or result_repository_id is not None)
        and monotonic_ns() - started <= total_budget_ns
    )
    program_graph = None
    if complete and catalogue.indexes:
        try:
            scanner_results = _program_graph_scanner_results(catalogue)
            if not _program_graph_facts_match_receipts(scanner_results, tuple(receipts)):
                raise ValueError("program graph facts do not match scanner receipts")
            call_facts = _program_graph_call_facts(catalogue)
            program_graph = build_program_graph(catalogue.indexes, scanner_results, call_facts)
        except Exception:
            complete = False
    complete = complete and monotonic_ns() - started <= total_budget_ns
    graph, aliases = _scanner_graph_from_signals(
        catalogue,
        tuple(signals),
        tenant_id,
        producer,
        program_graph=program_graph,
    )
    return ProductDeterministicScanResult(
        graph,
        tuple(receipts),
        complete,
        tuple(aliases),
        tuple(source_bindings),
        program_graph,
        result_repository_id,
    )


def scanner_facts_match_receipts(
    catalogue: NativeSourceCatalogue,
    scan: ProductDeterministicScanResult,
    *,
    repository_id: str | None = None,
) -> bool:
    """Close retained normalized facts over every original scanner signal."""
    try:
        if (
            type(catalogue) is not NativeSourceCatalogue
            or type(scan) is not ProductDeterministicScanResult
            or scan.is_complete is not True
            or (repository_id is not None and (type(repository_id) is not str or not repository_id))
        ):
            return False
        expected_repository_id = repository_id or scan.repository_id
        if (
            type(expected_repository_id) is not str
            or not expected_repository_id
            or scan.repository_id != expected_repository_id
        ):
            return False
        producer = first_party_scanner_producer()
        expected_bindings = tuple(
            ProductScannerSourceBinding(
                "static-" + hashlib.sha256(index.path.encode()).hexdigest(),
                scan.graph.tenant_id,
                index.repository_id,
                index.revision,
                index.path,
                len(index.source),
                index.content_sha256,
                producer.producer_sha256,
            )
            for index in catalogue.indexes
        )
        if scan.source_bindings != expected_bindings or len(scan.receipts) != len(
            expected_bindings
        ):
            return False
        for binding, receipt in zip(expected_bindings, scan.receipts, strict=True):
            if (
                receipt.request_id != binding.request_id
                or receipt.scanner.producer != producer
                or receipt.status is not ScannerRunStatus.SUCCEEDED
                or receipt.input_bytes != binding.size_bytes
                or any(
                    signal.tenant_id != binding.tenant_id
                    or signal.head_sha != binding.head_sha
                    or signal.location.path != binding.path
                    or signal.location.content_sha256 != binding.content_sha256
                    for signal in receipt.signals
                )
            ):
                return False
        if not catalogue.indexes:
            return (
                scan.program_graph is None
                and scan.graph.head_sha == catalogue.snapshot.head_sha
                and _catalogue_language_inventory_matches(catalogue)
                and not scan.receipts
                and not scan.source_bindings
                and not scan.source_aliases
                and not scan.graph.candidates
                and not scan.graph.evidence
                and not scan.graph.edges
            )
        scanner_results = _program_graph_scanner_results(catalogue)
        if (
            type(scan.program_graph) is not ProgramGraph
            or scan.program_graph.repository_id != expected_repository_id
            or scan.program_graph.revision != catalogue.snapshot.head_sha
            or any(
                index.repository_id != expected_repository_id
                or index.revision != scan.program_graph.revision
                for index in catalogue.indexes
            )
            or not _program_graph_facts_match_receipts(scanner_results, scan.receipts)
            or scan.program_graph
            != build_program_graph(
                catalogue.indexes,
                scanner_results,
                _program_graph_call_facts(catalogue),
            )
        ):
            return False
        graph, aliases = _scanner_graph_from_signals(
            catalogue,
            tuple(signal for receipt in scan.receipts for signal in receipt.signals),
            scan.graph.tenant_id,
            first_party_scanner_producer(),
            program_graph=scan.program_graph,
        )
        return graph == scan.graph and aliases == scan.source_aliases
    except Exception:
        return False


def _is_secret_child_payload(payload: bytes) -> bool:
    """Whether a hash-verified child fact records a detected secret."""
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, ValueError):
        return True  # An unreadable fact cannot prove the file is secret-free.
    rule_id = document.get("rule_id") if isinstance(document, dict) else None
    return not isinstance(rule_id, str) or rule_id.startswith("secret-")


def build_product_auditor_tools(
    catalogue: NativeSourceCatalogue,
    graph: EvidenceGraph,
    *,
    budget: RepositoryToolBudget,
    deterministic: ProductDeterministicScanResult | None = None,
    child_artifacts: tuple[tuple[Evidence, bytes], ...] = (),
    denied_source_paths: tuple[str, ...] = (),
    masked_sources: Mapping[str, str] | None = None,
) -> RepositoryToolSession:
    """Admit only graph evidence backed by retained host-owned source mappings.

    A restricted file listed in ``masked_sources`` becomes readable by line range with
    its secret values masked; its raw evidence windows stay unavailable.
    """
    if (
        type(graph) is not EvidenceGraph
        or graph.head_sha != catalogue.snapshot.head_sha
        or any(anchor.tenant_id != graph.tenant_id for anchor in catalogue.anchors)
    ):
        raise ValueError("Auditor source scope is invalid")
    native = {anchor.evidence_id: anchor for anchor in catalogue.anchors}
    static = {}
    if deterministic is not None:
        if (
            type(deterministic) is not ProductDeterministicScanResult
            or deterministic.graph.head_sha != graph.head_sha
            or deterministic.graph.tenant_id != graph.tenant_id
        ):
            raise ValueError("Auditor deterministic source scope is invalid")
        index_repository_ids = {index.repository_id for index in catalogue.indexes}
        if (
            type(deterministic.repository_id) is not str
            or not deterministic.repository_id
            or (index_repository_ids and index_repository_ids != {deterministic.repository_id})
        ):
            raise ValueError("Auditor deterministic repository scope is invalid")
        static = {record.evidence_id: record for record in deterministic.graph.evidence}
    children = {}
    aliases = []
    secret_paths: set[str] = set()
    files = {file.path: file for file in catalogue.snapshot.files}
    for record, payload in child_artifacts:
        artifact = record.artifact_ref
        file = files.get(record.location.path) if record.location is not None else None
        if (
            record.evidence_id in children
            or record.tenant_id != graph.tenant_id
            or record.head_sha != graph.head_sha
            or record.evidence_kind is not EvidenceKind.SCANNER_SIGNAL
            or record.data_class
            not in {
                DataClass.INTERNAL_METADATA,
                DataClass.CONFIDENTIAL_SOURCE,
                DataClass.RESTRICTED,
            }
            or artifact is None
            or artifact.tenant_id != graph.tenant_id
            or artifact.data_class is not record.data_class
            or hashlib.sha256(payload).hexdigest() != artifact.content_sha256
            or record.evidence_sha256 != artifact.content_sha256
            or len(payload) != artifact.size_bytes
            or file is None
            or record.location is None
            or record.location.content_sha256 != file.content_sha256
        ):
            raise ValueError("Auditor child artifact is invalid")
        children[record.evidence_id] = record
        if record.data_class is not DataClass.RESTRICTED:
            aliases.append((record.evidence_id, payload, artifact.content_sha256))
        if _is_secret_child_payload(payload):
            secret_paths.add(record.location.path)
    restricted_paths = {
        record.location.path
        for record in graph.evidence
        if record.data_class is DataClass.RESTRICTED and record.location is not None
    }
    # A secret projection holds no secret value (at most masked lines), but the file it
    # points at still holds the secret: never let model tools read it raw.
    restricted_paths.update(secret_paths)
    if any(path not in files for path in denied_source_paths):
        raise ValueError("Auditor denied source scope is invalid")
    restricted_paths.update(denied_source_paths)
    masked = dict(masked_sources or {})
    if any(path not in files for path in masked):
        raise ValueError("Auditor masked source scope is invalid")
    masked_windows = [
        anchor.read_artifact
        for anchor in catalogue.anchors
        if anchor.location.path in catalogue.masked_paths
    ]
    paths = set()
    admitted_ids = set()
    for record in graph.evidence:
        anchor = native.get(record.evidence_id)
        if anchor is not None:
            if (
                record.location != anchor.location
                or record.artifact_ref != anchor.read_artifact
                or record.evidence_kind is not EvidenceKind.SOURCE_LOCATION
                or record.data_class is not anchor.read_artifact.data_class
                or record.trust_label is not TrustLabel.UNTRUSTED_REPOSITORY
            ):
                raise ValueError("Auditor native source scope is invalid")
        elif (
            static.get(record.evidence_id) != record and children.get(record.evidence_id) != record
        ):
            raise ValueError("Auditor evidence alias is not admitted")
        if record.evidence_id in static and record.evidence_kind is EvidenceKind.DATA_FLOW:
            if (
                record.data_class is not DataClass.INTERNAL_METADATA
                or record.trust_label is not TrustLabel.UNTRUSTED_TOOL_OUTPUT
            ):
                raise ValueError("Auditor flow metadata is invalid")
            admitted_ids.add(record.evidence_id)
            continue
        if record.evidence_id in static and record.artifact_ref is None:
            if (
                record.evidence_kind is not EvidenceKind.SOURCE_LOCATION
                or record.location is None
                or record.data_class is not DataClass.INTERNAL_METADATA
                or record.trust_label is not TrustLabel.UNTRUSTED_TOOL_OUTPUT
            ):
                raise ValueError("Auditor source location is invalid")
            file = files.get(record.location.path)
            if file is None or record.location.content_sha256 != file.content_sha256:
                raise ValueError("Auditor source location is invalid")
            if record.location.path not in restricted_paths:
                paths.add(record.location.path)
                admitted_ids.add(record.evidence_id)
            elif record.location.path in masked:
                paths.add(record.location.path)
            continue
        if record.location is None:
            raise ValueError("Auditor source location is unavailable")
        if record.data_class is DataClass.RESTRICTED:
            continue
        if record.location.path in restricted_paths:
            # Native windows of a masked file are bound to the masked text; scanner
            # windows of the same file still hold raw bytes and stay unavailable.
            # In a masked file, scanner windows are bound to masked text and scanner
            # location metadata holds positions only; both are safe to read.
            if record.evidence_id in children or (
                record.location.path in catalogue.masked_paths
                and record.artifact_ref is not None
                and (
                    record.artifact_ref in masked_windows
                    or (
                        record.evidence_id in static
                        and record.data_class is DataClass.INTERNAL_METADATA
                        and record.artifact_ref.data_class is DataClass.INTERNAL_METADATA
                    )
                )
            ):
                admitted_ids.add(record.evidence_id)
            if record.location.path in masked:
                paths.add(record.location.path)
            continue
        if record.evidence_id in children:
            admitted_ids.add(record.evidence_id)
            continue
        paths.add(record.location.path)
        admitted_ids.add(record.evidence_id)
    backend = (
        deterministic.repository_view(catalogue) if deterministic else catalogue.repository_view()
    )
    if aliases:
        native_aliases = tuple(
            (
                anchor.evidence_id,
                catalogue._window_bytes(anchor),
                anchor.read_artifact.content_sha256,
            )
            for anchor in catalogue.anchors
        )
        static_aliases = deterministic.source_aliases if deterministic else ()
        backend = SealedRepositoryView(
            catalogue.indexes, evidence=(*native_aliases, *static_aliases, *aliases)
        )
    readable_masked = {path: masked[path] for path in masked if path in paths}
    view: RepositoryView = (
        MaskedSourceView(backend, readable_masked, head_sha=graph.head_sha)
        if readable_masked
        else backend
    )
    scope = RepositoryToolScope(
        graph.tenant_id,
        catalogue.indexes[0].repository_id if catalogue.indexes else "empty-repository",
        graph.head_sha,
        tuple(sorted(paths)),
        tuple(sorted(admitted_ids)),
    )
    return RepositoryToolSession(
        guard=RepositoryToolGuard(scope=scope, budget=budget), backend=view
    )
