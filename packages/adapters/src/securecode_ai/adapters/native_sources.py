"""Scanner-independent discovery anchors from verified immutable Git bytes."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import PurePosixPath

import tree_sitter_python
from securecode_ai.contracts import (
    ArtifactRef,
    CandidateOrigin,
    DataClass,
    DiscoveryCandidate,
    Evidence,
    EvidenceKind,
    ProducerRef,
    SourceLocation,
    TrustLabel,
)
from securecode_ai.core.evidence_graph import (
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceNodeKind,
    EvidenceNodeRef,
)
from securecode_ai.core.symbols import ParseHealth, SymbolIndex
from securecode_ai.core.tool_policy import (
    TOOL_ARGUMENT_SCHEMA_VERSION,
    ReadRangeArguments,
    RepositoryTool,
    RepositoryToolRequest,
)
from tree_sitter import Language, Parser

from .cst import (
    build_go_symbol_index,
    build_javascript_symbol_index,
    build_python_symbol_index,
    build_typescript_symbol_index,
)
from .cst_ecmascript import _javascript_language, _typescript_language
from .cst_go import _go_language
from .git_snapshot import GitObjectReader, GitRevisionSnapshot, materialize_git_snapshot
from .model import HmacContentIdentifier
from .product_runtime import DiscoveryEvidence
from .repository_view import SealedRepositoryView


def _window_text(source: str, arguments: object) -> str:
    if type(arguments) is not ReadRangeArguments:
        raise ValueError("native evidence window binding is invalid")
    lines = source.split("\n")
    if arguments.end_line > len(lines):
        raise ValueError("native evidence window is outside source")
    text = "\n".join(lines[arguments.start_line - 1 : arguments.end_line])
    if arguments.end_line < len(lines):
        text += "\n"
    return text


@dataclass(frozen=True, slots=True)
class NativeSourceCatalogue:
    snapshot: GitRevisionSnapshot
    indexes: tuple[SymbolIndex, ...]
    anchors: tuple[DiscoveryEvidence, ...]
    data_class: DataClass = DataClass.CONFIDENTIAL_SOURCE
    # (path, source) pairs whose detected secret values are replaced by redaction
    # markers; anchors of these files are bound to the masked windows.
    masked_sources: tuple[tuple[str, str], ...] = ()

    @property
    def masked_paths(self) -> frozenset[str]:
        return frozenset(path for path, _ in self.masked_sources)

    def with_masked_sources(
        self, masked: Mapping[str, str], *, content_key: bytes
    ) -> NativeSourceCatalogue:
        """Return a model-facing catalogue whose anchors in ``masked`` files read masked text.

        Evidence ids, locations and read requests stay the same; only the window bytes,
        and therefore the read artifacts, change. A model can then cite and read such a
        file like any other, without ever receiving the masked values.
        """
        if not masked:
            return self
        files = {file.path: file for file in self.snapshot.files}
        for path, text in masked.items():
            file = files.get(path)
            if (
                file is None
                or type(text) is not str
                or text.count("\n") != file.content.count(b"\n")
                or path in self.masked_paths
            ):
                raise ValueError("native masked source binding is invalid")
        identifier = HmacContentIdentifier(content_key)
        try:
            anchors = []
            for anchor in self.anchors:
                masked_text = masked.get(anchor.location.path)
                if masked_text is None:
                    anchors.append(anchor)
                    continue
                content = _window_text(masked_text, anchor.request.arguments).encode()
                artifact = ArtifactRef(
                    schema_version="0.2.0",
                    tenant_id=anchor.tenant_id,
                    content_id=identifier.identify(tenant_id=anchor.tenant_id, payload=content),
                    content_sha256=hashlib.sha256(content).hexdigest(),
                    size_bytes=len(content),
                    data_class=anchor.read_artifact.data_class,
                )
                anchors.append(replace(anchor, read_artifact=artifact))
        finally:
            identifier.close()
        return replace(
            self,
            anchors=tuple(anchors),
            masked_sources=(*self.masked_sources, *sorted(masked.items())),
        )

    def _window_bytes(self, anchor: DiscoveryEvidence) -> bytes:
        files = {file.path: file for file in self.snapshot.files}
        file = files.get(anchor.location.path)
        if (
            file is None
            or anchor.head_sha != self.snapshot.head_sha
            or file.content_sha256 != anchor.location.content_sha256
            or hashlib.sha256(file.content).hexdigest() != file.content_sha256
            or anchor.source_artifact.content_sha256 != file.content_sha256
            or anchor.source_artifact.size_bytes != len(file.content)
            or type(anchor.request.arguments) is not ReadRangeArguments
        ):
            raise ValueError("native evidence source binding is invalid")
        arguments = anchor.request.arguments
        arguments.__post_init__()
        if arguments.head_sha != self.snapshot.head_sha or arguments.path != file.path:
            raise ValueError("native evidence window binding is invalid")
        masked = dict(self.masked_sources).get(file.path)
        content = _window_text(
            file.content.decode("utf-8") if masked is None else masked, arguments
        ).encode()
        if (
            hashlib.sha256(content).hexdigest() != anchor.read_artifact.content_sha256
            or len(content) != anchor.read_artifact.size_bytes
        ):
            raise ValueError("native evidence window hash is invalid")
        return content

    def repository_view(self) -> SealedRepositoryView:
        return SealedRepositoryView(
            self.indexes,
            evidence=tuple(
                (
                    anchor.evidence_id,
                    self._window_bytes(anchor),
                    anchor.read_artifact.content_sha256,
                )
                for anchor in self.anchors
            ),
        )

    def evidence_records(self, producer: ProducerRef) -> tuple[Evidence, ...]:
        """Host creates immutable source metadata; provider cannot mint provenance."""
        producer = ProducerRef.model_validate_json(producer.model_dump_json())
        records = []
        for anchor in self.anchors:
            self._window_bytes(anchor)
            record = Evidence(
                schema_version="0.2.0",
                evidence_id=anchor.evidence_id,
                tenant_id=anchor.tenant_id,
                head_sha=anchor.head_sha,
                evidence_kind=EvidenceKind.SOURCE_LOCATION,
                producer=producer,
                trust_label=TrustLabel.UNTRUSTED_REPOSITORY,
                data_class=self.data_class,
                evidence_sha256="0" * 64,
                location=anchor.location,
                artifact_ref=anchor.read_artifact,
            )
            material = record.model_dump(mode="json", exclude={"evidence_sha256"})
            encoded = json.dumps(
                ["native-source-record-v1", material],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode()
            material["evidence_sha256"] = hashlib.sha256(encoded).hexdigest()
            records.append(Evidence.model_validate_json(json.dumps(material)))
        return tuple(records)

    def evidence_graph(
        self, *, graph_id: str, candidates: tuple[DiscoveryCandidate, ...], producer: ProducerRef
    ) -> EvidenceGraph:
        """Build only cited source closure; completed-zero has no orphan evidence."""
        if type(candidates) is not tuple or any(
            type(candidate) is not DiscoveryCandidate
            or candidate.candidate_origin is not CandidateOrigin.MODEL_NATIVE
            for candidate in candidates
        ):
            raise ValueError("native graph candidates are invalid")
        records = {item.evidence_id: item for item in self.evidence_records(producer)}
        selected = {
            evidence_id for candidate in candidates for evidence_id in candidate.evidence_ids
        }
        if not selected.issubset(records):
            raise ValueError("native graph cites unknown evidence")
        tenant_ids = {anchor.tenant_id for anchor in self.anchors}
        if len(tenant_ids) != 1:
            raise ValueError("native graph tenant binding is invalid")
        return EvidenceGraph(
            graph_id=graph_id,
            tenant_id=next(iter(tenant_ids)),
            head_sha=self.snapshot.head_sha,
            candidates=candidates,
            evidence=tuple(records[key] for key in sorted(selected)),
            edges=tuple(
                EvidenceGraphEdge(
                    EvidenceEdgeKind.CANDIDATE_EVIDENCE,
                    EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, candidate.candidate_id),
                    EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, evidence_id),
                )
                for candidate in candidates
                for evidence_id in candidate.evidence_ids
            ),
        )


def build_native_source_catalogue(
    *,
    reader: GitObjectReader,
    head_sha: str,
    tenant_id: str,
    repository_id: str,
    content_key: bytes,
    window_lines: int = 100,
    max_anchors: int = 4096,
    data_class: DataClass = DataClass.CONFIDENTIAL_SOURCE,
) -> NativeSourceCatalogue:
    """Reject incomplete intake; never consult scanner findings or mutable checkout.

    File windows ensure zero-call source is inspected. Generic CST call spans add
    independently citable roots; they are syntax locations, not vulnerability labels.
    Host admission of reader and repository scope remains the caller's obligation.
    """
    if (
        type(window_lines) is not int
        or not 1 <= window_lines <= 2000
        or type(max_anchors) is not int
        or not 1 <= max_anchors <= 4096
        or type(tenant_id) is not str
        or not tenant_id
        or type(repository_id) is not str
        or not repository_id
        or type(content_key) is not bytes
        or len(content_key) < 32
        or type(data_class) is not DataClass
        or data_class not in {DataClass.PUBLIC, DataClass.CONFIDENTIAL_SOURCE}
    ):
        raise ValueError("native source intake configuration is invalid")
    identifier = HmacContentIdentifier(content_key)
    snapshot = materialize_git_snapshot(reader, head_sha)
    indexes: list[SymbolIndex] = []
    anchors: list[DiscoveryEvidence] = []
    for file in snapshot.files:
        suffix = PurePosixPath(file.path).suffix.casefold()
        if suffix in (".py", ".pyi"):
            builder, grammar = build_python_symbol_index, tree_sitter_python.language()
        elif suffix in (".js", ".mjs", ".cjs", ".jsx"):
            builder, grammar = build_javascript_symbol_index, _javascript_language()
        elif suffix in (".ts", ".mts", ".cts", ".tsx"):
            builder = build_typescript_symbol_index
            grammar = _typescript_language(tsx=suffix == ".tsx")
        elif suffix == ".go":
            builder, grammar = build_go_symbol_index, _go_language()
        else:
            continue
        index = builder(
            repository_id=repository_id,
            revision=head_sha,
            path=file.path,
            content_sha256=file.content_sha256,
            source=file.content,
        )
        if index.parse_health is not ParseHealth.HEALTHY:
            raise ValueError("native source parse coverage is incomplete")
        indexes.append(index)
        lines = file.content.decode("utf-8", errors="strict").split("\n")
        source = ArtifactRef(
            schema_version="0.2.0",
            tenant_id=tenant_id,
            content_id=identifier.identify(tenant_id=tenant_id, payload=file.content),
            content_sha256=file.content_sha256,
            size_bytes=len(file.content),
            data_class=data_class,
        )
        roots: list[tuple[int, int, int, int]] = []
        for first in range(1, len(lines) + 1, window_lines):
            last = min(first + window_lines - 1, len(lines))
            roots.append((first, 1, last, len(lines[last - 1].encode()) + 1))
        tree = Parser(Language(grammar)).parse(file.content)
        stack = [tree.root_node]
        visited = 0
        while stack:
            node = stack.pop()
            visited += 1
            if visited > 100_000:
                raise ValueError("native syntax anchor traversal exceeds budget")
            if node.type in ("call", "call_expression"):
                roots.append(
                    (
                        node.start_point.row + 1,
                        node.start_point.column + 1,
                        node.end_point.row + 1,
                        node.end_point.column + 1,
                    )
                )
            stack.extend(reversed(node.children))
        for first, column, last, end_column in dict.fromkeys(roots):
            if len(anchors) >= max_anchors:
                raise ValueError("native source anchor coverage exceeds budget")
            window_first = ((first - 1) // window_lines) * window_lines + 1
            window_last = max(last, min(window_first + window_lines - 1, len(lines)))
            if window_last - window_first + 1 > 2000:
                raise ValueError("native source root exceeds window budget")
            text = "\n".join(lines[window_first - 1 : window_last])
            if window_last < len(lines):
                text += "\n"
            content = text.encode()
            artifact = ArtifactRef(
                schema_version="0.2.0",
                tenant_id=tenant_id,
                content_id=identifier.identify(tenant_id=tenant_id, payload=content),
                content_sha256=hashlib.sha256(content).hexdigest(),
                size_bytes=len(content),
                data_class=data_class,
            )
            location = SourceLocation.model_validate_json(
                json.dumps(
                    {
                        "schema_version": "0.2.0",
                        "path": file.path,
                        "start": {"schema_version": "0.2.0", "line": first, "column": column},
                        "end": {"schema_version": "0.2.0", "line": last, "column": end_column},
                        "content_sha256": file.content_sha256,
                    }
                )
            )
            identity = json.dumps(
                [tenant_id, repository_id, head_sha, file.path, first, column, last, end_column],
                separators=(",", ":"),
            ).encode()
            anchors.append(
                DiscoveryEvidence(
                    evidence_id="native-source-" + hashlib.sha256(identity).hexdigest(),
                    tenant_id=tenant_id,
                    head_sha=head_sha,
                    location=location,
                    source_artifact=source,
                    read_artifact=artifact,
                    request=RepositoryToolRequest(
                        RepositoryTool.READ_RANGE,
                        ReadRangeArguments(
                            TOOL_ARGUMENT_SCHEMA_VERSION,
                            head_sha,
                            file.path,
                            window_first,
                            window_last,
                        ),
                    ),
                )
            )
    if not indexes or not anchors:
        raise ValueError("native source supported scope is empty")
    return NativeSourceCatalogue(snapshot, tuple(indexes), tuple(anchors), data_class)
