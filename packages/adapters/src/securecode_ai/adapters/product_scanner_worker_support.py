"""Shared first-party worker conversion helpers."""

from __future__ import annotations

import hashlib
import re

from securecode_ai.contracts import (
    CommandOperation,
    CommandOperationEvidence,
    DataClass,
    ProducerRef,
    RawSignal,
    SourceLocation,
    SourcePosition,
)
from securecode_ai.core import SourceRange
from securecode_ai.core.scanning import ScannerRequest

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _fact_to_raw_signal(
    *,
    request: ScannerRequest,
    producer: ProducerRef,
    cwe: str,
    detector: str,
    location: SourceRange,
    scan_sha256: str,
    ordinal: int,
    rule_id: str | None = None,
    command_source: SourceRange | None = None,
    command_operation: str | None = None,
    command_detail: str | None = None,
) -> RawSignal:
    """Bind one rule-specific source range to the normal scanner contract."""

    if (
        type(request) is not ScannerRequest
        or type(producer) is not ProducerRef
        or type(location) is not SourceRange
        or type(scan_sha256) is not str
        or _SHA256.fullmatch(scan_sha256) is None
        or type(ordinal) is not int
        or ordinal < 0
        or not _range_matches_request(location, request)
    ):
        raise ValueError("scanner fact does not match its source request")

    start = location.start_point
    end = location.end_point
    source_location = SourceLocation(
        schema_version="0.2.0",
        path=request.file.path,
        start=SourcePosition(schema_version="0.2.0", line=start.row + 1, column=start.column + 1),
        end=SourcePosition(schema_version="0.2.0", line=end.row + 1, column=end.column + 1),
        content_sha256=request.file.content_sha256,
    )
    digest = hashlib.sha256(
        f"{request.tenant_id}:{request.repository_id}:{request.head_sha}:"
        f"{request.file.path}:{cwe}:{detector}:{scan_sha256}:{ordinal}".encode()
    ).hexdigest()
    stable_rule = rule_id or f"{detector.split('@', maxsplit=1)[0]}:{cwe.lower()}"
    command_evidence = None
    if any(value is not None for value in (command_source, command_operation, command_detail)):
        if (
            cwe != "CWE-78"
            or stable_rule != "portfolio-cwe-78"
            or type(command_source) is not SourceRange
            or type(command_operation) is not str
            or type(command_detail) is not str
            or not _range_matches_request(command_source, request)
        ):
            raise ValueError("command operation evidence input is invalid")
        command_start = command_source.start_point
        command_end = command_source.end_point
        command_location = SourceLocation(
            schema_version="0.2.0",
            path=request.file.path,
            start=SourcePosition(
                schema_version="0.2.0",
                line=command_start.row + 1,
                column=command_start.column + 1,
            ),
            end=SourcePosition(
                schema_version="0.2.0",
                line=command_end.row + 1,
                column=command_end.column + 1,
            ),
            content_sha256=request.file.content_sha256,
        )
        command_evidence = CommandOperationEvidence(
            schema_version="0.2.0",
            scanner_signal_id=f"product-{cwe.lower()}-{digest}",
            operation=CommandOperation(command_operation),
            detail=command_detail,
            source=command_location,
            sink=source_location,
        )
    return RawSignal(
        schema_version="0.2.0",
        raw_signal_id=f"product-{cwe.lower()}-{digest}",
        tenant_id=request.tenant_id,
        head_sha=request.head_sha,
        producer=producer,
        rule_id=stable_rule,
        location=source_location,
        payload_classification=DataClass.INTERNAL_METADATA,
        signal_sha256=digest,
        command_operation_evidence=command_evidence,
    )


def _range_matches_request(location: SourceRange, request: ScannerRequest) -> bool:
    source = request.source
    if location.end_byte > len(source):
        return False
    for byte_offset, point in (
        (location.start_byte, location.start_point),
        (location.end_byte, location.end_point),
    ):
        if byte_offset > len(source):
            return False
        line_start = source.rfind(b"\n", 0, byte_offset) + 1
        row = source.count(b"\n", 0, byte_offset)
        if point.row != row or point.column != byte_offset - line_start:
            return False
    return True
