"""First-party static scanner worker implementation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from securecode_ai.contracts import (
    DataClass,
    ProducerRef,
    RawSignal,
    SourceLocation,
    SourcePosition,
)
from securecode_ai.core.scanning import ScannerPluginOutput, ScannerRequest

from . import (
    cst,
    cwe89,
    cwe89_multilanguage,
    cwe_portfolio,
    ecmascript_cwe306,
    ecmascript_cwe639,
    go_cwe306,
    go_cwe639,
    python_ast,
    python_cwe306,
    python_cwe639,
)
from .product_scanner_worker_ecmascript import scan_ecmascript_rules
from .product_scanner_worker_go import scan_go_rules
from .product_scanner_worker_python import scan_python_rules
from .product_scanner_worker_support import _fact_to_raw_signal


def _scanner_producer() -> ProducerRef:
    from .product_scanner_manifest import build_first_party_scanner_producer

    return build_first_party_scanner_producer(Path(__file__).resolve().parent)


class FirstPartyStaticWorker:
    def scan(self, request: ScannerRequest) -> ScannerPluginOutput:
        return self._scan(request, _scanner_producer())

    def _scan(self, request: ScannerRequest, producer: ProducerRef) -> ScannerPluginOutput:
        suffix = Path(request.file.path).suffix.lower()
        builders = {
            ".py": cst.build_python_symbol_index,
            ".pyi": cst.build_python_symbol_index,
            ".js": cst.build_javascript_symbol_index,
            ".jsx": cst.build_javascript_symbol_index,
            ".mjs": cst.build_javascript_symbol_index,
            ".cjs": cst.build_javascript_symbol_index,
            ".ts": cst.build_typescript_symbol_index,
            ".mts": cst.build_typescript_symbol_index,
            ".cts": cst.build_typescript_symbol_index,
            ".tsx": cst.build_typescript_symbol_index,
            ".go": cst.build_go_symbol_index,
        }
        builder = builders.get(suffix)
        if builder is None:
            raise ValueError("unsupported scanner language")
        index = builder(
            repository_id=request.repository_id,
            revision=request.head_sha,
            path=request.file.path,
            content_sha256=request.file.content_sha256,
            source=request.source,
        )
        signals = list(
            cwe_portfolio.portfolio_signals_to_raw_signals(
                cwe_portfolio.scan_cwe_portfolio(index),
                tenant_id=request.tenant_id,
                producer=producer,
            )
        )
        python_analysis: python_ast.PythonAstAnalysis | None = None
        if index.language == "python":
            python_analysis = python_ast.analyze_python_ast(index)
            signals.extend(
                scan_python_rules(
                    index=index, request=request, producer=producer, analysis=python_analysis
                )
            )
        elif index.language == "go":
            signals.extend(scan_go_rules(index=index, request=request, producer=producer))
        elif index.language in {"javascript", "typescript"}:
            signals.extend(scan_ecmascript_rules(index=index, request=request, producer=producer))
        authorization: (
            python_cwe639.PythonCwe639ScanResult
            | go_cwe639.GoCwe639ScanResult
            | ecmascript_cwe639.EcmaScriptCwe639ScanResult
        )
        if index.language == "python":
            if python_analysis is None:
                raise ValueError("Python AST analysis is unavailable")
            authorization = python_cwe639.scan_python_cwe639(index, python_analysis)
        elif index.language == "go":
            authorization = go_cwe639.scan_go_cwe639(index)
        else:
            authorization = ecmascript_cwe639.scan_ecmascript_cwe639(index)
        authorization_signals: tuple[
            python_cwe639.PythonCwe639Signal
            | go_cwe639.GoCwe639Signal
            | ecmascript_cwe639.EcmaScriptCwe639Signal,
            ...,
        ] = authorization.signals
        for ordinal, authorization_signal in enumerate(authorization_signals):
            signals.append(
                _fact_to_raw_signal(
                    request=request,
                    producer=producer,
                    cwe=authorization_signal.cwe,
                    detector=authorization_signal.detector,
                    location=authorization_signal.sink,
                    scan_sha256=authorization.scan_sha256,
                    ordinal=ordinal,
                    rule_id=authorization_signal.rule_id,
                )
            )
        critical_authentication: (
            python_cwe306.PythonCwe306ScanResult
            | go_cwe306.GoCwe306ScanResult
            | ecmascript_cwe306.EcmaScriptCwe306ScanResult
            | None
        ) = None
        if index.language == "python":
            if python_analysis is None:
                raise ValueError("Python AST analysis is unavailable")
            critical_authentication = python_cwe306.scan_python_cwe306(index, python_analysis)
        elif index.language == "go":
            critical_authentication = go_cwe306.scan_go_cwe306(index)
        else:
            critical_authentication = ecmascript_cwe306.scan_ecmascript_cwe306(index)
        if critical_authentication is not None:
            critical_authentication_signals: tuple[
                python_cwe306.PythonCwe306Signal
                | go_cwe306.GoCwe306Signal
                | ecmascript_cwe306.EcmaScriptCwe306Signal,
                ...,
            ] = critical_authentication.signals
            for ordinal, critical_authentication_signal in enumerate(
                critical_authentication_signals
            ):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=critical_authentication_signal.cwe,
                        detector=critical_authentication_signal.detector,
                        location=critical_authentication_signal.sink,
                        scan_sha256=critical_authentication.scan_sha256,
                        ordinal=ordinal,
                        rule_id=critical_authentication_signal.rule_id,
                    )
                )
        sql: cwe89.Cwe89ScanResult | cwe89_multilanguage.MultilanguageCwe89ScanResult
        if index.language == "python":
            if python_analysis is None:
                raise ValueError("Python AST analysis is unavailable")
            sql = cwe89.scan_python_cwe89(index, python_analysis)
        else:
            scanners = {
                "javascript": cwe89_multilanguage.scan_javascript_cwe89,
                "typescript": cwe89_multilanguage.scan_typescript_cwe89,
                "go": cwe89_multilanguage.scan_go_cwe89,
            }
            sql = scanners[index.language](index)
        sql_signals: tuple[
            cwe89.Cwe89Signal | cwe89_multilanguage.MultilanguageCwe89Signal, ...
        ] = sql.signals
        for ordinal, signal in enumerate(sql_signals):
            location = SourceLocation(
                schema_version="0.2.0",
                path=signal.path,
                start=SourcePosition(
                    schema_version="0.2.0",
                    line=signal.sink.start_point.row + 1,
                    column=signal.sink.start_point.column + 1,
                ),
                end=SourcePosition(
                    schema_version="0.2.0",
                    line=signal.sink.end_point.row + 1,
                    column=signal.sink.end_point.column + 1,
                ),
                content_sha256=signal.content_sha256,
            )
            material = [
                "product-sql-fact-v1",
                request.tenant_id,
                request.repository_id,
                request.head_sha,
                sql.scan_sha256,
                ordinal,
                producer.model_dump(mode="json"),
            ]
            digest = hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()
            signals.append(
                RawSignal(
                    schema_version="0.2.0",
                    raw_signal_id="product-sql-" + digest,
                    tenant_id=request.tenant_id,
                    head_sha=request.head_sha,
                    producer=producer,
                    rule_id="cwe-89-sql-interpolation",
                    location=location,
                    payload_classification=DataClass.INTERNAL_METADATA,
                    signal_sha256=digest,
                )
            )
        return ScannerPluginOutput(tuple(sorted(signals, key=lambda item: item.raw_signal_id)))
