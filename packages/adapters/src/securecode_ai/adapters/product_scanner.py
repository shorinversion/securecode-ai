"""First-party static facts through the existing isolated scanner worker.

Repository code is parsed, never imported or executed. This process boundary
does not qualify an OCI sandbox or a full SAST baseline.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic_ns

from securecode_ai.contracts import (
    DataClass,
    DiscoveryCandidate,
    Evidence,
    EvidenceKind,
    ProducerRef,
    RawSignal,
    SourceLocation,
    SourcePosition,
    TrustLabel,
)
from securecode_ai.core import SourceRange
from securecode_ai.core.evidence_graph import (
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceNodeKind,
    EvidenceNodeRef,
)
from securecode_ai.core.model_discovery import RepositoryToolSession
from securecode_ai.core.normalization import normalize_signals
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
    ReadRangeArguments,
    RepositoryToolBudget,
    RepositoryToolGuard,
    RepositoryToolScope,
)

from . import (
    cst,
    cwe89,
    cwe89_multilanguage,
    cwe_portfolio,
    ecmascript_cwe1321,
    ecmascript_cwe22,
    ecmascript_cwe295,
    ecmascript_cwe1333,
    ecmascript_cwe367,
    ecmascript_cwe611,
    ecmascript_cwe377,
    ecmascript_cwe732,
    ecmascript_cwe117,
    ecmascript_cwe400,
    ecmascript_cwe307,
    ecmascript_cwe532,
    ecmascript_cwe776,
    ecmascript_cwe209,
    ecmascript_cwe613,
    ecmascript_cwe338,
    ecmascript_cwe521,
    ecmascript_cwe798,
    ecmascript_cwe502,
    ecmascript_cwe601,
    ecmascript_cwe78,
    ecmascript_cwe79,
    ecmascript_cwe90,
    ecmascript_cwe918,
    ecmascript_cwe94,
    go_cwe22,
    go_cwe295,
    go_cwe367,
    go_cwe400,
    go_cwe307,
    go_cwe327,
    go_cwe532,
    go_cwe776,
    go_cwe209,
    go_cwe613,
    go_cwe338,
    go_cwe521,
    go_cwe798,
    go_cwe502,
    go_cwe1333,
    go_cwe601,
    go_cwe78,
    go_cwe79,
    go_cwe90,
    go_cwe918,
    go_cwe_crypto,
    python_ast,
    python_cwe502,
    python_cwe295,
    python_cwe614,
    python_cwe732,
    python_cwe384,
    python_cwe117,
    python_cwe307,
    python_cwe327,
    python_cwe400,
    python_cwe532,
    python_cwe776,
    python_cwe209,
    python_cwe613,
    python_cwe338,
    python_cwe521,
    python_cwe798,
    python_cwe601,
    python_cwe78,
    python_cwe79,
    python_cwe90,
    python_cwe918,
    python_cwe94,
)
from .native_sources import NativeSourceCatalogue
from .repository_view import SealedRepositoryView
from .scanner_plugin import ScannerPluginBinding, register_scanner_worker, run_scanner_plugin

_FIRST_PARTY_SCANNER_SOURCES = (
    "product_scanner.py",
    "cst.py",
    "cst_ecmascript.py",
    "cst_go.py",
    "cst_models.py",
    "cst_python.py",
    "cwe89.py",
    "cwe89_contracts.py",
    "cwe89_multilanguage.py",
    "cwe89_multilanguage_models.py",
    "cwe89_multilanguage_scanner.py",
    "cwe89_multilanguage_utilities.py",
    "cwe_portfolio.py",
    "cwe_portfolio_helpers.py",
    "cwe_portfolio_models.py",
    "ecmascript_cwe1321.py",
    "ecmascript_cwe22.py",
    "ecmascript_cwe295.py",
    "ecmascript_cwe1333.py",
    "ecmascript_cwe377.py",
    "ecmascript_cwe367.py",
    "ecmascript_cwe611.py",
    "ecmascript_cwe732.py",
    "ecmascript_cwe117.py",
    "ecmascript_cwe400.py",
    "ecmascript_cwe307.py",
    "ecmascript_cwe532.py",
    "ecmascript_cwe776.py",
    "ecmascript_cwe209.py",
    "ecmascript_cwe613.py",
    "ecmascript_cwe338.py",
    "ecmascript_cwe521.py",
    "ecmascript_cwe798.py",
    "ecmascript_cwe502.py",
    "ecmascript_cwe601.py",
    "ecmascript_cwe78.py",
    "ecmascript_cwe79.py",
    "ecmascript_cwe90.py",
    "ecmascript_cwe918.py",
    "ecmascript_cwe94.py",
    "go_cwe22.py",
    "go_cwe295.py",
    "go_cwe367.py",
    "go_cwe400.py",
    "go_cwe307.py",
    "go_cwe327.py",
    "go_cwe532.py",
    "go_cwe776.py",
    "go_cwe209.py",
    "go_cwe613.py",
    "go_cwe338.py",
    "go_cwe521.py",
    "go_cwe798.py",
    "go_cwe502.py",
    "go_cwe1333.py",
    "go_cwe601.py",
    "go_cwe78.py",
    "go_cwe79.py",
    "go_cwe90.py",
    "go_cwe918.py",
    "go_cwe_crypto.py",
    "python_ast.py",
    "python_cwe502.py",
    "python_cwe295.py",
    "python_cwe614.py",
    "python_cwe732.py",
    "python_cwe384.py",
    "python_cwe117.py",
    "python_cwe307.py",
    "python_cwe327.py",
    "python_cwe400.py",
    "python_cwe532.py",
    "python_cwe776.py",
    "python_cwe209.py",
    "python_cwe613.py",
    "python_cwe338.py",
    "python_cwe521.py",
    "python_cwe798.py",
    "python_cwe611.py",
    "python_cwe1333.py",
    "python_cwe601.py",
    "python_cwe78.py",
    "python_cwe79.py",
    "python_cwe90.py",
    "python_cwe918.py",
    "python_cwe94.py",
    "scanner_plugin.py",
)


def first_party_scanner_producer() -> ProducerRef:
    """Pin every host-installed parser and detector implementation source."""
    root = Path(__file__).resolve().parent
    manifest = [
        (name, hashlib.sha256((root / name).read_bytes()).hexdigest())
        for name in _FIRST_PARTY_SCANNER_SOURCES
    ]
    digest = hashlib.sha256(json.dumps(manifest, separators=(",", ":")).encode()).hexdigest()
    return ProducerRef(
        schema_version="0.2.0",
        producer_id="securecode-first-party-static",
        producer_version="1.0.0",
        producer_sha256=digest,
    )


class FirstPartyStaticWorker:
    def scan(self, request: ScannerRequest) -> ScannerPluginOutput:
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
        producer = first_party_scanner_producer()
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
            credentials = python_cwe798.scan_python_cwe798(index, python_analysis)
            for ordinal, signal in enumerate(credentials.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=credentials.scan_sha256,
                        ordinal=ordinal,
                        rule_id=signal.rule_id,
                    )
                )
            password_policy = python_cwe521.scan_python_cwe521(index, python_analysis)
            for ordinal, signal in enumerate(password_policy.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=password_policy.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            weak_randomness = python_cwe338.scan_python_cwe338(index, python_analysis)
            for ordinal, signal in enumerate(weak_randomness.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=weak_randomness.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            session_expiration = python_cwe613.scan_python_cwe613(index, python_analysis)
            for ordinal, signal in enumerate(session_expiration.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=session_expiration.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            error_disclosure = python_cwe209.scan_python_cwe209(index, python_analysis)
            for ordinal, signal in enumerate(error_disclosure.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=error_disclosure.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            xml_expansion = python_cwe776.scan_python_cwe776(index, python_analysis)
            for ordinal, signal in enumerate(xml_expansion.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=xml_expansion.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            sensitive_logging = python_cwe532.scan_python_cwe532(index, python_analysis)
            for ordinal, signal in enumerate(sensitive_logging.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=sensitive_logging.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            weak_crypto = python_cwe327.scan_python_cwe327(index, python_analysis)
            for ordinal, signal in enumerate(weak_crypto.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=weak_crypto.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            resource_consumption = python_cwe400.scan_python_cwe400(index, python_analysis)
            for ordinal, signal in enumerate(resource_consumption.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=resource_consumption.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            rate_limit = python_cwe307.scan_python_cwe307(index, python_analysis)
            for ordinal, signal in enumerate(rate_limit.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=rate_limit.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            log_injection = python_cwe117.scan_python_cwe117(index, python_analysis)
            for ordinal, signal in enumerate(log_injection.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=log_injection.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            session_fixation = python_cwe384.scan_python_cwe384(index, python_analysis)
            for ordinal, signal in enumerate(session_fixation.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=session_fixation.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            file_permissions = python_cwe732.scan_python_cwe732(index, python_analysis)
            for ordinal, signal in enumerate(file_permissions.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=file_permissions.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            cookie_security = python_cwe614.scan_python_cwe614(index, python_analysis)
            for ordinal, signal in enumerate(cookie_security.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=cookie_security.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            tls_validation = python_cwe295.scan_python_cwe295(index, python_analysis)
            for ordinal, signal in enumerate(tls_validation.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=tls_validation.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            redirects = python_cwe601.scan_python_cwe601(index, python_analysis)
            for ordinal, signal in enumerate(redirects.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=redirects.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            commands = python_cwe78.scan_python_cwe78(index, python_analysis)
            for ordinal, signal in enumerate(commands.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=commands.scan_sha256,
                        ordinal=ordinal,
                        rule_id="portfolio-cwe-78",
                    )
                )
            xss = python_cwe79.scan_python_cwe79(index, python_analysis)
            for ordinal, signal in enumerate(xss.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=xss.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            regex_dos = python_cwe1333.scan_python_cwe1333(index, python_analysis)
            for ordinal, signal in enumerate(regex_dos.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=regex_dos.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            deserialization = python_cwe502.scan_python_cwe502(index, python_analysis)
            for ordinal, signal in enumerate(deserialization.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=deserialization.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            xml = python_cwe611.scan_python_cwe611(index, python_analysis)
            for ordinal, signal in enumerate(xml.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=xml.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            ldap = python_cwe90.scan_python_cwe90(index, python_analysis)
            for ordinal, signal in enumerate(ldap.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=ldap.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            ssrf = python_cwe918.scan_python_cwe918(index, python_analysis)
            for ordinal, signal in enumerate(ssrf.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=ssrf.scan_sha256,
                        ordinal=ordinal,
                        rule_id="portfolio-cwe-918",
                    )
                )
            python_scan = python_cwe94.scan_python_cwe94(index, python_analysis)
            for ordinal, signal in enumerate(python_scan.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=python_scan.scan_sha256,
                        ordinal=ordinal,
                    )
                )
        elif index.language == "go":
            credentials = go_cwe798.scan_go_cwe798(index)
            for ordinal, signal in enumerate(credentials.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=credentials.scan_sha256,
                        ordinal=ordinal,
                        rule_id=signal.rule_id,
                    )
                )
            password_policy = go_cwe521.scan_go_cwe521(index)
            for ordinal, signal in enumerate(password_policy.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=password_policy.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            weak_randomness = go_cwe338.scan_go_cwe338(index)
            for ordinal, signal in enumerate(weak_randomness.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=weak_randomness.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            session_expiration = go_cwe613.scan_go_cwe613(index)
            for ordinal, signal in enumerate(session_expiration.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=session_expiration.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            error_disclosure = go_cwe209.scan_go_cwe209(index)
            for ordinal, signal in enumerate(error_disclosure.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=error_disclosure.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            xml_expansion = go_cwe776.scan_go_cwe776(index)
            for ordinal, signal in enumerate(xml_expansion.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=xml_expansion.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            sensitive_logging = go_cwe532.scan_go_cwe532(index)
            for ordinal, signal in enumerate(sensitive_logging.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=sensitive_logging.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            rate_limit = go_cwe307.scan_go_cwe307(index)
            for ordinal, signal in enumerate(rate_limit.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=rate_limit.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            weak_crypto = go_cwe327.scan_go_cwe327(index)
            for ordinal, signal in enumerate(weak_crypto.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=weak_crypto.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            resource_consumption = go_cwe400.scan_go_cwe400(index)
            for ordinal, signal in enumerate(resource_consumption.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=resource_consumption.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            toctou = go_cwe367.scan_go_cwe367(index)
            for ordinal, signal in enumerate(toctou.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=toctou.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            regex_dos = go_cwe1333.scan_go_cwe1333(index)
            for ordinal, signal in enumerate(regex_dos.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=regex_dos.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            tls_validation = go_cwe295.scan_go_cwe295(index)
            for ordinal, signal in enumerate(tls_validation.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=tls_validation.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            deserialization = go_cwe502.scan_go_cwe502(index)
            for ordinal, signal in enumerate(deserialization.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=deserialization.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            xss = go_cwe79.scan_go_cwe79(index)
            for ordinal, signal in enumerate(xss.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=xss.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            redirects = go_cwe601.scan_go_cwe601(index)
            for ordinal, signal in enumerate(redirects.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=redirects.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            commands = go_cwe78.scan_go_cwe78(index)
            for ordinal, signal in enumerate(commands.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=commands.scan_sha256,
                        ordinal=ordinal,
                        rule_id="portfolio-cwe-78",
                    )
                )
            ldap = go_cwe90.scan_go_cwe90(index)
            for ordinal, signal in enumerate(ldap.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=ldap.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            crypto = go_cwe_crypto.scan_go_cwe_crypto(index)
            for ordinal, signal in enumerate(crypto.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=crypto.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            paths = go_cwe22.scan_go_cwe22(index)
            for ordinal, signal in enumerate(paths.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe="CWE-22",
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=paths.scan_sha256,
                        ordinal=ordinal,
                        rule_id="portfolio-cwe-22",
                    )
                )
            ssrf = go_cwe918.scan_go_cwe918(index)
            for ordinal, signal in enumerate(ssrf.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=ssrf.scan_sha256,
                        ordinal=ordinal,
                        rule_id="portfolio-cwe-918",
                    )
                )
        elif index.language in {"javascript", "typescript"}:
            credentials = ecmascript_cwe798.scan_ecmascript_cwe798(index)
            for ordinal, signal in enumerate(credentials.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=credentials.scan_sha256,
                        ordinal=ordinal,
                        rule_id=signal.rule_id,
                    )
                )
            password_policy = ecmascript_cwe521.scan_ecmascript_cwe521(index)
            for ordinal, signal in enumerate(password_policy.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=password_policy.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            weak_randomness = ecmascript_cwe338.scan_ecmascript_cwe338(index)
            for ordinal, signal in enumerate(weak_randomness.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=weak_randomness.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            session_expiration = ecmascript_cwe613.scan_ecmascript_cwe613(index)
            for ordinal, signal in enumerate(session_expiration.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=session_expiration.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            error_disclosure = ecmascript_cwe209.scan_ecmascript_cwe209(index)
            for ordinal, signal in enumerate(error_disclosure.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=error_disclosure.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            xml_expansion = ecmascript_cwe776.scan_ecmascript_cwe776(index)
            for ordinal, signal in enumerate(xml_expansion.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=xml_expansion.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            sensitive_logging = ecmascript_cwe532.scan_ecmascript_cwe532(index)
            for ordinal, signal in enumerate(sensitive_logging.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=sensitive_logging.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            rate_limit = ecmascript_cwe307.scan_ecmascript_cwe307(index)
            for ordinal, signal in enumerate(rate_limit.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=rate_limit.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            resource_consumption = ecmascript_cwe400.scan_ecmascript_cwe400(index)
            for ordinal, signal in enumerate(resource_consumption.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=resource_consumption.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            log_injection = ecmascript_cwe117.scan_ecmascript_cwe117(index)
            for ordinal, signal in enumerate(log_injection.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=log_injection.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            file_permissions = ecmascript_cwe732.scan_ecmascript_cwe732(index)
            for ordinal, signal in enumerate(file_permissions.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=file_permissions.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            toctou = ecmascript_cwe367.scan_ecmascript_cwe367(index)
            for ordinal, signal in enumerate(toctou.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=toctou.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            xml = ecmascript_cwe611.scan_ecmascript_cwe611(index)
            for ordinal, signal in enumerate(xml.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=xml.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            temporary_files = ecmascript_cwe377.scan_ecmascript_cwe377(index)
            for ordinal, signal in enumerate(temporary_files.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=temporary_files.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            regex_dos = ecmascript_cwe1333.scan_ecmascript_cwe1333(index)
            for ordinal, signal in enumerate(regex_dos.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=regex_dos.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            tls_validation = ecmascript_cwe295.scan_ecmascript_cwe295(index)
            for ordinal, signal in enumerate(tls_validation.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=tls_validation.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            deserialization = ecmascript_cwe502.scan_ecmascript_cwe502(index)
            for ordinal, signal in enumerate(deserialization.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=deserialization.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            commands = ecmascript_cwe78.scan_ecmascript_cwe78(index)
            for ordinal, signal in enumerate(commands.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=commands.scan_sha256,
                        ordinal=ordinal,
                        rule_id="portfolio-cwe-78",
                    )
                )
            xss = ecmascript_cwe79.scan_ecmascript_cwe79(index)
            for ordinal, signal in enumerate(xss.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=xss.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            ldap = ecmascript_cwe90.scan_ecmascript_cwe90(index)
            for ordinal, signal in enumerate(ldap.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=ldap.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            ssrf = ecmascript_cwe918.scan_ecmascript_cwe918(index)
            for ordinal, signal in enumerate(ssrf.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=ssrf.scan_sha256,
                        ordinal=ordinal,
                        rule_id="portfolio-cwe-918",
                    )
                )
            redirects = ecmascript_cwe601.scan_ecmascript_cwe601(index)
            for ordinal, signal in enumerate(redirects.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=redirects.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            prototype_pollution = ecmascript_cwe1321.scan_ecmascript_cwe1321(index)
            for ordinal, signal in enumerate(prototype_pollution.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=prototype_pollution.scan_sha256,
                        ordinal=ordinal,
                    )
                )
            paths = ecmascript_cwe22.scan_ecmascript_cwe22(index)
            for ordinal, signal in enumerate(paths.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe="CWE-22",
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=paths.scan_sha256,
                        ordinal=ordinal,
                        rule_id="portfolio-cwe-22",
                    )
                )
            dynamic_code = ecmascript_cwe94.scan_ecmascript_cwe94(index)
            for ordinal, signal in enumerate(dynamic_code.signals):
                signals.append(
                    _fact_to_raw_signal(
                        request=request,
                        producer=producer,
                        cwe=signal.cwe,
                        detector=signal.detector,
                        location=signal.sink,
                        scan_sha256=dynamic_code.scan_sha256,
                        ordinal=ordinal,
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
) -> RawSignal:
    """Bind one rule-specific source range to the normal scanner contract."""

    start = location.start_point
    end = location.end_point
    source_location = SourceLocation(
        schema_version="0.2.0",
        path=request.file.path,
        start=SourcePosition(
            schema_version="0.2.0", line=start.row + 1, column=start.column + 1
        ),
        end=SourcePosition(
            schema_version="0.2.0", line=end.row + 1, column=end.column + 1
        ),
        content_sha256=request.file.content_sha256,
    )
    digest = hashlib.sha256(
        f"{request.tenant_id}:{request.repository_id}:{request.head_sha}:"
        f"{request.file.path}:{cwe}:{detector}:{scan_sha256}:{ordinal}".encode("utf-8")
    ).hexdigest()
    stable_rule = rule_id or f"{detector.split('@', maxsplit=1)[0]}:{cwe.lower()}"
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
    )


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

    def repository_view(self, catalogue: NativeSourceCatalogue) -> SealedRepositoryView:
        if self.graph.head_sha != catalogue.snapshot.head_sha or any(
            anchor.tenant_id != self.graph.tenant_id for anchor in catalogue.anchors
        ):
            raise ValueError("deterministic source view binding is invalid")
        files = {file.path: file for file in catalogue.snapshot.files}
        aliases = {
            evidence_id: (content, digest) for evidence_id, content, digest in self.source_aliases
        }
        if len(aliases) != len(self.source_aliases) or set(aliases) != {
            record.evidence_id for record in self.graph.evidence
        }:
            raise ValueError("deterministic source aliases are invalid")
        for record in self.graph.evidence:
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
    total_budget_ns: int = 60_000_000_000,
) -> ProductDeterministicScanResult:
    if (
        type(catalogue) is not NativeSourceCatalogue
        or type(total_budget_ns) is not int
        or not (0 < total_budget_ns <= 60_000_000_000)
    ):
        raise ValueError("product scanner request is invalid")
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
    complete = True
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
    graph, aliases = _scanner_graph_from_signals(catalogue, tuple(signals), tenant_id, producer)
    complete = complete and monotonic_ns() - started <= total_budget_ns
    return ProductDeterministicScanResult(
        graph, tuple(receipts), complete, tuple(aliases), tuple(source_bindings)
    )


def _scanner_graph_from_signals(
    catalogue: NativeSourceCatalogue,
    signals: tuple[RawSignal, ...],
    tenant_id: str,
    producer: ProducerRef,
) -> tuple[EvidenceGraph, tuple[tuple[str, bytes, str], ...]]:
    candidates = normalize_signals(raw_signals=tuple(signals))
    records = []
    aliases = []
    for signal in signals:
        windows = [
            anchor
            for anchor in catalogue.anchors
            if isinstance(anchor.request.arguments, ReadRangeArguments)
            and anchor.location.path == signal.location.path
            and anchor.location.content_sha256 == signal.location.content_sha256
            and anchor.request.arguments.start_line <= signal.location.start.line
            and anchor.request.arguments.end_line >= signal.location.end.line
        ]
        if not windows:
            raise ValueError("scanner root has no admitted source window")
        anchor = min(windows, key=lambda item: (item.read_artifact.size_bytes, item.evidence_id))
        content = catalogue._window_bytes(anchor)
        record = Evidence(
            schema_version="0.2.0",
            evidence_id=signal.raw_signal_id,
            tenant_id=tenant_id,
            head_sha=catalogue.snapshot.head_sha,
            evidence_kind=EvidenceKind.SCANNER_SIGNAL,
            producer=producer,
            trust_label=TrustLabel.UNTRUSTED_TOOL_OUTPUT,
            data_class=anchor.read_artifact.data_class,
            evidence_sha256=signal.signal_sha256,
            location=signal.location,
            artifact_ref=anchor.read_artifact,
        )
        records.append(record)
        aliases.append((record.evidence_id, content, anchor.read_artifact.content_sha256))
    bound = []
    for candidate in candidates:
        data = candidate.model_dump(mode="json")
        ids = sorted({sid for lineage in candidate.lineage for sid in lineage.input_signal_ids})
        data["evidence_ids"] = ids
        for lineage in data["lineage"]:
            lineage["evidence_ids"] = lineage["input_signal_ids"]
        bound.append(DiscoveryCandidate.model_validate_json(json.dumps(data)))
    edges = tuple(
        EvidenceGraphEdge(
            EvidenceEdgeKind.CANDIDATE_EVIDENCE,
            EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, candidate.candidate_id),
            EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, evidence_id),
        )
        for candidate in bound
        for evidence_id in candidate.evidence_ids
    )
    graph = EvidenceGraph(
        graph_id="product-deterministic",
        tenant_id=tenant_id,
        head_sha=catalogue.snapshot.head_sha,
        candidates=tuple(bound),
        evidence=tuple(records),
        edges=edges,
    )
    return graph, tuple(aliases)


def scanner_facts_match_receipts(
    catalogue: NativeSourceCatalogue,
    scan: ProductDeterministicScanResult,
) -> bool:
    """Close retained normalized facts over every original scanner signal."""
    try:
        graph, aliases = _scanner_graph_from_signals(
            catalogue,
            tuple(signal for receipt in scan.receipts for signal in receipt.signals),
            scan.graph.tenant_id,
            first_party_scanner_producer(),
        )
        return graph == scan.graph and aliases == scan.source_aliases
    except Exception:
        return False


def build_product_auditor_tools(
    catalogue: NativeSourceCatalogue,
    graph: EvidenceGraph,
    *,
    budget: RepositoryToolBudget,
    deterministic: ProductDeterministicScanResult | None = None,
    child_artifacts: tuple[tuple[Evidence, bytes], ...] = (),
    denied_source_paths: tuple[str, ...] = (),
) -> RepositoryToolSession:
    """Admit only graph evidence backed by retained host-owned source mappings."""
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
        static = {record.evidence_id: record for record in deterministic.graph.evidence}
    children = {}
    aliases = []
    files = {file.path: file for file in catalogue.snapshot.files}
    for record, payload in child_artifacts:
        artifact = record.artifact_ref
        file = files.get(record.location.path) if record.location is not None else None
        if (
            record.evidence_id in children
            or record.tenant_id != graph.tenant_id
            or record.head_sha != graph.head_sha
            or record.evidence_kind is not EvidenceKind.SCANNER_SIGNAL
            or record.data_class not in {DataClass.INTERNAL_METADATA, DataClass.RESTRICTED}
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
    restricted_paths = {
        record.location.path
        for record in graph.evidence
        if record.data_class is DataClass.RESTRICTED and record.location is not None
    }
    if any(path not in files for path in denied_source_paths):
        raise ValueError("Auditor denied source scope is invalid")
    restricted_paths.update(denied_source_paths)
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
        if record.location is None:
            raise ValueError("Auditor source location is unavailable")
        if record.data_class is DataClass.RESTRICTED:
            continue
        if record.location.path in restricted_paths:
            if record.evidence_id in children:
                admitted_ids.add(record.evidence_id)
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
    scope = RepositoryToolScope(
        graph.tenant_id,
        catalogue.indexes[0].repository_id if catalogue.indexes else "empty-repository",
        graph.head_sha,
        tuple(sorted(paths)),
        tuple(sorted(admitted_ids)),
    )
    return RepositoryToolSession(
        guard=RepositoryToolGuard(scope=scope, budget=budget), backend=backend
    )
