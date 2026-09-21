"""Bounded deterministic diagnostic composition for the transitional CLI.

This module composes the available bounded local P2 adapters into aggregate
facts and can render an already-admitted
:class:`~securecode_ai.core.reports.DeterministicReport`.  Neither route can
promote this limited operation into a product-scan outcome: the model-native
lane and its mandatory interpretation stages remain outside this P2.13 scope.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable

from securecode_ai.adapters import (
    FileSystemRepositoryIntake,
    SecretFingerprintKey,
    analyze_python_ast,
    build_python_symbol_index,
    parse_python_requirements,
    scan_python_cwe89,
    scan_secrets,
)
from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION, CliExitCode
from securecode_ai.core import IgnorePolicy, InventoryLimits, RepositoryFile, discover_repository
from securecode_ai.core.reports import DeterministicReport, ReportFormat, render_report

from .atomic_output import write_new_output

DIAGNOSTIC_RESULT_VERSION = "1.0.0"
DIAGNOSTIC_INVENTORY_LIMITS = InventoryLimits(
    max_files=4096,
    max_directories=1024,
    max_depth=64,
    max_path_bytes=4096,
    max_file_bytes=2_000_000,
    max_total_bytes=64_000_000,
)


class DiagnosticFormat(StrEnum):
    """Formats admitted for an already validated deterministic report."""

    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    SARIF = "sarif"

    @property
    def report_format(self) -> ReportFormat:
        return ReportFormat(self.value)


class DiagnosticErrorCode(StrEnum):
    """Closed, non-echoing diagnostic-command failures."""

    FACTS_UNAVAILABLE = "FACTS_UNAVAILABLE"
    FACTS_INVALID = "FACTS_INVALID"
    FACTS_INCOMPLETE = "FACTS_INCOMPLETE"
    OUTPUT_UNAVAILABLE = "OUTPUT_UNAVAILABLE"


class DiagnosticFactsStatus(StrEnum):
    """Whether every available deterministic fact adapter completed."""

    COMPLETED = "COMPLETED"
    INCOMPLETE = "INCOMPLETE"


class DiagnosticError(RuntimeError):
    """A typed failure that intentionally retains no untrusted detail."""

    __slots__ = ("code",)

    def __init__(self, code: DiagnosticErrorCode) -> None:
        if type(code) is not DiagnosticErrorCode:
            raise TypeError("diagnostic error code is invalid")
        self.code = code
        super().__init__("deterministic diagnostic operation failed")
        self.__cause__ = None
        self.__context__ = None


@runtime_checkable
class DeterministicDiagnostic(Protocol):
    """Compose a non-product report from facts admitted by the host.

    ``target`` is an opaque selector to this boundary.  It is never rendered by
    this module, and an implementation must not treat it as authority to write
    repository source.  A later product scan owns repository intake, both
    discovery lanes, and product outcome derivation.
    """

    def compose(self, target: str) -> DeterministicReport | DiagnosticFacts: ...


class UnavailableDeterministicDiagnostic:
    """Default until a host wires an admitted facts composer into the CLI."""

    def compose(self, target: str) -> DeterministicReport | DiagnosticFacts:
        del target
        raise DiagnosticError(DiagnosticErrorCode.FACTS_UNAVAILABLE)


@dataclass(frozen=True, slots=True)
class DiagnosticFacts:
    """Safe aggregate facts from the available P2 deterministic components.

    This is intentionally distinct from :class:`DeterministicReport`.  The
    latter is an AuditRun report and its accepted contract requires model-native
    and Auditor receipts.  A diagnostic facts document therefore records that
    missing coverage instead of manufacturing those receipts.
    """

    tree_sha256: str
    files_total: int
    bytes_total: int
    python_files: int
    dependency_manifests: int
    dependencies_parsed: int
    cwe89_signals: int
    secret_candidates: int
    parser_diagnostics: int
    adapter_failures: int

    def __post_init__(self) -> None:
        counts = (
            self.files_total,
            self.bytes_total,
            self.python_files,
            self.dependency_manifests,
            self.dependencies_parsed,
            self.cwe89_signals,
            self.secret_candidates,
            self.parser_diagnostics,
            self.adapter_failures,
        )
        if (
            type(self.tree_sha256) is not str
            or len(self.tree_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.tree_sha256)
            or any(type(value) is not int or value < 0 for value in counts)
        ):
            raise ValueError("diagnostic facts are invalid")

    @property
    def status(self) -> DiagnosticFactsStatus:
        return (
            DiagnosticFactsStatus.INCOMPLETE
            if self.adapter_failures
            else DiagnosticFactsStatus.COMPLETED
        )

    def document(self) -> dict[str, object]:
        return {
            "diagnostic_facts_version": DIAGNOSTIC_RESULT_VERSION,
            "diagnostic_scope": "DETERMINISTIC_FACTS_AND_REPORTS_ONLY",
            "deterministic_facts": self.status.value,
            "facts": {
                "adapter_failures": self.adapter_failures,
                "bytes_total": self.bytes_total,
                "cwe89_signals": self.cwe89_signals,
                "dependencies_parsed": self.dependencies_parsed,
                "dependency_manifests": self.dependency_manifests,
                "files_total": self.files_total,
                "parser_diagnostics": self.parser_diagnostics,
                "python_files": self.python_files,
                "secret_candidates": self.secret_candidates,
                "tree_sha256": self.tree_sha256,
            },
            "model_native_discovery": "NOT_EXECUTED",
            "product_outcome": "NOT_EVALUATED",
            "recovery_action": "RUN_PRODUCT_SCAN_AFTER_MODEL_NATIVE_DISCOVERY_IS_AVAILABLE",
            "scan_readiness": "NOT_EVALUATED",
            "unexecuted_coverage": [
                "DEPENDENCY_ADVISORY_LOOKUP_NOT_EXECUTED",
                "MODEL_NATIVE_DISCOVERY_NOT_EXECUTED",
                "AUDITOR_INTERPRETATION_NOT_EXECUTED",
            ],
        }


class LocalDeterministicDiagnostic:
    """Compose a bounded local facts report without a model, network, or writes."""

    __slots__ = ()

    def compose(self, target: str) -> DeterministicReport | DiagnosticFacts:
        if type(target) is not str or not target:
            raise DiagnosticError(DiagnosticErrorCode.FACTS_INVALID)
        try:
            root = Path(target)
            intake = FileSystemRepositoryIntake(DIAGNOSTIC_INVENTORY_LIMITS)
            inventory = intake.inventory(root)
            discovery = discover_repository(inventory, IgnorePolicy("diagnostic", "1"))
            repository_id = f"diagnostic-{inventory.tree_sha256[:24]}"
            revision = inventory.tree_sha256[:40]
            fingerprint_key = SecretFingerprintKey("diagnostic", secrets.token_bytes(32))
            facts = _collect_local_facts(
                root=root,
                inventory=inventory,
                discovery=discovery,
                repository_id=repository_id,
                revision=revision,
                fingerprint_key=fingerprint_key,
            )
            if intake.inventory(root) != inventory:
                raise ValueError
            return facts
        except DiagnosticError:
            raise
        except Exception:
            raise DiagnosticError(DiagnosticErrorCode.FACTS_UNAVAILABLE) from None


@dataclass(frozen=True, slots=True)
class DiagnosticResult:
    """One machine-safe completion receipt for a non-product diagnostic."""

    report_format: DiagnosticFormat
    report_sha256: str
    output_written: bool

    def __post_init__(self) -> None:
        if (
            type(self.report_format) is not DiagnosticFormat
            or type(self.report_sha256) is not str
            or len(self.report_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.report_sha256)
            or type(self.output_written) is not bool
        ):
            raise ValueError("diagnostic result is invalid")

    def document(self) -> dict[str, object]:
        """Return the closed completion envelope, never a product scan result."""

        return {
            "command": "scan",
            "diagnostic_outcome": "DIAGNOSTIC_COMPLETED",
            "diagnostic_scope": "DETERMINISTIC_FACTS_AND_REPORTS_ONLY",
            "exit_code": int(CliExitCode.COMPLETED),
            "format": self.report_format.value,
            "model_native_discovery": "NOT_EXECUTED",
            "output_written": self.output_written,
            "product_outcome": "NOT_EVALUATED",
            "report_sha256": self.report_sha256,
            "result_version": DIAGNOSTIC_RESULT_VERSION,
            "scan_readiness": "NOT_EVALUATED",
            "schema_version": CONTRACT_SCHEMA_VERSION,
        }


def run_deterministic_diagnostic(
    diagnostic: DeterministicDiagnostic,
    *,
    target: str,
    report_format: DiagnosticFormat,
    output: Path | None = None,
) -> DiagnosticResult:
    """Render trusted deterministic facts without invoking a model.

    Output creation is opt-in.  An existing destination is rejected and the
    exclusive-create mode prevents a check-then-write overwrite race.  No
    output path or target is returned because either could disclose a local
    workspace layout.
    """

    if (
        not isinstance(diagnostic, DeterministicDiagnostic)
        or type(target) is not str
        or not target
        or type(report_format) is not DiagnosticFormat
        or (output is not None and not isinstance(output, Path))
    ):
        raise DiagnosticError(DiagnosticErrorCode.FACTS_INVALID)
    try:
        report = diagnostic.compose(target)
        if type(report) is DeterministicReport:
            rendered = render_report(report, report_format.report_format)
        elif type(report) is DiagnosticFacts:
            rendered = _render_diagnostic_facts(report, report_format)
        else:
            raise ValueError
    except DiagnosticError:
        raise
    except Exception:
        raise DiagnosticError(DiagnosticErrorCode.FACTS_INVALID) from None
    if output is not None:
        _write_new_output(output, rendered)
    if type(report) is DiagnosticFacts and report.status is DiagnosticFactsStatus.INCOMPLETE:
        raise DiagnosticError(DiagnosticErrorCode.FACTS_INCOMPLETE)
    return DiagnosticResult(
        report_format=report_format,
        report_sha256=hashlib.sha256(rendered).hexdigest(),
        output_written=output is not None,
    )


def _collect_local_facts(
    *,
    root: Path,
    inventory: object,
    discovery: object,
    repository_id: str,
    revision: str,
    fingerprint_key: SecretFingerprintKey,
) -> DiagnosticFacts:
    """Run only already-admitted local P2 adapters and retain aggregate facts."""

    # These exact runtime checks keep the CLI composition boundary closed even
    # though it deliberately consumes the existing public adapter surfaces.
    from securecode_ai.core import DiscoveryManifest, RepositoryInventory

    if type(inventory) is not RepositoryInventory or type(discovery) is not DiscoveryManifest:
        raise ValueError("diagnostic facts inputs are invalid")

    files = {item.path: item for item in inventory.files}
    python_files = 0
    dependencies_parsed = 0
    cwe89_signals = 0
    secret_candidates = 0
    parser_diagnostics = 0
    adapter_failures = 0
    dependency_paths = {item.path for item in discovery.dependency_manifests}

    for item in discovery.analyzed_files:
        file = files.get(item.path)
        if type(file) is not RepositoryFile:
            raise ValueError("admitted file is unavailable")
        source = _read_admitted_bytes(root, file)
        try:
            secret_result = scan_secrets(
                repository_id=repository_id,
                revision=revision,
                file=file,
                source=source,
                fingerprint_key=fingerprint_key,
            )
            secret_candidates += len(secret_result.candidates)
        except Exception:
            adapter_failures += 1

        if file.path.endswith((".py", ".pyi")):
            python_files += 1
            try:
                index = build_python_symbol_index(
                    repository_id=repository_id,
                    revision=revision,
                    path=file.path,
                    content_sha256=file.content_sha256,
                    source=source,
                )
                analysis = analyze_python_ast(index)
                parser_diagnostics += len(index.diagnostics)
                if analysis.status.value == "parsed":
                    cwe89_signals += len(scan_python_cwe89(index, analysis).signals)
            except Exception:
                adapter_failures += 1

        if file.path in dependency_paths:
            manifest = next(
                candidate
                for candidate in discovery.dependency_manifests
                if candidate.path == file.path
            )
            try:
                dependencies_parsed += len(
                    parse_python_requirements(
                        repository_id=repository_id,
                        revision=revision,
                        manifest=manifest,
                        file=file,
                        source=source,
                    ).dependencies
                )
            except Exception:
                adapter_failures += 1

    return DiagnosticFacts(
        tree_sha256=inventory.tree_sha256,
        files_total=len(inventory.files),
        bytes_total=inventory.total_bytes,
        python_files=python_files,
        dependency_manifests=len(discovery.dependency_manifests),
        dependencies_parsed=dependencies_parsed,
        cwe89_signals=cwe89_signals,
        secret_candidates=secret_candidates,
        parser_diagnostics=parser_diagnostics,
        adapter_failures=adapter_failures,
    )


def _read_admitted_bytes(root: Path, file: RepositoryFile) -> bytes:
    """Read one relative inventory member and bind its bytes before adapter use."""

    try:
        source = (root / Path(*file.path.split("/"))).read_bytes()
    except OSError:
        raise ValueError("admitted file is unavailable") from None
    if len(source) != file.size_bytes or hashlib.sha256(source).hexdigest() != file.content_sha256:
        raise ValueError("admitted file changed")
    return source


def _render_diagnostic_facts(facts: DiagnosticFacts, report_format: DiagnosticFormat) -> bytes:
    """Render a source-free facts document; this is not a P2.12 AuditRun report."""

    document = facts.document()
    if report_format is DiagnosticFormat.JSON:
        return _canonical_document_bytes(document)
    if report_format is DiagnosticFormat.MARKDOWN:
        return _diagnostic_markdown(document).encode("utf-8")
    if report_format is DiagnosticFormat.HTML:
        return _diagnostic_html(document).encode("utf-8")
    if report_format is DiagnosticFormat.SARIF:
        return _canonical_document_bytes(
            {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [
                    {
                        "automationDetails": {"id": "securecode-diagnostic-facts"},
                        "properties": document,
                        "results": [],
                        "tool": {
                            "driver": {
                                "informationUri": "https://example.invalid/securecode",
                                "name": "SecureCode AI deterministic diagnostic",
                                "rules": [],
                            }
                        },
                    }
                ],
                "version": "2.1.0",
            }
        )
    raise ValueError("diagnostic format is invalid")


def _canonical_document_bytes(document: dict[str, object]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _diagnostic_markdown(document: dict[str, object]) -> str:
    facts = document["facts"]
    if type(facts) is not dict:
        raise ValueError("diagnostic document is invalid")
    lines = ["# SecureCode AI deterministic diagnostic", "", "Product outcome: NOT_EVALUATED"]
    lines.append("Model-native discovery: NOT_EXECUTED")
    lines.append(f"Deterministic facts: {document['deterministic_facts']}")
    lines.append("")
    lines.append("## Aggregate facts")
    for key in sorted(facts):
        lines.append(f"- {key}: {facts[key]}")
    lines.append("")
    lines.append("Recovery action: run a product scan after model-native discovery is available.")
    return "\n".join(lines) + "\n"


def _diagnostic_html(document: dict[str, object]) -> str:
    facts = document["facts"]
    if type(facts) is not dict:
        raise ValueError("diagnostic document is invalid")
    rows = "".join(f"<tr><th>{key}</th><td>{facts[key]}</td></tr>" for key in sorted(facts))
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'">'
        "<title>SecureCode AI deterministic diagnostic</title></head><body>"
        "<h1>SecureCode AI deterministic diagnostic</h1>"
        "<p>Product outcome: NOT_EVALUATED</p><p>Model-native discovery: NOT_EXECUTED</p>"
        f"<p>Deterministic facts: {document['deterministic_facts']}</p>"
        f"<table>{rows}</table>"
        "<p>Recovery action: run a product scan after model-native discovery is available.</p>"
        "</body></html>"
    )


def canonical_diagnostic_json(result: DiagnosticResult) -> str:
    """Render exactly one versioned machine result with a terminal newline."""

    if type(result) is not DiagnosticResult:
        raise TypeError("diagnostic result is invalid")
    return json.dumps(
        result.document(),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _write_new_output(destination: Path, rendered: bytes) -> None:
    try:
        write_new_output(destination, rendered)
    except FileExistsError:
        raise DiagnosticError(DiagnosticErrorCode.OUTPUT_UNAVAILABLE) from None
    except OSError:
        raise DiagnosticError(DiagnosticErrorCode.OUTPUT_UNAVAILABLE) from None


__all__ = [
    "DIAGNOSTIC_INVENTORY_LIMITS",
    "DIAGNOSTIC_RESULT_VERSION",
    "DeterministicDiagnostic",
    "DiagnosticError",
    "DiagnosticErrorCode",
    "DiagnosticFacts",
    "DiagnosticFactsStatus",
    "DiagnosticFormat",
    "DiagnosticResult",
    "LocalDeterministicDiagnostic",
    "UnavailableDeterministicDiagnostic",
    "canonical_diagnostic_json",
    "run_deterministic_diagnostic",
]
