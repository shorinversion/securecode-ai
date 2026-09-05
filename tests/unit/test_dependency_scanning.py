"""Focused P2.6 dependency manifest and OSV normalization tests."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest
from securecode_ai.adapters import (
    DEFAULT_DEPENDENCY_SCAN_LIMITS,
    DependencyScanError,
    DependencyScanErrorCode,
    DependencyScanLimits,
    OsvAdvisoryRecord,
    OsvBatchRequest,
    OsvBatchResponse,
    OsvPackageResult,
    ParsedDependencyManifest,
    parse_python_requirements,
    scan_dependency_advisories,
)
from securecode_ai.core import (
    DependencyEcosystem,
    DependencyManifestEntry,
    DependencyManifestKind,
    RepositoryFile,
)

REPOSITORY_ID = "example/application"
REVISION = "6" * 40
PATH = "requirements.txt"
FIXTURES = Path(__file__).parents[1] / "fixtures" / "p2_6"


def _inputs(source: bytes) -> tuple[DependencyManifestEntry, RepositoryFile]:
    digest = hashlib.sha256(source).hexdigest()
    return (
        DependencyManifestEntry(
            path=PATH,
            content_sha256=digest,
            ecosystem=DependencyEcosystem.PYTHON,
            kind=DependencyManifestKind.REQUIREMENTS,
            ignored_by_rule_id=None,
        ),
        RepositoryFile(PATH, len(source), digest),
    )


def _parse(
    source: bytes,
    *,
    limits: DependencyScanLimits = DEFAULT_DEPENDENCY_SCAN_LIMITS,
) -> ParsedDependencyManifest:
    manifest, file = _inputs(source)
    return parse_python_requirements(
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        manifest=manifest,
        file=file,
        source=source,
        limits=limits,
    )


class _Scanner:
    scanner_id = "osv.dev"
    scanner_version = "v1"

    def __init__(self, response: OsvBatchResponse) -> None:
        self.response = response
        self.request: OsvBatchRequest | None = None

    def query_batch(self, request: OsvBatchRequest) -> OsvBatchResponse:
        self.request = request
        return self.response


def test_pinned_requirements_are_canonical_ordered_and_source_bound() -> None:
    source = (
        b"# frozen application dependencies\n"
        b"Requests==2.19.0 --hash=sha256:" + b"a" * 64 + b"\n"
        b"django_auth==4.2.16\n"
    )
    first = _parse(source)
    second = _parse(source)

    assert first == second
    assert [(item.name, item.version) for item in first.dependencies] == [
        ("django-auth", "4.2.16"),
        ("requests", "2.19.0"),
    ]
    requests = first.dependencies[1]
    assert requests.purl == "pkg:pypi/requests@2.19.0"
    assert source[requests.location.start_byte : requests.location.end_byte].startswith(
        b"Requests==2.19.0"
    )
    assert requests.manifest_sha256 == hashlib.sha256(source).hexdigest()


def test_safe_manifest_normalizes_an_explicit_empty_result() -> None:
    parsed = _parse((FIXTURES / "safe-requirements.txt").read_bytes())
    purl = parsed.dependencies[0].purl
    scanner = _Scanner(OsvBatchResponse((OsvPackageResult(purl, ()),)))

    result = scan_dependency_advisories(parsed, scanner)

    assert scanner.request == OsvBatchRequest((purl,))
    assert result.advisories == ()
    assert len(result.scan_sha256) == 64


def test_vulnerable_manifest_normalizes_ids_aliases_and_provenance() -> None:
    parsed = _parse((FIXTURES / "vulnerable-requirements.txt").read_bytes())
    purl = parsed.dependencies[0].purl
    scanner = _Scanner(
        OsvBatchResponse(
            (
                OsvPackageResult(
                    purl,
                    (OsvAdvisoryRecord("GHSA-9WX4-H78V-VM56", ("CVE-2018-18074",)),),
                ),
            )
        )
    )

    result = scan_dependency_advisories(parsed, scanner)

    assert len(result.advisories) == 1
    advisory = result.advisories[0]
    assert advisory.coordinate == parsed.dependencies[0]
    assert advisory.advisory_id == "GHSA-9WX4-H78V-VM56"
    assert advisory.aliases == ("CVE-2018-18074",)
    assert advisory.producer == "osv.dev@v1"
    assert len(advisory.advisory_sha256) == 64


@pytest.mark.parametrize(
    "source",
    [
        b"requests>=2.19.0\n",
        b"requests\n",
        b"-r shared.txt\n",
        b"package @ https://example.invalid/archive.whl\n",
        b"requests==2.19.0; python_version < '3.13'\n",
        b"requests==2.19.0\nRequests==2.32.5\n",
        b"requests==2.19.0 --hash=sha256:not-a-digest\n",
        b"\xff\n",
    ],
)
def test_unpinned_ambiguous_or_invalid_manifests_fail_closed(source: bytes) -> None:
    with pytest.raises(DependencyScanError) as raised:
        _parse(source)
    assert raised.value.code is DependencyScanErrorCode.MANIFEST_INVALID
    assert str(raised.value) == "dependency scan failed"


def test_manifest_identity_and_limits_fail_closed() -> None:
    source = b"requests==2.19.0\n"
    manifest, file = _inputs(source)
    with pytest.raises(DependencyScanError) as mismatch:
        parse_python_requirements(
            repository_id=REPOSITORY_ID,
            revision=REVISION,
            manifest=manifest,
            file=replace(file, content_sha256="0" * 64),
            source=source,
        )
    assert mismatch.value.code is DependencyScanErrorCode.REQUEST_INVALID

    with pytest.raises(DependencyScanError) as limited:
        _parse(source, limits=DependencyScanLimits(max_manifest_bytes=4))
    assert limited.value.code is DependencyScanErrorCode.MANIFEST_LIMIT

    with pytest.raises(DependencyScanError) as count:
        _parse(
            b"a==1\nb==1\n",
            limits=DependencyScanLimits(max_dependencies=1),
        )
    assert count.value.code is DependencyScanErrorCode.DEPENDENCY_LIMIT


def test_scanner_must_return_one_exact_result_per_requested_coordinate() -> None:
    parsed = _parse(b"requests==2.19.0\n")
    with pytest.raises(DependencyScanError) as missing:
        scan_dependency_advisories(parsed, _Scanner(OsvBatchResponse(())))
    assert missing.value.code is DependencyScanErrorCode.SCANNER_OUTPUT_INVALID

    wrong = OsvPackageResult("pkg:pypi/django@1.0", ())
    with pytest.raises(DependencyScanError) as substituted:
        scan_dependency_advisories(parsed, _Scanner(OsvBatchResponse((wrong,))))
    assert substituted.value.code is DependencyScanErrorCode.SCANNER_OUTPUT_INVALID


def test_scanner_exception_is_non_echoing_and_has_no_exception_chain() -> None:
    parsed = _parse(b"requests==2.19.0\n")
    canary = "private-scanner-output"

    class Broken:
        scanner_id = "osv.dev"
        scanner_version = "v1"

        def query_batch(self, request: OsvBatchRequest) -> OsvBatchResponse:
            del request
            raise RuntimeError(canary)

    with pytest.raises(DependencyScanError) as raised:
        scan_dependency_advisories(parsed, Broken())
    assert raised.value.code is DependencyScanErrorCode.SCANNER_FAILURE
    assert canary not in repr(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_empty_manifest_needs_no_external_call() -> None:
    parsed = _parse(b"# no runtime dependencies\n")

    class MustNotRun:
        scanner_id = "osv.dev"
        scanner_version = "v1"

        def query_batch(self, request: OsvBatchRequest) -> OsvBatchResponse:
            raise AssertionError(request)

    result = scan_dependency_advisories(parsed, MustNotRun())
    assert result.advisories == ()


def test_normalized_result_rejects_tampering() -> None:
    parsed = _parse(b"requests==2.19.0\n")
    purl = parsed.dependencies[0].purl
    scanner = _Scanner(
        OsvBatchResponse((OsvPackageResult(purl, (OsvAdvisoryRecord("OSV-2026-1"),)),))
    )
    result = scan_dependency_advisories(parsed, scanner)
    with pytest.raises(ValueError, match="dependency scan result is invalid"):
        replace(result, scan_sha256="0" * 64)
