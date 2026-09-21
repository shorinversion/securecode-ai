"""Real immutable secret-stage execution and source-free failure controls."""

import hashlib

import pytest
from securecode_ai.adapters.dependency_scanning import (
    OsvBatchRequest,
    OsvBatchResponse,
    OsvPackageResult,
)
from securecode_ai.adapters.product_execution import execute_secret_stage
from securecode_ai.adapters.secret_detection import SecretFingerprintKey


class Objects:
    def __init__(self) -> None:
        self.contents: dict[tuple[str, str], bytes] = {}

    def add(self, kind: str, content: bytes) -> str:
        oid = hashlib.sha1(
            f"{kind} {len(content)}\0".encode() + content, usedforsecurity=False
        ).hexdigest()
        self.contents[kind, oid] = content
        return oid

    def read(self, kind: str, oid: str, *, max_bytes: int) -> bytes:
        del max_bytes
        return self.contents[kind, oid]


def repository(source: bytes) -> tuple[Objects, str, str]:
    objects = Objects()
    blob = objects.add("blob", source)
    tree = objects.add("tree", b"100644 settings.py\0" + bytes.fromhex(blob))
    head = objects.add("commit", f"tree {tree}\n\nfixture".encode())
    return objects, head, blob


def test_actual_stage_retains_candidate_without_matched_value() -> None:
    value = b"development-" + b"credential-example"
    objects, head, _ = repository(b'password = "' + value + b'"\n')
    result = execute_secret_stage(
        reader=objects,
        head_sha=head,
        repository_id="public/fixture",
        fingerprint_key=SecretFingerprintKey("fixture", b"k" * 32),
    )
    assert result.head_sha == head
    assert len(result.results) == 1
    assert result.results[0].candidates
    assert value.decode() not in repr(result)
    assert result.output_sha256


def test_safe_zero_is_actual_completed_scan() -> None:
    objects, head, _ = repository(b"answer = 42\n")
    result = execute_secret_stage(
        reader=objects,
        head_sha=head,
        repository_id="public/fixture",
        fingerprint_key=SecretFingerprintKey("fixture", b"k" * 32),
    )
    assert len(result.results) == 1
    assert not result.results[0].candidates


@pytest.mark.parametrize("kind", ["commit", "tree", "blob"])
def test_poisoned_git_object_never_becomes_zero_success(kind: str) -> None:
    objects, head, _ = repository(b"answer = 42\n")
    key = next(key for key in objects.contents if key[0] == kind)
    objects.contents[key] += b"private-source-marker"
    with pytest.raises(ValueError) as caught:
        execute_secret_stage(
            reader=objects,
            head_sha=head,
            repository_id="public/fixture",
            fingerprint_key=SecretFingerprintKey("fixture", b"k" * 32),
        )
    assert "private-source-marker" not in str(caught.value)


class Osv:
    scanner_id = "osv.dev"
    scanner_version = "v1"

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.requests: list[OsvBatchRequest] = []

    def query_batch(self, request: OsvBatchRequest) -> OsvBatchResponse:
        self.requests.append(request)
        if self.fail:
            raise RuntimeError("private-source-marker")
        return OsvBatchResponse(tuple(OsvPackageResult(purl, ()) for purl in request.purls))


def manifest_repository(source: bytes, name: str = "requirements.txt") -> tuple[Objects, str]:
    objects = Objects()
    blob = objects.add("blob", source)
    tree = objects.add("tree", b"100644 " + name.encode() + b"\0" + bytes.fromhex(blob))
    return objects, objects.add("commit", f"tree {tree}\n\nfixture".encode())


def test_dependency_stage_actually_calls_approved_port() -> None:
    from securecode_ai.adapters.product_execution import execute_dependency_stage

    objects, head = manifest_repository(b"requests==2.19.0\n")
    scanner = Osv()
    result = execute_dependency_stage(
        reader=objects, head_sha=head, repository_id="public/fixture", scanner=scanner
    )
    assert len(scanner.requests) == 1
    assert len(result.results) == 1
    assert result.head_sha == head
    assert not result.results[0].advisories


@pytest.mark.parametrize("failure", ["missing", "failed", "unsupported"])
def test_dependency_stage_never_substitutes_clean(failure: str) -> None:
    from securecode_ai.adapters.product_execution import execute_dependency_stage

    objects, head = manifest_repository(
        b"requests==2.19.0\n", "pyproject.toml" if failure == "unsupported" else "requirements.txt"
    )
    with pytest.raises(ValueError) as caught:
        execute_dependency_stage(
            reader=objects,
            head_sha=head,
            repository_id="public/fixture",
            scanner=None if failure == "missing" else Osv(fail=failure == "failed"),
        )
    assert "private-source-marker" not in str(caught.value)


def test_dependency_advisory_is_retained_not_replaced_with_zero() -> None:
    from securecode_ai.adapters.dependency_scanning import (
        OsvAdvisoryRecord,
        OsvBatchResponse,
        OsvPackageResult,
    )
    from securecode_ai.adapters.product_execution import execute_dependency_stage

    class VulnerableOsv(Osv):
        def query_batch(self, request: OsvBatchRequest) -> OsvBatchResponse:
            return OsvBatchResponse(
                tuple(
                    OsvPackageResult(purl, (OsvAdvisoryRecord("GHSA-FIXTURE-TEST", ()),))
                    for purl in request.purls
                )
            )

    objects, head = manifest_repository(b"requests==2.19.0\n")
    result = execute_dependency_stage(
        reader=objects, head_sha=head, repository_id="public/fixture", scanner=VulnerableOsv()
    )
    assert result.results[0].advisories[0].advisory_id == "GHSA-FIXTURE-TEST"
    assert result.results[0].advisories[0].coordinate.revision == head


def test_incomplete_osv_response_does_not_become_clean() -> None:
    from securecode_ai.adapters.dependency_scanning import OsvBatchResponse
    from securecode_ai.adapters.product_execution import execute_dependency_stage

    class IncompleteOsv(Osv):
        def query_batch(self, request: OsvBatchRequest) -> OsvBatchResponse:
            return OsvBatchResponse(())

    objects, head = manifest_repository(b"requests==2.19.0\n")
    with pytest.raises(ValueError, match="PRODUCT_DEPENDENCY_EXECUTION_FAILED"):
        execute_dependency_stage(
            reader=objects, head_sha=head, repository_id="public/fixture", scanner=IncompleteOsv()
        )
