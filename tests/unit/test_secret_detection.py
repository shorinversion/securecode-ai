"""Acceptance and adversarial tests for value-free secret detection."""

from __future__ import annotations

import copy
import json
import logging
import pickle
from dataclasses import asdict, fields, replace

import pytest
from securecode_ai.adapters import (
    DEFAULT_SECRET_DETECTION_LIMITS,
    ApprovedExternalSecretScanner,
    ExternalSecretDetection,
    ExternalSecretScanRequest,
    ExternalSecretScanResponse,
    SecretDetectionError,
    SecretDetectionErrorCode,
    SecretDetectionLimits,
    SecretFingerprintKey,
    SecretKind,
    SecretProducer,
    SecretScanResult,
    scan_secrets,
)
from securecode_ai.core import RepositoryFile, SourcePoint, SourceRange

REPOSITORY_ID = "example/secure-repository"
REVISION = "3" * 40
PATH = "src/settings.py"
KEY = SecretFingerprintKey("tenant-fingerprint-v1", b"k" * 32)


def _file(source: bytes) -> RepositoryFile:
    import hashlib

    return RepositoryFile(PATH, len(source), hashlib.sha256(source).hexdigest())


def _scan(
    source: bytes,
    *,
    limits: SecretDetectionLimits = DEFAULT_SECRET_DETECTION_LIMITS,
    external_scanner: ApprovedExternalSecretScanner | None = None,
) -> SecretScanResult:
    return scan_secrets(
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        file=_file(source),
        source=source,
        fingerprint_key=KEY,
        limits=limits,
        external_scanner=external_scanner,
    )


def _canary() -> bytes:
    return b"AK" + b"IA" + b"A1B2C3D4E5F6G7H8"


def _entropy_value(length: int) -> bytes:
    alphabet = b"Aa0+/Bb1=" + b"Cc2Dd3Ee4+" + b"Ff5/Gg6=Hh7" + b"Ii8Jj9+"
    return (alphabet * ((length // len(alphabet)) + 1))[:length]


def _private_key_prefix() -> bytes:
    return b"-----BE" + b"GIN PRIVATE " + b"KEY-----\n"


def _private_key_suffix() -> bytes:
    return b"\n-----E" + b"ND PRIVATE " + b"KEY-----"


def test_first_party_patterns_are_ordered_redacted_and_deterministic() -> None:
    canary = _canary()
    assigned = b"n7V_2pQ+" + b"9xLm4Rz8" + b"T0cW"
    source = b"cloud = '" + canary + b"'\napi_key = '" + assigned + b"'\n"
    first = _scan(source)
    second = _scan(source)

    assert first == second
    assert [item.kind for item in first.candidates] == [
        SecretKind.AWS_ACCESS_KEY_ID,
        SecretKind.ASSIGNED_CREDENTIAL,
    ]
    assert all(item.data_class == "DC4_RESTRICTED" for item in first.candidates)
    assert all(item.redaction.startswith("<redacted:") for item in first.candidates)
    assert canary.decode() not in repr(first)
    assert assigned.decode() not in repr(first)


def test_private_key_marker_and_standalone_entropy_are_detected() -> None:
    token = b"Q7x3Lm+9" + b"Vp2Rz8Tk" + b"4Nw6Bc0A"
    source = _private_key_prefix() + token + _private_key_suffix() + b"\n"
    result = _scan(source)
    assert [item.kind for item in result.candidates] == [SecretKind.PRIVATE_MATERIAL]
    assert result.candidates[0].location.start_byte == len(_private_key_prefix())


def test_key_identity_separates_fingerprints_without_changing_location() -> None:
    source = b"token='" + _canary() + b"'\n"
    first = _scan(source)
    second = scan_secrets(
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        file=_file(source),
        source=source,
        fingerprint_key=SecretFingerprintKey("tenant-fingerprint-v2", b"m" * 32),
    )
    assert first.candidates[0].location == second.candidates[0].location
    assert first.candidates[0].fingerprint_sha256 != second.candidates[0].fingerprint_sha256


def test_fingerprint_key_identity_is_immutable() -> None:
    key = SecretFingerprintKey("tenant-fingerprint-v4", b"z" * 32)
    with pytest.raises(TypeError, match="secret fingerprint key is immutable"):
        key.key_id = "tenant-fingerprint-v5"  # type: ignore[misc]
    assert key.key_id == "tenant-fingerprint-v4"


def test_placeholders_hashes_and_low_entropy_values_are_negative() -> None:
    source = (
        b"api_"
        + b"key"
        + b"='your_api_key'\n"
        + b"to"
        + b"ken='aaaaaaaaaaaaaaaaaaaaaaaa'\n"
        + (b"a" * 64)
        + b"\nordinary_identifier_name\n"
    )
    assert _scan(source).candidates == ()


def test_identifiers_paths_uuids_and_messages_are_not_secrets() -> None:
    source = (
        b"class _SecureModuleImporter:\n"
        b"    source_security_group_owner_id = None\n"
        b"    def describe_instances_v6(self): pass\n"
        b"# http://www.apache.org/licenses/LICENSE-2.0\n"
        b"# https://stackoverflow.com/a/22107079/1688568\n"
        b"if CRYPTOGRAPHY_HAS_ED25519: pass\n"
        b"uid = '155d900f-4e14-4e4c-a73d-069cbf4541e6'\n"
        + b"pass"
        + b"word"
        + b' = "Password must meet the criteria below"\n'
    )
    assert _scan(source).candidates == ()


def test_random_tokens_next_to_code_text_are_still_detected() -> None:
    token = b"Q7x3Lm+9" + b"Vp2Rz8Tk" + b"4Nw6Bc0A"
    result = _scan(b"describe_instances_v6 = '" + token + b"'\n")
    assert [item.kind for item in result.candidates] == [SecretKind.HIGH_ENTROPY_TOKEN]


class _ExternalScanner:
    scanner_id = "detect-secrets"
    scanner_version = "1.5.0"

    def __init__(self, response: ExternalSecretScanResponse) -> None:
        self.response = response

    def scan(self, request: ExternalSecretScanRequest) -> ExternalSecretScanResponse:
        del request
        return self.response


def test_external_offsets_are_reissued_as_safe_local_metadata() -> None:
    source = b"prefix-opaque-value-suffix"
    scanner = _ExternalScanner(
        ExternalSecretScanResponse(
            (ExternalSecretDetection(SecretKind.ASSIGNED_CREDENTIAL, 7, 19),)
        )
    )
    result = _scan(source, external_scanner=scanner)
    candidate = result.candidates[0]
    assert candidate.producer is SecretProducer.APPROVED_EXTERNAL
    assert candidate.producer.value == "detect-secrets@1.5.0"
    assert candidate.location.start_byte == 7
    assert candidate.location.end_byte == 19
    assert source[7:19].decode() not in repr(candidate)


def test_external_scanner_cannot_change_admitted_file_identity() -> None:
    source = b"prefix-opaque-value-suffix"

    class MutatingScanner:
        scanner_id = "detect-secrets"
        scanner_version = "1.5.0"

        def scan(self, request: ExternalSecretScanRequest) -> ExternalSecretScanResponse:
            object.__setattr__(request.file, "path", "forged.py")
            object.__setattr__(request.file, "content_sha256", "0" * 64)
            return ExternalSecretScanResponse(
                (ExternalSecretDetection(SecretKind.ASSIGNED_CREDENTIAL, 7, 19),)
            )

    result = _scan(source, external_scanner=MutatingScanner())
    assert result.path == PATH
    assert result.content_sha256 == _file(source).content_sha256
    assert result.candidates[0].path == PATH


@pytest.mark.parametrize(
    ("limits", "source", "code"),
    [
        (SecretDetectionLimits(max_source_bytes=1), b"two", SecretDetectionErrorCode.SOURCE_LIMIT),
        (
            SecretDetectionLimits(max_match_bytes=8),
            b"token='abcdefghijklmnop'",
            SecretDetectionErrorCode.MATCH_LIMIT,
        ),
        (
            SecretDetectionLimits(max_candidates=1),
            b"x='" + _canary() + b"'\ny='" + _canary() + b"'",
            SecretDetectionErrorCode.CANDIDATE_LIMIT,
        ),
    ],
)
def test_hard_runtime_budgets_fail_closed(
    limits: SecretDetectionLimits, source: bytes, code: SecretDetectionErrorCode
) -> None:
    with pytest.raises(SecretDetectionError) as caught:
        _scan(source, limits=limits)
    assert caught.value.code is code


@pytest.mark.parametrize(
    ("prefix", "value_length", "suffix", "kind"),
    [
        (b"token='", 4096, b"'", SecretKind.ASSIGNED_CREDENTIAL),
        (b"", 4096, b"", SecretKind.HIGH_ENTROPY_TOKEN),
        (
            _private_key_prefix(),
            4095,
            _private_key_suffix(),
            SecretKind.PRIVATE_MATERIAL,
        ),
    ],
)
def test_default_match_budget_accepts_exact_boundary(
    prefix: bytes, value_length: int, suffix: bytes, kind: SecretKind
) -> None:
    result = _scan(prefix + _entropy_value(value_length) + suffix)
    assert [candidate.kind for candidate in result.candidates] == [kind]


@pytest.mark.parametrize(
    ("prefix", "value_length", "suffix"),
    [
        (b"token='", 4097, b"'"),
        (b"", 4097, b""),
        (_private_key_prefix(), 4096, _private_key_suffix()),
    ],
)
def test_default_match_budget_rejects_first_oversized_byte(
    prefix: bytes, value_length: int, suffix: bytes
) -> None:
    with pytest.raises(SecretDetectionError) as caught:
        _scan(prefix + _entropy_value(value_length) + suffix)
    assert caught.value.code is SecretDetectionErrorCode.MATCH_LIMIT


def test_malformed_external_output_fails_closed() -> None:
    source = b"0123456789abcdef"
    scanner = _ExternalScanner(
        ExternalSecretScanResponse(
            (
                ExternalSecretDetection(SecretKind.HIGH_ENTROPY_TOKEN, 2, 9),
                ExternalSecretDetection(SecretKind.HIGH_ENTROPY_TOKEN, 8, 12),
            )
        )
    )
    with pytest.raises(SecretDetectionError) as caught:
        _scan(source, external_scanner=scanner)
    assert caught.value.code is SecretDetectionErrorCode.EXTERNAL_OUTPUT_INVALID


def test_mutated_external_response_container_fails_typed_without_echo() -> None:
    marker = "EXTERNAL_CONTAINER_CANARY"

    class HostileDetections:
        def __len__(self) -> int:
            raise RuntimeError(marker)

        def __iter__(self) -> object:
            raise RuntimeError(marker)

    response = ExternalSecretScanResponse(())
    object.__setattr__(response, "detections", HostileDetections())
    scanner = _ExternalScanner(response)
    with pytest.raises(SecretDetectionError) as caught:
        _scan(b"safe", external_scanner=scanner)
    assert caught.value.code is SecretDetectionErrorCode.EXTERNAL_OUTPUT_INVALID
    assert marker not in repr(caught.value)


@pytest.mark.parametrize(
    "detections",
    [
        (
            ExternalSecretDetection(SecretKind.HIGH_ENTROPY_TOKEN, 8, 12),
            ExternalSecretDetection(SecretKind.HIGH_ENTROPY_TOKEN, 2, 6),
        ),
        (ExternalSecretDetection(SecretKind.HIGH_ENTROPY_TOKEN, 2, 17),),
    ],
)
def test_unsorted_or_out_of_bounds_external_output_fails_closed(
    detections: tuple[ExternalSecretDetection, ...],
) -> None:
    scanner = _ExternalScanner(ExternalSecretScanResponse(detections))
    with pytest.raises(SecretDetectionError) as caught:
        _scan(b"0123456789abcdef", external_scanner=scanner)
    assert caught.value.code is SecretDetectionErrorCode.EXTERNAL_OUTPUT_INVALID


def test_external_detection_budget_fails_closed_before_candidate_issue() -> None:
    source = b"0123456789abcdef"
    scanner = _ExternalScanner(
        ExternalSecretScanResponse(
            (
                ExternalSecretDetection(SecretKind.HIGH_ENTROPY_TOKEN, 0, 1),
                ExternalSecretDetection(SecretKind.HIGH_ENTROPY_TOKEN, 2, 3),
            )
        )
    )
    limits = SecretDetectionLimits(max_external_detections=1)
    with pytest.raises(SecretDetectionError) as caught:
        _scan(source, limits=limits, external_scanner=scanner)
    assert caught.value.code is SecretDetectionErrorCode.CANDIDATE_LIMIT


def test_external_exception_canary_is_not_retained() -> None:
    marker = "PRIVATE_EXTERNAL_CANARY"

    class FailingScanner:
        scanner_id = "detect-secrets"
        scanner_version = "1.5.0"

        def scan(self, request: ExternalSecretScanRequest) -> ExternalSecretScanResponse:
            del request
            raise RuntimeError(marker)

    with pytest.raises(SecretDetectionError) as caught:
        _scan(b"safe", external_scanner=FailingScanner())
    assert caught.value.code is SecretDetectionErrorCode.EXTERNAL_FAILURE
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert marker not in repr(caught.value)
    serialized = pickle.dumps(caught.value)
    restored = pickle.loads(serialized)
    assert restored.code is SecretDetectionErrorCode.EXTERNAL_FAILURE
    assert marker.encode() not in serialized


def test_multi_sink_secret_canary_is_absent_from_retained_surfaces(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    canary = _canary()
    result = _scan(b"value='" + canary + b"'\n")
    rendered = json.dumps(asdict(result), sort_keys=True, default=str)
    logging.getLogger("securecode-test").warning("%r", result)
    captured = capsys.readouterr()
    combined = rendered + caplog.text + captured.out + captured.err + repr(KEY)
    assert canary.decode() not in combined
    assert (b"k" * 32).decode() not in combined


def test_fingerprint_key_rejects_serialization_and_copy_without_echo() -> None:
    marker = b"PRIVATE_FINGERPRINT_KEY_CANARY!!"
    key = SecretFingerprintKey("tenant-fingerprint-v3", marker)

    operations = (
        lambda: pickle.dumps(key),
        lambda: key.__getstate__(),
        lambda: copy.copy(key),
        lambda: copy.deepcopy(key),
    )
    for operation in operations:
        with pytest.raises(TypeError) as caught:
            operation()
        assert marker.decode() not in repr(caught.value)


def test_safe_result_pickle_contains_no_matched_bytes() -> None:
    canary = _canary()
    result = _scan(b"value='" + canary + b"'\n")
    serialized = pickle.dumps(result)
    assert canary not in serialized


def test_retained_ranges_are_bound_to_the_exact_source_size() -> None:
    result = _scan(b"value='" + _canary() + b"'\n")
    candidate = result.candidates[0]
    assert candidate.source_size_bytes == result.source_size_bytes

    with pytest.raises(ValueError, match="secret candidate is invalid"):
        replace(candidate, source_size_bytes=candidate.location.end_byte - 1)
    with pytest.raises(ValueError, match="secret scan result is invalid"):
        replace(result, source_size_bytes=result.source_size_bytes + 1)


def test_unapproved_external_scanner_is_rejected_before_call() -> None:
    called = False

    class UnapprovedScanner:
        scanner_id = "unknown"
        scanner_version = "1.0.0"

        def scan(self, request: ExternalSecretScanRequest) -> ExternalSecretScanResponse:
            nonlocal called
            del request
            called = True
            return ExternalSecretScanResponse(())

    with pytest.raises(SecretDetectionError) as caught:
        _scan(b"safe", external_scanner=UnapprovedScanner())
    assert caught.value.code is SecretDetectionErrorCode.REQUEST_INVALID
    assert not called


def test_hostile_external_identity_comparison_is_typed_and_non_echoing() -> None:
    marker = "IDENTITY_CANARY"

    class HostileIdentity:
        def __eq__(self, other: object) -> bool:
            del other
            raise RuntimeError(marker)

    class HostileScanner:
        scanner_id = HostileIdentity()
        scanner_version = "1.5.0"

        def scan(self, request: ExternalSecretScanRequest) -> ExternalSecretScanResponse:
            del request
            raise AssertionError("scanner must not be called")

    with pytest.raises(SecretDetectionError) as caught:
        _scan(b"safe", external_scanner=HostileScanner())  # type: ignore[arg-type]
    assert caught.value.code is SecretDetectionErrorCode.REQUEST_INVALID
    assert marker not in repr(caught.value)


def test_external_request_validates_source_identity() -> None:
    source = b"safe"
    with pytest.raises(ValueError, match="external secret scan request is invalid"):
        ExternalSecretScanRequest("", REVISION, _file(source), source)
    with pytest.raises(ValueError, match="external secret scan request is invalid"):
        ExternalSecretScanRequest(REPOSITORY_ID, "bad", _file(source), source)
    with pytest.raises(ValueError, match="external secret scan request is invalid"):
        ExternalSecretScanRequest(REPOSITORY_ID, REVISION, _file(source), b"other")


def test_scan_digest_binds_line_and_column_points() -> None:
    result = _scan(b"header\nvalue='" + _canary() + b"'\n")
    candidate = result.candidates[0]
    forged_location = SourceRange(
        candidate.location.start_byte,
        candidate.location.end_byte,
        SourcePoint(99, 0),
        SourcePoint(99, candidate.location.end_byte - candidate.location.start_byte),
    )
    forged_candidate = replace(candidate, location=forged_location)
    with pytest.raises(ValueError, match="secret scan result is invalid"):
        replace(result, candidates=(forged_candidate,))


def test_public_surface_has_no_path_shell_network_or_environment_input() -> None:
    parameters = set(scan_secrets.__annotations__)
    assert not ({"path", "shell", "network", "command", "endpoint", "environment"} & parameters)
    assert {item.name for item in fields(ExternalSecretScanRequest)} == {
        "repository_id",
        "revision",
        "file",
        "source",
    }
    assert not any(
        hasattr(ExternalSecretScanRequest, name)
        for name in ("open", "run", "connect", "getenv", "read", "write")
    )
