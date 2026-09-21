"""Installed Linux-only command for one admitted CI worker invocation."""

from __future__ import annotations

import json
import os
import stat
import sys
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path
from typing import BinaryIO, Final, TextIO, cast

from securecode_ai.contracts import ArtifactRef, AuditRun, CliExitCode

from .artifacts import CiWorkerArtifactError, write_ci_worker_artifact
from .runner import CiWorkerRequest, run_ci_worker

_MAX_INPUT_BYTES: Final = 8 * 1024 * 1024
_O_NOFOLLOW: Final[int] = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC: Final[int] = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK: Final[int] = getattr(os, "O_NONBLOCK", 0)
_HELP: Final = """usage: securecode-worker --artifact-root PATH [--input PATH]

Run one admitted CI worker request. If --input is omitted, the request is read
from standard input. The artifact root and input file must use absolute paths.
"""


class _InvalidInput(ValueError):
    """Raised for a rejected command or AuditRun document."""


class _OperationalFailure(RuntimeError):
    """Raised for a local worker operation that cannot complete safely."""


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: BinaryIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Write one P5.12 artifact and render its source-free reference."""

    output = sys.stdout if stdout is None else stdout
    errors = sys.stderr if stderr is None else stderr
    tokens = tuple(sys.argv[1:] if argv is None else argv)
    if tokens in {("--help",), ("-h",)}:
        output.write(_HELP)
        return 0
    try:
        artifact_root, input_path = _parse_arguments(tokens)
        _require_linux()
        _validate_artifact_root(artifact_root)
        audit_run = _parse_audit_run(_read_input(input_path, stdin))
        request = CiWorkerRequest(audit_run=audit_run)
        result = run_ci_worker(request)
        if result.receipt is None:
            raise _InvalidInput
        reference = write_ci_worker_artifact(artifact_root, request, result)
        output.write(_canonical_artifact_reference(reference))
        return int(result.exit_code)
    except _InvalidInput:
        errors.write("invalid worker input\n")
        return int(CliExitCode.INVALID_USAGE_OR_CONFIG)
    except (_OperationalFailure, CiWorkerArtifactError, OSError):
        errors.write("worker operation failed\n")
        return int(CliExitCode.OPERATIONAL_ERROR)
    except Exception:
        errors.write("worker operation failed\n")
        return int(CliExitCode.OPERATIONAL_ERROR)


def _parse_arguments(tokens: tuple[str, ...]) -> tuple[Path, Path | None]:
    if any(type(token) is not str for token in tokens):
        raise _InvalidInput
    artifact_root: Path | None = None
    input_path: Path | None = None
    index = 0
    while index < len(tokens):
        option = tokens[index]
        if option not in {"--artifact-root", "--input"} or index + 1 >= len(tokens):
            raise _InvalidInput
        value = tokens[index + 1]
        if not value:
            raise _InvalidInput
        if option == "--artifact-root":
            if artifact_root is not None:
                raise _InvalidInput
            artifact_root = Path(value)
        else:
            if input_path is not None or value == "-":
                raise _InvalidInput
            input_path = Path(value)
        index += 2
    if artifact_root is None:
        raise _InvalidInput
    return artifact_root, input_path


def _require_linux() -> None:
    if sys.platform != "linux" or os.name != "posix" or _O_NOFOLLOW == 0 or _O_NONBLOCK == 0:
        raise _OperationalFailure


def _validate_artifact_root(root: Path) -> None:
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise _InvalidInput


def _read_input(input_path: Path | None, stdin: BinaryIO | None) -> bytes:
    if input_path is None:
        stream = _stdin_buffer() if stdin is None else stdin
        try:
            payload = stream.read(_MAX_INPUT_BYTES + 1)
        except OSError as error:
            raise _OperationalFailure from error
        if type(payload) is not bytes:
            raise _InvalidInput
        return _bounded_payload(payload)
    return _read_regular_file(input_path)


def _stdin_buffer() -> BinaryIO:
    stream = getattr(sys.stdin, "buffer", None)
    if stream is None:
        raise _OperationalFailure
    return cast(BinaryIO, stream)


def _read_regular_file(path: Path) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise _InvalidInput
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK)
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_size > _MAX_INPUT_BYTES:
            raise _InvalidInput
        chunks: list[bytes] = []
        remaining = _MAX_INPUT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return _bounded_payload(b"".join(chunks))
    except _InvalidInput:
        raise
    except OSError as error:
        raise _InvalidInput from error
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


def _bounded_payload(payload: bytes) -> bytes:
    if not payload or len(payload) > _MAX_INPUT_BYTES:
        raise _InvalidInput
    return payload


def _parse_audit_run(payload: bytes) -> AuditRun:
    try:
        text = payload.decode("utf-8")
        decoder = json.JSONDecoder(object_pairs_hook=_reject_duplicate_keys)
        start = len(text) - len(text.lstrip())
        _, end = decoder.raw_decode(text, start)
        if text[end:].strip():
            raise _InvalidInput
        return AuditRun.model_validate_json(payload)
    except _InvalidInput:
        raise
    except (RecursionError, UnicodeDecodeError, ValueError, TypeError):
        raise _InvalidInput from None


def _canonical_artifact_reference(reference: ArtifactRef) -> str:
    if type(reference) is not ArtifactRef:
        raise _OperationalFailure
    return (
        json.dumps(
            reference.model_dump(mode="json"),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise _InvalidInput
        document[key] = value
    return document


__all__ = ["main"]
