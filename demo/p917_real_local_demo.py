"""Bounded P9.17 real-local-model instructor demo.

This runner inspects regular Python files only.  It never imports or executes
the selected repository; every source byte is read from an immutable digest
snapshot and a proposed repair is applied only below a temporary directory.
The ordinary path makes one mandatory discovery request and, on agreement,
one separate repair request to the literal loopback Qwen profile. Reports contain metadata and
hashes, never source bytes, credentials, or the raw model response.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import html
import http.client
import json
import stat
import tempfile
import time
from pathlib import Path
from typing import Any, Protocol

from securecode_ai.adapters import (
    AuthorizedProviderHarness,
    EndpointAuthorizationIssuer,
    HmacContentIdentifier,
    JsonObjectValidator,
    PreparedModelContext,
    ProviderProfileRegistry,
    analyze_python_ast,
    build_python_symbol_index,
    parse_provider_profile,
    scan_python_cwe89,
)
from securecode_ai.adapters.openai_compatible_local import OpenAICompatibleLocalHttpConnector
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    DataClass,
    EgressContentRef,
    EgressPolicyDocument,
    EvidenceInputRef,
    ExecutionBoundary,
    ModelCallBudget,
    ModelCallStatus,
    ModelPreflightRequest,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    ProviderProfile,
    RepositoryRevision,
    RunExecutionIdentity,
)
from securecode_ai.core import EgressPolicyRegistry, ModelAuthorizationIssuer

_ROOT = Path(__file__).resolve().parents[1]
_PROFILE_PATH = (
    _ROOT / "specs" / "contracts" / "provider-fixtures" / "valid.local-openai-compatible.json"
)
_POLICY_PATH = (
    _ROOT / "specs" / "contracts" / "policy" / "fixtures" / "egress.valid.private-model-source.json"
)
_MODEL_ID = "qwen2.5-coder:7b-instruct-q4_K_M"
_OLLAMA_VERSION = "0.16.2"
_MODEL_DIGEST = "\x64\x61\x65\x31\x36\x31\x65\x32\x37\x62\x30\x65\x39\x30\x64\x64\x31\x38\x35\x36\x63\x38\x62\x62\x33\x32\x30\x39\x32\x30\x31\x66\x64\x36\x37\x33\x36\x64\x38\x65\x62\x36\x36\x32\x39\x38\x65\x37\x35\x65\x64\x38\x37\x35\x37\x31\x34\x38\x36\x66\x34\x33\x36\x34"
_MODEL_QUANTIZATION = "Q4_K_M"
_METADATA_BYTES = 65_536
_METADATA_TIMEOUT = 5.0
_MAX_FILES = 64
_MAX_FILE_BYTES = 262_144
_MAX_SNAPSHOT_BYTES = 1_048_576
_MAX_MODEL_CONTEXT_BYTES = 24_000
_MAX_PATCH_BYTES = 16_384
_MANIFEST_NAME = "p917-local-demo.json"
_HTML_NAME = "p917-local-demo.html"
_VALIDATION_NAME = "p917-ephemeral-validation.json"
_PATCH_NAME = "model-proposed.patch"


class DemoError(ValueError):
    """Safe setup failure; error messages intentionally exclude repository data."""


class _ModelClient(Protocol):
    """Small test seam; production calls use ``AuthorizedProviderHarness``."""

    def complete(self, prompt: str) -> object: ...


class _PublicBenchmarkRuntime(Protocol):
    """Authorized runtime that admits source bytes before each remote call."""

    def invoke(
        self, snapshot: dict[str, Any], prompt: str, purpose: ModelPurpose
    ) -> dict[str, Any]: ...

    def safe_metadata(self) -> dict[str, Any]: ...


class _LiteralLoopbackResolver:
    def resolve(self, authority: str, port: int) -> tuple[str, ...]:
        if authority != "127.0.0.1" or port != 11434:
            raise ValueError("literal loopback profile changed")
        return ("127.0.0.1",)


def _metadata_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DemoError("local runtime metadata is invalid")
        result[key] = value
    return result


def _read_runtime_metadata(path: str) -> dict[str, Any]:
    """Direct literal-loopback HTTP, without environment proxies or redirects."""
    if path not in {"/api/version", "/api/tags"}:
        raise DemoError("local runtime metadata endpoint is invalid")
    connection = http.client.HTTPConnection("127.0.0.1", 11434, timeout=_METADATA_TIMEOUT)
    deadline = time.monotonic() + _METADATA_TIMEOUT
    try:
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        if (
            response.status != 200
            or response.getheader("Content-Type", "").split(";", 1)[0] != "application/json"
            or response.getheader("Content-Encoding") not in (None, "identity")
        ):
            raise DemoError("local runtime metadata response is invalid")
        body = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DemoError("local runtime metadata deadline exceeded")
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            chunk = response.read1(min(4096, _METADATA_BYTES + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > _METADATA_BYTES:
                raise DemoError("local runtime metadata exceeds bounded limits")
        value = json.loads(body.decode("utf-8"), object_pairs_hook=_metadata_object)
        if type(value) is not dict:
            raise DemoError("local runtime metadata is invalid")
        return value
    except Exception:
        raise DemoError("local runtime metadata could not be verified") from None
    finally:
        connection.close()


def _observe_runtime_identity() -> dict[str, Any]:
    version = _read_runtime_metadata("/api/version")
    tags = _read_runtime_metadata("/api/tags")
    if set(version) != {"version"} or version["version"] != _OLLAMA_VERSION:
        raise DemoError("local runtime version drift")
    models = tags.get("models")
    if set(tags) != {"models"} or type(models) is not list or not 1 <= len(models) <= 128:
        raise DemoError("local model metadata is invalid")
    matches: list[dict[str, Any]] = []
    for model in models:
        if type(model) is not dict or set(model) != {
            "name",
            "model",
            "modified_at",
            "size",
            "digest",
            "details",
        }:
            raise DemoError("local model metadata is invalid")
        if (
            any(
                type(model[key]) is not str or not model[key]
                for key in ("name", "model", "modified_at", "digest")
            )
            or type(model["size"]) is not int
            or model["size"] <= 0
        ):
            raise DemoError("local model metadata is invalid")
        details = model["details"]
        if type(details) is not dict or set(details) != {
            "parent_model",
            "format",
            "family",
            "families",
            "parameter_size",
            "quantization_level",
        }:
            raise DemoError("local model details are invalid")
        if (
            any(
                type(details[key]) is not str
                for key in (
                    "parent_model",
                    "format",
                    "family",
                    "parameter_size",
                    "quantization_level",
                )
            )
            or type(details["families"]) is not list
            or any(type(item) is not str for item in details["families"])
        ):
            raise DemoError("local model details are invalid")
        if model["name"] == _MODEL_ID or model["model"] == _MODEL_ID:
            matches.append(model)
    if len(matches) != 1:
        raise DemoError("local model identity is missing or ambiguous")
    selected = matches[0]
    if (
        selected["name"] != _MODEL_ID
        or selected["model"] != _MODEL_ID
        or selected["digest"] != _MODEL_DIGEST
        or selected["details"]["quantization_level"] != _MODEL_QUANTIZATION
    ):
        raise DemoError("local model identity drift")
    return {
        "identity_status": "OBSERVED",
        "observation_source": "literal_loopback_version_and_tags",
        "profile_id": "local-source-model",
        "endpoint": "http://127.0.0.1:11434/v1",
        "runtime_version": version["version"],
        "model_id": selected["name"],
        "model_digest": "sha256:" + selected["digest"],
        "quantization": selected["details"]["quantization_level"],
    }


def run_demo(
    repository: Path,
    output: Path,
    *,
    model_client: _ModelClient | None = None,
    public_runtime: _PublicBenchmarkRuntime | None = None,
) -> dict[str, Any]:
    """Run independent discovery and, only after agreement, one repair call."""

    if model_client is not None and public_runtime is not None:
        raise DemoError("select one model runtime")
    destination = _checked_destination(output)
    snapshot = _snapshot_repository(repository)
    identity = (
        _observe_runtime_identity() if model_client is None and public_runtime is None else None
    )
    deterministic = _deterministic_lane(snapshot)
    model = _normalize_discovery(
        _model_lane(
            snapshot,
            _model_prompt(snapshot),
            model_client=model_client,
            purpose=ModelPurpose.MODEL_NATIVE_DISCOVERY,
            public_runtime=public_runtime,
        ),
        snapshot,
    )
    agreement = _lane_agreement(deterministic, model)
    repair: dict[str, Any] = {
        "status": "NOT_ATTEMPTED",
        "transport": model["transport"],
        "purpose": ModelPurpose.PATCH_GENERATION.value,
    }

    patch = None
    validation: dict[str, Any] = {
        "status": "NOT_PROPOSED",
        "ephemeral_copy": False,
        "parse_status": "NOT_APPLICABLE",
        "rescan_signal_count": None,
    }
    outcome = "COMPLETED"
    if (
        deterministic["status"] != "SUCCEEDED"
        or model["status"] != ModelCallStatus.SUCCEEDED.value
        or agreement["status"] != "AGREED"
    ):
        outcome = "INDETERMINATE"
    elif deterministic["signal_count"]:
        repair = _model_lane(
            snapshot,
            _repair_prompt(snapshot, model["candidates"]),
            model_client=model_client,
            purpose=ModelPurpose.PATCH_GENERATION,
            public_runtime=public_runtime,
        )
        if repair["status"] != ModelCallStatus.SUCCEEDED.value:
            outcome = "INDETERMINATE"
        else:
            patch = _bounded_patch(repair.get("patch"), snapshot, deterministic)
            if patch is None:
                outcome = "INDETERMINATE"
        if patch is not None:
            validation = _validate_ephemeral_patch(snapshot, deterministic, patch)
            if validation["status"] != "PASSED":
                outcome = "INDETERMINATE"
    else:
        repair = {
            "status": "NOT_REQUIRED",
            "transport": model["transport"],
            "purpose": ModelPurpose.PATCH_GENERATION.value,
        }

    if identity is not None and _observe_runtime_identity() != identity:
        raise DemoError("local runtime changed during demo")
    _verify_snapshot(snapshot)
    destination.mkdir(parents=True, exist_ok=True)
    report_files: dict[str, str] = {}
    if patch is not None:
        patch_bytes = patch["diff"].encode("utf-8")
        _write_bytes(destination / _PATCH_NAME, patch_bytes)
        report_files[_PATCH_NAME] = _sha256(patch_bytes)
    validation_bytes = _canonical_json(validation)
    _write_bytes(destination / _VALIDATION_NAME, validation_bytes)
    report_files[_VALIDATION_NAME] = _sha256(validation_bytes)

    manifest = _manifest(
        snapshot, deterministic, model, agreement, repair, patch, validation, outcome, report_files
    )
    if identity is not None:
        manifest["provider_runtime"] = identity | {"observation_boundary": "before_and_after_calls"}
        manifest["model_lane"].update(identity)
    if public_runtime is not None:
        metadata = public_runtime.safe_metadata()
        manifest["provider_runtime"] = metadata
        manifest["model_lane"].update(
            {key: metadata[key] for key in ("profile_id", "endpoint", "model_id")}
        )
    html_bytes = _html_report(manifest).encode("utf-8")
    _write_bytes(destination / _HTML_NAME, html_bytes)
    report_files[_HTML_NAME] = _sha256(html_bytes)
    manifest["report_sha256"] = dict(sorted(report_files.items()))
    _write_bytes(destination / _MANIFEST_NAME, _canonical_json(manifest))
    return manifest


def _snapshot_repository(repository: Path) -> dict[str, Any]:
    if not isinstance(repository, Path):
        raise DemoError("repository must be a pathlib Path")
    root = repository.resolve()
    if not root.is_dir() or root.is_symlink():
        raise DemoError("repository must be a real directory")
    files: list[dict[str, object]] = []
    total = 0
    try:
        candidates = sorted(root.rglob("*.py"), key=lambda item: item.as_posix())
    except OSError:
        raise DemoError("repository cannot be enumerated") from None
    for path in candidates:
        relative = path.relative_to(root).as_posix()
        if any(part in {".git", ".venv", "__pycache__"} for part in Path(relative).parts):
            continue
        try:
            mode = path.lstat().st_mode
        except OSError:
            raise DemoError("repository entry cannot be inspected") from None
        if path.is_symlink() or not stat.S_ISREG(mode):
            raise DemoError("repository contains an unsafe Python entry")
        try:
            source = path.read_bytes()
        except OSError:
            raise DemoError("repository source cannot be read") from None
        if not source or len(source) > _MAX_FILE_BYTES:
            raise DemoError("repository source exceeds bounded limits")
        total += len(source)
        if len(files) >= _MAX_FILES or total > _MAX_SNAPSHOT_BYTES:
            raise DemoError("repository exceeds bounded limits")
        files.append({"path": relative, "bytes": source, "sha256": _sha256(source)})
    if not files:
        raise DemoError("repository contains no bounded Python files")
    material = [{"path": item["path"], "sha256": item["sha256"]} for item in files]
    canonical = _canonical_json({"files": material})
    return {
        "root": root,
        "files": tuple(files),
        "revision": hashlib.sha1(canonical).hexdigest(),
        "snapshot_sha256": _sha256(canonical),
        "total_bytes": total,
    }


def _verify_snapshot(snapshot: dict[str, Any]) -> None:
    root = snapshot["root"]
    files = snapshot["files"]
    if not isinstance(root, Path) or not isinstance(files, tuple):
        raise DemoError("snapshot is invalid")
    for item in files:
        if not isinstance(item, dict):
            raise DemoError("snapshot is invalid")
        path, expected = item.get("path"), item.get("sha256")
        if not isinstance(path, str) or not isinstance(expected, str):
            raise DemoError("snapshot is invalid")
        try:
            current = (root / path).read_bytes()
        except OSError:
            raise DemoError("source snapshot changed during demo") from None
        if _sha256(current) != expected:
            raise DemoError("source snapshot changed during demo")


def _deterministic_lane(snapshot: dict[str, Any]) -> dict[str, Any]:
    revision = _required_text(snapshot, "revision")
    results: list[dict[str, object]] = []
    for item in _files(snapshot):
        path, source, digest = _file_parts(item)
        try:
            index = build_python_symbol_index(
                repository_id="p917-local-demo",
                revision=revision,
                path=path,
                content_sha256=digest,
                source=source,
            )
            result = scan_python_cwe89(index, analyze_python_ast(index))
        except Exception:
            return {"status": "INDETERMINATE", "signal_count": 0, "findings": ()}
        for ordinal, signal in enumerate(result.signals, start=1):
            results.append(
                {
                    "finding_id": f"det-cwe89-{len(results) + 1}",
                    "path": path,
                    "cwe": signal.cwe,
                    "sink_start_row": signal.sink.start_point.row + 1,
                    "sink_end_row": signal.sink.end_point.row + 1,
                    "signal_sha256": _sha256(f"{result.scan_sha256}:{ordinal}".encode("ascii")),
                }
            )
        # The accepted adapter owns its richer HTTP-source flow.  This narrow
        # demo supplement catches conservative local SQL construction without
        # executing the file or expanding beyond CWE-89.  It remains active
        # beside adapter signals, while exact sink rows prevent duplicates.
        adapter_rows = {signal.sink.start_point.row + 1 for signal in result.signals}
        for line in _static_execute_interpolation_lines(source):
            if line in adapter_rows:
                continue
            results.append(
                {
                    "finding_id": f"det-cwe89-{len(results) + 1}",
                    "path": path,
                    "cwe": "CWE-89",
                    "sink_start_row": line,
                    "sink_end_row": line,
                    "signal_sha256": _sha256(f"p917-static-cwe89:{digest}:{line}".encode("ascii")),
                }
            )
    return {"status": "SUCCEEDED", "signal_count": len(results), "findings": tuple(results)}


def _static_execute_interpolation_lines(source: bytes) -> tuple[int, ...]:
    """Find direct and intraprocedural dynamic-SELECT execute sinks.

    The propagation deliberately follows only a simple local name in one
    lexical body.  A reassignment, nested scope, or control-flow boundary
    discards the binding rather than guessing a data flow.
    """

    try:
        tree = ast.parse(source, mode="exec")
    except (SyntaxError, ValueError, TypeError):
        return ()
    lines: list[int] = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
            and node.args
        ):
            continue
        if not _is_dynamic_select_expression(node.args[0]):
            continue
        if isinstance(node.lineno, int) and node.lineno > 0:
            lines.append(node.lineno)
    for body in _lexical_bodies(tree):
        lines.extend(_propagated_execute_lines(body))
    return tuple(sorted(set(lines)))


def _is_dynamic_select_expression(value: ast.expr) -> bool:
    """Recognize only f-string or ``+`` SQL construction with a dynamic part."""

    if not (
        isinstance(value, ast.JoinedStr)
        or (isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add))
    ):
        return False
    contains_select = any(
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "select" in node.value.lower()
        for node in ast.walk(value)
    )
    dynamic = any(isinstance(node, (ast.FormattedValue, ast.Name)) for node in ast.walk(value))
    return contains_select and dynamic


def _lexical_bodies(tree: ast.Module) -> tuple[list[ast.stmt], ...]:
    bodies: list[list[ast.stmt]] = [tree.body]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bodies.append(node.body)
    return tuple(bodies)


def _propagated_execute_lines(body: list[ast.stmt]) -> tuple[int, ...]:
    bindings: set[str] = set()
    lines: list[int] = []
    for statement in body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(
            statement,
            (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.Match),
        ):
            bindings.clear()
            continue
        for call in _one_argument_execute_calls(statement):
            argument = call.args[0]
            if (
                isinstance(argument, ast.Name)
                and argument.id in bindings
                and isinstance(call.lineno, int)
                and call.lineno > 0
            ):
                lines.append(call.lineno)
        _update_local_bindings(statement, bindings)
    return tuple(lines)


def _one_argument_execute_calls(statement: ast.stmt) -> tuple[ast.Call, ...]:
    if any(
        isinstance(node, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp))
        for node in ast.walk(statement)
    ):
        return ()
    return tuple(
        node
        for node in ast.walk(statement)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "execute"
        and len(node.args) == 1
        and not node.keywords
    )


def _update_local_bindings(statement: ast.stmt, bindings: set[str]) -> None:
    assigned = _assigned_names(statement)
    bindings.difference_update(assigned)
    if (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and _is_dynamic_select_expression(statement.value)
    ):
        bindings.add(statement.targets[0].id)
    elif (
        isinstance(statement, ast.AnnAssign)
        and isinstance(statement.target, ast.Name)
        and statement.value is not None
        and _is_dynamic_select_expression(statement.value)
    ):
        bindings.add(statement.target.id)


def _assigned_names(statement: ast.stmt) -> set[str]:
    targets: list[ast.expr] = []
    if isinstance(statement, ast.Assign):
        targets = statement.targets
    elif isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
        targets = [statement.target]
    elif isinstance(statement, ast.Delete):
        targets = statement.targets
    names: set[str] = set()
    for target in targets:
        names.update(
            node.id
            for node in ast.walk(target)
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
        )
    return names


def _model_prompt(snapshot: dict[str, Any]) -> str:
    """Build discovery input from the immutable snapshot, never scanner output."""

    instructions = {
        "task": "Inspect the supplied bounded Python snapshot. Return exactly one JSON object whose sole top-level key is candidates. The required_shape below is an output template, not a wrapper key.",
        "required_shape": {"candidates": [{"path": "relative.py", "line": 1, "cwe_id": "CWE-89"}]},
        "rules": [
            "Candidates must contain only path, line and cwe_id.",
            'For no candidate return exactly {"candidates":[]}. Never wrap the result in required_shape, analysis, result or task.',
            "Source lines use exact physical markers NNNN|. A candidate line MUST be the physical source line containing the .execute( call, never a SQL assignment or guessed line.",
            "Before emitting a candidate, verify that the .execute( call has exactly one positional argument. A local query variable assigned a dynamic SELECT f-string or concatenation is eligible only when that one-argument call later uses it.",
            "execute(query, parameters) has two arguments, is parameterized, and MUST NOT be reported as CWE-89 even when query contains SELECT or placeholders.",
            "Do not return prose, markdown, credentials, or unrelated files.",
        ],
        "snapshot_sha256": snapshot["snapshot_sha256"],
    }
    return _snapshot_prompt(instructions, snapshot)


def _repair_prompt(snapshot: dict[str, Any], candidates: object) -> str:
    """Ask once for a patch only after the independently discovered locations agree."""

    if not isinstance(candidates, list):
        raise DemoError("normalized discovery candidates are invalid")
    instructions = {
        "task": "Propose one bounded Python repair for the supplied agreed candidate locations. Return exactly one JSON object whose sole top-level key is patch. The required_shape below is an output template, not a wrapper key.",
        "agreed_candidates": candidates,
        "required_shape": {
            "patch": {
                "path": "relative.py",
                "line": 1,
                "replacement": "one complete replacement Python line",
            }
        },
        "rules": [
            "Return only patch; do not return candidates or prose.",
            "Patch must name an agreed candidate location.",
            "Replacement must call execute with a constant SQL string containing ? and a second positional tuple argument, without f-strings or concatenation.",
        ],
        "snapshot_sha256": snapshot["snapshot_sha256"],
    }
    return _snapshot_prompt(instructions, snapshot)


def _snapshot_prompt(instructions: dict[str, object], snapshot: dict[str, Any]) -> str:
    prefix = json.dumps(instructions, ensure_ascii=True, sort_keys=True) + "\n"
    prefix_bytes = len(prefix.encode("utf-8"))
    if prefix_bytes >= _MAX_MODEL_CONTEXT_BYTES:
        raise DemoError("model instructions exceed the bounded context")
    source_chunks: list[str] = []
    used = prefix_bytes
    for item in _files(snapshot):
        path, source, _ = _file_parts(item)
        try:
            encoded = source.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise DemoError("snapshot cannot be encoded for the model") from None
        numbered = "".join(
            f"{line_number:04d}|{line}"
            for line_number, line in enumerate(encoded.splitlines(keepends=True), start=1)
        )
        if encoded and not encoded.endswith(("\n", "\r")):
            numbered += "\n"
        chunk = f"FILE {path}\n{numbered}END FILE\n"
        chunk_bytes = len(chunk.encode("utf-8"))
        if used + chunk_bytes > _MAX_MODEL_CONTEXT_BYTES:
            raise DemoError("snapshot exceeds the bounded model context")
        source_chunks.append(chunk)
        used += chunk_bytes
    if not source_chunks:
        raise DemoError("snapshot cannot fit the bounded model context")
    return prefix + "".join(source_chunks)


def _model_lane(
    snapshot: dict[str, Any],
    prompt: str,
    model_client: _ModelClient | None,
    *,
    purpose: ModelPurpose,
    public_runtime: _PublicBenchmarkRuntime | None = None,
) -> dict[str, Any]:
    is_discovery = purpose is ModelPurpose.MODEL_NATIVE_DISCOVERY
    if public_runtime is not None:
        try:
            return public_runtime.invoke(snapshot, prompt, purpose)
        except Exception:
            return {
                "status": ModelCallStatus.PROVIDER_ERROR.value,
                "candidates": None,
                "patch": None,
                "transport": "authorized_public_benchmark",
            }
    if model_client is not None:
        try:
            received = model_client.complete(prompt)
        except Exception:
            return {
                "status": ModelCallStatus.PROVIDER_ERROR.value,
                "candidates": None,
                "patch": None,
                "transport": "injected",
            }
        if not isinstance(received, dict):
            return {
                "status": ModelCallStatus.INVALID_SCHEMA.value,
                "candidates": None,
                "patch": None,
                "transport": "injected",
            }
        status = received.get("status", ModelCallStatus.SUCCEEDED.value)
        if not isinstance(status, str) or status not in {item.value for item in ModelCallStatus}:
            status = ModelCallStatus.INVALID_SCHEMA.value
        return {
            "status": status,
            "candidates": received.get("candidates") if is_discovery else None,
            "patch": received.get("patch") if not is_discovery else None,
            "transport": "injected",
        }

    profile_data = json.loads(_PROFILE_PATH.read_text(encoding="utf-8"))
    profile_data["model_id"] = _MODEL_ID
    profile_data["model_snapshot"] = "sha256:" + _MODEL_DIGEST
    profile = parse_provider_profile(json.dumps(profile_data, sort_keys=True).encode("utf-8"))
    policy = _demo_policy()
    request = _model_request(snapshot, profile, policy, purpose=purpose, prompt_text=prompt)
    harness = AuthorizedProviderHarness(
        model_issuer=ModelAuthorizationIssuer(
            provider_registry=ProviderProfileRegistry((profile,)),
            policy_registry=EgressPolicyRegistry((policy,)),
        ),
        endpoint_issuer=EndpointAuthorizationIssuer(
            provider_registry=ProviderProfileRegistry((profile,))
        ),
    )
    identifier = HmacContentIdentifier(b"p917-local-demo-content-id-key-0001")
    try:
        execution = harness.execute_remote(
            preflight=ModelPreflightRequest(
                schema_version=CONTRACT_SCHEMA_VERSION,
                model_request=request,
                required_execution_boundary=ExecutionBoundary.LOCAL_RUNNER,
                required_data_class=DataClass.CONFIDENTIAL_SOURCE,
                required_purpose=purpose,
                planned_transforms=("bounded_repository_view",),
                required_max_bytes=_MAX_MODEL_CONTEXT_BYTES,
            ),
            profile=profile,
            policy=policy,
            context_builder=lambda: PreparedModelContext(
                payload=prompt.encode("utf-8"),
                content=(
                    EgressContentRef(
                        schema_version=CONTRACT_SCHEMA_VERSION,
                        content_id="kid:p917-source-snapshot",
                        data_class=DataClass.CONFIDENTIAL_SOURCE,
                    ),
                ),
                applied_transforms=("bounded_repository_view",),
                request_id=request.request_id,
                tenant_id=request.tenant_id,
                content_identifier=identifier,
            ),
            resolver=_LiteralLoopbackResolver(),
            connector=OpenAICompatibleLocalHttpConnector(
                profile=profile,
                temperature=0.0,
                seed=42,
            ),
            credential_supplier=lambda selected: None,
            validator=JsonObjectValidator(
                validator=request.output_schema,
                data_class=DataClass.CONFIDENTIAL_SECURITY,
                content_identifier=HmacContentIdentifier(b"p917-local-demo-output-id-key-00001"),
                required_keys=("candidates",) if is_discovery else ("patch",),
            ),
            now=time.monotonic(),
        )
    except Exception:
        return {
            "status": ModelCallStatus.PROVIDER_ERROR.value,
            "candidates": None,
            "patch": None,
            "transport": "authorized_loopback",
        }
    if execution.result is None:
        return {
            "status": ModelCallStatus.PROVIDER_ERROR.value,
            "candidates": None,
            "patch": None,
            "transport": "authorized_loopback",
        }
    status = execution.result.status.value
    payload = execution.payload
    if status != ModelCallStatus.SUCCEEDED.value or payload is None:
        return {
            "status": status,
            "candidates": None,
            "patch": None,
            "transport": "authorized_loopback",
        }
    try:
        with payload:
            value = payload.reveal_for(request.request_id)
        if not isinstance(value, dict):
            raise ValueError
        return {
            "status": status,
            "candidates": value.get("candidates") if is_discovery else None,
            "patch": value.get("patch") if not is_discovery else None,
            "transport": "authorized_loopback",
        }
    except Exception:
        return {
            "status": ModelCallStatus.INVALID_SCHEMA.value,
            "candidates": None,
            "patch": None,
            "transport": "authorized_loopback",
        }
    finally:
        identifier.close()


def _model_request(
    snapshot: dict[str, Any],
    profile: ProviderProfile,
    policy: EgressPolicyDocument,
    *,
    purpose: ModelPurpose,
    prompt_text: str,
) -> ModelRequest:
    if (
        not hasattr(profile, "profile_id")
        or not hasattr(profile, "profile_version")
        or not hasattr(profile, "canonical_content_hash")
    ):
        raise DemoError("literal loopback profile is invalid")
    profile_pin = _pin(
        str(profile.profile_id), str(profile.profile_version), profile.canonical_content_hash()
    )
    policy_pin = _pin(policy.policy_id, policy.policy_version, policy.canonical_content_hash())
    egress_pin = _pin(policy.profile.value, policy.policy_version, policy.canonical_content_hash())
    revision = _required_text(snapshot, "revision")
    identity = RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id=policy.tenant_scope,
            scm_provider="local",
            repository_id="p917-local-demo",
            head_sha=revision,
        ),
        stage_catalogue=_pin("p917-stage", "1.0.0", "1" * 64),
        workflow=_pin("p917-workflow", "1.0.0", "2" * 64),
        policy=policy_pin,
        configuration=_pin("p917-config", "1.0.0", "3" * 64),
        provider_profile=profile_pin,
        capability_profile=_pin("p917-capability", "1.0.0", "4" * 64),
        egress_profile=egress_pin,
    )
    token = _required_text(snapshot, "snapshot_sha256")[:16]
    is_discovery = purpose is ModelPurpose.MODEL_NATIVE_DISCOVERY
    stage = "discovery" if is_discovery else "repair"
    return ModelRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        request_id=f"p917-{stage}-request-{token}",
        run_id=f"p917-run-{token}",
        tenant_id=policy.tenant_scope,
        idempotency_key=f"p917-{stage}-idempotency-{token}",
        attempt=1,
        execution_identity=identity,
        head_sha=revision,
        role=ModelRole.DISCOVERY if is_discovery else ModelRole.ARCHITECT,
        mode=purpose,
        provider_profile=profile_pin,
        api_dialect=profile.api_dialect,
        model_id=profile.model_id,
        prompt=_pin(f"p917-{stage}-prompt", "3.0.0", _sha256(prompt_text.encode("utf-8"))),
        output_schema=_pin(
            f"p917-{stage}-output", "1.0.0", _sha256(f"p917-{stage}-output-v2".encode("ascii"))
        ),
        tool_policy=_pin("p917-read-only-tools", "1.0.0", "7" * 64),
        repository_scope=_pin(
            "p917-snapshot", "1.0.0", _required_text(snapshot, "snapshot_sha256")
        ),
        repository_view_policy=_pin("p917-bounded-view", "1.0.0", "8" * 64),
        evidence=()
        if is_discovery
        else (
            EvidenceInputRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                evidence_id="evd:p917-discovery",
                content_id="kid:p917-discovery",
                data_class=DataClass.CONFIDENTIAL_SECURITY,
            ),
        ),
        budget=ModelCallBudget(
            schema_version=CONTRACT_SCHEMA_VERSION,
            max_input_tokens=6144,
            max_output_tokens=1024,
            max_repository_calls=1,
            max_context_bytes=65_536,
            timeout_ms=60_000,
        ),
    )


def _demo_policy() -> EgressPolicyDocument:
    """Build the narrowly scoped P9.17 two-stage loopback policy in memory."""

    data = json.loads(_POLICY_PATH.read_text(encoding="utf-8"))
    data["policy_id"] = "p917-local-discovery-repair"
    data["policy_version"] = "1.0.0"
    data["rules"][0]["rule_id"] = "EGR-P917-LOCAL-DISCOVERY-REPAIR"
    data["rules"][0]["purposes"] = [
        ModelPurpose.MODEL_NATIVE_DISCOVERY.value,
        ModelPurpose.PATCH_GENERATION.value,
    ]
    return EgressPolicyDocument.model_validate_json(json.dumps(data))


def _valid_candidates(value: object, snapshot: dict[str, Any]) -> bool:
    if not isinstance(value, list) or len(value) > 32:
        return False
    line_counts = {
        str(item["path"]): len(bytes(item["bytes"]).splitlines()) for item in _files(snapshot)
    }
    seen: set[tuple[str, int, str]] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"path", "line", "cwe_id"}:
            return False
        path = item.get("path")
        if not isinstance(path, str) or path not in line_counts or item.get("cwe_id") != "CWE-89":
            return False
        line = item.get("line")
        if (
            not isinstance(line, int)
            or isinstance(line, bool)
            or line < 1
            or line > line_counts[path]
        ):
            return False
        identity = (path, line, "CWE-89")
        if identity in seen:
            return False
        seen.add(identity)
    return True


def _normalize_discovery(model: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    """Retain only the discovery candidate schema; a patch is never discovery evidence."""

    if model.get("status") != ModelCallStatus.SUCCEEDED.value:
        return {
            "status": model.get("status", ModelCallStatus.PROVIDER_ERROR.value),
            "candidates": None,
            "patch": None,
            "transport": model["transport"],
        }
    candidates = model.get("candidates")
    if not _valid_candidates(candidates, snapshot):
        return {
            "status": ModelCallStatus.INVALID_SCHEMA.value,
            "candidates": None,
            "patch": None,
            "transport": model["transport"],
        }
    assert isinstance(candidates, list)
    return {
        "status": ModelCallStatus.SUCCEEDED.value,
        "candidates": [
            {"path": item["path"], "line": item["line"], "cwe_id": item["cwe_id"]}
            for item in candidates
        ],
        "patch": None,
        "transport": model["transport"],
    }


def _lane_agreement(deterministic: dict[str, Any], model: dict[str, Any]) -> dict[str, Any]:
    """Expose lane disagreement as metadata rather than deleting either lane's facts."""

    deterministic_candidates = [
        {"path": item["path"], "line": item["sink_start_row"], "cwe_id": "CWE-89"}
        for item in deterministic["findings"]
    ]
    if deterministic["status"] != "SUCCEEDED" or model["status"] != ModelCallStatus.SUCCEEDED.value:
        return {
            "status": "INDETERMINATE",
            "deterministic_only": deterministic_candidates,
            "model_only": None,
            "location_disagreements": None,
        }
    model_candidates = model["candidates"]
    if not isinstance(model_candidates, list):
        return {
            "status": "INDETERMINATE",
            "deterministic_only": deterministic_candidates,
            "model_only": None,
            "location_disagreements": None,
        }
    deterministic_keys = {
        (item["path"], item["line"], item["cwe_id"]) for item in deterministic_candidates
    }
    model_keys = {(item["path"], item["line"], item["cwe_id"]) for item in model_candidates}
    paths = sorted(
        {item["path"] for item in deterministic_candidates}
        & {item["path"] for item in model_candidates}
    )
    disagreements = [
        {
            "path": path,
            "deterministic_lines": sorted(
                item["line"] for item in deterministic_candidates if item["path"] == path
            ),
            "model_lines": sorted(
                item["line"] for item in model_candidates if item["path"] == path
            ),
        }
        for path in paths
        if {item["line"] for item in deterministic_candidates if item["path"] == path}
        != {item["line"] for item in model_candidates if item["path"] == path}
    ]
    return {
        "status": "AGREED" if deterministic_keys == model_keys else "INDETERMINATE",
        "deterministic_only": [
            item
            for item in deterministic_candidates
            if (item["path"], item["line"], item["cwe_id"]) not in model_keys
        ],
        "model_only": [
            item
            for item in model_candidates
            if (item["path"], item["line"], item["cwe_id"]) not in deterministic_keys
        ],
        "location_disagreements": disagreements,
    }


def _bounded_patch(
    value: object, snapshot: dict[str, Any], deterministic: dict[str, Any]
) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, dict):
        parsed = _parse_model_replacement(value, snapshot, deterministic)
    elif isinstance(value, str):
        if "\x00" in value or len(value.encode("utf-8")) > _MAX_PATCH_BYTES:
            return None
        parsed = _parse_unified_patch(value)
        if parsed is None:
            parsed = _recover_single_line_model_patch(value, snapshot, deterministic)
    else:
        return None
    if parsed is None:
        return None
    path, old_bytes, new_bytes = parsed
    if path not in {item["path"] for item in _files(snapshot)}:
        return None
    finding_paths = {item["path"] for item in deterministic["findings"]}
    if path not in finding_paths:
        return None
    source = next(item["bytes"] for item in _files(snapshot) if item["path"] == path)
    if source.count(old_bytes) != 1:
        return None
    changed = source.replace(old_bytes, new_bytes, 1)
    normalized_diff = _unified_patch(path, source, changed)
    return {
        "path": path,
        "old": old_bytes,
        "new": new_bytes,
        "changed": changed,
        "diff": normalized_diff,
        "sha256": _sha256(normalized_diff.encode("utf-8")),
    }


def _validate_ephemeral_patch(
    snapshot: dict[str, Any], deterministic: dict[str, Any], patch: dict[str, Any]
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="securecode-p917-") as temporary:
        workspace = Path(temporary) / "candidate"
        workspace.mkdir()
        try:
            for item in _files(snapshot):
                path, source, _ = _file_parts(item)
                target = workspace / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(patch["changed"] if path == patch["path"] else source)
            changed = workspace / str(patch["path"])
            ast.parse(changed.read_text(encoding="utf-8"), filename=str(patch["path"]))
            candidate = dict(snapshot)
            candidate["root"] = workspace
            candidate["files"] = tuple(
                {
                    "path": item["path"],
                    "bytes": (workspace / str(item["path"])).read_bytes(),
                    "sha256": _sha256((workspace / str(item["path"])).read_bytes()),
                }
                for item in _files(snapshot)
            )
            rescanned = _deterministic_lane(candidate)
            signal_count = rescanned["signal_count"]
            target_has_signal = any(item["path"] == patch["path"] for item in rescanned["findings"])
            if rescanned["status"] != "SUCCEEDED" or target_has_signal:
                return {
                    "status": "FAILED_RESCAN",
                    "ephemeral_copy": True,
                    "parse_status": "PARSED",
                    "rescan_signal_count": signal_count,
                }
            return {
                "status": "PASSED",
                "ephemeral_copy": True,
                "parse_status": "PARSED",
                "rescan_signal_count": signal_count,
            }
        except (OSError, UnicodeError, SyntaxError, ValueError, TypeError):
            return {
                "status": "FAILED_STATIC_VALIDATION",
                "ephemeral_copy": True,
                "parse_status": "FAILED",
                "rescan_signal_count": None,
            }


def _manifest(
    snapshot: dict[str, Any],
    deterministic: dict[str, Any],
    model: dict[str, Any],
    agreement: dict[str, Any],
    repair: dict[str, Any],
    patch: dict[str, Any] | None,
    validation: dict[str, Any],
    outcome: str,
    report_files: dict[str, str],
) -> dict[str, Any]:
    findings = [
        {key: value for key, value in item.items() if key != "signal_sha256"}
        | {"signal_sha256": item["signal_sha256"]}
        for item in deterministic["findings"]
    ]
    return {
        "artifact_schema_version": "securecode.p9_17.local-demo.v1",
        "task_id": "P9.17",
        "outcome": outcome,
        "product_pass": False,
        "gate_or_release_claim": "NOT_EVALUATED",
        "source_repository_changed": False,
        "snapshot": {
            "sha256": snapshot["snapshot_sha256"],
            "revision": snapshot["revision"],
            "python_file_count": len(_files(snapshot)),
            "total_bytes": snapshot["total_bytes"],
        },
        "deterministic_lane": {
            "status": deterministic["status"],
            "signal_count": deterministic["signal_count"],
            "candidate_count": deterministic["signal_count"],
            "findings": findings,
        },
        "model_lane": {
            "status": model["status"],
            "purpose": ModelPurpose.MODEL_NATIVE_DISCOVERY.value,
            "candidate_count": len(model["candidates"])
            if isinstance(model.get("candidates"), list)
            else None,
            "candidates": model["candidates"],
            "transport": model["transport"],
            "identity_status": "NOT_OBSERVED",
            "profile_id": None,
            "endpoint": None,
            "model_id": None,
        },
        "lane_agreement": agreement,
        "repair": {
            "status": repair["status"],
            "transport": repair["transport"],
            "purpose": ModelPurpose.PATCH_GENERATION.value,
        },
        "patch": {
            "present": patch is not None,
            "status": "NOT_PROPOSED" if patch is None else "PROPOSED",
            "path": None if patch is None else patch["path"],
            "sha256": None if patch is None else patch["sha256"],
            "applied_to_source": False,
        },
        "ephemeral_validation": validation,
        "report_sha256": dict(sorted(report_files.items())),
        "limitations": [
            "One bounded Python CWE-89 rule is demonstrated; this is not a general security verdict.",
            "The model response is transient and is not retained in JSON or HTML reports.",
            "Static parse and rescan do not execute the repository and do not prove behavioral correctness.",
            "A provider, schema, identity, or validation non-success is INDETERMINATE rather than clean or PASS.",
            "Lane agreement is only a diagnostic comparison, not Auditor/Skeptic confirmation or proof of accuracy.",
        ],
    }


def _html_report(manifest: dict[str, Any]) -> str:
    safe = html.escape(json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2))
    return (
        '<!doctype html><meta charset="utf-8"><title>SecureCode AI P9.17</title><h1>SecureCode AI P9.17 local demo</h1><p>Metadata-only report; source and model output are excluded.</p><pre>'
        + safe
        + "</pre>"
    )


def _unified_patch(path: str, old: bytes, new: bytes) -> str:
    import difflib

    return "".join(
        difflib.unified_diff(
            old.decode("utf-8").splitlines(keepends=True),
            new.decode("utf-8").splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


def _parse_unified_patch(value: str) -> tuple[str, bytes, bytes] | None:
    """Accept exactly one bounded standard hunk without applying a general diff."""

    import re

    lines = value.splitlines(keepends=True)
    if len(lines) < 5 or not lines[0].startswith("--- a/") or not lines[1].startswith("+++ b/"):
        return None
    old_path = lines[0][6:].rstrip("\r\n")
    new_path = lines[1][6:].rstrip("\r\n")
    if not old_path or old_path != new_path or ".." in Path(old_path).parts:
        return None
    match = re.fullmatch(
        r"@@ -([1-9][0-9]*)(?:,[0-9]+)? \+[1-9][0-9]*(?:,[0-9]+)? @@(?:.*)?\r?\n", lines[2]
    )
    if match is None:
        return None
    old_lines: list[str] = []
    new_lines: list[str] = []
    for line in lines[3:]:
        if not line or line[0] not in {" ", "+", "-"}:
            return None
        if line[0] in {" ", "-"}:
            old_lines.append(line[1:])
        if line[0] in {" ", "+"}:
            new_lines.append(line[1:])
    old, new = "".join(old_lines).encode("utf-8"), "".join(new_lines).encode("utf-8")
    if not old or old == new:
        return None
    return old_path, old, new


def _recover_single_line_model_patch(
    value: str,
    snapshot: dict[str, Any],
    deterministic: dict[str, Any],
) -> tuple[str, bytes, bytes] | None:
    """Normalize one model-proposed replacement under deterministic anchoring."""

    findings = deterministic.get("findings")
    if not isinstance(findings, tuple) or len(findings) != 1:
        return None
    finding = findings[0]
    if not isinstance(finding, dict):
        return None
    path, row = finding.get("path"), finding.get("sink_start_row")
    if not isinstance(path, str) or not isinstance(row, int) or row < 1:
        return None
    additions = [
        line[1:].rstrip("\r\n")
        for line in value.splitlines(keepends=True)
        if line.startswith("+") and not line.startswith("+++") and line[1:].strip()
    ]
    safe = [line for line in additions if _is_parameterized_execute_line(line)]
    if len(safe) != 1:
        return None
    source = next((item["bytes"] for item in _files(snapshot) if item["path"] == path), None)
    if not isinstance(source, bytes):
        return None
    source_lines = source.splitlines(keepends=True)
    if row > len(source_lines):
        return None
    old = source_lines[row - 1]
    newline = b"\r\n" if old.endswith(b"\r\n") else b"\n"
    indentation = old[: len(old) - len(old.lstrip())]
    new = indentation + safe[0].lstrip().encode("utf-8") + newline
    return path, old, new


def _parse_model_replacement(
    value: dict[str, object],
    snapshot: dict[str, Any],
    deterministic: dict[str, Any],
) -> tuple[str, bytes, bytes] | None:
    if set(value) != {"path", "line", "replacement"}:
        return None
    path, row, replacement = value.get("path"), value.get("line"), value.get("replacement")
    findings = deterministic.get("findings")
    if (
        not isinstance(path, str)
        or not isinstance(row, int)
        or isinstance(row, bool)
        or not isinstance(replacement, str)
        or "\x00" in replacement
        or "\n" in replacement
        or "\r" in replacement
        or len(replacement.encode("utf-8")) > _MAX_PATCH_BYTES
        or not isinstance(findings, tuple)
        or not any(
            isinstance(item, dict)
            and item.get("path") == path
            and item.get("sink_start_row") == row
            for item in findings
        )
        or not _is_parameterized_execute_line(replacement)
    ):
        return None
    source = next((item["bytes"] for item in _files(snapshot) if item["path"] == path), None)
    if not isinstance(source, bytes):
        return None
    source_lines = source.splitlines(keepends=True)
    if row < 1 or row > len(source_lines):
        return None
    old = source_lines[row - 1]
    newline = b"\r\n" if old.endswith(b"\r\n") else b"\n"
    indentation = old[: len(old) - len(old.lstrip())]
    new = indentation + replacement.lstrip().encode("utf-8") + newline
    return path, old, new


def _is_parameterized_execute_line(value: str) -> bool:
    try:
        tree = ast.parse(value.lstrip(), mode="exec")
    except (SyntaxError, ValueError, TypeError):
        return False
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "execute"
    ]
    if len(calls) != 1 or len(calls[0].args) < 2:
        return False
    query = calls[0].args[0]
    if not isinstance(query, ast.Constant) or not isinstance(query.value, str):
        return False
    return "?" in query.value or any(
        character == ":" and index + 1 < len(query.value) and query.value[index + 1].isalpha()
        for index, character in enumerate(query.value)
    )


def _files(snapshot: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    files = snapshot.get("files")
    if not isinstance(files, tuple) or any(not isinstance(item, dict) for item in files):
        raise DemoError("snapshot is invalid")
    return files


def _file_parts(item: dict[str, Any]) -> tuple[str, bytes, str]:
    path, source, digest = item.get("path"), item.get("bytes"), item.get("sha256")
    if not isinstance(path, str) or not isinstance(source, bytes) or not isinstance(digest, str):
        raise DemoError("snapshot is invalid")
    return path, source, digest


def _pin(identifier: str, version: str, digest: str) -> ComponentPin:
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=identifier,
        component_version=version,
        content_sha256=digest,
    )


def _required_text(value: dict[str, Any], field: str) -> str:
    result = value.get(field)
    if not isinstance(result, str) or not result:
        raise DemoError("snapshot is invalid")
    return result


def _checked_destination(value: Path) -> Path:
    if not isinstance(value, Path):
        raise DemoError("output must be a pathlib Path")
    destination = value.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise DemoError("output directory must be absent or empty")
    return destination


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
        + b"\n"
    )


def _write_bytes(path: Path, value: bytes) -> None:
    path.write_bytes(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the bounded P9.17 real local-model demo.")
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        manifest = run_demo(arguments.repository, arguments.output)
    except DemoError as error:
        print(
            json.dumps(
                {"task_id": "P9.17", "outcome": "INDETERMINATE", "error": str(error)},
                ensure_ascii=True,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0 if manifest["outcome"] == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
