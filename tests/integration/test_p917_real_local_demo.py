"""P9.17 real-local demo integration contract.

These tests use an injected model boundary.  They deliberately never call a
provider: the instructor demo's real connector is exercised by the integrator
after this deterministic contract suite passes.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).parents[2]
DEMO_PATH = ROOT / "demo" / "p917_real_local_demo.py"


@pytest.fixture(scope="module")
def demo_module() -> ModuleType:
    if not DEMO_PATH.exists():
        pytest.fail(f"P9.17 runner is not present: {DEMO_PATH}")
    spec = importlib.util.spec_from_file_location("securecode_p917_demo", DEMO_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeModel:
    """Small OpenAI-compatible boundary used by all local demo tests."""

    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[object] = []

    def complete(self, request: object) -> object:
        self.calls.append(request)
        if isinstance(self.response, list):
            response = self.response[len(self.calls) - 1]
            if isinstance(response, BaseException):
                raise response
            return response
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response

    def __call__(self, request: object) -> object:
        return self.complete(request)


def _repo(tmp_path: Path, source: str) -> tuple[Path, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    encoded = source.encode("utf-8")
    (repository / "app.py").write_bytes(encoded)
    return repository, hashlib.sha256(encoded).hexdigest()


def _run(module: ModuleType, repository: Path, output: Path, model: FakeModel) -> dict[str, Any]:
    result = module.run_demo(repository, output, model_client=model)
    assert isinstance(result, dict)
    manifest_path = output / "manifest.json"
    if manifest_path.exists():
        assert json.loads(manifest_path.read_text(encoding="utf-8")) == result
    return result


def test_vulnerable_repo_runs_both_lanes_and_validates_model_patch(
    tmp_path: Path, demo_module: ModuleType
) -> None:
    repository, original_hash = _repo(
        tmp_path,
        "import sqlite3\n\ndef find(conn, value):\n    return conn.execute('SELECT * FROM users WHERE name = ' + value)\n",
    )
    model = FakeModel(
        {
            "status": "SUCCEEDED",
            "candidates": [{"path": "app.py", "line": 4, "cwe_id": "CWE-89"}],
            "patch": "--- a/app.py\n+++ b/app.py\n@@ -2,2 +2,2 @@\n def find(conn, value):\n-    return conn.execute('SELECT * FROM users WHERE name = ' + value)\n+    return conn.execute('SELECT * FROM users WHERE name = ?', (value,))\n",
        }
    )

    manifest = _run(demo_module, repository, tmp_path / "out", model)

    assert model.calls, "model-native discovery must execute"
    assert len(model.calls) == 2
    assert manifest["outcome"] in {"FAIL", "COMPLETED"}
    assert manifest["deterministic_lane"]["status"] == "SUCCEEDED"
    assert manifest["model_lane"]["status"] == "SUCCEEDED"
    assert manifest["model_lane"]["candidate_count"] >= 1
    assert manifest["patch"]["present"] is True
    assert manifest["ephemeral_validation"]["status"] == "PASSED"
    assert len(manifest["patch"]["sha256"]) == 64
    assert hashlib.sha256((repository / "app.py").read_bytes()).hexdigest() == original_hash


def test_safe_repo_still_calls_model_and_has_no_patch(
    tmp_path: Path, demo_module: ModuleType
) -> None:
    repository, original_hash = _repo(
        tmp_path, "def healthy(value: str) -> str:\n    return value\n"
    )
    model = FakeModel({"status": "SUCCEEDED", "candidates": [], "patch": None})

    manifest = _run(demo_module, repository, tmp_path / "out", model)

    assert len(model.calls) == 1, "zero deterministic signals must not skip model lane"
    assert manifest["deterministic_lane"]["candidate_count"] == 0
    assert manifest["model_lane"]["status"] == "SUCCEEDED"
    assert manifest["model_lane"]["candidate_count"] == 0
    assert manifest["patch"]["present"] is False
    assert hashlib.sha256((repository / "app.py").read_bytes()).hexdigest() == original_hash


def test_fstring_sql_sink_is_deterministically_anchored(
    tmp_path: Path, demo_module: ModuleType
) -> None:
    repository, _ = _repo(
        tmp_path,
        "def find(cursor, value):\n    return cursor.execute(f\"SELECT * FROM users WHERE name = '{value}'\")\n",
    )
    model = FakeModel(
        {
            "status": "SUCCEEDED",
            "candidates": [{"path": "app.py", "line": 2, "cwe_id": "CWE-89"}],
            "patch": {
                "path": "app.py",
                "line": 2,
                "replacement": '    return cursor.execute("SELECT * FROM users WHERE name = ?", (value,))',
            },
        }
    )

    manifest = _run(demo_module, repository, tmp_path / "out", model)

    assert manifest["deterministic_lane"]["signal_count"] == 1
    assert manifest["ephemeral_validation"]["status"] == "PASSED"


def test_local_dynamic_select_variable_is_anchored_at_its_execute_call(
    tmp_path: Path, demo_module: ModuleType
) -> None:
    repository, _ = _repo(
        tmp_path,
        "def find(cursor, value):\n    query = f\"SELECT * FROM users WHERE name = '{value}'\"\n    return cursor.execute(query)\n",
    )
    snapshot = demo_module._snapshot_repository(repository)

    deterministic = demo_module._deterministic_lane(snapshot)

    assert deterministic["status"] == "SUCCEEDED"
    assert [(item["path"], item["sink_start_row"]) for item in deterministic["findings"]] == [
        ("app.py", 3)
    ]


def test_local_dynamic_select_concatenation_is_anchored_at_its_execute_call(
    demo_module: ModuleType,
) -> None:
    source = "def find(cursor, value):\n    query = 'SELECT * FROM users WHERE name = ' + value\n    return cursor.execute(query)\n"

    assert demo_module._static_execute_interpolation_lines(source.encode("utf-8")) == (3,)


def test_parameterized_query_variable_is_not_reported(
    tmp_path: Path, demo_module: ModuleType
) -> None:
    source = (
        "def find(cursor, value):\n"
        "    query = 'SELECT * FROM users WHERE name = ?'\n"
        "    return cursor.execute(query, (value,))\n"
    )

    assert demo_module._static_execute_interpolation_lines(source.encode("utf-8")) == ()


def test_reassigned_query_variable_is_not_propagated(
    tmp_path: Path, demo_module: ModuleType
) -> None:
    source = (
        "def find(cursor, value):\n"
        "    query = f\"SELECT * FROM users WHERE name = '{value}'\"\n"
        "    query = 'SELECT * FROM users WHERE name = ?'\n"
        "    return cursor.execute(query)\n"
    )

    assert demo_module._static_execute_interpolation_lines(source.encode("utf-8")) == ()


def test_query_variable_never_leaks_across_function_boundary(demo_module: ModuleType) -> None:
    source = (
        "query = f\"SELECT * FROM users WHERE name = '{value}'\"\n"
        "def find(cursor):\n"
        "    return cursor.execute(query)\n"
    )

    assert demo_module._static_execute_interpolation_lines(source.encode("utf-8")) == ()


def test_discovery_prompt_has_exact_line_markers_and_variable_guidance(
    tmp_path: Path, demo_module: ModuleType
) -> None:
    repository, _ = _repo(
        tmp_path,
        "def find(cursor, value):\n    query = f\"SELECT * FROM users WHERE name = '{value}'\"\n    return cursor.execute(query)\n",
    )

    prompt = demo_module._model_prompt(demo_module._snapshot_repository(repository))

    assert "0001|def find(cursor, value):" in prompt
    assert "0002|    query =" in prompt
    assert "0003|    return cursor.execute(query)" in prompt
    assert "MUST be the physical source line containing the .execute( call" in prompt
    assert "exactly one positional argument" in prompt
    assert "execute(query, parameters) has two arguments" in prompt
    assert "local query variable" in prompt
    assert "det-cwe89" not in prompt


def test_provider_non_success_is_indeterminate_and_does_not_fallback(
    tmp_path: Path, demo_module: ModuleType
) -> None:
    repository, original_hash = _repo(tmp_path, "def healthy(value):\n    return value\n")
    model = FakeModel(RuntimeError("provider unavailable MODEL_SECRET_CANARY"))

    manifest = _run(demo_module, repository, tmp_path / "out", model)

    assert manifest["outcome"] == "INDETERMINATE"
    assert manifest["model_lane"]["status"] != "SUCCEEDED"
    assert manifest["deterministic_lane"]["status"] == "SUCCEEDED"
    assert manifest["patch"]["present"] is False
    assert hashlib.sha256((repository / "app.py").read_bytes()).hexdigest() == original_hash


def test_model_false_positive_on_safe_repo_is_indeterminate(
    tmp_path: Path, demo_module: ModuleType
) -> None:
    repository, _ = _repo(tmp_path, "def healthy(value):\n    return value\n")
    model = FakeModel(
        {
            "status": "SUCCEEDED",
            "candidates": [{"path": "app.py", "line": 1, "cwe_id": "CWE-89"}],
            "patch": None,
        }
    )

    manifest = _run(demo_module, repository, tmp_path / "out", model)

    assert manifest["outcome"] == "INDETERMINATE"
    assert manifest["product_pass"] is False
    assert len(model.calls) == 1
    assert manifest["model_lane"]["candidate_count"] == 1
    assert manifest["model_lane"]["candidates"] == [
        {"path": "app.py", "line": 1, "cwe_id": "CWE-89"}
    ]


def test_discovery_is_identical_when_scanner_result_changes(
    tmp_path: Path, demo_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _ = _repo(
        tmp_path,
        "def find(conn, value):\n    return conn.execute('SELECT * FROM t WHERE x = ' + value)\n",
    )
    first = FakeModel({"status": "SUCCEEDED", "candidates": []})
    _run(demo_module, repository, tmp_path / "first", first)
    monkeypatch.setattr(
        demo_module,
        "_deterministic_lane",
        lambda snapshot: {"status": "SUCCEEDED", "signal_count": 0, "findings": ()},
    )
    second = FakeModel({"status": "SUCCEEDED", "candidates": []})
    _run(demo_module, repository, tmp_path / "second", second)
    assert first.calls[0] == second.calls[0]
    assert len(first.calls) == len(second.calls) == 1


@pytest.mark.parametrize(
    "response",
    [
        RuntimeError("offline"),
        {"status": "INVALID_SCHEMA"},
        {"status": "REFUSED"},
        {"status": "SUCCEEDED", "candidates": []},
    ],
)
def test_discovery_failure_or_miss_is_never_replaced_by_repair(
    tmp_path: Path, demo_module: ModuleType, response: object
) -> None:
    repository, _ = _repo(
        tmp_path,
        "def find(conn, value):\n    return conn.execute('SELECT * FROM t WHERE x = ' + value)\n",
    )
    model = FakeModel(response)
    manifest = _run(demo_module, repository, tmp_path / "out", model)
    assert manifest["outcome"] == "INDETERMINATE"
    assert len(model.calls) == 1
    assert manifest["patch"]["present"] is False


def test_equal_counts_at_different_locations_are_disagreement(
    tmp_path: Path, demo_module: ModuleType
) -> None:
    repository, _ = _repo(
        tmp_path,
        "def find(conn, value):\n    return conn.execute('SELECT * FROM t WHERE x = ' + value)\n",
    )
    model = FakeModel(
        {"status": "SUCCEEDED", "candidates": [{"path": "app.py", "line": 1, "cwe_id": "CWE-89"}]}
    )
    manifest = _run(demo_module, repository, tmp_path / "out", model)
    assert manifest["outcome"] == "INDETERMINATE"
    assert len(model.calls) == 1
    assert manifest["model_lane"]["candidate_count"] == 1


def test_repair_response_cannot_overwrite_discovery(
    tmp_path: Path, demo_module: ModuleType
) -> None:
    repository, _ = _repo(
        tmp_path,
        "def find(conn, value):\n    return conn.execute('SELECT * FROM t WHERE x = ' + value)\n",
    )
    model = FakeModel(
        [
            {
                "status": "SUCCEEDED",
                "candidates": [{"path": "app.py", "line": 2, "cwe_id": "CWE-89"}],
            },
            {"status": "REFUSED", "candidates": [], "patch": None},
        ]
    )
    manifest = _run(demo_module, repository, tmp_path / "out", model)
    assert len(model.calls) == 2
    assert model.calls[0] != model.calls[1]
    assert manifest["model_lane"]["status"] == "SUCCEEDED"
    assert manifest["model_lane"]["candidate_count"] == 1
    assert manifest["outcome"] == "INDETERMINATE"


def test_context_overflow_does_not_silently_omit_files(
    tmp_path: Path, demo_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _ = _repo(tmp_path, "x = 1\n")
    (repository / "z.py").write_text("#" + "a" * 2000 + "\n", encoding="utf-8")
    monkeypatch.setattr(demo_module, "_MAX_MODEL_CONTEXT_BYTES", 2000)
    model = FakeModel({"status": "SUCCEEDED", "candidates": []})
    with pytest.raises(demo_module.DemoError):
        _run(demo_module, repository, tmp_path / "out", model)
    assert model.calls == []


def test_discovery_patch_is_not_used_as_repair(tmp_path: Path, demo_module: ModuleType) -> None:
    repository, _ = _repo(
        tmp_path,
        "def find(conn, value):\n    return conn.execute('SELECT * FROM t WHERE x = ' + value)\n",
    )
    model = FakeModel(
        [
            {
                "status": "SUCCEEDED",
                "candidates": [{"path": "app.py", "line": 2, "cwe_id": "CWE-89"}],
                "patch": {
                    "path": "app.py",
                    "line": 2,
                    "replacement": "return conn.execute('SELECT * FROM t WHERE x = ?', (value,))",
                },
            },
            {"status": "SUCCEEDED", "patch": None},
        ]
    )
    manifest = _run(demo_module, repository, tmp_path / "out", model)
    assert len(model.calls) == 2
    assert manifest["patch"]["present"] is False
    assert manifest["outcome"] == "INDETERMINATE"


def test_out_of_snapshot_line_is_invalid_schema(tmp_path: Path, demo_module: ModuleType) -> None:
    repository, _ = _repo(tmp_path, "x = 1\n")
    model = FakeModel(
        {"status": "SUCCEEDED", "candidates": [{"path": "app.py", "line": 900, "cwe_id": "CWE-89"}]}
    )
    manifest = _run(demo_module, repository, tmp_path / "out", model)
    assert manifest["model_lane"]["status"] == "INVALID_SCHEMA"
    assert manifest["model_lane"]["candidate_count"] is None
    assert len(model.calls) == 1


def test_real_stage_requests_have_separate_authorized_purposes(
    tmp_path: Path, demo_module: ModuleType
) -> None:
    repository, _ = _repo(tmp_path, "x = 1\n")
    snapshot = demo_module._snapshot_repository(repository)
    policy = demo_module._demo_policy()
    profile = demo_module.parse_provider_profile(demo_module._PROFILE_PATH.read_bytes())
    requests = [
        demo_module._model_request(
            snapshot, profile, policy, purpose=purpose, prompt_text="test prompt"
        )
        for purpose in (
            demo_module.ModelPurpose.MODEL_NATIVE_DISCOVERY,
            demo_module.ModelPurpose.PATCH_GENERATION,
        )
    ]
    assert requests[0].request_id != requests[1].request_id
    assert requests[0].output_schema != requests[1].output_schema
    assert requests[0].role == demo_module.ModelRole.DISCOVERY
    assert requests[1].role == demo_module.ModelRole.ARCHITECT
    assert requests[0].prompt.content_sha256 == hashlib.sha256(b"test prompt").hexdigest()
    assert set(policy.rules[0].purposes) == {"model_native_discovery", "patch_generation"}


def test_reports_escape_html_and_retain_no_source_or_model_response(
    tmp_path: Path, demo_module: ModuleType
) -> None:
    source_canary = "SOURCE_PRIVATE_CANARY"
    model_canary = "MODEL_PRIVATE_CANARY <script>alert(1)</script>"
    repository, _ = _repo(tmp_path, f"def value():\n    return {source_canary!r}\n")
    model = FakeModel(
        {"status": "SUCCEEDED", "candidates": [], "patch": None, "note": model_canary}
    )

    _run(demo_module, repository, tmp_path / "out", model)
    output_bytes = b"".join(
        path.read_bytes() for path in (tmp_path / "out").rglob("*") if path.is_file()
    )
    output = output_bytes.decode("utf-8", errors="replace")

    assert source_canary not in output
    assert model_canary not in output
    assert "&lt;script&gt;" in output or "script" not in output.lower()


def test_missing_repository_fails_closed_without_creating_report(
    tmp_path: Path, demo_module: ModuleType
) -> None:
    output = tmp_path / "out"
    with pytest.raises((ValueError, OSError, demo_module.DemoError)):
        demo_module.run_demo(tmp_path / "does-not-exist", output, model_client=FakeModel({}))
    assert not output.exists()


def test_unsafe_filesystem_entry_is_rejected(tmp_path: Path, demo_module: ModuleType) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.py").write_text("print('ok')\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("SECRET_SOURCE\n", encoding="utf-8")
    try:
        (repository / "link.py").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this Windows environment")

    with pytest.raises((ValueError, OSError, demo_module.DemoError)):
        demo_module.run_demo(repository, tmp_path / "out", model_client=FakeModel({}))


def _runtime_metadata(module: ModuleType) -> dict[str, Any]:
    return {
        "/api/version": {"version": module._OLLAMA_VERSION},
        "/api/tags": {
            "models": [
                {
                    "name": module._MODEL_ID,
                    "model": module._MODEL_ID,
                    "modified_at": "2026-09-15T12:00:00Z",
                    "size": 4_680_000_000,
                    "digest": module._MODEL_DIGEST,
                    "details": {
                        "parent_model": "",
                        "format": "gguf",
                        "family": "qwen2",
                        "families": ["qwen2"],
                        "parameter_size": "7.6B",
                        "quantization_level": module._MODEL_QUANTIZATION,
                    },
                }
            ]
        },
    }


def test_observed_identity_is_bound_to_real_default_execution(
    tmp_path: Path, demo_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _ = _repo(tmp_path, "x = 1\n")
    metadata = _runtime_metadata(demo_module)
    calls: list[str] = []

    def read(path: str) -> dict[str, Any]:
        calls.append(path)
        return deepcopy(metadata[path])

    monkeypatch.setattr(demo_module, "_read_runtime_metadata", read)
    monkeypatch.setattr(
        demo_module,
        "_model_lane",
        lambda *args, **kwargs: {
            "status": "SUCCEEDED",
            "candidates": [],
            "patch": None,
            "transport": "authorized_loopback",
        },
    )
    manifest = demo_module.run_demo(repository, tmp_path / "out")
    assert manifest["outcome"] == "COMPLETED"
    identity = manifest["provider_runtime"]
    assert identity["identity_status"] == "OBSERVED"
    assert identity["runtime_version"] == metadata["/api/version"]["version"]
    assert identity["model_digest"] == "sha256:" + demo_module._MODEL_DIGEST
    assert identity["quantization"] == "Q4_K_M"
    assert identity["observation_boundary"] == "before_and_after_calls"
    assert manifest["model_lane"]["model_digest"] == identity["model_digest"]
    assert calls == ["/api/version", "/api/tags"] * 2


@pytest.mark.parametrize(
    "fault",
    [
        "version",
        "missing",
        "duplicate",
        "digest",
        "quantization",
        "name",
        "version-extra",
        "tags-extra",
        "model-extra",
        "details-extra",
        "size",
        "families",
    ],
)
def test_runtime_identity_drift_fails_before_model_or_output(
    tmp_path: Path, demo_module: ModuleType, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    repository, _ = _repo(tmp_path, "x = 1\n")
    metadata = _runtime_metadata(demo_module)
    model = metadata["/api/tags"]["models"][0]
    if fault == "version":
        metadata["/api/version"]["version"] = "0.0.0"
    elif fault == "missing":
        metadata["/api/tags"]["models"] = []
    elif fault == "duplicate":
        metadata["/api/tags"]["models"].append(deepcopy(model))
    elif fault in {"digest", "name"}:
        model[fault] = "drift"
    elif fault == "quantization":
        model["details"]["quantization_level"] = "Q8_0"
    elif fault.endswith("extra"):
        target = {
            "version-extra": metadata["/api/version"],
            "tags-extra": metadata["/api/tags"],
            "model-extra": model,
            "details-extra": model["details"],
        }[fault]
        target["unexpected"] = "PRIVATE_CANARY"
    elif fault == "size":
        model["size"] = True
    else:
        model["details"]["families"] = [False]
    monkeypatch.setattr(demo_module, "_read_runtime_metadata", lambda path: metadata[path])
    monkeypatch.setattr(demo_module, "_model_lane", lambda *a, **k: pytest.fail("model invoked"))
    with pytest.raises(demo_module.DemoError, match="local"):
        demo_module.run_demo(repository, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_post_call_runtime_drift_cannot_report_completion(
    tmp_path: Path, demo_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _ = _repo(tmp_path, "x = 1\n")
    metadata = _runtime_metadata(demo_module)
    monkeypatch.setattr(demo_module, "_read_runtime_metadata", lambda path: metadata[path])

    def invoke(*args: Any, **kwargs: Any) -> dict[str, Any]:
        metadata["/api/version"]["version"] = "0.0.0"
        return {"status": "SUCCEEDED", "candidates": [], "transport": "authorized_loopback"}

    monkeypatch.setattr(demo_module, "_model_lane", invoke)
    with pytest.raises(demo_module.DemoError, match="drift"):
        demo_module.run_demo(repository, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_injected_client_has_no_observed_local_identity(
    tmp_path: Path, demo_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _ = _repo(tmp_path, "x = 1\n")
    monkeypatch.setattr(demo_module, "_observe_runtime_identity", lambda: pytest.fail("network"))
    manifest = _run(demo_module, repository, tmp_path / "out", FakeModel({"candidates": []}))
    assert "provider_runtime" not in manifest
    assert manifest["model_lane"]["identity_status"] == "NOT_OBSERVED"
    assert manifest["model_lane"]["model_id"] is None
    assert manifest["model_lane"]["endpoint"] is None


def test_default_model_request_pins_the_qualified_artifact(
    tmp_path: Path, demo_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _ = _repo(tmp_path, "x = 1\n")
    profiles: list[Any] = []

    class Harness:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def execute_remote(self, **kwargs: Any) -> None:
            profiles.append(kwargs["profile"])
            raise RuntimeError("no network in contract test")

    monkeypatch.setattr(demo_module, "AuthorizedProviderHarness", Harness)
    result = demo_module._model_lane(
        demo_module._snapshot_repository(repository),
        "test",
        None,
        purpose=demo_module.ModelPurpose.MODEL_NATIVE_DISCOVERY,
    )
    assert result["status"] == "PROVIDER_ERROR"
    assert len(profiles) == 1
    assert profiles[0].model_snapshot == "sha256:" + demo_module._MODEL_DIGEST


def test_metadata_path_cannot_select_another_endpoint(
    demo_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        demo_module.http.client, "HTTPConnection", lambda *a, **k: pytest.fail("network")
    )
    with pytest.raises(demo_module.DemoError, match="endpoint"):
        demo_module._read_runtime_metadata("http://example.invalid/api/version")


@pytest.mark.parametrize(
    "fault",
    [
        "none",
        "redirect",
        "oversized",
        "malformed",
        "duplicate",
        "array",
        "compressed",
        "content-type",
    ],
)
def test_metadata_http_boundary_is_bounded_literal_loopback(
    demo_module: ModuleType, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    calls: list[object] = []
    body = b'{"version":"0.16.2"}'
    if fault == "oversized":
        body = b" " * (demo_module._METADATA_BYTES + 1)
    elif fault == "malformed":
        body = b'{"version":'
    elif fault == "duplicate":
        body = b'{"version":"0.16.2","version":"0.16.2"}'
    elif fault == "array":
        body = b"[]"

    class Response:
        status = 302 if fault == "redirect" else 200
        offset = 0

        def getheader(self, name: str, default: str | None = None) -> str | None:
            return {
                "Content-Type": "text/plain" if fault == "content-type" else "application/json",
                "Content-Encoding": "gzip" if fault == "compressed" else "identity",
                "Location": "http://example.invalid/PRIVATE_CANARY",
            }.get(name, default)

        def read1(self, amount: int) -> bytes:
            assert 0 < amount <= 4096
            data = body[self.offset : self.offset + amount]
            self.offset += len(data)
            return data

    class Connection:
        sock = None

        def __init__(self, host: str, port: int, *, timeout: float) -> None:
            calls.append((host, port, timeout))

        def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
            calls.append((method, path, headers))

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            calls.append("closed")

    monkeypatch.setenv("HTTP_PROXY", "http://example.invalid:9999")
    monkeypatch.setenv("ALL_PROXY", "http://example.invalid:9999")
    monkeypatch.setattr(demo_module.http.client, "HTTPConnection", Connection)
    if fault == "none":
        assert demo_module._read_runtime_metadata("/api/version") == {"version": "0.16.2"}
    else:
        with pytest.raises(demo_module.DemoError) as caught:
            demo_module._read_runtime_metadata("/api/version")
        assert "PRIVATE_CANARY" not in str(caught.value)
    assert calls[0] == ("127.0.0.1", 11434, demo_module._METADATA_TIMEOUT)
    assert len(calls) == 3
    assert calls[-1] == "closed"
