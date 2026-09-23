from __future__ import annotations

import runpy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PINNED_PYTHON = "python:3.12-slim-bookworm@sha256:\x64\x35\x61\x65\x37\x34\x61\x63\x62\x38\x30\x32\x36\x62\x33\x32\x61\x32\x66\x36\x64\x65\x65\x61\x34\x35\x30\x30\x33\x63\x35\x62\x64\x34\x65\x32\x38\x38\x30\x37\x30\x30\x63\x31\x39\x63\x34\x34\x62\x64\x61\x35\x34\x36\x37\x30\x61\x64\x33\x65\x66\x66\x39\x30"


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_worker_module_executes_its_command_boundary(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["securecode_ai.worker.service", "--help"])

    with pytest.raises(SystemExit) as raised:
        runpy.run_module("securecode_ai.worker.service", run_name="__main__")

    assert raised.value.code == 0
    assert capsys.readouterr().out.startswith("usage: securecode-worker-service")


def test_docker_context_is_an_explicit_source_allowlist() -> None:
    lines = tuple(
        line for line in _text(".dockerignore").splitlines() if line and not line.startswith("#")
    )

    assert lines[0] == "**"
    assert "!apps/server/src/**" in lines
    assert "!apps/worker/src/**" in lines
    assert "!packages/adapters/**" in lines
    assert "!packages/contracts/**" in lines
    assert "!packages/core/**" in lines
    assert not any(value.startswith("!.env") or value.startswith("!.venv") for value in lines)
    assert not any(
        value.startswith("!artifacts")
        or value.startswith("!report")
        or value.startswith("!evaluation")
        for value in lines
    )


@pytest.mark.parametrize(
    "path",
    (
        "Dockerfile",
        "deploy/docker/runtime.Dockerfile",
        "deploy/docker/server.Dockerfile",
        "deploy/docker/worker.Dockerfile",
    ),
)
def test_deployment_images_have_a_pinned_default_runtime(path: str) -> None:
    document = _text(path)

    assert PINNED_PYTHON in document
    assert "runtime-requirements.txt" in document


def test_server_images_bind_the_container_interface() -> None:
    for path in ("Dockerfile", "deploy/docker/server.Dockerfile"):
        document = _text(path)
        assert "SECURECODE_SERVER_HOST=0.0.0.0" in document
        assert "SECURECODE_SERVER_PORT=8080" in document
        assert "EXPOSE 8080" in document
        assert 'CMD ["python","-m","securecode_ai.server.main"]' in document


def test_compose_uses_loopback_ingress_and_secret_backed_tls() -> None:
    document = _text("docker-compose.yml")

    assert '"127.0.0.1:8080:8080"' in document
    assert "SECURECODE_CONTROL_PLANE_URL: https://server:8080" in document
    assert "SSL_CERT_FILE: /run/secrets/server_ca" in document
    assert "condition: service_healthy" in document
    assert "read_only: true" in document
    assert "SECURECODE_TLS_KEY_FILE: /run/secrets/server_tls_key" in document
    assert "mode: 0400" in document
    assert "SECURECODE_BOOTSTRAP_WORKER_TOKEN:" not in document


def test_gitlab_source_job_dispatches_exact_head_without_worker_authority() -> None:
    raw = _text(".gitlab-ci.yml")

    assert "securecode-audit-dispatch:" in raw
    assert 'project: "$SECURECODE_TRUSTED_AUDIT_PROJECT"' in raw
    assert 'branch: "$SECURECODE_TRUSTED_AUDIT_REF"' in raw
    assert "strategy: mirror" in raw
    assert 'source_commit_sha: "$CI_COMMIT_SHA"' in raw
    assert "yaml_variables: false" in raw
    assert "pipeline_variables: false" in raw
    assert "securecode-audit-configuration-error:" in raw
    assert "CI_MERGE_REQUEST_SOURCE_PROJECT_ID == $CI_PROJECT_ID" in raw
    assert "SECURECODE_WORKER_IMAGE" not in raw
    assert "privileged" not in raw.lower()
    assert "docker.sock" not in raw.lower()
