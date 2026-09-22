from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENVIRONMENT_NAME = re.compile(r"\bSECURECODE_[A-Z0-9_]+\b")


def test_server_image_probes_the_versioned_api_readiness_route() -> None:
    dockerfile = (ROOT / "deploy/docker/server.Dockerfile").read_text(encoding="utf-8")
    worker_dockerfile = (ROOT / "deploy/docker/worker.Dockerfile").read_text(encoding="utf-8")
    probe = (ROOT / "deploy/docker/healthcheck.py").read_text(encoding="utf-8")

    assert "USER 65532:65532" in dockerfile
    assert "USER 65532:65532" in worker_dockerfile
    assert "HEALTHCHECK --interval=" in dockerfile
    assert '"/app/healthcheck.py"' in dockerfile
    assert '"/api/v1/health/ready"' in probe
    assert '"X-SecureCode-Api-Version": "1.0.0"' in probe


def test_compose_is_loopback_only_non_root_and_does_not_mount_docker_socket() -> None:
    compose = (ROOT / "deploy/docker/compose.yaml").read_text(encoding="utf-8")

    assert '"127.0.0.1:${SECURECODE_SERVER_PUBLISHED_PORT:-8443}:8080"' in compose
    assert "read_only: true" in compose
    assert "cap_drop: [ALL]" in compose
    assert "condition: service_healthy" in compose
    assert "/var/run/docker.sock" not in compose
    assert "privileged:" not in compose


def test_deployment_readme_lists_application_environment_names() -> None:
    readme = (ROOT / "deploy/docker/README.md").read_text(encoding="utf-8")
    source_roots = (ROOT / "apps/server/src", ROOT / "apps/worker/src")
    required: set[str] = set()

    for source_root in source_roots:
        for source in source_root.rglob("*.py"):
            required.update(ENVIRONMENT_NAME.findall(source.read_text(encoding="utf-8")))

    missing = sorted(name for name in required if name not in readme)
    assert not missing, f"document these application environment names: {missing}"
