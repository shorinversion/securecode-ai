"""Generate a complete local Compose environment so the stack starts without manual setup.

Run from anywhere::

    python deploy/docker/quickstart.py --demo     # audit demo in Docker (DeepSeek if keyed)
    python deploy/docker/quickstart.py --demo --provider local   # same demo on local Ollama
    python deploy/docker/quickstart.py --up       # full server + worker stack (Linux)

The script writes only ``deploy/docker/.env`` and ``deploy/docker/.local/`` (both ignored by
git): a self-signed CA and server certificate for ``localhost``/``securecode-server``, two
random bearer tokens and every Compose input with a working local default.  Nothing is sent
anywhere.  These credentials are for a single-host trial; use a secret manager in production.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOCAL = HERE / ".local"
ENV_FILE = HERE / ".env"
LOCAL_MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"


def _openssl() -> str:
    path = shutil.which("openssl")
    if path is None:
        raise SystemExit("openssl is required to create the local TLS certificate")
    return path


def _run(*arguments: str) -> None:
    subprocess.run(arguments, check=True, capture_output=True)


def _write_secret(path: Path, value: str) -> None:
    path.write_text(value, encoding="ascii", newline="\n")
    path.chmod(0o444)  # The non-root container user (UID 65532) must be able to read it.


def _certificates() -> None:
    if all((LOCAL / name).exists() for name in ("ca.crt", "server.crt", "server.key")):
        return
    openssl = _openssl()
    _run(openssl, "genrsa", "-out", str(LOCAL / "ca.key"), "3072")
    _run(
        openssl, "req", "-x509", "-new", "-key", str(LOCAL / "ca.key"), "-sha256", "-days", "825",
        "-subj", "/CN=SecureCode local CA", "-out", str(LOCAL / "ca.crt"),
    )  # fmt: skip
    _run(openssl, "genrsa", "-out", str(LOCAL / "server.key"), "3072")
    _run(
        openssl, "req", "-new", "-key", str(LOCAL / "server.key"),
        "-subj", "/CN=securecode-server", "-out", str(LOCAL / "server.csr"),
    )  # fmt: skip
    extension = LOCAL / "server.ext"
    extension.write_text(
        "subjectAltName=DNS:localhost,DNS:securecode-server,IP:127.0.0.1\n"
        "extendedKeyUsage=serverAuth\n",
        encoding="ascii",
    )
    _run(
        openssl, "x509", "-req", "-in", str(LOCAL / "server.csr"), "-CA", str(LOCAL / "ca.crt"),
        "-CAkey", str(LOCAL / "ca.key"), "-CAcreateserial", "-out", str(LOCAL / "server.crt"),
        "-days", "825", "-sha256", "-extfile", str(extension),
    )  # fmt: skip
    for name in ("ca.crt", "server.crt", "server.key"):
        (LOCAL / name).chmod(0o444)


def _tokens() -> None:
    for name in ("admin.token", "worker.token"):
        if not (LOCAL / name).exists():
            _write_secret(LOCAL / name, secrets.token_urlsafe(48))


def _sha256_of(path: str | None) -> str:
    if not path or not Path(path).is_file():
        return "0" * 64
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _posix(path: Path) -> str:
    return path.resolve().as_posix()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--checkout", type=Path, default=HERE.parents[1], help="repository to audit"
    )
    parser.add_argument("--tenant", default="local", help="tenant identifier")
    parser.add_argument("--repository-id", default="local/project", help="repository identifier")
    parser.add_argument("--port", default="8443", help="loopback HTTPS port")
    parser.add_argument("--up", action="store_true", help="build, start and wait until ready")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="audit the bundled vulnerable fixture and print a report",
    )
    parser.add_argument(
        "--provider",
        choices=("auto", "deepseek", "local", "offline"),
        default="auto",
        help="demo model: DeepSeek if a key is configured (auto), local Ollama, or offline",
    )
    arguments = parser.parse_args()
    if arguments.demo:
        return _run_demo(arguments.provider)

    LOCAL.mkdir(exist_ok=True)
    _certificates()
    _tokens()
    bundle_root = LOCAL / "validator"
    bundle_root.mkdir(exist_ok=True)
    (LOCAL / "approval").mkdir(exist_ok=True)

    docker = shutil.which("docker")
    ollama = shutil.which("ollama")
    warnings: list[str] = []
    if docker is None:
        warnings.append("docker CLI not found: repair validation needs a rootless Docker socket")
    if ollama is None:
        warnings.append(
            "ollama not found: install it and run `ollama pull qwen2.5-coder:7b-instruct-q4_K_M`"
        )

    values = {
        # Server and worker (required).
        "SECURECODE_TLS_CERT_SOURCE": _posix(LOCAL / "server.crt"),
        "SECURECODE_TLS_KEY_SOURCE": _posix(LOCAL / "server.key"),
        "SECURECODE_TLS_CA_SOURCE": _posix(LOCAL / "ca.crt"),
        "SECURECODE_ADMIN_TOKEN_SOURCE": _posix(LOCAL / "admin.token"),
        "SECURECODE_WORKER_TOKEN_SOURCE": _posix(LOCAL / "worker.token"),
        "SECURECODE_BOOTSTRAP_TENANT_ID": arguments.tenant,
        "SECURECODE_BOOTSTRAP_WORKER_REPOSITORIES": arguments.repository_id,
        "SECURECODE_WORKER_SOURCE": _posix(arguments.checkout),
        "SECURECODE_WORKER_ID": "local-worker-1",
        "SECURECODE_SERVER_PUBLISHED_PORT": arguments.port,
        "SECURECODE_WORKER_APPROVAL_ANCHOR_SOURCE": _posix(LOCAL / "approval"),
        # Maintenance daemon defaults.
        "SECURECODE_MAINTENANCE_TENANT_ID": arguments.tenant,
        "SECURECODE_MAINTENANCE_OWNER_ID": "local-maintenance",
        "SECURECODE_RETENTION_METADATA_DAYS": "365",
        "SECURECODE_RETENTION_ARTIFACT_DAYS": "90",
        "SECURECODE_RETENTION_AUDIT_DAYS": "730",
        # Local repair validator broker (needs a rootless Docker socket on Linux).
        "SECURECODE_AI_VALIDATOR_BUNDLE_ROOT": _posix(bundle_root),
        "SECURECODE_AI_VALIDATOR_IDENTITY": "local-validator-broker",
        "SECURECODE_AI_VALIDATOR_DOCKER_SOCKET_UID": "1000",
        "SECURECODE_AI_VALIDATOR_DOCKER_SOCKET_SOURCE": "/run/user/1000/docker.sock",
        "SECURECODE_AI_VALIDATOR_DOCKER_EXECUTABLE_SOURCE": docker or "/usr/bin/docker",
        "SECURECODE_AI_VALIDATOR_DOCKER_EXECUTABLE_SHA256": _sha256_of(docker),
        "SECURECODE_AI_VALIDATION_IMAGE": "securecode-ai/repair-validator:local",
        # Local model runtime.
        "SECURECODE_OLLAMA_BINARY_SOURCE": ollama or "/usr/local/bin/ollama",
        "SECURECODE_OLLAMA_MODELS_SOURCE": str(Path.home() / ".ollama" / "models").replace(
            "\\", "/"
        ),
        "SECURECODE_OLLAMA_IMAGE": "ollama/ollama:latest",
    }
    ENV_FILE.write_text(
        "# Generated by deploy/docker/quickstart.py. Untracked; safe to delete and regenerate.\n"
        + "".join(f"{key}={value}\n" for key, value in values.items()),
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {ENV_FILE.relative_to(HERE.parents[1])} with {len(values)} values.")
    print(f"Secrets and certificates: {LOCAL.relative_to(HERE.parents[1])}/")
    for warning in warnings:
        print(f"warning: {warning}")
    compose = _compose_command()
    command = [*compose, "-f", str(HERE / "compose.yaml"), "--env-file", str(ENV_FILE)]
    if not arguments.up:
        print("Next: python deploy/docker/quickstart.py --up")
        return 0
    if compose == []:
        raise SystemExit("docker compose (or docker-compose) is required for --up")
    subprocess.run([*command, "up", "-d", "--build"], check=True)
    return _wait_ready(arguments.port, command)


def _deepseek_settings() -> dict[str, str]:
    """DEEPSEEK_* values from the environment, else from the repository-root ``.env``."""
    values = {key: value for key, value in os.environ.items() if key.startswith("DEEPSEEK_")}
    dotenv = HERE.parents[1] / ".env"
    if "DEEPSEEK_API_KEY" not in values and dotenv.is_file():
        for line in dotenv.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.strip().partition("=")
            if separator and key.startswith("DEEPSEEK_") and key not in values:
                values[key] = value.strip().strip("'\"")
    return values


def _run_demo(provider: str) -> int:
    """Audit the bundled vulnerable fixture and print the security report.

    ``auto`` uses DeepSeek when a key is configured and the deterministic lane only otherwise;
    both run in Docker.  ``local`` runs the same Auditor/Architect demo on the host against a
    running Ollama, pulling the pinned Qwen model first when needed.
    """
    root = HERE.parents[1]
    if provider == "local":
        ollama = shutil.which("ollama")
        if ollama is None:
            raise SystemExit("ollama is required for --provider local (https://ollama.com)")
        if subprocess.run([ollama, "pull", LOCAL_MODEL], check=False).returncode != 0:
            raise SystemExit("could not pull the model; is `ollama serve` running?")
        output = root / "output" / "demo-report"
        shutil.rmtree(output, ignore_errors=True)
        uv = shutil.which("uv")
        python = [uv, "run", "--locked", "python"] if uv else [sys.executable]
        demo = [*python, "-I", str(root / "demo" / "p917_real_local_demo.py")]
        fixture = str(root / "demo" / "fixtures" / "real-local-cwe89")
        status = subprocess.run(
            [*demo, "--repository", fixture, "--output", str(output)],
            check=False,
            stdout=subprocess.DEVNULL,
        ).returncode
        report = output / "security-report.md"
        if report.is_file():
            print(report.read_text(encoding="utf-8"))
            print(f"Reports: {output}")
        return status
    docker = shutil.which("docker")
    if docker is None:
        raise SystemExit("docker is required for --demo")
    subprocess.run(
        [docker, "build", "-f", str(HERE / "demo.Dockerfile"), "-t", "securecode-demo", str(root)],
        check=True,
    )
    settings = _deepseek_settings() if provider in {"auto", "deepseek"} else {}
    if provider == "deepseek" and not settings.get("DEEPSEEK_API_KEY"):
        raise SystemExit("DEEPSEEK_API_KEY is not set in the environment or .env")
    # Pass variable names only, so the key never appears in a process argument list.
    names = [name for name in ("DEEPSEEK_API_KEY", "DEEPSEEK_MODEL") if settings.get(name)]
    environment = os.environ | {name: settings[name] for name in names}
    command = [docker, "run", "--rm", *(item for name in names for item in ("-e", name))]
    return subprocess.run([*command, "securecode-demo"], check=False, env=environment).returncode


def _compose_command() -> list[str]:
    docker = shutil.which("docker")
    if docker is not None:
        probe = subprocess.run([docker, "compose", "version"], capture_output=True, check=False)
        if probe.returncode == 0:
            return [docker, "compose"]
    legacy = shutil.which("docker-compose")
    return [legacy] if legacy else []


def _wait_ready(port: str, command: list[str], timeout_seconds: int = 180) -> int:
    import ssl
    import time
    import urllib.request

    context = ssl.create_default_context(cafile=str(LOCAL / "ca.crt"))
    request = urllib.request.Request(
        f"https://localhost:{port}/api/v1/health/ready",
        headers={"X-SecureCode-Api-Version": "1.0.0"},
    )
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(request, context=context, timeout=5) as response:
                if response.status == 200:
                    print(f"SecureCode is ready: https://localhost:{port}/api/v1/health/ready")
                    print("Stop with: " + " ".join([*command, "down"]))
                    return 0
        except OSError:
            time.sleep(3)
    subprocess.run([*command, "ps"], check=False)
    print(
        "Server did not become ready; inspect: " + " ".join([*command, "logs", "securecode-server"])
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
