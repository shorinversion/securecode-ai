"""Generated, dependency-free OpenAPI description for the P6.1 boundary."""

from __future__ import annotations

from typing import Final

API_VERSION: Final = "1.0.0"
SUPPORTED_MAJOR: Final = 1
CAPABILITIES: Final = (
    "artifact-upload",
    "artifact-inventory",
    "audit-export",
    "authorization",
    "backup-restore",
    "durable-approvals",
    "durable-assurance",
    "durable-data-lifecycle",
    "durable-feedback",
    "durable-run-admission",
    "health",
    "idempotency",
    "identity",
    "operations-telemetry",
    "resource-governance",
    "safe-errors",
    "scm-webhooks",
    "secret-leases",
    "worker-leases",
)

_ROUTES: Final = (
    ("/api/v1/auth/login", "post", "start a bounded OIDC login"),
    ("/api/v1/auth/callback", "post", "exchange a signed OIDC response for a session"),
    ("/api/v1/auth/logout", "post", "revoke the current opaque session"),
    ("/api/v1/runs", "post", "request a run"),
    ("/api/v1/repositories/{repository_id}/runs", "get", "list repository runs"),
    ("/api/v1/scm/runs:resolve", "post", "resolve an exact SCM run"),
    ("/api/v1/runs/{run_id}", "get", "read a run"),
    ("/api/v1/runs/{run_id}:cancel", "post", "request cancellation"),
    ("/api/v1/runs/{run_id}/events", "get", "list safe events"),
    ("/api/v1/runs/{run_id}/findings", "get", "list findings"),
    ("/api/v1/runs/{run_id}/artifacts", "get", "list immutable artifacts"),
    ("/api/v1/runs/{run_id}/audit", "get", "export a verified audit chain"),
    ("/api/v1/operations/metrics", "get", "read source-free operational metrics"),
    ("/api/v1/findings/{finding_id}", "get", "read a finding"),
    (
        "/api/v1/findings/{finding_id}/evidence",
        "get",
        "read verified source-free evidence for a finding",
    ),
    ("/api/v1/findings/{finding_id}/decisions", "post", "record a decision"),
    ("/api/v1/artifacts:authorize", "post", "authorize an artifact transfer"),
    (
        "/api/v1/artifact-uploads/{tenant_id}/{content_sha256}/{authorization_id}",
        "put",
        "store an authorized artifact",
    ),
    ("/api/v1/policies", "get", "list authorized policies"),
    ("/api/v1/approvals", "post", "request an approval"),
    ("/api/v1/approvals/{approval_id}", "get", "read an approval"),
    ("/api/v1/approvals/{approval_id}:decide", "post", "decide an approval"),
    ("/api/v1/secret-grants", "post", "request an ephemeral secret grant"),
    ("/api/v1/secret-grants/{grant_id}", "get", "read a secret grant receipt"),
    (
        "/api/v1/secret-grants/{grant_id}:rotate",
        "post",
        "rotate an ephemeral secret grant",
    ),
    (
        "/api/v1/secret-grants/{grant_id}:revoke",
        "post",
        "revoke an ephemeral secret grant",
    ),
    ("/api/v1/backups", "post", "plan a tenant backup"),
    ("/api/v1/backups/{backup_id}", "get", "read a backup receipt"),
    (
        "/api/v1/backups/{backup_id}:execute",
        "post",
        "execute and verify a backup",
    ),
    (
        "/api/v1/backups/{backup_id}:restore",
        "post",
        "restore and verify a backup",
    ),
    ("/api/v1/lifecycle/deletions", "post", "request data deletion"),
    (
        "/api/v1/lifecycle/deletions/{deletion_id}",
        "get",
        "read data deletion state",
    ),
    (
        "/api/v1/lifecycle/deletions/{deletion_id}:approve",
        "post",
        "approve data deletion",
    ),
    (
        "/api/v1/lifecycle/deletions/{deletion_id}:legal-hold",
        "post",
        "change data deletion legal hold",
    ),
    (
        "/api/v1/lifecycle/deletions/{deletion_id}:execute",
        "post",
        "execute an approved data deletion",
    ),
    ("/api/v1/feedback", "post", "submit AppSec feedback"),
    ("/api/v1/feedback/metrics", "get", "read AppSec feedback metrics"),
    ("/api/v1/assurance", "post", "append source-free assurance evidence"),
    ("/api/v1/assurance", "get", "read source-free assurance evidence"),
    ("/api/v1/integrations/github/webhook", "post", "accept a GitHub webhook"),
    ("/api/v1/integrations/gitlab/webhook", "post", "accept a GitLab webhook"),
    ("/api/v1/worker-sessions", "post", "open a worker lease"),
    ("/api/v1/worker-sessions/{session_id}:heartbeat", "post", "renew a worker lease"),
    ("/api/v1/worker-sessions/{session_id}/events:append", "post", "append safe events"),
    ("/api/v1/worker-sessions/{session_id}/artifacts:commit", "post", "commit an artifact"),
    ("/api/v1/worker-sessions/{session_id}:complete", "post", "complete a worker session"),
)

_PRECONDITION_ROUTES: Final = frozenset(
    {
        "/api/v1/approvals/{approval_id}:decide",
        "/api/v1/findings/{finding_id}/decisions",
        "/api/v1/runs/{run_id}:cancel",
        "/api/v1/secret-grants/{grant_id}:rotate",
        "/api/v1/secret-grants/{grant_id}:revoke",
        "/api/v1/backups/{backup_id}:execute",
        "/api/v1/backups/{backup_id}:restore",
        "/api/v1/lifecycle/deletions/{deletion_id}:approve",
        "/api/v1/lifecycle/deletions/{deletion_id}:legal-hold",
        "/api/v1/lifecycle/deletions/{deletion_id}:execute",
        "/api/v1/feedback",
        "/api/v1/assurance",
        "/api/v1/worker-sessions/{session_id}:heartbeat",
        "/api/v1/worker-sessions/{session_id}/events:append",
        "/api/v1/worker-sessions/{session_id}/artifacts:commit",
        "/api/v1/worker-sessions/{session_id}:complete",
    }
)


def build_openapi_document() -> dict[str, object]:
    paths: dict[str, dict[str, object]] = {}
    for path, method, summary in _ROUTES:
        responses: dict[str, object] = {
            "200": {"description": "current resource or idempotent replay"},
            "201": {"description": "created"},
            "202": {"description": "accepted"},
            "400": {"description": "safe malformed request error"},
            "401": {"description": "identity required"},
            "403": {"description": "authorization denied"},
            "413": {"description": "request body exceeds the bounded size"},
            "409": {"description": "idempotency conflict"},
            "412": {"description": "precondition failed"},
            "503": {"description": "resource handler unavailable"},
        }
        operation: dict[str, object] = {
            "summary": summary,
            "responses": responses,
            "security": [{"bearerAuth": []}],
        }
        if path in {"/api/v1/auth/login", "/api/v1/auth/callback"}:
            operation["security"] = []
            responses["429"] = {"description": "login flow rate limit reached; see Retry-After"}
        if path == "/api/v1/auth/login":
            responses["200"] = {
                "description": "one-time OIDC authorization-code flow handle with PKCE",
                "headers": {
                    "Cache-Control": {"schema": {"type": "string"}},
                    "Pragma": {"schema": {"type": "string"}},
                },
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "required": ["nonce", "state"],
                            "properties": {
                                "nonce": {"type": "string", "minLength": 1, "maxLength": 1024},
                                "state": {"type": "string", "minLength": 1, "maxLength": 128},
                                "authorization_url": {"type": "string", "format": "uri"},
                                "code_verifier": {
                                    "type": "string",
                                    "minLength": 43,
                                    "maxLength": 128,
                                },
                                "code_challenge": {
                                    "type": "string",
                                    "minLength": 43,
                                    "maxLength": 43,
                                },
                                "code_challenge_method": {"const": "S256"},
                            },
                            "additionalProperties": False,
                        }
                    }
                },
            }
        if path == "/api/v1/auth/callback":
            operation["requestBody"] = {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "required": ["token", "nonce", "state"],
                            "properties": {
                                "token": {"type": "string", "minLength": 16, "maxLength": 16384},
                                "nonce": {"type": "string", "minLength": 1, "maxLength": 1024},
                                "state": {"type": "string", "minLength": 1, "maxLength": 128},
                            },
                            "additionalProperties": False,
                        }
                    }
                },
            }
        if path == "/api/v1/auth/callback":
            responses["200"] = {
                "description": "verified ID token after the public OIDC client exchanges its authorization code"
            }
        if path == "/api/v1/auth/logout":
            responses["200"] = {"description": "session revoked"}
        if path.startswith("/api/v1/artifact-uploads/"):
            operation["security"] = [{"artifactReceipt": []}]
        if path.startswith("/api/v1/artifact-uploads/"):
            idempotency_header = "X-SecureCode-Authorization-ID"
        elif path == "/api/v1/integrations/github/webhook":
            idempotency_header = "X-GitHub-Delivery"
        elif path == "/api/v1/integrations/gitlab/webhook":
            idempotency_header = "X-Gitlab-Event-Uuid"
        else:
            idempotency_header = "Idempotency-Key"
        if method in {"post", "put"} and not path.startswith("/api/v1/auth/"):
            operation["parameters"] = [
                {"name": idempotency_header, "in": "header", "required": True},
            ]
        if method == "post" and path in _PRECONDITION_ROUTES:
            parameters = operation.get("parameters")
            if not isinstance(parameters, list):
                parameters = []
                operation["parameters"] = parameters
            parameters.append({"name": "If-Match", "in": "header", "required": True})
        paths.setdefault(path, {})[method] = operation
    return {
        "openapi": "3.1.0",
        "info": {"title": "SecureCode AI control-plane API", "version": API_VERSION},
        "servers": [{"url": "/api/v1"}],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "artifactReceipt": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-SecureCode-Receipt-Signature",
                },
                "bearerAuth": {"type": "http", "scheme": "bearer"},
            }
        },
    }
