"""Generated, dependency-free OpenAPI description for the P6.1 boundary."""

from __future__ import annotations

import re
from typing import Final

API_VERSION: Final = "1.0.0"
SUPPORTED_MAJOR: Final = 1
CAPABILITIES: Final = (
    "artifact-upload",
    "artifact-inventory",
    "audit-export",
    "authorization",
    "backup-restore",
    "dependency-advisories",
    "dependency-inventory",
    "durable-approvals",
    "durable-assurance",
    "durable-data-lifecycle",
    "durable-feedback",
    "durable-run-admission",
    "expiring-finding-waivers",
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
    ("/api/v1/capabilities", "get", "read enabled server capabilities"),
    ("/api/v1/health/live", "get", "read process liveness"),
    ("/api/v1/health/ready", "get", "read dependency readiness"),
    ("/api/v1/openapi.json", "get", "read the control-plane API description"),
    ("/api/v1/runs", "post", "request a run"),
    ("/api/v1/repositories/{repository_id}/runs", "get", "list repository runs"),
    ("/api/v1/scm/runs:resolve", "post", "resolve an exact SCM run"),
    ("/api/v1/runs/{run_id}", "get", "read a run"),
    ("/api/v1/runs/{run_id}:cancel", "post", "request cancellation"),
    ("/api/v1/runs/{run_id}/events", "get", "list safe events"),
    ("/api/v1/runs/{run_id}/findings", "get", "list findings"),
    ("/api/v1/runs/{run_id}/artifacts", "get", "list immutable artifacts"),
    (
        "/api/v1/runs/{run_id}/artifacts/{content_sha256}/content",
        "get",
        "download one verified committed artifact",
    ),
    (
        "/api/v1/runs/{run_id}/repair-patches/{finding_id}/content",
        "get",
        "download one exact-scope validated repair patch",
    ),
    ("/api/v1/runs/{run_id}/audit", "get", "export a verified audit chain"),
    (
        "/api/v1/audit/resources/{resource_type}/{resource_id}",
        "get",
        "export a verified resource audit chain",
    ),
    (
        "/api/v1/audit/resources/{resource_type}",
        "get",
        "export resource audit chains for a tenant",
    ),
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
    ("/api/v1/policies", "post", "create a tenant-scoped policy version"),
    (
        "/api/v1/policies/{profile_id}/versions/{version}:activate",
        "post",
        "activate a tenant-scoped policy version",
    ),
    (
        "/api/v1/policies/{profile_id}/versions/{version}/assignment",
        "post",
        "assign an active policy version to one repository",
    ),
    (
        "/api/v1/policies/{profile_id}/versions/{version}/default",
        "post",
        "set an active policy version as tenant default",
    ),
    (
        "/api/v1/policies/repository-assignments",
        "post",
        "assign a policy profile to a repository",
    ),
    ("/api/v1/policies/tenant-default", "post", "set a tenant default policy profile"),
    ("/api/v1/approvals", "post", "request an approval"),
    ("/api/v1/approvals/{approval_id}", "get", "read an approval"),
    ("/api/v1/approvals/{approval_id}:decide", "post", "decide an approval"),
    ("/api/v1/findings/{finding_id}/waivers", "post", "grant an approved finding waiver"),
    ("/api/v1/waivers/{waiver_id}", "get", "read a finding waiver"),
    ("/api/v1/waivers/{waiver_id}:revoke", "post", "revoke a finding waiver"),
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
    (
        "/api/v1/backups/{backup_id}:restore:resolve",
        "post",
        "record an explicit resolution for an interrupted restore",
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
    (
        "/api/v1/worker-sessions/{session_id}/osv:query",
        "post",
        "query OSV for worker dependencies",
    ),
    ("/api/v1/worker-sessions/{session_id}:heartbeat", "post", "renew a worker lease"),
    ("/api/v1/worker-sessions/{session_id}/events:append", "post", "append safe events"),
    ("/api/v1/worker-sessions/{session_id}/artifacts:commit", "post", "commit an artifact"),
    ("/api/v1/worker-sessions/{session_id}:complete", "post", "complete a worker session"),
)

_PRECONDITION_ROUTES: Final = frozenset(
    {
        "/api/v1/approvals/{approval_id}:decide",
        "/api/v1/waivers/{waiver_id}:revoke",
        "/api/v1/findings/{finding_id}/decisions",
        "/api/v1/runs/{run_id}:cancel",
        "/api/v1/secret-grants/{grant_id}:rotate",
        "/api/v1/secret-grants/{grant_id}:revoke",
        "/api/v1/backups/{backup_id}:execute",
        "/api/v1/backups/{backup_id}:restore",
        "/api/v1/backups/{backup_id}:restore:resolve",
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
        if path == "/api/v1/runs/{run_id}/artifacts/{content_sha256}/content":
            responses["200"] = {
                "description": "verified immutable artifact bytes",
                "headers": {
                    "Cache-Control": {"schema": {"type": "string"}},
                    "Content-Sha256": {
                        "schema": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                    },
                },
                "content": {
                    "application/octet-stream": {
                        "schema": {"type": "string", "format": "binary"}
                    }
                },
            }
        if path == "/api/v1/runs/{run_id}/repair-patches/{finding_id}/content":
            responses["200"] = {
                "description": "verified validated repair patch bundle",
                "headers": {
                    "Cache-Control": {"schema": {"type": "string"}},
                    "Content-Sha256": {
                        "schema": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                    },
                    "X-Securecode-Repair-Finding": {"schema": {"type": "string"}},
                    "X-Securecode-Repair-Patch-Sha256": {
                        "schema": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                    },
                },
                "content": {
                    "application/octet-stream": {
                        "schema": {"type": "string", "format": "binary"}
                    }
                },
            }
        if path in {
            "/api/v1/capabilities",
            "/api/v1/health/live",
            "/api/v1/health/ready",
            "/api/v1/openapi.json",
        }:
            operation["security"] = []
            responses.pop("401", None)
        elif path == "/api/v1/integrations/github/webhook":
            operation["security"] = [{"githubWebhookSignature": []}]
        elif path == "/api/v1/integrations/gitlab/webhook":
            operation["security"] = [{"gitlabWebhookToken": []}]
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
        if path == "/api/v1/policies" and method == "get":
            operation["parameters"] = [
                {
                    "name": "cursor",
                    "in": "query",
                    "required": False,
                    "schema": {"type": "string", "minLength": 1, "maxLength": 1024},
                },
                {
                    "name": "limit",
                    "in": "query",
                    "required": False,
                    "schema": {"type": "integer", "minimum": 1, "maximum": 100},
                },
            ]
        if (
            path == "/api/v1/runs/{run_id}/repair-patches/{finding_id}/content"
            and method == "get"
        ):
            parameters = operation.get("parameters")
            if not isinstance(parameters, list):
                parameters = []
                operation["parameters"] = parameters
            parameters.append(
                {
                    "name": "patch_sha256",
                    "in": "query",
                    "required": True,
                    "schema": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                }
            )
        if path in {
            "/api/v1/integrations/github/webhook",
            "/api/v1/integrations/gitlab/webhook",
        }:
            parameters = operation.get("parameters")
            if not isinstance(parameters, list):
                parameters = []
                operation["parameters"] = parameters
            event_header, event_value = (
                ("X-GitHub-Event", "pull_request")
                if path == "/api/v1/integrations/github/webhook"
                else ("X-Gitlab-Event", "Merge Request Hook")
            )
            parameters.append(
                {
                    "name": event_header,
                    "in": "header",
                    "required": True,
                    "schema": {"type": "string", "const": event_value},
                }
            )
        if method == "post" and path in _PRECONDITION_ROUTES:
            parameters = operation.get("parameters")
            if not isinstance(parameters, list):
                parameters = []
                operation["parameters"] = parameters
            parameters.append({"name": "If-Match", "in": "header", "required": True})
        path_parameters = re.findall(r"\{([A-Za-z][A-Za-z0-9_]*)\}", path)
        if path_parameters:
            parameters = operation.get("parameters")
            if not isinstance(parameters, list):
                parameters = []
                operation["parameters"] = parameters
            existing = {
                (item.get("name"), item.get("in"))
                for item in parameters
                if isinstance(item, dict)
            }
            for name in path_parameters:
                if (name, "path") in existing:
                    continue
                schema: dict[str, object] = {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                }
                if name in {"content_sha256", "patch_sha256"}:
                    schema["pattern"] = "^[0-9a-f]{64}$"
                parameters.append(
                    {
                        "name": name,
                        "in": "path",
                        "required": True,
                        "schema": schema,
                    }
                )
                existing.add((name, "path"))
        paths.setdefault(path, {})[method] = operation
    return {
        "openapi": "3.1.0",
        "info": {"title": "SecureCode AI control-plane API", "version": API_VERSION},
        "servers": [{"url": "/"}],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "artifactReceipt": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-SecureCode-Receipt-Signature",
                },
                "githubWebhookSignature": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Hub-Signature-256",
                },
                "gitlabWebhookToken": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Gitlab-Token",
                },
                "bearerAuth": {"type": "http", "scheme": "bearer"},
            }
        },
    }
