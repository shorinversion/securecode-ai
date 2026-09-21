# SecureCode AI control plane

The server is the ASGI control plane for authenticated tenants, immutable audit
runs, worker admission, findings, approvals, waivers, artifacts, audit export,
retention, backup and operational readiness. Durable state is stored in SQLite
with versioned migrations and tenant-scoped identifiers.

Run it with `securecode-server`. A public bind requires a TLS certificate and a
private key. Authentication uses protected bootstrap token files or the offline
OIDC configuration. Repository source remains on the worker; the server accepts
bounded evidence and content-addressed artifacts.

Health endpoints:

```text
GET /api/v1/health/live
GET /api/v1/health/ready
```
