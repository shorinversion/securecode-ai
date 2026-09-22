# Server and worker containers

This Compose deployment runs the control plane and a connected worker on a
dedicated Linux host. The server publishes HTTPS only on loopback. The worker
gets a read-only checkout mount and no Docker socket or privileged mode. The
server image readiness check calls the actual `/api/v1/health/ready` API over
its local TLS listener and supplies the required API-version header.

## Clean start

Requirements: Docker Engine with Compose v2, a Linux host, and an HTTPS
certificate whose SANs include `localhost` and `securecode-server`. The worker
trusts the CA file given by `SECURECODE_TLS_CA_SOURCE`. The API remains bound to
`127.0.0.1`; place an authenticated TLS reverse proxy in front of it if remote
operators need access. Do not expose the container port directly.

Create five files outside the repository: a TLS certificate, its private key,
the issuing CA certificate, an admin bearer token, and a separate worker bearer
token. Tokens must contain at least 32 ASCII characters. On Linux, make the
private key and token files readable only by UID 65532, the non-root image user;
the TLS key must have no group or other permission bits. Keep the CA certificate
readable by the worker. Do not pass token values in Compose environment fields.

Set these Compose inputs in the shell or in an untracked `.env` beside this
file:

```dotenv
SECURECODE_TLS_CERT_SOURCE=/secure/secrets/server.crt
SECURECODE_TLS_KEY_SOURCE=/secure/secrets/server.key
SECURECODE_TLS_CA_SOURCE=/secure/secrets/ca.crt
SECURECODE_ADMIN_TOKEN_SOURCE=/secure/secrets/admin.token
SECURECODE_WORKER_TOKEN_SOURCE=/secure/secrets/worker.token
SECURECODE_BOOTSTRAP_TENANT_ID=acme
SECURECODE_BOOTSTRAP_WORKER_REPOSITORIES=payments-service
SECURECODE_WORKER_SOURCE=/srv/checkouts/payments-service
SECURECODE_WORKER_ID=payments-worker-1
SECURECODE_SERVER_PUBLISHED_PORT=8443
```

The checkout must exist on the host and is mounted read-only at
`/workspace/repository`. The worker can only process repositories admitted by
`SECURECODE_BOOTSTRAP_WORKER_REPOSITORIES`. Use repository identifiers from
your control-plane configuration; do not widen this list to `*`.

From the repository root, build and start the services:

```sh
docker compose -f deploy/docker/compose.yaml build
docker compose -f deploy/docker/compose.yaml up -d
docker compose -f deploy/docker/compose.yaml ps
curl --cacert "$SECURECODE_TLS_CA_SOURCE" \
  -H 'X-SecureCode-Api-Version: 1.0.0' \
  https://localhost:8443/api/v1/health/ready
```

The server must become `healthy` before Compose starts the worker. The worker
polls the server over the private Compose network and validates its TLS
certificate using the mounted CA. To stop the deployment, run
`docker compose -f deploy/docker/compose.yaml down`; persistent server and
worker state volumes remain. Add `--volumes` only when intentionally deleting
all local state. Back up the server volume before upgrades.

For an operator request from the host, install the issuing CA in the host trust
store and configure `SECURECODE_CONTROL_PLANE_URL=https://localhost:8443` plus
the admin token using the connected CLI's documented variables. Rotate tokens
by provisioning new token files, updating the Compose source path, and
recreating the affected services. The worker token is distinct from the admin
token.

## Runtime environment variables

This inventory was checked against string-valued `SECURECODE_*` environment
names in `apps/server/src` and `apps/worker/src`. `NAME_FILE` and `NAME` are
mutually exclusive where described. Secrets should use file variants and
read-only mounts. Values are not copied into telemetry.

| Variable | Service | Meaning |
|---|---|---|
| `SECURECODE_SERVER_HOST` | server | Bind address; a non-loopback bind requires TLS. |
| `SECURECODE_SERVER_PORT` | server | HTTP/TLS listener port, default `8080`. |
| `SECURECODE_DATA_DIR` | both | Private state directory, default `/var/lib/securecode`. |
| `SECURECODE_TMP_DIR` | both | Private temporary directory, default `/tmp/securecode`. |
| `SECURECODE_TLS_CERT_FILE`, `SECURECODE_TLS_KEY_FILE` | server | TLS certificate and private-key file paths; set both. |
| `SECURECODE_ARTIFACT_UPLOAD_URL` | server | Absolute HTTPS base URL for worker artifact uploads. |
| `SECURECODE_ARTIFACT_RECEIPT_KEY_ID` | server | Public identifier attached to signed artifact receipts. |
| `SECURECODE_ARTIFACT_RECEIPT_SECRET`, `SECURECODE_ARTIFACT_RECEIPT_SECRET_FILE` | server | Alternative signer secret sources; file is preferred. If omitted, a key is created in persistent server state. |
| `SECURECODE_BOOTSTRAP_TENANT_ID` | server | Tenant for bootstrap identities. |
| `SECURECODE_BOOTSTRAP_ADMIN_TOKEN`, `SECURECODE_BOOTSTRAP_ADMIN_TOKEN_FILE` | server | Alternative admin token sources. |
| `SECURECODE_BOOTSTRAP_WORKER_TOKEN`, `SECURECODE_BOOTSTRAP_WORKER_TOKEN_FILE` | server | Alternative worker token sources. |
| `SECURECODE_BOOTSTRAP_WORKER_REPOSITORIES` | server | Comma-separated repository IDs authorized for the bootstrap worker. |
| `SECURECODE_BOOTSTRAP_SCM_TOKEN`, `SECURECODE_BOOTSTRAP_SCM_TOKEN_FILE` | server | Alternative SCM workload token sources. |
| `SECURECODE_SCM_TENANT_ID` | server | Tenant used to build SCM webhook adapters; defaults to the first bootstrap identity tenant. |
| `SECURECODE_SCM_PINS_FILE` | server | Optional validated repository/branch pin document for SCM adapters. |
| `SECURECODE_GITHUB_API_URL` | server | Enables GitHub adapter and sets its API base URL. |
| `SECURECODE_GITHUB_INSTALLATION_ID` | server | GitHub App installation identifier; required with GitHub adapter. |
| `SECURECODE_GITHUB_TOKEN_FILE`, `SECURECODE_GITHUB_WEBHOOK_SECRET_FILE` | server | GitHub App token and webhook secret files. |
| `SECURECODE_GITLAB_API_URL` | server | Enables GitLab adapter and sets its API base URL. |
| `SECURECODE_GITLAB_TOKEN_FILE`, `SECURECODE_GITLAB_WEBHOOK_SECRET_FILE` | server | GitLab access token and webhook secret files. |
| `SECURECODE_OIDC_CONFIG_FILE`, `SECURECODE_OIDC_KEY_FILE` | server | OIDC verifier configuration and private signing key files. |
| `SECURECODE_ASSURANCE_VERIFIER_REGISTRY`, `SECURECODE_ASSURANCE_VERIFIER_REGISTRY_FILE` | server | Inline or file-based assurance-verifier registry. |
| `SECURECODE_RESOURCE_PROFILE_ID` | server | Resource-policy profile identifier. |
| `SECURECODE_MAX_CONCURRENT_RUNS`, `SECURECODE_MAX_ADMISSIONS_PER_WINDOW`, `SECURECODE_ADMISSION_WINDOW_MS` | server | Admission concurrency and rate-window limits. |
| `SECURECODE_MAX_TOKENS_PER_WINDOW`, `SECURECODE_MAX_COST_MICROUNITS_PER_WINDOW` | server | Tenant token and cost budgets for the admission window. |
| `SECURECODE_MAX_CPU_MS_PER_RUN`, `SECURECODE_MAX_MEMORY_BYTES_PER_RUN`, `SECURECODE_MAX_WALL_MS_PER_RUN` | server | Per-run CPU, memory and wall-clock ceilings. |
| `SECURECODE_RUN_TOKENS`, `SECURECODE_RUN_COST_MICROUNITS`, `SECURECODE_RUN_CPU_MS`, `SECURECODE_RUN_MEMORY_BYTES`, `SECURECODE_RUN_WALL_MS` | server | Default requested per-run resource budget. |
| `SECURECODE_RUN_LEASE_MS` | server | Worker run-lease duration. |
| `SECURECODE_BACKUP_EXECUTOR_EXECUTABLE`, `SECURECODE_BACKUP_EXECUTOR_EXECUTABLE_SHA256`, `SECURECODE_BACKUP_EXECUTOR_TIMEOUT_SECONDS` | server | Optional pinned backup executor executable and timeout. |
| `SECURECODE_SECRET_PROVIDER_EXECUTABLE`, `SECURECODE_SECRET_PROVIDER_EXECUTABLE_SHA256`, `SECURECODE_SECRET_PROVIDER_TIMEOUT_SECONDS` | server | Optional pinned secret-provider executable and timeout. |
| `SECURECODE_CONTROL_PLANE_URL` | worker | HTTPS control-plane base URL. |
| `SECURECODE_WORKER_ID`, `SECURECODE_WORKER_TARGET` | worker | Stable worker ID and absolute existing checkout directory. |
| `SECURECODE_WORKER_RUN_ID` | worker | Optional one-shot run ID; otherwise worker claims available work. |
| `SECURECODE_WORKER_TOKEN`, `SECURECODE_WORKER_TOKEN_FILE` | worker | Alternative worker bearer-token sources; file is preferred. |
| `SECURECODE_WORKER_REQUEST_TIMEOUT_SECONDS`, `SECURECODE_WORKER_POLL_SECONDS`, `SECURECODE_WORKER_MAX_BACKOFF_SECONDS` | worker | Bounded request, polling and retry timing. |
| `SECURECODE_WORKER_ARTIFACT_HOSTS` | worker | Comma-separated HTTPS hosts permitted for artifact upload. |

The worker also reads `CI_PROJECT_ID`, `CI_MERGE_REQUEST_IID` and
`CI_COMMIT_SHA` when resolving GitLab merge-request work. Set all three
together; the worker rejects a partial identity. The Compose file sets
`SSL_CERT_FILE` to the mounted CA so the worker verifies the server certificate.
Variables such as `SECURECODE_TLS_CERT_SOURCE` are Compose inputs, not
application environment variables.

## Production notes

- Keep bootstrap and provider credentials in a secret manager or protected
  secret files. Never put them in a committed `.env` or image layer.
- Use a dedicated Linux runner/host, a trusted image registry and immutable
  image digests for production. The `:local` tags are for clean-start testing.
- This deployment does not create per-run sandbox containers. Do not give the
  worker a Docker socket or use it to execute untrusted pull-request code
  without the separately enforced sandbox profile and default-deny egress.
- Configure log retention, backups, alerting, outbound network policy and
  certificate/token rotation for the target environment before onboarding
  private repositories.
