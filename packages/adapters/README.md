# Adapter package boundary

Adapters implement ports declared by Core; they do not own domain rules,
verdict semantics or competing wire models.

Reserved implementation namespaces are:

- `runtime/local` and `runtime/temporal`;
- `persistence/postgres`;
- `artifacts/filesystem` and `artifacts/s3`;
- `sandbox/oci` and `sandbox/kubernetes_gvisor`;
- `providers/fake`, `providers/openai`, `providers/anthropic` and
  `providers/openai_compatible`.

`P1.7` adds a configuration adapter outside those runtime namespaces. It parses
only approved immutable `ProviderProfile` objects, resolves selection-only
CLI/environment/repository/user/default precedence, and exposes host-bound
ephemeral credential leases. Repository and user configuration cannot inject
provider endpoints, model IDs, budgets, capabilities or credential values.

The locally verified `P1.8` candidate adds a hermetic exact-request fake,
OpenAI/Anthropic/OpenAI-compatible native-envelope normalization, safe public
model parsers, ephemeral zeroizable payloads and connect-time endpoint
authorization with all-address, resolution-replay and connected-peer checks.
The bounded harness snapshots and keys the exact authorized payload, binds the
manifest through the verified provider attempt, attaches credentials and bytes
only after peer verification, and applies lock-backed process-local in-flight
reservation so concurrent duplicates share one exact effect/result and semantic
conflicts add no effect. Durable/restart idempotency remains downstream runtime
and persistence work. This increment does not add a live HTTP/provider SDK,
retries or workflow routing; general telemetry redaction remains owned by
`P1.12`.
