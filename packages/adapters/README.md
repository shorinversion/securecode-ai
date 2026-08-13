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

Provider HTTP execution, DNS/rebinding checks and outcome normalization remain
owned by `P1.8`; general telemetry redaction remains owned by `P1.12`.
