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

These namespaces are allocation documentation only in `P1.1`; later tasks must
create them when their contracts and tests are in scope.
