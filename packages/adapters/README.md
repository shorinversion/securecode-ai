# Adapter package

Adapters implement Core ports. They own infrastructure integration and data
translation, while verdict semantics and policy remain in Core.

The current package provides:

- bounded Git snapshots and repository views;
- Python, JavaScript, TypeScript and Go CST/symbol adapters;
- deterministic CWE and dependency scanning, including bounded OSV lookup;
- approved-profile local provider transport and native Ollama tool turns;
- product discovery, Auditor, Skeptic and reporting composition;
- durable local patch artifacts and approval status;
- isolated OCI repair validation;
- GitHub Checks and GitLab status/discussion writers;
- SCM head and artifact reconciliation;
- release authorization and local publication adapters;
- secret detection and untrusted-contribution admission.

Endpoints, models, budgets and capabilities come from approved immutable
profiles. Repository or environment configuration may select a profile but may
not inject a new provider authority. Private source remains local unless an
explicit egress policy and capability authorize a bounded operation.

Adapters fail closed on stale commit identity, invalid schemas, incomplete
evidence, provider drift, resource exhaustion and unavailable isolation. They
do not define alternate domain models or a second audit workflow.
