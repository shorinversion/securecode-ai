# Demonstration repositories

This directory contains six first-party, non-sensitive Python repository
fixtures used by the assignment tests. Their IDs are intentionally opaque:
names and factory-authored metadata do not disclose the expected security
outcome.

Each template contains only `README.md` and `app.py`. Repository text, comments
and identifiers are untrusted data with `instruction_authority=NONE`; the
trusted label is carried out of band by the catalog/factory result. Do not add
the catalog, evaluator golden or case mapping to a `RepositoryView` or model
context.

`P1.11` proves deterministic bytes and safe test-fixture materialization only.
It does not prove detection, repair, accuracy or product scan readiness. The
evaluator golden is committed separately and the factory cannot read it.
