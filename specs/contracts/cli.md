# CLI contract

Spec version: `0.2.0`  
Lifecycle: `accepted`

Commands:

```text
securecode scan PATH [--config FILE] [--format json|sarif|markdown|html] [--output PATH]
securecode fix FINDING_ID [--output PATCH]
securecode validate PATCH [--repository PATH]
securecode apply PATCH [--repository PATH] [--yes]
securecode ci --server URL --run-id ID
securecode doctor [--json]
```

- `SC-CLI-001`: `scan/fix/validate` MUST work without backend; `ci` is the only
  command that requires control plane. **Oracle:** command tests with no server.
- `SC-CLI-002`: Machine-readable stdout MUST contain one versioned result; human
  diagnostics go to stderr and contain no terminal control/source/secret leaks.
  **Oracle:** stream snapshot/security tests.
- `SC-CLI-003`: Exit codes are stable: `0` completed/non-blocking policy result,
  `2` policy fail, `3` indeterminate, `4` operational error, `5` invalid usage/
  config, `6` cancelled/superseded. **Oracle:** scenario matrix.
- `SC-CLI-004`: In advisory mode confirmed findings MAY exit `0`, but result JSON
  MUST retain their severity/verdict and `gate_mode=advisory`. **Oracle:**
  advisory fixture.
- `SC-CLI-005`: CLI MUST NOT overwrite source or existing output without an
  explicit apply/overwrite action. **Oracle:** hash/overwrite tests.
- `SC-CLI-006`: Config precedence MUST be CLI → environment → repository config
  → user config → defaults, while secrets exist only as environment/secret-store
  references. **Oracle:** precedence and redaction suite.
- `SC-CLI-007`: Unsupported language/feature MUST be present in coverage and
  must cause non-pass when required by policy. **Oracle:** mixed repo scenario.
- `SC-CLI-008`: `--format sarif` and other format flags MUST NOT alter finding or
  gate semantics. **Oracle:** cross-format semantic comparison.
- `SC-CLI-009`: A full `scan` MUST exit `3` when mandatory model-native discovery
  is unavailable or non-successful; `doctor` MUST detect provider/capability/
  egress incompatibility before source context or network bytes are sent.
  Deterministic-only operation is an explicit evaluation/diagnostic mode and
  MUST NOT claim a product scan `PASS`. **Oracle:** profile/fault/exit-code matrix
  and zero-byte preflight capture.
