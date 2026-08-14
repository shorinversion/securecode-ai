# CLI application boundary

This package composes the shared contracts, Core and adapters. It owns argument
parsing, terminal/JSON presentation and stable process-exit mapping, never a
second workflow, security policy or verdict implementation.

The P1.10 entry point intentionally exposes only:

```text
securecode --help
securecode --version
securecode doctor [--json]
```

`doctor` performs four source-free structural checks against a credential-free,
hash-pinned fake profile. Its machine result always says
`scan_readiness=NOT_EVALUATED`; exit `0` means only that these diagnostics ran.
It opens no socket, reads no repository source and invokes no model. Functional
`scan`, `fix`, `validate`, `apply` and connected `ci` remain downstream tasks.
