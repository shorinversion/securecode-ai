# G4 open risks

release_blocking_risks: none

Accepted limitations:

- The reference flow covers one pinned synthetic Python CWE-89 vertical slice;
  it is not an accuracy or multi-language benchmark.
- Five Windows skips are POSIX descriptor/FIFO oracles and are unchanged from
  earlier gates; their platform-specific coverage remains available on POSIX.
- The demo uses deterministic in-process components, no network, and reports
  `product_outcome=NOT_EVALUATED`; real SCM delivery belongs to G5.
- Human approval remains required before applying a validated patch to a source
  repository.
