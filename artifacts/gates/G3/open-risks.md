# G3 open risks

release_blocking_risks: none

- GPU memory observations on this Windows host are labelled
  `PLATFORM_UNRELIABLE`; the qualification record preserves that uncertainty
  instead of presenting it as authoritative VRAM capacity.
- A first real-model attempt returned a transient typed provider error. A
  second attempt on unchanged commit bytes completed and recorded all required
  receipts; no product code changed between attempts.
- Five POSIX/FIFO repository-intake oracles are unavailable on Windows and were
  explicitly skipped. They are platform-specific existing tests, not G3
  functionality omitted from the candidate.
- G3 does not claim root-cause repair, patch validation, release readiness or
  project completion; those remain in G4 and later gates.
