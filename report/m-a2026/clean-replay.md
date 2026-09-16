# Clean replay

Run from a clean checkout with the locked local environment. These commands do not execute corpus source or contact a model provider. Choose a new, empty destination for every build.

```powershell
.venv\Scripts\python.exe -I scripts\build_m_a2026_submission.py --output <new-empty-output-directory>
.venv\Scripts\python.exe -I scripts\build_m_a2026_submission.py --validate <new-empty-output-directory>
```

The submission notebook was executed with the locked project interpreter. It runs the pinned public CWE-89 composition in an ephemeral workspace, reads the recorded benchmark aggregate and redacted real-local receipt, and makes no model call. Re-execute it from a clean checkout with the locked interpreter registered as a Jupyter kernel. Build the bundle separately with the command above, compare `delivery-manifest.json` hashes with the expected checkout, and retain `NOT_READY` until every external confirmation and durable final review is recorded.
