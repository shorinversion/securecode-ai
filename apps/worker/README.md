# SecureCode AI worker

The Linux worker polls the control plane, executes an admitted audit against an
exact repository revision, uploads verified artifacts and completes the run with
identity-bound receipts. It has no control-plane database access and receives no
SCM write credential.

Run it with `securecode-worker-service`. Configure the control-plane URL, worker
identity, target checkout and a protected worker token file through the
`SECURECODE_WORKER_*` variables documented in the root `.env.example`.
