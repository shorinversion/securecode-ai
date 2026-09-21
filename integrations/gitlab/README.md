# GitLab integration

The GitLab adapter validates project, merge-request and exact-head identity,
publishes commit status, discussions and summaries, and reconciles retries and
duplicate delivery. Renamed files preserve both old and new paths in inline
findings. Publication fails closed when the merge-request head changes.

The source project uses the credential-free trigger in `.gitlab-ci.yml`. The
trusted project uses `deploy/gitlab/trusted-audit.yml`, holds the worker token,
checks out the exact source SHA and runs the digest-pinned worker image.
