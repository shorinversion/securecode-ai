#!/bin/sh
# Reviewer demo entrypoint.  With DEEPSEEK_API_KEY set, the Auditor and Architect run on DeepSeek
# against the public CWE-89 fixture; otherwise only the deterministic lane runs (no model).
set -eu

if [ -n "${DEEPSEEK_API_KEY:-}" ]; then
    echo "SecureCode AI: Auditor + Architect on DeepSeek, public CWE-89 fixture"
    provider=deepseek
else
    echo "SecureCode AI: deterministic lane only (set DEEPSEEK_API_KEY for the model demo)"
    provider=offline
fi
status=0
python demo/p917_real_local_demo.py --repository demo/fixtures/real-local-cwe89 \
    --output /out/report --provider "$provider" > /out/manifest.json || status=$?
echo
cat /out/report/security-report.md
if [ "$provider" = offline ]; then
    exit 0  # INDETERMINATE is the expected outcome without a model.
fi
exit "$status"
