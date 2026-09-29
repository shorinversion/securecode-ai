# DeepSeek: owner-authorized private source

The project owner explicitly authorized using DeepSeek for private source code on 2026-09-27. This supersedes the earlier public-benchmark-only restriction for source the owner has authority to disclose.

This permission is not evidence of zero retention or no training by the provider. Do not label it as a verified ZDR profile. Credentials and restricted data remain excluded.

`owner-consent.json` records authorization, not an active runtime configuration. A narrowly scoped explicit-consent admission path is implemented for profile deepseek-owner-authorized, endpoint api.deepseek.com, managed_scan_opt_in, the dated owner-consent reference and tenant_admin_approval=true. Retention and training remain unknown rather than falsely verified. Thirty-eight preflight tests passed, including negative consent, endpoint and ZDR cases. On 2026-09-29 the P9.17 demo (`demo/p917_real_local_demo.py --provider deepseek`) ran discovery and repair through this profile on the public CWE-89 fixture: `outcome=COMPLETED`, two calls, $0.00014; see `report/submission-benchmark/evidence/current-deepseek-p917.json`. That first real call required accepting DeepSeek's `logprobs` and cache-accounting `usage` fields in the remote envelope validator. Private source has not been transmitted.

## Current installed CLI probe

The real `securecode scan` probe on the public CWE-89 fixture exited 3 before loading remote configuration. `load_local_product_host` rejected the Windows registry ACL. No DeepSeek request was started, no spend database was created, and no report was emitted. This is a host-admission failure, not a model-quality measurement. Do not bypass the host trust check or treat the result as a successful audit.
