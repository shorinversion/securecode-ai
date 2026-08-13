# G0 open risks and accepted deferrals

| ID | Risk | Current control | Owner / review gate |
|---|---|---|---|
| `G0-R01` | First-party MVP corpus is small and authored by project | claim limited to contract/CWE-89; independent fixture review | Evaluation / G4 |
| `G0-R02` | External benchmark revision/license/leakage unresolved | excluded from claims/runs until locked | Evaluation / G7 |
| `G0-R03` | Statistical blocking thresholds unknown | advisory-only compiler guard | AppSec / P7.9-G7 |
| `G0-R04` | Temporal adds operational/determinism complexity | port isolation, LocalRuntime and kill/replay contract suite | Platform / G1-G6 |
| `G0-R05` | gVisor may reject or slow real toolchains | mandatory compatibility matrix; no silent downgrade | Platform / G4-G8 |
| `G0-R06` | Provider retention/model aliases/capabilities change | explicit verified profile and preflight; source-local default | Security / every release |
| `G0-R07` | GitHub App/webhook/admin environment may be unavailable for defense | GitHub-first reference can be reversed by CR; Core/SCM contract neutral | Product / before P5 |
| `G0-R08` | PostgreSQL RLS bypass by owner/BYPASSRLS/insider | application authz primary, non-owner role, audit and isolation tests | Backend / G6-G8 |
| `G0-R09` | Sandbox/container escape remains possible | no high-value credentials, layered isolation, teardown and incident plan | Security / G8 |
| `G0-R10` | Deadline is stated as 27 September 23:59 but year/timezone and solo/team approval are unconfirmed | explicit `SC-PROD-021` and `P9.12`; ask instructor early and block final submission, not P1 contracts | Product owner / P9.12-G9 |
| `G0-R11` | Mandatory model-native discovery increases provider availability/cost and requires source-eligible policy | preflight eligibility, bounded tools/budgets, local/private profile and explicit `INDETERMINATE`; calibrate at P7 | AI security / G3-G7 |
| `G0-R12` | RLM/optimizer/synthetic experiments can leak, overfit or self-modify | isolated optional P7 lab, protected paths, executable oracle, held-out and human promotion; no Core dependency | Evaluation/AppSec / G7 |

Acceptance of these risks authorizes only the next phase named in the plan; it
does not waive later gates.
