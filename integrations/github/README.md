# GitHub integration

## Pull request audit (CI)

`integrations/github/action.yml` is a composite action that audits only the files a pull
request changes (`securecode analyze --base`), uploads the SARIF report to code scanning and
posts the findings as pull request comments (`securecode publish github`): one summary
comment kept up to date, and one inline comment per new confirmed weakness, with a
`suggestion` block when the validated fix is a single hunk next to the comment. Every
third-party action in it is pinned to a commit SHA.

```yaml
name: SecureCode AI
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write      # the summary and inline comments
  security-events: write    # the SARIF upload

jobs:
  audit:
    runs-on: ubuntu-24.04
    steps:
      - uses: shorinversion/securecode-ai/integrations/github@v1.3.0
        with:
          version: v1.3.0
          provider: openai-compatible
          model-base-url: https://api.openai.com/v1
          model: gpt-4o-mini
          model-api-key: ${{ secrets.SECURECODE_MODEL_API_KEY }}
          github-token: ${{ github.token }}
          # baseline: .securecode-baseline.json   # known findings that must not fail the job
```

Notes:

* The audit sends the changed source to the model service you name; read the data terms of
  that service first (D-118). A fork pull request gets no secrets, so the job cannot run
  there.
* The job fails like the CLI: exit code 2 for a confirmed finding that is not in the
  baseline, 3 when a stage or a candidate is unresolved, 4 for a configuration error.
* A comment on a line that is not part of the pull-request diff is refused by GitHub; such a
  finding stays in the summary and in the code-scanning alert.
* The same comments from a terminal: `securecode analyze . --base origin/main --format json
  --output report.json` and then `securecode publish github --report report.json --repo
  OWNER/NAME --pr N` (`--dry-run` prints the comments without a token or a network).

## GitHub App

The GitHub adapter validates webhook and installation identity, reconciles the
current pull-request head, publishes a bounded Check Run summary and annotations,
and refuses publication when the head SHA changes. Pagination, retries and
duplicate delivery are handled without giving the adapter verdict authority.

Runtime implementation lives in `packages/adapters/src/securecode_ai/adapters/`
under the `github_*` modules. Configure credentials through protected files as
shown in `.env.example`.
