# GitHub integration

The GitHub adapter validates webhook and installation identity, reconciles the
current pull-request head, publishes a bounded Check Run summary and annotations,
and refuses publication when the head SHA changes. Pagination, retries and
duplicate delivery are handled without giving the adapter verdict authority.

Runtime implementation lives in `packages/adapters/src/securecode_ai/adapters/`
under the `github_*` modules. Configure credentials through protected files as
shown in `.env.example`.
