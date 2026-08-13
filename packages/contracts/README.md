# Contracts package boundary

This package will own versioned domain/wire types and generated schema
compatibility surfaces beginning in `P1.5`. It may use validation libraries
selected by the packaging task, but it must not import model-provider, SCM,
database, object-store, container or workflow-runtime SDKs.

No executable contract implementation is part of `P1.1`.
