# Deployment boundary

`compose/` and `kubernetes/` deployment assets are reserved for later backend
and release phases. Deployment configuration must compose released
applications and adapters; it cannot introduce domain behavior or bypass
security policy. No deployment assets are implemented by `P1.1`.
