# Server application boundary

The server will compose the shared Core as the backend control plane. It owns
HTTP/authentication composition and durable coordination, not a second audit
engine and not checkout ingestion by default. Backend implementation belongs to
`P6`.
