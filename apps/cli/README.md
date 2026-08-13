# CLI application boundary

The CLI will compose the shared Core for offline repository operation. It owns
argument parsing, terminal/JSON presentation and process exit mapping, not
security rules or a separate workflow implementation. Functional work begins
in `P1.10`.
