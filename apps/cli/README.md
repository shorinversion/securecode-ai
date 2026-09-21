# SecureCode AI CLI

The CLI composes the shared contracts, Core and adapters for local repository
audits and guarded repair workflows.

```text
securecode doctor
securecode scan <checkout> [--config <file>] [--format json|sarif|markdown|html]
securecode fix <checkout>
securecode validate <checkout> [--patch <selector>]
securecode approve <checkout> --patch <selector> --artifact-sha256 <digest> ...
securecode release --config <file> [--publish --authorization <file>]
```

Exit code `0` means a successful command or clean result, `2` means findings or
a failed result, and `3` means an indeterminate result. Output files are created
atomically and are never silently overwritten. `fix` proposes a patch only;
validation and explicit approval are separate operations.
