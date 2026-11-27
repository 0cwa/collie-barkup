# Collie Barkup agent notes

- Keep the binary standalone; do not add dependencies on other Collie projects.
- Preserve Android archive bytes exactly and reject malformed or unsupported manifests.
- Store uploads and snapshots under the configured data directory; protect published media from overwrite.
- Do not log credentials, authorization headers, request bodies, or pairing tokens.
- Use `agent-heavy --` for builds and full test runs, with a persistent task-local Cargo target directory.
