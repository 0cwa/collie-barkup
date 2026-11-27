# v1 conformance

The JSON schema and canonical examples under `contracts/backup/v1` define the versioned pairing, upload, and inventory envelopes. `fixtures/files-frame.hex` is a canonical length-delimited protobuf manifest example. The Rust handler enforces token protection, content and chunk limits, offset checks, range reads, strict media naming, and protobuf `FilesFrame` parsing. `cargo test --all-targets` exercises contract helpers and end-to-end HTTP behavior.

Clients must preserve `metadata`, `main`, and `files` bytes exactly, resume from the server-reported upload offset, and treat non-success statuses as failure. Finalize only after all referenced media have committed. Pruning conflicts while any stage or upload exists.
