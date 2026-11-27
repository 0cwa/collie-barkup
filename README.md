# Collie Barkup

Standalone encrypted V2 backup sidecar and wire contract (`contracts/backup/v1`) for Collie.

## Build and run

Build with `cargo build --locked --release`. The container image runs `serve` by default and also accepts CLI subcommands:

```sh
docker run --rm -v barkup-data:/data IMAGE pair create --url https://backup.example
docker run --rm -v barkup-data:/data --mount type=bind,src=/path/to/token,dst=/run/secrets/barkup-token,readonly -e BARKUP_TOKEN_FILE=/run/secrets/barkup-token -p 8082:8082 IMAGE serve
```

Set `BARKUP_DATA` for archive storage and optionally `BARKUP_STATE_DIR` for private pairing and device state. Pairing creation requires `--url` or `BARKUP_URL`; there is no loopback URL fallback. `devices list` shows the device label and active/revoked state, and `devices revoke <id>` revokes a device. `healthcheck` performs a short TCP check against the configured listener.

The service stages snapshot members, streams restores and supports resumable chunks for media and large snapshot members. Run `cargo test --locked --all-targets`, `python3 conformance/check.py`, and `BARKUP_BIN=target/debug/collie-barkup bash conformance/run.sh` for local verification.
