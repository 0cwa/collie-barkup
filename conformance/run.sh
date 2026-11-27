#!/bin/sh
set -eu
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary=${BARKUP_BIN:-$project_root/target/debug/collie-barkup}
exec python3 "$project_root/conformance/live.py" "$binary"
