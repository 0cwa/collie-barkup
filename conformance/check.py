#!/usr/bin/env python3
"""Check canonical v1 fixtures against the contract's deliberately small schema subset."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "contracts/backup/v1"


def load(name):
    return json.loads((ROOT / "fixtures" / name).read_text())


def check_object(value, schema_name):
    schema = json.loads((ROOT / schema_name).read_text())
    assert schema["type"] == "object"
    assert set(schema["required"]) <= value.keys()
    assert not (value.keys() - schema["properties"].keys()) if schema.get("additionalProperties") is False else True
    for key, rule in schema["properties"].items():
        if key not in value:
            continue
        item = value[key]
        if "const" in rule:
            assert item == rule["const"]
        if rule.get("type") == "string":
            assert isinstance(item, str)
            if "pattern" in rule:
                assert re.fullmatch(rule["pattern"], item)
        if rule.get("type") == "integer":
            assert isinstance(item, int) and not isinstance(item, bool)
            assert item >= rule.get("minimum", 0)


check_object(load("pairing.json"), "pairing.schema.json")
check_object(load("bootstrap.json"), "bootstrap.schema.json")
check_object(load("pair-redeem.json"), "pair-redeem.schema.json")
check_object(load("upload-create.json"), "upload-create.schema.json")
check_object(load("upload-session.json"), "upload-session.schema.json")
inventory = load("inventory.json")
check_object(inventory, "inventory.schema.json")
for name, size in inventory["files"].items():
    assert re.fullmatch(r"[0-9a-f]{64}", name) and isinstance(size, int) and size >= 0
snapshots = load("snapshot-list.json")
assert all(re.fullmatch(r"signal-backup-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}", x) for x in snapshots)
frame = bytes.fromhex((ROOT / "fixtures/files-frame.hex").read_text().strip())
assert frame[0] == len(frame) - 1 and frame[1:3] == b"\x0a\x40"
assert re.fullmatch(rb"[0-9a-f]{64}", frame[3:])
print("v1 canonical fixtures conform")
