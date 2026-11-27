#!/usr/bin/env python3
"""Exercise real loopback responses and validate versioned JSON schemas."""
import json
import hashlib
from datetime import datetime, timezone
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
from urllib.parse import urlsplit
import urllib.request
from pathlib import Path

root = Path(__file__).resolve().parents[1]
schemas = root / "contracts/backup/v1"
binary = str(Path(sys.argv[1]).resolve())
secret = "conformance-static-secret"
checks = 0


def validate(value, schema_file):
    schema = json.loads((schemas / schema_file).read_text())
    if schema["type"] == "array":
        assert isinstance(value, list)
        for item in value:
            assert isinstance(item, str)
            if "pattern" in schema["items"]:
                import re
                assert re.fullmatch(schema["items"]["pattern"], item)
        return True
    assert schema["type"] == "object" and set(schema["required"]) <= value.keys()
    if schema.get("additionalProperties") is False:
        assert value.keys() <= schema["properties"].keys()
    for key, rule in schema["properties"].items():
        if key not in value:
            continue
        item = value[key]
        if "const" in rule:
            assert item == rule["const"]
        if rule.get("type") == "string":
            assert isinstance(item, str)
            assert len(item) >= rule.get("minLength", 0)
            assert len(item) <= rule.get("maxLength", 1 << 30)
            if "pattern" in rule:
                import re
                assert re.fullmatch(rule["pattern"], item)
            if rule.get("format") == "date-time":
                assert datetime.strptime(item, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if rule.get("format") == "uri":
                parsed = urlsplit(item)
                assert parsed.scheme in ("http", "https") and parsed.hostname
                assert not parsed.query and not parsed.fragment and parsed.username is None
        if rule.get("type") == "integer":
            assert isinstance(item, int) and not isinstance(item, bool)
    return True


def call(url, method="GET", token=None, body=None):
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=4) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except urllib.error.URLError:
        return 0, b""


with tempfile.TemporaryDirectory(prefix="barkup-conformance-") as data:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    for key in ("BARKUP_STATE_DIR", "BARKUP_TOKEN_FILE", "BARKUP_MAX_BYTES", "BARKUP_RETENTION"):
        env.pop(key, None)
    env.update(BARKUP_DATA=data, BARKUP_TOKEN=secret, BARKUP_URL=base)
    qr = subprocess.run([binary, "pair", "create"], env=env, check=True, capture_output=True, text=True)
    bootstrap = json.loads(qr.stdout)
    validate(bootstrap, "bootstrap.schema.json")
    state = json.loads((Path(data) / ".devices.json").read_text())
    token_hash = hashlib.sha256(bootstrap["token"].encode()).hexdigest()
    expiry = state["bootstrap"][token_hash]
    assert int(datetime.strptime(bootstrap["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()) == expiry
    checks += 1
    server = subprocess.Popen([binary, "serve"], env=dict(env, BARKUP_BIND=f"127.0.0.1:{port}"), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pairing = {"token": ""}
    try:
        for _ in range(100):
            if server.poll() is not None:
                raise RuntimeError("service exited before readiness")
            status, _ = call(base + "/health")
            if status == 200:
                break
            time.sleep(0.03)
        else:
            raise RuntimeError("service readiness timed out")
        checks += 1
        status, _ = call(base + "/v1/files")
        assert status == 401
        checks += 1
        status, body = call(base + "/v1/pair/redeem", "POST", body=json.dumps({"token": bootstrap["token"], "label": "CI device"}).encode())
        assert status == 200
        pairing = json.loads(body)
        validate(pairing, "pairing.schema.json")
        checks += 1
        status, _ = call(base + "/v1/pair/redeem", "POST", body=json.dumps({"token": bootstrap["token"]}).encode())
        assert status == 403
        checks += 1
        status, body = call(base + "/v1/files", token=secret)
        assert status == 200
        inventory = json.loads(body)
        validate(inventory, "inventory.schema.json")
        assert inventory["files"] == {}
        checks += 1
        upload_body = json.dumps({"name": "0" * 64, "length": 1}).encode()
        status, body = call(base + "/v1/uploads", "POST", secret, upload_body)
        assert status == 201
        validate(json.loads(body), "upload-session.schema.json")
        checks += 1
        status, body = call(base + "/v1/snapshots", token=secret)
        assert status == 200
        validate(json.loads(body), "snapshot-list.schema.json")
        checks += 1
    finally:
        server.terminate()
        stdout, stderr = server.communicate(timeout=5)
        logs = stdout + stderr
        assert secret.encode() not in logs and bootstrap["token"].encode() not in logs and pairing["token"].encode() not in logs
assert checks >= 8, "the live suite must exercise every configured conformance behavior"
print(f"live conformance checks passed: {checks} exercised behaviors")
