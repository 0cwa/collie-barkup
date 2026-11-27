use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const SECRET: &str = "static-secret-for-process-test";

fn request(
    addr: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &[u8],
    extra: &[(&str, &str)],
) -> (u16, String, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    if let Some(token) = token {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    for (k, v) in extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let split = response.windows(4).position(|x| x == b"\r\n\r\n").unwrap() + 4;
    let headers = String::from_utf8_lossy(&response[..split]).into_owned();
    let status = headers
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, headers, response[split..].to_vec())
}

fn cli(data: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_collie-barkup"))
        .args(args)
        .env("BARKUP_DATA", data)
        .env("BARKUP_TOKEN", SECRET)
        .env("BARKUP_URL", "https://backup.example/v1")
        .env_remove("BARKUP_STATE_DIR")
        .env_remove("BARKUP_TOKEN_FILE")
        .env_remove("BARKUP_MAX_BYTES")
        .env_remove("BARKUP_RETENTION")
        .output()
        .unwrap()
}
fn cli_without_pair_url(data: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_collie-barkup"))
        .args(["pair", "create"])
        .env("BARKUP_DATA", data)
        .env("BARKUP_TOKEN", SECRET)
        .env_remove("BARKUP_URL")
        .env_remove("BARKUP_STATE_DIR")
        .env_remove("BARKUP_TOKEN_FILE")
        .output()
        .unwrap()
}

fn start(data: &std::path::Path, addr: &str) -> Child {
    server_command(data, addr).spawn().unwrap()
}

fn server_command(data: &std::path::Path, addr: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_collie-barkup"));
    command
        .arg("serve")
        .env("BARKUP_DATA", data)
        .env("BARKUP_TOKEN", SECRET)
        .env("BARKUP_BIND", addr)
        .env_remove("BARKUP_STATE_DIR")
        .env_remove("BARKUP_TOKEN_FILE")
        .env_remove("BARKUP_MAX_BYTES")
        .env_remove("BARKUP_RETENTION")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn wait_ready(child: &mut Child, addr: &str) {
    for _ in 0..100 {
        if child.try_wait().unwrap().is_some() {
            panic!("server exited before readiness");
        }
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("server did not become ready");
}

fn stop(mut child: Child) -> String {
    #[cfg(unix)]
    {
        let pid = i32::try_from(child.id()).unwrap();
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    }
    #[cfg(not(unix))]
    child.kill().unwrap();
    let mut exited = false;
    for _ in 0..200 {
        if child.try_wait().unwrap().is_some() {
            exited = true;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    if !exited {
        child.kill().unwrap();
    }
    let output = child.wait_with_output().unwrap();
    #[cfg(unix)]
    assert!(
        output.status.success(),
        "service did not shut down cleanly on SIGTERM"
    );
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!logs.contains(SECRET), "server logs exposed static token");
    logs
}

fn tmp_data() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("barkup-live-{stamp}"))
}

#[test]
fn live_commit_recovers_after_durable_publication() {
    let data = tmp_data();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    drop(listener);
    let mut server = start(&data, &addr);
    wait_ready(&mut server, &addr);
    let call = |method, path: &str, body: &[u8], headers: &[(&str, &str)]| {
        request(&addr, method, path, Some(SECRET), body, headers)
    };
    let ts = "2026-11-27-08-00-00";
    let snapshot = format!("/v1/snapshots/{ts}");
    assert_eq!(call("POST", &snapshot, b"", &[]).0, 201);
    let name = "ac".repeat(32);
    let media = format!("/v1/files/ac/{name}");
    let mut uploads = Vec::new();
    for (path, input, payload, destination) in [
        (
            "/v1/uploads".to_owned(),
            json!({"name":name,"length":5}),
            b"media".as_slice(),
            data.join("SignalBackups/files/ac").join(&name),
        ),
        (
            format!("{snapshot}/uploads/main"),
            json!({"length":4}),
            b"main".as_slice(),
            data.join(format!("SignalBackups/signal-backup-{ts}-tmp/main")),
        ),
    ] {
        let (status, _, reply) = call(
            "POST",
            &path,
            &serde_json::to_vec(&input).unwrap(),
            &[("Content-Type", "application/json")],
        );
        assert_eq!(status, 201);
        let state: Value = serde_json::from_slice(&reply).unwrap();
        let id = state["id"].as_str().unwrap().to_owned();
        assert_eq!(
            call(
                "PATCH",
                &format!("/v1/uploads/{id}"),
                payload,
                &[("Upload-Offset", "0")]
            )
            .0,
            204
        );
        uploads.push((id, payload, destination));
    }

    stop(server);
    // Recreate the durable state just after rename and before session retirement.
    for (id, payload, destination) in &uploads {
        let session = data.join(".uploads").join(id);
        let state_file = session.join("state.json");
        let mut state: Value =
            serde_json::from_slice(&std::fs::read(&state_file).unwrap()).unwrap();
        state["commit_hash"] = json!(format!("{:x}", Sha256::digest(payload)));
        std::fs::write(state_file, serde_json::to_vec(&state).unwrap()).unwrap();
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::rename(session.join("data"), destination).unwrap();
    }
    let tombstone = data.join("SignalBackups/.barkup-retired-Ab123456789012345678901X");
    std::fs::create_dir(&tombstone).unwrap();
    std::fs::write(tombstone.join("main"), b"partly removed old snapshot").unwrap();
    let retained_ts = "2026-11-26-08-00-00";
    let retained = data.join(format!("SignalBackups/signal-backup-{retained_ts}"));
    std::fs::create_dir(&retained).unwrap();
    let mut manifest = vec![66, 10, 64];
    manifest.extend(name.as_bytes());
    for (member, bytes) in [
        ("main", b"previous main".as_slice()),
        ("metadata", b"previous metadata".as_slice()),
        ("files", &manifest),
    ] {
        std::fs::write(retained.join(member), bytes).unwrap();
    }
    server = start(&data, &addr);
    wait_ready(&mut server, &addr);
    assert_eq!(
        serde_json::from_slice::<Value>(&call("GET", "/v1/snapshots", b"", &[]).2).unwrap(),
        json!([format!("signal-backup-{retained_ts}")])
    );
    for member in ["main", "metadata", "files"] {
        let endpoint = format!("/v1/snapshots/{retained_ts}/{member}");
        let (status, _, body) = call("GET", &endpoint, b"", &[]);
        assert_eq!(status, 200);
        assert_eq!(body, std::fs::read(retained.join(member)).unwrap());
    }
    assert!(!tombstone.exists());
    assert_eq!(call("POST", "/v1/files/prune", b"", &[]).0, 409);
    assert_eq!(
        call("PUT", &format!("{snapshot}/main"), b"replace", &[]).0,
        409
    );
    for (id, _, _) in &uploads {
        assert_eq!(
            call("POST", &format!("/v1/uploads/{id}/commit"), b"", &[]).0,
            200
        );
    }
    assert_eq!(std::fs::read_dir(data.join(".uploads")).unwrap().count(), 0);

    assert_eq!(
        call("PUT", &format!("{snapshot}/metadata"), b"meta", &[]).0,
        204
    );
    assert_eq!(
        call("PUT", &format!("{snapshot}/files"), &manifest, &[]).0,
        204
    );
    assert_eq!(
        call("POST", &format!("{snapshot}/finalize"), b"", &[]).0,
        201
    );
    assert_eq!(
        call("GET", &format!("{snapshot}/main"), b"", &[]).2,
        b"main"
    );
    assert_eq!(
        call("POST", "/v1/files/prune", b"", &[]).2,
        b"{\"removed_bytes\":0}"
    );
    assert_eq!(call("GET", &media, b"", &[]).2, b"media");
    stop(server);
    std::fs::remove_dir_all(data).unwrap();
}

#[test]
fn live_quota_reserves_upload_state_and_expires_idle_sessions() {
    let data = tmp_data();
    let bad_config = server_command(&data, "invalid-bind")
        .env("BARKUP_MAX_BYTES", "not-bytes")
        .output()
        .unwrap();
    assert!(!bad_config.status.success());
    assert!(String::from_utf8_lossy(&bad_config.stderr)
        .contains("BARKUP_MAX_BYTES must be a nonnegative integer"));

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    drop(listener);
    let mut server = server_command(&data, &addr)
        .env("BARKUP_MAX_BYTES", (4096 + 5).to_string())
        .spawn()
        .unwrap();
    wait_ready(&mut server, &addr);
    let call = |method, path: &str, body: &[u8]| {
        request(
            &addr,
            method,
            path,
            Some(SECRET),
            body,
            &[("Content-Type", "application/json")],
        )
    };
    let expire = |response: &(u16, String, Vec<u8>)| {
        assert_eq!(response.0, 201);
        let upload: Value = serde_json::from_slice(&response.2).unwrap();
        std::fs::File::open(data.join(".uploads").join(upload["id"].as_str().unwrap()))
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(8 * 24 * 60 * 60))
            .unwrap();
    };
    let media_upload = |length| {
        let body = serde_json::to_vec(&json!({"name":"ab".repeat(32),"length":length})).unwrap();
        call("POST", "/v1/uploads", &body)
    };
    assert_eq!(media_upload(6).0, 507);
    let pending = media_upload(5);
    assert_eq!(pending.0, 201);
    assert_eq!(media_upload(1).0, 507);
    assert_eq!(call("POST", "/v1/files/prune", b"").0, 409);
    expire(&pending);
    assert_eq!(call("POST", "/v1/files/prune", b"").0, 200);

    let snapshot = "/v1/snapshots/2026-11-27-08-00-00";
    assert_eq!(call("POST", snapshot, b"").0, 201);
    for member in ["main", "metadata", "files"] {
        assert_eq!(call("PUT", &format!("{snapshot}/{member}"), b"").0, 204);
    }
    let pending = call(
        "POST",
        &format!("{snapshot}/uploads/main"),
        br#"{"length":5}"#,
    );
    assert_eq!(pending.0, 201);
    assert_eq!(call("POST", &format!("{snapshot}/finalize"), b"").0, 409);
    assert_eq!(call("PUT", &format!("{snapshot}/main"), b"x").0, 409);
    expire(&pending);
    assert_eq!(call("POST", &format!("{snapshot}/finalize"), b"").0, 201);
    stop(server);
    std::fs::remove_dir_all(data).unwrap();
}

#[test]
fn live_pairing_resume_restore_auth_and_revocation() {
    let data = tmp_data();
    std::fs::create_dir_all(&data).unwrap();
    assert!(
        !cli_without_pair_url(&data).status.success(),
        "pair creation unexpectedly selected a default URL"
    );
    let bad_url = Command::new(env!("CARGO_BIN_EXE_collie-barkup"))
        .args(["pair", "create", "--url", "file:///tmp"])
        .env("BARKUP_DATA", &data)
        .env("BARKUP_URL", "https://backup.example")
        .output()
        .unwrap();
    assert!(
        !bad_url.status.success(),
        "pair creation accepted a non-HTTP URL"
    );
    let boot = cli(&data, &["pair", "create"]);
    assert!(boot.status.success());
    let mut qr: Value = serde_json::from_slice(&boot.stdout).unwrap();
    assert_eq!(qr["collie_barkup_pairing"], 1);
    assert!(qr["expires_at"].as_str().unwrap().ends_with('Z'));
    assert!(qr["url"].as_str().unwrap().starts_with("http"));
    let expired_token = qr["token"].as_str().unwrap().to_owned();
    let auth_path = data.join(".devices.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&auth_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(data.join(".devices.json.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let mut auth_state: Value =
        serde_json::from_slice(&std::fs::read(&auth_path).unwrap()).unwrap();
    let expiry = auth_state["bootstrap"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .as_u64()
        .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!((now + 590..=now + 601).contains(&expiry));
    let expired_hash = auth_state["bootstrap"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    auth_state["bootstrap"][&expired_hash] = json!(0);
    std::fs::write(&auth_path, serde_json::to_vec(&auth_state).unwrap()).unwrap();
    let fresh = cli(&data, &["pair", "create"]);
    assert!(fresh.status.success());
    qr = serde_json::from_slice(&fresh.stdout).unwrap();
    let current: Value = serde_json::from_slice(&std::fs::read(&auth_path).unwrap()).unwrap();
    assert_eq!(
        current["bootstrap"].as_object().unwrap().len(),
        1,
        "CLI create must prune expired tokens"
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    drop(listener);
    let mut server = start(&data, &addr);
    wait_ready(&mut server, &addr);
    assert!(Command::new(env!("CARGO_BIN_EXE_collie-barkup"))
        .arg("healthcheck")
        .env("BARKUP_DATA", &data)
        .env("BARKUP_TOKEN", SECRET)
        .env("BARKUP_BIND", &addr)
        .status()
        .unwrap()
        .success());
    assert_eq!(request(&addr, "GET", "/v1/files", None, b"", &[]).0, 401);
    assert_eq!(
        request(&addr, "GET", "/v1/files?token=bad", Some(SECRET), b"", &[]).0,
        400
    );
    assert_eq!(
        request(&addr, "GET", "/v1/files", Some("wrong"), b"", &[]).0,
        403
    );
    assert_eq!(
        request(
            &addr,
            "POST",
            "/v1/pair/redeem",
            None,
            &vec![b'x'; 2048],
            &[("Content-Type", "application/json")]
        )
        .0,
        413
    );
    assert_eq!(
        request(
            &addr,
            "POST",
            "/v1/pair/redeem",
            None,
            &serde_json::to_vec(&json!({"token":expired_token})).unwrap(),
            &[("Content-Type", "application/json")]
        )
        .0,
        403
    );

    let invalid_label_body = serde_json::to_vec(&json!({
        "token": qr["token"],
        "label": "invalid\nlabel"
    }))
    .unwrap();
    assert_eq!(
        request(
            &addr,
            "POST",
            "/v1/pair/redeem",
            None,
            &invalid_label_body,
            &[("Content-Type", "application/json")]
        )
        .0,
        400
    );
    let redeem_body =
        serde_json::to_vec(&json!({"token": qr["token"], "label":"primary tablet"})).unwrap();
    let (status, _, body) = request(
        &addr,
        "POST",
        "/v1/pair/redeem",
        None,
        &redeem_body,
        &[("Content-Type", "application/json")],
    );
    assert_eq!(status, 200);
    let paired: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(paired["version"], 1);
    assert_eq!(paired["label"], "primary tablet");
    assert_eq!(
        request(
            &addr,
            "POST",
            "/v1/pair/redeem",
            None,
            &redeem_body,
            &[("Content-Type", "application/json")]
        )
        .0,
        403
    );

    let data_bytes = b"live backup payload";
    let name = "01".repeat(32);
    let start_body = serde_json::to_vec(&json!({"name":name,"length":data_bytes.len()})).unwrap();
    let (status, _, body) = request(
        &addr,
        "POST",
        "/v1/uploads",
        Some(SECRET),
        &start_body,
        &[("Content-Type", "application/json")],
    );
    assert_eq!(status, 201);
    let upload: Value = serde_json::from_slice(&body).unwrap();
    let id = upload["id"].as_str().unwrap();

    // Disconnect before the declared PATCH body is complete. The persisted offset must stay at zero.
    let mut socket = TcpStream::connect(&addr).unwrap();
    write!(socket, "PATCH /v1/uploads/{id} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {SECRET}\r\nUpload-Offset: 0\r\nContent-Length: 100\r\n\r\nshort").unwrap();
    socket.shutdown(std::net::Shutdown::Write).unwrap();
    let mut ignored = Vec::new();
    let _ = socket.read_to_end(&mut ignored);
    assert!(request(
        &addr,
        "HEAD",
        &format!("/v1/uploads/{id}"),
        Some(SECRET),
        b"",
        &[]
    )
    .1
    .to_ascii_lowercase()
    .contains("upload-offset: 0"));
    // Simulate a restart after the bytes reached disk but before the offset did.
    stop(server);
    std::fs::write(
        data.join(".uploads").join(id).join("data"),
        b"unacknowledged",
    )
    .unwrap();
    server = start(&data, &addr);
    wait_ready(&mut server, &addr);
    assert_eq!(
        request(
            &addr,
            "PATCH",
            &format!("/v1/uploads/{id}"),
            Some(SECRET),
            data_bytes,
            &[("Upload-Offset", "0")]
        )
        .0,
        204
    );

    stop(server);
    server = start(&data, &addr);
    wait_ready(&mut server, &addr);
    assert!(request(
        &addr,
        "HEAD",
        &format!("/v1/uploads/{id}"),
        Some(SECRET),
        b"",
        &[]
    )
    .1
    .to_ascii_lowercase()
    .contains(&format!("upload-offset: {}", data_bytes.len())));
    assert_eq!(
        request(
            &addr,
            "POST",
            &format!("/v1/uploads/{id}/commit"),
            Some(SECRET),
            b"",
            &[]
        )
        .0,
        201
    );

    let mut manifest = vec![66, 10, 64];
    manifest.extend(name.as_bytes());
    for (snapshot_index, (ts, meta, main)) in [
        (
            "2026-11-27-12-00-00",
            b"metadata full".as_slice(),
            b"main full".as_slice(),
        ),
        (
            "2026-11-27-12-01-00",
            b"metadata incremental".as_slice(),
            b"main incremental".as_slice(),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            request(
                &addr,
                "POST",
                &format!("/v1/snapshots/{ts}"),
                Some(SECRET),
                b"",
                &[]
            )
            .0,
            201
        );
        for (member, value) in [
            ("metadata", meta),
            ("main", main),
            ("files", manifest.as_slice()),
        ] {
            if snapshot_index == 1 && member == "main" {
                let length = 101 * 1024 * 1024usize;
                let body = serde_json::to_vec(&json!({"length":length})).unwrap();
                let (status, _, session_body) = request(
                    &addr,
                    "POST",
                    &format!("/v1/snapshots/{ts}/uploads/main"),
                    Some(SECRET),
                    &body,
                    &[("Content-Type", "application/json")],
                );
                assert_eq!(status, 201);
                let session: Value = serde_json::from_slice(&session_body).unwrap();
                let upload_id = session["id"].as_str().unwrap();
                let mut offset = 0usize;
                while offset < length {
                    let amount = (length - offset).min(32 * 1024 * 1024);
                    let chunk = vec![0u8; amount];
                    let offset_header = offset.to_string();
                    assert_eq!(
                        request(
                            &addr,
                            "PATCH",
                            &format!("/v1/uploads/{upload_id}"),
                            Some(SECRET),
                            &chunk,
                            &[("Upload-Offset", &offset_header)]
                        )
                        .0,
                        204
                    );
                    offset += amount;
                }
                assert_eq!(
                    request(
                        &addr,
                        "POST",
                        &format!("/v1/uploads/{upload_id}/commit"),
                        Some(SECRET),
                        b"",
                        &[]
                    )
                    .0,
                    201
                );
                continue;
            }
            assert_eq!(
                request(
                    &addr,
                    "PUT",
                    &format!("/v1/snapshots/{ts}/{member}"),
                    Some(SECRET),
                    value,
                    &[]
                )
                .0,
                204
            );
        }
        assert_eq!(
            request(
                &addr,
                "POST",
                &format!("/v1/snapshots/{ts}/finalize"),
                Some(SECRET),
                b"",
                &[]
            )
            .0,
            201
        );
        assert_eq!(
            request(
                &addr,
                "POST",
                &format!("/v1/snapshots/{ts}/finalize"),
                Some(SECRET),
                b"",
                &[]
            )
            .0,
            200,
            "repeating finalize confirms the already-published snapshot"
        );
        assert_eq!(
            request(
                &addr,
                "POST",
                &format!("/v1/snapshots/{ts}"),
                Some(SECRET),
                b"",
                &[]
            )
            .0,
            409,
            "finalized timestamps cannot be staged again"
        );
        let (status, headers, restored) = request(
            &addr,
            "GET",
            &format!("/v1/snapshots/{ts}/metadata"),
            Some(SECRET),
            b"",
            &[],
        );
        assert_eq!(status, 200);
        assert!(headers.to_ascii_lowercase().contains("content-length:"));
        assert_eq!(restored, meta);
        if snapshot_index == 1 {
            let length = 101 * 1024 * 1024usize;
            let range_size = 32 * 1024 * 1024usize;
            for start in (0..length).step_by(range_size) {
                let end = (start + range_size).min(length) - 1;
                let range = format!("bytes={start}-{end}");
                let (status, headers, bytes) = request(
                    &addr,
                    "GET",
                    &format!("/v1/snapshots/{ts}/main"),
                    Some(SECRET),
                    b"",
                    &[("Range", &range)],
                );
                assert_eq!(status, 206);
                assert_eq!(bytes.len(), end - start + 1);
                assert!(bytes.iter().all(|byte| *byte == 0));
                assert!(headers
                    .to_ascii_lowercase()
                    .contains(&format!("content-range: bytes {start}-{end}/{length}")));
            }
            let (status, _, restored_files) = request(
                &addr,
                "GET",
                &format!("/v1/snapshots/{ts}/files"),
                Some(SECRET),
                b"",
                &[],
            );
            assert_eq!(status, 200);
            assert_eq!(restored_files, manifest);
        } else {
            let (status, _, restored_main) = request(
                &addr,
                "GET",
                &format!("/v1/snapshots/{ts}/main"),
                Some(SECRET),
                b"",
                &[],
            );
            assert_eq!(status, 200);
            assert_eq!(restored_main, main);
            let (status, _, restored_files) = request(
                &addr,
                "GET",
                &format!("/v1/snapshots/{ts}/files"),
                Some(SECRET),
                b"",
                &[],
            );
            assert_eq!(status, 200);
            assert_eq!(restored_files, manifest);
        }
    }
    let (status, headers, restored) = request(
        &addr,
        "GET",
        &format!("/v1/files/{}/{name}", &name[..2]),
        Some(SECRET),
        b"",
        &[],
    );
    assert_eq!(status, 200);
    assert_eq!(restored, data_bytes);
    assert!(headers
        .to_ascii_lowercase()
        .contains("accept-ranges: bytes"));
    let (status, headers, _) = request(
        &addr,
        "GET",
        &format!("/v1/files/{}/{name}", &name[..2]),
        Some(SECRET),
        b"",
        &[("Range", "bytes=999-")],
    );
    assert_eq!(status, 416);
    assert!(headers
        .to_ascii_lowercase()
        .contains("content-range: bytes */19"));

    let device_token = paired["token"].as_str().unwrap();
    let device_id = paired["device_id"].as_str().unwrap();
    let revoked = cli(&data, &["devices", "revoke", device_id]);
    assert!(revoked.status.success());
    let listed_devices = cli(&data, &["devices", "list"]);
    let listed_devices = String::from_utf8(listed_devices.stdout).unwrap();
    assert!(listed_devices.contains("primary tablet"));
    assert!(listed_devices.contains("revoked"));
    assert!(!listed_devices.contains(device_token));
    assert_eq!(
        request(&addr, "GET", "/v1/files", Some(device_token), b"", &[]).0,
        403
    );
    #[cfg(unix)]
    {
        let outside = data.with_extension("outside");
        let outside_body = b"outside write denied";
        let outside_name = "02".repeat(32);
        std::fs::create_dir_all(outside.join("files")).unwrap();
        std::fs::remove_dir_all(data.join("SignalBackups")).unwrap();
        std::os::unix::fs::symlink(&outside, data.join("SignalBackups")).unwrap();
        assert_eq!(
            request(&addr, "GET", "/v1/files", Some(SECRET), b"", &[]).0,
            500,
            "inventory must reject a symlinked storage parent"
        );
        assert_eq!(
            request(&addr, "GET", "/v1/snapshots", Some(SECRET), b"", &[]).0,
            500,
            "snapshot listing must reject a symlinked storage parent"
        );
        assert_eq!(
            request(&addr, "POST", "/v1/files/prune", Some(SECRET), b"", &[]).0,
            409,
            "prune must stop when the storage tree is unsafe"
        );
        assert_eq!(
            request(
                &addr,
                "PUT",
                &format!("/v1/files/{}/{outside_name}", &outside_name[..2]),
                Some(SECRET),
                outside_body,
                &[]
            )
            .0,
            403,
            "file publication must reject a symlinked storage parent"
        );
        assert!(!outside
            .join("files")
            .join(&outside_name[..2])
            .join(&outside_name)
            .exists());
        assert!(!outside.join("files").join(&outside_name[..2]).exists());
        std::fs::remove_dir_all(outside).unwrap();
    }
    let logs = stop(server);
    assert!(!logs.contains(qr["token"].as_str().unwrap()));
    assert!(!logs.contains(device_token));
    let _ = std::fs::remove_dir_all(data);

    let symlink_data = tmp_data();
    std::fs::create_dir_all(&symlink_data).unwrap();
    let target = symlink_data.join("external-auth-target");
    std::fs::write(&target, b"must-not-be-read-or-overwritten").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, symlink_data.join(".devices.json")).unwrap();
        let denied = cli(&symlink_data, &["pair", "create"]);
        assert!(
            !denied.status.success(),
            "pairing followed an auth-state symlink"
        );
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"must-not-be-read-or-overwritten"
        );
    }
    let _ = std::fs::remove_dir_all(symlink_data);

    #[cfg(unix)]
    {
        let linked_root = tmp_data();
        let root_target = tmp_data();
        std::fs::create_dir_all(&root_target).unwrap();
        std::fs::write(root_target.join("sentinel"), b"root target stays untouched").unwrap();
        std::os::unix::fs::symlink(&root_target, &linked_root).unwrap();
        let rejected = Command::new(env!("CARGO_BIN_EXE_collie-barkup"))
            .args(["pair", "create"])
            .env("BARKUP_DATA", &linked_root)
            .env("BARKUP_TOKEN", SECRET)
            .env("BARKUP_URL", "https://backup.example")
            .output()
            .unwrap();
        assert!(
            !rejected.status.success(),
            "symlinked storage roots are rejected"
        );
        assert_eq!(
            std::fs::read(root_target.join("sentinel")).unwrap(),
            b"root target stays untouched"
        );
        std::fs::remove_file(&linked_root).unwrap();
        std::fs::remove_dir_all(root_target).unwrap();

        let corrupt = tmp_data();
        std::fs::create_dir_all(&corrupt).unwrap();
        let state = corrupt.join(".devices.json");
        std::fs::write(&state, b"{invalid json").unwrap();
        let rejected = cli(&corrupt, &["pair", "create"]);
        assert!(
            !rejected.status.success(),
            "corrupt auth state must fail closed"
        );
        assert_eq!(std::fs::read(&state).unwrap(), b"{invalid json");
        assert!(!String::from_utf8_lossy(&rejected.stdout).contains(SECRET));
        assert!(!String::from_utf8_lossy(&rejected.stderr).contains(SECRET));
        std::fs::remove_dir_all(corrupt).unwrap();

        let separate_data = tmp_data();
        let separate_state = tmp_data();
        let separate = Command::new(env!("CARGO_BIN_EXE_collie-barkup"))
            .args(["pair", "create"])
            .env("BARKUP_DATA", &separate_data)
            .env("BARKUP_STATE_DIR", &separate_state)
            .env("BARKUP_TOKEN", SECRET)
            .env("BARKUP_URL", "https://backup.example")
            .output()
            .unwrap();
        assert!(separate.status.success());
        assert!(separate_state.join(".devices.json").is_file());
        assert!(!separate_data.join(".devices.json").exists());
        std::fs::remove_dir_all(separate_data).unwrap();
        std::fs::remove_dir_all(separate_state).unwrap();

        let state_target = tmp_data();
        let state_link = tmp_data();
        std::fs::create_dir_all(&state_target).unwrap();
        std::os::unix::fs::symlink(&state_target, &state_link).unwrap();
        let rejected = Command::new(env!("CARGO_BIN_EXE_collie-barkup"))
            .args(["pair", "create"])
            .env("BARKUP_DATA", tmp_data())
            .env("BARKUP_STATE_DIR", &state_link)
            .env("BARKUP_TOKEN", SECRET)
            .env("BARKUP_URL", "https://backup.example")
            .output()
            .unwrap();
        assert!(
            !rejected.status.success(),
            "symlinked auth directories are rejected"
        );
        assert!(!state_target.join(".devices.json").exists());
        std::fs::remove_file(state_link).unwrap();
        std::fs::remove_dir_all(state_target).unwrap();
    }
}
