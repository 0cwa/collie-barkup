use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, patch, post, put},
    Json, Router,
};
use cap_fs_ext::{
    DirExt, FollowSymlinks, OpenOptionsExt as CapOpenOptionsExt, OpenOptionsFollowExt,
};
use cap_std::{ambient_authority, fs::Dir as CapDir};
use clap::{Parser, Subcommand};
use rand::{distr::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::{BTreeMap, HashSet},
    env,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::Mutex,
};
use tokio_util::io::ReaderStream;

const CHUNK_MAX: u64 = 32 * 1024 * 1024;
const REQUEST_MAX: usize = 34 * 1024 * 1024;
const UPLOAD_STATE_RESERVE: u64 = 4096;
const STALE_AFTER: Duration = Duration::from_secs(7 * 24 * 60 * 60);

async fn init_layout(root: &FsPath) -> Result<(), std::io::Error> {
    let cap_root = create_cap_dir_path(root)?;
    for relative in ["SignalBackups", "SignalBackups/files", ".uploads"] {
        let path = root.join(relative);
        match cap_create_dir(&cap_root, root, &path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = rooted_dir(&cap_root, root, &path)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn open_cap_dir(path: &FsPath) -> Result<CapDir, std::io::Error> {
    if !path.is_absolute() {
        return Err(std::io::Error::other("directory path must be absolute"));
    }
    let mut dir = CapDir::open_ambient_dir("/", ambient_authority())?;
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => dir = dir.open_dir_nofollow(name)?,
            std::path::Component::CurDir => {}
            _ => return Err(std::io::Error::other("invalid absolute directory path")),
        }
    }
    Ok(dir)
}
fn create_cap_dir_path(path: &FsPath) -> Result<CapDir, std::io::Error> {
    if !path.is_absolute() {
        return Err(std::io::Error::other("directory path must be absolute"));
    }
    let mut dir = CapDir::open_ambient_dir("/", ambient_authority())?;
    for component in path.components() {
        let std::path::Component::Normal(name) = component else {
            if matches!(component, std::path::Component::RootDir) {
                continue;
            }
            if matches!(component, std::path::Component::CurDir) {
                continue;
            }
            return Err(std::io::Error::other("invalid absolute directory path"));
        };
        match dir.open_dir_nofollow(name) {
            Ok(next) => dir = next,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match create_child_dir(&dir, name) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
                dir = dir.open_dir_nofollow(name)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(dir)
}
fn absolute_configured_path(path: &FsPath) -> Result<PathBuf, std::io::Error> {
    let source = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut result = PathBuf::from("/");
    for component in source.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::Normal(name) => result.push(name),
            _ => return Err(std::io::Error::other("invalid configured directory path")),
        }
    }
    if result == FsPath::new("/") {
        return Err(std::io::Error::other(
            "configured directory cannot be the filesystem root",
        ));
    }
    Ok(result)
}
fn instance_lock(root: &CapDir) -> Result<std::fs::File, std::io::Error> {
    use fs2::FileExt;
    let mut options = cap_std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    options.mode(0o600);
    let file = root.open_with(".server.lock", &options)?.into_std();
    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.try_lock_exclusive().map_err(|_| {
        std::io::Error::other("another server is already using this data directory")
    })?;
    Ok(file)
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[derive(Parser)]
#[command(name = "collie-barkup", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Serve,
    Healthcheck,
    Pair {
        #[command(subcommand)]
        command: PairCommand,
    },
    Devices {
        #[command(subcommand)]
        command: DeviceCommand,
    },
}
#[derive(Subcommand)]
enum PairCommand {
    Create {
        #[arg(long)]
        url: Option<String>,
    },
}
#[derive(Subcommand)]
enum DeviceCommand {
    List,
    Revoke { id: String },
}

#[derive(Clone)]
struct App {
    root: PathBuf,
    cap_root: Arc<CapDir>,
    auth: Arc<Auth>,
    serial: Arc<Mutex<()>>,
    max: u64,
    retention: usize,
}
#[derive(Serialize, Deserialize, Clone, Default)]
struct AuthFile {
    devices: BTreeMap<String, String>,
    revoked: HashSet<String>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    bootstrap: BTreeMap<String, u64>,
}
struct Auth {
    static_token: Option<String>,
    state: PathBuf,
    cap_state: Arc<CapDir>,
    lock: Mutex<()>,
}
#[derive(Deserialize)]
struct StartUpload {
    name: String,
    length: u64,
}
#[derive(Deserialize)]
struct SnapshotMemberUpload {
    length: u64,
}
#[derive(Deserialize, Serialize)]
struct UploadState {
    name: String,
    length: u64,
    offset: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commit_hash: Option<String>,
}
#[derive(Deserialize)]
struct Redeem {
    token: String,
    #[serde(default)]
    label: Option<String>,
}
#[derive(Serialize)]
struct PairResponse {
    version: u8,
    device_id: String,
    token: String,
    label: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    if matches!(&cli.command, Command::Healthcheck) {
        healthcheck().await?;
        return Ok(());
    }
    let root = absolute_configured_path(&PathBuf::from(
        env::var("BARKUP_DATA").unwrap_or_else(|_| "/data".into()),
    ))?;
    init_layout(&root).await?;
    let cap_root = Arc::new(open_cap_dir(&root)?);
    let state_root = absolute_configured_path(&PathBuf::from(
        env::var("BARKUP_STATE_DIR").unwrap_or_else(|_| root.to_string_lossy().into_owned()),
    ))?;
    let cap_state = Arc::new(create_cap_dir_path(&state_root)?);
    let auth = Arc::new(Auth {
        static_token: read_token()?.map(|v| hash_bytes(&v)),
        state: state_root.join(".devices.json"),
        cap_state,
        lock: Mutex::new(()),
    });
    match cli.command {
        Command::Pair {
            command: PairCommand::Create { url },
        } => {
            let token = random(32);
            let url = url
                .or_else(|| env::var("BARKUP_URL").ok())
                .ok_or("set BARKUP_URL or pass --url")?;
            if !valid_base_url(&url) {
                return Err("pairing URL must be an HTTP(S) origin or base URL".into());
            }
            let _g = auth.lock.lock().await;
            let _file_lock = auth_file_lock(&auth)?;
            let mut a = auth_read(&auth).await?;
            prune_bootstrap(&mut a);
            let expires = unix_seconds() + 600;
            a.bootstrap.insert(hash(&token), expires);
            auth_write(&auth, &a).await?;
            println!(
                "{}",
                json!({"collie_barkup_pairing":1,"url":url,"token":token,"expires_at":format_rfc3339(expires)})
            );
        }
        Command::Devices {
            command: DeviceCommand::List,
        } => {
            let a = auth_read(&auth).await?;
            for id in a.devices.keys() {
                println!(
                    "{id}\t{}\t{}",
                    a.labels.get(id).map(String::as_str).unwrap_or(""),
                    if a.revoked.contains(id) {
                        "revoked"
                    } else {
                        "active"
                    }
                );
            }
        }
        Command::Devices {
            command: DeviceCommand::Revoke { id },
        } => {
            let _g = auth.lock.lock().await;
            let _file_lock = auth_file_lock(&auth)?;
            let mut a = auth_read(&auth).await?;
            if !a.devices.contains_key(&id) {
                return Err("unknown device id".into());
            }
            a.revoked.insert(id);
            auth_write(&auth, &a).await?;
        }
        Command::Healthcheck => {
            unreachable!("healthcheck returned before storage initialization");
        }
        Command::Serve => {
            let max = match env::var("BARKUP_MAX_BYTES") {
                Ok(value) => value
                    .parse::<u64>()
                    .map_err(|_| "BARKUP_MAX_BYTES must be a nonnegative integer")?,
                Err(env::VarError::NotPresent) => 100 * 1024 * 1024 * 1024,
                Err(_) => return Err("BARKUP_MAX_BYTES must be a nonnegative integer".into()),
            };
            let app = App {
                root: root.clone(),
                cap_root: cap_root.clone(),
                auth,
                serial: Arc::new(Mutex::new(())),
                max,
                retention: env::var("BARKUP_RETENTION")
                    .ok()
                    .and_then(|x| x.parse().ok())
                    .unwrap_or(2),
            };
            let _instance_lock = instance_lock(&cap_root)?;
            cleanup_temporary_writes(&app)?;
            let active = live_uploads(&app).await?;
            expire_stages(&app, &active)?;
            let router = routes(app);
            let bind = env::var("BARKUP_BIND").unwrap_or_else(|_| "127.0.0.1:18082".into());
            let addr: SocketAddr = bind.parse()?;
            let listener = tokio::net::TcpListener::bind(addr).await?;
            eprintln!("collie-barkup: listening on {addr}");
            axum::serve(listener, router)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
    }
    Ok(())
}
async fn healthcheck() -> Result<(), Box<dyn std::error::Error>> {
    let bind = env::var("BARKUP_BIND").unwrap_or_else(|_| "127.0.0.1:18082".into());
    let mut address: SocketAddr = bind.parse()?;
    if address.ip().is_unspecified() {
        address.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(address),
    )
    .await??;
    Ok(())
}
fn routes(app: App) -> Router {
    Router::new()
        .route("/health", get(|| async { Json(json!({"ready":true})) }))
        .route(
            "/v1/pair/redeem",
            post(redeem).layer(DefaultBodyLimit::max(1024)),
        )
        .route("/v1/files", get(inventory))
        .route("/v1/files/prune", post(prune))
        .route("/v1/files/{shard}/{name}", put(file_put).get(file_get))
        .route("/v1/uploads", post(upload_start))
        .route("/v1/uploads/{id}", patch(upload_patch).head(upload_head))
        .route("/v1/uploads/{id}/commit", post(upload_commit))
        .route("/v1/snapshots", get(snapshots))
        .route("/v1/snapshots/{ts}", post(snapshot_start))
        .route(
            "/v1/snapshots/{ts}/uploads/{member}",
            post(snapshot_member_upload_start),
        )
        .route(
            "/v1/snapshots/{ts}/{member}",
            put(snapshot_member).get(snapshot_get),
        )
        .route("/v1/snapshots/{ts}/finalize", post(snapshot_finalize))
        .layer(DefaultBodyLimit::max(REQUEST_MAX))
        .layer(middleware::from_fn_with_state(app.clone(), authorize))
        .with_state(app)
}
async fn authorize(State(app): State<App>, req: Request<Body>, next: Next) -> Response {
    let p = req.uri().path();
    if p == "/health" {
        return next.run(req).await;
    }
    if req.uri().query().is_some() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if p == "/v1/pair/redeem" {
        return no_store(next.run(req).await);
    }
    let supplied = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let Some(token) = supplied else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if let Some(expected) = &app.auth.static_token {
        if hash(token)
            .as_bytes()
            .ct_eq(expected.as_bytes())
            .unwrap_u8()
            == 1
        {
            return no_store(next.run(req).await);
        }
    }
    let digest = hash(token);
    let a = match auth_read(&app.auth).await {
        Ok(x) => x,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if a.devices.iter().any(|(id, stored)| {
        stored.as_bytes().ct_eq(digest.as_bytes()).unwrap_u8() == 1 && !a.revoked.contains(id)
    }) {
        return no_store(next.run(req).await);
    }
    StatusCode::FORBIDDEN.into_response()
}
fn no_store(mut r: Response) -> Response {
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}
async fn redeem(State(app): State<App>, Json(body): Json<Redeem>) -> Response {
    let label = match body.label.as_deref() {
        Some(value) if !valid_label(value) => return StatusCode::BAD_REQUEST.into_response(),
        Some(value) => value.to_owned(),
        None => "Android device".to_owned(),
    };
    let _g = app.auth.lock.lock().await;
    let _file_lock = match auth_file_lock(&app.auth) {
        Ok(lock) => lock,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let mut a = match auth_read(&app.auth).await {
        Ok(a) => a,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    prune_bootstrap(&mut a);
    let h = hash(&body.token);
    if !a
        .bootstrap
        .keys()
        .any(|stored| stored.as_bytes().ct_eq(h.as_bytes()).unwrap_u8() == 1)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    a.bootstrap.remove(&h);
    let id = random(12);
    let token = random(32);
    a.devices.insert(id.clone(), hash(&token));
    a.labels.insert(id.clone(), label.clone());
    if auth_write(&app.auth, &a).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    no_store(
        Json(PairResponse {
            version: 1,
            device_id: id,
            token,
            label,
        })
        .into_response(),
    )
}
async fn inventory(State(a): State<App>) -> Response {
    let _g = a.serial.lock().await;
    let mut files = BTreeMap::new();
    let base = a.root.join("SignalBackups/files");
    if walk_files(&a.cap_root, &a.root, &base, &mut files).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    no_store(Json(json!({"files":files})).into_response())
}
async fn file_put(
    State(a): State<App>,
    Path((shard, name)): Path<(String, String)>,
    body: bytes::Bytes,
) -> Response {
    if !valid_media(&shard, &name) || body.len() > CHUNK_MAX as usize {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let _g = a.serial.lock().await;
    let p = a.root.join("SignalBackups/files").join(&shard).join(&name);
    if let Err(e) = ensure_parent(&a.root, &a.cap_root, &p).await {
        let _ = e;
        return StatusCode::FORBIDDEN.into_response();
    }
    let (parent, leaf) = match rooted_parent(&a.cap_root, &a.root, &p, false) {
        Ok(x) => x,
        Err(_) => return StatusCode::FORBIDDEN.into_response(),
    };
    match parent.symlink_metadata(&leaf) {
        Ok(meta) if meta.is_file() && meta.len() == body.len() as u64 => {
            let Ok(existing) = rooted_file(&a.cap_root, &a.root, &p) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            if hash_file(existing).await.as_deref() == Some(hash_bytes(&body).as_str()) {
                return StatusCode::OK.into_response();
            }
            return StatusCode::CONFLICT.into_response();
        }
        Ok(_) => return StatusCode::CONFLICT.into_response(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    if quota(&a, body.len() as u64).await.is_err() {
        return StatusCode::INSUFFICIENT_STORAGE.into_response();
    }
    if atomic_publish(&a.cap_root, &a.root, &p, &body)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    StatusCode::CREATED.into_response()
}
async fn file_get(
    State(a): State<App>,
    Path((shard, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !valid_media(&shard, &name) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let p = a.root.join("SignalBackups/files").join(shard).join(name);
    let Ok(file) = rooted_file(&a.cap_root, &a.root, &p) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !file.metadata().await.map(|m| m.is_file()).unwrap_or(false) {
        return StatusCode::NOT_FOUND.into_response();
    }
    streamed_file(file, &headers).await
}
async fn streamed_file(mut file: fs::File, headers: &HeaderMap) -> Response {
    let Ok(length) = file.metadata().await.map(|m| m.len()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let range = match headers.get(header::RANGE) {
        None => None,
        Some(value) => match value
            .to_str()
            .ok()
            .and_then(|value| parse_range(value, usize::try_from(length).ok()?))
        {
            Some(bounds) => Some(bounds),
            None => {
                let mut r = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
                r.headers_mut().insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes */{length}")).unwrap(),
                );
                r.headers_mut()
                    .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
                return no_store(r);
            }
        },
    };
    let (start, count, status, content_range) = if let Some((start, end)) = range {
        (
            start as u64,
            (end - start + 1) as u64,
            StatusCode::PARTIAL_CONTENT,
            Some(format!("bytes {start}-{end}/{length}")),
        )
    } else {
        (0, length, StatusCode::OK, None)
    };
    if file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let reader = file.take(count);
    let mut r = Response::new(Body::from_stream(ReaderStream::new(reader)));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&count.to_string()).unwrap(),
    );
    r.headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Some(value) = content_range {
        r.headers_mut().insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&value).unwrap(),
        );
    }
    no_store(r)
}
async fn upload_start(State(a): State<App>, Json(req): Json<StartUpload>) -> Response {
    if !valid_filename(&req.name) || req.length == 0 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let _g = a.serial.lock().await;
    create_upload(&a, req.name, req.length, None).await
}

async fn snapshot_member_upload_start(
    State(a): State<App>,
    Path((ts, member)): Path<(String, String)>,
    Json(req): Json<SnapshotMemberUpload>,
) -> Response {
    if !valid_ts(&ts)
        || !matches!(member.as_str(), "metadata" | "main" | "files")
        || req.length == 0
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let _g = a.serial.lock().await;
    if rooted_dir(&a.cap_root, &a.root, &stage_path(&a.root, &ts)).is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !snapshot_member_available(&a, &ts, &member).await {
        return StatusCode::CONFLICT.into_response();
    }
    create_upload(&a, member, req.length, Some(ts)).await
}

async fn snapshot_member_available(a: &App, ts: &str, member: &str) -> bool {
    live_uploads(a).await.is_ok_and(|active| {
        !active
            .iter()
            .any(|upload| upload.snapshot.as_deref() == Some(ts) && upload.name == member)
    })
}

async fn create_upload(a: &App, name: String, length: u64, snapshot: Option<String>) -> Response {
    let Some(reserved) = length.checked_add(UPLOAD_STATE_RESERVE) else {
        return StatusCode::INSUFFICIENT_STORAGE.into_response();
    };
    if quota(a, reserved).await.is_err() {
        return StatusCode::INSUFFICIENT_STORAGE.into_response();
    }
    let id = random(16);
    let dir = a.root.join(".uploads").join(&id);
    if cap_create_dir(&a.cap_root, &a.root, &dir).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let state = UploadState {
        name,
        length,
        offset: 0,
        snapshot,
        commit_hash: None,
    };
    if save_upload_state(a, &dir, &state).await.is_err() {
        let _ = retire_dir(a, &dir);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        StatusCode::CREATED,
        Json(json!({"id":id,"offset":0,"chunk_max":CHUNK_MAX})),
    )
        .into_response()
}

async fn save_upload_state(a: &App, dir: &FsPath, state: &UploadState) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(state).map_err(std::io::Error::other)?;
    if bytes.len() as u64 > UPLOAD_STATE_RESERVE / 2 {
        return Err(std::io::Error::other("upload state exceeds reservation"));
    }
    atomic_replace(&a.cap_root, &a.root, &dir.join("state.json"), &bytes).await
}

async fn read_upload_state(file: fs::File) -> std::io::Result<UploadState> {
    let mut bytes = Vec::new();
    file.take(UPLOAD_STATE_RESERVE / 2 + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > UPLOAD_STATE_RESERVE / 2 {
        return Err(std::io::Error::other("oversize upload state"));
    }
    decode_upload_state(&bytes)
}

fn decode_upload_state(bytes: &[u8]) -> std::io::Result<UploadState> {
    let state: UploadState = serde_json::from_slice(bytes).map_err(std::io::Error::other)?;
    let target_valid = match &state.snapshot {
        Some(ts) => valid_ts(ts) && matches!(state.name.as_str(), "metadata" | "main" | "files"),
        None => valid_filename(&state.name),
    };
    if !target_valid
        || state.length == 0
        || state.offset > state.length
        || state
            .commit_hash
            .as_deref()
            .is_some_and(|digest| !valid_hash(digest) || state.offset != state.length)
    {
        return Err(std::io::Error::other("invalid upload state"));
    }
    Ok(state)
}

async fn upload_head(State(a): State<App>, Path(id): Path<String>) -> Response {
    if !valid_id(&id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let state_path = a.root.join(".uploads").join(id).join("state.json");
    let Ok(file) = rooted_file(&a.cap_root, &a.root, &state_path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(state) = read_upload_state(file).await else {
        return StatusCode::CONFLICT.into_response();
    };
    (
        StatusCode::NO_CONTENT,
        [("upload-offset", state.offset.to_string())],
    )
        .into_response()
}

async fn upload_patch(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: bytes::Bytes,
) -> Response {
    if !valid_id(&id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if body.is_empty() || body.len() as u64 > CHUNK_MAX {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let Some(offset) = headers
        .get("upload-offset")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let _g = a.serial.lock().await;
    let dir = a.root.join(".uploads").join(id);
    let Ok(state_file) = rooted_file(&a.cap_root, &a.root, &dir.join("state.json")) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(mut state) = read_upload_state(state_file).await else {
        return StatusCode::CONFLICT.into_response();
    };
    let Some(end) = offset.checked_add(body.len() as u64) else {
        return StatusCode::CONFLICT.into_response();
    };
    if state.offset != offset || end > state.length {
        return StatusCode::CONFLICT.into_response();
    }
    let (parent, leaf) = match rooted_parent(&a.cap_root, &a.root, &dir.join("data"), false) {
        Ok(x) => x,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let exists = match parent.symlink_metadata(&leaf) {
        Ok(m) if m.is_file() => true,
        Ok(_) => return StatusCode::CONFLICT.into_response(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let mut options = cap_std::fs::OpenOptions::new();
    options
        .create(offset == 0)
        .truncate(false)
        .read(true)
        .write(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    options.mode(0o600);
    let Ok(mut f) = parent
        .open_with(&leaf, &options)
        .map(|f| fs::File::from_std(f.into_std()))
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(actual) = f.metadata().await.map(|m| m.len()) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if (!exists && offset != 0) || actual < offset {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    // Discard bytes synced before a crash if their offset was never committed.
    if (actual > offset && f.set_len(offset).await.is_err())
        || f.seek(std::io::SeekFrom::Start(offset)).await.is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if f.write_all(&body).await.is_err() || f.sync_all().await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if f.metadata().await.map(|m| m.len()).ok() != Some(end) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    state.offset = end;
    if save_upload_state(&a, &dir, &state).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        StatusCode::NO_CONTENT,
        [("upload-offset", state.offset.to_string())],
    )
        .into_response()
}

async fn upload_commit(State(a): State<App>, Path(id): Path<String>) -> Response {
    if !valid_id(&id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let _g = a.serial.lock().await;
    let dir = a.root.join(".uploads").join(id);
    let data = dir.join("data");
    let Ok(state_file) = rooted_file(&a.cap_root, &a.root, &dir.join("state.json")) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(mut state) = read_upload_state(state_file).await else {
        return StatusCode::CONFLICT.into_response();
    };
    if state.offset != state.length {
        return StatusCode::CONFLICT.into_response();
    }
    let dest = match &state.snapshot {
        Some(ts) => {
            let stage = stage_path(&a.root, ts);
            if rooted_dir(&a.cap_root, &a.root, &stage).is_err() {
                return StatusCode::NOT_FOUND.into_response();
            }
            stage.join(&state.name)
        }
        None => a
            .root
            .join("SignalBackups/files")
            .join(&state.name[..2])
            .join(&state.name),
    };
    let (dest_parent, dest_leaf) = match rooted_parent(&a.cap_root, &a.root, &dest, true) {
        Ok(x) => x,
        Err(_) => return StatusCode::FORBIDDEN.into_response(),
    };
    let data_file = match rooted_file(&a.cap_root, &a.root, &data) {
        Ok(f) => f,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let Some(expected) = &state.commit_hash else {
                return StatusCode::CONFLICT.into_response();
            };
            // The first attempt may have renamed the bytes but lost the response.
            if !published_upload_matches(&a, &dest, state.length, expected).await {
                return StatusCode::CONFLICT.into_response();
            }
            if sync_dir(&dest_parent).is_err() {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            return complete_upload(&a, &dir, StatusCode::OK);
        }
        Err(_) => return StatusCode::CONFLICT.into_response(),
    };
    if !regular_file_with_length(&data_file, state.length).await {
        return StatusCode::CONFLICT.into_response();
    }
    if state.snapshot.is_some()
        && state.name == "files"
        && validate_manifest_file(&a.cap_root, &a.root, &data, None, None)
            .await
            .is_err()
    {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }
    let Some(digest) = hash_file(data_file).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if state.snapshot.is_none() {
        match dest_parent.symlink_metadata(&dest_leaf) {
            Ok(_) => {
                if published_upload_matches(&a, &dest, state.length, &digest).await {
                    return complete_upload(&a, &dir, StatusCode::OK);
                }
                return StatusCode::CONFLICT.into_response();
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
    // Persist the expected ciphertext digest and target before publication.
    state.commit_hash = Some(digest);
    if save_upload_state(&a, &dir, &state).await.is_err()
        || cap_rename(&a.cap_root, &a.root, &data, &dest, state.snapshot.is_some()).is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    complete_upload(&a, &dir, StatusCode::CREATED)
}

async fn regular_file_with_length(file: &fs::File, length: u64) -> bool {
    file.metadata()
        .await
        .is_ok_and(|metadata| metadata.is_file() && metadata.len() == length)
}

async fn published_upload_matches(a: &App, dest: &FsPath, length: u64, digest: &str) -> bool {
    let Ok(file) = rooted_file(&a.cap_root, &a.root, dest) else {
        return false;
    };
    regular_file_with_length(&file, length).await
        && hash_file(file).await.as_deref() == Some(digest)
}

fn complete_upload(a: &App, dir: &FsPath, status: StatusCode) -> Response {
    match retire_dir(a, dir) {
        Ok(()) => status.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
async fn snapshots(State(a): State<App>) -> Response {
    let base = a.root.join("SignalBackups");
    let mut v = Vec::new();
    let Ok(dir) = rooted_dir(&a.cap_root, &a.root, &base) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(entries) = dir.entries() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    for e in entries {
        let Ok(e) = e else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        let Ok(kind) = e.file_type() else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        if kind.is_symlink() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        let n = e.file_name().to_string_lossy().into_owned();
        if n.strip_prefix("signal-backup-").is_some_and(valid_ts) {
            if kind.is_dir() {
                v.push(n);
            } else {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }
    v.sort_by(|x, y| y.cmp(x));
    no_store(Json(json!(v)).into_response())
}
async fn snapshot_start(State(a): State<App>, Path(ts): Path<String>) -> Response {
    if !valid_ts(&ts) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let _g = a.serial.lock().await;
    let target = a
        .root
        .join("SignalBackups")
        .join(format!("signal-backup-{ts}"));
    match rooted_dir(&a.cap_root, &a.root, &target) {
        Ok(_) => return StatusCode::CONFLICT.into_response(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return StatusCode::CONFLICT.into_response(),
    }
    let p = stage_path(&a.root, &ts);
    if cap_create_dir(&a.cap_root, &a.root, &p).is_err() {
        return StatusCode::CONFLICT.into_response();
    }
    no_store(StatusCode::CREATED.into_response())
}
async fn snapshot_member(
    State(a): State<App>,
    Path((ts, member)): Path<(String, String)>,
    body: bytes::Bytes,
) -> Response {
    if !valid_ts(&ts)
        || !matches!(member.as_str(), "metadata" | "main" | "files")
        || body.len() > REQUEST_MAX
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if member == "files" && validate_manifest(&body).is_err() {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }
    let _g = a.serial.lock().await;
    let stage = stage_path(&a.root, &ts);
    if rooted_dir(&a.cap_root, &a.root, &stage).is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !snapshot_member_available(&a, &ts, &member).await {
        return StatusCode::CONFLICT.into_response();
    }
    let p = stage_path(&a.root, &ts).join(&member);
    if ensure_parent(&a.root, &a.cap_root, &p).await.is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    if quota(&a, body.len() as u64).await.is_err() {
        return StatusCode::INSUFFICIENT_STORAGE.into_response();
    }
    if atomic_replace(&a.cap_root, &a.root, &p, &body)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    no_store(StatusCode::NO_CONTENT.into_response())
}
async fn snapshot_get(
    State(a): State<App>,
    Path((ts, member)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !valid_ts(&ts) || !matches!(member.as_str(), "metadata" | "main" | "files") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let p = a
        .root
        .join("SignalBackups")
        .join(format!("signal-backup-{ts}"))
        .join(member);
    let Ok(file) = rooted_file(&a.cap_root, &a.root, &p) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    streamed_file(file, &headers).await
}
async fn snapshot_finalize(State(a): State<App>, Path(ts): Path<String>) -> Response {
    if !valid_ts(&ts) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let _g = a.serial.lock().await;
    let active = match live_uploads(&a).await {
        Ok(active) => active,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if active
        .iter()
        .any(|upload| upload.snapshot.as_deref() == Some(ts.as_str()))
    {
        return StatusCode::CONFLICT.into_response();
    }
    let stage = stage_path(&a.root, &ts);
    let target = a
        .root
        .join("SignalBackups")
        .join(format!("signal-backup-{ts}"));
    match rooted_dir(&a.cap_root, &a.root, &stage) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if validate_snapshot_members(&a, &target).await.is_err() {
                return StatusCode::CONFLICT.into_response();
            }
            return match apply_retention(&a) {
                Ok(()) => no_store(StatusCode::OK.into_response()),
                Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    match rooted_dir(&a.cap_root, &a.root, &target) {
        Ok(_) => return StatusCode::CONFLICT.into_response(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return StatusCode::CONFLICT.into_response(),
    }
    if validate_snapshot_members(&a, &stage).await.is_err() {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }
    if cap_rename(&a.cap_root, &a.root, &stage, &target, false).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    match apply_retention(&a) {
        Ok(()) => no_store(StatusCode::CREATED.into_response()),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
async fn validate_snapshot_members(a: &App, dir: &FsPath) -> Result<(), ()> {
    for member in ["metadata", "main", "files"] {
        let file = rooted_file(&a.cap_root, &a.root, &dir.join(member)).map_err(|_| ())?;
        if !file
            .metadata()
            .await
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
        {
            return Err(());
        }
    }
    validate_manifest_file(
        &a.cap_root,
        &a.root,
        &dir.join("files"),
        Some(&a.root.join("SignalBackups/files")),
        None,
    )
    .await
    .map_err(|_| ())
}
fn apply_retention(a: &App) -> Result<(), std::io::Error> {
    let mut all = Vec::new();
    let snapshots_root = rooted_dir(&a.cap_root, &a.root, &a.root.join("SignalBackups"))?;
    let entries = snapshots_root.entries()?;
    for entry in entries {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return Err(std::io::Error::other("symlink snapshot entry rejected"));
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.strip_prefix("signal-backup-").is_some_and(valid_ts) {
            if !kind.is_dir() {
                return Err(std::io::Error::other("invalid snapshot entry"));
            }
            all.push(name);
        }
    }
    all.sort();
    while all.len() > a.retention.max(1) {
        let oldest = all.remove(0);
        retire_dir(a, &a.root.join("SignalBackups").join(oldest))?;
    }
    Ok(())
}
async fn prune(State(a): State<App>) -> Response {
    let _g = a.serial.lock().await;
    let active = match live_uploads(&a).await {
        Ok(active) => active,
        Err(_) => return StatusCode::CONFLICT.into_response(),
    };
    if expire_stages(&a, &active).is_err()
        || !active.is_empty()
        || has_active_stages(&a.cap_root, &a.root)
    {
        return StatusCode::CONFLICT.into_response();
    }
    let base = a.root.join("SignalBackups/files");
    let mut candidates = BTreeMap::new();
    if walk_files(&a.cap_root, &a.root, &base, &mut candidates).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let signal_backups = a.root.join("SignalBackups");
    let snapshots_dir = match rooted_dir(&a.cap_root, &a.root, &signal_backups) {
        Ok(dir) => dir,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let entries = match snapshots_dir.entries() {
        Ok(entries) => entries,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    for e in entries {
        let e = match e {
            Ok(e) => e,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        let kind = match e.file_type() {
            Ok(t) => t,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        if kind.is_symlink() {
            return StatusCode::CONFLICT.into_response();
        }
        let is_snapshot = e
            .file_name()
            .to_string_lossy()
            .strip_prefix("signal-backup-")
            .is_some_and(valid_ts);
        if is_snapshot {
            if !kind.is_dir() {
                return StatusCode::CONFLICT.into_response();
            }
            let manifest = signal_backups.join(e.file_name()).join("files");
            if validate_manifest_file(&a.cap_root, &a.root, &manifest, None, Some(&mut candidates))
                .await
                .is_err()
            {
                return StatusCode::CONFLICT.into_response();
            }
        }
    }
    let mut removed = 0u64;
    for (n, size) in candidates {
        let p = base.join(&n[..2]).join(&n);
        if cap_remove_file(&a.cap_root, &a.root, &p).is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        removed += size;
    }
    no_store(Json(json!({"removed_bytes":removed})).into_response())
}
fn read_token() -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let value = if let Ok(p) = env::var("BARKUP_TOKEN_FILE") {
        let path = absolute_configured_path(FsPath::new(&p))?;
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("token file parent is missing"))?;
        let leaf = path
            .file_name()
            .ok_or_else(|| std::io::Error::other("token file name is missing"))?;
        let cap_parent = open_cap_dir(parent)?;
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let file = cap_parent.open_with(leaf, &options)?.into_std();
        if !file.metadata()?.is_file() {
            return Err("BARKUP_TOKEN_FILE must name a regular file".into());
        }
        use std::io::Read;
        let mut bytes = Vec::new();
        file.take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err("BARKUP_TOKEN_FILE is too large".into());
        }
        Some(String::from_utf8(bytes)?.trim().to_owned())
    } else {
        env::var("BARKUP_TOKEN").ok()
    };
    if value
        .as_ref()
        .is_some_and(|token| token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()))
    {
        return Err("BARKUP_TOKEN must be non-empty printable ASCII without spaces".into());
    }
    Ok(value.map(String::into_bytes))
}
async fn auth_read(a: &Auth) -> Result<AuthFile, std::io::Error> {
    let leaf = a
        .state
        .file_name()
        .ok_or_else(|| std::io::Error::other("auth state name missing"))?;
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    match a
        .cap_state
        .open_with(leaf, &options)
        .map(|f| {
            use std::io::Read;
            let mut bytes = Vec::new();
            f.into_std().take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
            Ok::<_, std::io::Error>(bytes)
        })
        .and_then(|result| result)
    {
        Ok(b) => {
            if b.len() > 1024 * 1024 {
                return Err(std::io::Error::other("invalid auth state"));
            }
            let state: AuthFile = serde_json::from_slice(&b)
                .map_err(|_| std::io::Error::other("invalid auth state"))?;
            if state.devices.values().any(|h| !valid_hash(h))
                || state.bootstrap.iter().any(|(h, _)| !valid_hash(h))
                || state
                    .devices
                    .keys()
                    .any(|id| id.len() != 12 || !id.bytes().all(|b| b.is_ascii_alphanumeric()))
                || state
                    .revoked
                    .iter()
                    .any(|id| !state.devices.contains_key(id))
                || state
                    .labels
                    .iter()
                    .any(|(id, label)| !state.devices.contains_key(id) || !valid_label(label))
            {
                return Err(std::io::Error::other("invalid auth state"));
            }
            Ok(state)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(AuthFile::default()),
        Err(e) => Err(e),
    }
}
fn auth_file_lock(a: &Auth) -> Result<std::fs::File, std::io::Error> {
    use fs2::FileExt;
    let mut options = cap_std::fs::OpenOptions::new();
    options
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    options.mode(0o600);
    let leaf = a
        .state
        .file_name()
        .ok_or_else(|| std::io::Error::other("auth state name missing"))?;
    let file = a
        .cap_state
        .open_with(format!("{}.lock", leaf.to_string_lossy()), &options)?
        .into_std();
    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.lock_exclusive()?;
    Ok(file)
}
async fn auth_write(a: &Auth, state: &AuthFile) -> Result<(), std::io::Error> {
    let bytes = serde_json::to_vec(state).map_err(std::io::Error::other)?;
    if bytes.len() > 1024 * 1024 {
        return Err(std::io::Error::other("auth state is too large"));
    }
    for _ in 0..8 {
        let tmp = format!(".devices-{}.tmp", random(24));
        let mut options = cap_std::fs::OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        options.mode(0o600);
        let file = match a.cap_state.open_with(&tmp, &options) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        let result = (|| {
            use std::io::Write;
            let mut file = file.into_std();
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            let leaf = a
                .state
                .file_name()
                .ok_or_else(|| std::io::Error::other("auth state name missing"))?;
            match a.cap_state.symlink_metadata(leaf) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(std::io::Error::other("auth state symlink rejected"));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            a.cap_state.rename(&tmp, &a.cap_state, leaf)?;
            a.cap_state.open(".")?.into_std().sync_all()?;
            Ok::<(), std::io::Error>(())
        })();
        if result.is_err() {
            let _ = a.cap_state.remove_file(&tmp);
        }
        return result;
    }
    Err(std::io::Error::other("could not allocate auth temp file"))
}
fn random(n: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(n)
        .map(char::from)
        .collect()
}
fn hash(v: &str) -> String {
    hash_bytes(v.as_bytes())
}
fn hash_bytes(v: &[u8]) -> String {
    format!("{:x}", Sha256::digest(v))
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" _.-".contains(&b))
}
fn valid_base_url(value: &str) -> bool {
    if value.contains(['?', '#', '@']) || value.bytes().any(|b| b.is_ascii_whitespace()) {
        return false;
    }
    let Ok(uri) = value.parse::<http::Uri>() else {
        return false;
    };
    matches!(uri.scheme_str(), Some("http" | "https"))
        && uri
            .authority()
            .is_some_and(|a| !a.as_str().is_empty() && !a.as_str().contains('@'))
        && uri
            .path_and_query()
            .is_some_and(|p| !p.as_str().contains('?'))
}
fn format_rfc3339(timestamp: u64) -> String {
    let days = (timestamp / 86_400) as i64;
    let day_seconds = timestamp % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        day_seconds / 3600,
        day_seconds % 3600 / 60,
        day_seconds % 60
    )
}
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn prune_bootstrap(a: &mut AuthFile) {
    let now = unix_seconds();
    a.bootstrap.retain(|_, expires| *expires > now);
}
fn valid_ts(s: &str) -> bool {
    if s.len() != 19
        || !s.bytes().enumerate().all(|(i, b)| {
            if [4, 7, 10, 13, 16].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
    {
        return false;
    }
    let part = |range: std::ops::Range<usize>| s[range].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        part(0..4),
        part(5..7),
        part(8..10),
        part(11..13),
        part(14..16),
        part(17..19),
    ) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    year != 0 && (1..=days).contains(&day) && hour < 24 && minute < 60 && second < 60
}
fn valid_filename(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_id(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| b.is_ascii_alphanumeric())
}
fn valid_shard(shard: &str) -> bool {
    shard.len() == 2
        && shard
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_media(shard: &str, name: &str) -> bool {
    valid_filename(name) && valid_shard(shard) && name.starts_with(shard)
}
fn parse_range(value: &str, length: usize) -> Option<(usize, usize)> {
    let value = value.strip_prefix("bytes=")?;
    if value.contains(',') || length == 0 {
        return None;
    }
    let (start, end) = value.split_once('-')?;
    let (start, end) = if start.is_empty() {
        let suffix = end.parse::<usize>().ok()?;
        if suffix == 0 {
            return None;
        }
        (length.saturating_sub(suffix), length - 1)
    } else {
        let start = start.parse::<usize>().ok()?;
        let end = if end.is_empty() {
            length - 1
        } else {
            end.parse::<usize>().ok()?.min(length - 1)
        };
        (start, end)
    };
    (start <= end && start < length).then_some((start, end))
}
async fn ensure_parent(root: &FsPath, cap: &CapDir, p: &FsPath) -> Result<(), std::io::Error> {
    let _ = rooted_parent(cap, root, p, true)?;
    Ok(())
}
fn rooted_parent(
    root: &CapDir,
    root_path: &FsPath,
    path: &FsPath,
    create: bool,
) -> Result<(CapDir, std::ffi::OsString), std::io::Error> {
    let relative = path
        .strip_prefix(root_path)
        .map_err(|_| std::io::Error::other("path escapes storage root"))?;
    let mut parts = relative
        .components()
        .map(|c| match c {
            std::path::Component::Normal(n) => Ok(n.to_os_string()),
            _ => Err(std::io::Error::other("invalid rooted path")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = parts
        .pop()
        .ok_or_else(|| std::io::Error::other("missing file name"))?;
    let mut dir = root.try_clone()?;
    for part in parts {
        match dir.open_dir_nofollow(&part) {
            Ok(next) => dir = next,
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                match create_child_dir(&dir, &part) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
                dir = dir.open_dir_nofollow(&part)?;
            }
            Err(error) => return Err(error),
        }
    }
    match dir.symlink_metadata(&leaf) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(std::io::Error::other("symlink leaf rejected"))
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok((dir, leaf))
}
fn rooted_dir(root: &CapDir, root_path: &FsPath, path: &FsPath) -> Result<CapDir, std::io::Error> {
    let relative = path
        .strip_prefix(root_path)
        .map_err(|_| std::io::Error::other("path escapes storage root"))?;
    let mut dir = root.try_clone()?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(std::io::Error::other("invalid rooted directory path"));
        };
        dir = dir.open_dir_nofollow(name)?;
    }
    Ok(dir)
}
fn cap_create_dir(root: &CapDir, root_path: &FsPath, path: &FsPath) -> Result<(), std::io::Error> {
    let (parent, leaf) = rooted_parent(root, root_path, path, true)?;
    create_child_dir(&parent, &leaf)
}
fn create_child_dir(parent: &CapDir, leaf: &std::ffi::OsStr) -> Result<(), std::io::Error> {
    parent.create_dir(leaf)?;
    if let Err(error) = sync_dir(parent) {
        let _ = parent.remove_dir(leaf);
        return Err(error);
    }
    Ok(())
}
fn sync_dir(dir: &CapDir) -> std::io::Result<()> {
    dir.open(".")?.into_std().sync_all()
}
fn cap_rename(
    root: &CapDir,
    root_path: &FsPath,
    from: &FsPath,
    to: &FsPath,
    replace: bool,
) -> Result<(), std::io::Error> {
    let (from_parent, from_leaf) = rooted_parent(root, root_path, from, false)?;
    let (to_parent, to_leaf) = rooted_parent(root, root_path, to, true)?;
    if !replace && to_parent.try_exists(&to_leaf)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "destination exists",
        ));
    }
    from_parent.rename(from_leaf, &to_parent, to_leaf)?;
    sync_dir(&from_parent)?;
    sync_dir(&to_parent)?;
    Ok(())
}
fn cap_remove_dir_all(
    root: &CapDir,
    root_path: &FsPath,
    path: &FsPath,
) -> Result<(), std::io::Error> {
    let (parent, leaf) = rooted_parent(root, root_path, path, false)?;
    parent.remove_dir_all(leaf)
}
fn cap_remove_file(root: &CapDir, root_path: &FsPath, path: &FsPath) -> Result<(), std::io::Error> {
    let (parent, leaf) = rooted_parent(root, root_path, path, false)?;
    parent.remove_file(leaf)
}
fn rooted_file(
    root: &CapDir,
    root_path: &FsPath,
    path: &FsPath,
) -> Result<tokio::fs::File, std::io::Error> {
    let (parent, leaf) = rooted_parent(root, root_path, path, false)?;
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = parent.open_with(leaf, &options)?.into_std();
    Ok(tokio::fs::File::from_std(file))
}
async fn atomic_publish(
    root: &CapDir,
    root_path: &FsPath,
    dest: &FsPath,
    bytes: &[u8],
) -> Result<(), std::io::Error> {
    atomic_write_rooted(root, root_path, dest, bytes, false)
}
async fn hash_file(mut file: fs::File) -> Option<String> {
    let mut digest = Sha256::new();
    let mut buffer = vec![0; 128 * 1024];
    loop {
        let n = file.read(&mut buffer).await.ok()?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    Some(format!("{:x}", digest.finalize()))
}
async fn atomic_replace(
    root: &CapDir,
    root_path: &FsPath,
    dest: &FsPath,
    bytes: &[u8],
) -> Result<(), std::io::Error> {
    atomic_write_rooted(root, root_path, dest, bytes, true)
}
fn atomic_write_rooted(
    root: &CapDir,
    root_path: &FsPath,
    dest: &FsPath,
    bytes: &[u8],
    replace: bool,
) -> Result<(), std::io::Error> {
    let (parent, leaf) = rooted_parent(root, root_path, dest, true)?;
    if !replace && parent.try_exists(&leaf)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "destination exists",
        ));
    }
    for _ in 0..8 {
        let temp = format!(".barkup-{}.tmp", random(24));
        let mut options = cap_std::fs::OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        options.mode(0o600);
        let file = match parent.open_with(&temp, &options) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let mut file = file.into_std();
        use std::io::Write;
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            if !replace && parent.try_exists(&leaf)? {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "destination exists",
                ));
            }
            parent.rename(&temp, &parent, &leaf)?;
            parent.open(".")?.into_std().sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = parent.remove_file(&temp);
        }
        return result;
    }
    Err(std::io::Error::other("could not allocate temporary file"))
}
async fn quota(a: &App, add: u64) -> Result<(), ()> {
    live_uploads(a).await.map_err(|_| ())?;
    let mut sum = 0u64;
    let mut todo = vec![(a.cap_root.try_clone().map_err(|_| ())?, PathBuf::new())];
    while let Some((dir, rel)) = todo.pop() {
        for entry in dir.entries().map_err(|_| ())? {
            let entry = entry.map_err(|_| ())?;
            let name = entry.file_name();
            let kind = entry.file_type().map_err(|_| ())?;
            if kind.is_symlink() {
                return Err(());
            }
            let entry_rel = rel.join(&name);
            if kind.is_dir() {
                todo.push((dir.open_dir_nofollow(&name).map_err(|_| ())?, entry_rel));
            } else {
                let size = entry.metadata().map_err(|_| ())?.len();
                sum = sum.saturating_add(size);
                if entry_rel.file_name().is_some_and(|n| n == "state.json")
                    && entry_rel
                        .parent()
                        .and_then(FsPath::file_name)
                        .and_then(|n| n.to_str())
                        .is_some_and(valid_id)
                    && entry_rel
                        .parent()
                        .and_then(FsPath::parent)
                        .and_then(FsPath::file_name)
                        .is_some_and(|n| n == ".uploads")
                {
                    let mut options = cap_std::fs::OpenOptions::new();
                    options.read(true).follow(FollowSymlinks::No);
                    let file = entry.open_with(&options).map_err(|_| ())?.into_std();
                    use std::io::Read;
                    let mut bytes = Vec::new();
                    file.take(UPLOAD_STATE_RESERVE / 2 + 1)
                        .read_to_end(&mut bytes)
                        .map_err(|_| ())?;
                    if bytes.len() as u64 > UPLOAD_STATE_RESERVE / 2 {
                        return Err(());
                    }
                    let state = decode_upload_state(&bytes).map_err(|_| ())?;
                    sum = sum.checked_add(state.length - state.offset).ok_or(())?;
                    sum = sum
                        .checked_add(UPLOAD_STATE_RESERVE.checked_sub(size).ok_or(())?)
                        .ok_or(())?;
                }
            }
        }
    }
    if sum.saturating_add(add) > a.max {
        Err(())
    } else {
        Ok(())
    }
}
fn walk_files(
    root: &CapDir,
    root_path: &FsPath,
    base: &FsPath,
    out: &mut BTreeMap<String, u64>,
) -> Result<(), std::io::Error> {
    let base_dir = rooted_dir(root, root_path, base)?;
    for shard_entry in base_dir.entries()? {
        let shard_entry = shard_entry?;
        let kind = shard_entry.file_type()?;
        if kind.is_symlink() || !kind.is_dir() {
            return Err(std::io::Error::other("invalid media shard entry"));
        }
        let shard = shard_entry.file_name().to_string_lossy().into_owned();
        if shard.len() != 2
            || !shard
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(std::io::Error::other("invalid media shard"));
        }
        let shard_dir = base_dir.open_dir_nofollow(&shard)?;
        for file_entry in shard_dir.entries()? {
            let file_entry = file_entry?;
            let name = file_entry.file_name().to_string_lossy().into_owned();
            let file_kind = file_entry.file_type()?;
            if file_kind.is_symlink() || !file_kind.is_file() || !valid_media(&shard, &name) {
                return Err(std::io::Error::other("invalid media entry"));
            }
            out.insert(name, file_entry.metadata()?.len());
        }
    }
    Ok(())
}
fn retire_dir(a: &App, path: &FsPath) -> std::io::Result<()> {
    let tombstone = path.with_file_name(format!(".barkup-retired-{}", random(24)));
    // Sync the namespace change before deleting any descendants.
    cap_rename(&a.cap_root, &a.root, path, &tombstone, false)?;
    let _ = cap_remove_dir_all(&a.cap_root, &a.root, &tombstone);
    Ok(())
}

fn retired_dir_name(name: &str) -> bool {
    name.strip_prefix(".barkup-retired-")
        .is_some_and(|id| id.len() == 24 && id.bytes().all(|b| b.is_ascii_alphanumeric()))
}

fn stale(entry: &cap_std::fs::DirEntry) -> std::io::Result<bool> {
    let modified = entry.metadata()?.modified()?.into_std();
    Ok(modified.elapsed().is_ok_and(|age| age > STALE_AFTER))
}

async fn live_uploads(a: &App) -> std::io::Result<Vec<UploadState>> {
    let uploads = a.root.join(".uploads");
    let uploads_dir = rooted_dir(&a.cap_root, &a.root, &uploads)?;
    let mut active = Vec::new();
    let entries = uploads_dir
        .entries()?
        .collect::<std::io::Result<Vec<_>>>()?;
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = uploads.join(&name);
        if !entry.file_type()?.is_dir() {
            return Err(std::io::Error::other("invalid upload directory entry"));
        }
        if retired_dir_name(&name) {
            // The previous rename may have succeeded before its sync failed.
            sync_dir(&uploads_dir)?;
            let _ = uploads_dir.remove_dir_all(&name);
        } else if !valid_id(&name) {
            return Err(std::io::Error::other("invalid upload session directory"));
        } else if stale(&entry)? {
            retire_dir(a, &path)?;
        } else {
            match rooted_file(&a.cap_root, &a.root, &path.join("state.json")) {
                Ok(state_file) => active.push(read_upload_state(state_file).await?),
                // A crash before saving the initial state leaves no usable session.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => retire_dir(a, &path)?,
                Err(error) => return Err(error),
            }
        }
    }
    Ok(active)
}

fn expire_stages(a: &App, active: &[UploadState]) -> std::io::Result<()> {
    let backup_path = a.root.join("SignalBackups");
    let backups = rooted_dir(&a.cap_root, &a.root, &backup_path)?;
    let entries = backups.entries()?.collect::<std::io::Result<Vec<_>>>()?;
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return Err(std::io::Error::other("symlink snapshot entry rejected"));
        }
        if !kind.is_dir() {
            continue;
        }
        let path = backup_path.join(&name);
        if retired_dir_name(&name) {
            // Keep prune closed until retirement is durable.
            sync_dir(&backups)?;
            let _ = backups.remove_dir_all(&name);
        } else if let Some(ts) = stage_timestamp(&name) {
            if !active
                .iter()
                .any(|upload| upload.snapshot.as_deref() == Some(ts))
                && stale(&entry)?
            {
                retire_dir(a, &path)?;
            }
        }
    }
    Ok(())
}

fn cleanup_temporary_writes(a: &App) -> std::io::Result<()> {
    for (directory, eligible) in [
        ("SignalBackups/files", valid_shard as fn(&str) -> bool),
        (".uploads", valid_id),
        ("SignalBackups", |name| stage_timestamp(name).is_some()),
    ] {
        let parent = rooted_dir(&a.cap_root, &a.root, &a.root.join(directory))?;
        for entry in parent.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_str().is_some_and(eligible)
                && entry.file_type()?.is_dir()
                && (directory == "SignalBackups/files" || !stale(&entry)?)
            {
                remove_temporary_writes(&parent.open_dir_nofollow(name)?)?;
            }
        }
    }
    Ok(())
}

fn stage_timestamp(name: &str) -> Option<&str> {
    name.strip_prefix("signal-backup-")?
        .strip_suffix("-tmp")
        .filter(|ts| valid_ts(ts))
}

fn remove_temporary_writes(dir: &CapDir) -> Result<(), std::io::Error> {
    for entry in dir.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        let id = name
            .to_str()
            .and_then(|name| name.strip_prefix(".barkup-"))
            .and_then(|name| name.strip_suffix(".tmp"));
        if id.is_some_and(|id| id.len() == 24 && id.bytes().all(|b| b.is_ascii_alphanumeric()))
            && entry.file_type()?.is_file()
        {
            dir.remove_file(name)?;
        }
    }
    Ok(())
}
fn stage_path(root: &FsPath, ts: &str) -> PathBuf {
    root.join("SignalBackups")
        .join(format!("signal-backup-{ts}-tmp"))
}
fn has_active_stages(root: &CapDir, root_path: &FsPath) -> bool {
    let Ok(dir) = rooted_dir(root, root_path, &root_path.join("SignalBackups")) else {
        return true;
    };
    let Ok(entries) = dir.entries() else {
        return true;
    };
    for entry in entries {
        let Ok(e) = entry else {
            return true;
        };
        let name = e.file_name().to_string_lossy().into_owned();
        if e.file_type().map(|t| t.is_symlink()).unwrap_or(true) {
            return true;
        }
        if name
            .strip_prefix("signal-backup-")
            .and_then(|n| n.strip_suffix("-tmp"))
            .is_some_and(valid_ts)
        {
            return true;
        }
    }
    false
}
fn read_varint(b: &[u8], i: &mut usize) -> Result<u64, ()> {
    let mut v = 0u64;
    for shift in (0..70).step_by(7) {
        let x = *b.get(*i).ok_or(())?;
        *i += 1;
        if shift == 63 && x > 1 {
            return Err(());
        }
        v |= ((x & 127) as u64) << shift;
        if x & 128 == 0 {
            return Ok(v);
        }
    }
    Err(())
}
fn validate_manifest(b: &[u8]) -> Result<Vec<String>, ()> {
    let mut i = 0;
    let mut names = Vec::new();
    while i < b.len() {
        let n = read_varint(b, &mut i)? as usize;
        let end = i.checked_add(n).ok_or(())?;
        if end > b.len() {
            return Err(());
        }
        let mut found = false;
        while i < end {
            let key = read_varint(b, &mut i)?;
            let field = key >> 3;
            let wire = key & 7;
            if field != 1 {
                return Err(());
            }
            if wire != 2 || found {
                return Err(());
            }
            let len = read_varint(b, &mut i)? as usize;
            let stop = i.checked_add(len).ok_or(())?;
            if stop > end {
                return Err(());
            }
            let name = std::str::from_utf8(&b[i..stop]).map_err(|_| ())?.to_owned();
            if !valid_filename(&name) {
                return Err(());
            }
            names.push(name);
            i = stop;
            found = true
        }
        if i != end || !found {
            return Err(());
        }
    }
    Ok(names)
}

async fn read_stream_varint<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    mut byte: u8,
) -> Result<u64, std::io::Error> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        if shift > 0 {
            reader.read_exact(std::slice::from_mut(&mut byte)).await?;
        }
        if shift == 63 && byte > 1 {
            return Err(std::io::Error::other("invalid manifest varint"));
        }
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(std::io::Error::other("invalid manifest varint"))
}
async fn validate_manifest_file(
    cap_root: &CapDir,
    root_path: &FsPath,
    path: &FsPath,
    media_root: Option<&FsPath>,
    mut candidates: Option<&mut BTreeMap<String, u64>>,
) -> Result<(), std::io::Error> {
    let file = rooted_file(cap_root, root_path, path)?;
    let mut reader = tokio::io::BufReader::new(file);
    loop {
        let mut first = [0u8; 1];
        let n = reader.read(&mut first).await?;
        if n == 0 {
            break;
        }
        let size = read_stream_varint(&mut reader, first[0]).await?;
        if size > 128 {
            return Err(std::io::Error::other("oversized manifest frame"));
        }
        let mut frame = vec![0; size as usize];
        reader.read_exact(&mut frame).await?;
        let mut encoded = Vec::with_capacity(frame.len() + 2);
        let mut length = size;
        while length >= 0x80 {
            encoded.push((length as u8) | 0x80);
            length >>= 7;
        }
        encoded.push(length as u8);
        encoded.extend_from_slice(&frame);
        let names =
            validate_manifest(&encoded).map_err(|_| std::io::Error::other("invalid manifest"))?;
        if names.len() != 1 {
            return Err(std::io::Error::other("invalid manifest frame"));
        }
        if let Some(candidates) = candidates.as_deref_mut() {
            candidates.remove(&names[0]);
        }
        if let Some(root) = media_root {
            let name = &names[0];
            let media = root.join(&name[..2]).join(name);
            let full = root_path
                .join("SignalBackups/files")
                .join(&name[..2])
                .join(name);
            let available = if media.starts_with(root) {
                match rooted_file(cap_root, root_path, &full) {
                    Ok(file) => file
                        .metadata()
                        .await
                        .map(|meta| meta.is_file())
                        .unwrap_or(false),
                    Err(_) => false,
                }
            } else {
                false
            };
            if !available {
                return Err(std::io::Error::other(
                    "manifest references unavailable media",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use http::Request;
    use serde_json::Value;
    use tower::ServiceExt;

    fn test_app() -> (Router, PathBuf) {
        let root = env::temp_dir().join(format!("barkup-test-{}", random(14)));
        std::fs::create_dir_all(root.join("SignalBackups/files")).unwrap();
        std::fs::create_dir_all(root.join(".uploads")).unwrap();
        let cap = Arc::new(open_cap_dir(&root).unwrap());
        let auth = Arc::new(Auth {
            static_token: Some(hash("secret")),
            state: root.join(".devices.json"),
            cap_state: cap.clone(),
            lock: Mutex::new(()),
        });
        let app = App {
            root: root.clone(),
            cap_root: cap,
            auth,
            serial: Arc::new(Mutex::new(())),
            max: 2 * 1024 * 1024 * 1024,
            retention: 2,
        };
        (routes(app), root)
    }

    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        auth: Option<&str>,
        body: Vec<u8>,
    ) -> Response {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(token) = auth {
            req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let req = req
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        app.clone().oneshot(req).await.unwrap()
    }

    #[test]
    fn protobuf_manifest_is_framed_and_fails_closed() {
        assert!(valid_ts("2024-02-29-23-59-59"));
        assert!(!valid_ts("2023-02-29-23-59-59"));
        assert!(!valid_ts("2026-13-01-00-00-00"));
        assert_eq!(parse_range("bytes=1-", 7), Some((1, 6)));
        assert_eq!(parse_range("bytes=-2", 7), Some((5, 6)));
        assert_eq!(parse_range("bytes=0-2,4-5", 7), None);
        assert_eq!(parse_range("bytes=-0", 7), None);
        let name = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let mut good = vec![66, 10, 64];
        good.extend(name.as_bytes());
        assert_eq!(validate_manifest(&good).unwrap(), vec![name]);
        assert!(validate_manifest(&good[..good.len() - 1]).is_err());
        assert!(validate_manifest(&[3, 10, 64, b'a']).is_err());
        assert!(validate_manifest(&[2, 11, 0]).is_err());
        assert!(validate_manifest(&[4, 18, 2, b'a', b'a']).is_err());
        let hex = include_str!("../contracts/backup/v1/fixtures/files-frame.hex").trim();
        let fixture: Vec<u8> = hex
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                let digit = |b: u8| (b as char).to_digit(16).unwrap() as u8;
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect();
        assert_eq!(validate_manifest(&fixture).unwrap(), vec![name]);
    }

    #[tokio::test]
    async fn upload_resume_snapshot_restore_prune_and_auth() {
        let (app, root) = test_app();
        assert_eq!(
            call(&app, "GET", "/v1/files", None, vec![]).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(
                &app,
                "GET",
                "/v1/files?token=secret",
                Some("secret"),
                vec![]
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(&app, "GET", "/v1/files", Some("wrong-token"), vec![])
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let video = call(
            &app,
            "POST",
            "/v1/uploads",
            Some("secret"),
            serde_json::to_vec(&json!({"name":"cc00000000000000000000000000000000000000000000000000000000000000","length":150_000_000u64})).unwrap(),
        ).await;
        assert_eq!(video.status(), StatusCode::CREATED);
        let video: Value =
            serde_json::from_slice(&to_bytes(video.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        std::fs::remove_dir_all(root.join(".uploads").join(video["id"].as_str().unwrap())).unwrap();

        let payload = b"payload";
        let name = "01".repeat(32);
        let response = call(
            &app,
            "POST",
            "/v1/uploads",
            Some("secret"),
            serde_json::to_vec(&json!({"name":name,"length":payload.len()})).unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let start: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        let id = start["id"].as_str().unwrap();
        assert_eq!(
            call(&app, "POST", "/v1/files/prune", Some("secret"), vec![])
                .await
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            call(
                &app,
                "PATCH",
                &format!("/v1/uploads/{id}"),
                Some("secret"),
                payload[..3].to_vec()
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let req = Request::builder()
            .method("PATCH")
            .uri(format!("/v1/uploads/{id}"))
            .header(header::AUTHORIZATION, "Bearer secret")
            .header("upload-offset", "0")
            .body(Body::from(payload[..3].to_vec()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::NO_CONTENT
        );
        let app = routes(App {
            root: root.clone(),
            cap_root: Arc::new(open_cap_dir(&root).unwrap()),
            auth: Arc::new(Auth {
                static_token: Some(hash("secret")),
                state: root.join(".devices.json"),
                cap_state: Arc::new(open_cap_dir(&root).unwrap()),
                lock: Mutex::new(()),
            }),
            serial: Arc::new(Mutex::new(())),
            max: 100_000_000,
            retention: 2,
        });
        let req = Request::builder()
            .method("HEAD")
            .uri(format!("/v1/uploads/{id}"))
            .header(header::AUTHORIZATION, "Bearer secret")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().headers()["upload-offset"],
            "3"
        );
        let upload_data = root.join(".uploads").join(id).join("data");
        std::fs::write(&upload_data, &payload[..1]).unwrap();
        let req = Request::builder()
            .method("PATCH")
            .uri(format!("/v1/uploads/{id}"))
            .header(header::AUTHORIZATION, "Bearer secret")
            .header("upload-offset", "3")
            .body(Body::from(payload[3..].to_vec()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(std::fs::metadata(&upload_data).unwrap().len(), 1);
        std::fs::write(&upload_data, &payload[..3]).unwrap();
        let req = Request::builder()
            .method("PATCH")
            .uri(format!("/v1/uploads/{id}"))
            .header(header::AUTHORIZATION, "Bearer secret")
            .header("upload-offset", "3")
            .body(Body::from(payload[3..].to_vec()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/v1/uploads/{id}/commit"),
                Some("secret"),
                vec![]
            )
            .await
            .status(),
            StatusCode::CREATED
        );

        let ts = "2026-11-27-12-34-56";
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/v1/snapshots/{ts}"),
                Some("secret"),
                vec![]
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        for (member, bytes) in [("metadata", b"meta".to_vec()), ("main", b"main".to_vec())] {
            assert_eq!(
                call(
                    &app,
                    "PUT",
                    &format!("/v1/snapshots/{ts}/{member}"),
                    Some("secret"),
                    bytes
                )
                .await
                .status(),
                StatusCode::NO_CONTENT
            );
        }
        let mut manifest = vec![66, 10, 64];
        manifest.extend(name.as_bytes());
        assert_eq!(
            call(
                &app,
                "PUT",
                &format!("/v1/snapshots/{ts}/files"),
                Some("secret"),
                manifest
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/v1/snapshots/{ts}/finalize"),
                Some("secret"),
                vec![]
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        let req = Request::builder()
            .method("GET")
            .uri(format!("/v1/files/{}/{name}", &name[..2]))
            .header(header::AUTHORIZATION, "Bearer secret")
            .header(header::RANGE, "bytes=1-3")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            &to_bytes(response.into_body(), usize::MAX).await.unwrap()[..],
            b"ayl"
        );
        assert_eq!(
            call(&app, "POST", "/v1/files/prune", Some("secret"), vec![])
                .await
                .status(),
            StatusCode::OK
        );
        assert!(root
            .join("SignalBackups/files")
            .join(&name[..2])
            .join(&name)
            .exists());

        let oversized = call(
            &app,
            "POST",
            "/v1/uploads",
            Some("secret"),
            serde_json::to_vec(&json!({"name":"aa00000000000000000000000000000000000000000000000000000000000000","length":CHUNK_MAX+1})).unwrap(),
        ).await;
        let oversized: Value =
            serde_json::from_slice(&to_bytes(oversized.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        let req = Request::builder()
            .method("PATCH")
            .uri(format!("/v1/uploads/{}", oversized["id"].as_str().unwrap()))
            .header(header::AUTHORIZATION, "Bearer secret")
            .header("upload-offset", "0")
            .body(Body::from(vec![0; CHUNK_MAX as usize + 1]))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        std::fs::remove_dir_all(
            root.join(".uploads")
                .join(oversized["id"].as_str().unwrap()),
        )
        .unwrap();

        let stage_ts = "2026-11-27-12-34-57";
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/v1/snapshots/{stage_ts}"),
                Some("secret"),
                vec![]
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            call(&app, "POST", "/v1/files/prune", Some("secret"), vec![])
                .await
                .status(),
            StatusCode::CONFLICT
        );
        std::fs::remove_dir_all(stage_path(&root, stage_ts)).unwrap();
        let orphan = "aa00000000000000000000000000000000000000000000000000000000000000";
        std::fs::create_dir_all(root.join("SignalBackups/files/aa")).unwrap();
        std::fs::write(root.join("SignalBackups/files/aa").join(orphan), b"orphan").unwrap();
        let pruned = call(&app, "POST", "/v1/files/prune", Some("secret"), vec![]).await;
        assert_eq!(pruned.status(), StatusCode::OK);
        let report: Value =
            serde_json::from_slice(&to_bytes(pruned.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(report["removed_bytes"], 6);
        assert!(!root.join("SignalBackups/files/aa").join(orphan).exists());

        for ts in ["2026-11-28-00-00-00", "2026-11-29-00-00-00"] {
            assert_eq!(
                call(
                    &app,
                    "POST",
                    &format!("/v1/snapshots/{ts}"),
                    Some("secret"),
                    vec![]
                )
                .await
                .status(),
                StatusCode::CREATED
            );
            let files = if ts == "2026-11-28-00-00-00" {
                let mut manifest = vec![66, 10, 64];
                manifest.extend(name.as_bytes());
                manifest
            } else {
                vec![]
            };
            for (member, bytes) in [("metadata", vec![]), ("main", vec![]), ("files", files)] {
                assert_eq!(
                    call(
                        &app,
                        "PUT",
                        &format!("/v1/snapshots/{ts}/{member}"),
                        Some("secret"),
                        bytes
                    )
                    .await
                    .status(),
                    StatusCode::NO_CONTENT
                );
            }
            assert_eq!(
                call(
                    &app,
                    "POST",
                    &format!("/v1/snapshots/{ts}/finalize"),
                    Some("secret"),
                    vec![]
                )
                .await
                .status(),
                StatusCode::CREATED
            );
        }
        let listed = call(&app, "GET", "/v1/snapshots", Some("secret"), vec![]).await;
        let listed: Value =
            serde_json::from_slice(&to_bytes(listed.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(listed.as_array().unwrap().len(), 2);
        assert_eq!(listed[0], "signal-backup-2026-11-29-00-00-00");

        let auth = root.join(".devices.json");
        let mut state = AuthFile::default();
        state
            .bootstrap
            .insert(hash("one-use"), unix_seconds() + 600);
        auth_write(
            &Auth {
                static_token: None,
                state: auth,
                cap_state: Arc::new(open_cap_dir(&root).unwrap()),
                lock: Mutex::new(()),
            },
            &state,
        )
        .await
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(root.join(".devices.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let redeem = || {
            Request::builder()
                .method("POST")
                .uri("/v1/pair/redeem")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"token":"one-use"}"#))
                .unwrap()
        };
        let response = app.clone().oneshot(redeem()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let pair: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(
            app.clone().oneshot(redeem()).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let id = pair["device_id"].as_str().unwrap();
        let mut state = auth_read(&Auth {
            static_token: None,
            state: root.join(".devices.json"),
            cap_state: Arc::new(open_cap_dir(&root).unwrap()),
            lock: Mutex::new(()),
        })
        .await
        .unwrap();
        state.revoked.insert(id.to_owned());
        auth_write(
            &Auth {
                static_token: None,
                state: root.join(".devices.json"),
                cap_state: Arc::new(open_cap_dir(&root).unwrap()),
                lock: Mutex::new(()),
            },
            &state,
        )
        .await
        .unwrap();
        let device_app = routes(App {
            root: root.clone(),
            cap_root: Arc::new(open_cap_dir(&root).unwrap()),
            auth: Arc::new(Auth {
                static_token: None,
                state: root.join(".devices.json"),
                cap_state: Arc::new(open_cap_dir(&root).unwrap()),
                lock: Mutex::new(()),
            }),
            serial: Arc::new(Mutex::new(())),
            max: 100_000_000,
            retention: 2,
        });
        let req = Request::builder()
            .method("GET")
            .uri("/v1/files")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", pair["token"].as_str().unwrap()),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            device_app.oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn quota_and_symlink_routes_fail_closed() {
        let root = env::temp_dir().join(format!("barkup-quota-{}", random(14)));
        init_layout(&root).await.unwrap();
        let app = routes(App {
            root: root.clone(),
            cap_root: Arc::new(open_cap_dir(&root).unwrap()),
            auth: Arc::new(Auth {
                static_token: Some(hash("secret")),
                state: root.join(".devices.json"),
                cap_state: Arc::new(open_cap_dir(&root).unwrap()),
                lock: Mutex::new(()),
            }),
            serial: Arc::new(Mutex::new(())),
            max: 1,
            retention: 2,
        });
        let first = "01".repeat(32);
        let second = "02".repeat(32);
        assert_eq!(
            call(
                &app,
                "PUT",
                &format!("/v1/files/{}/{first}", &first[..2]),
                Some("secret"),
                b"x".to_vec()
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            call(
                &app,
                "PUT",
                &format!("/v1/files/{}/{first}", &first[..2]),
                Some("secret"),
                b"z".to_vec()
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            call(
                &app,
                "PUT",
                &format!("/v1/files/{}/{second}", &second[..2]),
                Some("secret"),
                b"y".to_vec()
            )
            .await
            .status(),
            StatusCode::INSUFFICIENT_STORAGE
        );
        let ts = "2026-11-27-00-00-00";
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/v1/snapshots/{ts}"),
                Some("secret"),
                vec![]
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            call(
                &app,
                "PUT",
                &format!("/v1/snapshots/{ts}/main"),
                Some("secret"),
                b"xx".to_vec()
            )
            .await
            .status(),
            StatusCode::INSUFFICIENT_STORAGE
        );
        #[cfg(unix)]
        {
            let outside = root.with_extension("outside");
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::write(outside.join(&second), b"outside").unwrap();
            std::fs::remove_dir(root.join("SignalBackups/files").join(&second[..2])).unwrap();
            std::os::unix::fs::symlink(
                &outside,
                root.join("SignalBackups/files").join(&second[..2]),
            )
            .unwrap();
            let response = call(
                &app,
                "GET",
                &format!("/v1/files/{}/{second}", &second[..2]),
                Some("secret"),
                vec![],
            )
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            std::fs::remove_dir_all(outside).unwrap();
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
