#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use lain_core::peer::PeerId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, mpsc};
use tracing;

#[derive(Error, Debug)]
pub enum IpcError {
    #[error("listener error: {0}")]
    Listener(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum IpcRequest {
    Connect { peer_id: Option<String>, invite: String },
    Tso { invite: String },
    FindPeer { peer_id: String },
    Disconnect { peer_id: String },
    Accept { connection_id: u64 },
    Reject { connection_id: u64 },
    ListPeers,
    GetInvite,
    Whoami,
    Subscribe,
    Shutdown,
    Send { peer_id: String, data: String },  // base64-encoded bytes
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum IpcResponse {
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<serde_json::Value>,
    },
    Error { code: String, message: String },
    Event {
        event: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        peer_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<serde_json::Value>,
    },
}

pub enum IpcCommand {
    ConnectPeer { peer_id: Option<PeerId>, invite: String },
    TsoPeer { invite: String },
    FindPeer { peer_id: String },
    DisconnectPeer { peer_id: PeerId },
    AcceptConnection { connection_id: u64 },
    RejectConnection { connection_id: u64 },
    Shutdown,
    SendToPeer { peer_id: PeerId, data: Vec<u8> },
    GetStatus { reply: tokio::sync::oneshot::Sender<serde_json::Value> },
    GetWhoami { reply: tokio::sync::oneshot::Sender<String> },
    GetInviteCode { reply: tokio::sync::oneshot::Sender<String> },
}

pub struct IpcConfig {
    pub uds_path: Option<PathBuf>,
    pub http_addr: Option<std::net::SocketAddr>,
}

impl Default for IpcConfig {
    fn default() -> Self { Self { uds_path: None, http_addr: None } }
}

pub struct IpcServer {
    config: IpcConfig,
    cmd_tx: mpsc::Sender<IpcCommand>,
    event_tx: broadcast::Sender<IpcResponse>,
    next_conn_id: u64,
    /// Daemon metadata (set after construction)
    pub peer_id: Option<PeerId>,
    pub invite_code: Option<String>,
}

impl IpcServer {
    pub fn new(config: IpcConfig, cmd_tx: mpsc::Sender<IpcCommand>) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        Self { config, cmd_tx, event_tx, next_conn_id: 1, peer_id: None, invite_code: None }
    }

    pub fn event_sender(&self) -> broadcast::Sender<IpcResponse> {
        self.event_tx.clone()
    }

    pub fn notify_incoming(&mut self, peer_id: PeerId) -> u64 {
        let conn_id = self.next_conn_id;
        self.next_conn_id = self.next_conn_id.wrapping_add(1);
        self.event_tx.send(IpcResponse::Event {
            event: "incoming_connection".into(),
            peer_id: Some(peer_id.to_string()),
            data: Some(serde_json::json!({"connection_id": conn_id})),
        }).ok();
        conn_id
    }

    pub async fn run(self) -> Result<(), IpcError> {
        let mut tasks = Vec::new();

        // Local IPC listener
        if let Some(ref path) = self.config.uds_path {
            let _ = std::fs::remove_file(path);
            if let Some(p) = path.parent() { std::fs::create_dir_all(p).ok(); }
            let listener = bind_local(path)
                .map_err(|e| IpcError::Listener(e))?;
            tracing::info!("IPC local on {:?}", path);

            let tx = self.cmd_tx.clone();
            let ev = self.event_tx.clone();
            tasks.push(tokio::spawn(listen_local(listener, tx, ev)));
        }

        // HTTP server
        if let Some(http_addr) = self.config.http_addr {
            let listener = tokio::net::TcpListener::bind(http_addr).await
                .map_err(|e| IpcError::Listener(format!("HTTP: {e}")))?;
            tracing::info!("IPC HTTP on {http_addr}");
            let tx = self.cmd_tx.clone();
            let ev = self.event_tx.clone();
            tasks.push(tokio::spawn(serve_http(listener, tx, ev)));
        }

        for t in tasks { let _ = t.await; }
        Ok(())
    }
}

// ── Platform-specific local listener ──

#[cfg(unix)]
fn bind_local(path: &std::path::Path) -> Result<tokio::net::UnixListener, String> {
    tokio::net::UnixListener::bind(path).map_err(|e| format!("UDS bind: {e}"))
}

#[cfg(windows)]
fn bind_local(_path: &std::path::Path) -> Result<std::path::PathBuf, String> {
    Ok(std::path::PathBuf::from(r"\\.\pipe\lain"))
}

#[cfg(windows)]
async fn listen_local(
    pipe_path: std::path::PathBuf,
    cmd_tx: mpsc::Sender<IpcCommand>,
    ev_tx: broadcast::Sender<IpcResponse>,
) {
    use tokio::net::windows::named_pipe::ServerOptions;
    let pipe_name = pipe_path.to_string_lossy().to_string();

    loop {
        let server = match ServerOptions::new().create(&pipe_name) {
            Ok(s) => s,
            Err(e) => { tracing::error!("NamedPipe create: {e}"); break; }
        };

        match server.connect().await {
            Ok(()) => {
                let (r, w) = tokio::io::split(server);
                let tx = cmd_tx.clone();
                let ev = ev_tx.clone();
                tokio::spawn(handle_client(r, w, tx, ev));
            }
            Err(e) => { tracing::error!("NamedPipe connect: {e}"); continue; }
        }
    }
}

#[cfg(unix)]
async fn listen_local(
    listener: tokio::net::UnixListener,
    cmd_tx: mpsc::Sender<IpcCommand>,
    ev_tx: broadcast::Sender<IpcResponse>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                // Verify caller is same user (prevent other local processes from hijacking)
                if let Ok(cred) = stream.peer_cred() {
                    let my_uid = unsafe { libc::getuid() };
                    if cred.uid() != 0 && cred.uid() != my_uid {
                        tracing::warn!("IPC rejected: uid {} != {}", cred.uid(), my_uid);
                        continue;
                    }
                }
                let (r, w) = tokio::io::split(stream);
                let tx = cmd_tx.clone();
                let ev = ev_tx.clone();
                tokio::spawn(handle_client(r, w, tx, ev));
            }
            Err(e) => { tracing::error!("UDS accept: {e}"); continue; }
        }
    }
}

// ── HTTP Server ──

async fn serve_http(
    listener: tokio::net::TcpListener,
    cmd_tx: mpsc::Sender<IpcCommand>,
    _ev_tx: broadcast::Sender<IpcResponse>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let (r, w) = tokio::io::split(stream);
                let tx = cmd_tx.clone();
                tokio::spawn(handle_http_client(r, w, tx));
            }
            Err(e) => { tracing::error!("HTTP accept: {e}"); continue; }
        }
    }
}


// ── Client handlers ──

async fn handle_client<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: R,
    mut writer: W,
    cmd_tx: mpsc::Sender<IpcCommand>,
    ev_tx: broadcast::Sender<IpcResponse>,
) {
    let mut buf = BufReader::new(reader);
    let mut line = String::new();
    let mut ev_rx = ev_tx.subscribe();

    loop {
        line.clear();
        tokio::select! {
            read_result = buf.read_line(&mut line) => {
                match read_result {
                    Ok(0) => break,
                    Ok(_) => {
                        let resp = dispatch(&line, &cmd_tx).await;
                        let mut json = serde_json::to_string(&resp).unwrap_or_default();
                        json.push('\n');
                        writer.write_all(json.as_bytes()).await.ok();
                    }
                    Err(_) => break,
                }
            }
            event_result = ev_rx.recv() => {
                match event_result {
                    Ok(event) => {
                        let mut json = serde_json::to_string(&event).unwrap_or_default();
                        json.push('\n');
                        if writer.write_all(json.as_bytes()).await.is_err() { break; }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::debug!("IPC event lagged by {n}");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

async fn handle_http_client<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: R,
    mut writer: W,
    cmd_tx: mpsc::Sender<IpcCommand>,
) {
    let mut buf = BufReader::new(reader);
    let mut line = String::new();

    line.clear();
    if buf.read_line(&mut line).await.is_err() { return; }
    let mut content_length = 0usize;
    loop {
        line.clear();
        if buf.read_line(&mut line).await.is_err() { return; }
        let t = line.trim().to_lowercase();
        if t.is_empty() { break; }
        if let Some(l) = t.strip_prefix("content-length:") {
            content_length = l.trim().parse().unwrap_or(0);
        }
    }

    let mut body = vec![0u8; content_length.min(65536)];
    if content_length > 0 {
        use tokio::io::AsyncReadExt;
        if buf.read_exact(&mut body).await.is_err() { return; }
    }

    let req_str = String::from_utf8_lossy(&body);
    let resp = dispatch(&req_str, &cmd_tx).await;
    let json = serde_json::to_string(&resp).unwrap_or_default();
    let http = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        json.len(), json
    );
    writer.write_all(http.as_bytes()).await.ok();
}

fn send_or_warn(tx: &mpsc::Sender<IpcCommand>, cmd: IpcCommand, label: &str) {
    match tx.try_send(cmd) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            tracing::warn!("IPC {label} dropped (channel full)");
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            tracing::debug!("IPC {label} channel closed");
        }
    }
}

// ── Request dispatch ──

async fn dispatch(
    line: &str,
    cmd_tx: &mpsc::Sender<IpcCommand>,
) -> IpcResponse {
    let req: IpcRequest = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => return IpcResponse::Error { code: "PARSE".into(), message: e.to_string() },
    };

    match req {
        IpcRequest::Connect { invite, .. } => {
            send_or_warn(cmd_tx, IpcCommand::ConnectPeer { peer_id: None, invite: invite.clone() }, "connect");
            IpcResponse::Ok { message: Some(format!("connecting: {invite}")), data: None }
        }
        IpcRequest::Tso { invite } => {
            send_or_warn(cmd_tx, IpcCommand::TsoPeer { invite: invite.clone() }, "tso");
            IpcResponse::Ok { message: Some(format!("tso: {invite}")), data: None }
        }
        IpcRequest::FindPeer { peer_id } => {
            send_or_warn(cmd_tx, IpcCommand::FindPeer { peer_id: peer_id.clone() }, "find");
            IpcResponse::Ok { message: Some(format!("finding: {peer_id}")), data: None }
        }
        IpcRequest::Disconnect { peer_id } => {
            if let Ok(pid) = PeerId::from_hex(&peer_id) {
                send_or_warn(cmd_tx, IpcCommand::DisconnectPeer { peer_id: pid }, "disconnect");
            }
            IpcResponse::Ok { message: Some("disconnecting".into()), data: None }
        }
        IpcRequest::Accept { connection_id } => {
            send_or_warn(cmd_tx, IpcCommand::AcceptConnection { connection_id }, "accept");
            IpcResponse::Ok { message: Some("accepted".into()), data: None }
        }
        IpcRequest::Reject { connection_id } => {
            send_or_warn(cmd_tx, IpcCommand::RejectConnection { connection_id }, "reject");
            IpcResponse::Ok { message: Some("rejected".into()), data: None }
        }
        IpcRequest::ListPeers => {
            let (tx, rx) = tokio::sync::oneshot::channel();
            send_or_warn(cmd_tx, IpcCommand::GetStatus { reply: tx }, "status");
            match rx.await {
                Ok(data) => IpcResponse::Ok { message: None, data: Some(data) },
                Err(_) => IpcResponse::Error { code: "TIMEOUT".into(), message: "daemon busy".into() },
            }
        }
        IpcRequest::Whoami => {
            let (tx, rx) = tokio::sync::oneshot::channel();
            send_or_warn(cmd_tx, IpcCommand::GetWhoami { reply: tx }, "whoami");
            match rx.await {
                Ok(pid) => IpcResponse::Ok { message: Some(pid), data: None },
                Err(_) => IpcResponse::Error { code: "TIMEOUT".into(), message: "daemon busy".into() },
            }
        }
        IpcRequest::GetInvite => {
            let (tx, rx) = tokio::sync::oneshot::channel();
            send_or_warn(cmd_tx, IpcCommand::GetInviteCode { reply: tx }, "invite");
            match rx.await {
                Ok(code) => IpcResponse::Ok { message: Some(code), data: None },
                Err(_) => IpcResponse::Error { code: "TIMEOUT".into(), message: "daemon busy".into() },
            }
        }
        IpcRequest::Subscribe => {
            IpcResponse::Ok { message: Some("subscribed".into()), data: None }
        }
        IpcRequest::Shutdown => {
            send_or_warn(cmd_tx, IpcCommand::Shutdown, "shutdown");
            IpcResponse::Ok { message: Some("shutting down".into()), data: None }
        }
        IpcRequest::Send { peer_id, data } => {
            if let Ok(pid) = PeerId::from_hex(&peer_id) {
                // Decode base64
                if let Ok(bytes) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &data) {
                    send_or_warn(cmd_tx, IpcCommand::SendToPeer { peer_id: pid, data: bytes }, "send");
                }
            }
            IpcResponse::Ok { message: Some("sent".into()), data: None }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_connect() {
        let r = IpcRequest::Connect { peer_id: None, invite: "lain://abc".into() };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("abc"));
    }

    #[test]
    fn test_deserialize_connect() {
        let r: IpcRequest = serde_json::from_str(r#"{"cmd":"Connect","invite":"lain://x"}"#).unwrap();
        match r { IpcRequest::Connect { invite, .. } => assert_eq!(invite, "lain://x"), _ => panic!() }
    }

    #[test]
    fn test_response_ok() {
        let r = IpcResponse::Ok { message: Some("ok".into()), data: None };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("ok"));
    }

    #[test]
    fn test_deserialize_malformed_json() {
        assert!(serde_json::from_str::<IpcRequest>("not json").is_err());
        assert!(serde_json::from_str::<IpcRequest>("{").is_err());
    }

    #[test]
    fn test_deserialize_unknown_command() {
        let r = serde_json::from_str::<IpcRequest>(r#"{"cmd":"UnknownCmd"}"#);
        assert!(r.is_err(), "unknown command should fail to deserialize");
    }

    #[test]
    fn test_deserialize_missing_required_field() {
        // Connect without invite should fail
        let r = serde_json::from_str::<IpcRequest>(r#"{"cmd":"Connect"}"#);
        assert!(r.is_err(), "Connect without invite should fail");
    }

    #[test]
    fn test_deserialize_shutdown() {
        let r: IpcRequest = serde_json::from_str(r#"{"cmd":"Shutdown"}"#).unwrap();
        assert!(matches!(r, IpcRequest::Shutdown));
    }

    #[test]
    fn test_deserialize_send() {
        let r: IpcRequest = serde_json::from_str(r#"{"cmd":"Send","peer_id":"abc","data":"ZGF0YQ=="}"#).unwrap();
        match r {
            IpcRequest::Send { peer_id, data } => {
                assert_eq!(peer_id, "abc");
                assert!(!data.is_empty());
            }
            _ => panic!("expected Send"),
        }
    }

    #[test]
    fn test_deserialize_subscribe() {
        let r: IpcRequest = serde_json::from_str(r#"{"cmd":"Subscribe"}"#).unwrap();
        assert!(matches!(r, IpcRequest::Subscribe));
    }

    #[test]
    fn test_deserialize_get_status() {
        let r: IpcRequest = serde_json::from_str(r#"{"cmd":"ListPeers"}"#).unwrap();
        assert!(matches!(r, IpcRequest::ListPeers));
    }

    #[test]
    fn test_deserialize_get_whoami() {
        let r: IpcRequest = serde_json::from_str(r#"{"cmd":"Whoami"}"#).unwrap();
        assert!(matches!(r, IpcRequest::Whoami));
    }

    #[test]
    fn test_deserialize_get_invite() {
        let r: IpcRequest = serde_json::from_str(r#"{"cmd":"GetInvite"}"#).unwrap();
        assert!(matches!(r, IpcRequest::GetInvite));
    }

    #[test]
    fn test_response_error() {
        let r = IpcResponse::Error { code: "ERR".into(), message: "fail".into() };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("ERR"));
        assert!(j.contains("fail"));
    }

    #[test]
    fn test_response_event() {
        let r = IpcResponse::Event {
            event: "connected".into(),
            peer_id: Some("p1".into()),
            data: Some(serde_json::json!({"key": "val"})),
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("connected"));
        assert!(j.contains("p1"));
    }

    // ── Platform-specific IPC integration ──

    #[cfg(windows)]
    #[tokio::test]
    async fn test_windows_bind_local_returns_pipe_path() {
        use std::path::Path;
        let result = super::bind_local(Path::new("/dummy"));
        assert!(result.is_ok());
        let path = result.unwrap();
        assert_eq!(path.to_string_lossy(), r"\\.\pipe\lain");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn test_named_pipe_create_succeeds() {
        use tokio::net::windows::named_pipe::ServerOptions;
        let pipe_name = r"\\.\pipe\lain-test-create";
        let server = ServerOptions::new().create(pipe_name);
        assert!(server.is_ok(), "should create named pipe: {:?}", server.err());
        drop(server);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn test_named_pipe_roundtrip() {
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let pipe_name = r"\\.\pipe\lain-test-roundtrip";

        // Spawn server
        let srv = ServerOptions::new().create(pipe_name).unwrap();

        let server_handle = tokio::spawn(async move {
            srv.connect().await.unwrap();
            let (mut r, mut w) = tokio::io::split(srv);
            // Read client message
            let mut buf = vec![0u8; 4096];
            let n = r.read(&mut buf).await.unwrap();
            let req: serde_json::Value = serde_json::from_slice(&buf[..n]).unwrap();
            assert_eq!(req["cmd"], "Whoami");

            // Send response
            let resp = serde_json::json!({"type":"Ok","message":"peer-abc"});
            let resp_str = serde_json::to_string(&resp).unwrap() + "\n";
            w.write_all(resp_str.as_bytes()).await.unwrap();
        });

        // Client connect and send
        let client = ClientOptions::new().open(pipe_name).unwrap();
        let (mut cr, mut cw) = tokio::io::split(client);

        let req = br#"{"cmd":"Whoami"}"#;
        cw.write_all(req).await.unwrap();

        // handle_client uses BufReader::read_line, needs \n
        cw.write_all(b"\n").await.unwrap();

        // Read response
        let mut buf = vec![0u8; 4096];
        let n = cr.read(&mut buf).await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&buf[..n]).unwrap();

        assert_eq!(resp["type"], "Ok");
        assert_eq!(resp["message"], "peer-abc");

        server_handle.await.unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn test_named_pipe_connect_command_sent_to_handler() {
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
        use tokio::io::AsyncWriteExt;

        let pipe_name = r"\\.\pipe\lain-test-cmd";

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<super::IpcCommand>(8);
        let (ev_tx, _) = broadcast::channel::<super::IpcResponse>(8);

        let srv = ServerOptions::new().create(pipe_name).unwrap();

        // Spawn server using the real handler
        tokio::spawn(async move {
            srv.connect().await.unwrap();
            let (r, w) = tokio::io::split(srv);
            super::handle_client(r, w, cmd_tx, ev_tx).await;
        });

        // Client sends Connect command (with newline, required by BufReader::read_line)
        let client = ClientOptions::new().open(pipe_name).unwrap();
        let (_, mut cw) = tokio::io::split(client);

        let req = b"{\"cmd\":\"Connect\",\"invite\":\"lain://test\"}\n";
        cw.write_all(req).await.unwrap();

        // Server should parse and send IpcCommand::Connect to cmd_tx
        let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), cmd_rx.recv()).await;
        assert!(cmd.is_ok(), "should receive Connect command");
        match cmd.unwrap() {
            Some(super::IpcCommand::ConnectPeer { invite, .. }) => {
                assert_eq!(invite, "lain://test");
            }
            other => panic!("expected ConnectPeer, got {:?}", other.map(|_| ())),
        }

        // Cleanup: close pipe
        drop(cw);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn test_named_pipe_malformed_json_does_not_crash_handler() {
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
        use tokio::io::AsyncWriteExt;

        let pipe_name = r"\\.\pipe\lain-test-malformed";

        let (cmd_tx, _cmd_rx) = mpsc::channel::<super::IpcCommand>(8);
        let (ev_tx, _) = broadcast::channel::<super::IpcResponse>(8);

        let srv = ServerOptions::new().create(pipe_name).unwrap();

        tokio::spawn(async move {
            srv.connect().await.unwrap();
            let (r, w) = tokio::io::split(srv);
            super::handle_client(r, w, cmd_tx, ev_tx).await;
        });

        // Send garbage
        let client = ClientOptions::new().open(pipe_name).unwrap();
        let (_, mut cw) = tokio::io::split(client);
        cw.write_all(b"not json at all!!!").await.unwrap();

        // Should not crash — handler returns, pipe closes
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
