#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use clap::{Parser, Subcommand};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;

/// Cross-platform IPC connection
enum IpcStream {
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
    #[cfg(target_os = "windows")]
    Pipe(std::fs::File),
}

impl IpcStream {
    fn connect(path: &PathBuf) -> std::io::Result<Self> {
        #[cfg(unix)]
        { std::os::unix::net::UnixStream::connect(path).map(IpcStream::Unix) }
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .read(true).write(true)
                .custom_flags(0x40000000) // FILE_FLAG_OVERLAPPED — non-blocking
                .open(path)?;
            Ok(IpcStream::Pipe(file))
        }
    }
}

impl Read for IpcStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)] IpcStream::Unix(s) => s.read(buf),
            #[cfg(windows)] IpcStream::Pipe(f) => f.read(buf),
        }
    }
}

impl Write for IpcStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)] IpcStream::Unix(s) => s.write(buf),
            #[cfg(windows)] IpcStream::Pipe(f) => f.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            #[cfg(unix)] IpcStream::Unix(s) => s.flush(),
            #[cfg(windows)] IpcStream::Pipe(f) => f.flush(),
        }
    }
}

#[derive(Parser)]
#[command(name = "lain", about = "Zero-server P2P network daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(short = 's', long, default_value = "")]
    socket: String,
    /// Run in foreground (log to stdout instead of file)
    #[arg(short = 'f', long, global = true)]
    foreground: bool,
}

fn ipc_socket(path: &str) -> PathBuf {
    if !path.is_empty() { return PathBuf::from(path); }
    #[cfg(unix)] { dirs_home().map(|d| d.join(".lain").join("socket")).unwrap_or_else(|| PathBuf::from("/tmp/lain.socket")) }
    #[cfg(target_os = "windows")] { r"\\.\pipe\lain".into() }
}

fn dirs_home() -> Option<PathBuf> {
    if let Ok(h) = std::env::var("LAIN_HOME") { return Some(PathBuf::from(h)); }
    #[cfg(unix)]
    { if let Ok(h) = std::env::var("HOME") { return Some(PathBuf::from(h)); } }
    #[cfg(target_os = "windows")]
    { if let Ok(h) = std::env::var("USERPROFILE") { return Some(PathBuf::from(h)); } }
    None
}

#[derive(Subcommand)]
enum Command {
    Daemon,
    Whoami,
    Invite,
    Connect { invite: String },
    Tso { invite: String },
    Find { peer_id: String },
    Disconnect { peer_id: String },
    Monitor,
    Shutdown,
    Status,
}

fn main() {
    let cli = Cli::parse();
    let socket_path = ipc_socket(&cli.socket);

    // Set up logging
    if cli.foreground {
        tracing_subscriber::fmt::init();
    } else {
        // Log to file in Lain config directory
        let log_path = {
            let mut d = if let Ok(h) = std::env::var("LAIN_HOME") {
                PathBuf::from(h)
            } else if let Some(h) = dirs_home() {
                h.join(".lain")
            } else {
                PathBuf::from(".")
            };
            std::fs::create_dir_all(&d).ok();
            d.push("daemon.log");
            d
        };
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true).append(true).open(&log_path)
        {
            tracing_subscriber::fmt()
                .with_writer(std::sync::Mutex::new(file))
                .with_ansi(false)
                .init();
        } else {
            tracing_subscriber::fmt::init();
        }
    }

    match cli.command.unwrap_or(Command::Status) {
        Command::Daemon => run_daemon(cli.foreground),
        Command::Whoami => {
            match ipc_req(&socket_path, r#"{"cmd":"Whoami"}"#) {
                Some(v) => {
                    let pid = v.get("message").and_then(|m| m.as_str()).unwrap_or("?");
                    println!("PeerID: {pid}");
                }
                None => eprintln!("daemon not running — run 'lain daemon' to start"),
            }
        }
        Command::Invite => {
            match ipc_req(&socket_path, r#"{"cmd":"GetInvite"}"#) {
                Some(v) => {
                    let inv = v.get("message").and_then(|m| m.as_str()).unwrap_or("?");
                    println!("Invite: {inv}");
                }
                None => eprintln!("daemon not running — run 'lain daemon' to start"),
            }
        }
        Command::Connect { invite } => connect_feedback(&socket_path, &invite),
        Command::Tso { invite } => tso_connect(&socket_path, &invite),
        Command::Find { peer_id } => find_and_connect(&socket_path, &peer_id),
        Command::Disconnect { peer_id } => {
            match ipc_req(&socket_path, &format!(r#"{{"cmd":"Disconnect","peer_id":"{peer_id}"}}"#)) {
                Some(_) => println!("disconnected from {peer_id}"),
                None => eprintln!("daemon not running — run 'lain daemon' to start"),
            }
        }
        Command::Monitor => monitor_loop(&socket_path),
        Command::Shutdown => {
            match ipc_req(&socket_path, r#"{"cmd":"Shutdown"}"#) {
                Some(_) => println!("daemon shutting down"),
                None => eprintln!("daemon not running — run 'lain daemon' to start"),
            }
        }
        Command::Status => {
            match ipc_req(&socket_path, r#"{"cmd":"ListPeers"}"#) {
                Some(v) => print_status(&v),
                None => eprintln!("daemon not running — run 'lain daemon' to start"),
            }
        }
    }
}

fn run_daemon(foreground: bool) {
    if !foreground {
        let socket_path = ipc_socket("");
        // Check if daemon is already running
        if IpcStream::connect(&socket_path).is_ok() {
            eprintln!("daemon is already running");
            return;
        }
        // Spawn as a separate process so the terminal is not blocked
        let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("lain"));
        match std::process::Command::new(&exe)
            .arg("-f").arg("daemon")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn() {
            Ok(mut child) => {
                println!("Starting daemon (NAT probe + DHT bootstrap may take a few seconds)...");
                for i in 0..20 {
                    if i == 4 { eprintln!("still waiting (NAT probe may take a while)..."); }
                    // Check if child died early (stale pipe, config error, etc.)
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            eprintln!("daemon exited unexpectedly (code: {status})");
                            return;
                        }
                        Err(e) => {
                            eprintln!("daemon process error: {e}");
                            return;
                        }
                        Ok(None) => {} // still running
                    }
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    match ipc_req(&socket_path, r#"{"cmd":"Whoami"}"#) {
                        Some(v) => {
                            if v.get("type").and_then(|t| t.as_str()) == Some("Ok") {
                                let pid = v.get("message").and_then(|m| m.as_str()).unwrap_or("?");
                                println!("Lain daemon started");
                                println!("PeerID: {pid}");
                                println!("Logs: ~/.lain/daemon.log");
                                return;
                            }
                            // Got error response (daemon busy) — keep retrying
                        }
                        None => {} // IPC not available yet — keep retrying
                    }
                }
                eprintln!("daemon failed to start (timeout)");
            }
            Err(e) => eprintln!("cannot start daemon: {e}"),
        }
        return;
    }

    let rt = tokio::runtime::Runtime::new().expect("tokio");
    rt.block_on(async {
        let config = lain_daemon::config::DaemonConfig::load_or_default().unwrap_or_default();
        match lain_daemon::Daemon::new(config).await {
            Ok(daemon) => {
                let pid = daemon.peer_id();
                if let Err(e) = daemon.run().await {
                    eprintln!("daemon error: {e}");
                }
                let _ = pid; // used in foreground mode for logging
            }
            Err(e) => eprintln!("daemon init failed: {e}"),
        }
    });
}

fn read_line_timeout(reader: &mut BufReader<IpcStream>, timeout_secs: u64) -> std::io::Result<String> {
    // Move the reader into a spawned thread so we can time out
    // We can't move BufReader, so use raw reads with a small buffer
    let mut buf = vec![0u8; 1];
    let mut line = String::new();
    let start = std::time::Instant::now();
    loop {
        if start.elapsed().as_secs() > timeout_secs {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"));
        }
        // Read one byte at a time with a short wait between retries
        match reader.get_mut().read(&mut buf) {
            Ok(0) => {
                if line.is_empty() { return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof")); }
                return Ok(line);
            }
            Ok(_) => {
                line.push(buf[0] as char);
                if buf[0] == b'\n' { return Ok(line); }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

fn ipc_req(socket_path: &PathBuf, json: &str) -> Option<serde_json::Value> {
    let mut stream = IpcStream::connect(socket_path).ok()?;
    let req = json.to_string() + "\n";
    stream.write_all(req.as_bytes()).ok()?;
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response).ok()?;
    serde_json::from_str(&response).ok()
}

fn connect_feedback(socket_path: &PathBuf, invite: &str) {
    let owned;
    let invite = if !invite.starts_with("lain://") {
        owned = format!("lain://{invite}");
        &owned
    } else {
        invite
    };

    let mut stream = match IpcStream::connect(socket_path) {
        Ok(s) => s,
        Err(e) => { eprintln!("cannot connect to daemon: {e}"); return; }
    };
    let req = serde_json::json!({"cmd":"Connect","invite":invite}).to_string() + "\n";
    stream.write_all(req.as_bytes()).ok();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok();
    // Check immediate response for errors
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
        if v.get("type").and_then(|t| t.as_str()) == Some("Error") {
            let msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("unknown error");
            eprintln!("cannot connect: {msg}");
            return;
        }
    }
    eprintln!("connecting (trying all paths: QUIC → relay → TSO, up to 2 min)...");
    // Subscribe
    reader.get_mut().write_all(b"{\"cmd\":\"Subscribe\"}\n").ok();
    line.clear();
    let start = std::time::Instant::now();
    loop {
        line.clear();
        match read_line_timeout(&mut reader, 5) {
            Ok(l) => line = l,
            Err(_) => break,
        }
        if start.elapsed().as_secs() > 130 {
            println!("timeout — check 'lain status'");
            // Suggest TSO exchange for hard-to-reach peers
            match ipc_req(socket_path, r#"{"cmd":"GetInvite"}"#) {
                Some(v) => {
                    let my_inv = v.get("message").and_then(|m| m.as_str()).unwrap_or("?");
                    println!("\nDirect connection failed. To use TSO (TCP simultaneous open):");
                    println!("  1. Share your invite with the other person:");
                    println!("     {my_inv}");
                    println!("  2. Both of you run within 102 seconds:");
                    println!("     lain tso <other-person-invite>");
                }
                None => {}
            }
            break;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            if let Some(ev) = v.get("event").and_then(|e| e.as_str()) {
                match ev {
                    "peer_connected" => {
                        let pid = v.get("peer_id").and_then(|p| p.as_str()).unwrap_or("?");
                        println!("connected to {pid}");
                        break;
                    }
                    "peer_error" => {
                        let err = v.get("data").and_then(|d| d.get("error")).and_then(|e| e.as_str()).unwrap_or("?");
                        println!("connection failed: {err}");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn tso_connect(socket_path: &PathBuf, invite: &str) {
    let owned;
    let invite = if !invite.starts_with("lain://") {
        owned = format!("lain://{invite}");
        &owned
    } else { invite };

    // Tell daemon to do TSO via IPC
    let mut stream = match IpcStream::connect(socket_path) {
        Ok(s) => s,
        Err(e) => { eprintln!("cannot connect to daemon: {e}"); return; }
    };
    let req = serde_json::json!({"cmd":"Tso","invite":invite}).to_string() + "\n";
    stream.write_all(req.as_bytes()).ok();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok();

    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
        if v.get("type").and_then(|t| t.as_str()) == Some("Error") {
            let msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("?");
            eprintln!("TSO error: {msg}");
            return;
        }
    }

    println!("TSO mode — trying simultaneous TCP open (102s)...");
    reader.get_mut().write_all(b"{\"cmd\":\"Subscribe\"}\n").ok();
    line.clear();
    let start = std::time::Instant::now();
    loop {
        line.clear();
        match read_line_timeout(&mut reader, 5) {
            Ok(l) => line = l,
            Err(_) => break,
        }
        if start.elapsed().as_secs() > 110 {
            println!("TSO timeout — both peers must run 'lain tso' within 102 seconds");
            break;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            if let Some(ev) = v.get("event").and_then(|e| e.as_str()) {
                match ev {
                    "peer_connected" => {
                        let pid = v.get("peer_id").and_then(|p| p.as_str()).unwrap_or("?");
                        let via = v.get("data").and_then(|d| d.get("via")).and_then(|v| v.as_str()).unwrap_or("TSO");
                        println!("connected to {pid} via {via}");
                        break;
                    }
                    "peer_error" => {
                        let err = v.get("data").and_then(|d| d.get("error")).and_then(|e| e.as_str()).unwrap_or("?");
                        println!("TSO failed: {err}");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn find_and_connect(socket_path: &PathBuf, peer_id: &str) {
    let mut stream = match IpcStream::connect(socket_path) {
        Ok(s) => s,
        Err(e) => { eprintln!("cannot connect to daemon: {e}"); return; }
    };
    let req = serde_json::json!({"cmd":"FindPeer","peer_id":peer_id}).to_string() + "\n";
    stream.write_all(req.as_bytes()).ok();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok();

    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
        if v.get("type").and_then(|t| t.as_str()) == Some("Error") {
            let msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("?");
            eprintln!("find error: {msg}");
            return;
        }
    }

    println!("searching DHT...");
    reader.get_mut().write_all(b"{\"cmd\":\"Subscribe\"}\n").ok();
    line.clear();
    let start = std::time::Instant::now();
    loop {
        line.clear();
        if reader.read_line(&mut line).is_err() { break; }
        if start.elapsed().as_secs() > 15 {
            println!("not found");
            break;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            if let Some(ev) = v.get("event").and_then(|e| e.as_str()) {
                match ev {
                    "peer_connected" => {
                        let pid = v.get("peer_id").and_then(|p| p.as_str()).unwrap_or("?");
                        println!("connected to {pid}");
                        break;
                    }
                    "peer_error" => {
                        let err = v.get("data").and_then(|d| d.get("error")).and_then(|e| e.as_str()).unwrap_or("?");
                        println!("could not connect: {err}");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn monitor_loop(socket_path: &PathBuf) {
    let mut stream = match IpcStream::connect(socket_path) {
        Ok(s) => s,
        Err(e) => { eprintln!("cannot connect to daemon: {e}"); return; }
    };
    stream.write_all(b"{\"cmd\":\"Subscribe\"}\n").ok();
    println!("monitoring... (Ctrl+C to stop)");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        match read_line_timeout(&mut reader, 5) {
            Ok(l) => line = l,
            Err(_) => break,
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            // Skip non-event messages (e.g. subscription confirmation)
            let event = match v.get("event").and_then(|e| e.as_str()) {
                Some(e) => e,
                None => continue,
            };
            let peer = v.get("peer_id").and_then(|p| p.as_str()).unwrap_or("-");
            match event {
                "peer_connected" => println!("[connected] {peer}"),
                "data" => {
                    if let Some(data_field) = v.get("data") {
                        if let Some(b64) = data_field.get("bytes").and_then(|b| b.as_str()) {
                            use base64::Engine;
                            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
                                println!("[data] from {peer} ({} bytes)", bytes.len());
                            }
                        }
                    }
                },
                _ => println!("[{event}] {peer}"),
            }
        }
    }
}

fn print_status(v: &serde_json::Value) {
    let data = v.get("data").and_then(|d| d.as_object());
    let pid = data.and_then(|d| d.get("peer_id")).and_then(|p| p.as_str()).unwrap_or("?");
    let nat = data.and_then(|d| d.get("nat_type")).and_then(|p| p.as_str()).unwrap_or("?");
    let ipv6_avail = data.and_then(|d| d.get("ipv6")).and_then(|p| p.as_bool()).unwrap_or(false);
    let ipv6_addr = data.and_then(|d| d.get("ipv6_addr")).and_then(|p| p.as_str()).unwrap_or("none");
    let port_delta = data.and_then(|d| d.get("port_delta")).and_then(|p| p.as_u64());
    let rtt = data.and_then(|d| d.get("stun_rtt_ms")).and_then(|p| p.as_u64());
    let dht = data.and_then(|d| d.get("dht_nodes")).and_then(|p| p.as_u64()).unwrap_or(0);
    let known = data.and_then(|d| d.get("known_peers")).and_then(|p| p.as_u64()).unwrap_or(0);
    let active = data.and_then(|d| d.get("connected_peers")).and_then(|p| p.as_u64()).unwrap_or(0);
    let peers = data.and_then(|d| d.get("peers")).and_then(|p| p.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()).unwrap_or_default();

    println!("PeerID:    {pid}");
    println!("NAT:       {nat}");
    if ipv6_avail {
        println!("IPv6:      {ipv6_addr}");
    } else {
        println!("IPv6:      no");
    }
    if let Some(d) = port_delta {
        let kind = if d == 1 { "port-preserving" } else if d > 1 { "fixed-offset" } else { "unknown" };
        println!("Port:      {kind} (delta={d})");
    }
    if let Some(r) = rtt { println!("STUN RTT:  {r}ms"); }
    println!("DHT nodes: {dht}");
    println!("Known:     {known}");
    println!("Connected: {active}");
    if !peers.is_empty() {
        println!("Peers:");
        for p in peers { println!("  {p}"); }
    }
}
