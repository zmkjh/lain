#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use clap::{Parser, Subcommand};
#[cfg_attr(not(unix), allow(unused_imports))]
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "lain", about = "Zero-server P2P network daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(short = 's', long, default_value = "")]
    socket: String,
    /// Run in foreground (log to stdout instead of file)
    #[arg(short = 'f', long)]
    foreground: bool,
}

fn ipc_socket(path: &str) -> PathBuf {
    if !path.is_empty() { return PathBuf::from(path); }
    #[cfg(unix)] { dirs_home().map(|d| d.join(".lain").join("socket")).unwrap_or_else(|| PathBuf::from("/tmp/lain.socket")) }
    #[cfg(windows)] { r"\\.\pipe\lain".into() }
}

#[cfg(unix)]
fn dirs_home() -> Option<PathBuf> {
    if let Ok(h) = std::env::var("LAIN_HOME") { return Some(PathBuf::from(h)); }
    if let Ok(h) = std::env::var("HOME") { return Some(PathBuf::from(h)); }
    None
}

#[derive(Subcommand)]
enum Command {
    /// Start the daemon
    Daemon,
    Whoami,
    Invite,
    Connect { invite: String },
    Send { peer_id: String, file: String },
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
        // Log to file
        let log_path = {
            let mut d = if let Ok(h) = std::env::var("LAIN_HOME") {
                PathBuf::from(h)
            } else if let Ok(h) = std::env::var("HOME") {
                PathBuf::from(h).join(".lain")
            } else {
                PathBuf::from(".")
            };
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

    match cli.command.unwrap_or(Command::Daemon) {
        Command::Daemon => run_daemon(cli.foreground),
        Command::Whoami => {
            match ipc_req(&socket_path, r#"{"cmd":"Whoami"}"#) {
                Some(v) => {
                    let pid = v.get("message").and_then(|m| m.as_str()).unwrap_or("?");
                    println!("PeerID: {pid}");
                }
                None => eprintln!("daemon not running"),
            }
        }
        Command::Invite => {
            match ipc_req(&socket_path, r#"{"cmd":"GetInvite"}"#) {
                Some(v) => {
                    let inv = v.get("message").and_then(|m| m.as_str()).unwrap_or("?");
                    println!("Invite: {inv}");
                }
                None => eprintln!("daemon not running"),
            }
        }
        Command::Connect { invite } => connect_feedback(&socket_path, &invite),
        Command::Send { peer_id, file } => send_file(&socket_path, &peer_id, &file),
        Command::Monitor => monitor_loop(&socket_path),
        Command::Shutdown => {
            let _ = ipc_req(&socket_path, r#"{"cmd":"Shutdown"}"#);
            println!("daemon shutting down");
        }
        Command::Status => {
            match ipc_req(&socket_path, r#"{"cmd":"ListPeers"}"#) {
                Some(v) => print_status(&v),
                None => eprintln!("daemon not running"),
            }
        }
    }
}

fn run_daemon(foreground: bool) {
    let rt = tokio::runtime::Runtime::new().expect("tokio");
    rt.block_on(async {
        let config = lain_daemon::config::DaemonConfig::load_or_default().unwrap_or_default();
        match lain_daemon::Daemon::new(config).await {
            Ok(daemon) => {
                let pid = daemon.peer_id();
                // Always print PeerID to stdout
                if !foreground {
                    println!("Lain daemon started");
                    println!("PeerID: {pid}");
                    println!("Logs: ~/.lain/daemon.log");
                }
                if let Err(e) = daemon.run().await {
                    eprintln!("daemon error: {e}");
                }
            }
            Err(e) => eprintln!("daemon init failed: {e}"),
        }
    });
}

fn ipc_req(socket_path: &PathBuf, json: &str) -> Option<serde_json::Value> {
    #[cfg(unix)]
    {
        let mut stream = std::os::unix::net::UnixStream::connect(socket_path).ok()?;
        let mut req = json.to_string() + "\n";
        stream.write_all(req.as_bytes()).ok()?;
        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        reader.read_line(&mut response).ok()?;
        serde_json::from_str(&response).ok()
    }
    #[cfg(not(unix))]
    {
        let _ = socket_path; let _ = json;
        None
    }
}

#[cfg_attr(not(unix), allow(unused_variables))]
fn connect_feedback(socket_path: &PathBuf, invite: &str) {
    let owned;
    let invite = if !invite.starts_with("lain://") {
        owned = format!("lain://{invite}");
        &owned
    } else {
        invite
    };
    #[cfg(unix)]
    {
        let mut stream = match std::os::unix::net::UnixStream::connect(socket_path) {
            Ok(s) => s,
            Err(e) => { eprintln!("cannot connect to daemon: {e}"); return; }
        };
        // Send connect
        let req = serde_json::json!({"cmd":"Connect","invite":invite}).to_string() + "\n";
        stream.write_all(req.as_bytes()).ok();
        // Read OK
        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        reader.read_line(&mut line).ok();
        println!("connecting...");
        // Subscribe
        stream.write_all(b"{\"cmd\":\"Subscribe\"}\n").ok();
        line.clear();
        let start = std::time::Instant::now();
        loop {
            line.clear();
            if reader.read_line(&mut line).is_err() { break; }
            if start.elapsed().as_secs() > 15 {
                println!("timeout — check 'lain status'");
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
        return;
    }
    eprintln!("not supported on this platform");
}

fn send_file(socket_path: &PathBuf, peer_id: &str, file: &str) {
    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => { eprintln!("cannot read {file}: {e}"); return; }
    };
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
    let req = serde_json::json!({"cmd":"Send","peer_id":peer_id,"data":b64}).to_string();
    if let Some(resp) = ipc_req(socket_path, &req) {
        if resp.get("type").and_then(|t| t.as_str()) == Some("Ok") {
            println!("sent {} bytes to {peer_id}", data.len());
        }
    }
}

#[cfg_attr(not(unix), allow(unused_variables))]
fn monitor_loop(socket_path: &PathBuf) {
    #[cfg(unix)]
    {
        let mut stream = match std::os::unix::net::UnixStream::connect(socket_path) {
            Ok(s) => s,
            Err(e) => { eprintln!("cannot connect to daemon: {e}"); return; }
        };
        stream.write_all(b"{\"cmd\":\"Subscribe\"}\n").ok();
        println!("monitoring events... (Ctrl+C to stop)");
        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).is_err() { break; }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                let event = v.get("event").and_then(|e| e.as_str()).unwrap_or("?");
                let peer = v.get("peer_id").and_then(|p| p.as_str()).unwrap_or("-");
                match event {
                    "peer_connected" => println!("[connected] {peer}"),
                    "incoming_connection" => println!("[incoming] {peer}"),
                    "data" => {
                        // Try to save received data as file
                        if let Some(data_field) = v.get("data") {
                            if let Some(b64) = data_field.get("bytes").and_then(|b| b.as_str()) {
                                use base64::Engine;
                                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
                                    let filename = format!("received_from_{peer}.bin");
                                    let _ = std::fs::write(&filename, &bytes);
                                    println!("[data] from {peer} → saved {filename} ({} bytes)", bytes.len());
                                }
                            } else {
                                println!("[data] from {peer}");
                            }
                        }
                    },
                    _ => println!("[{event}] {peer}"),
                }
            }
        }
        return;
    }
    eprintln!("not supported on this platform");
}

fn print_status(v: &serde_json::Value) {
    let data = v.get("data").and_then(|d| d.as_object());
    let pid = data.and_then(|d| d.get("peer_id")).and_then(|p| p.as_str()).unwrap_or("?");
    let nat = data.and_then(|d| d.get("nat_type")).and_then(|p| p.as_str()).unwrap_or("?");
    let ipv6 = data.and_then(|d| d.get("ipv6")).and_then(|p| p.as_bool()).unwrap_or(false);
    let dht = data.and_then(|d| d.get("dht_nodes")).and_then(|p| p.as_u64()).unwrap_or(0);
    let known = data.and_then(|d| d.get("known_peers")).and_then(|p| p.as_u64()).unwrap_or(0);
    let active = data.and_then(|d| d.get("connected_peers")).and_then(|p| p.as_u64()).unwrap_or(0);
    let peers = data.and_then(|d| d.get("peers")).and_then(|p| p.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()).unwrap_or_default();

    println!("PeerID:    {pid}");
    println!("NAT:       {nat}");
    println!("IPv6:      {}", if ipv6 { "yes" } else { "no" });
    println!("DHT nodes: {dht}");
    println!("Known:     {known}");
    println!("Connected: {active}");
    if !peers.is_empty() {
        println!("Peers:");
        for p in peers { println!("  {p}"); }
    }
}
