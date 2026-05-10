#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "lain", about = "Zero-server P2P network daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to IPC socket (default: ~/.lain/socket)
    #[arg(short = 's', long, default_value = "")]
    socket: String,
}

fn ipc_socket(path: &str) -> PathBuf {
    if !path.is_empty() {
        return PathBuf::from(path);
    }
    // Default: ~/.lain/socket
    #[cfg(unix)]
    { dirs_home().map(|d| d.join(".lain").join("socket")).unwrap_or_else(|| PathBuf::from("/tmp/lain.socket")) }
    #[cfg(windows)]
    { r"\\.\pipe\lain".into() }
}

#[cfg(unix)]
fn dirs_home() -> Option<PathBuf> {
    if let Ok(h) = std::env::var("LAIN_HOME") { return Some(PathBuf::from(h)); }
    if let Ok(h) = std::env::var("HOME") { return Some(PathBuf::from(h)); }
    None
}

#[derive(Subcommand)]
enum Command {
    /// Show own PeerID
    Whoami,
    /// Generate invite code
    Invite,
    /// Connect to a peer via invite
    Connect { invite: String },
    /// Show daemon status
    Status,
}

fn main() {
    let cli = Cli::parse();
    let socket_path = ipc_socket(&cli.socket);

    match cli.command.unwrap_or(Command::Status) {
        Command::Whoami => {
            if let Some(v) = ipc_request(&socket_path, r#"{"cmd":"Whoami"}"#) {
                if let Some(msg) = v.get("message").and_then(|m| m.as_str()) {
                    println!("PeerID: {}", msg);
                }
            }
        },
        Command::Invite => {
            if let Some(v) = ipc_request(&socket_path, r#"{"cmd":"GetInvite"}"#) {
                if let Some(msg) = v.get("message").and_then(|m| m.as_str()) {
                    println!("Invite: {}", msg);
                }
            }
        },
        Command::Connect { invite } => {
            let req = serde_json::json!({"cmd":"Connect","invite":invite}).to_string();
            let _ = ipc_request(&socket_path, &req);
            println!("connecting... (use 'lain status' to check)");
        }
        Command::Status => {
            let resp = ipc_request(&socket_path, r#"{"cmd":"ListPeers"}"#);
            if let Some(v) = resp {
                print_status(&v);
            }
        }
    }
}

fn ipc_request(socket_path: &PathBuf, json: &str) -> Option<serde_json::Value> {
    #[cfg(unix)]
    {
        use std::io::{BufRead, BufReader, Write};
        match std::os::unix::net::UnixStream::connect(socket_path) {
            Ok(mut stream) => {
                let mut req = json.to_string() + "\n";
                stream.write_all(req.as_bytes()).ok();
                let mut reader = BufReader::new(&stream);
                let mut response = String::new();
                if reader.read_line(&mut response).is_ok() {
                    return serde_json::from_str::<serde_json::Value>(&response).ok();
                }
            }
            Err(_) => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = socket_path;
        let _ = json;
    }

    None
}

fn print_status(v: &serde_json::Value) {
    let data = v.get("data").and_then(|d| d.as_object());
    let peer_id = data.and_then(|d| d.get("peer_id")).and_then(|p| p.as_str()).unwrap_or("?");
    let nat = data.and_then(|d| d.get("nat_type")).and_then(|p| p.as_str()).unwrap_or("?");
    let ipv6 = data.and_then(|d| d.get("ipv6")).and_then(|p| p.as_bool()).unwrap_or(false);
    let dht = data.and_then(|d| d.get("dht_nodes")).and_then(|p| p.as_u64()).unwrap_or(0);
    let known = data.and_then(|d| d.get("known_peers")).and_then(|p| p.as_u64()).unwrap_or(0);
    let active = data.and_then(|d| d.get("connected_peers")).and_then(|p| p.as_u64()).unwrap_or(0);
    let peers = data.and_then(|d| d.get("peers")).and_then(|p| p.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()).unwrap_or_default();

    println!("PeerID:    {}", peer_id);
    println!("NAT:       {}", nat);
    println!("IPv6:      {}", if ipv6 { "yes" } else { "no" });
    println!("DHT nodes: {}", dht);
    println!("Known:     {}", known);
    println!("Connected: {}", active);
    if !peers.is_empty() {
        println!("Peers:");
        for p in peers { println!("  {}", p); }
    }
}
