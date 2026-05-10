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
        Command::Whoami => ipc_request(&socket_path, r#"{"cmd":"Whoami"}"#),
        Command::Invite => ipc_request(&socket_path, r#"{"cmd":"GetInvite"}"#),
        Command::Connect { invite } => {
            let req = serde_json::json!({"cmd":"Connect","invite":invite}).to_string();
            ipc_request(&socket_path, &req);
        }
        Command::Status => ipc_request(&socket_path, r#"{"cmd":"ListPeers"}"#),
    }
}

fn ipc_request(socket_path: &PathBuf, json: &str) {
    #[cfg(unix)]
    {
        use std::io::{BufRead, BufReader, Write, Read};
        match std::os::unix::net::UnixStream::connect(socket_path) {
            Ok(mut stream) => {
                let mut req = json.to_string() + "\n";
                stream.write_all(req.as_bytes()).ok();
                let mut reader = BufReader::new(&stream);
                let mut response = String::new();
                if reader.read_line(&mut response).is_ok() {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&response) {
                        println!("{}", serde_json::to_string_pretty(&v).unwrap_or(response));
                    }
                }
                return;
            }
            Err(_) => {}
        }
    }

    #[cfg(not(unix))]
    {
        // Try HTTP IPC on localhost
        let _ = socket_path;
        let _ = json;
    }

    // Fallback: daemon not running
    println!("daemon not running");
}
