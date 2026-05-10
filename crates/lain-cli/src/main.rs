#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use clap::{Parser, Subcommand};
use lain_core::identity::IdentityProvider;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "lain", about = "Zero-server P2P network daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[arg(short, long, default_value = "lain.toml")]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Command {
    Daemon,
    Invite,
    Status,
    Connect {
        invite: String,
    },
    Whoami,
}

fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

    rt.block_on(async {
        match cli.command.unwrap_or(Command::Daemon) {
            Command::Daemon => {
                tracing::info!("Lain daemon starting...");
                let config = lain_daemon::config::DaemonConfig::load_or_default()
                    .map_err(|e| {
                        tracing::error!("Config error: {e}");
                        std::process::exit(1);
                    })
                    .ok()
                    .unwrap();

                let daemon = lain_daemon::Daemon::new(config)
                    .await
                    .map_err(|e| {
                        tracing::error!("Daemon init error: {e}");
                        std::process::exit(1);
                    })
                    .ok()
                    .unwrap();

                if let Err(e) = daemon.run().await {
                    tracing::error!("Daemon error: {e}");
                }
            }
            Command::Invite => {
                println!("Generating invite...");
                let id = lain_identity::Identity::load_or_generate().ok().unwrap();
                let invite = lain_discovery::InviteCode::new(
                    id.peer_id(),
                    *id.public_key(),
                    lain_core::capabilities::Capabilities::new(),
                    vec![],
                    &|data| id.sign(data),
                );
                let s = invite.to_base62();
                println!("Your invite: lain://{}", s);
            }
            Command::Status => {
                println!("Lain daemon status: check daemon socket");
            }
            Command::Connect { invite } => {
                println!("Connecting via invite: {invite}");
                if let Ok(code) = lain_discovery::InviteCode::from_uri(&invite)
                    .or_else(|_| lain_discovery::InviteCode::from_base62(&invite))
                {
                    println!("PeerID: {}", code.peer_id);
                    println!("Endpoints: {} found", code.endpoints.len());
                } else {
                    tracing::error!("Invalid invite code");
                }
            }
            Command::Whoami => {
                let id = lain_identity::Identity::load_or_generate().ok().unwrap();
                println!("PeerID: {}", id.peer_id());
            }
        }
    });
}
