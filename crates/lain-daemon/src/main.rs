#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

fn main() {
    tracing_subscriber::fmt::init();

    // rustls crypto provider must be installed before any QUIC activity
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => { tracing::error!("Failed to create tokio runtime: {e}"); return; }
    };

    rt.block_on(async {
        let config = match lain_daemon::config::DaemonConfig::load_or_default() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Config error: {e}");
                std::process::exit(1);
            }
        };

        let daemon = match lain_daemon::Daemon::new(config).await {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("Daemon init error: {e}");
                std::process::exit(1);
            }
        };

        if let Err(e) = daemon.run().await {
            tracing::error!("Daemon error: {e}");
        }
    });
}
