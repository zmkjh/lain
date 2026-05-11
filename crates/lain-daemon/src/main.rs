#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

fn main() {
    tracing_subscriber::fmt::init();

    // rustls crypto provider must be installed before any QUIC activity
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

    rt.block_on(async {
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
    });
}
