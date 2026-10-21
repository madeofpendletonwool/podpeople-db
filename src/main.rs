use std::net::SocketAddr;

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,tower_http=warn")))
        .init();

    let config = podpeople::config::Config::from_env();
    let port = config.port;
    let crawler = config.crawler_enabled;
    let state = match podpeople::init(config).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("startup failed: {e}");
            std::process::exit(1);
        }
    };
    if crawler {
        tokio::spawn(podpeople::crawler::run(state.clone()));
    }

    let app = podpeople::router(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    tracing::info!("PodPeopleDB listening on {addr}");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server");
}
