use std::{future::Future, net::SocketAddr, process::ExitCode, sync::Arc, time::Duration};

use tokio::{net::TcpListener, sync::watch};

use super::{
    routes::{internal_router, public_router},
    settings::{GatewayArgs, Settings},
    state::GatewayState,
};
use crate::{
    clock,
    lang::{tr, Lang},
};

/// How long in-flight requests get to finish after a shutdown signal.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
const RELAY_DRAIN: Duration = Duration::from_secs(5);
const CLOCK_RESYNC: Duration = Duration::from_secs(30 * 60);

/// Serves both routers until `shutdown` resolves, then drains connections
/// (bounded by [`SHUTDOWN_GRACE`]).
pub async fn serve(
    state: Arc<GatewayState>,
    public: TcpListener,
    internal: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        shutdown.await;
        let _ = tx.send(true);
    });

    let stop = |mut rx: watch::Receiver<bool>| async move {
        let _ = rx.wait_for(|v| *v).await;
    };
    let public =
        axum::serve(public, public_router(state.clone())).with_graceful_shutdown(stop(rx.clone()));
    let internal =
        axum::serve(internal, internal_router(state)).with_graceful_shutdown(stop(rx.clone()));
    let both = async { tokio::try_join!(public, internal).map(|_| ()) };

    // Keep-alive connections could hold a graceful shutdown open forever.
    let deadline = async {
        let mut rx = rx;
        let _ = rx.wait_for(|v| *v).await;
        tokio::time::sleep(SHUTDOWN_GRACE).await;
    };
    tokio::select! {
        r = both => r,
        () = deadline => {
            tracing::warn!("forcing shutdown with connections still open");
            Ok(())
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = term => {} }
}

pub async fn run(args: GatewayArgs, lang: Lang) -> anyhow::Result<ExitCode> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .try_init();

    let from_flag =
        args.gateway_secret.is_some() && std::env::var_os("XENTREE_GATEWAY_SECRET").is_none();
    let cwd = std::env::current_dir()?;
    let settings = Settings::from_args(args, &cwd, lang)?;
    warn_about_risky_setup(&settings, from_flag, lang);

    let base_url = settings.config.base_url.clone();
    let (bind, internal_bind) = (settings.bind, settings.internal_bind);
    let state = Arc::new(GatewayState::new(settings)?);

    // Calibrate before serving: a skewed clock makes every launch fail.
    sync_clock(&state, &base_url).await;
    let resync = tokio::spawn({
        let (state, base_url) = (state.clone(), base_url);
        async move {
            loop {
                tokio::time::sleep(CLOCK_RESYNC).await;
                sync_clock(&state, &base_url).await;
            }
        }
    });

    let public = listen(bind, lang).await?;
    let internal = listen(internal_bind, lang).await?;
    eprintln!(
        "{}",
        tr(
            lang,
            "gateway.listening_public",
            &[("addr", &public.local_addr()?.to_string())]
        )
    );
    eprintln!(
        "{}",
        tr(
            lang,
            "gateway.listening_internal",
            &[("addr", &internal.local_addr()?.to_string())]
        )
    );

    serve(state.clone(), public, internal, shutdown_signal()).await?;

    eprintln!("{}", tr(lang, "gateway.shutdown", &[]));
    resync.abort();
    state.drain(RELAY_DRAIN).await;
    // Last owner: dropping the state zeroizes the stored signing key.
    drop(state);
    Ok(ExitCode::SUCCESS)
}

async fn listen(addr: SocketAddr, lang: Lang) -> anyhow::Result<TcpListener> {
    TcpListener::bind(addr).await.map_err(|e| {
        anyhow::anyhow!(tr(
            lang,
            "gateway.error.bind",
            &[("addr", &addr.to_string()), ("error", &e.to_string())]
        ))
    })
}

async fn sync_clock(state: &GatewayState, base_url: &str) {
    match clock::measure(&clock::Options::new(base_url)).await {
        Ok(skew) => {
            skew.log();
            state.set_clock_offset(skew.signer_offset_secs());
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not measure the clock; keeping the previous offset")
        }
    }
}

fn warn_about_risky_setup(s: &Settings, secret_from_flag: bool, lang: Lang) {
    let warn = |key: &str, args: &[(&str, &str)]| eprintln!("{}", tr(lang, key, args));
    if secret_from_flag {
        warn("gateway.warn.flag_secret", &[]);
    }
    if !s.internal_bind.ip().is_loopback() {
        warn(
            "gateway.warn.internal_exposed",
            &[("addr", &s.internal_bind.to_string())],
        );
    }
    if s.allow_query_secret {
        warn("gateway.warn.query_secret", &[]);
    }
    if !s.trusted_headers.is_empty() {
        let names: Vec<&str> = s.trusted_headers.iter().map(|h| h.as_str()).collect();
        warn(
            "gateway.warn.trusted_headers",
            &[("names", &names.join(", "))],
        );
    }
    if s.webhook.is_none() {
        warn("gateway.warn.no_webhook", &[]);
    }
    warn("gateway.warn.no_tls", &[]);
}
