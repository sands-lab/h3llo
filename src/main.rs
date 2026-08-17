//! h3llo executable entrypoint.

#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::{bail, Context, Result};
use h3llo::config::Config;
use std::env;
use std::fs::File;
use std::path::{Path, PathBuf};
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    init_logging();

    let config_path = parse_config_path()?;
    run(&config_path).await
}

async fn run(config_path: &Path) -> Result<()> {
    let file = File::open(config_path)
        .with_context(|| format!("open configuration file `{}`", config_path.display()))?;
    let config = Config::load_from_reader(file)
        .with_context(|| format!("load configuration from `{}`", config_path.display()))?;

    h3llo::run(config).await.context("run h3llo")
}

fn init_logging() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn,h3llo=info"));

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(std::io::stderr)
        .init();

    // Bridge foundations/slog → tracing subscriber.
    // tokio-quiche logs via foundations::telemetry::log macros, which use an
    // internal OnceLock<LogHarness>. The tracing-rs-compat feature installs
    // TracingSlogDrain as the root slog drain, forwarding all slog records
    // into the active tracing subscriber. This is a one-shot call.
    let service_info = foundations::ServiceInfo {
        name: "h3llo",
        ..Default::default()
    };
    let settings = foundations::telemetry::settings::TelemetrySettings {
        logging: foundations::telemetry::settings::LoggingSettings {
            output: foundations::telemetry::settings::LogOutput::TracingRsCompat,
            // Let tracing's EnvFilter handle all level filtering.
            // Default LogVerbosity::Info would silently discard debug/trace
            // slog records before they reach the tracing subscriber.
            verbosity: foundations::telemetry::settings::LogVerbosity::Trace,
            ..Default::default()
        },
        ..Default::default()
    };
    if let Err(e) = foundations::telemetry::init(foundations::telemetry::TelemetryConfig {
        service_info: &service_info,
        settings: &settings,
    }) {
        eprintln!("failed to init foundations telemetry: {e}");
    }
}

/// Parses the config file path from command-line arguments (`-c` / `--config`).
fn parse_config_path() -> Result<PathBuf> {
    let mut args = env::args().skip(1);
    let mut config_path = None;

    while let Some(arg) = args.next() {
        if let Some(value) = arg
            .strip_prefix("--config=")
            .or_else(|| arg.strip_prefix("-c="))
        {
            config_path = Some(PathBuf::from(value));
        } else if matches!(arg.as_str(), "-c" | "--config") {
            let value = args.next().context("missing value for -c/--config")?;
            config_path = Some(PathBuf::from(value));
        } else {
            bail!("unknown argument: {arg}");
        }
    }

    config_path.context("missing -c/--config")
}

#[cfg(test)]
mod tests {
    use tracing_subscriber::EnvFilter;

    #[test]
    fn default_filter_parses() {
        // Ensure the hardcoded default filter string is syntactically valid.
        let filter = EnvFilter::new("warn,h3llo=info");
        // EnvFilter::new panics on invalid syntax, so reaching here is success.
        drop(filter);
    }
}
