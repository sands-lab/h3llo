//! h3llo executable entrypoint.

#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use h3llo::config::Config;
use h3llo::orch::Orchestrator;
use std::env;
use std::fs::File;
use std::path::PathBuf;
use tracing::error;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    init_logging();

    let config_path = match parse_config_path() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("{err}");
            eprintln!("Usage: h3llo -c <config.yaml>");
            std::process::exit(2);
        }
    };

    let file = match File::open(&config_path) {
        Ok(file) => file,
        Err(err) => {
            error!("failed to open config {}: {}", config_path.display(), err);
            std::process::exit(1);
        }
    };

    let config = match Config::load_from_reader(file) {
        Ok(config) => config,
        Err(err) => {
            error!("failed to load config {}: {}", config_path.display(), err);
            std::process::exit(1);
        }
    };

    let orchestrator = match Orchestrator::new(config).await {
        Ok(o) => o,
        Err(err) => {
            error!("orchestrator initialization failed: {err}");
            std::process::exit(1);
        }
    };

    if let Err(err) = orchestrator.run().await {
        error!("orchestrator runtime failed: {err}");
        std::process::exit(1);
    }
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
fn parse_config_path() -> Result<PathBuf, String> {
    let mut args = env::args().skip(1);
    let mut config_path = None;

    while let Some(arg) = args.next() {
        if let Some(value) = arg
            .strip_prefix("--config=")
            .or_else(|| arg.strip_prefix("-c="))
        {
            config_path = Some(PathBuf::from(value));
        } else if matches!(arg.as_str(), "-c" | "--config") {
            let value = args
                .next()
                .ok_or_else(|| "missing value for -c/--config".to_string())?;
            config_path = Some(PathBuf::from(value));
        } else {
            return Err(format!("unknown argument: {arg}"));
        }
    }

    config_path.ok_or_else(|| "missing -c/--config".to_string())
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
