//! h3llo executable entrypoint.

use h3llo::config::Config;
use h3llo::orch::run_bare;
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

    if let Err(err) = run_bare(config).await {
        error!("bare runtime failed: {err}");
        std::process::exit(1);
    }
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("h3llo=info"));

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(std::io::stderr)
        .init();
}

fn parse_config_path() -> Result<PathBuf, String> {
    let mut args = env::args().skip(1);
    let mut config_path = None;

    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--config=") {
            config_path = Some(PathBuf::from(value));
            continue;
        }
        if let Some(value) = arg.strip_prefix("-c=") {
            config_path = Some(PathBuf::from(value));
            continue;
        }
        match arg.as_str() {
            "-c" | "--config" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for -c/--config".to_string())?;
                config_path = Some(PathBuf::from(value));
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    config_path.ok_or_else(|| "missing -c/--config".to_string())
}
