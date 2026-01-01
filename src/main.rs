//! h3llo executable entrypoint.

use h3llo::config::Config;
use h3llo::orch::run_bare;
use log::{error, LevelFilter, Log, Metadata, Record};
use std::env;
use std::fs::File;
use std::path::PathBuf;

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
    static LOGGER: SimpleLogger = SimpleLogger;
    let level = env::var("RUST_LOG")
        .ok()
        .and_then(|value| parse_level(&value))
        .unwrap_or(LevelFilter::Info);
    let _ = log::set_logger(&LOGGER).map(|()| log::set_max_level(level));
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

struct SimpleLogger;

impl Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            eprintln!("{} [{}] {}", record.level(), record.target(), record.args());
        }
    }

    fn flush(&self) {}
}

fn parse_level(value: &str) -> Option<LevelFilter> {
    for part in value.split(',') {
        let level = part.split('=').next_back().unwrap_or(part).trim();
        let parsed = match level.to_ascii_lowercase().as_str() {
            "trace" => Some(LevelFilter::Trace),
            "debug" => Some(LevelFilter::Debug),
            "info" => Some(LevelFilter::Info),
            "warn" | "warning" => Some(LevelFilter::Warn),
            "error" => Some(LevelFilter::Error),
            _ => None,
        };
        if parsed.is_some() {
            return parsed;
        }
    }
    None
}
