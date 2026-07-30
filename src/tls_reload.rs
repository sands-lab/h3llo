//! Filesystem-driven TLS certificate reloading for the H3 listener.

use crate::actor::{ActorError, ActorExitResult};
use crate::config::H3Tuning;
use crate::h3listener::{make_server_quiche_config, DispatcherCommand};
use crate::h3session::CONNECT_IP_OVERHEAD;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{self, Instant};
use tracing::{debug, info, warn};

/// Quiet period used to coalesce multi-file certificate rotations.
const RELOAD_DEBOUNCE: Duration = Duration::from_millis(500);
/// Bounded callback queue; one retained event is enough to trigger validation.
const WATCH_EVENT_QUEUE_DEPTH: usize = 64;

/// Errors returned while initializing certificate filesystem watches.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TlsReloadError {
    /// A configured credential path could not be made absolute.
    #[error("failed to resolve credential path `{path}`: {source}")]
    ResolvePath {
        /// Configured credential path.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// The platform's recommended watcher could not be created.
    #[error("failed to create filesystem watcher: {0}")]
    CreateWatcher(notify::Error),
    /// A credential parent directory could not be watched.
    #[error("failed to watch credential directory `{path}`: {source}")]
    WatchDirectory {
        /// Directory containing a credential file.
        path: PathBuf,
        /// Underlying watcher error.
        source: notify::Error,
    },
}

/// Long-lived watcher state for an H3 listener's certificate and private key.
pub(crate) struct TlsReloader {
    /// Kept alive so native filesystem watches remain registered.
    _watcher: RecommendedWatcher,
    event_rx: mpsc::Receiver<notify::Result<Event>>,
    cert_path: PathBuf,
    key_path: PathBuf,
    h3_tuning: H3Tuning,
    max_udp_payload: usize,
    dispatcher_tx: mpsc::UnboundedSender<DispatcherCommand>,
}

impl TlsReloader {
    async fn run(mut self) -> ActorExitResult {
        let debounce = time::sleep(Duration::MAX);
        tokio::pin!(debounce);
        let mut reload_pending = false;

        info!(
            cert = %self.cert_path.display(),
            key = %self.key_path.display(),
            "TLS certificate watcher started"
        );

        loop {
            tokio::select! {
                event = self.event_rx.recv() => {
                    let Some(event) = event else {
                        return Err(ActorError::TlsReloader {
                            reason: "filesystem watcher event channel closed".into(),
                        });
                    };

                    match event {
                        Ok(event) if should_reload(&event) => {
                            debug!(
                                kind = ?event.kind,
                                paths = ?event.paths,
                                rescan = event.need_rescan(),
                                "TLS credential filesystem change detected"
                            );
                            debounce
                                .as_mut()
                                .reset(Instant::now() + RELOAD_DEBOUNCE);
                            reload_pending = true;
                        }
                        Ok(_) => {}
                        Err(error) => {
                            warn!(
                                %error,
                                "TLS certificate watcher reported an error; validating current files"
                            );
                            debounce
                                .as_mut()
                                .reset(Instant::now() + RELOAD_DEBOUNCE);
                            reload_pending = true;
                        }
                    }
                }

                () = &mut debounce, if reload_pending => {
                    reload_pending = false;
                    self.reload().await?;
                }
            }
        }
    }

    async fn reload(&self) -> ActorExitResult {
        let cert_path = self.cert_path.clone();
        let key_path = self.key_path.clone();
        let h3_tuning = self.h3_tuning.clone();
        let max_udp_payload = self.max_udp_payload;

        let loaded = tokio::task::spawn_blocking(move || {
            make_server_quiche_config(&h3_tuning, max_udp_payload, &cert_path, &key_path)
        })
        .await
        .map_err(|error| ActorError::TlsReloader {
            reason: format!("credential loader task failed: {error}"),
        })?;

        let config = match loaded {
            Ok(config) => config,
            Err(error) => {
                warn!(
                    %error,
                    cert = %self.cert_path.display(),
                    key = %self.key_path.display(),
                    "TLS certificate reload rejected; retaining previous certificate"
                );
                return Ok(());
            }
        };

        let (applied_tx, applied_rx) = oneshot::channel();
        self.dispatcher_tx
            .send(DispatcherCommand::ReplaceTlsConfig {
                config: Box::new(config),
                applied_tx,
            })
            .map_err(|_| ActorError::TlsReloader {
                reason: "H3 dispatcher command channel closed".into(),
            })?;
        applied_rx.await.map_err(|_| ActorError::TlsReloader {
            reason: "H3 dispatcher closed before applying TLS configuration".into(),
        })?;

        info!(
            cert = %self.cert_path.display(),
            key = %self.key_path.display(),
            "TLS certificate reloaded"
        );
        Ok(())
    }
}

/// Creates a certificate reloader without spawning its actor task.
///
/// Parent directories are watched rather than credential file inodes so
/// atomic rename and symlink-based rotation schemes remain observable.
pub(crate) fn make_tls_reloader(
    cert_path: &Path,
    key_path: &Path,
    tun_mtu: u16,
    h3_tuning: &H3Tuning,
    dispatcher_tx: mpsc::UnboundedSender<DispatcherCommand>,
) -> Result<TlsReloader, TlsReloadError> {
    let cert_path = absolute_path(cert_path)?;
    let key_path = absolute_path(key_path)?;
    let watch_directories = [cert_path.as_path(), key_path.as_path()]
        .into_iter()
        .filter_map(Path::parent)
        .map(Path::to_path_buf)
        .collect::<BTreeSet<_>>();

    let (event_tx, event_rx) = mpsc::channel(WATCH_EVENT_QUEUE_DEPTH);
    let mut watcher = notify::recommended_watcher(move |event| {
        let _ = event_tx.try_send(event);
    })
    .map_err(TlsReloadError::CreateWatcher)?;

    for directory in &watch_directories {
        watcher
            .watch(directory, RecursiveMode::NonRecursive)
            .map_err(|source| TlsReloadError::WatchDirectory {
                path: directory.clone(),
                source,
            })?;
    }

    Ok(TlsReloader {
        _watcher: watcher,
        event_rx,
        cert_path,
        key_path,
        h3_tuning: h3_tuning.clone(),
        max_udp_payload: usize::from(tun_mtu) + CONNECT_IP_OVERHEAD,
        dispatcher_tx,
    })
}

/// Spawns the certificate reloader on the current Tokio runtime.
pub(crate) fn spawn_tls_reloader(
    reloader: TlsReloader,
) -> tokio::task::JoinHandle<ActorExitResult> {
    tokio::spawn(reloader.run())
}

fn absolute_path(path: &Path) -> Result<PathBuf, TlsReloadError> {
    std::path::absolute(path).map_err(|source| TlsReloadError::ResolvePath {
        path: path.to_path_buf(),
        source,
    })
}

fn should_reload(event: &Event) -> bool {
    event.need_rescan() || !matches!(event.kind, EventKind::Access(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use std::fs;

    fn generate_pem_pair() -> (String, String) {
        let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(subject_alt_names).expect("cert generation");
        (cert.pem(), signing_key.serialize_pem())
    }

    fn write_pair(cert_path: &Path, key_path: &Path, cert: &str, key: &str) {
        fs::write(cert_path, cert).expect("write certificate");
        fs::write(key_path, key).expect("write private key");
    }

    async fn receive_and_ack_reload(command_rx: &mut mpsc::UnboundedReceiver<DispatcherCommand>) {
        let command = time::timeout(Duration::from_secs(3), command_rx.recv())
            .await
            .expect("timeout waiting for TLS reload")
            .expect("dispatcher command channel closed");
        let DispatcherCommand::ReplaceTlsConfig { applied_tx, .. } = command else {
            panic!("unexpected dispatcher command: {command:?}");
        };
        applied_tx.send(()).expect("acknowledge TLS reload");
    }

    #[test]
    fn ignores_read_only_access_events() {
        let event = Event::new(EventKind::Access(notify::event::AccessKind::Read));
        assert!(!should_reload(&event));
    }

    #[test]
    fn reloads_for_mutating_events() {
        let event = Event::new(EventKind::Modify(notify::event::ModifyKind::Any));
        assert!(should_reload(&event));
    }

    #[tokio::test]
    async fn reloads_atomically_replaced_credentials_more_than_once() {
        let directory = tempfile::tempdir().expect("create temp directory");
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        let (initial_cert, initial_key) = generate_pem_pair();
        write_pair(&cert_path, &key_path, &initial_cert, &initial_key);

        let (command_tx, mut command_rx) = mpsc::unbounded_channel();
        let reloader = make_tls_reloader(
            &cert_path,
            &key_path,
            1291,
            &H3Tuning::default(),
            command_tx,
        )
        .expect("create TLS reloader");
        let handle = spawn_tls_reloader(reloader);

        for generation in 0..2 {
            let (cert, key) = generate_pem_pair();
            let staged_cert = directory.path().join(format!("cert-{generation}.tmp"));
            let staged_key = directory.path().join(format!("key-{generation}.tmp"));
            write_pair(&staged_cert, &staged_key, &cert, &key);
            fs::rename(staged_cert, &cert_path).expect("replace certificate");
            fs::rename(staged_key, &key_path).expect("replace private key");
            receive_and_ack_reload(&mut command_rx).await;
        }

        handle.abort();
    }

    #[tokio::test]
    async fn rejects_mismatched_pair_then_recovers() {
        let directory = tempfile::tempdir().expect("create temp directory");
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        let (initial_cert, initial_key) = generate_pem_pair();
        write_pair(&cert_path, &key_path, &initial_cert, &initial_key);

        let (command_tx, mut command_rx) = mpsc::unbounded_channel();
        let reloader = make_tls_reloader(
            &cert_path,
            &key_path,
            1291,
            &H3Tuning::default(),
            command_tx,
        )
        .expect("create TLS reloader");
        let handle = spawn_tls_reloader(reloader);

        let (replacement_cert, replacement_key) = generate_pem_pair();
        fs::write(&cert_path, replacement_cert).expect("replace certificate");
        assert!(
            time::timeout(
                RELOAD_DEBOUNCE + Duration::from_millis(500),
                command_rx.recv()
            )
            .await
            .is_err(),
            "mismatched certificate and key must not replace the active configuration"
        );

        fs::write(&key_path, replacement_key).expect("replace private key");
        receive_and_ack_reload(&mut command_rx).await;

        handle.abort();
    }
}
