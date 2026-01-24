//! Route sync integration test orchestrator.
//!
//! Copies the `integration-container-route` binary into a privileged Docker
//! container and waits for it to exit with code 0.
//!
//! Implements the Container Test Pattern documented in `docs/test.md`.
//!
//! Run with:
//! ```bash
//! cargo test --test integration-container-route --no-run  # build container binary
//! cargo test --test integration -- route --ignored --nocapture
//! ```

use std::path::PathBuf;
use std::process::Command;

use testcontainers::core::wait::ExitWaitStrategy;
use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

const TEST_IMAGE: &str = "h3llo";
const TEST_TAG: &str = "test";
const BINARY_NAME: &str = "integration-container-route";
const CONTAINER_BINARY_PATH: &str = "/usr/local/bin/integration-container-route";

/// Locates the compiled container test binary in the target directory.
///
/// `cargo test --no-run` places binaries in `target/{profile}/deps/` with
/// underscores replacing hyphens and a hash suffix (e.g.,
/// `integration_container_route-abc123`). This function finds the matching
/// executable by prefix.
fn find_test_binary() -> PathBuf {
    let target_dir =
        PathBuf::from(std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string()));

    // Binary name uses underscores in the deps directory
    let deps_prefix = BINARY_NAME.replace('-', "_");

    for profile in ["debug", "release"] {
        let deps_dir = target_dir.join(profile).join("deps");
        if let Ok(entries) = std::fs::read_dir(&deps_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                // Match: prefix + '-' + hash, exclude .d metadata files
                if name_str.starts_with(&deps_prefix)
                    && !name_str.ends_with(".d")
                    && entry.file_type().map(|t| t.is_file()).unwrap_or(false)
                {
                    return entry.path();
                }
            }
        }
    }

    panic!(
        "Cannot find test binary '{BINARY_NAME}'. Build it first with:\n  \
         cargo test --test {BINARY_NAME} --no-run"
    );
}

/// Checks if the h3llo:test Docker image exists locally.
fn ensure_image_exists() -> bool {
    let output = Command::new("docker")
        .args(["image", "inspect", &format!("{TEST_IMAGE}:{TEST_TAG}")])
        .output();
    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

/// Runs the route integration test binary inside a privileged Docker container.
///
/// The container binary exercises `sync_tun_routes` with real `RouteManagerHandle`
/// (netlink API), verifying route installation and cleanup on dummy interfaces.
#[tokio::test]
#[ignore = "requires Docker, pre-built image, and pre-compiled container binary"]
async fn route_container_integration() {
    if !ensure_image_exists() {
        panic!(
            "Docker image {TEST_IMAGE}:{TEST_TAG} not found. Build with:\n  \
             docker build --target test -t {TEST_IMAGE}:{TEST_TAG} ."
        );
    }

    let binary_path = find_test_binary();
    eprintln!("Using test binary: {}", binary_path.display());

    let container = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_entrypoint(CONTAINER_BINARY_PATH)
        .with_wait_for(WaitFor::Exit(ExitWaitStrategy::new().with_exit_code(0)))
        .with_privileged(true)
        .with_copy_to(CONTAINER_BINARY_PATH, binary_path)
        .start()
        .await
        .expect("container should start and exit successfully");

    let stderr = container.stderr_to_vec().await.unwrap_or_default();
    eprintln!("Container output:\n{}", String::from_utf8_lossy(&stderr));
}
