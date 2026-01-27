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

use testcontainers::core::wait::ExitWaitStrategy;
use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

use super::common::{
    ensure_image_exists, find_test_binary, get_container_exit_code, TEST_IMAGE, TEST_TAG,
};

const BINARY_NAME: &str = "integration-container-route";
const CONTAINER_BINARY_PATH: &str = "/usr/local/bin/integration-container-route";

/// Runs the route integration test binary inside a privileged Docker container.
///
/// The container binary exercises `sync_tun_routes` with real `RouteManagerHandle`
/// (netlink API), verifying route installation and cleanup on dummy interfaces.
#[tokio::test]
#[ignore = "requires Docker, pre-built image, and pre-compiled container binary"]
async fn route_container_integration() {
    if !ensure_image_exists(TEST_IMAGE, TEST_TAG) {
        panic!(
            "Docker image {TEST_IMAGE}:{TEST_TAG} not found. Build with:\n  \
             docker build --target test -t {TEST_IMAGE}:{TEST_TAG} ."
        );
    }

    let binary_path = find_test_binary(BINARY_NAME);
    eprintln!("Using test binary: {}", binary_path.display());

    // Wait for container to exit without checking exit code - allows us to get logs first
    let container = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_entrypoint(CONTAINER_BINARY_PATH)
        .with_wait_for(WaitFor::Exit(ExitWaitStrategy::new()))
        .with_privileged(true)
        .with_copy_to(CONTAINER_BINARY_PATH, binary_path)
        .start()
        .await
        .expect("container should start");

    // Get container output before checking exit code
    let stderr = container.stderr_to_vec().await.unwrap_or_default();
    eprintln!("Container output:\n{}", String::from_utf8_lossy(&stderr));

    // Check exit code
    let exit_code = get_container_exit_code(container.id());
    if exit_code != Some(0) {
        panic!("container should exit with code 0, got: {:?}", exit_code);
    }
}
