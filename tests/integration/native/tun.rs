//! TUN integration test orchestrator.
//!
//! Runs the `integration-container-tun` binary (pre-built inside Docker image)
//! in a privileged container and waits for it to exit with code 0.
//!
//! Implements the Container Test Pattern documented in `docs/test.md`.
//!
//! Run with:
//! ```bash
//! docker buildx build --target test -t h3llo:test --load .  # build image with embedded binaries
//! cargo test --test integration -- tun --ignored --nocapture
//! ```

use testcontainers::core::wait::ExitWaitStrategy;
use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

use super::common::{
    ensure_image_exists, get_container_exit_code, CONTAINER_TUN_BINARY, TEST_IMAGE, TEST_TAG,
};

/// Runs the TUN integration test binary inside a privileged Docker container.
///
/// The container binary exercises `h3llo::tun::make_tun()` with real TUN
/// devices, verifying device creation, multi-address assignment, and MTU.
#[tokio::test]
#[ignore = "requires Docker and pre-built test image with embedded binaries"]
async fn tun_container_integration() {
    if !ensure_image_exists(TEST_IMAGE, TEST_TAG) {
        panic!(
            "Docker image {TEST_IMAGE}:{TEST_TAG} not found. Build with:\n  \
             docker buildx build --target test -t {TEST_IMAGE}:{TEST_TAG} --load ."
        );
    }

    eprintln!("Using embedded test binary: {CONTAINER_TUN_BINARY}");

    let container = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_entrypoint(CONTAINER_TUN_BINARY)
        .with_wait_for(WaitFor::Exit(ExitWaitStrategy::new()))
        .with_privileged(true)
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
