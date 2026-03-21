//! Shared utilities for native integration test orchestrators.
//!
//! Provides common helper functions for Container Test Pattern tests.

/// Default test image name.
pub const TEST_IMAGE: &str = "h3llo";

/// Default test image tag.
pub const TEST_TAG: &str = "test";

/// Container path for TUN test binary.
pub const CONTAINER_TUN_BINARY: &str = "/usr/local/bin/integration-container-tun";

/// Container path for route test binary.
pub const CONTAINER_ROUTE_BINARY: &str = "/usr/local/bin/integration-container-route";

/// Runs a future on the current tokio runtime from a synchronous context.
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
}

/// Returns a shared bollard Docker client.
fn docker() -> bollard::Docker {
    bollard::Docker::connect_with_local_defaults().expect("connect to Docker daemon")
}

/// Checks if a Docker image exists locally via the Docker API.
///
/// # Arguments
///
/// * `image` - Image name
/// * `tag` - Image tag
///
/// # Returns
///
/// `true` if the image exists, `false` otherwise.
pub fn ensure_image_exists(image: &str, tag: &str) -> bool {
    block_on(docker().inspect_image(&format!("{image}:{tag}"))).is_ok()
}

/// Gets the exit code of a container by ID via the Docker API.
///
/// # Arguments
///
/// * `container_id` - The Docker container ID
///
/// # Returns
///
/// The exit code if successfully retrieved, or `None` on failure.
pub fn get_container_exit_code(container_id: &str) -> Option<i64> {
    let resp = block_on(docker().inspect_container(container_id, None)).ok()?;
    resp.state?.exit_code
}
