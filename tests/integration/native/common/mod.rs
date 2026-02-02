//! Shared utilities for native integration test orchestrators.
//!
//! Provides common helper functions for Container Test Pattern tests.

use std::process::Command;

/// Default test image name.
pub const TEST_IMAGE: &str = "h3llo";

/// Default test image tag.
pub const TEST_TAG: &str = "test";

/// Container path for TUN test binary.
pub const CONTAINER_TUN_BINARY: &str = "/usr/local/bin/integration-container-tun";

/// Container path for route test binary.
pub const CONTAINER_ROUTE_BINARY: &str = "/usr/local/bin/integration-container-route";

/// Checks if a Docker image exists locally.
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
    let output = Command::new("docker")
        .args(["image", "inspect", &format!("{image}:{tag}")])
        .output();
    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

/// Gets the exit code of a container by ID.
///
/// Uses `docker inspect` to retrieve the container's exit code.
///
/// # Arguments
///
/// * `container_id` - The Docker container ID
///
/// # Returns
///
/// The exit code if successfully retrieved, or `None` on failure.
pub fn get_container_exit_code(container_id: &str) -> Option<i64> {
    let output = Command::new("docker")
        .args(["inspect", "-f", "{{.State.ExitCode}}", container_id])
        .output()
        .ok()?;
    if output.status.success() {
        String::from_utf8_lossy(&output.stdout).trim().parse().ok()
    } else {
        None
    }
}
