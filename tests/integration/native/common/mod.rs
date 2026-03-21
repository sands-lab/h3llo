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

/// Checks if a Docker image exists locally via the Docker API.
pub async fn ensure_image_exists(image: &str, tag: &str) -> bool {
    let docker = bollard::Docker::connect_with_local_defaults().expect("connect to Docker daemon");
    docker
        .inspect_image(&format!("{image}:{tag}"))
        .await
        .is_ok()
}

/// Gets the exit code of a container by ID via the Docker API.
pub async fn get_container_exit_code(container_id: &str) -> Option<i64> {
    let docker = bollard::Docker::connect_with_local_defaults().expect("connect to Docker daemon");
    let resp = docker.inspect_container(container_id, None).await.ok()?;
    resp.state?.exit_code
}
