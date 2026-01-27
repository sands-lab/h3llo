//! Shared utilities for native integration test orchestrators.
//!
//! Provides common helper functions for Container Test Pattern tests.

use std::path::PathBuf;
use std::process::Command;

/// Default test image name.
pub const TEST_IMAGE: &str = "h3llo";

/// Default test image tag.
pub const TEST_TAG: &str = "test";

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

/// Locates a compiled test binary in the target directory.
///
/// `cargo test --no-run` places binaries in `target/{profile}/deps/` with
/// underscores replacing hyphens and a hash suffix. For musl cross-compilation,
/// binaries are in `target/x86_64-unknown-linux-musl/{profile}/deps/`.
///
/// # Arguments
///
/// * `binary_name` - The binary name with hyphens (e.g., "integration-container-tun")
///
/// # Panics
///
/// Panics if the binary cannot be found.
pub fn find_test_binary(binary_name: &str) -> PathBuf {
    let target_dir =
        PathBuf::from(std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string()));

    let deps_prefix = binary_name.replace('-', "_");

    // Search musl target directory first, then fall back to default
    let search_bases = [
        target_dir.join("x86_64-unknown-linux-musl"),
        target_dir.clone(),
    ];

    for base in search_bases {
        for profile in ["debug", "release"] {
            let deps_dir = base.join(profile).join("deps");
            if let Ok(entries) = std::fs::read_dir(&deps_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with(&deps_prefix)
                        && !name_str.ends_with(".d")
                        && entry.file_type().map(|t| t.is_file()).unwrap_or(false)
                    {
                        return entry.path();
                    }
                }
            }
        }
    }

    panic!(
        "Cannot find test binary '{binary_name}'. Build it first with:\n  \
         cargo test --test {binary_name} --target x86_64-unknown-linux-musl --no-run"
    );
}
