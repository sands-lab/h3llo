#!/usr/bin/env bash

set -euo pipefail

readonly MUSL_CROSS_VERSION="${MUSL_CROSS_VERSION:-20250929}"
readonly RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-stable}"

usage() {
    echo "Usage: $0 <amd64|arm64|riscv64> <output-directory>" >&2
}

if [[ $# -ne 2 ]]; then
    usage
    exit 2
fi

arch_label="$1"
output_dir="$2"

case "$arch_label" in
    amd64)
        rust_target="x86_64-unknown-linux-musl"
        toolchain="x86_64-unknown-linux-musl"
        ;;
    arm64)
        rust_target="aarch64-unknown-linux-musl"
        toolchain="aarch64-unknown-linux-musl"
        ;;
    riscv64)
        rust_target="riscv64gc-unknown-linux-musl"
        toolchain="riscv64-unknown-linux-musl"
        ;;
    *)
        usage
        exit 2
        ;;
esac

cache_root="${MUSL_CROSS_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/h3llo/musl-cross}"
toolchain_root="$cache_root/$MUSL_CROSS_VERSION"
toolchain_dir="$toolchain_root/$toolchain"

if [[ ! -x "$toolchain_dir/bin/$toolchain-gcc" ]]; then
    mkdir -p "$toolchain_root"
    archive="$(mktemp --suffix=.tar.xz)"
    trap 'rm -f "$archive"' EXIT
    curl -sSfL \
        "https://github.com/cross-tools/musl-cross/releases/download/$MUSL_CROSS_VERSION/$toolchain.tar.xz" \
        -o "$archive"
    tar -xJf "$archive" -C "$toolchain_root"
fi

export PATH="$toolchain_dir/bin:$PATH"
target_env="${rust_target//-/_}"
upper_target_env="${target_env^^}"
export "CC_${target_env}=$toolchain-gcc"
export "CXX_${target_env}=$toolchain-g++"
export "AR_${target_env}=$toolchain-ar"
export "CARGO_TARGET_${upper_target_env}_LINKER=$toolchain-gcc"
export BORING_BSSL_SYSROOT="$toolchain_dir/$toolchain/sysroot"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}"
export RUSTFLAGS="${RUSTFLAGS:--C target-feature=+crt-static}"

rustup target add --toolchain "$RUST_TOOLCHAIN" "$rust_target"
export RUSTC="$(rustup which --toolchain "$RUST_TOOLCHAIN" rustc)"
export RUSTDOC="$(rustup which --toolchain "$RUST_TOOLCHAIN" rustdoc)"
cargo_command=("$(rustup which --toolchain "$RUST_TOOLCHAIN" cargo)")

"${cargo_command[@]}" build --locked --release --target "$rust_target" --bin h3llo

build_test_binary() {
    local test_name="$1"
    local executable

    executable="$("${cargo_command[@]}" test --locked --release --target "$rust_target" \
        --test "$test_name" --no-run --message-format=json \
        | jq -r --arg name "$test_name" \
            'select(.reason == "compiler-artifact" and .target.name == $name and .executable != null) | .executable' \
        | tail -n 1)"

    if [[ -z "$executable" ]]; then
        echo "Cargo did not report an executable for test target $test_name" >&2
        return 1
    fi

    echo "$executable"
}

tun_binary="$(build_test_binary integration-container-tun)"
route_binary="$(build_test_binary integration-container-route)"

mkdir -p "$output_dir"
install -m 0755 "$CARGO_TARGET_DIR/$rust_target/release/h3llo" "$output_dir/h3llo"
install -m 0755 "$tun_binary" "$output_dir/integration-container-tun"
install -m 0755 "$route_binary" "$output_dir/integration-container-route"

echo "Built $rust_target binaries with musl-cross $MUSL_CROSS_VERSION in $output_dir"
