#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
hook_path="$repo_root/.git/hooks/pre-commit"

cat > "$hook_path" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

echo "Running cargo fmt -- --check..."
cargo fmt -- --check

echo "Running cargo clippy -- -D warnings..."
cargo clippy -- -D warnings

echo "Running cargo test (may require elevated privileges)..."
cargo test
EOF

chmod +x "$hook_path"
echo "Pre-commit hook installed at $hook_path"
