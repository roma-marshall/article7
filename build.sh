#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$project_dir"

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: Cargo is required for a source build" >&2
    exit 1
fi
if [ ! -f Cargo.lock ] || [ ! -f .cargo/config.toml ] || [ ! -d vendor ]; then
    echo "error: locked vendored dependency state is incomplete" >&2
    exit 1
fi

case "$(uname -s)" in
    Darwin) platform=macos ;;
    Linux) platform=linux ;;
    *) echo "error: unsupported Unix platform" >&2; exit 1 ;;
esac

case "$(uname -m)" in
    arm64|aarch64) architecture=arm64 ;;
    x86_64|amd64) architecture=x64 ;;
    *) echo "error: unsupported architecture" >&2; exit 1 ;;
esac

cargo fmt -- --check
cargo check --offline --locked
cargo test --offline --locked
cargo build --release --offline --locked

output_dir="dist/$platform-$architecture"
mkdir -p "$output_dir"
cp target/release/sealed "$output_dir/sealed"
chmod 755 "$output_dir/sealed"
echo "Built $project_dir/$output_dir/sealed"

