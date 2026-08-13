#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$project_dir"
verify_dir=$(mktemp -d "${TMPDIR:-/tmp}/sealed-verify.XXXXXX")
trap 'rm -rf -- "$verify_dir"' EXIT HUP INT TERM
build_dir="$verify_dir/build"
first="$verify_dir/first-sealed"

CARGO_TARGET_DIR="$build_dir" cargo build --release --offline --locked
cp "$build_dir/release/sealed" "$first"
rm -rf -- "$build_dir"
CARGO_TARGET_DIR="$build_dir" cargo build --release --offline --locked

second="$build_dir/release/sealed"
if ! cmp -s "$first" "$second"; then
    echo "error: two clean same-host/same-path builds differ" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$first"
else
    shasum -a 256 "$first"
fi
echo "Two clean same-host/same-path release builds are byte-identical."
echo "This is not a cross-path or cross-environment reproducibility claim."
