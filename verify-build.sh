#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$project_dir"
verify_dir=$(mktemp -d "${TMPDIR:-/tmp}/sealed-verify.XXXXXX")
trap 'rm -rf -- "$verify_dir"' EXIT HUP INT TERM

CARGO_TARGET_DIR="$verify_dir/first" cargo build --release --offline --locked
CARGO_TARGET_DIR="$verify_dir/second" cargo build --release --offline --locked

first="$verify_dir/first/release/sealed"
second="$verify_dir/second/release/sealed"
if ! cmp -s "$first" "$second"; then
    echo "error: two clean same-host builds differ" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$first"
else
    shasum -a 256 "$first"
fi
echo "Two clean same-host release builds are byte-identical."
echo "This is not a cross-environment reproducibility claim."

