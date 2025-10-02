#!/bin/bash
set -euo pipefail

# Use provided CARGO_TARGET_DIR, else default to target
TARGET_DIR="${CARGO_TARGET_DIR:-target}"

cargo build --release > /dev/null

BIN="$TARGET_DIR/release/tcp-rust"

if [[ "$(uname)" == "Linux" ]]; then
    sudo setcap cap_net_admin=eip "$BIN"
    "$BIN"
elif [[ "$(uname)" == "Darwin" ]]; then
    sudo "$BIN"
else
    echo "Unsupported OS: $(uname)"
    exit 1
fi