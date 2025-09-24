#!/bin/bash
set -e

# Use provided CARGO_TARGET_DIR, else default to target
TARGET_DIR="${CARGO_TARGET_DIR:-target}"

cargo build --release
sudo "$TARGET_DIR/release/tcp-rust"