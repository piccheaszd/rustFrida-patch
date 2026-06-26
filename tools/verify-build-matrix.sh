#!/usr/bin/env bash
set -euo pipefail

TARGET="${TARGET:-aarch64-linux-android}"
PROFILE="${PROFILE:-debug}"

case "$PROFILE" in
  debug)
    PROFILE_ARGS=()
    ;;
  release)
    PROFILE_ARGS=(--release)
    ;;
  *)
    echo "Unsupported PROFILE=$PROFILE; use debug or release" >&2
    exit 2
    ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

run() {
  printf '\n==> %s\n' "$*"
  "$@"
}

run cargo fmt --all --check
run ./zymbiote/build.sh

run cargo build -p agent --target "$TARGET" "${PROFILE_ARGS[@]}"
run cargo check -p rust_frida --target "$TARGET" "${PROFILE_ARGS[@]}"

run cargo build -p agent --target "$TARGET" "${PROFILE_ARGS[@]}" --no-default-features --features quickjs,noptrace
run cargo build -p agent --target "$TARGET" "${PROFILE_ARGS[@]}" --no-default-features --features quickjs-full-api,noptrace
run cargo check -p rust_frida --target "$TARGET" "${PROFILE_ARGS[@]}" --no-default-features --features noptrace

# Leave the workspace in the default ptrace-agent state for ordinary development.
run cargo build -p agent --target "$TARGET" "${PROFILE_ARGS[@]}"
run cargo check -p rust_frida --target "$TARGET" "${PROFILE_ARGS[@]}"
