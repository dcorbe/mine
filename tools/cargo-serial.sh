#!/usr/bin/env bash
# Run exactly one cargo at a time, workspace-wide.
#
# This box has 7.5 GB of RAM, sits in swap at rest, and carries a 17 GB
# target/ against 45 GB of free disk. Two concurrent rustc invocations are
# enough to push it into the OOM killer, and an OOM here takes the desktop
# with it -- see the 2026-08 incident. Parallel agents therefore funnel every
# cargo command through this wrapper rather than calling cargo directly.
#
# The lock is advisory and held for the life of the cargo process. A waiting
# caller blocks rather than failing, so an agent's TDD cycle still works --
# it just queues.
#
# Usage:  tools/cargo-serial.sh test -p mbbs --lib some_test_name
#         tools/cargo-serial.sh clippy -p mbbs --all-targets
#
# NEVER run `cargo test --workspace` through this or any other path: it does
# not finish. btrieve-oracle's engine.rs runs two Wine-spawning tests in
# parallel against one Wine prefix and they deadlock. Use
# `--workspace --exclude btrieve-oracle`.

set -euo pipefail

ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
LOCK="$ROOT/tmp/scratch/.cargo-serial.lock"

mkdir -p "$(dirname "$LOCK")"

# Cap codegen parallelism as well as process count. Four CPUs, but the
# constraint here is memory, not cores: -j2 keeps peak rustc residency inside
# what is actually available while a desktop and a running board share the box.
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"

if [ "${1:-}" = "--wait-notice" ]; then
    shift
    exec 9>"$LOCK"
    if ! flock -n 9; then
        echo "cargo-serial: another cargo holds the lock; waiting..." >&2
    fi
    flock 9
    exec cargo "$@"
fi

exec flock "$LOCK" cargo "$@"
