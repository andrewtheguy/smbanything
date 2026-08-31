#!/usr/bin/env bash
# Clippy, tests, and a release build, then the SMB smoke test in
# ci/unix/smoke.sh against that build. Runs natively on whatever Unix machine
# invokes it: this Linux host through ci/unix/remote.sh (a Linux driver always
# runs locally), or the macOS VM through `ci/unix/remote.sh -H macvm`. It
# installs nothing permanently; the smoke creates one native TUN adapter and
# two host routes, then removes them. `remote.sh doctor` checks its prerequisites.
set -euo pipefail

# Invoked over ssh the working directory is the login user's home, not the
# checkout, so anchor to the repo root this script sits in. A non-interactive
# ssh shell also skips the profile that puts rustup's bin dir on PATH.
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"

step() {
    local name=$1; shift
    echo ''
    echo "== $name =="
    echo "   cargo $*"
    cargo "$@"
}

echo '== toolchain =='
rustc --version
cargo --version
cargo clippy --version
[ -n "${CARGO_TARGET_DIR:-}" ] && echo "   CARGO_TARGET_DIR=$CARGO_TARGET_DIR"

step 'Clippy' clippy --workspace --all-targets --all-features -- -D warnings
step 'Test' test --workspace --all-features
step 'Release build' build --release

echo ''
echo '== SMB smoke =='
./ci/unix/smoke.sh

echo ''
echo 'all steps passed'
