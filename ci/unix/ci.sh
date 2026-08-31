#!/usr/bin/env bash
# Clippy, tests, and a release build, then the SMB smoke test in
# ci/unix/smoke.sh against that build. Runs natively on whatever Unix machine
# invokes it: this Linux host through ci/unix/remote.sh (a Linux driver always
# runs locally), or the macOS VM through `ci/unix/remote.sh -H macvm`. It
# installs nothing and changes no machine state; `remote.sh doctor` checks for
# the SMB client the smoke needs.
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

step 'Clippy' clippy --all-targets --all-features -- -D warnings
step 'Test' test --all-features
step 'Release build' build --release

echo ''
echo '== SMB smoke =='
./ci/unix/smoke.sh

echo ''
echo 'all steps passed'
