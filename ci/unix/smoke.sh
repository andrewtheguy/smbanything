#!/usr/bin/env bash
# SMB smoke test of the release binary: serve each candle fixture archive
# (zip, tar, tar.gz) from ./tmp and read a known file back over SMB — through
# smbclient on Linux, mount_smbfs on macOS. The fixtures are the source
# archives of the candle 0.11.0 GitHub release
# (https://github.com/huggingface/candle/releases/tag/0.11.0), fetched into
# ./tmp when missing; the plain tar is the tar.gz decompressed. Non-zip
# archives must spill nothing into the runtime temp directory while serving or
# after shutdown (the zip backing expands entries by design, but must clean up
# on shutdown like the rest).
set -euo pipefail

cd "$(dirname "$0")/../.."
binary="${CARGO_TARGET_DIR:-$PWD/target}/release/smbanything"
password=ci-smoke-password
expected_hash=11ad61a87d8defac2031c6d6d5f88a4d5538df501b88503fddab6f739391169e
fixture_base=https://github.com/huggingface/candle/archive/refs/tags/0.11.0
platform=$(uname -s)
pid=
mount_dir=
elevated_pid=false

info() { echo "[smoke] $*"; }
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

cleanup() {
    if [[ -n "$mount_dir" ]]; then
        # macOS canonicalizes /tmp to /private/tmp in `mount` output, so a
        # textual mount-table check misses the exact mount we just created.
        # umount already gives us the authoritative answer and this path is a
        # per-run mktemp directory, never a broad target.
        umount "$mount_dir" 2>/dev/null || true
    fi
    if [[ -n "$pid" ]] && { kill -0 "$pid" 2>/dev/null || $elevated_pid; }; then
        if $elevated_pid; then
            # $pid is sudo, which runs the server as a child rather than
            # exec'ing it in place and does not relay SIGINT to it on macOS —
            # signalling sudo there leaves the server running and the wait
            # below never returns. Signal that child directly; waiting on sudo
            # then still waits for the server, because sudo exits once its
            # child does, which is what the post-shutdown checks rely on.
            sudo -n pkill -INT -P "$pid" 2>/dev/null \
                || sudo -n kill -INT "$pid" 2>/dev/null \
                || true
        else
            kill -INT "$pid"
        fi
        wait "$pid"
    fi
    pid=
    mount_dir=
    elevated_pid=false
}
trap cleanup EXIT

mkdir -p tmp
[[ -f tmp/candle-0.11.0.tar.gz ]] || {
    info 'fetching candle-0.11.0.tar.gz'
    curl -fsSL "$fixture_base.tar.gz" -o tmp/candle-0.11.0.tar.gz
}
[[ -f tmp/candle-0.11.0.zip ]] || {
    info 'fetching candle-0.11.0.zip'
    curl -fsSL "$fixture_base.zip" -o tmp/candle-0.11.0.zip
}
[[ -f tmp/candle-0.11.0.tar ]] || gzip -dc tmp/candle-0.11.0.tar.gz > tmp/candle-0.11.0.tar
fixture_hash=$(tar -xzOf tmp/candle-0.11.0.tar.gz candle-0.11.0/Cargo.toml | sha256 | cut -d' ' -f1)
if [[ "$fixture_hash" != "$expected_hash" ]]; then
    echo "fixture Cargo.toml hash mismatch: $fixture_hash" >&2
    exit 1
fi

for archive in tmp/candle-0.11.0.zip tmp/candle-0.11.0.tar tmp/candle-0.11.0.tar.gz; do
    name=$(basename "$archive")
    work=$(mktemp -d "${TMPDIR:-/tmp}/smbanything-smoke-${name//./-}.XXXXXX")
    runtime_tmp="$work/runtime-tmp"
    mkdir "$runtime_tmp"
    server_log="$work/server.log"
    downloaded="$work/Cargo.toml"

    info "serving $name"
    TMPDIR="$runtime_tmp" SMBANYTHING_PASSWORD="$password" \
        "$binary" "$archive" --port 0 >"$server_log" 2>&1 &
    pid=$!

    port=
    for _ in $(seq 1 200); do
        if grep -q '^Port:' "$server_log"; then
            port=$(grep -m1 '^Port:' "$server_log" | awk '{print $2}')
            break
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            cat "$server_log" >&2
            exit 1
        fi
        sleep 0.05
    done
    if [[ -z "$port" ]]; then
        echo "timed out waiting for $name to start" >&2
        cat "$server_log" >&2
        exit 1
    fi
    folder=$(grep -m1 '^Folder:' "$server_log" | sed 's/.*\\//')

    if [[ "$platform" == Darwin ]]; then
        mount_dir="$work/mount"
        mkdir "$mount_dir"
        mount_smbfs "//smbanything:$password@127.0.0.1:$port/share/$folder" "$mount_dir"
        cp "$mount_dir/candle-0.11.0/Cargo.toml" "$downloaded"
    else
        smbclient //127.0.0.1/share \
            -p "$port" \
            -U "smbanything%$password" \
            '--option=client min protocol=SMB2_10' \
            '--option=client max protocol=SMB2_10' \
            -c "get ${folder}\\candle-0.11.0\\Cargo.toml $downloaded" \
            >"$work/client.log" 2>&1 \
            || { cat "$work/client.log" >&2; exit 1; }
    fi

    actual_hash=$(sha256 "$downloaded" | cut -d' ' -f1)
    if [[ "$actual_hash" != "$expected_hash" ]]; then
        echo "served $name hash mismatch: $actual_hash" >&2
        exit 1
    fi

    if [[ "$name" != *.zip ]] && find "$runtime_tmp" -mindepth 1 -print -quit | grep -q .; then
        echo "unexpected temporary files while serving $name" >&2
        find "$runtime_tmp" -mindepth 1 -maxdepth 2 -print >&2
        exit 1
    fi

    cleanup
    if find "$runtime_tmp" -mindepth 1 -print -quit | grep -q .; then
        echo "temporary files remained after stopping $name" >&2
        find "$runtime_tmp" -mindepth 1 -maxdepth 2 -print >&2
        exit 1
    fi

    info "verified $name ($actual_hash)"
done

# Exercise the packet path itself with the TAR.GZ fixture. Creating the native
# TUN adapter and its two host routes is the one part that needs elevation; no
# privileged TCP socket is opened, and dropping the process removes both.
work=$(mktemp -d "${TMPDIR:-/tmp}/smbanything-tun-smoke.XXXXXX")
runtime_tmp="$work/runtime-tmp"
mkdir "$runtime_tmp"
server_log="$work/server.log"
downloaded="$work/Cargo.toml"

info 'serving candle-0.11.0.tar.gz through 169.254.255.1'
sudo -n env TMPDIR="$runtime_tmp" SMBANYTHING_PASSWORD="$password" \
    "$binary" tmp/candle-0.11.0.tar.gz --smb-tun >"$server_log" 2>&1 &
pid=$!
elevated_pid=true

for _ in $(seq 1 200); do
    grep -q '^Port:' "$server_log" && break
    sudo -n kill -0 "$pid" 2>/dev/null || { cat "$server_log" >&2; exit 1; }
    sleep 0.05
done
grep -q '^Port:[[:space:]]*445$' "$server_log" || {
    echo 'packet tunnel did not start on port 445' >&2
    cat "$server_log" >&2
    exit 1
}
folder=$(grep -m1 '^Folder:' "$server_log" | sed 's/.*\\//')

# A client whose handshake and FIN are processed in the same batch reaches the
# tunnel already in CLOSE-WAIT and never appears as ESTABLISHED. Bridge slots
# are a fixed pool, so one that is not recycled is retired for the life of the
# process. Three times the pool, then the read below: both have to survive.
info 'probing the bridge pool with connect-then-close clients'
for _ in $(seq 1 24); do
    exec 3<>/dev/tcp/169.254.255.1/445 || {
        echo 'a connect-then-close client was refused: the bridge pool is not recycling' >&2
        cat "$server_log" >&2
        exit 1
    }
    exec 3>&-
    sleep 0.02
done

if [[ "$platform" == Darwin ]]; then
    mount_dir="$work/mount"
    mkdir "$mount_dir"
    mount_smbfs "//smbanything:$password@169.254.255.1/share/$folder" "$mount_dir"
    cp "$mount_dir/candle-0.11.0/Cargo.toml" "$downloaded"
else
    smbclient //169.254.255.1/share \
        -U "smbanything%$password" \
        '--option=client min protocol=SMB2_10' \
        '--option=client max protocol=SMB2_10' \
        -c "get ${folder}\\candle-0.11.0\\Cargo.toml $downloaded" \
        >"$work/client.log" 2>&1 \
        || { cat "$work/client.log" >&2; exit 1; }
fi

actual_hash=$(sha256 "$downloaded" | cut -d' ' -f1)
[[ "$actual_hash" == "$expected_hash" ]] || {
    echo "packet-tunneled file hash mismatch: $actual_hash" >&2
    exit 1
}
cleanup
info "verified packet tunnel ($actual_hash)"
