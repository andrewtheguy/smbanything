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
# The packet tunnel's foreign-source check plays a neighbour at this spare
# TEST-NET-2 address. Linux aliases it onto loopback; macOS puts it behind a
# peered feth pair with IP forwarding on. Cleanup undoes only what this run
# created, so an interface or route that was already there is left alone.
foreign_source=198.51.100.7
foreign_alias=
feth4450_created=false
feth4451_created=false
neighbour_route=false
forwarding_was=
tcpdump_sudo=
capture=

info() { echo "[smoke] $*"; }
# The banner's `Server:   listening on <host>:<port>  (...)` line, and the
# archive's 8-hex id from `Folder:   <id>`.
listen_port() { sed -n 's/^Server: *listening on .*:\([0-9][0-9]*\)  .*/\1/p' "$1" | head -n1; }
archive_folder() { awk '/^Folder:/ {print $2; exit}' "$1"; }
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

remove_foreign_alias() {
    [[ -n "$foreign_alias" ]] || return 0
    sudo -n ip addr del "$foreign_source/32" dev "$foreign_alias" || true
    foreign_alias=
}

# The process named like $2 at or below pid $1. sudo runs its command as a
# child, or as a grandchild when it interposes a monitor process (use_pty).
descendant_named() {
    local pid=$1
    while [[ -n "$pid" && "$(ps -o comm= -p "$pid" || true)" != *"$2"* ]]; do
        pid=$(pgrep -P "$pid" | head -n1 || true)
    done
    echo "$pid"
}

# Record TCP port 445 traffic on the tunnel interface $1 into $capture.
start_capture() {
    capture="$work/capture.txt"
    sudo -n tcpdump -n -l -U -i "$1" 'tcp port 445' >"$capture" 2>"$work/tcpdump.err" &
    tcpdump_sudo=$!
    for _ in $(seq 1 100); do
        grep -q 'listening on' "$work/tcpdump.err" && return 0
        sleep 0.05
    done
    echo "tcpdump never started capturing on $1" >&2
    cat "$work/tcpdump.err" >&2
    exit 1
}

# $tcpdump_sudo is sudo, which does not relay a signal from this shell on
# macOS, so signal tcpdump itself, wherever under sudo it runs. It exits on
# SIGINT once its buffer is written; if it has not after 5 s, kill it, so the
# wait for sudo cannot hang.
stop_tcpdump() {
    [[ -n "$tcpdump_sudo" ]] || return 0
    local tcpdump_pid
    tcpdump_pid=$(descendant_named "$tcpdump_sudo" tcpdump)
    if [[ -n "$tcpdump_pid" ]]; then
        sudo -n kill -INT "$tcpdump_pid" 2>/dev/null || true
        for _ in $(seq 1 100); do
            ps -p "$tcpdump_pid" >/dev/null || break
            sleep 0.05
        done
        sudo -n kill -KILL "$tcpdump_pid" 2>/dev/null || true
    else
        sudo -n kill -KILL "$tcpdump_sudo" 2>/dev/null || true
    fi
    wait "$tcpdump_sudo" 2>/dev/null || true
    tcpdump_sudo=
}

# With tcpdump stopped: SYNs from $foreign_source must have reached the tunnel
# interface $1, or the check proved nothing, and nothing may have answered.
check_capture() {
    local arrived answered
    arrived=$(grep -c "$foreign_source\.[0-9]* > 169\.254\.255\.1\.445: Flags \[S\]" "$capture" || true)
    answered=$(grep -c "> $foreign_source\." "$capture" || true)
    if (( arrived == 0 )); then
        echo "no SYN from $foreign_source reached $1, so the check proved nothing" >&2
        cat "$work/tcpdump.err" "$capture" >&2
        exit 1
    fi
    if (( answered != 0 )); then
        echo "the tunnel answered a SYN from $foreign_source" >&2
        cat "$capture" >&2
        exit 1
    fi
    info "$arrived SYNs from $foreign_source reached $1 and got no answer"
}

remove_neighbour() {
    stop_tcpdump
    if $neighbour_route; then
        sudo -n route -q delete -host "$foreign_source" >/dev/null 2>&1 || true
        neighbour_route=false
    fi
    if $feth4451_created; then
        sudo -n ifconfig feth4451 destroy 2>/dev/null || true
        feth4451_created=false
    fi
    if $feth4450_created; then
        sudo -n ifconfig feth4450 destroy 2>/dev/null || true
        feth4450_created=false
    fi
    if [[ -n "$forwarding_was" ]]; then
        sudo -n sysctl -q net.inet.ip.forwarding="$forwarding_was" >/dev/null || true
        forwarding_was=
    fi
}

cleanup() {
    remove_foreign_alias
    remove_neighbour
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
        port=$(listen_port "$server_log")
        [[ -n "$port" ]] && break
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
    folder=$(archive_folder "$server_log")

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
    grep -q '^Server:' "$server_log" && break
    sudo -n kill -0 "$pid" 2>/dev/null || { cat "$server_log" >&2; exit 1; }
    sleep 0.05
done
grep -q '^Server: *listening on 169\.254\.255\.1:445 ' "$server_log" || {
    echo 'packet tunnel did not start on port 445' >&2
    cat "$server_log" >&2
    exit 1
}
folder=$(archive_folder "$server_log")

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

# Root is needed only to create the adapter. The server sudo started must
# have given it up, in every thread, before it served anything. $pid is sudo;
# the server is a descendant, one or two levels down depending on whether sudo
# interposes a monitor process.
server_pid=$(descendant_named "$pid" smbanything)
[[ -n "$server_pid" ]] || { echo 'cannot find the tunnel server under sudo' >&2; exit 1; }
if [[ "$platform" == Darwin ]]; then
    server_uids=$(ps -o uid= -p "$server_pid" | tr -d ' ')
else
    server_uids=$(sudo -n cat /proc/"$server_pid"/task/*/status | awk '/^Uid:/ {print $3}' | sort -u | xargs)
fi
[[ "$server_uids" == "$(id -u)" ]] || {
    echo "the tunnel server still runs as uid(s) '$server_uids', not $(id -u)" >&2
    exit 1
}
info "server runs as uid $server_uids after creating the adapter"

# Nothing but the adapter address is a client. A packet the host forwards
# from anywhere else has to get no answer at all.
if [[ "$platform" == Darwin ]]; then
    # macOS never sends a locally sourced packet from another address into
    # the utun, so the neighbour has to be real enough to be forwarded: SYNs
    # written by BPF onto one end of a peered feth pair arrive on the other,
    # which this host owns, and with forwarding on it routes them into the
    # tunnel — link-local destination and all. tcpdump on the utun proves
    # they got there and that nothing answered.
    info 'checking that a forwarded neighbour gets no answer'
    uv_bin=$(command -v uv || echo "$HOME/.local/bin/uv")
    # A no-op once uv has it; the injector runs on uv's Python, never the system's.
    "$uv_bin" python install --quiet 3.13 \
        && python=$("$uv_bin" python find --managed-python 3.13) || {
        echo 'the forwarded-neighbour check needs uv and its Python 3.13' >&2
        exit 1
    }
    utun=$(route -n get 169.254.255.1 | awk '/interface:/ {print $2}')
    [[ "$utun" == utun* ]] || { echo "169.254.255.1 routes via '$utun', not a utun" >&2; exit 1; }
    forwarding_was=$(sysctl -n net.inet.ip.forwarding)
    # Each flag is set only once its resource exists: under `set -e` a
    # failed create exits first, and cleanup leaves the existing one alone.
    sudo -n ifconfig feth4450 create
    feth4450_created=true
    sudo -n ifconfig feth4451 create
    feth4451_created=true
    sudo -n ifconfig feth4450 peer feth4451
    sudo -n ifconfig feth4450 up
    sudo -n ifconfig feth4451 inet 203.0.113.1/24 up
    # Any reply goes back to the fake neighbour, never onto the real network.
    sudo -n route -q add -host "$foreign_source" -interface feth4451 >/dev/null
    neighbour_route=true
    sudo -n sysctl -q net.inet.ip.forwarding=1 >/dev/null
    start_capture "$utun"
    sudo -n "$python" -I ci/unix/inject-syn.py feth4450 \
        "$(ifconfig feth4450 | awk '/ether/ {print $2}')" \
        "$(ifconfig feth4451 | awk '/ether/ {print $2}')" \
        "$foreign_source" 169.254.255.1 445
    sleep 1.5
    remove_neighbour
    check_capture "$utun"
else
    # Linux does route a locally sourced packet from a spare address into the
    # tunnel, which stands in for a forwarded one without enabling forwarding.
    info 'checking that another source address gets no answer'
    tun_if=$(ip -o route get 169.254.255.1 | sed -n 's/.* dev \([^ ]*\).*/\1/p')
    [[ "$tun_if" == smbany* ]] || { echo "169.254.255.1 routes via '$tun_if', not the tunnel" >&2; exit 1; }
    sudo -n ip addr add "$foreign_source/32" dev lo
    foreign_alias=lo
    start_capture "$tun_if"
    # nc's failure alone would prove nothing; the capture shows its SYNs got
    # to the tunnel and that nothing answered them.
    if nc -z -w 2 -s "$foreign_source" 169.254.255.1 445 2>/dev/null; then
        echo "a connection from $foreign_source reached the tunnel" >&2
        exit 1
    fi
    stop_tcpdump
    remove_foreign_alias
    check_capture "$tun_if"
    nc -z -w 2 169.254.255.1 445 2>/dev/null || {
        echo 'the adapter address itself can no longer connect' >&2
        exit 1
    }
fi

# The packet thread sleeps on the adapter, the bridges and smoltcp's timers
# rather than on a clock, so an idle bridged connection costs it no wakeups.
# Linux counts them per thread; macOS has no equivalent to read.
if [[ "$platform" != Darwin ]]; then
    exec 3<>/dev/tcp/169.254.255.1/445
    sleep 0.5
    tun_task=$(grep -lx 'smbanything-tun' /proc/"$server_pid"/task/*/comm 2>/dev/null | head -n1)
    tun_task=${tun_task%/comm}
    if [[ -z "$tun_task" ]]; then
        echo 'no smbanything-tun thread in the server' >&2
        exit 1
    fi
    switches() { sudo -n awk '/^voluntary_ctxt_switches/ {print $2}' "$tun_task/status"; }
    before=$(switches)
    sleep 2
    wakeups=$(( $(switches) - before ))
    exec 3>&-
    (( wakeups < 20 )) || {
        echo "the packet thread woke $wakeups times in 2 s with an idle connection" >&2
        exit 1
    }
    info "packet thread woke $wakeups times in 2 s with an idle connection"
fi

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
