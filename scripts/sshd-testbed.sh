#!/usr/bin/env bash
# sshd-testbed.sh — a throwaway containerized OpenSSH server for RustConn's
# #[ignore] SSH integration tests (K0, W3 phase 2).
#
# It is NOT part of the build and nothing runs it automatically: the tests that
# use it are `#[ignore]`, so a developer (or CI) starts a profile here first,
# exports the printed RUSTCONN_SSHD_* variables, then runs the tests with
# `-- --ignored`. See `rustconn-core/tests/ssh_testbed.rs` for the contract.
#
# Why a container and not the host's sshd: the tests need a server with known,
# hostile-ish configurations (StrictModes, ForceCommand, an unknown host key)
# that must not touch the developer's own ~/.ssh or sshd. Everything here lives
# inside one short-lived rootless-podman container and is torn down with it.
#
# Runtime: podman (rootless). Docker works too if `docker` is aliased to it, but
# only podman is tested. No new Rust dependency — this is pure shell + an image.
#
# Usage:
#   scripts/sshd-testbed.sh up <profile>   # start, print RUSTCONN_SSHD_* env
#   scripts/sshd-testbed.sh down           # stop and remove the container
#   scripts/sshd-testbed.sh profiles       # list the profiles
#
# Profiles (plan 0.24, W3 K0):
#   password        password auth only, user `tester` / `testpw`
#   bastion         password auth, meant to sit in front of another host (-J)
#   strictmodes     StrictModes yes with a deliberately loose key dir, so a
#                   mis-permissioned key is refused (regression guard)
#   key-otp         publickey + keyboard-interactive (two-factor shape)
#   forcecommand    ForceCommand echoes a sentinel and exits (deploy-script guard)
#   unknown-hostkey a freshly generated host key, so the client always sees an
#                   unknown key (StrictHostKeyChecking=yes path, K2/K5 verify)
#
# The container binds sshd to a random free host port on 127.0.0.1 only. The
# port and the paths the tests need are printed as `export` lines AND written to
# `$RUSTCONN_SSHD_ENV` (default: target/sshd-testbed.env) so the test runner can
# `source` them.
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

CONTAINER="${RUSTCONN_SSHD_CONTAINER:-rustconn-sshd-testbed}"
IMAGE="${RUSTCONN_SSHD_IMAGE:-localhost/rustconn-sshd-testbed:latest}"
ENV_FILE="${RUSTCONN_SSHD_ENV:-target/sshd-testbed.env}"
SSH_USER="tester"
SSH_PASS="testpw"

runtime() {
    if command -v podman >/dev/null 2>&1; then
        echo podman
    elif command -v docker >/dev/null 2>&1; then
        echo docker
    else
        echo "sshd-testbed: no podman or docker on PATH" >&2
        exit 2
    fi
}
RT="$(runtime)"

profiles() {
    cat <<'EOF'
password        password auth only (tester/testpw)
bastion         password auth, front for a -J jump
strictmodes     StrictModes yes, refuses a mis-permissioned key
key-otp         publickey + keyboard-interactive (two-factor shape)
forcecommand    ForceCommand echoes a sentinel and exits
unknown-hostkey  fresh host key every start (StrictHostKeyChecking=yes path)
EOF
}

# The image is tiny: Alpine + openssh. Built once, cached by the runtime.
build_image() {
    if "$RT" image exists "$IMAGE" 2>/dev/null; then
        return 0
    fi
    echo "sshd-testbed: building $IMAGE ..." >&2
    local ctx
    ctx="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$ctx'" RETURN
    cat > "$ctx/Dockerfile" <<'EOF'
FROM docker.io/library/alpine:3.20
RUN apk add --no-cache openssh openssh-server shadow \
 && adduser -D -s /bin/sh tester \
 && echo 'tester:testpw' | chpasswd \
 && ssh-keygen -A
# Entry script is injected at run time via a bind mount, not baked in, so one
# image serves every profile.
EOF
    "$RT" build -t "$IMAGE" "$ctx" >&2
}

sshd_config_for() {
    # Prints a profile-specific sshd_config body on stdout.
    local profile="$1"
    cat <<'EOF'
Port 22
AddressFamily inet
ListenAddress 0.0.0.0
PidFile /run/sshd.pid
LogLevel VERBOSE
UsePAM no
PrintMotd no
EOF
    case "$profile" in
    password | bastion)
        cat <<'EOF'
PasswordAuthentication yes
PubkeyAuthentication no
KbdInteractiveAuthentication no
EOF
        ;;
    strictmodes)
        cat <<'EOF'
PasswordAuthentication yes
PubkeyAuthentication yes
StrictModes yes
EOF
        ;;
    key-otp)
        cat <<'EOF'
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
EOF
        ;;
    forcecommand)
        cat <<'EOF'
PasswordAuthentication yes
PubkeyAuthentication yes
ForceCommand echo RUSTCONN_FORCECOMMAND_SENTINEL; exit 0
EOF
        ;;
    unknown-hostkey)
        cat <<'EOF'
PasswordAuthentication yes
PubkeyAuthentication yes
EOF
        ;;
    *)
        echo "sshd-testbed: unknown profile '$profile'" >&2
        echo "run 'scripts/sshd-testbed.sh profiles' for the list" >&2
        exit 2
        ;;
    esac
}

up() {
    local profile="${1:-}"
    if [ -z "$profile" ]; then
        echo "sshd-testbed: 'up' needs a profile" >&2
        profiles >&2
        exit 2
    fi
    build_image

    # A fresh config per start. For unknown-hostkey we regenerate host keys so
    # the client never has the key cached, exercising the StrictHostKeyChecking
    # path the key-setup verify step (K2/K5) relies on.
    local cfgdir
    cfgdir="$(mktemp -d)"
    sshd_config_for "$profile" > "$cfgdir/sshd_config"

    down >/dev/null 2>&1 || true

    local regen=""
    if [ "$profile" = "unknown-hostkey" ]; then
        regen="rm -f /etc/ssh/ssh_host_* && ssh-keygen -A &&"
    fi

    # Bind sshd to a random free host port on loopback only.
    "$RT" run -d --name "$CONTAINER" \
        -p 127.0.0.1::22 \
        -v "$cfgdir/sshd_config:/etc/ssh/sshd_config.d/99-testbed.conf:ro,Z" \
        "$IMAGE" \
        sh -c "${regen} exec /usr/sbin/sshd -D -e" >/dev/null

    # Resolve the mapped host port.
    local hostport
    hostport="$("$RT" port "$CONTAINER" 22/tcp | head -1 | sed 's/.*://')"
    if [ -z "$hostport" ]; then
        echo "sshd-testbed: could not resolve mapped port" >&2
        "$RT" logs "$CONTAINER" >&2 || true
        down >/dev/null 2>&1 || true
        exit 1
    fi

    # Wait for sshd to accept TCP (bounded).
    local i
    for i in $(seq 1 50); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$hostport") 2>/dev/null; then
            exec 3>&- 3<&-
            break
        fi
        sleep 0.1
        if [ "$i" -eq 50 ]; then
            echo "sshd-testbed: sshd did not come up on 127.0.0.1:$hostport" >&2
            "$RT" logs "$CONTAINER" >&2 || true
            down >/dev/null 2>&1 || true
            exit 1
        fi
    done

    mkdir -p "$(dirname "$ENV_FILE")"
    {
        echo "export RUSTCONN_SSHD_HOST=127.0.0.1"
        echo "export RUSTCONN_SSHD_PORT=$hostport"
        echo "export RUSTCONN_SSHD_USER=$SSH_USER"
        echo "export RUSTCONN_SSHD_PASS=$SSH_PASS"
        echo "export RUSTCONN_SSHD_PROFILE=$profile"
    } > "$ENV_FILE"

    echo "sshd-testbed: '$profile' up on 127.0.0.1:$hostport (user $SSH_USER)" >&2
    echo "sshd-testbed: env written to $ENV_FILE — 'source' it before the tests" >&2
    cat "$ENV_FILE"
}

down() {
    "$RT" rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -f "$ENV_FILE" 2>/dev/null || true
    echo "sshd-testbed: down" >&2
}

case "${1:-}" in
up) shift; up "$@" ;;
down) down ;;
profiles) profiles ;;
*)
    echo "usage: scripts/sshd-testbed.sh {up <profile>|down|profiles}" >&2
    exit 2
    ;;
esac
