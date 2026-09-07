#!/bin/sh
# Does the container we intend to deploy actually start, serve, and refuse to
# start unsafely?
#
# The build gate already proves the image builds. An image that builds is not an
# image that runs: a missing runtime dependency, a bad CMD, a permission problem
# on the data volume or an entrypoint that dies on start all pass `docker build`
# and fail the first time anybody deploys them. This is the difference between
# "it compiles" and "it comes up".
#
# Four things, and the second is the one worth having:
#
#   1. it starts and answers /healthz
#   2. it REFUSES to start with no credentials configured, rather than coming up
#      unauthenticated — the property that keeps a deployment from quietly
#      serving tenant data to anyone who finds the port
#   3. /readyz answers, so an orchestrator has something to gate traffic on
#   4. it runs as a non-root user
#
# POSIX sh, no bashisms. SKIPs loudly when docker is absent rather than passing
# silently, because a skipped gate that reads as green is worse than no gate.

set -eu

IMAGE="${IMAGE:-icit-dnsguard:gate}"
PORT="${PORT:-18000}"
NAME="dnsguard-smoke-$$"
# Generated per run rather than written here: a literal would be a committed
# credential shape, and the secret-hygiene gate is right to refuse one even when
# it is only a fixture. Scoped to a container that lives about ten seconds and is
# never reachable off the runner.
TOKEN="smoke-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"

say()  { printf '\n=== %s ===\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1"; exit 1; }
skip() { printf 'SKIP: %s\n' "$1"; exit 0; }

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    rm -f /tmp/"$NAME".log
}
trap cleanup EXIT INT TERM

command -v docker >/dev/null 2>&1 || skip "docker not installed - container not smoke tested"

say "container smoke test"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    printf 'building %s\n' "$IMAGE"
    docker build -t "$IMAGE" . >/dev/null || fail "docker build failed"
fi

# ── 1. it refuses to start with no credentials ──────────────────────────────
# Done first, and deliberately: if this passes for the wrong reason (the image
# cannot start at all) the next check will catch it, whereas the other order
# would let a broken image look like a secure one.
printf 'checking it refuses to start unauthenticated... '
if docker run --rm --name "$NAME-anon" "$IMAGE" >/tmp/"$NAME".log 2>&1; then
    fail "the container started with no credentials configured"
fi
if ! grep -q "will not start unauthenticated" /tmp/"$NAME".log; then
    printf '\n--- container output ---\n'
    cat /tmp/"$NAME".log
    fail "it exited, but not because credentials were missing"
fi
printf 'refused\n'

# ── 2. it starts and serves ─────────────────────────────────────────────────
printf 'starting the container... '
docker run -d --name "$NAME" -p "$PORT":8000 \
    -e DNSGUARD_API_TOKEN="$TOKEN" \
    -e DNSGUARD_API_TENANT=smoke \
    -e DNSGUARD_API_ROLES=viewer \
    "$IMAGE" >/dev/null || fail "the container would not start"

READY=0
i=0
while [ "$i" -lt 30 ]; do
    if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
        READY=1
        break
    fi
    # If it has already exited there is nothing to wait for, and waiting the
    # full thirty seconds to say so wastes the reader's time.
    if [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != "true" ]; then
        break
    fi
    i=$((i + 1))
    sleep 1
done

if [ "$READY" -ne 1 ]; then
    printf '\n--- container logs ---\n'
    docker logs "$NAME" 2>&1 | tail -40
    fail "the container never answered /healthz"
fi
printf 'up\n'

# ── 3. readiness ────────────────────────────────────────────────────────────
printf 'checking /readyz... '
curl -fsS "http://127.0.0.1:$PORT/readyz" >/dev/null 2>&1 \
    || fail "/readyz did not answer; an orchestrator has nothing to gate traffic on"
printf 'ready\n'

# ── 4. non-root ─────────────────────────────────────────────────────────────
printf 'checking it does not run as root... '
UID_IN_CONTAINER=$(docker exec "$NAME" id -u 2>/dev/null || echo unknown)
[ "$UID_IN_CONTAINER" != "0" ] || fail "the container runs as root"
[ "$UID_IN_CONTAINER" != "unknown" ] || fail "could not determine the container user"
printf 'uid %s\n' "$UID_IN_CONTAINER"

printf '\ncontainer smoke test passed\n'
